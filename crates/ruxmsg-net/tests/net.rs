//! Tokio driver: real handshakes over duplex pipes and loopback TCP, with
//! injected write failures, stalls and paused-time timeouts.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{duplex, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::mpsc::Receiver;
use tokio::time::{timeout, Instant};
use zeroize::Zeroizing;

use ruxmsg::close::CloseReason;
use ruxmsg::crypto::IdentityKeypair;
use ruxmsg::handshake::HelloRole;
use ruxmsg::machine::CloseCause;
use ruxmsg_net::{
    ConnEvent, ConnectionHandle, DecodeError, FrameDecoder, HandleError, Net, NetEvent,
};
use ruxmsg::protocol::MessageType;
use ruxmsg::wire::Frame;

fn identity(seed: u8) -> IdentityKeypair {
    IdentityKeypair::from_bytes(&[seed; 32])
}

async fn next(rx: &mut Receiver<NetEvent>) -> NetEvent {
    timeout(Duration::from_secs(600), rx.recv())
        .await
        .expect("event within the (virtual) deadline")
        .expect("event channel open")
}

/// Answers SAS requests with `approve` until the connection is established.
async fn establish(rx: &mut Receiver<NetEvent>, handle: &ConnectionHandle, approve: bool) {
    loop {
        match next(rx).await {
            NetEvent::Conn {
                event: ConnEvent::SasRequired { .. },
                ..
            } => handle.answer_sas(approve).unwrap(),
            NetEvent::Conn {
                event: ConnEvent::Established { .. },
                ..
            } => return,
            NetEvent::Conn {
                event: ConnEvent::Closed(cause),
                ..
            } => panic!("closed during handshake: {cause:?}"),
            _ => {}
        }
    }
}

async fn message(rx: &mut Receiver<NetEvent>) -> Vec<u8> {
    loop {
        if let NetEvent::Conn {
            event: ConnEvent::Message(bytes),
            ..
        } = next(rx).await
        {
            return bytes.to_vec();
        }
    }
}

async fn closed(rx: &mut Receiver<NetEvent>) -> CloseCause {
    loop {
        if let NetEvent::Conn {
            event: ConnEvent::Closed(cause),
            ..
        } = next(rx).await
        {
            return cause;
        }
    }
}

async fn connected_pair() -> (
    (ConnectionHandle, Receiver<NetEvent>),
    (ConnectionHandle, Receiver<NetEvent>),
) {
    let (a_net, mut a_rx) = Net::new(identity(1));
    let (b_net, mut b_rx) = Net::new(identity(2));
    let (a_stream, b_stream) = duplex(64 * 1024);

    let a = a_net.adopt(a_stream, HelloRole::Initiator);
    let b = b_net.adopt(b_stream, HelloRole::Responder);

    tokio::join!(
        establish(&mut a_rx, &a, true),
        establish(&mut b_rx, &b, true)
    );

    ((a, a_rx), (b, b_rx))
}

// ----------------------------------------------------------- stream wrapper

/// Duplex wrapper that can fail after a byte budget or stall writes.
struct Gate<S> {
    inner: S,
    budget: Option<usize>,
    stall: Arc<AtomicBool>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Gate<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Gate<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.stall.load(Ordering::Relaxed) {
            return Poll::Pending;
        }

        let allowed = match self.budget {
            Some(0) => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Some(budget) => buf.len().min(budget),
            None => buf.len(),
        };

        let result = Pin::new(&mut self.inner).poll_write(cx, &buf[..allowed]);

        if let (Poll::Ready(Ok(written)), Some(budget)) = (&result, &mut self.budget) {
            *budget -= written;
        }

        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.stall.load(Ordering::Relaxed) {
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------- decoder

fn encoded(kind: MessageType, payload: Vec<u8>) -> Vec<u8> {
    Frame::new(kind, payload).unwrap().encode().unwrap()
}

#[test]
fn decoder_keeps_partial_frames_across_pushes() {
    let wire = encoded(MessageType::Close, vec![0xa0, 0x01, 0x02]);
    let mut decoder = FrameDecoder::new();

    for (index, byte) in wire.iter().enumerate() {
        assert_eq!(decoder.next_frame(), Ok(None), "frame completed early at {index}");
        decoder.push(&[*byte]);
    }

    let frame = decoder.next_frame().unwrap().unwrap();
    assert_eq!(frame.message_type, MessageType::Close);
    assert_eq!(frame.payload, vec![0xa0, 0x01, 0x02]);
    assert_eq!(decoder.buffered(), 0);
}

#[test]
fn decoder_splits_back_to_back_frames() {
    let mut wire = encoded(MessageType::Close, vec![0xa0]);
    wire.extend(encoded(MessageType::Data, vec![0xa1, 0x02]));

    let mut decoder = FrameDecoder::new();
    decoder.push(&wire);

    assert_eq!(decoder.next_frame().unwrap().unwrap().message_type, MessageType::Close);
    assert_eq!(decoder.next_frame().unwrap().unwrap().message_type, MessageType::Data);
    assert_eq!(decoder.next_frame(), Ok(None));
}

#[test]
fn decoder_rejects_bad_headers_before_the_payload_arrives() {
    for (header, expected) in [
        ([9, 1, 0, 0, 0, 0], DecodeError::UnsupportedVersion),
        ([1, 9, 0, 0, 0, 0], DecodeError::Malformed),
        ([1, 0, 0, 0, 0, 0], DecodeError::Malformed),
        // 1,025-byte HANDSHAKE and an over-limit DATA length, payload absent.
        ([1, 1, 0, 0, 4, 1], DecodeError::Malformed),
        ([1, 3, 0, 0x10, 0, 1], DecodeError::Malformed),
    ] {
        let mut decoder = FrameDecoder::new();
        decoder.push(&header);
        assert_eq!(decoder.next_frame(), Err(expected));
    }
}

// --------------------------------------------------------------- handshake

#[tokio::test]
async fn handshake_message_and_rekey_over_a_pipe() {
    let ((a, mut a_rx), (b, mut b_rx)) = connected_pair().await;

    a.send_message(Zeroizing::new(b"hello".to_vec())).unwrap();
    assert_eq!(message(&mut b_rx).await, b"hello");

    b.send_message(Zeroizing::new(b"world".to_vec())).unwrap();
    assert_eq!(message(&mut a_rx).await, b"world");

    a.request_rekey().unwrap();

    for rx in [&mut a_rx, &mut b_rx] {
        loop {
            if let NetEvent::Conn {
                event: ConnEvent::RekeyCompleted,
                ..
            } = next(rx).await
            {
                break;
            }
        }
    }

    a.send_message(Zeroizing::new(b"after".to_vec())).unwrap();
    assert_eq!(message(&mut b_rx).await, b"after");
}

#[tokio::test]
async fn closing_one_side_closes_the_other_as_unauthenticated() {
    let ((a, mut a_rx), (_b, mut b_rx)) = connected_pair().await;

    a.close(CloseReason::Normal).unwrap();

    assert_eq!(closed(&mut a_rx).await, CloseCause::Local);
    assert_eq!(
        closed(&mut b_rx).await,
        CloseCause::PeerUnauthenticated(CloseReason::Normal)
    );
}

#[tokio::test]
async fn dropping_every_handle_shuts_the_connection_down() {
    let ((a, mut a_rx), (_b, mut b_rx)) = connected_pair().await;

    drop(a);

    assert_eq!(closed(&mut a_rx).await, CloseCause::Local);
    assert!(matches!(
        closed(&mut b_rx).await,
        CloseCause::PeerUnauthenticated(CloseReason::Shutdown)
    ));
}

// ------------------------------------------------------- wire-level policy

#[tokio::test]
async fn unsupported_version_is_closed_without_any_response() {
    let (net, mut rx) = Net::new(identity(2));
    let (mut peer, stream) = duplex(4096);
    let _handle = net.adopt(stream, HelloRole::Responder);

    peer.write_all(&[9, 1, 0, 0, 0, 0]).await.unwrap();

    assert_eq!(closed(&mut rx).await, CloseCause::ProtocolError);

    let mut received = Vec::new();
    peer.read_to_end(&mut received).await.unwrap();
    assert!(received.is_empty(), "no protocol response to a bad version");
}

#[tokio::test]
async fn an_oversized_control_frame_header_ends_the_connection_with_a_close() {
    let (net, mut rx) = Net::new(identity(2));
    let (mut peer, stream) = duplex(4096);
    let _handle = net.adopt(stream, HelloRole::Responder);

    // Declares 1,025 HANDSHAKE bytes and sends none: it must be refused from the header.
    peer.write_all(&[1, 1, 0, 0, 4, 1]).await.unwrap();

    assert_eq!(closed(&mut rx).await, CloseCause::ProtocolError);

    let mut received = Vec::new();
    peer.read_to_end(&mut received).await.unwrap();
    let (frame, _) = Frame::decode(&received).unwrap();
    assert_eq!(frame.message_type, MessageType::Close);
}

// -------------------------------------------------------- partial writes

#[tokio::test]
async fn a_write_that_fails_mid_frame_ends_the_connection() {
    let (net, mut rx) = Net::new(identity(1));
    let (stream, mut peer) = duplex(4096);

    let gated = Gate {
        inner: stream,
        budget: Some(10),
        stall: Arc::new(AtomicBool::new(false)),
    };
    let _handle = net.adopt(gated, HelloRole::Initiator);

    assert_eq!(closed(&mut rx).await, CloseCause::TransportLost);

    let mut received = Vec::new();
    peer.read_to_end(&mut received).await.unwrap();
    assert_eq!(received.len(), 10, "exactly the written prefix, nothing after it");
}

#[tokio::test(start_paused = true)]
async fn a_stalled_write_times_out_and_the_local_queue_stays_bounded() {
    let (a_net, mut a_rx) = Net::new(identity(1));
    let (b_net, mut b_rx) = Net::new(identity(2));
    let (a_stream, b_stream) = duplex(64 * 1024);

    let stall = Arc::new(AtomicBool::new(false));
    let gated = Gate {
        inner: a_stream,
        budget: None,
        stall: Arc::clone(&stall),
    };

    let a = a_net.adopt(gated, HelloRole::Initiator);
    let b = b_net.adopt(b_stream, HelloRole::Responder);

    tokio::join!(
        establish(&mut a_rx, &a, true),
        establish(&mut b_rx, &b, true)
    );

    stall.store(true, Ordering::Relaxed);

    let mut accepted = 0;
    let mut busy = false;

    for _ in 0..200 {
        match a.send_message(Zeroizing::new(vec![0; 16])) {
            Ok(()) => accepted += 1,
            Err(HandleError::Busy) => {
                busy = true;
                break;
            }
            Err(HandleError::Gone) => panic!("connection ended early"),
        }
    }

    assert!(busy, "the command queue must push back");
    assert!(accepted <= 64);

    let start = Instant::now();

    // The first send blocks in a write; the write timeout then ends the connection.
    assert_eq!(closed(&mut a_rx).await, CloseCause::TransportLost);
    assert!(start.elapsed() >= Duration::from_secs(15));
}

// ---------------------------------------------------------------- timeouts

#[tokio::test(start_paused = true)]
async fn a_silent_peer_hits_the_frame_timeout() {
    let (net, mut rx) = Net::new(identity(2));
    let (_peer, stream) = duplex(4096);
    let _handle = net.adopt(stream, HelloRole::Responder);

    let start = Instant::now();

    assert_eq!(closed(&mut rx).await, CloseCause::Timeout);
    assert_eq!(start.elapsed(), Duration::from_secs(15));
}

#[tokio::test(start_paused = true)]
async fn an_unanswered_sas_times_out_after_120_seconds() {
    let (a_net, mut a_rx) = Net::new(identity(1));
    let (b_net, mut b_rx) = Net::new(identity(2));
    let (a_stream, b_stream) = duplex(64 * 1024);

    let _a = a_net.adopt(a_stream, HelloRole::Initiator);
    let _b = b_net.adopt(b_stream, HelloRole::Responder);

    let start = Instant::now();

    let mut saw_sas = false;
    let cause = loop {
        match next(&mut a_rx).await {
            NetEvent::Conn {
                event: ConnEvent::SasRequired { .. },
                ..
            } => saw_sas = true,
            NetEvent::Conn {
                event: ConnEvent::Closed(cause),
                ..
            } => break cause,
            _ => {}
        }
    };

    assert!(saw_sas);
    assert_eq!(cause, CloseCause::Timeout);
    assert_eq!(start.elapsed(), Duration::from_secs(120));

    assert!(matches!(
        closed(&mut b_rx).await,
        CloseCause::Timeout | CloseCause::PeerUnauthenticated(_)
    ));
}

#[tokio::test]
async fn rejecting_the_sas_closes_both_sides_without_a_session() {
    let (a_net, mut a_rx) = Net::new(identity(1));
    let (b_net, mut b_rx) = Net::new(identity(2));
    let (a_stream, b_stream) = duplex(64 * 1024);

    let a = a_net.adopt(a_stream, HelloRole::Initiator);
    let b = b_net.adopt(b_stream, HelloRole::Responder);

    let deny = async {
        loop {
            if let NetEvent::Conn {
                event: ConnEvent::SasRequired { .. },
                ..
            } = next(&mut a_rx).await
            {
                a.answer_sas(false).unwrap();
                return closed(&mut a_rx).await;
            }
        }
    };

    let approve = async {
        loop {
            if let NetEvent::Conn {
                event: ConnEvent::SasRequired { .. },
                ..
            } = next(&mut b_rx).await
            {
                b.answer_sas(true).unwrap();
                return closed(&mut b_rx).await;
            }
        }
    };

    let (a_cause, b_cause) = tokio::join!(deny, approve);

    assert_eq!(a_cause, CloseCause::SasRejected);
    assert!(matches!(b_cause, CloseCause::PeerUnauthenticated(_)));
}

// -------------------------------------------------------------------- TCP

#[tokio::test]
async fn loopback_tcp_listener_and_connect() {
    let (server, mut server_rx) = Net::new(identity(2));
    let (client, mut client_rx) = Net::new(identity(1));

    let listener = server.listen("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().to_string();

    let dialed = client.connect(&addr).await.unwrap();

    let accepted = loop {
        if let NetEvent::Opened { handle, .. } = next(&mut server_rx).await {
            break handle;
        }
    };

    tokio::join!(
        establish(&mut client_rx, &dialed, true),
        establish(&mut server_rx, &accepted, true)
    );

    dialed.send_message(Zeroizing::new(b"over tcp".to_vec())).unwrap();
    assert_eq!(message(&mut server_rx).await, b"over tcp");

    listener.stop();
}

#[tokio::test]
async fn the_listener_serves_at_most_four_unauthenticated_handshakes() {
    let (server, mut rx) = Net::new(identity(2));
    let listener = server.listen("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr();

    let mut clients = Vec::new();
    for _ in 0..5 {
        clients.push(TcpStream::connect(addr).await.unwrap());
    }

    let mut accepted = 0;
    let mut handles = Vec::new();
    while let Ok(Some(event)) = timeout(Duration::from_millis(500), rx.recv()).await {
        if let NetEvent::Opened { handle, .. } = event {
            accepted += 1;
            // Dropping every handle would shut the connection down.
            handles.push(handle);
        }
    }
    assert_eq!(accepted, 4);

    let mut byte = [0u8; 1];

    // The fifth connection is dropped by the server; the others stay open and idle.
    let fifth = timeout(Duration::from_secs(2), clients[4].read(&mut byte)).await;
    assert!(matches!(fifth, Ok(Ok(0)) | Ok(Err(_))), "fifth connection must be closed");

    let first = timeout(Duration::from_millis(200), clients[0].read(&mut byte)).await;
    assert!(first.is_err(), "admitted connections stay open while waiting for COMMIT");

    listener.stop();
}

// ---------------------------------------------------------------- hygiene

#[test]
fn event_debug_output_never_contains_message_content() {
    let event = ConnEvent::Message(Zeroizing::new(b"canary-plaintext-9c1d".to_vec()));

    assert!(!format!("{event:?}").contains("canary"));
}
