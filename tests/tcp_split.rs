use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Instant;

use ruxmsg::close::CloseReason;
use ruxmsg::connection::{ConnectionEvent, PeerConnection};
use ruxmsg::crypto::IdentityKeypair;
use ruxmsg::transport::FramedTransport;

#[test]
fn split_connection_can_send_while_the_reader_is_blocked_waiting_on_the_peer() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();

    let server_thread = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let connection = PeerConnection::establish_as_responder(
            FramedTransport::new(stream),
            IdentityKeypair::from_bytes(&[2; 32]),
            |_| true,
            Instant::now(),
        )
        .unwrap();
        let (mut reader, writer) = connection.split_tcp().unwrap();

        // Nothing has arrived yet; this call blocks the reader thread while
        // the client below sends on the writer half concurrently.
        let first = reader.recv_next().unwrap();
        writer.send(b"reply while a read was pending").unwrap();
        let second = reader.recv_next().unwrap();
        (first, second)
    });

    let stream = TcpStream::connect(address).unwrap();
    let connection = PeerConnection::establish_as_initiator(
        FramedTransport::new(stream),
        IdentityKeypair::from_bytes(&[1; 32]),
        |_| true,
        Instant::now(),
    )
    .unwrap();
    let (mut client_reader, client_writer) = connection.split_tcp().unwrap();

    // The server's reader is blocked in recv_next() with nothing sent yet;
    // proves the writer half isn't blocked behind it.
    client_writer.send(b"hello while you were reading").unwrap();
    let client_event = client_reader.recv_next().unwrap();
    assert_eq!(
        client_event,
        ConnectionEvent::Data(b"reply while a read was pending".to_vec())
    );

    client_writer.close(CloseReason::Normal).unwrap();

    let (first, second) = server_thread.join().unwrap();
    assert_eq!(
        first,
        ConnectionEvent::Data(b"hello while you were reading".to_vec())
    );
    assert_eq!(second, ConnectionEvent::PeerClosed(CloseReason::Normal));
}
