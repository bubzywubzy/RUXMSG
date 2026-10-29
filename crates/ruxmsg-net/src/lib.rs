//! Tokio driver for the sans-IO [`ruxmsg::machine::Engine`].
//!
//! One task owns one connection and its engine. Nothing else touches protocol
//! state, so cancelling a `select!` branch can never leave it half-updated.
//!
//! # Cancellation and partial writes
//!
//! - Cancel-safe branches only appear in the `select!`: a `read` into a scratch
//!   buffer, channel receives, and a sleep. Partial frames live in a decoder
//!   that persists across iterations, so a dropped read loses nothing.
//! - Writes are never raced. They run to completion under a timeout, outside
//!   the `select!`. A write that errors or times out may have put part of a
//!   frame on the wire, so it is treated as a lost connection, never as unsent.
//! - A rekey timeout aborts only the candidate (the engine decides); a write
//!   failure always ends the connection.
//!
//! # Bounds
//!
//! Every queue is bounded: commands, control, events, the decoder buffer
//! (one maximum frame plus one read chunk), deadlines, and the number of
//! unauthenticated inbound handshakes. Local input gets back-pressure
//! ([`HandleError::Busy`]); network input is bounded by TCP flow control.

use std::fmt;
use std::future::pending;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{self, error::TrySendError};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep_until, timeout};
use zeroize::Zeroizing;

use ruxmsg::close::CloseReason;
use ruxmsg::crypto::IdentityKeypair;
use ruxmsg::error::Error;
use ruxmsg::handshake::HelloRole;
use ruxmsg::identity::PeerIdentity;
use ruxmsg::machine::{
    CloseCause, DeadlineId, Effect, Engine, EngineState, Entropy, Event, Input, OsEntropy,
    RekeyFailure, SendRejection,
};
use ruxmsg::protocol::{MAX_FRAME_SIZE, MAX_UNAUTHENTICATED_HANDSHAKES};
use ruxmsg::wire::{Frame, HEADER_SIZE};

const MESSAGE_QUEUE: usize = 64;
const CONTROL_QUEUE: usize = 8;
const EVENT_QUEUE: usize = 256;
const READ_CHUNK: usize = 16 * 1024;
const WRITE_TIMEOUT: Duration = Duration::from_secs(15);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_ACCEPT_FAILURES: u32 = 20;
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

// ------------------------------------------------------------------ decoder

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// Close without a protocol response (spec §4.2).
    UnsupportedVersion,
    Malformed,
}

/// Incremental frame decoder. Version, type and per-type length are checked
/// from the header before the payload is awaited or allocated.
#[derive(Default)]
pub struct FrameDecoder {
    buffer: Vec<u8>,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }

    pub fn next_frame(&mut self) -> Result<Option<Frame>, DecodeError> {
        let Some(header) = self.buffer.first_chunk::<HEADER_SIZE>() else {
            return Ok(None);
        };

        let (_, _, length) = Frame::parse_header(header).map_err(|error| match error {
            Error::UnsupportedVersion(_) => DecodeError::UnsupportedVersion,
            _ => DecodeError::Malformed,
        })?;

        let total = HEADER_SIZE + length as usize;

        if self.buffer.len() < total {
            return Ok(None);
        }

        let (frame, consumed) =
            Frame::decode(&self.buffer[..total]).map_err(|_| DecodeError::Malformed)?;

        self.buffer.drain(..consumed);

        if self.buffer.is_empty() && self.buffer.capacity() > 64 * 1024 {
            self.buffer.shrink_to(READ_CHUNK)
        }
        Ok(Some(frame))
    }
}

// ------------------------------------------------------------------- events

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnId(pub u64);

pub enum ConnEvent {
    SasRequired {
        words: [&'static str; 3],
        peer_identity: PeerIdentity,
    },
    Established {
        peer_identity: PeerIdentity,
    },
    Message(Zeroizing<Vec<u8>>),
    RekeyStarted,
    RekeyCompleted,
    RekeyFailed(RekeyFailure),
    DataRejected,
    SendRejected(SendRejection),
    /// Final event for the connection.
    Closed(CloseCause),
}

pub enum NetEvent {
    /// A connection exists, inbound or dialed. Always precedes its `Conn` events.
    Opened {
        id: ConnId,
        handle: ConnectionHandle,
        remote: SocketAddr,
        outbound: bool,
    },
    DialFailed {
        addr: String,
        error: io::ErrorKind,
    },
    ListenerStopped {
        addr: SocketAddr,
        error: Option<io::ErrorKind>,
    },
    Conn {
        id: ConnId,
        event: ConnEvent,
    },
}

// Message bodies must never reach logs through `{:?}`.
impl fmt::Debug for ConnEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SasRequired { .. } => "ConnEvent::SasRequired",
            Self::Established { .. } => "ConnEvent::Established",
            Self::Message(_) => "ConnEvent::Message",
            Self::RekeyStarted => "ConnEvent::RekeyStarted",
            Self::RekeyCompleted => "ConnEvent::RekeyCompleted",
            Self::RekeyFailed(_) => "ConnEvent::RekeyFailed",
            Self::DataRejected => "ConnEvent::DataRejected",
            Self::SendRejected(_) => "ConnEvent::SendRejected",
            Self::Closed(_) => "ConnEvent::Closed",
        })
    }
}

impl fmt::Debug for NetEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Opened { .. } => "NetEvent::Opened",
            Self::DialFailed { .. } => "NetEvent::DialFailed",
            Self::ListenerStopped { .. } => "NetEvent::ListenerStopped",
            Self::Conn { .. } => "NetEvent::Conn",
        })
    }
}

// ------------------------------------------------------------------- handle

enum Control {
    Close(CloseReason),
    RequestRekey,
    Sas(bool),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandleError {
    /// A bounded queue is full. Retry later; the connection is unaffected.
    Busy,
    /// The connection task has ended.
    Gone,
}

/// Cheap, cloneable command side of one connection.
#[derive(Clone)]
pub struct ConnectionHandle {
    id: ConnId,
    messages: mpsc::Sender<Zeroizing<Vec<u8>>>,
    control: mpsc::Sender<Control>,
}

fn map_try_send<T>(result: Result<(), TrySendError<T>>) -> Result<(), HandleError> {
    result.map_err(|error| match error {
        TrySendError::Full(_) => HandleError::Busy,
        TrySendError::Closed(_) => HandleError::Gone,
    })
}

impl ConnectionHandle {
    pub const fn id(&self) -> ConnId {
        self.id
    }

    pub fn send_message(&self, content: Zeroizing<Vec<u8>>) -> Result<(), HandleError> {
        map_try_send(self.messages.try_send(content))
    }

    pub fn close(&self, reason: CloseReason) -> Result<(), HandleError> {
        map_try_send(self.control.try_send(Control::Close(reason)))
    }

    pub fn request_rekey(&self) -> Result<(), HandleError> {
        map_try_send(self.control.try_send(Control::RequestRekey))
    }

    pub fn answer_sas(&self, approved: bool) -> Result<(), HandleError> {
        map_try_send(self.control.try_send(Control::Sas(approved)))
    }

    pub fn is_closed(&self) -> bool {
        self.control.is_closed()
    }
}

// --------------------------------------------------------------------- task

struct Task<S> {
    id: ConnId,
    stream: S,
    engine: Engine,
    events: mpsc::Sender<NetEvent>,
    deadlines: Vec<(DeadlineId, Instant)>,
    decoder: FrameDecoder,
    /// Released once the handshake ends, so it only counts while unauthenticated.
    permit: Option<OwnedSemaphorePermit>,
    lost: bool,
    orphaned: bool,
    closing: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Task<S> {
    async fn run(
        mut self,
        announce: Option<(ConnectionHandle, SocketAddr, bool)>,
        mut messages: mpsc::Receiver<Zeroizing<Vec<u8>>>,
        mut control: mpsc::Receiver<Control>,
    ) {
        if let Some((handle, remote, outbound)) = announce {
            let event = NetEvent::Opened {
                id: self.id,
                handle,
                remote,
                outbound,
            };

            if self.events.send(event).await.is_err() {
                return;
            }
        }

        self.apply(Input::Start).await;

        let mut chunk = vec![0u8; READ_CHUNK];

        while !self.closing {
            let next = self.deadlines.iter().map(|(_, due)| *due).min();

            tokio::select! {
                read = self.stream.read(&mut chunk) => {
                    match read {
                        Ok(0) | Err(_) => self.apply(Input::TransportClosed).await,
                        Ok(count) => {
                            self.decoder.push(&chunk[..count]);
                            self.drain_frames().await;
                        }
                    }
                }
                Some(content) = messages.recv() => {
                    self.apply(Input::LocalSend(content)).await;
                }
                command = control.recv() => {
                    let input = match command {
                        Some(Control::Close(reason)) => Input::LocalClose(reason),
                        Some(Control::RequestRekey) => Input::RequestRekey,
                        Some(Control::Sas(approved)) => Input::SasDecision(approved),
                        // Every handle was dropped.
                        None => Input::LocalClose(CloseReason::Shutdown),
                    };
                    self.apply(input).await;
                }
                () = async {
                    match next {
                        Some(due) => sleep_until(due).await,
                        None => pending().await,
                    }
                } => {
                    self.fire_due().await;
                }
            }
        }

        let _ = timeout(WRITE_TIMEOUT, self.stream.shutdown()).await;
    }

    async fn drain_frames(&mut self) {
        while !self.closing {
            match self.decoder.next_frame() {
                Ok(Some(frame)) => self.apply(Input::FrameReceived(frame)).await,
                Ok(None) => break,
                Err(DecodeError::UnsupportedVersion) => {
                    self.apply(Input::Malformed { respond: false }).await;
                }
                Err(DecodeError::Malformed) => {
                    self.apply(Input::Malformed { respond: true }).await;
                }
            }
        }
    }

    async fn fire_due(&mut self) {
        let now = Instant::now();

        let mut due: Vec<(Instant, DeadlineId)> = self
            .deadlines
            .iter()
            .filter(|(_, at)| *at <= now)
            .map(|(id, at)| (*at, *id))
            .collect();

        due.sort();

        for (_, id) in due {
            self.deadlines.retain(|(armed, _)| *armed != id);
            self.apply(Input::Timeout(id)).await;
        }
    }

    async fn apply(&mut self, input: Input) {
        let effects = self.engine.handle(input);
        self.process(effects).await;

        // A failed write means the transport is gone; a vanished consumer
        // means nobody can answer SAS or read messages.
        if self.lost && self.engine.state() != EngineState::Closed {
            let effects = self.engine.handle(Input::TransportClosed);
            self.process(effects).await;
        }

        if self.orphaned && self.engine.state() != EngineState::Closed {
            let effects = self.engine.handle(Input::LocalClose(CloseReason::Shutdown));
            self.process(effects).await;
        }
    }

    async fn process(&mut self, effects: Vec<Effect>) {
        for effect in effects {
            match effect {
                Effect::Send(frame) => {
                    if !self.lost && self.write(&frame).await.is_err() {
                        self.lost = true;
                    }
                }
                Effect::SetDeadline { id, after, .. } => {
                    self.deadlines.push((id, Instant::now() + after));
                }
                Effect::CancelDeadline(id) => {
                    self.deadlines.retain(|(armed, _)| *armed != id);
                }
                Effect::RequestSas {
                    words,
                    peer_identity,
                } => {
                    self.emit(ConnEvent::SasRequired {
                        words,
                        peer_identity,
                    })
                    .await;
                }
                Effect::Deliver(content) => self.emit(ConnEvent::Message(content)).await,
                Effect::Notify(event) => {
                    let mapped = match event {
                        Event::Established { peer_identity } => {
                            self.permit = None;
                            ConnEvent::Established { peer_identity }
                        }
                        Event::RekeyStarted => ConnEvent::RekeyStarted,
                        Event::RekeyCompleted => ConnEvent::RekeyCompleted,
                        Event::RekeyFailed(failure) => ConnEvent::RekeyFailed(failure),
                        Event::DataRejected => ConnEvent::DataRejected,
                        Event::SendRejected(reason) => ConnEvent::SendRejected(reason),
                        Event::Closed(cause) => {
                            self.permit = None;
                            ConnEvent::Closed(cause)
                        }
                    };
                    self.emit(mapped).await;
                }
                Effect::CloseTransport => self.closing = true,
            }
        }
    }

    /// Runs to completion or fails; never raced against anything. A timeout
    /// may leave a partial frame on the wire, so the caller treats any error
    /// as a lost connection.
    async fn write(&mut self, frame: &Frame) -> io::Result<()> {
        let bytes = frame.encode().map_err(io::Error::other)?;

        let stream = &mut self.stream;

        timeout(WRITE_TIMEOUT, async {
            stream.write_all(&bytes).await?;
            stream.flush().await
        })
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
    }

    async fn emit(&mut self, event: ConnEvent) {
        let message = NetEvent::Conn { id: self.id, event };

        if self.events.send(message).await.is_err() {
            self.orphaned = true;
        }
    }
}

// ------------------------------------------------------------------ facade

/// Maximum buffered bytes in a decoder: one frame plus one read chunk.
pub const MAX_DECODER_BUFFER: usize = HEADER_SIZE + MAX_FRAME_SIZE as usize + READ_CHUNK;

pub struct Net {
    identity: IdentityKeypair,
    events: mpsc::Sender<NetEvent>,
    next_id: Arc<AtomicU64>,
    unauthenticated: Arc<Semaphore>,
}

pub struct Listener {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl Listener {
    pub const fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Stops accepting. Established and handshaking connections continue.
    pub fn stop(self) {
        self.task.abort();
    }
}

impl Net {
    /// Creates the facade and the bounded event channel the application reads.
    pub fn new(identity: IdentityKeypair) -> (Self, mpsc::Receiver<NetEvent>) {
        let (events, receiver) = mpsc::channel(EVENT_QUEUE);

        let net = Self {
            identity,
            events,
            next_id: Arc::new(AtomicU64::new(1)),
            unauthenticated: Arc::new(Semaphore::new(MAX_UNAUTHENTICATED_HANDSHAKES)),
        };

        (net, receiver)
    }

    /// Runs the protocol over any byte stream. The dialing side is the initiator.
    pub fn adopt<S>(&self, stream: S, role: HelloRole) -> ConnectionHandle
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.spawn(stream, role, Box::new(OsEntropy), None, None)
    }

    pub async fn connect(&self, addr: &str) -> io::Result<ConnectionHandle> {
        let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;

        stream.set_nodelay(true)?;

        Ok(self.adopt(stream, HelloRole::Initiator))
    }

    /// Dials in the background. The outcome arrives as `Opened` or `DialFailed`
    /// on the event channel, so the caller never blocks on the connect.
    pub fn dial(&self, addr: String) {
        let net = self.clone_parts();

        tokio::spawn(async move {
            let attempt = async {
                let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr.as_str()))
                    .await
                    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;

                stream.set_nodelay(true)?;

                let remote = stream.peer_addr()?;

                Ok::<_, io::Error>((stream, remote))
            };

            match attempt.await {
                Ok((stream, remote)) => {
                    net.spawn(
                        stream,
                        HelloRole::Initiator,
                        Box::new(OsEntropy),
                        None,
                        Some((remote, true)),
                    );
                }
                Err(error) => {
                    let _ = net
                        .events
                        .send(NetEvent::DialFailed {
                            addr,
                            error: error.kind(),
                        })
                        .await;
                }
            }
        });
    }

    pub async fn listen(&self, addr: &str) -> io::Result<Listener> {
        let listener = TcpListener::bind(addr).await?;
        let local = listener.local_addr()?;

        let net = self.clone_parts();

        let task = tokio::spawn(async move {
            let mut failures = 0u32;

            loop {
                let (stream, remote) = match listener.accept().await {
                    Ok(accepted) => {
                        failures = 0;
                        accepted
                    }
                    Err(error) => {
                        // A peer resetting mid-accept or a momentary descriptor
                        // shortage must not take the listener down.
                        failures += 1;

                        if failures >= MAX_ACCEPT_FAILURES {
                            let _ = net
                                .events
                                .send(NetEvent::ListenerStopped {
                                    addr: local,
                                    error: Some(error.kind()),
                                })
                                .await;
                            return;
                        }

                        tokio::time::sleep(ACCEPT_BACKOFF).await;
                        continue;
                    }
                };

                // Spec §11: bound concurrent unauthenticated handshakes.
                let Ok(permit) = Arc::clone(&net.unauthenticated).try_acquire_owned() else {
                    drop(stream);
                    continue;
                };

                let _ = stream.set_nodelay(true);

                net.spawn(
                    stream,
                    HelloRole::Responder,
                    Box::new(OsEntropy),
                    Some(permit),
                    Some((remote, false)),
                );
            }
        });

        Ok(Listener { addr: local, task })
    }

    fn clone_parts(&self) -> Self {
        Self {
            identity: self.identity.clone(),
            events: self.events.clone(),
            next_id: Arc::clone(&self.next_id),
            unauthenticated: Arc::clone(&self.unauthenticated),
        }
    }

    fn spawn<S>(
        &self,
        stream: S,
        role: HelloRole,
        entropy: Box<dyn Entropy + Send>,
        permit: Option<OwnedSemaphorePermit>,
        announce: Option<(SocketAddr, bool)>,
    ) -> ConnectionHandle
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let id = ConnId(self.next_id.fetch_add(1, Ordering::Relaxed));

        let (messages_tx, messages_rx) = mpsc::channel(MESSAGE_QUEUE);
        let (control_tx, control_rx) = mpsc::channel(CONTROL_QUEUE);

        let handle = ConnectionHandle {
            id,
            messages: messages_tx,
            control: control_tx,
        };

        let task = Task {
            id,
            stream,
            engine: Engine::new(role, self.identity.clone(), entropy),
            events: self.events.clone(),
            deadlines: Vec::new(),
            decoder: FrameDecoder::new(),
            permit,
            lost: false,
            orphaned: false,
            closing: false,
        };

        let announce = announce.map(|(remote, outbound)| (handle.clone(), remote, outbound));

        tokio::spawn(task.run(announce, messages_rx, control_rx));

        handle
    }
}
