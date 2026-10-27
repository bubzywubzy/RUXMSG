use std::time::Instant;

use crate::close::{ClosePayload, CloseReason};
use crate::crypto::IdentityKeypair;
use crate::engine::{establish_initiator, establish_responder};
use crate::error::{Error, Result};
use crate::handshake::HelloRole;
use crate::manager::SessionManager;
use crate::protocol::MessageType;
use crate::transport::{Demuxer, SeededTransport, Transport};
use crate::wire::Frame;

/// An event surfaced while driving an established `PeerConnection`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionEvent {
    Data(Vec<u8>),
    PeerClosed(CloseReason),
}

/// Drives one live transport through handshake, DATA, rekey, and close.
///
/// Frames not expected during a handshake/rekey exchange (DATA arriving while
/// the peer's old session is still usable, per D-008/9.1) are buffered by a
/// [`Demuxer`] and served first by [`PeerConnection::recv_next`], so a single
/// shared transport can carry interleaved handshake and DATA traffic as long
/// as the caller drives one `PeerConnection` method at a time.
pub struct PeerConnection<T: Transport> {
    transport: T,
    identity: IdentityKeypair,
    manager: SessionManager,
    pending: std::collections::VecDeque<Frame>,
}

impl<T: Transport> PeerConnection<T> {
    /// Establishes an initial session as the initiator.
    ///
    /// For an initial handshake, `sas_approved` is called exactly once with
    /// the current three-word SAS. Returning `false` aborts the candidate
    /// session.
    pub fn establish_as_initiator(
        mut transport: T,
        identity: IdentityKeypair,
        sas_approved: impl FnOnce([&'static str; 3]) -> bool,
        now: Instant,
    ) -> Result<Self> {
        let mut demux = Demuxer::new(&mut transport);

        let established =
            establish_initiator(&mut demux, &identity, None, sas_approved)?;

        let pending = demux.take_buffered();

        let manager =
            SessionManager::from_initial_handshake(established, HelloRole::Initiator, now)?;

        Ok(Self {
            transport,
            identity,
            manager,
            pending,
        })
    }

    /// Establishes an initial session as the responder.
    ///
    /// For an initial handshake, `sas_approved` is called exactly once with
    /// the current three-word SAS. Returning `false` aborts the candidate
    /// session.
    pub fn establish_as_responder(
        mut transport: T,
        identity: IdentityKeypair,
        sas_approved: impl FnOnce([&'static str; 3]) -> bool,
        now: Instant,
    ) -> Result<Self> {
        let mut demux = Demuxer::new(&mut transport);

        let established =
            establish_responder(&mut demux, &identity, None, sas_approved)?;

        let pending = demux.take_buffered();

        let manager =
            SessionManager::from_initial_handshake(established, HelloRole::Responder, now)?;

        Ok(Self {
            transport,
            identity,
            manager,
            pending,
        })
    }

    /// Borrows the session manager for read-only lifecycle and identity state.
    pub const fn manager(&self) -> &SessionManager {
        &self.manager
    }

    /// Encrypts and sends application bytes on the active session.
    pub fn send(&mut self, content: &[u8]) -> Result<()> {
        let frame = self.manager.encrypt(content)?;
        self.transport.send(&frame)
    }

    /// Reads and dispatches one inbound event.
    ///
    /// Buffered DATA/CLOSE frames are consumed before reading the transport.
    /// An inbound REKEY frame is the opening COMMIT of a peer-initiated rekey;
    /// it is handed back to `establish_responder` through `SeededTransport`
    /// rather than being discarded.
    pub fn recv_next(&mut self) -> Result<ConnectionEvent> {
        loop {
            let frame = match self.pending.pop_front() {
                Some(frame) => frame,
                None => self.transport.receive()?,
            };

            match frame.message_type {
                MessageType::Data => {
                    return Ok(ConnectionEvent::Data(
                        self.manager.decrypt(&frame)?,
                    ));
                }

                MessageType::Close => {
                    let close = ClosePayload::decode(&frame)?;

                    let known =
                        close.session_id == Some(self.manager.active_session_id())
                            || close.session_id
                                == self
                                    .manager
                                    .draining()
                                    .map(|draining| draining.session_id());

                    // D-017: ignore CLOSE frames for unknown sessions.
                    if !known {
                        continue;
                    }

                    self.manager.close();

                    return Ok(ConnectionEvent::PeerClosed(close.reason));
                }

                MessageType::Rekey => {
                    self.handle_peer_initiated_rekey(frame)?;
                    continue;
                }

                _ => return Err(Error::InvalidHandshake),
            }
        }
    }

    /// Handles a peer-initiated REKEY whose opening COMMIT has already been
    /// consumed by `recv_next`.
    ///
    /// `SeededTransport` puts that COMMIT back in front of the underlying
    /// transport so `establish_responder` can consume the complete handshake
    /// using its normal protocol logic.
    fn handle_peer_initiated_rekey(&mut self, seed: Frame) -> Result<()> {
        self.manager.begin_rekey()?;

        let previous_session_id = self.manager.active_session_id();

        let mut seeded = SeededTransport::new(seed, &mut self.transport);
        let mut demux = Demuxer::new(&mut seeded);

        let result = establish_responder(
            &mut demux,
            &self.identity,
            Some(previous_session_id),
            |_| true,
        );

        self.pending.extend(demux.take_buffered());

        let candidate = match result {
            Ok(candidate) => candidate,
            Err(error) => {
                let _ = self.manager.abort_rekey();
                return Err(error);
            }
        };

        if let Err(error) = self.manager.complete_rekey(
            candidate,
            HelloRole::Responder,
            Instant::now(),
        ) {
            let _ = self.manager.abort_rekey();
            return Err(error);
        }

        Ok(())
    }

    /// Runs a locally initiated rekey handshake over the same live transport,
    /// buffering any DATA/CLOSE frames that arrive before the candidate is
    /// confirmed.
    pub fn rekey(
        &mut self,
        sas_approved: impl FnOnce([&'static str; 3]) -> bool,
        now: Instant,
    ) -> Result<()> {
        self.manager.begin_rekey()?;

        let previous_session_id = self.manager.active_session_id();
        let local_role = self
            .manager
            .rekey_role(&self.identity.identity());

        let mut demux = Demuxer::new(&mut self.transport);

        let result = match local_role {
            HelloRole::Initiator => establish_initiator(
                &mut demux,
                &self.identity,
                Some(previous_session_id),
                sas_approved,
            ),

            HelloRole::Responder => establish_responder(
                &mut demux,
                &self.identity,
                Some(previous_session_id),
                sas_approved,
            ),
        };

        self.pending.extend(demux.take_buffered());

        let candidate = match result {
            Ok(candidate) => candidate,

            Err(error) => {
                let _ = self.manager.abort_rekey();
                return Err(error);
            }
        };

        if let Err(error) = self
            .manager
            .complete_rekey(candidate, local_role, now)
        {
            let _ = self.manager.abort_rekey();
            return Err(error);
        }

        Ok(())
    }

    /// Drops any expired drained session; call periodically from the event loop.
    pub fn expire_drain(&mut self, now: Instant) {
        self.manager.expire_drain(now);
    }

    /// Sends a CLOSE frame and destroys local session state immediately.
    pub fn close(&mut self, reason: CloseReason) -> Result<()> {
        let frame = ClosePayload {
            session_id: Some(self.manager.active_session_id()),
            reason,
            detail: None,
        }
        .encode()?;

        self.transport.send(&frame)?;

        self.manager.close();

        self.transport.close()
    }
}

impl PeerConnection<crate::transport::FramedTransport<std::net::TcpStream>> {
    /// Splits an established TCP connection into a reader (owns the socket's
    /// exclusive read half; drives `recv_next`/`rekey`, the only operations
    /// that read) and a writer (drives ordinary `send`/`close` through a
    /// shared write half), so sending is never blocked behind a pending read.
    ///
    /// `SessionManager` is shared behind a mutex so both halves see one
    /// consistent lifecycle/ratchet state; the mutex is only ever held for
    /// the brief, non-blocking encrypt/decrypt/state-transition calls, never
    /// across a socket read.
    pub fn split_tcp(self) -> Result<(TcpConnectionReader, TcpConnectionWriter)> {
        let read = self.transport.into_inner();

        let write = read
            .try_clone()
            .map_err(|error| Error::Transport(error.to_string()))?;

        let write = std::sync::Arc::new(std::sync::Mutex::new(write));
        let manager = std::sync::Arc::new(std::sync::Mutex::new(self.manager));

        let reader = TcpConnectionReader {
            manager: manager.clone(),
            identity: self.identity,
            transport: DuplexTcpTransport {
                read,
                write: write.clone(),
            },
            pending: self.pending,
        };

        let writer = TcpConnectionWriter { manager, write };

        Ok((reader, writer))
    }
}

/// A `Transport` whose reads use an exclusive socket clone and whose writes
/// go through a mutex shared with a [`TcpConnectionWriter`].
struct DuplexTcpTransport {
    read: std::net::TcpStream,
    write: std::sync::Arc<std::sync::Mutex<std::net::TcpStream>>,
}

impl Transport for DuplexTcpTransport {
    fn send(&mut self, frame: &Frame) -> Result<()> {
        use std::io::Write;

        let bytes = frame.encode()?;

        let mut write = self
            .write
            .lock()
            .expect("write mutex is not poisoned");

        write
            .write_all(&bytes)
            .map_err(|error| Error::Transport(error.to_string()))?;

        write
            .flush()
            .map_err(|error| Error::Transport(error.to_string()))
    }

    fn receive(&mut self) -> Result<Frame> {
        use std::io::Read;

        let mut header = [0; 6];

        self.read
            .read_exact(&mut header)
            .map_err(|error| Error::Transport(error.to_string()))?;

        let length =
            u32::from_be_bytes(header[2..6].try_into().expect("header has four bytes"));

        crate::protocol::FrameLength::new(length)?;

        let mut bytes = Vec::with_capacity(6 + length as usize);
        bytes.extend_from_slice(&header);

        let mut payload = vec![0; length as usize];

        self.read
            .read_exact(&mut payload)
            .map_err(|error| Error::Transport(error.to_string()))?;

        bytes.extend_from_slice(&payload);

        let (frame, consumed) = Frame::decode(&bytes)?;

        if consumed != bytes.len() {
            return Err(Error::TrailingFrameBytes);
        }

        Ok(frame)
    }

    fn close(&mut self) -> Result<()> {
        let _ = self.read.shutdown(std::net::Shutdown::Both);
        Ok(())
    }
}

/// The read/rekey half produced by [`PeerConnection::split_tcp`].
pub struct TcpConnectionReader {
    manager: std::sync::Arc<std::sync::Mutex<SessionManager>>,
    identity: IdentityKeypair,
    transport: DuplexTcpTransport,
    pending: std::collections::VecDeque<Frame>,
}

impl TcpConnectionReader {
    /// Receives one DATA or peer-CLOSE event.
    ///
    /// A peer-initiated REKEY is handled internally and the method then
    /// resumes waiting for the next application-level event.
    pub fn recv_next(&mut self) -> Result<ConnectionEvent> {
        loop {
            let frame = match self.pending.pop_front() {
                Some(frame) => frame,
                None => self.transport.receive()?,
            };

            match frame.message_type {
                MessageType::Data => {
                    let mut manager = self
                        .manager
                        .lock()
                        .expect("manager mutex is not poisoned");

                    return Ok(ConnectionEvent::Data(manager.decrypt(&frame)?));
                }

                MessageType::Close => {
                    let close = ClosePayload::decode(&frame)?;

                    let mut manager = self
                        .manager
                        .lock()
                        .expect("manager mutex is not poisoned");

                    let known =
                        close.session_id == Some(manager.active_session_id())
                            || close.session_id
                                == manager
                                    .draining()
                                    .map(|draining| draining.session_id());

                    // D-017: ignore CLOSE frames for unknown sessions.
                    if !known {
                        continue;
                    }

                    manager.close();

                    return Ok(ConnectionEvent::PeerClosed(close.reason));
                }

                MessageType::Rekey => {
                    self.handle_peer_initiated_rekey(frame)?;
                    continue;
                }

                _ => return Err(Error::InvalidHandshake),
            }
        }
    }

    /// Handles a peer-initiated REKEY whose opening COMMIT was already
    /// consumed by `recv_next`.
    fn handle_peer_initiated_rekey(&mut self, seed: Frame) -> Result<()> {
        let previous_session_id = {
            let mut manager = self
                .manager
                .lock()
                .expect("manager mutex is not poisoned");

            manager.begin_rekey()?;
            manager.active_session_id()
        };

        let mut seeded = SeededTransport::new(seed, &mut self.transport);
        let mut demux = Demuxer::new(&mut seeded);

        let result = establish_responder(
            &mut demux,
            &self.identity,
            Some(previous_session_id),
            |_| true,
        );

        self.pending.extend(demux.take_buffered());

        let candidate = match result {
            Ok(candidate) => candidate,

            Err(error) => {
                let mut manager = self
                    .manager
                    .lock()
                    .expect("manager mutex is not poisoned");

                let _ = manager.abort_rekey();

                return Err(error);
            }
        };

        if let Err(error) = {
            let mut manager = self
                .manager
                .lock()
                .expect("manager mutex is not poisoned");

            manager.complete_rekey(
                candidate,
                HelloRole::Responder,
                Instant::now(),
            )
        } {
            let mut manager = self
                .manager
                .lock()
                .expect("manager mutex is not poisoned");

            let _ = manager.abort_rekey();

            return Err(error);
        }

        Ok(())
    }

    pub fn rekey(
        &mut self,
        sas_approved: impl FnOnce([&'static str; 3]) -> bool,
        now: Instant,
    ) -> Result<()> {
        {
            let mut manager = self
                .manager
                .lock()
                .expect("manager mutex is not poisoned");

            manager.begin_rekey()?;

            let previous_session_id = manager.active_session_id();
            let local_role = manager.rekey_role(&self.identity.identity());

            drop(manager);

            let mut demux = Demuxer::new(&mut self.transport);

            let result = match local_role {
                HelloRole::Initiator => establish_initiator(
                    &mut demux,
                    &self.identity,
                    Some(previous_session_id),
                    sas_approved,
                ),

                HelloRole::Responder => establish_responder(
                    &mut demux,
                    &self.identity,
                    Some(previous_session_id),
                    sas_approved,
                ),
            };

            self.pending.extend(demux.take_buffered());

            let candidate = match result {
                Ok(candidate) => candidate,

                Err(error) => {
                    let mut manager = self
                        .manager
                        .lock()
                        .expect("manager mutex is not poisoned");

                    let _ = manager.abort_rekey();

                    return Err(error);
                }
            };

            if let Err(error) = {
                let mut manager = self
                    .manager
                    .lock()
                    .expect("manager mutex is not poisoned");

                manager.complete_rekey(candidate, local_role, now)
            } {
                let mut manager = self
                    .manager
                    .lock()
                    .expect("manager mutex is not poisoned");

                let _ = manager.abort_rekey();

                return Err(error);
            }
        }

        Ok(())
    }

    pub fn expire_drain(&mut self, now: Instant) {
        self.manager
            .lock()
            .expect("manager mutex is not poisoned")
            .expire_drain(now);
    }
}

/// The send/close half produced by [`PeerConnection::split_tcp`].
#[derive(Clone)]
pub struct TcpConnectionWriter {
    manager: std::sync::Arc<std::sync::Mutex<SessionManager>>,
    write: std::sync::Arc<std::sync::Mutex<std::net::TcpStream>>,
}

impl TcpConnectionWriter {
    pub fn send(&self, content: &[u8]) -> Result<()> {
        let frame = self
            .manager
            .lock()
            .expect("manager mutex is not poisoned")
            .encrypt(content)?;

        self.write_frame(&frame)
    }

    pub fn close(&self, reason: CloseReason) -> Result<()> {
        let session_id = self
            .manager
            .lock()
            .expect("manager mutex is not poisoned")
            .active_session_id();

        let frame = ClosePayload {
            session_id: Some(session_id),
            reason,
            detail: None,
        }
        .encode()?;

        self.write_frame(&frame)?;

        self.manager
            .lock()
            .expect("manager mutex is not poisoned")
            .close();
        if let Ok(write) = self.write.lock() {
            let _ = write.shutdown(std::net::Shutdown::Both);
        }

        Ok(())
    }

    fn write_frame(&self, frame: &Frame) -> Result<()> {
        use std::io::Write;

        let bytes = frame.encode()?;

        let mut write = self
            .write
            .lock()
            .expect("write mutex is not poisoned");

        write
            .write_all(&bytes)
            .map_err(|error| Error::Transport(error.to_string()))?;

        write
            .flush()
            .map_err(|error| Error::Transport(error.to_string()))
    }
}