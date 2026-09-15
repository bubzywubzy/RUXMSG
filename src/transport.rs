//! Framed transport abstractions used by handshake, session, and connection code.
//!
//! A transport moves complete RUXMSG [`Frame`] values. It is responsible for
//! I/O and framing, not for peer authentication or message confidentiality.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::sync::mpsc::{self, Receiver, Sender};

use crate::error::{Error, Result};
use crate::protocol::MessageType;
use crate::wire::Frame;

pub trait Transport {
    /// Sends one complete protocol frame.
    fn send(&mut self, frame: &Frame) -> Result<()>;
    /// Receives one complete protocol frame, blocking as appropriate for the transport.
    fn receive(&mut self) -> Result<Frame>;
    /// Closes the transport and releases its I/O resources.
    fn close(&mut self) -> Result<()>;
}

/// Wraps a live `Transport` during a handshake/rekey exchange so that DATA and
/// CLOSE frames arriving out of turn (the peer's active session is still
/// usable while a rekey negotiates) are buffered instead of breaking the
/// handshake's strict expected-frame-type reads.
pub struct Demuxer<'a, T: Transport> {
    inner: &'a mut T,
    buffered: VecDeque<Frame>,
}

impl<'a, T: Transport> Demuxer<'a, T> {
    pub fn new(inner: &'a mut T) -> Self {
        Self {
            inner,
            buffered: VecDeque::new(),
        }
    }

    /// Consumes the demuxer, returning any DATA/CLOSE frames buffered while
    /// waiting for handshake/rekey frames, in receipt order.
    pub fn take_buffered(self) -> VecDeque<Frame> {
        self.buffered
    }
}

impl<T: Transport> Transport for Demuxer<'_, T> {
    fn send(&mut self, frame: &Frame) -> Result<()> {
        self.inner.send(frame)
    }

    fn receive(&mut self) -> Result<Frame> {
        loop {
            let frame = self.inner.receive()?;
            if matches!(frame.message_type, MessageType::Data | MessageType::Close) {
                self.buffered.push_back(frame);
                continue;
            }
            return Ok(frame);
        }
    }

    fn close(&mut self) -> Result<()> {
        self.inner.close()
    }
}

pub struct InMemoryTransport {
    incoming: Receiver<Vec<u8>>,
    outgoing: Sender<Vec<u8>>,
    closed: bool,
}

impl InMemoryTransport {
    /// Creates two connected endpoints for deterministic tests.
    pub fn pair() -> (Self, Self) {
        let (a_tx, a_rx) = mpsc::channel();
        let (b_tx, b_rx) = mpsc::channel();
        (
            Self {
                incoming: a_rx,
                outgoing: b_tx,
                closed: false,
            },
            Self {
                incoming: b_rx,
                outgoing: a_tx,
                closed: false,
            },
        )
    }
}

impl Transport for InMemoryTransport {
    fn send(&mut self, frame: &Frame) -> Result<()> {
        if self.closed {
            return Err(Error::TransportClosed);
        }
        self.outgoing
            .send(frame.encode()?)
            .map_err(|_| Error::TransportClosed)
    }

    fn receive(&mut self) -> Result<Frame> {
        if self.closed {
            return Err(Error::TransportClosed);
        }
        let bytes = self.incoming.recv().map_err(|_| Error::TransportClosed)?;
        let (frame, consumed) = Frame::decode(&bytes)?;
        if consumed != bytes.len() {
            return Err(Error::TrailingFrameBytes);
        }
        Ok(frame)
    }

    fn close(&mut self) -> Result<()> {
        self.closed = true;
        Ok(())
    }
}

pub struct FramedTransport<S> {
    stream: S,
    closed: bool,
}

impl<S> FramedTransport<S> {
    /// Wraps a readable/writable stream in the RUXMSG six-byte frame format.
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            closed: false,
        }
    }

    /// Reclaims the underlying stream; used by callers that need to split a
    /// duplex socket into independent read/write handles after handshake.
    pub(crate) fn into_inner(self) -> S {
        self.stream
    }
}

impl<S: Read + Write> Transport for FramedTransport<S> {
    fn send(&mut self, frame: &Frame) -> Result<()> {
        if self.closed {
            return Err(Error::TransportClosed);
        }
        let bytes = frame.encode()?;
        self.stream.write_all(&bytes).map_err(io_error)?;
        self.stream.flush().map_err(io_error)
    }

    fn receive(&mut self) -> Result<Frame> {
        if self.closed {
            return Err(Error::TransportClosed);
        }
        let mut header = [0; 6];
        self.stream.read_exact(&mut header).map_err(io_error)?;
        let length = u32::from_be_bytes(header[2..6].try_into().expect("header has four bytes"));
        crate::protocol::FrameLength::new(length)?;
        let mut bytes = Vec::with_capacity(6 + length as usize);
        bytes.extend_from_slice(&header);
        let mut payload = vec![0; length as usize];
        self.stream.read_exact(&mut payload).map_err(io_error)?;
        bytes.extend_from_slice(&payload);
        let (frame, consumed) = Frame::decode(&bytes)?;
        if consumed != bytes.len() {
            return Err(Error::TrailingFrameBytes);
        }
        Ok(frame)
    }

    fn close(&mut self) -> Result<()> {
        self.closed = true;
        Ok(())
    }
}

fn io_error(error: io::Error) -> Error {
    Error::Transport(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::MessageType;

    #[test]
    fn in_memory_pair_transfers_framed_messages() {
        let (mut left, mut right) = InMemoryTransport::pair();
        let frame = Frame::new(MessageType::Close, vec![0xa0]).unwrap();
        left.send(&frame).unwrap();
        assert_eq!(right.receive().unwrap(), frame);
    }
}
