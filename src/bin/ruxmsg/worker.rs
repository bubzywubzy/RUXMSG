//! Per-connection session worker.

use std::collections::HashMap;
use std::net::TcpStream;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use ruxmsg::close::CloseReason;
use ruxmsg::connection::{ConnectionEvent, PeerConnection};
use ruxmsg::crypto::IdentityKeypair;
use ruxmsg::transport::FramedTransport;

use crate::app::*;
use crate::events::*;

// NETWORK SESSION WORKER
// =====================================================================

pub(crate) fn spawn_session(
    stream: TcpStream,
    identity: Arc<IdentityKeypair>,
    as_initiator: bool,
    label: String,
    remote_addr: String,
    sessions: Arc<Mutex<HashMap<String, PeerHandle>>>,
    events_tx: mpsc::Sender<NetEvent>,
) {
    let (tx, rx) = mpsc::channel::<SessionCommand>();

    {
        let mut sessions_guard = match sessions.lock() {
            Ok(guard) => guard,
            Err(_) => return,
        };

        sessions_guard.insert(
            label.clone(),
            PeerHandle {
                remote_addr,
                fingerprint: None,
                status: SessionStatus::Handshaking,
                outbound: as_initiator,
                tx,
            },
        );
    }

    thread::spawn(move || {
        let transport = FramedTransport::new(stream);

        let sas_events_tx = events_tx.clone();
        let sas_label = label.clone();

        let sas_approved = move |words: [&'static str; 3]| -> bool {
            let (answer_tx, answer_rx) = mpsc::channel();

            if sas_events_tx
                .send(NetEvent::Sas {
                    label: sas_label.clone(),
                    words,
                    answer_tx,
                })
                .is_err()
            {
                return false;
            }

            answer_rx.recv().unwrap_or(false)
        };

        let established = if as_initiator {
            PeerConnection::establish_as_initiator(
                transport,
                (*identity).clone(),
                sas_approved,
                Instant::now(),
            )
        } else {
            PeerConnection::establish_as_responder(
                transport,
                (*identity).clone(),
                sas_approved,
                Instant::now(),
            )
        };

        let connection = match established {
            Ok(connection) => connection,

            Err(error) => {
                let _ = events_tx.send(NetEvent::Error {
                    label: label.clone(),
                    message: error.to_string(),
                });

                if let Ok(mut sessions) = sessions.lock() {
                    sessions.remove(&label);
                }

                return;
            }
        };

        let fingerprint = format_identity(&connection.manager().active().peer_identity());

        let (mut reader, writer) = match connection.split_tcp() {
            Ok(halves) => halves,

            Err(error) => {
                let _ = events_tx.send(NetEvent::Error {
                    label: label.clone(),
                    message: error.to_string(),
                });

                if let Ok(mut sessions) = sessions.lock() {
                    sessions.remove(&label);
                }

                return;
            }
        };

        if let Ok(mut sessions) = sessions.lock()
            && let Some(handle) = sessions.get_mut(&label)
        {
            handle.fingerprint = Some(fingerprint.clone());
            handle.status = SessionStatus::Connected;
        }

        let _ = events_tx.send(NetEvent::Ready {
            label: label.clone(),
            fingerprint,
        });

        let writer_events_tx = events_tx.clone();
        let writer_label = label.clone();

        let writer_thread = thread::spawn(move || {
            for command in rx {
                match command {
                    SessionCommand::Send(text) => {
                        if let Err(error) = writer.send(text.as_bytes()) {
                            let _ = writer_events_tx.send(NetEvent::Error {
                                label: writer_label.clone(),
                                message: error.to_string(),
                            });

                            break;
                        }
                    }

                    SessionCommand::Close => {
                        let _ = writer.close(CloseReason::Normal);
                        break;
                    }
                }
            }
        });

        loop {
            match reader.recv_next() {
                Ok(ConnectionEvent::Data(bytes)) => {
                    let text = ruxmsg::display::sanitize_for_display(&String::from_utf8_lossy(&bytes));

                    if events_tx
                        .send(NetEvent::Message {
                            label: label.clone(),
                            text,
                        })
                        .is_err()
                    {
                        break;
                    }
                }

                Ok(ConnectionEvent::PeerClosed(reason)) => {
                    let _ = events_tx.send(NetEvent::PeerClosed {
                        label: label.clone(),
                        reason,
                    });

                    break;
                }

                Err(error) => {
                    let _ = events_tx.send(NetEvent::Error {
                        label: label.clone(),
                        message: error.to_string(),
                    });

                    break;
                }
            }
        }

        let _ = writer_thread.join();

        if let Ok(mut sessions) = sessions.lock() {
            sessions.remove(&label);
        }
    });
}
