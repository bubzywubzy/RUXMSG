use std::thread;
use std::time::Instant;

use ruxmsg::connection::{ConnectionEvent, PeerConnection};
use ruxmsg::crypto::IdentityKeypair;
use ruxmsg::transport::InMemoryTransport;

#[test]
fn data_frame_queued_before_a_rekey_survives_the_interleaved_handshake() {
    let (initiator_transport, responder_transport) = InMemoryTransport::pair();
    let initiator_identity = IdentityKeypair::from_bytes(&[1; 32]);

    let responder_thread = thread::spawn(move || {
        let mut responder = PeerConnection::establish_as_responder(
            responder_transport,
            IdentityKeypair::from_bytes(&[2; 32]),
            |_| true,
            Instant::now(),
        )
        .unwrap();
        // Rekey concurrently with the DATA frame the initiator queued below;
        // the responder's own rekey handshake must buffer it, not choke on it.
        responder.rekey(|_| true, Instant::now()).unwrap();
        let event = responder.recv_next().unwrap();
        (responder, event)
    });

    let mut initiator = PeerConnection::establish_as_initiator(
        initiator_transport,
        initiator_identity,
        |_| true,
        Instant::now(),
    )
    .unwrap();

    // Queued on the wire before the rekey handshake frames.
    initiator.send(b"queued before rekey").unwrap();
    initiator.rekey(|_| true, Instant::now()).unwrap();

    let (mut responder, event) = responder_thread.join().unwrap();
    assert_eq!(
        event,
        ConnectionEvent::Data(b"queued before rekey".to_vec())
    );

    // The rekeyed session still works for ordinary traffic afterward.
    initiator.send(b"after rekey").unwrap();
    assert_eq!(
        responder.recv_next().unwrap(),
        ConnectionEvent::Data(b"after rekey".to_vec())
    );
}
