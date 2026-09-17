use std::thread;

use ruxmsg::crypto::IdentityKeypair;
use ruxmsg::engine::{establish_initiator, establish_responder};
use ruxmsg::transport::InMemoryTransport;

#[test]
fn peers_complete_hello_signature_and_confirmation_exchange() {
    let (mut initiator_transport, mut responder_transport) = InMemoryTransport::pair();
    let initiator_identity = IdentityKeypair::from_bytes(&[1; 32]);
    let responder_identity = IdentityKeypair::from_bytes(&[2; 32]);
    let initiator_public = initiator_identity.identity();
    let responder_public = responder_identity.identity();
    let responder = thread::spawn(move || {
        establish_responder(&mut responder_transport, &responder_identity, None, |_| {
            true
        })
        .unwrap()
    });
    let initiator =
        establish_initiator(&mut initiator_transport, &initiator_identity, None, |_| {
            true
        })
        .unwrap();
    let responder = responder.join().unwrap();
    assert_eq!(initiator.peer_identity, responder_public);
    assert_eq!(responder.peer_identity, initiator_public);
    assert_eq!(initiator.transcript_hash, responder.transcript_hash);
    assert_eq!(initiator.keys.session_id, responder.keys.session_id);
}
