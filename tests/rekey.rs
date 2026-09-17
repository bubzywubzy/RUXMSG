use std::thread;
use std::time::{Duration, Instant};

use ruxmsg::crypto::IdentityKeypair;
use ruxmsg::engine::{establish_initiator, establish_responder};
use ruxmsg::handshake::HelloRole;
use ruxmsg::manager::SessionManager;
use ruxmsg::session::SessionState;
use ruxmsg::transport::InMemoryTransport;

#[test]
fn rekey_over_a_live_transport_replaces_the_session_and_drains_the_old_one() {
    let (mut initiator_transport, mut responder_transport) = InMemoryTransport::pair();
    let initiator_identity = IdentityKeypair::from_bytes(&[1; 32]);
    let responder_identity = IdentityKeypair::from_bytes(&[2; 32]);

    let responder_thread = thread::spawn(move || {
        let initial =
            establish_responder(&mut responder_transport, &responder_identity, None, |_| {
                true
            })
            .unwrap();
        let mut manager =
            SessionManager::from_initial_handshake(initial, HelloRole::Responder, Instant::now())
                .unwrap();
        let old_id = manager.active_session_id();

        manager.begin_rekey().unwrap();
        let candidate = establish_responder(
            &mut responder_transport,
            &responder_identity,
            Some(old_id),
            |_| true,
        )
        .unwrap();
        manager
            .complete_rekey(candidate, HelloRole::Responder, Instant::now())
            .unwrap();
        (old_id, manager.active_session_id())
    });

    let initial = establish_initiator(&mut initiator_transport, &initiator_identity, None, |_| {
        true
    })
    .unwrap();
    let mut manager =
        SessionManager::from_initial_handshake(initial, HelloRole::Initiator, Instant::now())
            .unwrap();
    let old_id = manager.active_session_id();

    manager.begin_rekey().unwrap();
    // The active session keeps sending while the rekey candidate negotiates.
    manager.encrypt(b"still on the old session").unwrap();
    let candidate = establish_initiator(
        &mut initiator_transport,
        &initiator_identity,
        Some(old_id),
        |_| true,
    )
    .unwrap();
    manager
        .complete_rekey(candidate, HelloRole::Initiator, Instant::now())
        .unwrap();

    let (responder_old_id, responder_new_id) = responder_thread.join().unwrap();

    assert_eq!(old_id, responder_old_id);
    assert_eq!(manager.active_session_id(), responder_new_id);
    assert_ne!(old_id, manager.active_session_id());

    let draining = manager.draining().unwrap();
    assert_eq!(draining.session_id(), old_id);
    assert_eq!(draining.state(), SessionState::Draining);
    assert!(!draining.can_originate_data());

    manager.expire_drain(Instant::now() + Duration::from_secs(16));
    assert!(manager.draining().is_none());
}
