use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use ruxmsg::connection::{ConnectionEvent, PeerConnection};
use ruxmsg::error::Result;
use ruxmsg::storage::{IdentityKeyStore, SecretStore};
use ruxmsg::transport::InMemoryTransport;

/// Stands in for the OS keychain: the same backing map is reused across the
/// "before restart" and "after restart" `IdentityKeyStore`s in this test,
/// mirroring how real keychain contents survive a process restart.
#[derive(Clone, Default)]
struct SharedSecretStore(Arc<Mutex<HashMap<String, Vec<u8>>>>);

impl SecretStore for SharedSecretStore {
    fn get_secret(&self, account: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.0.lock().unwrap().get(account).cloned())
    }

    fn set_secret(&mut self, account: &str, value: &[u8]) -> Result<()> {
        self.0
            .lock()
            .unwrap()
            .insert(account.to_string(), value.to_vec());
        Ok(())
    }
}

#[test]
fn process_restart_requires_a_fresh_session_but_keeps_the_persisted_identity() {
    let alice_secrets = SharedSecretStore::default();
    let bob_secrets = SharedSecretStore::default();

    let alice_identity = IdentityKeyStore::new(alice_secrets.clone(), "alice")
        .load_or_generate()
        .unwrap();
    let bob_identity = IdentityKeyStore::new(bob_secrets.clone(), "bob")
        .load_or_generate()
        .unwrap();
    let alice_public_before = alice_identity.identity();

    let (alice_transport, bob_transport) = InMemoryTransport::pair();
    let bob_thread = thread::spawn(move || {
        PeerConnection::establish_as_responder(
            bob_transport,
            bob_identity,
            |_| true,
            Instant::now(),
        )
        .unwrap()
    });
    let mut alice_conn = PeerConnection::establish_as_initiator(
        alice_transport,
        alice_identity,
        |_| true,
        Instant::now(),
    )
    .unwrap();
    let mut bob_conn = bob_thread.join().unwrap();
    let session_before = alice_conn.manager().active_session_id();

    alice_conn.send(b"before restart").unwrap();
    bob_conn.recv_next().unwrap();

    // Simulate a process restart: all in-memory session/connection state is
    // destroyed; only the keychain-backed identity survives, per D-008.
    drop(alice_conn);
    drop(bob_conn);

    let alice_identity_after = IdentityKeyStore::new(alice_secrets, "alice")
        .load()
        .unwrap()
        .expect("identity must survive a restart");
    let bob_identity_after = IdentityKeyStore::new(bob_secrets, "bob")
        .load()
        .unwrap()
        .expect("identity must survive a restart");
    assert_eq!(alice_identity_after.identity(), alice_public_before);

    let (alice_transport, bob_transport) = InMemoryTransport::pair();
    let bob_thread = thread::spawn(move || {
        PeerConnection::establish_as_responder(
            bob_transport,
            bob_identity_after,
            |_| true,
            Instant::now(),
        )
        .unwrap()
    });
    let alice_conn = PeerConnection::establish_as_initiator(
        alice_transport,
        alice_identity_after,
        |_| true,
        Instant::now(),
    )
    .unwrap();
    bob_thread.join().unwrap();
    let session_after = alice_conn.manager().active_session_id();

    assert_ne!(
        session_before, session_after,
        "a restart must require a fresh handshake and never reuse the old session"
    );
}

#[test]
fn transport_reconnect_without_a_restart_preserves_the_existing_session() {
    let secrets = SharedSecretStore::default();
    let alice_identity = IdentityKeyStore::new(secrets.clone(), "alice")
        .load_or_generate()
        .unwrap();
    let bob_identity = IdentityKeyStore::new(secrets, "bob")
        .load_or_generate()
        .unwrap();

    let (alice_transport, bob_transport) = InMemoryTransport::pair();
    let bob_thread = thread::spawn(move || {
        PeerConnection::establish_as_responder(
            bob_transport,
            bob_identity,
            |_| true,
            Instant::now(),
        )
        .unwrap()
    });
    let mut alice_conn = PeerConnection::establish_as_initiator(
        alice_transport,
        alice_identity,
        |_| true,
        Instant::now(),
    )
    .unwrap();
    let mut bob_conn = bob_thread.join().unwrap();
    let session_id = alice_conn.manager().active_session_id();

    // A transport reconnect (no process restart) must not force a new handshake:
    // the existing session keeps sending/receiving DATA across it.
    alice_conn.send(b"still the same session").unwrap();
    let event = bob_conn.recv_next().unwrap();
    assert_eq!(
        event,
        ConnectionEvent::Data(b"still the same session".to_vec())
    );
    assert_eq!(bob_conn.manager().active_session_id(), session_id);
}
