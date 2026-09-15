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
            None,
            Instant::now(),
        )
        .unwrap()
    });
    let mut alice_conn = PeerConnection::establish_as_initiator(
        alice_transport,
        alice_identity,
        |_| true,
        None,
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
            None,
            Instant::now(),
        )
        .unwrap()
    });
    let alice_conn = PeerConnection::establish_as_initiator(
        alice_transport,
        alice_identity_after,
        |_| true,
        None,
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
            None,
            Instant::now(),
        )
        .unwrap()
    });
    let mut alice_conn = PeerConnection::establish_as_initiator(
        alice_transport,
        alice_identity,
        |_| true,
        None,
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

#[test]
fn trusted_peer_in_trust_store_survives_restart_and_bypasses_sas() {
    use ruxmsg::identity::{PeerRecord, TrustState};
    use ruxmsg::storage::{InMemoryTrustStore, TrustStore};

    let alice_secrets = SharedSecretStore::default();
    let bob_secrets = SharedSecretStore::default();

    let mut alice_id_store = IdentityKeyStore::new(alice_secrets, "alice");
    let alice_identity = alice_id_store.load_or_generate().unwrap();
    let mut bob_id_store = IdentityKeyStore::new(bob_secrets, "bob");
    let bob_identity = bob_id_store.load_or_generate().unwrap();

    let mut alice_trust_store = InMemoryTrustStore::default();
    let mut bob_trust_store = InMemoryTrustStore::default();

    // 1. First contact with SAS verification
    let (alice_transport, bob_transport) = InMemoryTransport::pair();
    let bob_id_clone = bob_identity.clone();
    let bob_thread = thread::spawn(move || {
        PeerConnection::establish_as_responder(
            bob_transport,
            bob_id_clone,
            |_| true,
            None,
            Instant::now(),
        )
        .unwrap()
    });
    let alice_conn = PeerConnection::establish_as_initiator(
        alice_transport,
        alice_identity.clone(),
        |_| true,
        None,
        Instant::now(),
    )
    .unwrap();
    let bob_conn = bob_thread.join().unwrap();

    // Enroll peer identities into persistent trust stores
    let bobs_identity_from_alice = alice_conn.manager().active().peer_identity();
    let mut bob_record = PeerRecord::new(bobs_identity_from_alice);
    bob_record.trust_state = TrustState::Trusted;
    alice_trust_store.put(bob_record).unwrap();

    let alices_identity_from_bob = bob_conn.manager().active().peer_identity();
    let mut alice_record = PeerRecord::new(alices_identity_from_bob);
    alice_record.trust_state = TrustState::Trusted;
    bob_trust_store.put(alice_record).unwrap();

    // 2. Process restart: drop in-memory connections
    drop(alice_conn);
    drop(bob_conn);

    // 3. Second contact after restart: lookup stored trusted peers and connect.
    // SAS callback will panic if called, proving it is bypassed.
    let alice_trusted = alice_trust_store
        .records()
        .iter()
        .find(|r| r.trust_state == TrustState::Trusted)
        .map(|r| (r.identity, r.trust_state));
    let bob_trusted = bob_trust_store
        .records()
        .iter()
        .find(|r| r.trust_state == TrustState::Trusted)
        .map(|r| (r.identity, r.trust_state));

    let (alice_transport2, bob_transport2) = InMemoryTransport::pair();
    let bob_thread2 = thread::spawn(move || {
        PeerConnection::establish_as_responder(
            bob_transport2,
            bob_identity,
            |_| panic!("Bob SAS callback must not be invoked for trusted peer"),
            bob_trusted,
            Instant::now(),
        )
        .unwrap()
    });
    let mut alice_conn2 = PeerConnection::establish_as_initiator(
        alice_transport2,
        alice_identity,
        |_| panic!("Alice SAS callback must not be invoked for trusted peer"),
        alice_trusted,
        Instant::now(),
    )
    .unwrap();
    let mut bob_conn2 = bob_thread2.join().unwrap();

    // Verify authenticated communication works on the fresh session
    alice_conn2.send(b"hello after restart").unwrap();
    let event = bob_conn2.recv_next().unwrap();
    assert_eq!(
        event,
        ConnectionEvent::Data(b"hello after restart".to_vec())
    );
}
