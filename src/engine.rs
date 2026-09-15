//! Blocking initiator and responder handshake drivers.
//!
//! A successful function call means transcript authentication, SAS approval,
//! key derivation, and both confirmation checks completed. The returned
//! session is not persisted; callers own its lifecycle.

use rand_core::{OsRng, RngCore};

use crate::crypto::{EphemeralKeypair, IdentityKeypair, SessionKeys, transcript_hash};
use crate::error::{Error, Result};
use crate::handshake::{
    HandshakePayload, HandshakePurpose, HandshakeType, HelloPayload, HelloRole,
    SessionConfirmPayload, transcript_from_hellos, verify_handshake_for_role,
};
use crate::identity::{PeerIdentity, TrustState};
use crate::protocol::SessionId;
use crate::transport::Transport;

#[derive(Debug)]
pub struct EstablishedSession {
    /// Keys and session identifier derived from the authenticated transcript.
    pub keys: SessionKeys,
    /// Hash displayed indirectly through the SAS and authenticated by both peers.
    pub transcript_hash: [u8; 32],
    /// The remote persistent identity authenticated by the handshake.
    pub peer_identity: PeerIdentity,
}

fn fresh_nonce() -> [u8; 16] {
    let mut nonce = [0; 16];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

fn purpose_from_previous(previous: Option<SessionId>) -> HandshakePurpose {
    if previous.is_some() {
        HandshakePurpose::Rekey
    } else {
        HandshakePurpose::Initial
    }
}

/// Runs the complete blocking handshake from the initiator role.
///
/// The SAS callback receives the current transcript's three words. A trusted
/// identity may bypass the callback only when its state is `Trusted` and its
/// public key matches the authenticated peer.
pub fn establish_initiator<T, F>(
    transport: &mut T,
    identity: &IdentityKeypair,
    previous_session_id: Option<SessionId>,
    sas_approved: F,
    trusted_identity: Option<(PeerIdentity, TrustState)>,
) -> Result<EstablishedSession>
where
    T: Transport,
    F: FnOnce([&'static str; 3]) -> bool,
{
    let ephemeral = EphemeralKeypair::generate();
    let local_hello = HelloPayload {
        cipher_suite: 1,
        purpose: purpose_from_previous(previous_session_id),
        role: HelloRole::Initiator,
        identity_public_key: identity.identity(),
        ephemeral_public_key: ephemeral.public_key(),
        nonce: fresh_nonce(),
        previous_session_id,
    };
    transport.send(&local_hello.encode()?)?;
    let remote_hello = HelloPayload::decode(&transport.receive()?)?;
    let shared_secret = ephemeral.shared_secret(&remote_hello.ephemeral_public_key)?;
    let transcript = transcript_from_hellos(&local_hello, &remote_hello)?;
    let transcript_bytes = transcript.encode()?;
    let hash = transcript_hash(&transcript_bytes);
    let remote_is_trusted = matches!(
        trusted_identity,
        Some((trusted_key, TrustState::Trusted)) if trusted_key == remote_hello.identity_public_key
    );
    if !remote_is_trusted && !sas_approved(crate::crypto::sas_words(&hash)) {
        return Err(Error::SasRejected);
    }
    let auth = HandshakePayload {
        handshake_type: HandshakeType::try_from(transcript.handshake_type as u64)?,
        stage: 0,
        cipher_suite: transcript.cipher_suite,
        initiator_identity: transcript.initiator_identity,
        responder_identity: transcript.responder_identity,
        initiator_ephemeral: transcript.initiator_ephemeral,
        responder_ephemeral: transcript.responder_ephemeral,
        initiator_nonce: transcript.initiator_nonce,
        responder_nonce: transcript.responder_nonce,
        previous_session_id: transcript.previous_session_id,
        initiator_signature: identity.sign_transcript(&hash, true),
        responder_signature: None,
    };
    transport.send(&auth.encode()?)?;
    let response = HandshakePayload::decode(&transport.receive()?)?;
    let (keys, _) = verify_handshake_for_role(
        &response,
        &shared_secret,
        true,
        trusted_identity,
        HelloRole::Initiator,
    )?;
    let initiator_confirm = SessionConfirmPayload {
        session_id: keys.session_id,
        role: 0,
        confirmation: crate::crypto::confirmation_mac(&keys.confirmation_key, &hash, true),
    };
    transport.send(&initiator_confirm.encode()?)?;
    let responder_confirm = SessionConfirmPayload::decode(&transport.receive()?)?;
    responder_confirm.verify(&keys, &hash)?;
    Ok(EstablishedSession {
        keys,
        transcript_hash: hash,
        peer_identity: response.responder_identity,
    })
}

/// Runs the complete blocking handshake from the responder role.
///
/// The SAS callback receives the current transcript's three words. A trusted
/// identity may bypass the callback only when its state is `Trusted` and its
/// public key matches the authenticated peer.
pub fn establish_responder<T, F>(
    transport: &mut T,
    identity: &IdentityKeypair,
    previous_session_id: Option<SessionId>,
    sas_approved: F,
    trusted_identity: Option<(PeerIdentity, TrustState)>,
) -> Result<EstablishedSession>
where
    T: Transport,
    F: FnOnce([&'static str; 3]) -> bool,
{
    let remote_hello = HelloPayload::decode(&transport.receive()?)?;
    if remote_hello.role != HelloRole::Initiator
        || remote_hello.previous_session_id != previous_session_id
    {
        return Err(Error::InvalidHandshake);
    }
    let ephemeral = EphemeralKeypair::generate();
    let shared_secret = ephemeral.shared_secret(&remote_hello.ephemeral_public_key)?;
    let local_hello = HelloPayload {
        cipher_suite: remote_hello.cipher_suite,
        purpose: remote_hello.purpose,
        role: HelloRole::Responder,
        identity_public_key: identity.identity(),
        ephemeral_public_key: ephemeral.public_key(),
        nonce: fresh_nonce(),
        previous_session_id,
    };
    transport.send(&local_hello.encode()?)?;
    let transcript = transcript_from_hellos(&remote_hello, &local_hello)?;
    let hash = transcript_hash(&transcript.encode()?);
    let remote_is_trusted = matches!(
        trusted_identity,
        Some((trusted_key, TrustState::Trusted)) if trusted_key == remote_hello.identity_public_key
    );
    if !remote_is_trusted && !sas_approved(crate::crypto::sas_words(&hash)) {
        return Err(Error::SasRejected);
    }
    let request = HandshakePayload::decode(&transport.receive()?)?;
    let (candidate_keys, _) = verify_handshake_for_role(
        &request,
        &shared_secret,
        true,
        trusted_identity,
        HelloRole::Responder,
    )?;
    let response = HandshakePayload {
        handshake_type: HandshakeType::try_from(transcript.handshake_type as u64)?,
        stage: 1,
        cipher_suite: transcript.cipher_suite,
        initiator_identity: transcript.initiator_identity,
        responder_identity: transcript.responder_identity,
        initiator_ephemeral: transcript.initiator_ephemeral,
        responder_ephemeral: transcript.responder_ephemeral,
        initiator_nonce: transcript.initiator_nonce,
        responder_nonce: transcript.responder_nonce,
        previous_session_id: transcript.previous_session_id,
        initiator_signature: request.initiator_signature,
        responder_signature: Some(identity.sign_transcript(&hash, false)),
    };
    transport.send(&response.encode()?)?;
    let initiator_confirm = SessionConfirmPayload::decode(&transport.receive()?)?;
    initiator_confirm.verify(&candidate_keys, &hash)?;
    let responder_confirm = SessionConfirmPayload {
        session_id: candidate_keys.session_id,
        role: 1,
        confirmation: crate::crypto::confirmation_mac(
            &candidate_keys.confirmation_key,
            &hash,
            false,
        ),
    };
    transport.send(&responder_confirm.encode()?)?;
    Ok(EstablishedSession {
        keys: candidate_keys,
        transcript_hash: hash,
        peer_identity: request.initiator_identity,
    })
}
