use bip39::Language;
use sha2::{Digest, Sha256};

use ruxmsg::crypto::{
    confirmation_mac, derive_message_key, derive_session_keys, message_nonce, sas_indices,
    sas_words, transcript_hash, verify_confirmation, verify_transcript_signature, EphemeralKeypair,
    IdentityKeypair,
};
use ruxmsg::data::{DataPlaintext, DataReceiver, DataSender};
use ruxmsg::encoding::Transcript;
use ruxmsg::error::Error;
use ruxmsg::handshake::{
    transcript_from_hellos, verify_handshake, HandshakePayload, HandshakePurpose, HandshakeType,
    HelloPayload, HelloRole, SessionConfirmPayload,
};
use ruxmsg::identity::PeerIdentity;
use ruxmsg::protocol::{
    DirectionId, FrameLength, MessageType, ProtocolVersion, SessionId, DEFAULT_PADDING_QUANTUM,
    MAX_FRAME_SIZE,
};
use ruxmsg::ratchet::{ReceivingChain, ReplayStatus, ReplayWindow};
use ruxmsg::wire::Frame;

#[test]
fn bip39_wordlist_matches_pinned_protocol_artifact() {
    // SAS depends on the exact BIP-39 English word list. A changed upstream
    // dependency must therefore fail loudly rather than silently changing
    // the words displayed to users.
    let words = Language::English.word_list();

    assert_eq!(words.len(), 2048);

    let mut corpus = Vec::with_capacity(words.len() * 8);
    for word in words {
        corpus.extend_from_slice(word.as_bytes());
        corpus.push(b'\n');
    }

    let digest = Sha256::digest(&corpus);
    let hash = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    assert_eq!(
        hash,
        "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
    );
}

#[test]
fn sas_uses_exact_33_bit_msb_first_mapping() {
    // Three 11-bit words consume exactly 33 bits of the transcript hash.
    // This test isolates every byte boundary involved in that extraction.
    let zero = [0u8; 32];
    let indices = sas_indices(&zero);

    assert_eq!(indices.first, 0);
    assert_eq!(indices.second, 0);
    assert_eq!(indices.third, 0);
    assert_eq!(sas_words(&zero), ["abandon", "abandon", "abandon"]);

    // Only H[0..4], with bit 7 of H[4], contributes to the SAS.
    let mut all_ones = [0u8; 32];
    all_ones[..4].fill(0xff);
    all_ones[4] = 0x80;

    let indices = sas_indices(&all_ones);

    assert_eq!(indices.first, 2047);
    assert_eq!(indices.second, 2047);
    assert_eq!(indices.third, 2047);
    assert_eq!(sas_words(&all_ones), ["zoo", "zoo", "zoo"]);

    // H[0] bit 0 becomes bit 3 of the first 11-bit index.
    let mut hash = [0u8; 32];
    hash[0] = 0x01;

    let indices = sas_indices(&hash);
    assert_eq!(indices.first, 0x008);
    assert_eq!(indices.second, 0);
    assert_eq!(indices.third, 0);

    // H[1] bit 7 becomes bit 2 of the first index.
    hash = [0u8; 32];
    hash[1] = 0x80;

    let indices = sas_indices(&hash);
    assert_eq!(indices.first, 0x004);
    assert_eq!(indices.second, 0);
    assert_eq!(indices.third, 0);

    // H[1] bit 5 is the final bit of the first index.
    hash = [0u8; 32];
    hash[1] = 0x20;

    let indices = sas_indices(&hash);
    assert_eq!(indices.first, 0x001);
    assert_eq!(indices.second, 0);
    assert_eq!(indices.third, 0);

    // H[1] bit 4 is the first bit of the second index.
    hash = [0u8; 32];
    hash[1] = 0x10;

    let indices = sas_indices(&hash);
    assert_eq!(indices.first, 0);
    assert_eq!(indices.second, 0x400);
    assert_eq!(indices.third, 0);

    // H[2] bit 2 is the final bit of the second index.
    hash = [0u8; 32];
    hash[2] = 0x04;

    let indices = sas_indices(&hash);
    assert_eq!(indices.first, 0);
    assert_eq!(indices.second, 0x001);
    assert_eq!(indices.third, 0);

    // H[2] bit 1 is the first bit of the third index.
    hash = [0u8; 32];
    hash[2] = 0x02;

    let indices = sas_indices(&hash);
    assert_eq!(indices.first, 0);
    assert_eq!(indices.second, 0);
    assert_eq!(indices.third, 0x400);

    // The third index spans all of H[3] and the top bit of H[4].
    hash = [0u8; 32];
    hash[3] = 0x01;

    assert_eq!(sas_indices(&hash).third, 0x002);

    hash = [0u8; 32];
    hash[4] = 0x80;

    assert_eq!(sas_indices(&hash).third, 0x001);

    // Bits after the 33rd must have no effect on the SAS.
    let mut baseline = [0u8; 32];
    let baseline_indices = sas_indices(&baseline);

    baseline[4] = 0x7f;
    baseline[5..].fill(0xff);

    assert_eq!(sas_indices(&baseline), baseline_indices);
}

#[test]
fn cryptographic_test_vector_is_deterministic() {
    // Fixed seeds make every primitive below reproducible. This is intended
    // to catch accidental changes to transcript construction, role binding,
    // key derivation, nonce construction, and the data layer.
    let initiator_identity = IdentityKeypair::from_bytes(&[0x10; 32]);
    let responder_identity = IdentityKeypair::from_bytes(&[0x20; 32]);

    let initiator_ephemeral = EphemeralKeypair::from_bytes(&[0x30; 32]);
    let responder_ephemeral = EphemeralKeypair::from_bytes(&[0x40; 32]);

    let initiator_identity_public = initiator_identity.identity();
    let responder_identity_public = responder_identity.identity();

    let initiator_ephemeral_public = initiator_ephemeral.public_key();
    let responder_ephemeral_public = responder_ephemeral.public_key();

    let initiator_shared = initiator_ephemeral
        .shared_secret(&responder_ephemeral_public)
        .unwrap();
    let responder_shared = responder_ephemeral
        .shared_secret(&initiator_ephemeral_public)
        .unwrap();

    assert_eq!(initiator_shared, responder_shared);
    assert_ne!(initiator_shared, [0u8; 32]);

    let transcript = Transcript {
        handshake_type: 0,
        cipher_suite: 1,
        initiator_identity: initiator_identity_public,
        responder_identity: responder_identity_public,
        initiator_ephemeral: initiator_ephemeral_public,
        responder_ephemeral: responder_ephemeral_public,
        initiator_nonce: [0x55; 16],
        responder_nonce: [0x66; 16],
        previous_session_id: None,
    };

    let encoded = transcript.encode().unwrap();
    assert!(!encoded.is_empty());

    // Encoding the same semantic transcript twice must produce identical
    // bytes; otherwise the transcript hash would not be interoperable.
    assert_eq!(encoded, transcript.encode().unwrap());

    let hash = transcript_hash(&encoded);
    assert_eq!(hash, transcript_hash(&encoded));

    // SAS indices must select exactly the words returned by sas_words().
    let indices = sas_indices(&hash);
    let words = sas_words(&hash);
    let word_list = Language::English.word_list();

    assert_eq!(word_list[indices.first as usize], words[0]);
    assert_eq!(word_list[indices.second as usize], words[1]);
    assert_eq!(word_list[indices.third as usize], words[2]);

    let initiator_signature = initiator_identity.sign_transcript(&hash, true);
    let responder_signature = responder_identity.sign_transcript(&hash, false);

    verify_transcript_signature(
        &initiator_identity_public,
        &hash,
        &initiator_signature,
        true,
    )
    .unwrap();

    verify_transcript_signature(
        &responder_identity_public,
        &hash,
        &responder_signature,
        false,
    )
    .unwrap();

    // Role is part of the signature domain. A valid signature for one role
    // must not become valid when interpreted as the other role.
    assert!(
        verify_transcript_signature(
            &initiator_identity_public,
            &hash,
            &initiator_signature,
            false
        )
        .is_err()
    );

    // A signature from another identity must not authenticate the claimed
    // identity even when the transcript hash is identical.
    assert!(
        verify_transcript_signature(
            &responder_identity_public,
            &hash,
            &initiator_signature,
            true
        )
        .is_err()
    );

    let keys = derive_session_keys(&initiator_shared, &hash).unwrap();

    assert_ne!(keys.root_key, [0u8; 32]);
    assert_ne!(keys.initiator_to_responder, [0u8; 32]);
    assert_ne!(keys.responder_to_initiator, [0u8; 32]);
    assert_ne!(keys.confirmation_key, [0u8; 32]);

    // Directional keys must be distinct. Reusing one key in both directions
    // would collapse the protocol's directional separation.
    assert_ne!(
        keys.initiator_to_responder,
        keys.responder_to_initiator
    );

    let initiator_confirmation =
        confirmation_mac(&keys.confirmation_key, &hash, true);
    let responder_confirmation =
        confirmation_mac(&keys.confirmation_key, &hash, false);

    verify_confirmation(
        &keys.confirmation_key,
        &hash,
        &initiator_confirmation,
        true,
    )
    .unwrap();

    verify_confirmation(
        &keys.confirmation_key,
        &hash,
        &responder_confirmation,
        false,
    )
    .unwrap();

    assert!(
        verify_confirmation(
            &keys.confirmation_key,
            &hash,
            &initiator_confirmation,
            false
        )
        .is_err()
    );

    let (message_key_0, chain_key_1) =
        derive_message_key(&keys.initiator_to_responder, DirectionId::InitiatorToResponder);
    let (message_key_1, chain_key_2) =
        derive_message_key(&chain_key_1, DirectionId::InitiatorToResponder);

    assert_ne!(message_key_0, message_key_1);
    assert_ne!(keys.initiator_to_responder, *chain_key_1);
    assert_ne!(chain_key_1, chain_key_2);

    // The nonce construction is deterministic and direction-specific.
    assert_eq!(
        message_nonce(DirectionId::InitiatorToResponder, 0),
        [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(
        message_nonce(DirectionId::InitiatorToResponder, 1),
        [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1]
    );

    let plaintext = b"Normative Test Vector Plaintext";
    let padded = DataPlaintext::padded(plaintext).unwrap();

    assert_eq!(padded.content, plaintext);
    assert!(padded.padding.iter().all(|byte| *byte == 0));

    let encoded_plaintext = padded.encode().unwrap();

    // Padding is selected so the plaintext plus the AEAD tag lands exactly
    // on the protocol's padding quantum.
    assert_eq!(
        (encoded_plaintext.len() + 16) % DEFAULT_PADDING_QUANTUM,
        0
    );

    let mut sender = DataSender::new(
        keys.session_id,
        DirectionId::InitiatorToResponder,
        keys.initiator_to_responder,
    );

    let frame = sender.encrypt(plaintext).unwrap();
    assert_eq!(frame.message_type, MessageType::Data);

    let mut receiver = DataReceiver::new(
        keys.session_id,
        DirectionId::InitiatorToResponder,
        keys.initiator_to_responder,
    );

    assert_eq!(receiver.decrypt(&frame).unwrap(), plaintext);
}

#[test]
fn x25519_rejects_all_zero_shared_secret() {
    // X25519 can produce an all-zero shared secret for low-order inputs.
    // Such a result must never enter the session key schedule.
    let ephemeral = EphemeralKeypair::from_bytes(&[1; 32]);

    assert_eq!(
        ephemeral.shared_secret(&[0u8; 32]),
        Err(Error::AllZeroSharedSecret)
    );
}

#[test]
fn protocol_version_and_message_registry_are_closed() {
    assert_eq!(
        ProtocolVersion::try_from(0x01).unwrap(),
        ProtocolVersion::V1
    );

    for version in [0x00, 0x02, 0xff] {
        assert!(matches!(
            ProtocolVersion::try_from(version),
            Err(Error::UnsupportedVersion(_))
        ));
    }

    assert_eq!(
        MessageType::try_from(0x01).unwrap(),
        MessageType::Handshake
    );
    assert_eq!(
        MessageType::try_from(0x02).unwrap(),
        MessageType::SessionConfirm
    );
    assert_eq!(MessageType::try_from(0x03).unwrap(), MessageType::Data);
    assert_eq!(MessageType::try_from(0x04).unwrap(), MessageType::Rekey);
    assert_eq!(MessageType::try_from(0x05).unwrap(), MessageType::Close);

    for message_type in [0x00, 0x06, 0xff] {
        assert!(matches!(
            MessageType::try_from(message_type),
            Err(Error::UnknownMessageType(_))
        ));
    }
}

#[test]
fn frame_length_and_truncation_limits_are_enforced() {
    assert!(FrameLength::new(0).is_ok());
    assert!(FrameLength::new(MAX_FRAME_SIZE).is_ok());

    assert_eq!(
        FrameLength::new(MAX_FRAME_SIZE + 1),
        Err(Error::InvalidFrameLength(MAX_FRAME_SIZE + 1))
    );

    assert_eq!(
        FrameLength::new(u32::MAX),
        Err(Error::InvalidFrameLength(u32::MAX))
    );

    // The header declares sixteen payload bytes, but only five follow it.
    let mut truncated = vec![0x01, 0x03, 0x00, 0x00, 0x00, 0x10];
    truncated.extend_from_slice(&[0xaa; 5]);

    assert_eq!(Frame::decode(&truncated), Err(Error::TruncatedFrame));

    // A frame header itself is six bytes, so a shorter input cannot be
    // interpreted without guessing at missing fields.
    assert_eq!(
        Frame::decode(&[0x01, 0x03, 0x00]),
        Err(Error::TruncatedFrame)
    );
}

#[test]
fn canonical_cbor_rejects_noncanonical_and_malformed_maps() {
    // Canonical map with ascending integer keys.
    let valid = Frame::new(
        MessageType::Data,
        vec![0xa2, 0x00, 0x01, 0x01, 0x02],
    )
    .unwrap();

    assert!(valid.validate_cbor_map().is_ok());

    // A key may not occur twice, even if the two values differ.
    let duplicate = Frame::new(
        MessageType::Data,
        vec![0xa2, 0x00, 0x01, 0x00, 0x02],
    )
    .unwrap();

    assert_eq!(
        duplicate.validate_cbor_map(),
        Err(Error::DuplicateMapKey(0))
    );

    // Protocol maps use unsigned integer keys; text keys are invalid.
    let text_key = Frame::new(
        MessageType::Data,
        vec![0xa1, 0x61, b'x', 0x01],
    )
    .unwrap();

    assert_eq!(
        text_key.validate_cbor_map(),
        Err(Error::InvalidMapKey)
    );

    // Canonical CBOR requires map keys to be ordered.
    let unsorted = Frame::new(
        MessageType::Data,
        vec![0xa2, 0x01, 0x01, 0x00, 0x02],
    )
    .unwrap();

    assert_eq!(
        unsorted.validate_cbor_map(),
        Err(Error::NonCanonicalEncoding)
    );

    // A payload must contain exactly one CBOR object. Bytes after that
    // object cannot be silently ignored.
    let trailing = Frame::new(
        MessageType::Data,
        vec![0xa1, 0x00, 0x01, 0x00],
    )
    .unwrap();

    assert_eq!(
        trailing.validate_cbor_map(),
        Err(Error::NonCanonicalEncoding)
    );

    // Every protocol payload that reaches this validator must be a map.
    let array = Frame::new(MessageType::Data, vec![0x81, 0x01]).unwrap();

    assert_eq!(
        array.validate_cbor_map(),
        Err(Error::InvalidPayloadShape)
    );
}

#[test]
fn hello_payload_enforces_initial_and_rekey_schema() {
    let identity = PeerIdentity::from_bytes([1; 32]);

    let initial_with_previous = HelloPayload {
        cipher_suite: 1,
        purpose: HandshakePurpose::Initial,
        role: HelloRole::Initiator,
        identity_public_key: identity,
        ephemeral_public_key: [2; 32],
        nonce: [3; 16],
        previous_session_id: Some(SessionId::from_bytes([4; 16])),
    };

    // Initial handshakes create a new session and therefore cannot claim a
    // previous session identifier.
    assert_eq!(
        initial_with_previous.encode(),
        Err(Error::InvalidHandshake)
    );

    let rekey_without_previous = HelloPayload {
        cipher_suite: 1,
        purpose: HandshakePurpose::Rekey,
        role: HelloRole::Initiator,
        identity_public_key: identity,
        ephemeral_public_key: [2; 32],
        nonce: [3; 16],
        previous_session_id: None,
    };

    // Rekey handshakes must identify the session they are replacing.
    assert_eq!(
        rekey_without_previous.encode(),
        Err(Error::InvalidHandshake)
    );

    let initiator = HelloPayload {
        cipher_suite: 1,
        purpose: HandshakePurpose::Initial,
        role: HelloRole::Initiator,
        identity_public_key: identity,
        ephemeral_public_key: [2; 32],
        nonce: [3; 16],
        previous_session_id: None,
    };

    let second_initiator = HelloPayload {
        cipher_suite: 1,
        purpose: HandshakePurpose::Initial,
        role: HelloRole::Initiator,
        identity_public_key: PeerIdentity::from_bytes([9; 32]),
        ephemeral_public_key: [8; 32],
        nonce: [7; 16],
        previous_session_id: None,
    };

    // A transcript needs exactly one initiator and one responder.
    assert_eq!(
        transcript_from_hellos(&initiator, &second_initiator),
        Err(Error::InvalidHandshake)
    );
}

#[test]
fn handshake_signature_requires_current_sas_approval() {
    let initiator = IdentityKeypair::from_bytes(&[1; 32]);
    let responder = IdentityKeypair::from_bytes(&[2; 32]);

    let mut payload = HandshakePayload {
        handshake_type: HandshakeType::Initial,
        stage: 0,
        cipher_suite: 1,
        initiator_identity: initiator.identity(),
        responder_identity: responder.identity(),
        initiator_ephemeral: [3; 32],
        responder_ephemeral: [4; 32],
        initiator_nonce: [5; 16],
        responder_nonce: [6; 16],
        previous_session_id: None,
        initiator_signature: [0; 64],
        responder_signature: None,
    };

    let hash = transcript_hash(&payload.transcript().encode().unwrap());
    payload.initiator_signature = initiator.sign_transcript(&hash, true);

    // The cryptographic signature can be valid while the user has still
    // rejected the SAS. Authentication and local SAS approval are separate
    // protocol decisions.
    assert!(matches!(
        verify_handshake(&payload, &[7; 32], false),
        Err(Error::SasRejected)
    ));

    // The current volatile design does not persist trust enrollment.
    // Approval must therefore be supplied for this connection.
    assert!(verify_handshake(&payload, &[7; 32], true).is_ok());
}

#[test]
fn session_confirmation_binds_confirmation_to_session() {
    let session_id = SessionId::from_bytes([1; 16]);
    let confirmation_key = [2; 32];
    let hash = [3; 32];

    let payload = SessionConfirmPayload {
        session_id,
        role: 0,
        confirmation: confirmation_mac(&confirmation_key, &hash, true),
    };

    let frame = payload.encode().unwrap();
    assert_eq!(frame.message_type, MessageType::SessionConfirm);

    let decoded = SessionConfirmPayload::decode(&frame).unwrap();
    assert_eq!(decoded, payload);

    let keys = ruxmsg::crypto::SessionKeys {
        root_key: [0; 32],
        initiator_to_responder: [0; 32],
        responder_to_initiator: [0; 32],
        session_id,
        confirmation_key,
    };

    assert!(decoded.verify(&keys, &hash).is_ok());

    // A valid MAC from another session must not authenticate this session.
    let wrong_session = ruxmsg::crypto::SessionKeys {
        root_key: [0; 32],
        initiator_to_responder: [0; 32],
        responder_to_initiator: [0; 32],
        session_id: SessionId::from_bytes([9; 16]),
        confirmation_key,
    };

    assert_eq!(
        decoded.verify(&wrong_session, &hash),
        Err(Error::ConfirmationInvalid)
    );
}

#[test]
fn replay_window_enforces_duplicate_and_age_boundaries() {
    let mut window = ReplayWindow::new();

    assert_eq!(window.highest(), None);

    window.accept(0).unwrap();
    window.accept(1).unwrap();

    assert_eq!(window.accept(0), Err(Error::ReplayRejected));
    assert_eq!(window.accept(1), Err(Error::ReplayRejected));

    // Counter 10 advances the highest counter while leaving earlier
    // counters inside the replay window.
    window.accept(10).unwrap();

    assert_eq!(window.classify(5), ReplayStatus::New);
    window.accept(5).unwrap();
    assert_eq!(window.classify(5), ReplayStatus::Duplicate);

    assert_eq!(window.accept(5), Err(Error::ReplayRejected));

    // The protocol permits an out-of-order counter 63 positions behind
    // the current highest value.
    window.accept(73).unwrap();

    assert_eq!(window.classify(10), ReplayStatus::Duplicate);
    assert_eq!(window.classify(9), ReplayStatus::TooOld);
    assert_eq!(window.accept(9), Err(Error::ReplayRejected));

    // A sufficiently large forward jump advances the replay window and
    // makes the old history permanently unusable.
    window.accept(1000).unwrap();

    assert_eq!(window.classify(73), ReplayStatus::TooOld);
}

#[test]
fn receiving_chain_prepares_without_consuming_keys() {
    let mut chain =
        ReceivingChain::new([1; 32], DirectionId::InitiatorToResponder);

    assert_eq!(chain.skipped_len(), 0);

    let key_5 = chain.prepare_message_key(5).unwrap();

    // Preparing a future message derives the intervening keys, but none of
    // them can be destroyed before the corresponding ciphertext authenticates.
    assert_eq!(chain.skipped_len(), 6);

    let key_2 = chain.prepare_message_key(2).unwrap();
    assert_eq!(chain.skipped_len(), 6);
    assert_eq!(chain.prepare_message_key(2).unwrap(), key_2);

    chain.commit_message_key(2).unwrap();

    assert_eq!(chain.skipped_len(), 5);
    assert_eq!(
        chain.prepare_message_key(2),
        Err(Error::MessageKeyUnavailable(2))
    );

    // A prepared future key remains usable until its own authentication
    // succeeds and it is explicitly committed.
    assert_eq!(chain.prepare_message_key(5).unwrap(), key_5);

    chain.commit_message_key(5).unwrap();

    assert_eq!(chain.skipped_len(), 4);
    assert_eq!(
        chain.prepare_message_key(5),
        Err(Error::MessageKeyUnavailable(5))
    );
}

#[test]
fn receiving_chain_enforces_skipped_key_limit() {
    let mut chain =
        ReceivingChain::new([2; 32], DirectionId::InitiatorToResponder);

    // A gap of 65 requires more than the permitted skipped-key budget.
    assert_eq!(
        chain.prepare_message_key(65),
        Err(Error::SkippedKeyLimit)
    );

    // A gap of exactly 64 is permitted: 64 skipped keys plus the pending
    // target key occupy 65 entries.
    chain.prepare_message_key(64).unwrap();
    assert_eq!(chain.skipped_len(), 65);

    // Once that cache is full, another forward jump cannot be prepared.
    assert_eq!(
        chain.prepare_message_key(66),
        Err(Error::SkippedKeyLimit)
    );
}

#[test]
fn data_padding_preserves_content_and_requires_zero_padding() {
    for size in [0, 1, 10, 100, 230, 256, 500, 1024] {
        let content = vec![0x42; size];
        let padded = DataPlaintext::padded(&content).unwrap();

        assert_eq!(padded.content, content);
        assert!(padded.padding.iter().all(|byte| *byte == 0));

        let encoded = padded.encode().unwrap();

        assert_eq!(
            (encoded.len() + 16) % DEFAULT_PADDING_QUANTUM,
            0
        );

        let decoded = DataPlaintext::decode(&encoded).unwrap();
        assert_eq!(decoded.content, content);
    }

    // Padding is authenticated as part of the plaintext format. A non-zero
    // padding byte must not be accepted as an alternative representation.
    let invalid = DataPlaintext {
        content: b"test".to_vec(),
        padding: vec![0, 0, 1, 0],
    };

    let encoded = invalid.encode().unwrap();

    assert_eq!(
        DataPlaintext::decode(&encoded),
        Err(Error::InvalidPadding)
    );
}

#[test]
fn failed_aead_does_not_burn_current_message_key() {
    let session_id = SessionId::from_bytes([1; 16]);

    let mut sender =
        DataSender::new(session_id, DirectionId::InitiatorToResponder, [5; 32]);

    let mut receiver =
        DataReceiver::new(session_id, DirectionId::InitiatorToResponder, [5; 32]);

    // Generate exactly one frame so the legitimate copy is still counter 0.
    let frame = sender.encrypt(b"secret payload").unwrap();

    let mut tampered = frame.clone();

    if let Some(last) = tampered.payload.last_mut() {
        *last ^= 0x01;
    }

    assert_eq!(
        receiver.decrypt(&tampered),
        Err(Error::AeadFailure)
    );

    // Authentication failure must not commit or destroy the ratchet key.
    // Otherwise an attacker could permanently desynchronize the receiver
    // by sending a modified ciphertext.
    assert_eq!(
        receiver.decrypt(&frame).unwrap(),
        b"secret payload"
    );
}

#[test]
fn failed_aead_does_not_burn_future_message_key() {
    let session_id = SessionId::from_bytes([2; 16]);

    let mut sender =
        DataSender::new(session_id, DirectionId::InitiatorToResponder, [6; 32]);

    let mut receiver =
        DataReceiver::new(session_id, DirectionId::InitiatorToResponder, [6; 32]);

    let mut frames = Vec::new();

    for _ in 0..6 {
        frames.push(sender.encrypt(b"future payload").unwrap());
    }

    // Counter 5 forces the receiver to derive/cache counters 0..5 before
    // authentication. The target key must remain pending until AEAD succeeds.
    let mut tampered = frames[5].clone();

    if let Some(last) = tampered.payload.last_mut() {
        *last ^= 0x01;
    }

    assert_eq!(
        receiver.decrypt(&tampered),
        Err(Error::AeadFailure)
    );

    assert_eq!(
        receiver.decrypt(&frames[5]).unwrap(),
        b"future payload"
    );
}

#[test]
fn wrong_direction_is_rejected_without_advancing_the_ratchet() {
    let session_id = SessionId::from_bytes([4; 16]);

    let mut sender =
        DataSender::new(session_id, DirectionId::ResponderToInitiator, [8; 32]);

    let mut receiver =
        DataReceiver::new(session_id, DirectionId::InitiatorToResponder, [8; 32]);

    let frame = sender.encrypt(b"wrong direction").unwrap();

    assert_eq!(
        receiver.decrypt(&frame),
        Err(Error::InvalidDataPayload)
    );

    // The receiver must still be able to process its own direction's counter
    // zero after seeing the invalid-direction frame. This catches implementations
    // that advance replay or ratchet state before validating direction.
    let mut valid_sender =
        DataSender::new(session_id, DirectionId::InitiatorToResponder, [8; 32]);

    let valid_frame = valid_sender.encrypt(b"valid direction").unwrap();

    assert_eq!(
        receiver.decrypt(&valid_frame).unwrap(),
        b"valid direction"
    );
}

#[test]
fn successful_decryption_commits_key_and_rejects_replay() {
    let session_id = SessionId::from_bytes([5; 16]);

    let mut sender =
        DataSender::new(session_id, DirectionId::InitiatorToResponder, [9; 32]);

    let mut receiver =
        DataReceiver::new(session_id, DirectionId::InitiatorToResponder, [9; 32]);

    let frame = sender.encrypt(b"one time message").unwrap();

    assert_eq!(
        receiver.decrypt(&frame).unwrap(),
        b"one time message"
    );

    // Once authenticated, the counter is committed to the replay window.
    assert_eq!(
        receiver.decrypt(&frame),
        Err(Error::ReplayRejected)
    );
}

#[test]
fn close_reason_registry_and_detail_limit_are_enforced() {
    use ruxmsg::close::{ClosePayload, CloseReason};

    let reasons = [
        (0, CloseReason::Normal),
        (1, CloseReason::ProtocolError),
        (2, CloseReason::AuthenticationFailure),
        (3, CloseReason::IdentityChanged),
        (4, CloseReason::ResourceLimit),
        (5, CloseReason::Shutdown),
    ];

    for (code, reason) in reasons {
        assert_eq!(CloseReason::try_from(code).unwrap(), reason);

        let payload = ClosePayload {
            session_id: Some(SessionId::from_bytes([0x77; 16])),
            reason,
            detail: Some("Normal shutdown".to_string()),
        };

        let frame = payload.encode().unwrap();

        assert_eq!(frame.message_type, MessageType::Close);
        assert_eq!(ClosePayload::decode(&frame).unwrap(), payload);
    }

    for code in [6, 255] {
        assert!(matches!(
            CloseReason::try_from(code),
            Err(Error::InvalidClosePayload)
        ));
    }

    // The limit is measured in UTF-8 bytes, not Unicode scalar values.
    let valid_ascii = "a".repeat(128);

    assert!(
        ClosePayload {
            session_id: None,
            reason: CloseReason::Normal,
            detail: Some(valid_ascii),
        }
        .encode()
        .is_ok()
    );

    let oversized_ascii = "a".repeat(129);

    assert_eq!(
        ClosePayload {
            session_id: None,
            reason: CloseReason::Normal,
            detail: Some(oversized_ascii),
        }
        .encode(),
        Err(Error::InvalidClosePayload)
    );

    // 64 two-byte UTF-8 characters occupy exactly 128 bytes.
    let valid_multibyte = "é".repeat(64);

    assert!(
        ClosePayload {
            session_id: None,
            reason: CloseReason::Normal,
            detail: Some(valid_multibyte),
        }
        .encode()
        .is_ok()
    );

    // 65 × 2-byte UTF-8 characters = 130 bytes.
    let oversized_multibyte = "é".repeat(65);

    assert_eq!(
        ClosePayload {
            session_id: None,
            reason: CloseReason::Normal,
            detail: Some(oversized_multibyte),
        }
        .encode(),
        Err(Error::InvalidClosePayload)
    );
}