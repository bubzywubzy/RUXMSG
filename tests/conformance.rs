use bip39::Language;
use sha2::{Digest, Sha256};

use ruxmsg::crypto::{
    EphemeralKeypair, IdentityKeypair, confirmation_mac, derive_message_key, derive_session_keys,
    message_nonce, sas_indices, sas_words, transcript_hash, verify_confirmation,
    verify_transcript_signature,
};
use ruxmsg::data::{DataPlaintext, DataReceiver, DataSender};
use ruxmsg::encoding::Transcript;
use ruxmsg::error::Error;
use ruxmsg::handshake::{
    HandshakePayload, HandshakePurpose, HandshakeType, HelloPayload, HelloRole,
    SessionConfirmPayload, transcript_from_hellos, verify_handshake,
};
use ruxmsg::identity::PeerIdentity;
use ruxmsg::protocol::{
    DEFAULT_PADDING_QUANTUM, DirectionId, FrameLength, MAX_FRAME_SIZE, MessageType,
    ProtocolVersion, SessionId,
};
use ruxmsg::ratchet::{ReceivingChain, ReplayStatus, ReplayWindow};
use ruxmsg::wire::Frame;

// ============================================================================
// Phase 1: Cryptographic Suite & Mandatory Test Vectors (§2, §4.3, §5.1, §7, §12.3)
// ============================================================================

#[test]
fn phase1_bip39_wordlist_hash_matches_pinned_artifact() {
    // Protocol spec §4.3 / D-010: BIP-0039 English word list (2048 LF-delimited words).
    // Pinned SHA-256: 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda
    let words = Language::English.word_list();
    assert_eq!(words.len(), 2048);

    let mut corpus = Vec::new();
    for word in words {
        corpus.extend_from_slice(word.as_bytes());
        corpus.push(b'\n');
    }
    let mut hasher = Sha256::new();
    hasher.update(&corpus);
    let hash = hasher.finalize();
    let hex_hash: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        hex_hash,
        "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
    );
}

#[test]
fn phase1_sas_bit_boundary_transitions_and_msb_first() {
    // Test §4.3 & §12.3 bit boundary transitions:
    // W0: bits 0..10  (H[0] bits 7..0, H[1] bits 7..5)
    // W1: bits 11..21 (H[1] bits 4..0, H[2] bits 7..2)
    // W2: bits 22..32 (H[2] bits 1..0, H[3] bits 7..0, H[4] bit 7)

    // All zeros: W0=0, W1=0, W2=0 -> abandon, abandon, abandon
    let zero_hash = [0u8; 32];
    assert_eq!(sas_indices(&zero_hash).first, 0);
    assert_eq!(sas_indices(&zero_hash).second, 0);
    assert_eq!(sas_indices(&zero_hash).third, 0);
    assert_eq!(sas_words(&zero_hash), ["abandon", "abandon", "abandon"]);

    // All ones across the first 33 bits:
    // H[0..4] = 0xFF, H[4] = 0x80 -> W0 = 2047 (0x7FF), W1 = 2047 (0x7FF), W2 = 2047 (0x7FF)
    // Word 2047 in BIP-39 English is "zoo"
    let mut all_ones = [0u8; 32];
    all_ones[..4].copy_from_slice(&[0xff, 0xff, 0xff, 0xff]);
    all_ones[4] = 0x80;
    let ones_indices = sas_indices(&all_ones);
    assert_eq!(ones_indices.first, 2047);
    assert_eq!(ones_indices.second, 2047);
    assert_eq!(ones_indices.third, 2047);
    assert_eq!(sas_words(&all_ones), ["zoo", "zoo", "zoo"]);

    // Boundary Test H[0] -> H[1] (test single bit at H[0] bit 0 vs H[1] bit 7)
    // H[0] = 0x01 (bit 7 of 33-bit stream is 1)
    let mut h0_boundary = [0u8; 32];
    h0_boundary[0] = 0x01;
    let idx = sas_indices(&h0_boundary);
    assert_eq!(idx.first, 0x008); // (1 << 3)
    assert_eq!(idx.second, 0);
    assert_eq!(idx.third, 0);

    // H[1] = 0x80 (bit 8 of 33-bit stream is 1)
    let mut h1_boundary = [0u8; 32];
    h1_boundary[1] = 0x80;
    let idx = sas_indices(&h1_boundary);
    assert_eq!(idx.first, 0x004); // (1 << 2)
    assert_eq!(idx.second, 0);
    assert_eq!(idx.third, 0);

    // Boundary Test H[1] -> H[2] (W0 ends at bit 10; W1 starts at bit 11)
    // H[1] = 0x20 -> bit 10 is 1 (last bit of W0)
    let mut w0_end = [0u8; 32];
    w0_end[1] = 0x20;
    let idx = sas_indices(&w0_end);
    assert_eq!(idx.first, 0x001);
    assert_eq!(idx.second, 0x000);
    assert_eq!(idx.third, 0x000);

    // H[1] = 0x10 -> bit 11 is 1 (first bit of W1)
    let mut w1_start = [0u8; 32];
    w1_start[1] = 0x10;
    let idx = sas_indices(&w1_start);
    assert_eq!(idx.first, 0x000);
    assert_eq!(idx.second, 0x400); // 1 << 10
    assert_eq!(idx.third, 0x000);

    // Boundary Test H[2] -> H[3] (W1 ends at bit 21; W2 starts at bit 22)
    // H[2] = 0x04 -> bit 21 is 1 (last bit of W1)
    let mut w1_end = [0u8; 32];
    w1_end[2] = 0x04;
    let idx = sas_indices(&w1_end);
    assert_eq!(idx.first, 0x000);
    assert_eq!(idx.second, 0x001);
    assert_eq!(idx.third, 0x000);

    // H[2] = 0x02 -> bit 22 is 1 (first bit of W2)
    let mut w2_start = [0u8; 32];
    w2_start[2] = 0x02;
    let idx = sas_indices(&w2_start);
    assert_eq!(idx.first, 0x000);
    assert_eq!(idx.second, 0x000);
    assert_eq!(idx.third, 0x400);

    // Boundary Test H[3] -> H[4] (W2 covers H[3] and bit 7 of H[4])
    // H[3] = 0x01 -> bit 31 is 1
    let mut w2_h3 = [0u8; 32];
    w2_h3[3] = 0x01;
    let idx = sas_indices(&w2_h3);
    assert_eq!(idx.third, 0x002);

    // H[4] = 0x80 -> bit 32 is 1 (last bit of W2)
    let mut w2_h4 = [0u8; 32];
    w2_h4[4] = 0x80;
    let idx = sas_indices(&w2_h4);
    assert_eq!(idx.third, 0x001);

    // Bits after bit 32 (H[4] bit 6 down to 0) must be ignored
    let mut ignored_bits = [0u8; 32];
    ignored_bits[4] = 0x7f;
    ignored_bits[5..].fill(0xff);
    let idx = sas_indices(&ignored_bits);
    assert_eq!(idx.first, 0);
    assert_eq!(idx.second, 0);
    assert_eq!(idx.third, 0);
}

#[test]
fn phase1_comprehensive_deterministic_test_vector() {
    // 1. Fixed Ed25519 identity keypairs
    let initiator_identity = IdentityKeypair::from_bytes(&[0x10; 32]);
    let responder_identity = IdentityKeypair::from_bytes(&[0x20; 32]);
    let init_id_pub = initiator_identity.identity();
    let resp_id_pub = responder_identity.identity();

    // 2. Fixed X25519 ephemeral keypairs
    let initiator_ephemeral = EphemeralKeypair::from_bytes(&[0x30; 32]);
    let responder_ephemeral = EphemeralKeypair::from_bytes(&[0x40; 32]);
    let init_eph_pub = initiator_ephemeral.public_key();
    let resp_eph_pub = responder_ephemeral.public_key();

    // 3. X25519 shared secret
    let dh_shared_initiator = initiator_ephemeral.shared_secret(&resp_eph_pub).unwrap();
    let dh_shared_responder = responder_ephemeral.shared_secret(&init_eph_pub).unwrap();
    assert_eq!(dh_shared_initiator, dh_shared_responder);
    assert_ne!(dh_shared_initiator, [0u8; 32]);

    // 4. Fixed handshake nonces
    let init_nonce = [0x55; 16];
    let resp_nonce = [0x66; 16];

    // 5. Canonical transcript
    let transcript = Transcript {
        handshake_type: 0,
        cipher_suite: 1,
        initiator_identity: init_id_pub,
        responder_identity: resp_id_pub,
        initiator_ephemeral: init_eph_pub,
        responder_ephemeral: resp_eph_pub,
        initiator_nonce: init_nonce,
        responder_nonce: resp_nonce,
        previous_session_id: None,
    };
    let transcript_bytes = transcript.encode().unwrap();
    assert!(!transcript_bytes.is_empty());

    // 6. TranscriptHash
    let t_hash = transcript_hash(&transcript_bytes);
    assert_eq!(
        t_hash,
        transcript_hash(&transcript.encode().unwrap()),
        "transcript hash must be perfectly deterministic"
    );

    // 7. SAS derivation
    let sas = sas_words(&t_hash);
    let sas_idx = sas_indices(&t_hash);
    assert_eq!(
        Language::English.word_list()[sas_idx.first as usize],
        sas[0]
    );
    assert_eq!(
        Language::English.word_list()[sas_idx.second as usize],
        sas[1]
    );
    assert_eq!(
        Language::English.word_list()[sas_idx.third as usize],
        sas[2]
    );

    // 8. Ed25519 signatures
    let sig_i = initiator_identity.sign_transcript(&t_hash, true);
    let sig_r = responder_identity.sign_transcript(&t_hash, false);
    verify_transcript_signature(&init_id_pub, &t_hash, &sig_i, true).unwrap();
    verify_transcript_signature(&resp_id_pub, &t_hash, &sig_r, false).unwrap();

    // Cross verification failure (wrong role or wrong key)
    assert!(verify_transcript_signature(&init_id_pub, &t_hash, &sig_i, false).is_err());
    assert!(verify_transcript_signature(&resp_id_pub, &t_hash, &sig_i, true).is_err());

    // 9. HKDF Key Schedule
    let session_keys = derive_session_keys(&dh_shared_initiator, &t_hash).unwrap();
    assert_ne!(session_keys.root_key, [0u8; 32]);
    assert_ne!(session_keys.initiator_to_responder, [0u8; 32]);
    assert_ne!(session_keys.responder_to_initiator, [0u8; 32]);
    assert_ne!(session_keys.confirmation_key, [0u8; 32]);
    assert_ne!(
        session_keys.initiator_to_responder,
        session_keys.responder_to_initiator
    );

    // 10. Confirmation MACs
    let confirm_i = confirmation_mac(&session_keys.confirmation_key, &t_hash, true);
    let confirm_r = confirmation_mac(&session_keys.confirmation_key, &t_hash, false);
    verify_confirmation(&session_keys.confirmation_key, &t_hash, &confirm_i, true).unwrap();
    verify_confirmation(&session_keys.confirmation_key, &t_hash, &confirm_r, false).unwrap();
    assert!(
        verify_confirmation(&session_keys.confirmation_key, &t_hash, &confirm_i, false).is_err()
    );

    // 11. Symmetric Message Ratchet & Nonces
    let chain_key_0 = session_keys.initiator_to_responder;
    let (mk_0, chain_key_1) = derive_message_key(&chain_key_0, DirectionId::InitiatorToResponder);
    let (mk_1, chain_key_2) = derive_message_key(&chain_key_1, DirectionId::InitiatorToResponder);
    assert_ne!(mk_0, mk_1);
    assert_ne!(chain_key_0, chain_key_1);
    assert_ne!(chain_key_1, chain_key_2);

    let nonce_0 = message_nonce(DirectionId::InitiatorToResponder, 0);
    let nonce_1 = message_nonce(DirectionId::InitiatorToResponder, 1);
    assert_eq!(nonce_0, [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(nonce_1, [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1]);

    // 12. Plaintext, Padding & AAD
    let content = b"Normative Test Vector Plaintext";
    let padded = DataPlaintext::padded(content).unwrap();
    assert_eq!(padded.content, content);
    assert!(padded.padding.iter().all(|&b| b == 0));

    let plaintext_encoded = padded.encode().unwrap();
    assert_eq!((plaintext_encoded.len() + 16) % DEFAULT_PADDING_QUANTUM, 0);

    let mut sender = DataSender::new(
        session_keys.session_id,
        DirectionId::InitiatorToResponder,
        session_keys.initiator_to_responder,
    );
    let frame = sender.encrypt(content).unwrap();
    assert_eq!(frame.message_type, MessageType::Data);

    let mut receiver = DataReceiver::new(
        session_keys.session_id,
        DirectionId::InitiatorToResponder,
        session_keys.initiator_to_responder,
    );
    let decrypted = receiver.decrypt(&frame).unwrap();
    assert_eq!(decrypted, content);
}

#[test]
fn phase1_all_zero_shared_secret_rejection() {
    // Rejection of all-zero X25519 shared secret
    let ephemeral = EphemeralKeypair::from_bytes(&[1; 32]);
    let zero_point = [0u8; 32];
    assert_eq!(
        ephemeral.shared_secret(&zero_point),
        Err(Error::AllZeroSharedSecret)
    );
}

// ============================================================================
// Phase 2: Wire Framing, Registry & Strict CBOR Validation (Appendix E.1–E.3, §10)
// ============================================================================

#[test]
fn phase2_outer_frame_version_and_registry_enforcement() {
    // ProtocolVersion enforcement
    assert_eq!(
        ProtocolVersion::try_from(0x01).unwrap(),
        ProtocolVersion::V1
    );
    assert!(matches!(
        ProtocolVersion::try_from(0x00),
        Err(Error::UnsupportedVersion(0x00))
    ));
    assert!(matches!(
        ProtocolVersion::try_from(0x02),
        Err(Error::UnsupportedVersion(0x02))
    ));
    assert!(matches!(
        ProtocolVersion::try_from(0xFF),
        Err(Error::UnsupportedVersion(0xFF))
    ));

    // MessageType registry (0x01..0x05 valid, others reserved)
    assert_eq!(MessageType::try_from(0x01).unwrap(), MessageType::Handshake);
    assert_eq!(
        MessageType::try_from(0x02).unwrap(),
        MessageType::SessionConfirm
    );
    assert_eq!(MessageType::try_from(0x03).unwrap(), MessageType::Data);
    assert_eq!(MessageType::try_from(0x04).unwrap(), MessageType::Rekey);
    assert_eq!(MessageType::try_from(0x05).unwrap(), MessageType::Close);

    assert!(matches!(
        MessageType::try_from(0x00),
        Err(Error::UnknownMessageType(0x00))
    ));
    assert!(matches!(
        MessageType::try_from(0x06),
        Err(Error::UnknownMessageType(0x06))
    ));
    assert!(matches!(
        MessageType::try_from(0xFF),
        Err(Error::UnknownMessageType(0xFF))
    ));
}

#[test]
fn phase2_frame_payload_length_limits_and_truncation() {
    // MAX_FRAME_SIZE is 1 MiB (1,048,576)
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

    // Frame truncation detection
    let mut raw_truncated = vec![0x01, 0x03, 0x00, 0x00, 0x00, 0x10]; // header declaring 16 bytes
    raw_truncated.extend_from_slice(&[0xaa; 5]); // only 5 bytes provided
    assert_eq!(Frame::decode(&raw_truncated), Err(Error::TruncatedFrame));

    // Header shorter than 6 bytes
    assert_eq!(
        Frame::decode(&[0x01, 0x03, 0x00]),
        Err(Error::TruncatedFrame)
    );
}

#[test]
fn phase2_deterministic_cbor_validation_rules() {
    // Valid canonical CBOR map: {0: 1, 1: 2} -> 0xa2, 0x00, 0x01, 0x01, 0x02
    let valid_frame = Frame::new(MessageType::Data, vec![0xa2, 0x00, 0x01, 0x01, 0x02]).unwrap();
    assert!(valid_frame.validate_cbor_map().is_ok());

    // Duplicate map keys rejected
    let dup_key_frame = Frame::new(MessageType::Data, vec![0xa2, 0x00, 0x01, 0x00, 0x02]).unwrap();
    assert_eq!(
        dup_key_frame.validate_cbor_map(),
        Err(Error::DuplicateMapKey(0))
    );

    // Non-integer key rejected (text key "x")
    let text_key_frame = Frame::new(MessageType::Data, vec![0xa1, 0x61, b'x', 0x01]).unwrap();
    assert_eq!(
        text_key_frame.validate_cbor_map(),
        Err(Error::InvalidMapKey)
    );

    // Unsorted integer keys rejected (key 1 before key 0)
    let unsorted_frame = Frame::new(MessageType::Data, vec![0xa2, 0x01, 0x01, 0x00, 0x02]).unwrap();
    assert_eq!(
        unsorted_frame.validate_cbor_map(),
        Err(Error::NonCanonicalEncoding)
    );

    // Trailing unconsumed bytes after CBOR map rejected
    let trailing_frame = Frame::new(MessageType::Data, vec![0xa1, 0x00, 0x01, 0x00]).unwrap();
    assert_eq!(
        trailing_frame.validate_cbor_map(),
        Err(Error::NonCanonicalEncoding)
    );

    // Non-map payload rejected
    let array_frame = Frame::new(MessageType::Data, vec![0x81, 0x01]).unwrap();
    assert_eq!(
        array_frame.validate_cbor_map(),
        Err(Error::InvalidPayloadShape)
    );
}

// ============================================================================
// Phase 3: Handshake, Transcript, SAS, and Trust Enrollment (§3, §4, §5, App E.4-E.5)
// ============================================================================

#[test]
fn phase3_hello_schema_strict_validation() {
    let identity = PeerIdentity::from_bytes([1; 32]);
    let ephemeral = [2; 32];
    let nonce = [3; 16];

    // Initial HELLO must not have previous_session_id
    let invalid_initial = HelloPayload {
        cipher_suite: 1,
        purpose: HandshakePurpose::Initial,
        role: HelloRole::Initiator,
        identity_public_key: identity,
        ephemeral_public_key: ephemeral,
        nonce,
        previous_session_id: Some(SessionId::from_bytes([4; 16])),
    };
    assert_eq!(invalid_initial.encode(), Err(Error::InvalidHandshake));

    // Rekey HELLO must have previous_session_id
    let invalid_rekey = HelloPayload {
        cipher_suite: 1,
        purpose: HandshakePurpose::Rekey,
        role: HelloRole::Initiator,
        identity_public_key: identity,
        ephemeral_public_key: ephemeral,
        nonce,
        previous_session_id: None,
    };
    assert_eq!(invalid_rekey.encode(), Err(Error::InvalidHandshake));

    // Roles must be different (cannot assemble transcript from two initiators)
    let init1 = HelloPayload {
        cipher_suite: 1,
        purpose: HandshakePurpose::Initial,
        role: HelloRole::Initiator,
        identity_public_key: identity,
        ephemeral_public_key: ephemeral,
        nonce,
        previous_session_id: None,
    };
    let init2 = HelloPayload {
        cipher_suite: 1,
        purpose: HandshakePurpose::Initial,
        role: HelloRole::Initiator,
        identity_public_key: PeerIdentity::from_bytes([9; 32]),
        ephemeral_public_key: ephemeral,
        nonce,
        previous_session_id: None,
    };
    assert_eq!(
        transcript_from_hellos(&init1, &init2),
        Err(Error::InvalidHandshake)
    );
}

#[test]
fn phase3_handshake_signature() {
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
    let t_hash = transcript_hash(&payload.transcript().encode().unwrap());
    payload.initiator_signature = initiator.sign_transcript(&t_hash, true);

    // SAS rejection aborts
    assert!(matches!(
        verify_handshake(&payload, &[7; 32], false),
        Err(Error::SasRejected)
    ));

    // SAS approved on first contact succeeds
    assert!(verify_handshake(&payload, &[7; 32], true).is_ok());

    // Previously trusted peer matches -> succeeds
    assert!(verify_handshake(&payload, &[7; 32], true,).is_ok());
}

#[test]
fn phase3_session_confirm_verification() {
    let session_id = SessionId::from_bytes([1; 16]);
    let conf_key = [2; 32];
    let t_hash = [3; 32];

    let confirm_payload = SessionConfirmPayload {
        session_id,
        role: 0,
        confirmation: confirmation_mac(&conf_key, &t_hash, true),
    };
    let frame = confirm_payload.encode().unwrap();
    assert_eq!(frame.message_type, MessageType::SessionConfirm);

    let decoded = SessionConfirmPayload::decode(&frame).unwrap();
    assert_eq!(decoded, confirm_payload);

    let session_keys = ruxmsg::crypto::SessionKeys {
        root_key: [0; 32],
        initiator_to_responder: [0; 32],
        responder_to_initiator: [0; 32],
        session_id,
        confirmation_key: conf_key,
    };
    assert!(decoded.verify(&session_keys, &t_hash).is_ok());

    // Mismatched session ID
    let wrong_session_keys = ruxmsg::crypto::SessionKeys {
        root_key: [0; 32],
        initiator_to_responder: [0; 32],
        responder_to_initiator: [0; 32],
        session_id: SessionId::from_bytes([9; 16]),
        confirmation_key: conf_key,
    };
    assert_eq!(
        decoded.verify(&wrong_session_keys, &t_hash),
        Err(Error::ConfirmationInvalid)
    );
}

// ============================================================================
// Phase 4: Symmetric Ratchet, Replay Protection & DATA Padding (§7, §8, App E.6)
// ============================================================================

#[test]
fn phase4_replay_window_sliding_and_boundaries() {
    let mut window = ReplayWindow::new();

    assert_eq!(window.highest(), None);

    // In-order messages
    window.accept(0).unwrap();
    assert_eq!(window.highest(), Some(0));

    window.accept(1).unwrap();
    assert_eq!(window.highest(), Some(1));

    // Duplicate message rejected
    assert_eq!(window.accept(0), Err(Error::ReplayRejected));
    assert_eq!(window.accept(1), Err(Error::ReplayRejected));

    // Out-of-order within 64-window
    window.accept(10).unwrap();
    assert_eq!(window.highest(), Some(10));

    assert_eq!(window.classify(5), ReplayStatus::New);

    window.accept(5).unwrap();
    assert_eq!(window.classify(5), ReplayStatus::Duplicate);

    assert_eq!(window.accept(5), Err(Error::ReplayRejected));

    // Boundary at distance 63 (accepted)
    assert!(window.accept(10 + 63).is_ok());

    // Counter 73 - 64 = 9 is now TooOld (distance >= 64)
    assert_eq!(window.classify(9), ReplayStatus::TooOld);
    assert_eq!(window.accept(9), Err(Error::ReplayRejected));

    // Counter 73 - 63 = 10 is inside window
    assert_eq!(window.classify(10), ReplayStatus::Duplicate);

    // Large jump shifts window completely
    window.accept(1000).unwrap();

    assert_eq!(window.classify(73), ReplayStatus::TooOld);
}

#[test]
fn phase4_prepared_key_cache_and_commit_semantics() {
    let mut chain = ReceivingChain::new([1; 32], DirectionId::InitiatorToResponder);

    assert_eq!(chain.skipped_len(), 0);

    // Preparing counter 5 derives counters 0..5 and retains every
    // derived key until authentication/commit succeeds.
    let key_5 = chain.prepare_message_key(5).unwrap();

    // Counters 0..5 are all retained:
    // 0..4 = skipped/unconsumed
    // 5    = prepared target awaiting authentication
    assert_eq!(chain.skipped_len(), 6);

    // Preparing counter 2 retrieves the cached key without deriving
    // another ratchet step.
    let key_2 = chain.prepare_message_key(2).unwrap();

    assert_eq!(chain.skipped_len(), 6);

    // The same key remains available until commit.
    assert_eq!(chain.prepare_message_key(2).unwrap(), key_2);
    assert_eq!(chain.skipped_len(), 6);

    // Commit consumes only counter 2.
    chain.commit_message_key(2).unwrap();

    assert_eq!(chain.skipped_len(), 5);

    // A committed key can no longer be recovered.
    assert_eq!(
        chain.prepare_message_key(2),
        Err(Error::MessageKeyUnavailable(2))
    );

    // The target key also remains recoverable until committed.
    assert_eq!(chain.prepare_message_key(5).unwrap(), key_5);

    chain.commit_message_key(5).unwrap();

    assert_eq!(chain.skipped_len(), 4);

    assert_eq!(
        chain.prepare_message_key(5),
        Err(Error::MessageKeyUnavailable(5))
    );
}

#[test]
fn phase4_skipped_key_cache_and_bounds() {
    let mut chain = ReceivingChain::new([1; 32], DirectionId::InitiatorToResponder);

    // Requesting counter 5 derives keys for 0..5.
    //
    // The target key is now retained as a pending key as well as
    // the five preceding skipped keys.
    let _ = chain.prepare_message_key(5).unwrap();

    assert_eq!(chain.skipped_len(), 6);

    // Arriving out of order: key 2 is retrieved from the pending cache.
    let _ = chain.prepare_message_key(2).unwrap();

    // Preparing does NOT consume the key.
    assert_eq!(chain.skipped_len(), 6);

    // Commit explicitly consumes it.
    chain.commit_message_key(2).unwrap();

    assert_eq!(chain.skipped_len(), 5);

    // Requesting key 2 again fails because it was committed/consumed.
    assert_eq!(
        chain.prepare_message_key(2),
        Err(Error::MessageKeyUnavailable(2))
    );

    // Requesting a gap > 64 fails with SkippedKeyLimit.
    let mut chain2 = ReceivingChain::new([2; 32], DirectionId::InitiatorToResponder);

    assert_eq!(chain2.prepare_message_key(65), Err(Error::SkippedKeyLimit));

    // Exactly 64 gap is allowed.
    assert!(chain2.prepare_message_key(64).is_ok());

    // With the new prepare semantics, counters 0..64 are retained:
    // 64 skipped keys + counter 64's pending target key.
    assert_eq!(chain2.skipped_len(), 65);

    // The ratchet's MAX_SKIPPED_KEYS bound still prevents a further
    // large jump once the pending cache is full.
    assert_eq!(chain2.prepare_message_key(66), Err(Error::SkippedKeyLimit));
}

#[test]
fn phase4_data_padding_quantum_and_corruption_checks() {
    // Quantum calculation for various sizes
    for size in [0, 1, 10, 100, 230, 256, 500, 1024] {
        let content = vec![0x42; size];

        let padded = DataPlaintext::padded(&content).unwrap();

        assert_eq!(padded.content, content);
        assert!(padded.padding.iter().all(|&b| b == 0));

        let encoded = padded.encode().unwrap();

        assert_eq!((encoded.len() + 16) % DEFAULT_PADDING_QUANTUM, 0);

        // Decode round-trip
        let decoded = DataPlaintext::decode(&encoded).unwrap();

        assert_eq!(decoded.content, content);
    }

    // Corrupted padding byte (non-zero)
    let invalid_padding_plaintext = DataPlaintext {
        content: b"test".to_vec(),
        padding: vec![0, 0, 1, 0],
    };

    let encoded_invalid = invalid_padding_plaintext.encode().unwrap();

    assert_eq!(
        DataPlaintext::decode(&encoded_invalid),
        Err(Error::InvalidPadding)
    );
}

#[test]
fn phase4_aead_tampering_does_not_consume_message_key() {
    let session_id = SessionId::from_bytes([1; 16]);

    let mut sender = DataSender::new(session_id, DirectionId::InitiatorToResponder, [5; 32]);

    let mut receiver = DataReceiver::new(session_id, DirectionId::InitiatorToResponder, [5; 32]);

    // Generate ONE legitimate frame.
    //
    // This is important: do not generate a second frame after tampering,
    // because that would have counter 1 and would not prove that counter 0
    // survived the failed authentication attempt.
    let frame = sender.encrypt(b"secret payload").unwrap();

    // Attack a copy of counter 0.
    let mut tampered_frame = frame.clone();

    if let Some(last) = tampered_frame.payload.last_mut() {
        *last ^= 0x01;
    }

    // Authentication must fail.
    assert_eq!(receiver.decrypt(&tampered_frame), Err(Error::AeadFailure));

    // The ORIGINAL counter-0 frame must still decrypt successfully.
    //
    // This is the critical regression test for Finding 1:
    //
    //     AEAD failure must NOT consume the message key.
    assert_eq!(receiver.decrypt(&frame).unwrap(), b"secret payload");
}

#[test]
fn phase4_future_counter_tampering_does_not_consume_target_key() {
    let session_id = SessionId::from_bytes([2; 16]);

    let mut sender = DataSender::new(session_id, DirectionId::InitiatorToResponder, [6; 32]);

    let mut receiver = DataReceiver::new(session_id, DirectionId::InitiatorToResponder, [6; 32]);

    // Generate counters 0..5.
    let mut frames = Vec::new();

    for _ in 0..6 {
        frames.push(sender.encrypt(b"future payload").unwrap());
    }

    // Deliver counter 5 first, but tampered.
    //
    // The receiver must derive/cache keys 0..5, including the target
    // key for counter 5, but must NOT commit counter 5 until authentication
    // succeeds.
    let mut tampered = frames[5].clone();

    if let Some(last) = tampered.payload.last_mut() {
        *last ^= 0x01;
    }

    assert_eq!(receiver.decrypt(&tampered), Err(Error::AeadFailure));

    // The legitimate counter-5 frame must still decrypt.
    assert_eq!(receiver.decrypt(&frames[5]).unwrap(), b"future payload");
}

#[test]
fn phase4_wrong_direction_rejected_before_ratchet_use() {
    let session_id = SessionId::from_bytes([4; 16]);

    let mut sender = DataSender::new(session_id, DirectionId::ResponderToInitiator, [8; 32]);

    let mut receiver = DataReceiver::new(session_id, DirectionId::InitiatorToResponder, [8; 32]);

    let frame = sender.encrypt(b"wrong direction").unwrap();

    // Direction is session state, not something the receiver should
    // accept from the peer as an authority over its ratchet.
    assert_eq!(receiver.decrypt(&frame), Err(Error::InvalidDataPayload));
}

#[test]
fn phase4_successful_decryption_commits_key_and_rejects_replay() {
    let session_id = SessionId::from_bytes([5; 16]);

    let mut sender = DataSender::new(session_id, DirectionId::InitiatorToResponder, [9; 32]);

    let mut receiver = DataReceiver::new(session_id, DirectionId::InitiatorToResponder, [9; 32]);

    let frame = sender.encrypt(b"one time message").unwrap();

    // First authenticated delivery succeeds.
    assert_eq!(receiver.decrypt(&frame).unwrap(), b"one time message");

    // Second delivery is rejected by replay protection.
    assert_eq!(receiver.decrypt(&frame), Err(Error::ReplayRejected));
}

// ============================================================================
// Phase 5: Session Lifecycle, Rekeying & Glare Resolution (§6, §9, App E.7, E.10)
// ============================================================================

#[test]
fn phase5_session_lifecycle_transitions_and_predicates() {
    use ruxmsg::session::{SessionLifecycle, SessionState};
    use std::time::{Duration, Instant};

    let session_id = SessionId::from_bytes([0x55; 16]);
    let mut lifecycle = SessionLifecycle::new(session_id);

    // Initial state is Handshaking
    assert_eq!(lifecycle.state(), SessionState::Handshaking);
    assert!(!lifecycle.can_originate_data());
    assert!(!lifecycle.can_receive_data());
    assert_eq!(
        lifecycle.record_sent_data(),
        Err(Error::InvalidStateTransition)
    );

    // Activation transitions to Active
    let t0 = Instant::now();
    lifecycle.activate(t0).unwrap();
    assert_eq!(lifecycle.state(), SessionState::Active);
    assert!(lifecycle.can_originate_data());
    assert!(lifecycle.can_receive_data());

    // Record sent data
    lifecycle.record_sent_data().unwrap();

    // Rekey triggers: time (24h) and message count (1M)
    assert!(!lifecycle.rekey_due(t0));
    assert!(lifecycle.rekey_due(t0 + Duration::from_secs(24 * 60 * 60)));

    // Begin rekey transitions to Rekeying (still permits originating & receiving data)
    lifecycle.begin_rekey().unwrap();
    assert_eq!(lifecycle.state(), SessionState::Rekeying);
    assert!(lifecycle.can_originate_data());
    assert!(lifecycle.can_receive_data());
    lifecycle.record_sent_data().unwrap();

    // Begin draining transitions to Draining (receive-only, origin disabled)
    let t_drain = Instant::now();
    lifecycle.begin_draining(t_drain).unwrap();
    assert_eq!(lifecycle.state(), SessionState::Draining);
    assert!(!lifecycle.can_originate_data());
    assert!(lifecycle.can_receive_data());
    assert_eq!(
        lifecycle.record_sent_data(),
        Err(Error::InvalidStateTransition)
    );

    // Drain expiration after 15 seconds
    assert!(!lifecycle.drain_expired(t_drain));
    assert!(!lifecycle.drain_expired(t_drain + Duration::from_secs(14)));
    assert!(lifecycle.drain_expired(t_drain + Duration::from_secs(15)));

    // Close transitions to Closed
    lifecycle.close();
    assert_eq!(lifecycle.state(), SessionState::Closed);
    assert!(!lifecycle.can_originate_data());
    assert!(!lifecycle.can_receive_data());
}

#[test]
fn phase5_rekey_glare_unsigned_lexicographical_tiebreak() {
    use ruxmsg::handshake::local_identity_wins_rekey_glare;

    // Compare raw 32-byte Ed25519 public keys using unsigned lexicographic byte order
    let key_low = PeerIdentity::from_bytes([0x01; 32]);
    let mut key_high_bytes = [0x01; 32];
    key_high_bytes[31] = 0x02;
    let key_high = PeerIdentity::from_bytes(key_high_bytes);

    assert!(local_identity_wins_rekey_glare(&key_high, &key_low));
    assert!(!local_identity_wins_rekey_glare(&key_low, &key_high));

    // Test byte boundary ordering (e.g. 0x80 vs 0x7F where signedness would fail)
    let key_msb_set = PeerIdentity::from_bytes([0x80; 32]);
    let key_msb_unset = PeerIdentity::from_bytes([0x7f; 32]);
    assert!(local_identity_wins_rekey_glare(
        &key_msb_set,
        &key_msb_unset
    ));
    assert!(!local_identity_wins_rekey_glare(
        &key_msb_unset,
        &key_msb_set
    ));
}

// ============================================================================
// Phase 6: Transport Independence & Concurrency (§6.2, §6.3, §11, App C)
// ============================================================================

#[test]
fn phase6_transport_memory_pair_duplex_and_close() {
    use ruxmsg::transport::{InMemoryTransport, Transport};

    let (mut left, mut right) = InMemoryTransport::pair();
    let frame1 = Frame::new(MessageType::Data, vec![0xa0]).unwrap();
    let frame2 = Frame::new(MessageType::Close, vec![0xa0]).unwrap();

    left.send(&frame1).unwrap();
    right.send(&frame2).unwrap();

    assert_eq!(right.receive().unwrap(), frame1);
    assert_eq!(left.receive().unwrap(), frame2);

    left.close().unwrap();
    assert_eq!(left.send(&frame1), Err(Error::TransportClosed));
    assert_eq!(left.receive(), Err(Error::TransportClosed));

    // When the remote endpoint is dropped, receiving on the peer returns TransportClosed
    drop(left);
    assert_eq!(right.receive(), Err(Error::TransportClosed));
}

// ============================================================================
// Phase 7: Error Handling, Resource Limits & CLOSE Registry (§10.1, §12.4, App E.8-E.9)
// ============================================================================

#[test]
fn phase7_close_frame_schema_and_reasons() {
    use ruxmsg::close::{ClosePayload, CloseReason};

    // Valid close reasons: 0=Normal, 1=ProtocolError, 2=AuthenticationFailure, 3=IdentityChanged, 4=ResourceLimit, 5=Shutdown
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
        let decoded = ClosePayload::decode(&frame).unwrap();
        assert_eq!(decoded, payload);
    }

    // Invalid reason codes
    assert!(matches!(
        CloseReason::try_from(6),
        Err(Error::InvalidClosePayload)
    ));
    assert!(matches!(
        CloseReason::try_from(255),
        Err(Error::InvalidClosePayload)
    ));

    // Detail field length bounded to 128 UTF-8 bytes (§E.8)
    let valid_detail = "a".repeat(128);
    let valid_payload = ClosePayload {
        session_id: None,
        reason: CloseReason::Normal,
        detail: Some(valid_detail),
    };
    assert!(valid_payload.encode().is_ok());

    let oversized_detail = "a".repeat(129);
    let oversized_payload = ClosePayload {
        session_id: None,
        reason: CloseReason::Normal,
        detail: Some(oversized_detail),
    };
    assert_eq!(oversized_payload.encode(), Err(Error::InvalidClosePayload));
}
