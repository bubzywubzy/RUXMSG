//! Persistence boundaries for identity credentials and trusted peers.
//!
//! Active cryptographic sessions are intentionally not represented here.
//! Implementations should keep identity seeds and sealing keys in an OS
//! credential store rather than application-controlled plaintext files.

use ciborium::value::Value;

use crate::crypto::{IdentityKeypair, decrypt_message, encrypt_message};
use crate::error::{Error, Result};
use crate::identity::{PeerIdentity, PeerRecord, TrustState};

/// Persistence boundary for identity and trust records.
///
/// Session state must not be persisted through this interface. Implementations
/// must keep private identity material local and must update records atomically.
pub trait TrustStore {
    /// Looks up a peer by its cryptographic identity.
    fn get(&self, identity: &PeerIdentity) -> Result<Option<PeerRecord>>;
    /// Inserts or replaces a peer record atomically from the caller's view.
    fn put(&mut self, record: PeerRecord) -> Result<()>;
    /// Removes a peer record and returns the previous value, if present.
    fn remove(&mut self, identity: &PeerIdentity) -> Result<Option<PeerRecord>>;
}

#[derive(Debug, Default)]
pub struct InMemoryTrustStore {
    records: Vec<PeerRecord>,
}

impl InMemoryTrustStore {
    /// Returns a slice of all stored records.
    pub fn records(&self) -> &[PeerRecord] {
        &self.records
    }
}

impl TrustStore for InMemoryTrustStore {
    fn get(&self, identity: &PeerIdentity) -> Result<Option<PeerRecord>> {
        Ok(self
            .records
            .iter()
            .find(|record| &record.identity == identity)
            .cloned())
    }

    fn put(&mut self, record: PeerRecord) -> Result<()> {
        if let Some(existing) = self
            .records
            .iter_mut()
            .find(|item| item.identity == record.identity)
        {
            *existing = record;
        } else {
            self.records.push(record);
        }
        Ok(())
    }

    fn remove(&mut self, identity: &PeerIdentity) -> Result<Option<PeerRecord>> {
        let position = self
            .records
            .iter()
            .position(|record| &record.identity == identity);
        Ok(position.map(|index| self.records.remove(index)))
    }
}

/// Abstracts an OS-level credential store so identity/trust-key material can
/// be persisted without ever touching application-controlled plaintext files.
pub trait SecretStore {
    /// Loads secret bytes for an account, returning `None` when absent.
    fn get_secret(&self, account: &str) -> Result<Option<Vec<u8>>>;
    /// Stores secret bytes for an account.
    fn set_secret(&mut self, account: &str, value: &[u8]) -> Result<()>;
}

/// Real OS keychain (Secret Service on Linux, Keychain on macOS, Credential
/// Manager on Windows) backed by the `keyring` crate.
pub struct KeyringSecretStore {
    service: String,
}

impl KeyringSecretStore {
    /// Creates a keyring adapter scoped to one service name.
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    fn entry(&self, account: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(&self.service, account)
            .map_err(|error| Error::Storage(error.to_string()))
    }
}

impl SecretStore for KeyringSecretStore {
    fn get_secret(&self, account: &str) -> Result<Option<Vec<u8>>> {
        match self.entry(account)?.get_secret() {
            Ok(bytes) => Ok(Some(bytes)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(Error::Storage(error.to_string())),
        }
    }

    fn set_secret(&mut self, account: &str, value: &[u8]) -> Result<()> {
        self.entry(account)?
            .set_secret(value)
            .map_err(|error| Error::Storage(error.to_string()))
    }
}

/// Persists the local Ed25519 identity seed in an OS keychain via [`SecretStore`].
///
/// Only the 32-byte seed ever leaves memory, and only into the OS credential
/// store; it is never written to an application-controlled file.
pub struct IdentityKeyStore<S: SecretStore> {
    secrets: S,
    account: String,
}

impl<S: SecretStore> IdentityKeyStore<S> {
    /// Associates an identity seed with a credential-store account.
    pub fn new(secrets: S, account: impl Into<String>) -> Self {
        Self {
            secrets,
            account: account.into(),
        }
    }

    /// Loads and validates the persisted 32-byte identity seed, if present.
    pub fn load(&self) -> Result<Option<IdentityKeypair>> {
        let Some(bytes) = self.secrets.get_secret(&self.account)? else {
            return Ok(None);
        };
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::Storage("stored identity seed has the wrong length".to_string()))?;
        Ok(Some(IdentityKeypair::from_bytes(&seed)))
    }

    /// Persists only the identity seed through the configured secret store.
    pub fn save(&mut self, identity: &IdentityKeypair) -> Result<()> {
        self.secrets.set_secret(&self.account, &identity.to_bytes())
    }

    /// Loads the persisted identity, generating and saving a fresh one on first run.
    pub fn load_or_generate(&mut self) -> Result<IdentityKeypair> {
        if let Some(identity) = self.load()? {
            return Ok(identity);
        }
        let identity = IdentityKeypair::generate();
        self.save(&identity)?;
        Ok(identity)
    }
}

const TRUST_STORE_AAD: &[u8] = b"RUXMSG/1/trust-store";
const NONCE_LEN: usize = 12;

/// A `TrustStore` whose on-disk representation is AEAD-sealed with a key held
/// in an OS keychain, so the file alone (without the keychain secret) reveals
/// nothing about trusted peers.
pub struct SealedFileTrustStore<S: SecretStore> {
    path: std::path::PathBuf,
    key_store: IdentityKeyStoreLikeKey<S>,
    records: Vec<PeerRecord>,
}

/// Reuses the seed-sealing primitives for a symmetric AEAD key instead of an
/// Ed25519 seed; the stored bytes are an opaque 32-byte key either way.
struct IdentityKeyStoreLikeKey<S: SecretStore> {
    secrets: S,
    account: String,
}

impl<S: SecretStore> IdentityKeyStoreLikeKey<S> {
    fn load_or_generate(&mut self) -> Result<[u8; 32]> {
        if let Some(bytes) = self.secrets.get_secret(&self.account)? {
            return bytes.try_into().map_err(|_| {
                Error::Storage("stored trust-store key has the wrong length".to_string())
            });
        }
        let mut key = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut key);
        self.secrets.set_secret(&self.account, &key)?;
        Ok(key)
    }
}

impl<S: SecretStore> SealedFileTrustStore<S> {
    /// Opens (or creates) the sealed trust file at `path`, generating a fresh
    /// AEAD key under `key_account` in `secrets` on first use.
    pub fn open(
        path: impl Into<std::path::PathBuf>,
        secrets: S,
        key_account: impl Into<String>,
    ) -> Result<Self> {
        let path = path.into();
        let mut key_store = IdentityKeyStoreLikeKey {
            secrets,
            account: key_account.into(),
        };
        let key = key_store.load_or_generate()?;
        let records = match std::fs::read(&path) {
            Ok(sealed) => decrypt_records(&key, &sealed)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(Error::Storage(error.to_string())),
        };
        Ok(Self {
            path,
            key_store,
            records,
        })
    }

    /// Returns a slice of all stored records.
    pub fn records(&self) -> &[PeerRecord] {
        &self.records
    }

    fn persist(&mut self) -> Result<()> {
        let key = self.key_store.load_or_generate()?;
        let sealed = encrypt_records(&key, &self.records)?;
        let tmp_path = self.path.with_extension("tmp");
        std::fs::write(&tmp_path, &sealed).map_err(|error| Error::Storage(error.to_string()))?;
        std::fs::rename(&tmp_path, &self.path).map_err(|error| Error::Storage(error.to_string()))
    }
}

impl<S: SecretStore> TrustStore for SealedFileTrustStore<S> {
    fn get(&self, identity: &PeerIdentity) -> Result<Option<PeerRecord>> {
        Ok(self
            .records
            .iter()
            .find(|record| &record.identity == identity)
            .cloned())
    }

    fn put(&mut self, record: PeerRecord) -> Result<()> {
        if let Some(existing) = self
            .records
            .iter_mut()
            .find(|item| item.identity == record.identity)
        {
            *existing = record;
        } else {
            self.records.push(record);
        }
        self.persist()
    }

    fn remove(&mut self, identity: &PeerIdentity) -> Result<Option<PeerRecord>> {
        let position = self
            .records
            .iter()
            .position(|record| &record.identity == identity);
        let removed = position.map(|index| self.records.remove(index));
        if removed.is_some() {
            self.persist()?;
        }
        Ok(removed)
    }
}

fn trust_state_code(state: TrustState) -> u8 {
    match state {
        TrustState::Unknown => 0,
        TrustState::Trusted => 1,
        TrustState::Revoked => 2,
        TrustState::Replaced => 3,
    }
}

fn trust_state_from_code(code: u64) -> Result<TrustState> {
    match code {
        0 => Ok(TrustState::Unknown),
        1 => Ok(TrustState::Trusted),
        2 => Ok(TrustState::Revoked),
        3 => Ok(TrustState::Replaced),
        _ => Err(Error::Storage("unknown trust state code".to_string())),
    }
}

fn encode_records(records: &[PeerRecord]) -> Result<Vec<u8>> {
    let entries = records
        .iter()
        .map(|record| {
            let mut fields = vec![
                (
                    Value::Integer(0.into()),
                    Value::Bytes(record.identity.as_bytes().to_vec()),
                ),
                (
                    Value::Integer(1.into()),
                    Value::Integer(u64::from(trust_state_code(record.trust_state)).into()),
                ),
            ];
            if let Some(name) = &record.display_name {
                fields.push((Value::Integer(2.into()), Value::Text(name.clone())));
            }
            Value::Map(fields)
        })
        .collect();
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&Value::Array(entries), &mut encoded)
        .map_err(|error| Error::Storage(error.to_string()))?;
    Ok(encoded)
}

fn decode_records(bytes: &[u8]) -> Result<Vec<PeerRecord>> {
    let value: Value = ciborium::de::from_reader(bytes)
        .map_err(|error| Error::Storage(format!("corrupt trust store contents: {error}")))?;
    let Value::Array(entries) = value else {
        return Err(Error::Storage("corrupt trust store contents".to_string()));
    };
    entries
        .into_iter()
        .map(|entry| {
            let Value::Map(fields) = entry else {
                return Err(Error::Storage("corrupt trust store record".to_string()));
            };
            let mut identity = None;
            let mut trust_state = None;
            let mut display_name = None;
            for (key, value) in fields {
                let Value::Integer(key) = key else {
                    return Err(Error::Storage("corrupt trust store record".to_string()));
                };
                match u64::try_from(key)
                    .map_err(|_| Error::Storage("corrupt trust store record".to_string()))?
                {
                    0 => {
                        let Value::Bytes(bytes) = value else {
                            return Err(Error::Storage("corrupt trust store record".to_string()));
                        };
                        let array: [u8; PeerIdentity::LENGTH] = bytes.try_into().map_err(|_| {
                            Error::Storage("corrupt trust store identity length".to_string())
                        })?;
                        identity = Some(PeerIdentity::from_bytes(array));
                    }
                    1 => {
                        let Value::Integer(code) = value else {
                            return Err(Error::Storage("corrupt trust store record".to_string()));
                        };
                        let code = u64::try_from(code).map_err(|_| {
                            Error::Storage("corrupt trust store record".to_string())
                        })?;
                        trust_state = Some(trust_state_from_code(code)?);
                    }
                    2 => {
                        let Value::Text(text) = value else {
                            return Err(Error::Storage("corrupt trust store record".to_string()));
                        };
                        display_name = Some(text);
                    }
                    _ => return Err(Error::Storage("corrupt trust store record".to_string())),
                }
            }
            Ok(PeerRecord {
                identity: identity
                    .ok_or_else(|| Error::Storage("missing trust store identity".to_string()))?,
                display_name,
                trust_state: trust_state
                    .ok_or_else(|| Error::Storage("missing trust store state".to_string()))?,
            })
        })
        .collect()
}

fn encrypt_records(key: &[u8; 32], records: &[PeerRecord]) -> Result<Vec<u8>> {
    let plaintext = encode_records(records)?;
    let mut nonce = [0u8; NONCE_LEN];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut nonce);
    let ciphertext = encrypt_message(key, &nonce, TRUST_STORE_AAD, &plaintext)?;
    let mut sealed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    Ok(sealed)
}

fn decrypt_records(key: &[u8; 32], sealed: &[u8]) -> Result<Vec<PeerRecord>> {
    if sealed.len() < NONCE_LEN {
        return Err(Error::Storage("truncated trust store file".to_string()));
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().expect("split_at guarantees the length");
    let plaintext = decrypt_message(key, &nonce, TRUST_STORE_AAD, ciphertext)
        .map_err(|_| Error::Storage("trust store authentication failed".to_string()))?;
    decode_records(&plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;

    #[derive(Default, Clone)]
    struct FakeSecretStore(Rc<RefCell<HashMap<String, Vec<u8>>>>);

    impl SecretStore for FakeSecretStore {
        fn get_secret(&self, account: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.0.borrow().get(account).cloned())
        }

        fn set_secret(&mut self, account: &str, value: &[u8]) -> Result<()> {
            self.0
                .borrow_mut()
                .insert(account.to_string(), value.to_vec());
            Ok(())
        }
    }

    #[test]
    fn identity_key_store_generates_once_and_persists_across_instances() {
        let secrets = FakeSecretStore::default();
        let mut first = IdentityKeyStore::new(secrets.clone(), "identity");
        let generated = first.load_or_generate().unwrap();

        let second = IdentityKeyStore::new(secrets, "identity");
        let reloaded = second.load().unwrap().unwrap();
        assert_eq!(reloaded.to_bytes(), generated.to_bytes());
    }

    #[test]
    fn sealed_trust_store_round_trips_through_disk() {
        let dir =
            std::env::temp_dir().join(format!("ruxmsg-trust-store-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("trust.sealed");
        let secrets = FakeSecretStore::default();

        let identity = PeerIdentity::from_bytes([7; 32]);
        {
            let mut store =
                SealedFileTrustStore::open(&path, secrets.clone(), "trust-key").unwrap();
            let mut record = PeerRecord::new(identity);
            record.trust_state = TrustState::Trusted;
            record.display_name = Some("alice".to_string());
            store.put(record).unwrap();
        }

        let reopened = SealedFileTrustStore::open(&path, secrets, "trust-key").unwrap();
        let record = reopened.get(&identity).unwrap().unwrap();
        assert_eq!(record.trust_state, TrustState::Trusted);
        assert_eq!(record.display_name.as_deref(), Some("alice"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn sealed_trust_store_rejects_tampered_ciphertext() {
        let dir =
            std::env::temp_dir().join(format!("ruxmsg-trust-store-tamper-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("trust.sealed");
        let secrets = FakeSecretStore::default();
        {
            let mut store =
                SealedFileTrustStore::open(&path, secrets.clone(), "trust-key").unwrap();
            store
                .put(PeerRecord::new(PeerIdentity::from_bytes([1; 32])))
                .unwrap();
        }
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        std::fs::write(&path, bytes).unwrap();

        assert!(SealedFileTrustStore::open(&path, secrets, "trust-key").is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn sealed_trust_store_wrong_key_cannot_decrypt() {
        let dir = std::env::temp_dir().join(format!(
            "ruxmsg-trust-store-wrongkey-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("trust.sealed");
        {
            let secrets = FakeSecretStore::default();
            let mut store = SealedFileTrustStore::open(&path, secrets, "trust-key").unwrap();
            store
                .put(PeerRecord::new(PeerIdentity::from_bytes([1; 32])))
                .unwrap();
        }
        // A different secret store has no record of the original key.
        let other_secrets = FakeSecretStore::default();
        assert!(SealedFileTrustStore::open(&path, other_secrets, "trust-key").is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}
