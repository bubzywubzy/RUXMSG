//! Persistence boundary for the local RUXMSG identity.
//!
//! RUXMSG deliberately persists exactly one piece of application state:
//! the local Ed25519 private identity seed.
//!
//! Everything else is volatile:
//!
//! - peer identities
//! - peer addresses
//! - trust state
//! - SAS approvals
//! - session state
//! - ratchet state
//! - message keys
//! - skipped keys
//! - session IDs
//! - chat history
//! - logs
//! - profile enumeration metadata
//!
//! The identity seed is stored through the operating system credential store,
//! never in an application-controlled plaintext file.

use crate::crypto::IdentityKeypair;
use crate::error::{Error, Result};

/// Abstracts an OS-level credential store.
///
/// Implementations must keep secret material inside the operating system's
/// credential mechanism rather than application-controlled files.
pub trait SecretStore {
    /// Loads secret bytes for an account.
    ///
    /// Returns `None` when the account does not exist.
    fn get_secret(&self, account: &str) -> Result<Option<Vec<u8>>>;

    /// Stores secret bytes for an account.
    fn set_secret(&mut self, account: &str, value: &[u8]) -> Result<()>;
}

/// Real OS credential-store adapter.
///
/// Depending on the platform, the `keyring` crate maps this to the native
/// credential mechanism:
///
/// - Linux: Secret Service
/// - macOS: Keychain
/// - Windows: Credential Manager
pub struct KeyringSecretStore {
    service: String,
}

impl KeyringSecretStore {
    /// Creates a credential-store adapter scoped to one RUXMSG profile.
    ///
    /// The profile name becomes part of the credential-store service name.
    /// RUXMSG does not persist a separate profile registry.
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

/// Persists exactly one local Ed25519 identity seed through [`SecretStore`].
///
/// The seed is always 32 bytes. No public identity, fingerprint, peer record,
/// session state, or other RUXMSG state is persisted here.
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

    /// Loads the persisted identity.
    ///
    /// Returns `Ok(None)` when this profile has never been initialized.
    pub fn load(&self) -> Result<Option<IdentityKeypair>> {
        let Some(bytes) = self.secrets.get_secret(&self.account)? else {
            return Ok(None);
        };

        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::Storage("stored identity seed has the wrong length".to_string()))?;

        Ok(Some(IdentityKeypair::from_bytes(&seed)))
    }

    /// Persists exactly the Ed25519 private seed.
    pub fn save(&mut self, identity: &IdentityKeypair) -> Result<()> {
        self.secrets.set_secret(&self.account, &identity.to_bytes())
    }

    /// Loads the existing identity or generates it on first use.
    pub fn load_or_generate(&mut self) -> Result<IdentityKeypair> {
        if let Some(identity) = self.load()? {
            return Ok(identity);
        }

        let identity = IdentityKeypair::generate();
        self.save(&identity)?;
        Ok(identity)
    }
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
        let reloaded = second.load().unwrap().expect("identity should exist");

        assert_eq!(reloaded.to_bytes(), generated.to_bytes());
    }

    #[test]
    fn missing_identity_is_distinguishable_from_existing_identity() {
        let secrets = FakeSecretStore::default();

        let store = IdentityKeyStore::new(secrets, "identity");

        assert!(store.load().unwrap().is_none());
    }

    #[test]
    fn malformed_identity_seed_is_rejected() {
        let secrets = FakeSecretStore::default();

        let mut store = IdentityKeyStore::new(secrets.clone(), "identity");

        store.secrets.set_secret("identity", &[1, 2, 3]).unwrap();

        assert!(store.load().is_err());
    }
}
