//! OS credential-store adapter for the identity seed.

use ruxmsg::error::{Error, Result};
use ruxmsg::storage::SecretStore;
use zeroize::Zeroizing;

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
    fn get_secret(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        match self.entry(account)?.get_secret() {
            Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
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
