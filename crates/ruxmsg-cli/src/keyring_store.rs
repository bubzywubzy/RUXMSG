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
    fn ensure_persistent(&self) -> Result<()> {
        // `keyring` is built with native backends only in this project
        // (Credential Manager, Keychain, and Secret Service). Do not silently
        // accept another platform or an in-memory/file fallback: identity
        // persistence is a protocol requirement, not a convenience.
        #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
        {
            Ok(())
        }

        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        {
            Err(Error::Storage(
                "no verified persistent native credential-store backend for this platform"
                    .to_string(),
            ))
        }
    }

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
