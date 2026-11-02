//! Saved SSH, Git and proxy credentials in the current OS user's credential store.
//! Legacy JSON files are migrated and removed only after every item is verified.

use ide_core::{IdeError, IdeResult};
use keyring::{Entry, Error as KeyringError};
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::path::PathBuf;

const SERVICE: &str = "ai.l0ng.openidea";
static LOCK: Mutex<()> = Mutex::new(());

pub struct SecretFile {
    path: PathBuf,
}

impl SecretFile {
    pub fn new(path: PathBuf) -> Self {
        #[cfg(test)]
        init_mock_store();
        Self { path }
    }

    pub fn get(&self, key: &str) -> Option<String> {
        let _g = LOCK.lock();
        if let Err(error) = self.migrate_legacy() {
            tracing::warn!("could not migrate saved credentials: {}", error.message);
            return None;
        }
        match self.entry(key).and_then(|entry| match entry.get_secret() {
            Ok(value) => String::from_utf8(value).map(Some).map_err(|error| store_error("decode credential", error)),
            Err(KeyringError::NoEntry) => Ok(None),
            Err(error) => Err(store_error("read credential", error)),
        }) {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!("could not read saved credential: {}", error.message);
                None
            }
        }
    }

    pub fn set(&self, key: &str, secret: &str) -> IdeResult<()> {
        let _g = LOCK.lock();
        self.migrate_legacy()?;
        let mut keys = self.read_keys()?;
        let entry = self.entry(key)?;
        let previous = match entry.get_secret() {
            Ok(value) => Some(value),
            Err(KeyringError::NoEntry) => None,
            Err(error) => return Err(store_error("read credential before update", error)),
        };
        entry.set_secret(secret.as_bytes()).map_err(|error| store_error("save credential", error))?;
        if keys.insert(key.to_owned())
            && let Err(error) = self.write_keys(&keys)
        {
            let rollback = match previous {
                Some(previous) => entry.set_secret(&previous),
                None => entry.delete_credential(),
            };
            if let Err(rollback_error) = rollback {
                tracing::error!("credential index update failed and rollback failed: {rollback_error}");
            }
            return Err(error);
        }
        Ok(())
    }

    pub fn delete(&self, key: &str) {
        let _g = LOCK.lock();
        if let Err(error) = self.migrate_legacy() {
            tracing::warn!("could not migrate saved credentials before deletion: {}", error.message);
            return;
        }
        let result = self.entry(key).and_then(|entry| {
            let previous = match entry.get_secret() {
                Ok(value) => Some(value),
                Err(KeyringError::NoEntry) => None,
                Err(error) => return Err(store_error("read credential before deletion", error)),
            };
            let mut keys = self.read_keys()?;
            let was_indexed = keys.remove(key);
            match entry.delete_credential() {
                Ok(()) | Err(KeyringError::NoEntry) => {}
                Err(error) => return Err(store_error("delete credential", error)),
            }
            if was_indexed && let Err(error) = self.write_keys(&keys) {
                if let Some(previous) = previous
                    && let Err(rollback_error) = entry.set_secret(&previous)
                {
                    tracing::error!("credential index update failed and rollback failed: {rollback_error}");
                }
                return Err(error);
            }
            Ok(())
        });
        if let Err(error) = result {
            tracing::warn!("could not delete saved credential: {}", error.message);
        }
    }

    /// Sorted keys stored for Settings › Git credential management.
    pub fn keys(&self) -> Vec<String> {
        let _g = LOCK.lock();
        if let Err(error) = self.migrate_legacy() {
            tracing::warn!("could not migrate saved credentials: {}", error.message);
            return Vec::new();
        }
        match self.read_keys() {
            Ok(keys) => keys.into_iter().collect(),
            Err(error) => {
                tracing::warn!("could not list saved credentials: {}", error.message);
                Vec::new()
            }
        }
    }

    fn entry(&self, key: &str) -> IdeResult<Entry> {
        Entry::new(SERVICE, &account(&self.path.to_string_lossy(), "credential", key))
            .map_err(|error| store_error("open credential", error))
    }

    fn index_entry(&self) -> IdeResult<Entry> {
        Entry::new(SERVICE, &account(&self.path.to_string_lossy(), "index", ""))
            .map_err(|error| store_error("open credential index", error))
    }

    fn read_keys(&self) -> IdeResult<std::collections::BTreeSet<String>> {
        let entry = self.index_entry()?;
        match entry.get_secret() {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|error| IdeError::unavailable(format!("invalid OS credential index: {error}"))),
            Err(KeyringError::NoEntry) => Ok(std::collections::BTreeSet::new()),
            Err(error) => Err(store_error("read credential index", error)),
        }
    }

    fn write_keys(&self, keys: &std::collections::BTreeSet<String>) -> IdeResult<()> {
        let entry = self.index_entry()?;
        let bytes = serde_json::to_vec(keys).map_err(|error| IdeError::internal(error.to_string()))?;
        entry.set_secret(&bytes).map_err(|error| store_error("save credential index", error))?;
        let stored = entry.get_secret().map_err(|error| store_error("verify credential index", error))?;
        if stored != bytes {
            return Err(IdeError::unavailable("credential index verification failed"));
        }
        Ok(())
    }

    fn migrate_legacy(&self) -> IdeResult<()> {
        let temporary = self.path.with_extension("json.tmp");
        let (source, bytes) = match std::fs::read(&temporary) {
            Ok(bytes) => (temporary.clone(), bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => match std::fs::read(&self.path) {
                Ok(bytes) => (self.path.clone(), bytes),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(store_error("read legacy credential file", error)),
            },
            Err(error) => return Err(store_error("read interrupted credential write", error)),
        };
        let legacy: BTreeMap<String, String> = serde_json::from_slice(&bytes)
            .map_err(|error| IdeError::unavailable(format!("invalid legacy credential file: {error}")))?;
        let mut keys = std::collections::BTreeSet::new();
        for (key, secret) in legacy {
            let entry = self.entry(&key)?;
            entry.set_secret(secret.as_bytes()).map_err(|error| store_error("migrate credential", error))?;
            let stored = entry.get_secret().map_err(|error| store_error("verify migrated credential", error))?;
            if stored != secret.as_bytes() {
                return Err(IdeError::unavailable("credential migration verification failed"));
            }
            keys.insert(key);
        }
        self.write_keys(&keys)?;
        for legacy_path in [&self.path, &source, &temporary] {
            match std::fs::remove_file(legacy_path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(store_error("remove migrated credential file", error)),
            }
        }
        Ok(())
    }
}

fn account(namespace: &str, kind: &str, key: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(namespace.as_bytes());
    hasher.update(&[0]);
    hasher.update(kind.as_bytes());
    hasher.update(&[0]);
    hasher.update(key.as_bytes());
    format!("v1-{}", hasher.finalize().to_hex())
}

fn store_error(action: &str, error: impl std::fmt::Display) -> IdeError {
    IdeError::unavailable(format!("could not {action} in the OS credential store: {error}"))
}

#[cfg(test)]
fn init_mock_store() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| keyring::set_default_credential_builder(test_credential_store::builder()));
}

#[cfg(test)]
mod test_credential_store {
    use keyring::Error;
    use keyring::credential::{Credential, CredentialApi, CredentialBuilderApi, CredentialPersistence};
    use std::any::Any;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Mutex, OnceLock};

    static VALUES: OnceLock<Mutex<HashMap<String, Vec<u8>>>> = OnceLock::new();
    static FAIL_NEXT_SET: AtomicBool = AtomicBool::new(false);

    #[derive(Debug)]
    struct MemoryBuilder;

    #[derive(Debug)]
    struct MemoryCredential(String);

    impl CredentialApi for MemoryCredential {
        fn set_secret(&self, secret: &[u8]) -> keyring::Result<()> {
            if FAIL_NEXT_SET.swap(false, Ordering::SeqCst) {
                return Err(Error::NoStorageAccess(Box::new(std::io::Error::other("injected store failure"))));
            }
            VALUES.get_or_init(Default::default).lock().unwrap().insert(self.0.clone(), secret.to_vec());
            Ok(())
        }

        fn get_secret(&self) -> keyring::Result<Vec<u8>> {
            VALUES.get_or_init(Default::default).lock().unwrap().get(&self.0).cloned().ok_or(Error::NoEntry)
        }

        fn delete_credential(&self) -> keyring::Result<()> {
            VALUES.get_or_init(Default::default).lock().unwrap().remove(&self.0).map(|_| ()).ok_or(Error::NoEntry)
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    impl CredentialBuilderApi for MemoryBuilder {
        fn build(&self, _target: Option<&str>, service: &str, user: &str) -> keyring::Result<Box<Credential>> {
            Ok(Box::new(MemoryCredential(format!("{service}\0{user}"))))
        }

        fn as_any(&self) -> &dyn Any {
            self
        }

        fn persistence(&self) -> CredentialPersistence {
            CredentialPersistence::UntilDelete
        }
    }

    pub(super) fn builder() -> Box<keyring::credential::CredentialBuilder> {
        Box::new(MemoryBuilder)
    }

    pub(super) fn fail_next_set() {
        FAIL_NEXT_SET.store(true, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrates_then_creates_updates_and_deletes_without_plaintext_files() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ssh-passwords.json");
        std::fs::write(&path, br#"{"profile":"legacy-secret"}"#).unwrap();
        let file = SecretFile::new(path.clone());

        assert_eq!(file.get("profile").as_deref(), Some("legacy-secret"));
        assert_eq!(file.keys(), vec!["profile"]);
        assert!(!path.exists(), "legacy plaintext is removed after verified migration");
        assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);

        file.set("profile", "updated-secret").unwrap();
        assert_eq!(file.get("profile").as_deref(), Some("updated-secret"));
        file.delete("profile");
        assert_eq!(file.get("profile"), None);
        assert!(file.keys().is_empty());
        assert!(!path.exists(), "no plaintext fallback is created");
    }

    #[test]
    fn retains_invalid_legacy_source_and_fails_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ssh-passwords.json");
        let original = br#"{"profile":"secret""#;
        std::fs::write(&path, original).unwrap();
        let file = SecretFile::new(path.clone());

        assert!(file.set("new", "secret").is_err());
        assert_eq!(file.get("profile"), None);
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }

    #[test]
    fn store_failure_does_not_create_plaintext_or_remove_legacy_source() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ssh-passwords.json");
        let original = br#"{"profile":"legacy-secret"}"#;
        std::fs::write(&path, original).unwrap();
        let file = SecretFile::new(path.clone());

        test_credential_store::fail_next_set();
        assert!(file.set("new", "secret").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original);

        std::fs::remove_file(&path).unwrap();
        test_credential_store::fail_next_set();
        assert!(file.set("new", "secret").is_err());
        assert!(!path.exists(), "store failures never trigger plaintext fallback");
    }

    #[test]
    fn separates_credential_files() {
        let tmp = tempfile::tempdir().unwrap();
        let ssh = SecretFile::new(tmp.path().join("ssh-passwords.json"));
        let proxy = SecretFile::new(tmp.path().join("proxy-password.json"));
        ssh.set("same-key", "ssh-secret").unwrap();
        proxy.set("same-key", "proxy-secret").unwrap();
        assert_eq!(ssh.get("same-key").as_deref(), Some("ssh-secret"));
        assert_eq!(proxy.get("same-key").as_deref(), Some("proxy-secret"));
    }

    #[test]
    fn migrates_interrupted_atomic_write_from_legacy_temp_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("git-credentials.json");
        let temporary = path.with_extension("json.tmp");
        std::fs::write(&path, br#"{"https://example.test":"old\nold-secret"}"#).unwrap();
        std::fs::write(&temporary, br#"{"https://example.test":"new\nnew-secret"}"#).unwrap();
        let file = SecretFile::new(path.clone());

        assert_eq!(file.get("https://example.test").as_deref(), Some("new\nnew-secret"));
        assert!(!path.exists());
        assert!(!temporary.exists());
    }
}
