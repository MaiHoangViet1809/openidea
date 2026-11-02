//! Saved database passwords and SSH passphrases in the current OS user's
//! credential store. Legacy JSON data migrates only after verified writes.

use ide_core::{IdeError, IdeResult};
use keyring::{Entry, Error as KeyringError};
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const SERVICE: &str = "ai.l0ng.openidea";
/// Serializes migration and updates to the legacy file shared by projects.
static LOCK: Mutex<()> = Mutex::new(());

/// Project root → credential key → secret.
type Contents = BTreeMap<String, BTreeMap<String, String>>;

pub struct SecretStore {
    path: PathBuf,
    project: String,
}

/// Credential key of the SSH password / key passphrase of data source `id`.
pub fn ssh_key(id: &str) -> String {
    format!("{id}#ssh")
}

impl SecretStore {
    pub fn new(path: PathBuf, root: &Path) -> Self {
        #[cfg(test)]
        init_mock_store();
        Self { path, project: root.to_string_lossy().into_owned() }
    }

    pub fn get(&self, key: &str) -> Option<String> {
        let _g = LOCK.lock();
        if let Err(error) = self.migrate_legacy() {
            tracing::warn!("could not migrate saved database credentials: {}", error.message);
            return None;
        }
        match self.entry(&self.project, key).and_then(|entry| match entry.get_secret() {
            Ok(value) => String::from_utf8(value).map(Some).map_err(|error| store_error("decode credential", error)),
            Err(KeyringError::NoEntry) => Ok(None),
            Err(error) => Err(store_error("read credential", error)),
        }) {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!("could not read saved database credential: {}", error.message);
                None
            }
        }
    }

    pub fn set(&self, key: &str, secret: &str) -> IdeResult<()> {
        let _g = LOCK.lock();
        self.migrate_legacy()?;
        self.entry(&self.project, key)?
            .set_secret(secret.as_bytes())
            .map_err(|error| store_error("save credential", error))
    }

    pub fn delete(&self, key: &str) {
        let _g = LOCK.lock();
        if let Err(error) = self.migrate_legacy() {
            tracing::warn!("could not migrate saved database credentials before deletion: {}", error.message);
            return;
        }
        let result = self.entry(&self.project, key).and_then(|entry| match entry.delete_credential() {
            Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
            Err(error) => Err(store_error("delete credential", error)),
        });
        if let Err(error) = result {
            tracing::warn!("could not delete saved database credential: {}", error.message);
        }
    }

    fn entry(&self, project: &str, key: &str) -> IdeResult<Entry> {
        let namespace = self.path.to_string_lossy();
        Entry::new(SERVICE, &account(&namespace, project, key)).map_err(|error| store_error("open credential", error))
    }

    fn migrate_legacy(&self) -> IdeResult<()> {
        let temporary = self.path.with_extension("json.tmp");
        let (source, bytes) = match std::fs::read(&temporary) {
            Ok(bytes) => (temporary.clone(), bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => match std::fs::read(&self.path) {
                Ok(bytes) => (self.path.clone(), bytes),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(store_error("read legacy database credential file", error)),
            },
            Err(error) => return Err(store_error("read interrupted database credential write", error)),
        };
        let legacy: Contents = serde_json::from_slice(&bytes)
            .map_err(|error| IdeError::unavailable(format!("invalid legacy database credential file: {error}")))?;
        for (project, credentials) in legacy {
            for (key, secret) in credentials {
                let entry = self.entry(&project, &key)?;
                entry
                    .set_secret(secret.as_bytes())
                    .map_err(|error| store_error("migrate database credential", error))?;
                let stored =
                    entry.get_secret().map_err(|error| store_error("verify migrated database credential", error))?;
                if stored != secret.as_bytes() {
                    return Err(IdeError::unavailable("database credential migration verification failed"));
                }
            }
        }
        for legacy_path in [&self.path, &source, &temporary] {
            match std::fs::remove_file(legacy_path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(store_error("remove migrated database credential file", error)),
            }
        }
        Ok(())
    }
}

fn account(namespace: &str, project: &str, key: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    for value in [namespace.as_bytes(), project.as_bytes(), key.as_bytes()] {
        hasher.update(value);
        hasher.update(&[0]);
    }
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
    fn separates_projects_and_supports_crud_without_plaintext_files() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("db-passwords.json");
        let a = SecretStore::new(path.clone(), Path::new("/p/a"));
        let b = SecretStore::new(path.clone(), Path::new("/p/b"));
        a.set("s1", "pw-a").unwrap();
        b.set("s1", "pw-b").unwrap();
        b.set(&ssh_key("s1"), "pass").unwrap();
        assert_eq!(a.get("s1").as_deref(), Some("pw-a"));
        assert_eq!(b.get("s1#ssh").as_deref(), Some("pass"));
        assert_eq!(b.get("s1").as_deref(), Some("pw-b"));
        assert!(!path.exists(), "new saves never create a plaintext store");

        a.set("s1", "pw-a2").unwrap();
        assert_eq!(a.get("s1").as_deref(), Some("pw-a2"));
        a.delete("s1");
        assert_eq!(a.get("s1"), None);
        assert_eq!(b.get("s1").as_deref(), Some("pw-b"));
    }

    #[test]
    fn migrates_all_projects_and_removes_legacy_file_after_verification() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("db-passwords.json");
        std::fs::write(&path, br#"{"/p/a":{"s1":"pw-a"},"/p/b":{"s1":"pw-b"}}"#).unwrap();
        let a = SecretStore::new(path.clone(), Path::new("/p/a"));
        let b = SecretStore::new(path.clone(), Path::new("/p/b"));

        assert_eq!(a.get("s1").as_deref(), Some("pw-a"));
        assert_eq!(b.get("s1").as_deref(), Some("pw-b"));
        assert!(!path.exists());
    }

    #[test]
    fn retains_invalid_legacy_source_and_does_not_fall_back_to_plaintext() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("db-passwords.json");
        let original = br#"{"/p/a":{"s1":"secret""#;
        std::fs::write(&path, original).unwrap();
        let store = SecretStore::new(path.clone(), Path::new("/p/a"));

        assert!(store.set("new", "secret").is_err());
        assert_eq!(store.get("s1"), None);
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }

    #[test]
    fn store_failure_preserves_legacy_and_never_writes_plaintext() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("db-passwords.json");
        let original = br#"{"/p/a":{"s1":"legacy-secret"}}"#;
        std::fs::write(&path, original).unwrap();
        let store = SecretStore::new(path.clone(), Path::new("/p/a"));

        test_credential_store::fail_next_set();
        assert!(store.set("new", "secret").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original);

        std::fs::remove_file(&path).unwrap();
        test_credential_store::fail_next_set();
        assert!(store.set("new", "secret").is_err());
        assert!(!path.exists(), "store failures never trigger plaintext fallback");
    }

    #[test]
    fn migrates_interrupted_atomic_write_from_legacy_temp_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("db-passwords.json");
        let temporary = path.with_extension("json.tmp");
        std::fs::write(&path, br#"{"/p/a":{"s1":"old"}}"#).unwrap();
        std::fs::write(&temporary, br#"{"/p/a":{"s1":"new"}}"#).unwrap();
        let store = SecretStore::new(path.clone(), Path::new("/p/a"));

        assert_eq!(store.get("s1").as_deref(), Some("new"));
        assert!(!path.exists());
        assert!(!temporary.exists());
    }
}
