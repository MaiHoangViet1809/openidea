//! Response history: request/response exchanges are authenticated-encrypted in
//! the project's data folder, with the random key held by the OS credential store.

use crate::exec::{HttpResponse, PreparedRequest};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead, aead::consts::U12};
use ide_core::{IdeError, IdeResult, IpcPath};
use keyring::{Entry, Error as KeyringError};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use specta::Type;
use std::path::{Path, PathBuf};

pub const MAX_ENTRIES: usize = 100;
const LEGACY_INDEX: &str = "index.json";
const INDEX: &str = "index.enc";
const MAGIC: &[u8; 4] = b"OIH1";
const SERVICE: &str = "ai.l0ng.openidea";
static KEY_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Type)]
#[serde(rename_all = "camelCase")]
#[serde(rename = "HttpHistoryEntry")]
pub struct HistoryEntry {
    pub id: String,
    /// Unix epoch, ms.
    pub time_ms: f64,
    pub name: Option<String>,
    pub method: String,
    pub url: String,
    /// `None` when the request failed.
    pub status: Option<u16>,
    pub total_ms: Option<f64>,
    /// The `.http` file the request came from.
    pub file: Option<IpcPath>,
    pub error: Option<String>,
}

/// One request with its outcome.
#[derive(Debug, Clone, Serialize, Deserialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct HttpExchange {
    pub entry: HistoryEntry,
    pub request: PreparedRequest,
    pub response: Option<HttpResponse>,
}

pub struct History {
    dir: PathBuf,
    lock: Mutex<()>,
}

impl History {
    pub fn new(dir: PathBuf) -> Self {
        #[cfg(test)]
        init_mock_store();
        Self { dir, lock: Mutex::new(()) }
    }

    fn file(&self, id: &str) -> IdeResult<PathBuf> {
        if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(IdeError::invalid("invalid history id"));
        }
        Ok(self.dir.join(format!("{id}.enc")))
    }

    pub fn list(&self) -> Vec<HistoryEntry> {
        let _g = self.lock.lock();
        let result = self.migrate_legacy().and_then(|()| self.read_index());
        match result {
            Ok(index) => index,
            Err(error) => {
                tracing::warn!("could not read HTTP history: {}", error.message);
                Vec::new()
            }
        }
    }

    pub fn get(&self, id: &str) -> IdeResult<HttpExchange> {
        let _g = self.lock.lock();
        self.migrate_legacy()?;
        let bytes = std::fs::read(self.file(id)?)?;
        let plaintext = self.decrypt(&bytes)?;
        let exchange: HttpExchange = serde_json::from_slice(&plaintext)
            .map_err(|error| IdeError::internal(format!("corrupt history entry: {error}")))?;
        if exchange.entry.id != id {
            return Err(IdeError::internal("history entry id does not match its file"));
        }
        Ok(exchange)
    }

    /// Saves `exchange`, dropping the oldest entries beyond [`MAX_ENTRIES`].
    pub fn add(&self, exchange: &HttpExchange) -> IdeResult<()> {
        let _g = self.lock.lock();
        self.migrate_legacy()?;
        std::fs::create_dir_all(&self.dir)?;
        let json = serde_json::to_vec(exchange).map_err(|error| IdeError::internal(error.to_string()))?;
        self.write_encrypted(&self.file(&exchange.entry.id)?, &json)?;
        let mut index = self.read_index()?;
        index.retain(|entry| entry.id != exchange.entry.id);
        index.insert(0, exchange.entry.clone());
        for old in index.drain(MAX_ENTRIES.min(index.len())..) {
            match std::fs::remove_file(self.file(&old.id)?) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(history_error("remove expired entry", error)),
            }
        }
        self.write_index(&index)
    }

    fn read_index(&self) -> IdeResult<Vec<HistoryEntry>> {
        let path = self.dir.join(INDEX);
        let encrypted = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(history_error("read index", error)),
        };
        let plaintext = self.decrypt(&encrypted)?;
        serde_json::from_slice(&plaintext)
            .map_err(|error| IdeError::internal(format!("corrupt history index: {error}")))
    }

    fn write_index(&self, index: &[HistoryEntry]) -> IdeResult<()> {
        let json = serde_json::to_vec(index).map_err(|error| IdeError::internal(error.to_string()))?;
        self.write_encrypted(&self.dir.join(INDEX), &json)
    }

    pub fn clear(&self) -> IdeResult<()> {
        let _g = self.lock.lock();
        self.migrate_legacy()?;
        for entry in self.read_index()? {
            match std::fs::remove_file(self.file(&entry.id)?) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(history_error("clear entry", error)),
            }
        }
        if self.dir.exists() {
            self.write_index(&[])?;
        }
        Ok(())
    }

    fn key_entry(&self) -> IdeResult<Entry> {
        Entry::new(SERVICE, &key_account(&self.dir)).map_err(|error| key_error("open history encryption key", error))
    }

    fn encryption_key(&self) -> IdeResult<[u8; 32]> {
        let _g = KEY_LOCK.lock();
        let entry = self.key_entry()?;
        match entry.get_secret() {
            Ok(value) => {
                value.try_into().map_err(|_| IdeError::unavailable("HTTP history encryption key has an invalid length"))
            }
            Err(KeyringError::NoEntry) => {
                let first = uuid::Uuid::new_v4();
                let second = uuid::Uuid::new_v4();
                let mut key = [0; 32];
                key[..16].copy_from_slice(first.as_bytes());
                key[16..].copy_from_slice(second.as_bytes());
                entry.set_secret(&key).map_err(|error| key_error("store history encryption key", error))?;
                let stored = entry.get_secret().map_err(|error| key_error("verify history encryption key", error))?;
                if stored != key {
                    return Err(IdeError::unavailable("HTTP history encryption key verification failed"));
                }
                Ok(key)
            }
            Err(error) => Err(key_error("read history encryption key", error)),
        }
    }

    fn encrypt(&self, plaintext: &[u8]) -> IdeResult<Vec<u8>> {
        let key = self.encryption_key()?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|error| IdeError::internal(format!("invalid history encryption key: {error}")))?;
        let random = uuid::Uuid::new_v4();
        let nonce_bytes: [u8; 12] = random.as_bytes()[..12].try_into().expect("UUID has 16 bytes");
        let nonce =
            Nonce::<U12>::try_from(&nonce_bytes[..]).map_err(|_| IdeError::internal("invalid HTTP history nonce"))?;
        let ciphertext =
            cipher.encrypt(&nonce, plaintext).map_err(|_| IdeError::internal("HTTP history encryption failed"))?;
        let mut output = Vec::with_capacity(MAGIC.len() + nonce_bytes.len() + ciphertext.len());
        output.extend_from_slice(MAGIC);
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    fn decrypt(&self, encrypted: &[u8]) -> IdeResult<Vec<u8>> {
        if encrypted.len() < MAGIC.len() + 12 + 16 || !encrypted.starts_with(MAGIC) {
            return Err(IdeError::internal("invalid encrypted HTTP history format"));
        }
        let key = self.encryption_key()?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|error| IdeError::internal(format!("invalid history encryption key: {error}")))?;
        let nonce = Nonce::<U12>::try_from(&encrypted[MAGIC.len()..MAGIC.len() + 12])
            .map_err(|_| IdeError::internal("invalid encrypted HTTP history nonce"))?;
        cipher
            .decrypt(&nonce, &encrypted[MAGIC.len() + 12..])
            .map_err(|_| IdeError::internal("HTTP history authentication failed"))
    }

    fn write_encrypted(&self, path: &Path, plaintext: &[u8]) -> IdeResult<()> {
        let encrypted = self.encrypt(plaintext)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let temporary = path.with_extension("enc.tmp");
        std::fs::write(&temporary, encrypted).map_err(|error| history_error("write encrypted history", error))?;
        let stored = std::fs::read(&temporary).map_err(|error| history_error("verify encrypted history", error))?;
        if self.decrypt(&stored)? != plaintext {
            return Err(IdeError::unavailable("HTTP history encryption verification failed"));
        }
        std::fs::rename(temporary, path).map_err(|error| history_error("replace history file", error))
    }

    /// Migrate every legacy JSON file. New copies are encrypted and verified
    /// before any plaintext source file is removed.
    fn migrate_legacy(&self) -> IdeResult<()> {
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(history_error("scan legacy history", error)),
        };
        let mut sources = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| history_error("scan legacy history", error))?;
            let path = entry.path();
            if path.extension().is_some_and(|extension| extension == "json")
                && entry.file_type().map_err(|error| history_error("inspect legacy history", error))?.is_file()
            {
                sources.push(path);
            }
        }
        if sources.is_empty() {
            return Ok(());
        }

        let mut encrypted_sources = Vec::with_capacity(sources.len());
        for source in &sources {
            let plaintext = std::fs::read(source).map_err(|error| history_error("read legacy history", error))?;
            let target = match source.file_name().and_then(|name| name.to_str()) {
                Some(LEGACY_INDEX) => {
                    serde_json::from_slice::<Vec<HistoryEntry>>(&plaintext)
                        .map_err(|error| IdeError::internal(format!("corrupt legacy history index: {error}")))?;
                    self.dir.join(INDEX)
                }
                Some(name) => {
                    let id = source
                        .file_stem()
                        .and_then(|stem| stem.to_str())
                        .ok_or_else(|| IdeError::invalid("invalid legacy history filename"))?;
                    if name != format!("{id}.json") {
                        return Err(IdeError::invalid("invalid legacy history filename"));
                    }
                    let exchange: HttpExchange = serde_json::from_slice(&plaintext)
                        .map_err(|error| IdeError::internal(format!("corrupt legacy history entry: {error}")))?;
                    if exchange.entry.id != id {
                        return Err(IdeError::internal("legacy history entry id does not match its file"));
                    }
                    self.file(id)?
                }
                None => return Err(IdeError::invalid("invalid legacy history filename")),
            };
            self.write_encrypted(&target, &plaintext)?;
            encrypted_sources.push(target);
        }

        // Re-open all new files through the normal decrypt path before cleanup.
        for (source, target) in sources.iter().zip(&encrypted_sources) {
            let original = std::fs::read(source).map_err(|error| history_error("verify legacy history", error))?;
            let encrypted = std::fs::read(target).map_err(|error| history_error("verify migrated history", error))?;
            if self.decrypt(&encrypted)? != original {
                return Err(IdeError::unavailable("HTTP history migration verification failed"));
            }
        }
        for source in sources {
            std::fs::remove_file(source).map_err(|error| history_error("remove migrated plaintext history", error))?;
        }
        Ok(())
    }
}

fn key_account(path: &Path) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"http-history-key\0");
    hasher.update(path.to_string_lossy().as_bytes());
    format!("v1-{}", hasher.finalize().to_hex())
}

fn key_error(action: &str, error: impl std::fmt::Display) -> IdeError {
    IdeError::unavailable(format!("could not {action} in the OS credential store: {error}"))
}

fn history_error(action: &str, error: impl std::fmt::Display) -> IdeError {
    IdeError::unavailable(format!("could not {action}: {error}"))
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

    fn exchange(id: &str) -> HttpExchange {
        HttpExchange {
            entry: HistoryEntry {
                id: id.into(),
                time_ms: 1.0,
                name: None,
                method: "GET".into(),
                url: "https://user:password@example.test/private?token=secret".into(),
                status: Some(200),
                total_ms: Some(3.0),
                file: None,
                error: None,
            },
            request: PreparedRequest {
                name: None,
                method: "GET".into(),
                url: "https://user:password@example.test/private?token=secret".into(),
                headers: vec![("Authorization".into(), "Bearer secret-header".into())],
                body: Some("secret request body".into()),
            },
            response: Some(HttpResponse {
                status: 200,
                status_text: "OK".into(),
                version: "HTTP/1.1".into(),
                headers: vec![("Set-Cookie".into(), "secret-cookie".into())],
                content_type: Some("text/plain".into()),
                body: Some("secret response body".into()),
                size: 20.0,
                truncated: false,
                ttfb_ms: 2.0,
                total_ms: 3.0,
            }),
        }
    }

    #[test]
    fn encrypts_roundtrips_and_rejects_tampering() {
        let tmp = tempfile::tempdir().unwrap();
        let history = History::new(tmp.path().join("h"));
        let exchange = exchange("e1");
        history.add(&exchange).unwrap();

        for path in [history.dir.join(INDEX), history.file("e1").unwrap()] {
            let encrypted = std::fs::read(path).unwrap();
            assert!(encrypted.starts_with(MAGIC));
            let text = String::from_utf8_lossy(&encrypted);
            for secret in ["Authorization", "secret-header", "token=secret", "secret request body"] {
                assert!(!text.contains(secret), "encrypted history leaked {secret}");
            }
        }
        let loaded = history.get("e1").unwrap();
        assert_eq!(loaded.entry.url, exchange.entry.url);
        assert_eq!(loaded.request.headers, exchange.request.headers);
        assert_eq!(loaded.response.unwrap().body.as_deref(), Some("secret response body"));

        let path = history.file("e1").unwrap();
        let mut encrypted = std::fs::read(&path).unwrap();
        *encrypted.last_mut().unwrap() ^= 1;
        std::fs::write(path, encrypted).unwrap();
        assert!(history.get("e1").is_err(), "tampered history must fail authentication");
    }

    #[test]
    fn migrates_all_plaintext_and_removes_sources_after_verification() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("h");
        std::fs::create_dir_all(&dir).unwrap();
        let exchange = exchange("e1");
        std::fs::write(dir.join("e1.json"), serde_json::to_vec(&exchange).unwrap()).unwrap();
        std::fs::write(dir.join(LEGACY_INDEX), serde_json::to_vec(std::slice::from_ref(&exchange.entry)).unwrap())
            .unwrap();
        let history = History::new(dir.clone());

        assert_eq!(history.list().len(), 1);
        assert_eq!(history.get("e1").unwrap().request.body.as_deref(), Some("secret request body"));
        assert!(!dir.join("e1.json").exists());
        assert!(!dir.join(LEGACY_INDEX).exists());
        assert!(dir.join("e1.enc").exists());
        assert!(dir.join(INDEX).exists());
    }

    #[test]
    fn retains_plaintext_sources_when_migration_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("h");
        std::fs::create_dir_all(&dir).unwrap();
        let index = br#"[{"id":"e1"}]"#;
        let exchange_source = b"not valid history JSON";
        std::fs::write(dir.join(LEGACY_INDEX), index).unwrap();
        std::fs::write(dir.join("e1.json"), exchange_source).unwrap();
        let history = History::new(dir.clone());

        assert!(history.add(&exchange("e2")).is_err());
        assert_eq!(std::fs::read(dir.join(LEGACY_INDEX)).unwrap(), index);
        assert_eq!(std::fs::read(dir.join("e1.json")).unwrap(), exchange_source);
        assert!(!dir.join("e2.enc").exists(), "failed migration blocks new history writes");
    }

    #[test]
    fn unavailable_credential_store_preserves_history_and_blocks_plaintext_writes() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("h");
        std::fs::create_dir_all(&dir).unwrap();
        let legacy_exchange = exchange("e1");
        let source = serde_json::to_vec(&legacy_exchange).unwrap();
        let index = serde_json::to_vec(std::slice::from_ref(&legacy_exchange.entry)).unwrap();
        std::fs::write(dir.join("e1.json"), &source).unwrap();
        std::fs::write(dir.join(LEGACY_INDEX), &index).unwrap();
        let history = History::new(dir.clone());

        test_credential_store::fail_next_set();
        assert!(history.add(&exchange("e2")).is_err());
        assert_eq!(std::fs::read(dir.join("e1.json")).unwrap(), source);
        assert_eq!(std::fs::read(dir.join(LEGACY_INDEX)).unwrap(), index);
        assert!(!dir.join("e1.enc").exists());
        assert!(!dir.join("e2.enc").exists());

        let new_dir = tmp.path().join("new-history");
        let new_history = History::new(new_dir.clone());
        test_credential_store::fail_next_set();
        assert!(new_history.add(&exchange("new")).is_err());
        assert_eq!(std::fs::read_dir(new_dir).unwrap().count(), 0);
    }

    #[test]
    fn stores_newest_first_caps_and_clears() {
        let tmp = tempfile::tempdir().unwrap();
        let h = History::new(tmp.path().join("h"));
        for i in 0..MAX_ENTRIES + 3 {
            h.add(&exchange(&format!("e{i}"))).unwrap();
        }
        let list = h.list();
        assert_eq!(list.len(), MAX_ENTRIES);
        assert_eq!(list[0].id, format!("e{}", MAX_ENTRIES + 2));
        assert!(h.get("e0").is_err());
        assert_eq!(h.get("e5").unwrap().entry.id, "e5");
        assert!(h.get("../x").is_err());
        h.clear().unwrap();
        assert!(h.list().is_empty());
    }
}
