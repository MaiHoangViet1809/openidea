//! System Settings › HTTP Proxy: applied on write, the password kept out of settings.toml.

use ide_core::NullSink;
use ide_core::proxy_settings::{ProxyMode, ProxyRoute, proxy};
use ide_core::settings::Settings;
use ide_host::{Host, HostConfig, ops};
use ide_ssh::secrets::SecretFile;
use ide_workspace::SettingsScope;
use ide_workspace::settings::SettingsStore;
use std::ops::Deref;
use std::sync::Arc;

struct TestHost {
    host: Arc<Host>,
    proxy_credential: SecretFile,
}

impl Deref for TestHost {
    type Target = Host;

    fn deref(&self) -> &Self::Target {
        &self.host
    }
}

impl Drop for TestHost {
    fn drop(&mut self) {
        self.proxy_credential.delete("httpProxy");
    }
}

fn host(base: &std::path::Path) -> TestHost {
    let host = Arc::new(Host::new(HostConfig {
        config_dir: base.join("config"),
        data_dir: base.join("data"),
        local_data_dir: base.join("data"),
        languages: Arc::new(ide_language::LanguageRegistry::load(None).unwrap()),
        syntax: Arc::default(),
        sink_for: Box::new(|_| Arc::new(NullSink)),
        owner: |w| w,
        runtime: tokio::runtime::Handle::current(),
        project_environment: false,
    }));
    TestHost { host, proxy_credential: SecretFile::new(base.join("data/proxy-password.json")) }
}

fn set(host: &Host, key: &str, value: &str) -> ide_core::settings::Settings {
    ops::project::set_settings(host, "main", SettingsScope::Global, key, value).unwrap().settings
}

fn settings_files(base: &std::path::Path) -> String {
    let mut text = String::new();
    for entry in walk(&base.join("config")) {
        text.push_str(&std::fs::read_to_string(entry).unwrap_or_default());
    }
    text
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() { out.extend(walk(&path)) } else { out.push(path) }
    }
    out
}

fn global_settings(base: &std::path::Path, text: &str) -> std::path::PathBuf {
    let path = base.join("config/settings.toml");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, text).unwrap();
    path
}

fn settings_bundle(path: &std::path::Path, settings: &str) {
    let bytes = serde_json::to_vec(&serde_json::json!({
        "format": "openidea-settings",
        "version": 1,
        "settings": settings,
        "storage": {}
    }))
    .unwrap();
    std::fs::write(path, bytes).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn manual_proxy_applies_and_the_password_is_saved_apart() {
    let tmp = tempfile::tempdir().unwrap();
    let host = host(tmp.path());
    assert_eq!(proxy().mode, ProxyMode::Auto);

    set(&host, "proxy.mode", "\"manual\"");
    set(&host, "proxy.host", "\"proxy.corp\"");
    set(&host, "proxy.port", "3128");
    set(&host, "proxy.authenticate", "true");
    set(&host, "proxy.login", "\"me\"");
    let settings = set(&host, "proxy.password", "\"s3cret\"");
    assert_eq!(settings.proxy.password, "s3cret", "the dialog sees the saved password");
    assert_eq!(
        proxy().route_for_url("https://example.com/"),
        ProxyRoute::Via("http://me:s3cret@proxy.corp:3128".into())
    );

    assert!(!settings_files(tmp.path()).contains("s3cret"), "no password in settings.toml");
    assert!(
        !tmp.path().join("data/proxy-password.json").exists(),
        "the proxy password is kept in the OS credential store, not an app-data JSON file"
    );
    assert_eq!(ops::project::settings(&host, "main").proxy.password, "s3cret");

    // A whole-table write keeps the password out of the file too; an empty one forgets it.
    let settings = set(&host, "proxy", r#"{"mode":"none","host":"proxy.corp","password":""}"#);
    assert_eq!(settings.proxy.password, "");
    assert!(!settings_files(tmp.path()).contains("password"));
    assert_eq!(proxy().route_for_url("https://example.com/"), ProxyRoute::Direct);

    set(&host, "proxy", r#"{"mode":"auto"}"#);
    assert_eq!(proxy().mode, ProxyMode::Auto);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn global_toml_password_migrates_before_proxy_is_applied() {
    let tmp = tempfile::tempdir().unwrap();
    let config = global_settings(
        tmp.path(),
        "[proxy]\nmode = \"manual\"\nhost = \"proxy.corp\"\nport = 3128\nauthenticate = true\nlogin = \"me\"\npassword = \"legacy-secret\"\n",
    );

    let host = host(tmp.path());

    assert!(!std::fs::read_to_string(&config).unwrap().contains("legacy-secret"));
    assert_eq!(ops::project::settings(&host, "main").proxy.password, "legacy-secret");
    assert_eq!(
        proxy().route_for_url("https://example.com/"),
        ProxyRoute::Via("http://me:legacy-secret@proxy.corp:3128".into())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_global_toml_does_not_replace_an_existing_credential() {
    let tmp = tempfile::tempdir().unwrap();
    let secret_file = SecretFile::new(tmp.path().join("data/proxy-password.json"));
    secret_file.set("httpProxy", "saved-secret").unwrap();
    let config = global_settings(
        tmp.path(),
        "[proxy]\nmode = \"manual\"\nhost = \"proxy.corp\"\nport = 3128\nauthenticate = true\nlogin = \"me\"\npassword = \"stale-secret\"\n",
    );

    let host = host(tmp.path());

    assert!(!std::fs::read_to_string(&config).unwrap().contains("stale-secret"));
    assert_eq!(ops::project::settings(&host, "main").proxy.password, "saved-secret");
    assert_eq!(
        proxy().route_for_url("https://example.com/"),
        ProxyRoute::Via("http://me:saved-secret@proxy.corp:3128".into())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn project_toml_password_is_neither_used_nor_promoted_to_global_storage() {
    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("project");
    let project_settings = project.join(".openidea/settings.toml");
    std::fs::create_dir_all(project_settings.parent().unwrap()).unwrap();
    std::fs::write(&project_settings, "[proxy]\npassword = \"project-secret\"\n").unwrap();
    let host = host(tmp.path());

    let effective = SettingsStore::load(&tmp.path().join("config"), Some(&project)).effective();
    assert_eq!(effective.proxy.password, "project-secret");
    assert_eq!(host.with_proxy_password(effective).proxy.password, "");
    assert_eq!(SecretFile::new(tmp.path().join("data/proxy-password.json")).try_get("httpProxy").unwrap(), None);
    assert!(std::fs::read_to_string(project_settings).unwrap().contains("project-secret"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn credential_read_failure_keeps_toml_and_never_uses_its_password() {
    let tmp = tempfile::tempdir().unwrap();
    let legacy = "[proxy]\nmode = \"manual\"\nhost = \"proxy.corp\"\nport = 3128\nauthenticate = true\nlogin = \"me\"\npassword = \"must-not-escape\"\n";
    let config = global_settings(tmp.path(), legacy);
    std::fs::create_dir_all(tmp.path().join("data/proxy-password.json")).unwrap();

    let host = host(tmp.path());
    let settings = ops::project::settings(&host, "main");

    assert_eq!(std::fs::read_to_string(&config).unwrap(), legacy);
    assert_eq!(settings.proxy.password, "");
    assert!(!matches!(
        proxy().route_for_url("https://example.com/"),
        ProxyRoute::Via(url) if url.contains("must-not-escape")
    ));
    assert!(ops::project::set_settings(&host, "main", SettingsScope::Global, "proxy.password", "\"\"").is_err());
    assert_eq!(std::fs::read_to_string(&config).unwrap(), legacy);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn settings_bundle_import_keeps_password_out_of_toml() {
    let tmp = tempfile::tempdir().unwrap();
    let bundle = tmp.path().join("settings.json");
    settings_bundle(
        &bundle,
        "[proxy]\nmode = \"manual\"\nhost = \"proxy.corp\"\nport = 3128\nauthenticate = true\nlogin = \"me\"\npassword = \"imported-secret\"\n",
    );
    let host = host(tmp.path());

    let (settings, storage) = host.import_settings_bundle(&bundle).unwrap();
    host.apply_proxy();

    assert!(storage.is_empty());
    assert_eq!(settings.proxy.password, "");
    assert_eq!(host.with_proxy_password(settings).proxy.password, "imported-secret");
    assert!(!std::fs::read_to_string(tmp.path().join("config/settings.toml")).unwrap().contains("imported-secret"));
    assert_eq!(
        proxy().route_for_url("https://example.com/"),
        ProxyRoute::Via("http://me:imported-secret@proxy.corp:3128".into())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn settings_bundle_store_failure_keeps_the_current_settings_file() {
    let tmp = tempfile::tempdir().unwrap();
    let existing = global_settings(tmp.path(), "[editor]\nfontSize = 19\n");
    std::fs::create_dir_all(tmp.path().join("data/proxy-password.json")).unwrap();
    let bundle = tmp.path().join("settings.json");
    settings_bundle(&bundle, "[proxy]\npassword = \"import-secret\"\n");
    let host = host(tmp.path());
    let original = std::fs::read(&existing).unwrap();

    assert!(host.import_settings_bundle(&bundle).is_err());
    assert_eq!(std::fs::read(&existing).unwrap(), original);
    assert!(!std::fs::read(&existing).unwrap().windows(b"import-secret".len()).any(|w| w == b"import-secret"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn importing_a_bundle_without_password_migrates_current_legacy_password_first() {
    let tmp = tempfile::tempdir().unwrap();
    let current = global_settings(
        tmp.path(),
        "[proxy]\nmode = \"manual\"\nhost = \"proxy.corp\"\nport = 3128\nauthenticate = true\nlogin = \"me\"\npassword = \"current-secret\"\n",
    );
    let bundle = tmp.path().join("settings.json");
    settings_bundle(&bundle, "[editor]\nfontSize = 20\n");
    let host = host(tmp.path());
    assert!(!std::fs::read_to_string(&current).unwrap().contains("current-secret"));

    let (settings, _) = host.import_settings_bundle(&bundle).unwrap();

    assert_eq!(settings.editor.font_size, 20.0);
    assert_eq!(host.with_proxy_password(settings).proxy.password, "current-secret");
    assert!(!std::fs::read_to_string(&current).unwrap().contains("current-secret"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unavailable_store_blocks_import_that_would_discard_current_legacy_password() {
    let tmp = tempfile::tempdir().unwrap();
    let legacy = "[proxy]\nmode = \"manual\"\npassword = \"current-secret\"\n";
    let current = global_settings(tmp.path(), legacy);
    std::fs::create_dir_all(tmp.path().join("data/proxy-password.json")).unwrap();
    let bundle = tmp.path().join("settings.json");
    settings_bundle(&bundle, "[editor]\nfontSize = 20\n");
    let host = host(tmp.path());

    assert!(host.import_settings_bundle(&bundle).is_err());
    assert_eq!(std::fs::read_to_string(&current).unwrap(), legacy);
    assert_eq!(host.with_proxy_password(Settings::default()).proxy.password, "");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_settings_bundle_commit_restores_the_previous_proxy_credential() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("config/settings.toml")).unwrap();
    let bundle = tmp.path().join("settings.json");
    settings_bundle(
        &bundle,
        "[proxy]\nmode = \"manual\"\nhost = \"proxy.corp\"\nport = 3128\nauthenticate = true\nlogin = \"me\"\npassword = \"new-secret\"\n",
    );
    let host = host(tmp.path());
    set(&host, "proxy.password", "\"old-secret\"");

    assert!(host.import_settings_bundle(&bundle).is_err());
    assert_eq!(host.with_proxy_password(Settings::default()).proxy.password, "old-secret");
    assert!(tmp.path().join("config/settings.toml").is_dir());
}
