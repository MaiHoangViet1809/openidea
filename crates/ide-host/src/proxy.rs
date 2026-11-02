//! System Settings › HTTP Proxy on the host: the global settings made current for
//! connections and child processes, the password kept in the saved passwords
//! (owner-only `proxy-password.json`) instead of `settings.toml`.

use crate::Host;
use ide_core::settings::Settings;
use ide_core::{IdeError, IdeResult};
use std::collections::BTreeMap;
use std::path::Path;

const PASSWORD_KEY: &str = "httpProxy";

impl Host {
    /// `settings` with the saved proxy password filled in, as the Settings dialog edits it.
    pub fn with_proxy_password(&self, mut settings: Settings) -> Settings {
        settings.proxy.password.clear();
        match self.proxy_password.try_get(PASSWORD_KEY) {
            Ok(Some(password)) => settings.proxy.password = password,
            Ok(None) => {}
            Err(error) => tracing::warn!("could not load HTTP proxy credential: {}", error.message),
        }
        settings
    }

    /// Moves a legacy global TOML password only after the OS credential store confirms a value.
    pub(crate) fn migrate_global_proxy_password(&self) -> IdeResult<()> {
        let password = self.global_settings.effective().proxy.password;
        if password.is_empty() {
            return Ok(());
        }
        self.proxy_password.set_if_absent(PASSWORD_KEY, &password)?;
        self.global_settings.set(
            ide_workspace::settings::SettingsScope::Global,
            "proxy.password",
            serde_json::Value::Null,
        )?;
        Ok(())
    }

    /// Imports a Settings bundle without persisting its proxy password in TOML.
    pub fn import_settings_bundle(&self, path: &Path) -> IdeResult<(Settings, BTreeMap<String, String>)> {
        let mut bundle = ide_workspace::settings::SettingsStore::prepare_bundle_import(path)?;
        let imported_password = bundle.take_proxy_password();
        let Some(password) = imported_password.as_deref() else {
            self.migrate_global_proxy_password()?;
            return self.global_settings.commit_bundle_import(bundle);
        };

        let previous = self.proxy_password.try_get(PASSWORD_KEY)?;
        let update = if password.is_empty() {
            self.proxy_password.delete_checked(PASSWORD_KEY)
        } else {
            self.proxy_password.set(PASSWORD_KEY, password)
        };
        if let Err(error) = update {
            return Err(self.rollback_proxy_import(error, previous.as_deref()));
        }

        let expected = (!password.is_empty()).then_some(password);
        match self.proxy_password.try_get(PASSWORD_KEY) {
            Ok(actual) if actual.as_deref() == expected => {}
            Ok(_) => {
                let error = IdeError::unavailable("imported proxy credential verification failed");
                return Err(self.rollback_proxy_import(error, previous.as_deref()));
            }
            Err(error) => return Err(self.rollback_proxy_import(error, previous.as_deref())),
        }

        match self.global_settings.commit_bundle_import(bundle) {
            Ok(imported) => Ok(imported),
            Err(error) => Err(self.rollback_proxy_import(error, previous.as_deref())),
        }
    }

    fn rollback_proxy_import(&self, cause: IdeError, previous: Option<&str>) -> IdeError {
        let rollback = match previous {
            Some(password) => self.proxy_password.set(PASSWORD_KEY, password).and_then(|()| {
                match self.proxy_password.try_get(PASSWORD_KEY)? {
                    Some(stored) if stored == password => Ok(()),
                    _ => Err(IdeError::unavailable("proxy credential rollback verification failed")),
                }
            }),
            None => self.proxy_password.delete_checked(PASSWORD_KEY).and_then(|()| {
                if self.proxy_password.try_get(PASSWORD_KEY)?.is_none() {
                    Ok(())
                } else {
                    Err(IdeError::unavailable("proxy credential rollback verification failed"))
                }
            }),
        };
        match rollback {
            Ok(()) => cause,
            Err(error) => {
                tracing::error!("proxy credential rollback failed: {}", error.message);
                IdeError::unavailable(format!("{}; proxy credential rollback failed: {}", cause.message, error.message))
            }
        }
    }

    /// Makes the global proxy settings the proxy of every later connection and child process.
    pub fn apply_proxy(&self) {
        let settings = self.with_proxy_password(self.global_settings.effective());
        if let Some(problem) = settings.proxy.problem() {
            tracing::warn!("HTTP proxy: {problem}");
        }
        ide_core::proxy_settings::set_proxy(settings.proxy);
    }

    /// Takes the proxy password out of a settings write of `key` and saves it.
    /// Returns the value left to write, `None` when nothing is.
    pub(crate) fn take_proxy_password(
        &self,
        key: &str,
        mut value: serde_json::Value,
    ) -> IdeResult<Option<serde_json::Value>> {
        let password = match key {
            "proxy.password" => Some(value.take()),
            "proxy" => value.as_object_mut().and_then(|o| o.remove("password")),
            _ => return Ok(Some(value)),
        };
        if let Some(password) = password {
            match password.as_str().filter(|p| !p.is_empty()) {
                Some(p) => self.proxy_password.set(PASSWORD_KEY, p)?,
                None => self.proxy_password.delete_checked(PASSWORD_KEY)?,
            }
        }
        Ok((key != "proxy.password").then_some(value))
    }
}
