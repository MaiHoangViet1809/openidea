# SOW_20261102_6B530D9E_EXT_R7X4M9Q2 — Migrate plaintext global proxy passwords

- Status: COMPLETE
- Approval: APPROVED (User)
- Proposed-By: Codex
- create_dttm: 2026-11-02T14:36:29+07:00
- approve_dttm: 2026-11-02T14:59:05+07:00
- finish_dttm: 2026-11-02T15:18:32+07:00
- Base SOW: SOW_20261102_6B530D9E
- Dependencies: Base SOW C3; this extension adds the omitted proxy owner and settings-bundle import/export paths.

## Task

Move manually configured global proxy passwords out of `settings.toml` into the OS credential store, remove the plaintext fallback, and prevent Settings bundles from exporting or restoring the password in plaintext.

## Scope Delta

The base SOW moves proxy passwords saved through Settings from JSON into the OS credential store. Review found that `Host::with_proxy_password` still returns a manually entered TOML password when the credential-store read misses or fails. It also found that Settings bundle export copies raw global TOML and import writes it back directly.

Only the following new paths are added beyond the base SOW Location:

- `crates/ide-host/src/proxy.rs` — migrate the supported global TOML value and remove the plaintext fallback.
- `crates/ide-workspace/src/settings.rs` — keep `proxy.password` out of exported and persisted imported bundle settings.
- `src-tauri/src/commands/app.rs` — coordinate secure proxy-password handling during Settings bundle import/export.

These paths are already in the base SOW Location and may be edited for this extension:

- `crates/ide-host/src/lib.rs` — migrate the global settings layer before the initial proxy is applied.
- `crates/ide-host/tests/proxy.rs` — verify migration, retention on failure, import/export behavior, and no plaintext fallback.
- `crates/ide-ssh/src/secrets.rs` — distinguish a missing credential from a credential-store error and store only when absent, if needed.

No other path is authorized by this draft.

## Why

`SecretFile::get` currently collapses credential-store errors into `None`, and `with_proxy_password` then falls back to `settings.proxy.password`. This can return or apply a plaintext password. `Host::new` applies the proxy before any proposed migration. Settings bundle export copies the raw global TOML, and import writes that TOML back before `apply_proxy`, so those routes can disclose or reintroduce the password.

The HTTP Proxy settings page and settings schema define proxy configuration as global-only. Project-layer passwords are not a supported proxy scope. Migrating a project-controlled value into the single host-wide credential could promote repository content into the user's global credential, so this extension does not migrate or rewrite project settings. After fallback removal, those unsupported values will not be returned or applied by the app; an existing project TOML value remains a plaintext residual that must be removed manually.

## As-Is Diagram (ASCII)

```text
global settings.toml proxy.password
  -> keychain lookup misses or fails
  -> plaintext TOML value is returned and applied

Settings export -> copies raw settings.toml into bundle
Settings import -> writes bundle TOML to disk -> applies proxy

project settings.toml proxy.password
  -> unsupported scope, but can appear in effective settings
  -> may be returned through the plaintext fallback
```

## To-Be Diagram (ASCII)

```text
global settings.toml proxy.password
  -> distinguish keychain miss from keychain error
  -> store only if absent, verify read-back
  -> remove TOML value only after verification

Settings export -> omit proxy.password from exported copy
Settings import -> store and verify password first
  -> persist only sanitized settings TOML

credential-store failure -> keep current global settings unchanged
  -> do not return or apply plaintext password

project settings.toml proxy.password -> never migrate to global credential
  -> never return or apply as fallback; manual removal remains necessary
```

## Deliverables

- The global legacy TOML password migrates to the OS credential store and is removed only after the destination is verified.
- Existing credential-store values take precedence over stale global TOML values; stale TOML is removed only after a successful credential-store read.
- `with_proxy_password` clears the password from the incoming settings first, then fills it only from a confirmed credential-store value. A missing entry or read error leaves it empty.
- Settings bundle export omits `proxy.password` without changing the source settings file.
- An explicit Settings bundle import replaces the current proxy credential with the bundle's included password: store and verify it before replacing global settings, then persist a sanitized settings document. If storage fails, the current global settings remain unchanged and the import fails without writing the password to TOML. If the settings-file commit fails after a credential update, restore the prior credential value and verify the rollback.
- If a bundle omits `proxy.password`, migrate any current global TOML password before replacing that file; if migration fails, leave the current global settings untouched.
- If credential storage is unavailable, Settings reads and proxy application do not fall back to plaintext.
- Passwords saved through the existing Settings UI continue to work. No new JSON or TOML secret write is introduced.
- Project-layer `proxy.password` values are neither promoted into the global credential nor automatically rewritten. They are not returned or applied after fallback removal; their presence remains a documented manual-cleanup residual.

## Done Criteria

- Host checks cover global TOML migration before the first proxy application, verified cleanup, and preserved proxy behavior after migration.
- Failure-path checks prove the global source TOML remains intact and plaintext is neither returned to settings consumers nor applied to proxy requests when credential storage is unavailable.
- A stale global TOML password cannot overwrite a different existing OS credential-store value.
- Settings bundle checks prove export omits the password and import preserves proxy behavior through the OS credential store without persisting plaintext. An import storage failure leaves the current settings file unchanged.
- Importing a bundle without a password migrates any existing global TOML password first; an unavailable credential store leaves that source settings file unchanged.
- An import settings-file commit failure restores the prior credential-store value, or reports an explicit sanitized rollback failure without exposing either secret.
- A project TOML password is not used as a fallback or promoted to the global OS credential store.
- `cargo +1.96.0 test -p ide-host --test proxy -- --test-threads=1`, relevant `ide-ssh` and `ide-workspace` checks, the targeted Settings bundle checks, and Rust formatting pass on macOS.
- No secret values appear in test output, logs, or exported Settings bundles.

## Out-of-Scope

- Automatic migration or rewriting of project-layer `proxy.password`; proxy is global-only, and project values require manual cleanup.
- New proxy configuration fields or UI changes.
- Changes to other settings or secret types, or encrypted export/import for other credentials.
- Cross-platform runtime checks beyond the base SOW's existing platform coverage.

## Cautions / Risks

- Clearing global TOML before a verified Keychain write could lose the only copy; source removal must happen last.
- A failed Keychain read must not be mistaken for a confirmed missing item when deciding whether the global TOML value may be migrated.
- During Settings import, the credential must be stored and verified before replacing the current settings file; an error must leave the existing file intact.
- Settings import spans the credential store and settings file; rollback behavior must be explicit so a failed file commit cannot silently change the active proxy credential.
- Project-layer `proxy.password` values can remain plaintext in checked-in project settings. They will no longer be used by the app, but this extension does not remove them.
- Keychain-backed values remain scoped to the current OS user and do not automatically travel with project files or backups.

## Review

- Review date: 2026-11-02
- Review result: REVISED DRAFT; explicitly approved by the user for implementation on 2026-11-02.
- Findings: the initial draft treated project-layer passwords as if they shared a safe migration path with the global credential, and excluded Settings bundle import/export even though those paths copy raw TOML. The scope above limits automatic migration to the supported global setting and adds bundle sanitization. Project-layer plaintext remains an explicit residual.

## Progress

- task_classification: complex — coordinated security migration across credential storage, host startup, settings bundles, and failure rollback.
- delegation_decision: delegated — requested one independent read-only import/export review from exact native greennode/glm-5.3 at max. It remained running beyond the 10-minute wait and was interrupted without a result; coordinator completed and recorded a self-review. No independent review PASS is claimed.
- progress_updated_dttm: 2026-11-02T15:19:15+07:00

| Item                              | Status   | Evidence / Pending reason                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Next action / Owner                                                        |
| --------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| R1: Review and revise draft scope | COMPLETE | Confirmed global-only proxy UI/schema, host-wide Keychain credential, TOML fallback on missing/error, and raw TOML bundle import/export paths. Revised the EXT and recorded user approval; no code changed during review.                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Implementation proceeds under I1; Codex                                    |
| I1: Implement approved extension  | COMPLETE | Global TOML migrates only after Keychain read-back, TOML fallback is removed, bundle export/import strips credentials, failed commits roll back, and unsupported project TOML passwords are neither migrated nor applied. `cargo +1.96.0 test -p ide-host --test proxy -- --test-threads=1`: 10 passed using macOS Keychain; `cargo +1.96.0 test -p ide-ssh -- --test-threads=1`: 22 unit + 4 integration passed; `cargo +1.96.0 test -p ide-workspace settings::tests::settings -- --test-threads=1`: 3 passed; `cargo +1.96.0 check -p openidea --lib`, rustfmt, and `git diff --check` pass. Coordinator self-review completed; independent delegated review returned no result. | Include this closeout and finished-bundle move in the scoped commit; Codex |
