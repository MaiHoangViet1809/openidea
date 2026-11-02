# SOW_20261102_6B530D9E_EXT_R7X4M9Q2 — Migrate plaintext proxy passwords from settings

- Status: DRAFT
- Approval: PENDING
- Proposed-By: Codex
- create_dttm: 2026-11-02T14:36:29+07:00
- approve_dttm: null
- finish_dttm: null
- Base SOW: SOW_20261102_6B530D9E
- Dependencies: Base SOW C3; this extension adds one omitted implementation file.

## Task

Move manually configured proxy passwords from global and project `settings.toml` files into the OS credential store, verify the saved value before removing plaintext, and never use the plaintext setting as a fallback.

## Scope Delta

The base SOW moves proxy passwords saved through Settings from JSON into the OS credential store. Review during implementation found `Host::with_proxy_password` still reads a manually entered `proxy.password` from TOML when no credential-store item exists. This extension adds that path to the migration and fallback-removal behavior.

Only the following new path is added beyond the base SOW Location:

- `crates/ide-host/src/proxy.rs` — migrate TOML values and remove the plaintext fallback.

These paths are already in the base SOW Location and may be edited for this extension:

- `crates/ide-host/src/lib.rs` — migrate the global settings layer during host initialization.
- `crates/ide-host/src/project.rs` — migrate a project settings layer before project settings are applied.
- `crates/ide-host/tests/proxy.rs` — verify migration, retention on failure, and no plaintext fallback.
- `crates/ide-ssh/src/secrets.rs` — expose fallible credential reads if needed to distinguish a missing item from an unavailable store.

No other path is authorized by this draft.

## Why

The current `with_proxy_password` implementation fills an empty credential-store result from `settings.proxy.password`. This allows a password typed directly into global or project TOML to remain in plaintext and be returned to the app or used by its proxy. A project TOML file can also be checked into that project's source control.

## As-Is Diagram (ASCII)

```text
settings.toml proxy.password
  -> keychain lookup misses or fails
  -> plaintext TOML value is returned and applied
```

## To-Be Diagram (ASCII)

```text
settings.toml proxy.password
  -> read OS credential store
  -> save if absent, then verify read-back
  -> remove TOML value only after verification

credential-store unavailable or migration fails
  -> retain source file unchanged
  -> do not return or apply plaintext password
```

## Deliverables

- Global and project legacy TOML passwords migrate into the OS credential store and are removed only after the destination value is verified.
- Existing credential-store values take precedence over stale TOML values; stale plaintext is removed after a successful read.
- If the OS credential store cannot be read or written, preserve the TOML source and fail closed: settings reads and proxy application do not fall back to plaintext.
- Passwords saved through the existing Settings UI continue to work, and no new JSON or TOML secret write is introduced.

## Done Criteria

- Host integration checks cover global and project TOML migration, verified cleanup, and preserved proxy behavior after migration.
- A failure-path check proves the source TOML remains intact and plaintext is neither returned to settings consumers nor applied to proxy requests when credential storage is unavailable.
- A stale TOML password cannot overwrite a different existing OS credential-store value.
- `cargo +1.96.0 test -p ide-host --test proxy -- --test-threads=1`, relevant `ide-ssh` tests, and Rust formatting pass on macOS.
- No secret values appear in test output or logs.

## Out-of-Scope

- New proxy configuration fields, UI changes, or credential import/export workflows.
- Changes to other settings or secret types.
- Cross-platform runtime checks beyond the base SOW's existing platform coverage.

## Cautions / Risks

- Clearing a TOML value before a verified Keychain write could lose the only copy; source removal must happen last.
- A failed Keychain read must not be mistaken for a confirmed missing item when deciding whether a stale TOML value may be migrated.
- Keychain-backed values remain scoped to the current OS user and do not automatically travel with project files or backups.
