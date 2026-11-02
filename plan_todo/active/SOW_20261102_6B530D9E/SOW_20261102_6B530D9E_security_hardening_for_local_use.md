# SOW_20261102_6B530D9E — Harden OpenIDEA for safer local use

- Status: IN_PROGRESS
- Approval: APPROVED (User)
- Proposed-By: Codex
- create_dttm: 2026-11-02T12:35:45+07:00
- approve_dttm: 2026-11-02T13:22:12+07:00
- finish_dttm: null
- Plan / Reference: Read-only review of baseline `8e8a998abe37758a073923424239df7b49e89815`; GHSA-238p-pmpm-9mq7; mermaid-js/mermaid#8388.
- Decision Log: SOW_20261102_6B530D9E_decision.md

## Task

Harden the local HTML preview and debug bridge, credential and HTTP-history storage, and vulnerable KaTeX dependency identified in the read-only review, while keeping local MCP, Restricted Mode preview, and request-history workflows available.

## Location

- `crates/ide-web/src/server.rs` — preview path resolution and its existing tests.
- `crates/ide-host/tests/trust.rs` — verify `web_url` remains available in Restricted Mode while execution commands remain denied.
- `src/features/web/WebEditor.tsx` and `src/features/web/WebEditor.test.tsx` — apply and verify a less privileged iframe sandbox for untrusted projects.
- `Cargo.toml`, `Cargo.lock`, `vendor/tauri-plugin-mcp-bridge/**`, and `src-tauri/src/lib.rs` — patch the existing bridge's WebSocket handshake to reject browser-origin connections while retaining loopback MCP in local debug builds and no bridge in release builds.
- `Cargo.lock`, `crates/ide-ssh/Cargo.toml`, `crates/ide-db/Cargo.toml`, `crates/ide-http/Cargo.toml` — compatible OS credential-store and authenticated-encryption dependencies, if needed.
- `crates/ide-ssh/src/secrets.rs`, `crates/ide-ssh/src/manager.rs`, `crates/ide-ssh/src/git_creds.rs`, `crates/ide-host/src/lib.rs`, and `crates/ide-host/tests/proxy.rs` — SSH, Git credential, and proxy-password storage and migration.
- `crates/ide-db/src/secrets.rs`, `crates/ide-db/src/lib.rs`, `crates/ide-db/tests/mysql.rs`, `crates/ide-db/tests/sqlite.rs`, and `crates/ide-host/src/project.rs` — database credential storage and migration.
- `crates/ide-http/src/history.rs` and `crates/ide-host/src/project.rs` — encrypt persisted HTTP history and migrate existing history.
- `package.json`, `pnpm-lock.yaml`, and `src/features/viewers/markdown/mermaid.test.ts` — resolve the vulnerable transitive KaTeX dependency and preserve diagram rendering.

Only files in these paths may change. The listed lockfiles are the only generated project outputs in scope; the vendored bridge must retain its upstream license and required package files. Any other generated output, unrelated product feature, or path requires an approved SOW update.

## Why

The reviewed baseline is commit `8e8a998abe37758a073923424239df7b49e89815`. The product deliberately offers “Preview in Restricted Mode” for untrusted projects, but the iframe currently permits scripts, same-origin access, forms, modals, and popups; the preview server also follows symlinks when resolving files. Debug builds register an unauthenticated MCP WebSocket bridge on loopback. Its plugin exposes only bind-address and port configuration, with no authentication or Origin-validation option ([plugin configuration](https://github.com/hypothesi/mcp-server-tauri/blob/main/packages/tauri-plugin-mcp-bridge/README.md)); its current WebSocket handler accepts the handshake without checking request headers ([upstream source](https://raw.githubusercontent.com/hypothesi/mcp-server-tauri/main/packages/tauri-plugin-mcp-bridge/src/websocket.rs)). Saved SSH, database, Git, and proxy secrets are JSON files; HTTP history persists complete request/response exchanges as JSON. The lockfile resolves KaTeX 0.16.47, covered by [GHSA-238p-pmpm-9mq7](https://github.com/KaTeX/KaTeX/security/advisories/GHSA-238p-pmpm-9mq7), fixed in 0.18.2. Mermaid 12.1.0's dependency range may prevent a straightforward upgrade; see [mermaid-js/mermaid#8388](https://github.com/mermaid-js/mermaid/issues/8388).

The changes reduce accidental exposure and malicious-project risk for a developer using a local build. They do not make trusted project code safe to execute or replace a full sandbox.

## As-Is Diagram (ASCII)

```text
Untrusted project HTML
  -> Restricted Mode intentionally allows web_url
  -> 127.0.0.1 token server rooted at project
  -> path resolution follows symlinks
  -> sandbox allows scripts + same-origin + forms + popups

Debug/local build
  -> MCP plugin registered under cfg(debug_assertions)
  -> 127.0.0.1 unauthenticated WebSocket
  -> accepts browser-origin handshake; exposes execute-JS / window-control commands

SSH / DB / Git / proxy secrets -> plaintext JSON in app data
HTTP request + response       -> plaintext JSON history in app data
Mermaid preview               -> KaTeX 0.16.47
```

## To-Be Diagram (ASCII)

```text
Untrusted project -> Restricted Mode preview remains available
  -> iframe sandbox has opaque origin; scripts cannot use same-origin, forms, or popups
Trusted project -> current preview permissions remain available
Both modes -> canonical target confined under project root
  -> symlink escapes and known credential metadata paths rejected
  -> normal project web assets remain previewable

Local debug build -> MCP remains available on 127.0.0.1
  -> browser-origin WebSocket handshakes rejected
Release build -> no MCP bridge listener
Same-user native local processes can still connect; this residual is documented

SSH / DB / Git / proxy secrets -> native OS credential store
HTTP history                 -> authenticated encryption; key held by OS store
Mermaid preview              -> dependency set with patched KaTeX
```

## Concept Compliance

- Applicable Concepts: None. This fork has no `docs/concept/README.md`, concept catalog, inline rules, or `.agents/rules/` at the reviewed baseline.
- Concept Change: No
- Required Concept Updates: None.

## Deliverables

- The preview server resolves and verifies targets under the canonical project root, rejects symlink escapes, and refuses known credential/source-control metadata paths including `.env*`, `.git/**`, `.ssh/**`, `.aws/**`, `.netrc`, and `.npmrc`. This is a targeted denylist, not general secret detection.
- Restricted Mode preview remains available while the project is untrusted. Its iframe uses an opaque origin (`sandbox="allow-scripts"`) and does not permit same-origin access, forms, modals, or popups. Trusted-project preview retains the current sandbox permissions. The backend continues to allow `web_url` in Restricted Mode.
- The MCP bridge source is vendored at the exact locked version 0.13.1, with its upstream license preserved; the local source change is limited to validating WebSocket Origin headers.
- Local debug builds retain the current MCP workflow and keep the bridge bound to `127.0.0.1`; release builds have no bridge. A source-level patch to the existing plugin rejects WebSocket handshakes carrying browser `Origin` headers while allowing the native MCP client path. This is Origin protection, not authentication: same-user local processes can still connect and control the app.
- Saved SSH, Git, proxy, and database credentials use a cross-platform credential-store API backed by the native OS store on supported desktop platforms. Secrets remain scoped to that OS user/store and do not automatically move across machines or operating systems. Existing JSON credentials migrate only after destination writes are verified; plaintext files are removed after successful migration. If the OS store is unavailable or migration fails, the app fails closed and reports an actionable error instead of writing new plaintext secrets.
- HTTP history remains available across restarts, but exchange entries and the index are authenticated-encrypted at rest with a random key stored in the OS credential store. Existing plaintext history is migrated without data loss; files are replaced only after the encrypted copy is complete and readable.
- The resolved production dependency tree contains no vulnerable KaTeX version. Use a Mermaid release that supports patched KaTeX or a dependency override only after confirming compatibility; do not keep a second vulnerable nested KaTeX copy or force an unverified incompatible version. Existing strict Mermaid rendering behavior is preserved.

## Done Criteria

- Preview tests prove literal and encoded traversal are rejected, symlinks to files and directories outside the root are rejected, listed credential metadata paths are not served, and ordinary nested assets/index pages still work.
- Frontend tests prove Restricted Mode preview remains available with an opaque-origin sandbox lacking `allow-same-origin`, `allow-forms`, `allow-modals`, and `allow-popups`; trusted preview retains the current permission set. Host trust tests prove `web_url` remains allowed while execution commands remain denied for untrusted projects.
- The existing local MCP client connects successfully to a debug build on `127.0.0.1`; a browser-origin handshake is rejected; the release build starts no listener. Document that local native processes remain unauthenticated and privileged.
- Credential-store tests cover create/read/update/delete, successful migration, source-file retention on migration failure, no plaintext fallback, and isolation between projects/services. On macOS, verify the built app reads and writes an actual Keychain item; other supported OSes receive compile/CI coverage and backend-specific runtime coverage where available.
- HTTP-history tests prove correct round-trip, tamper rejection, all-or-nothing migration with original history retained on failure, and that neither index nor exchange files reveal request headers, URL secrets, or bodies in plaintext.
- `pnpm audit` reports no GHSA-238p-pmpm-9mq7 in the production dependency tree. Frontend tests and build pass, and a real Mermaid math diagram renders with strict mode enabled.
- Run the targeted Rust checks for `ide-web`, `ide-host`, `ide-ssh`, `ide-db`, and `ide-http`, plus the vendored bridge tests and formatting check; then workspace formatting/lint checks required by CI. Build and launch the macOS release app once to verify packaging and the no-bridge default.
- Negative check: a preview symlink to an external secret file returns not found; Restricted Mode preview never gains same-origin, form, modal, or popup permissions; a release app exposes no MCP port; a tampered history entry cannot be read; and missing OS-store support never causes a plaintext write.

## Out-of-Scope

- Publishing the fork, opening an upstream PR, signing/notarizing releases, or deploying the app.
- Broad review of every third-party plugin, every language server, or all possible remote-code-execution paths.
- Treating project trust as a sandbox: trusted project HTML retains the existing preview permissions and can make network requests and read ordinary files intentionally exposed as web assets. Restricted Mode's iframe sandbox is a mitigation, not a complete OS-level sandbox.
- Full historical secret scanning or rotation of secrets users may previously have stored in the app.

## Cautions / Risks

- An OS credential store may be unavailable in headless Linux sessions. The app must fail closed rather than silently revert to plaintext.
- OS-backed credentials and the HTTP-history encryption key will not automatically travel with app-data backups or across operating systems; encrypted export/import is outside this scope.
- If encrypted-history migration cannot complete, retain the original data, report the failure, and do not create a new plaintext history file.
- The debug MCP bridge remains unauthenticated to native local processes because its upstream plugin and MCP client have no token handshake. Origin validation blocks browser-origin WebSockets but does not authenticate local programs; the bridge remains privileged while running.
- The targeted metadata denylist does not detect arbitrary secrets in ordinary filenames. Preserve `.well-known` and other ordinary web assets unless they match the explicit denylist.
- Restricted Mode's opaque origin can prevent project scripts from reading same-origin responses or submitting forms; that is the intended boundary for untrusted preview.
- Key loss or reset can make encrypted history unreadable; keep migration and error handling explicit.
- Mermaid currently constrains KaTeX to the 0.16 line; any override must be verified against a real Mermaid math diagram and the existing renderer tests before changing the lockfile.

## Extensions

1. `SOW_20261102_6B530D9E_EXT_R7X4M9Q2_proxy_settings_password_migration.md` — DRAFT, approval pending. Adds migration and fail-closed handling for manually configured proxy passwords in global/project `settings.toml`; no implementation is authorized by this draft.

## Verification / Closeout

- Definitely implemented: Approved preview, debug MCP Origin guard, OS credential-store and JSON migration, encrypted HTTP history, and Mermaid/KaTeX dependency changes, committed as `c808fee`. Targeted tests pass; the macOS debug MCP native-client and Origin checks pass; a release `.app` bundle launched without a listener on ports 9223–9322. The proxy integration test used macOS Keychain.
- Approximated / simulated: Unit tests use an in-memory credential-store backend for deterministic migration/failure checks. Windows and Linux credential-store builds were attempted but could not run because this Mac lacks the Windows SDK headers and `x86_64-linux-gnu-gcc`.
- Not implemented / not verified: A manually typed `proxy.password` in global or project TOML can still be used as a fallback; the proposed fix is in DRAFT extension `SOW_20261102_6B530D9E_EXT_R7X4M9Q2`. Cross-platform runtime coverage is not available here. The `.app` bundle built and launched, while updater archive signing stopped because no private signing key is configured; release signing is out of scope.

## Progress
- progress_updated_dttm: 2026-11-02T14:38:44+07:00

| Item | Status | Evidence / Pending reason | Next action / Owner |
| --- | --- | --- | --- |
| V0: Independent implementation-risk review | COMPLETE | Read-only review findings were integrated: preview open/verify TOCTOU and LightEdit private-root gaps were fixed; Restricted Mode trust coverage now includes `web_url`; Origin guard retains native clients. | Main records residuals and closes the approved scope. |
| C1: Preview path and Restricted Mode hardening | COMPLETE | `ide-web`: 7 tests; host trust: 8 tests; frontend WebEditor/Mermaid: 12 tests; build passes. Symlink identity is checked against the retained open file handle. | Main records check output and commit. |
| C2: Local MCP browser-Origin guard | COMPLETE | Vendored bridge: 13 tests. Debug app connected at `127.0.0.1:9223`; native status command succeeded and a handshake with `Origin` returned 403. Release bundle ran with no listener on 9223–9322. | Main records the native-process residual and commit. |
| C3: OS credential storage and legacy migration | COMPLETE (base scope) | SSH/Git: 21 tests; DB: 40 unit and 13 integration tests; HTTP proxy integration: 1 test using macOS Keychain. JSON/temp migration, failure retention, and no plaintext JSON write are covered. Manual TOML fallback is tracked separately in the unapproved DRAFT extension. | Obtain separate approval before editing the newly identified proxy owner file. |
| C4: Encrypted HTTP history and migration | COMPLETE | `ide-http`: 23 tests pass, including round-trip, tamper, migration retention, and unavailable-store behavior. | Main records evidence and commit. |
| C5: Patched KaTeX dependency resolution | COMPLETE | Production audit reports no known vulnerabilities; strict Mermaid math and WebEditor tests pass; `pnpm build` passes. | Main records evidence and commit. |
| C6: Runtime verification, gap review, and scoped commit | COMPLETE (base scope) | Commit `c808fee` contains the approved implementation and SOW bundle. Rustfmt and changed-file frontend lint/format pass; targeted Clippy passes. Full workspace Clippy reports findings in untouched `ide-syntax` and `ide-lsp`; full frontend lint reports unused catch variables in untouched upstream vendor JS; full format check flags AGENTS/SOW and untouched vendor files. Release `.app` built/launched; updater signing lacks a private key. | Await explicit approval for DRAFT extension `SOW_20261102_6B530D9E_EXT_R7X4M9Q2` before widening scope. |
