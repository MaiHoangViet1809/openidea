# SOW_20261102_6B530D9E — Decisions

- Owner: SOW_20261102_6B530D9E

## D001 — Security-hardening strategy for local use

- Date: 2026-11-02
- Status: APPROVED
- Owner / Approver: Codex / User
- Context: Static review at baseline commit `8e8a998abe37758a073923424239df7b49e89815` found preview path escape through symlinks, an over-permissive iframe in the existing Restricted Mode preview, an unauthenticated debug-only MCP listener, plaintext credential/history persistence, and a low KaTeX advisory. The project explicitly offers Restricted Mode preview, so removing it would break an existing product workflow.
- Options:
  1. Patch only the preview path check and leave the trust, storage, bridge, and dependency findings unchanged.
  2. Apply layered fixes: retain Restricted Mode preview with an opaque-origin iframe sandbox and confine served paths; keep local MCP available in debug builds while rejecting browser-origin WebSockets; use native OS credential storage and encrypted HTTP history; resolve KaTeX to a patched version through a verified compatible Mermaid dependency set.
  3. Remove project preview and persistent HTTP history entirely.
- Chosen strategy / Why: Option 2 was approved by the user on 2026-11-02. It addresses the findings while preserving local MCP, Restricted Mode preview, credential storage, and request history. The untrusted iframe loses same-origin, form, modal, and popup privileges; trusted preview retains current behavior. Local MCP stays available in debug builds on loopback; browser-origin WebSockets are rejected. The bridge remains unauthenticated to native local processes and is treated as a documented residual risk.
- Accepted tradeoffs: Restricted Mode preview keeps scripts for normal HTML rendering but cannot use same-origin response reads, forms, modals, or popups. Known credential metadata paths are denied, but arbitrary secrets in ordinary assets are not detected. Saved secrets and the HTTP-history key require an available OS credential store and do not automatically move with backups or across OS accounts. Origin validation blocks browser-origin connections but does not authenticate same-user native processes.
- Edge cases / Risks: Existing JSON secrets/history need failure-safe migration. Linux may lack a Secret Service daemon. A native local process can still use the bridge to control the app while it runs. Trusted project HTML can make network requests and read ordinary files exposed for preview. Mermaid 12.1.0 currently constrains KaTeX to the 0.16 line, so an override must be verified against real diagram rendering before use.
- Evidence / References: `crates/ide-web/src/server.rs`, `src/features/project-trust/trust.test.tsx`, `src/features/web/WebEditor.tsx`, `crates/ide-host/src/trust.rs`, `src-tauri/src/lib.rs`, `vendor/tauri-plugin-mcp-bridge/src/websocket.rs`, `crates/ide-ssh/src/secrets.rs`, `crates/ide-db/src/secrets.rs`, `crates/ide-http/src/history.rs`, `pnpm-lock.yaml`, GHSA-238p-pmpm-9mq7, and mermaid-js/mermaid#8388 at the baseline commit above.
- Supersedes / Superseded by: None.
