use ide_core::{IdeError, IdeResult};
use parking_lot::RwLock;
use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

/// IDEA's built-in server port, tried first so bookmarked URLs keep working.
const PREFERRED_PORT: u16 = 63342;
const MAX_HEAD: usize = 16 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Characters escaped in one URL path segment.
const SEGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'/')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

struct Shared {
    token: String,
    /// URL key (`/<token>/<key>/…`) → served directory.
    roots: RwLock<HashMap<String, PathBuf>>,
}

/// The built-in web server; started on the first [`WebServer::url_for`].
pub struct WebServer {
    shared: Arc<Shared>,
    port: tokio::sync::OnceCell<u16>,
}

impl Default for WebServer {
    fn default() -> Self {
        Self::new()
    }
}

impl WebServer {
    pub fn new() -> Self {
        Self {
            shared: Arc::new(Shared { token: uuid::Uuid::new_v4().simple().to_string(), roots: RwLock::default() }),
            port: tokio::sync::OnceCell::new(),
        }
    }

    /// The URL serving `file`: under `root` (the project) when it contains the
    /// file, else under the file's directory. Starts the server if needed.
    pub async fn url_for(&self, root: Option<&Path>, file: &Path) -> IdeResult<String> {
        let (base, rel) = match root {
            Some(root) if file.starts_with(root) && file != root => {
                (tokio::fs::canonicalize(root).await?, file.strip_prefix(root).expect("prefix checked"))
            }
            _ => {
                let parent =
                    file.parent().ok_or_else(|| IdeError::invalid(format!("no directory: {}", file.display())))?;
                (
                    tokio::fs::canonicalize(parent).await?,
                    file.strip_prefix(parent).map_err(|e| IdeError::internal(e.to_string()))?,
                )
            }
        };
        if private_path(&base) || private_path(rel) {
            return Err(IdeError::not_found("preview path is not available"));
        }
        let port = self.port().await?;
        let key = self.register(&base);
        let mut url = format!("http://127.0.0.1:{port}/{}/{}", self.shared.token, enc(&key));
        for c in rel.components() {
            url.push('/');
            url.push_str(&enc(&c.as_os_str().to_string_lossy()));
        }
        Ok(url)
    }

    /// The key `dir` is served under: its name, made unique.
    fn register(&self, dir: &Path) -> String {
        let mut roots = self.shared.roots.write();
        if let Some((k, _)) = roots.iter().find(|(_, d)| d.as_path() == dir) {
            return k.clone();
        }
        let name: String = dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
            .chars()
            .map(|c| if c.is_alphanumeric() || "._-".contains(c) { c } else { '_' })
            .collect();
        let name = if name.is_empty() || name == "." || name == ".." { "root".to_string() } else { name };
        let key = (1..)
            .map(|i| if i == 1 { name.clone() } else { format!("{name}-{i}") })
            .find(|k| !roots.contains_key(k))
            .expect("unbounded");
        roots.insert(key.clone(), dir.to_path_buf());
        key
    }

    async fn port(&self) -> IdeResult<u16> {
        self.port
            .get_or_try_init(|| async {
                let listener = match TcpListener::bind(("127.0.0.1", PREFERRED_PORT)).await {
                    Ok(l) => l,
                    Err(_) => TcpListener::bind(("127.0.0.1", 0)).await?,
                };
                let port = listener.local_addr()?.port();
                let shared = self.shared.clone();
                tokio::spawn(async move {
                    loop {
                        match listener.accept().await {
                            Ok((sock, _)) => {
                                let shared = shared.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = serve(sock, &shared, port).await {
                                        tracing::debug!("web server: {e}");
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::warn!("web server accept: {e}");
                                tokio::time::sleep(Duration::from_millis(100)).await;
                            }
                        }
                    }
                });
                tracing::info!("built-in web server on 127.0.0.1:{port}");
                Ok::<_, std::io::Error>(port)
            })
            .await
            .copied()
            .map_err(|e| IdeError::unavailable(format!("cannot start the built-in web server: {e}")))
    }
}

fn enc(s: &str) -> String {
    utf8_percent_encode(s, SEGMENT).to_string()
}

struct Request {
    method: String,
    target: String,
    host: Option<String>,
}

async fn read_head(sock: &mut TcpStream) -> std::io::Result<Option<Request>> {
    let mut reader = BufReader::new(sock).take(MAX_HEAD as u64);
    let mut line = String::new();
    if reader.read_line(&mut line).await? == 0 {
        return Ok(None);
    }
    let mut parts = line.split_whitespace();
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else { return Ok(None) };
    let (method, target) = (method.to_string(), target.to_string());
    let mut host = None;
    loop {
        line.clear();
        if reader.read_line(&mut line).await? == 0 {
            return Ok(None);
        }
        let l = line.trim_end();
        if l.is_empty() {
            break;
        }
        if let Some((name, value)) = l.split_once(':')
            && name.eq_ignore_ascii_case("host")
        {
            host = Some(value.trim().to_ascii_lowercase());
        }
    }
    Ok(Some(Request { method, target, host }))
}

enum Response {
    File { file: tokio::fs::File, path: PathBuf, len: u64 },
    Redirect(String),
    Error(u16, &'static str),
}

async fn serve(mut sock: TcpStream, shared: &Shared, port: u16) -> std::io::Result<()> {
    let Ok(head) = tokio::time::timeout(READ_TIMEOUT, read_head(&mut sock)).await else { return Ok(()) };
    let Some(req) = head? else { return Ok(()) };
    let head_only = req.method == "HEAD";
    let response = if !matches!(req.method.as_str(), "GET" | "HEAD") {
        Response::Error(405, "Method Not Allowed")
    } else if !host_allowed(req.host.as_deref(), port) {
        Response::Error(403, "Forbidden")
    } else {
        resolve(shared, &req.target).await
    };
    let mut out = String::new();
    match &response {
        Response::File { path, len, .. } => {
            out.push_str("HTTP/1.1 200 OK\r\n");
            out.push_str(&format!("Content-Type: {}\r\nContent-Length: {len}\r\n", content_type(path)));
        }
        Response::Redirect(to) => {
            out.push_str(&format!("HTTP/1.1 301 Moved Permanently\r\nLocation: {to}\r\nContent-Length: 0\r\n"));
        }
        Response::Error(code, reason) => {
            out.push_str(&format!(
                "HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n",
                reason.len()
            ));
        }
    }
    out.push_str("Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n");
    sock.write_all(out.as_bytes()).await?;
    if !head_only {
        match response {
            Response::File { mut file, .. } => {
                tokio::io::copy(&mut file, &mut sock).await?;
            }
            Response::Error(_, reason) => sock.write_all(reason.as_bytes()).await?,
            Response::Redirect(_) => {}
        }
    }
    sock.shutdown().await
}

fn host_allowed(host: Option<&str>, port: u16) -> bool {
    host.is_some_and(|h| h == format!("127.0.0.1:{port}") || h == format!("localhost:{port}"))
}

async fn resolve(shared: &Shared, target: &str) -> Response {
    const NOT_FOUND: Response = Response::Error(404, "Not Found");
    let path = target.split(['?', '#']).next().unwrap_or("");
    let Some(rest) = path.strip_prefix('/') else { return NOT_FOUND };
    let mut segments = rest.split('/');
    if segments.next() != Some(shared.token.as_str()) {
        return NOT_FOUND;
    }
    let Some(key) = segments.next().and_then(dec) else { return NOT_FOUND };
    let Some(root) = shared.roots.read().get(&key).cloned() else { return NOT_FOUND };
    let mut file = root.clone();
    let mut rel = PathBuf::new();
    let mut trailing_slash = true;
    for seg in segments {
        trailing_slash = seg.is_empty();
        if seg.is_empty() {
            continue;
        }
        match dec(seg) {
            Some(s) if s != "." && s != ".." && !s.contains(['/', '\\', ':', '\0']) => {
                rel.push(&s);
                file.push(s);
            }
            _ => return NOT_FOUND,
        }
    }
    if private_path(&rel) {
        return NOT_FOUND;
    }
    let Ok(mut file) = tokio::fs::canonicalize(&file).await else { return NOT_FOUND };
    let Ok(rel) = file.strip_prefix(&root) else { return NOT_FOUND };
    if private_path(rel) {
        return NOT_FOUND;
    }
    let Ok(meta) = tokio::fs::metadata(&file).await else { return NOT_FOUND };
    if meta.is_dir() {
        // Relative URLs in an index page resolve against the directory.
        if !trailing_slash {
            return Response::Redirect(format!("{path}/"));
        }
        file.push("index.html");
        let Ok(index) = tokio::fs::canonicalize(&file).await else { return NOT_FOUND };
        let Ok(rel) = index.strip_prefix(&root) else { return NOT_FOUND };
        if private_path(rel) {
            return NOT_FOUND;
        }
        return open_verified(&root, &index).await.unwrap_or(NOT_FOUND);
    }
    if meta.is_file() { open_verified(&root, &file).await.unwrap_or(NOT_FOUND) } else { NOT_FOUND }
}

/// Open first, then verify the name still identifies the opened file. The
/// retained handle prevents a later path swap from changing the served file.
async fn open_verified(root: &Path, path: &Path) -> Option<Response> {
    let file = tokio::fs::File::open(path).await.ok()?;
    let opened = file.metadata().await.ok()?;
    if !opened.is_file() {
        return None;
    }
    let canonical = tokio::fs::canonicalize(path).await.ok()?;
    let relative = canonical.strip_prefix(root).ok()?;
    if private_path(relative) {
        return None;
    }
    let named = tokio::fs::metadata(&canonical).await.ok()?;
    if !same_file(&opened, &named) {
        return None;
    }
    Some(Response::File { file, path: canonical, len: opened.len() })
}

#[cfg(unix)]
fn same_file(opened: &std::fs::Metadata, named: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    opened.dev() == named.dev() && opened.ino() == named.ino()
}

#[cfg(windows)]
fn same_file(opened: &std::fs::Metadata, named: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    matches!(
        (
            opened.volume_serial_number(),
            opened.file_index(),
            named.volume_serial_number(),
            named.file_index()
        ),
        (Some(opened_volume), Some(opened_index), Some(named_volume), Some(named_index))
            if opened_volume == named_volume && opened_index == named_index
    )
}

#[cfg(not(any(unix, windows)))]
fn same_file(_opened: &std::fs::Metadata, _named: &std::fs::Metadata) -> bool {
    false
}

fn private_path(path: &Path) -> bool {
    path.components()
        .filter_map(|component| match component {
            std::path::Component::Normal(name) => Some(name.to_string_lossy().to_ascii_lowercase()),
            _ => None,
        })
        .any(|name| name.starts_with(".env") || matches!(name.as_str(), ".git" | ".ssh" | ".aws" | ".netrc" | ".npmrc"))
}

fn dec(s: &str) -> Option<String> {
    percent_decode_str(s).decode_utf8().ok().map(|s| s.into_owned())
}

fn content_type(path: &Path) -> &'static str {
    let ext = path.extension().map(|e| e.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    match ext.as_str() {
        "html" | "htm" | "xhtml" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" | "cjs" => "text/javascript; charset=utf-8",
        "json" | "map" | "webmanifest" => "application/json; charset=utf-8",
        "xml" => "application/xml; charset=utf-8",
        "txt" | "md" | "csv" => "text/plain; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "ico" => "image/x-icon",
        "bmp" => "image/bmp",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "wasm" => "application/wasm",
        "pdf" => "application/pdf",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "ogg" => "audio/ogg",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn get(url: &str, host: Option<&str>) -> String {
        let rest = url.strip_prefix("http://").unwrap();
        let (authority, path) = rest.split_at(rest.find('/').unwrap());
        let mut sock = TcpStream::connect(authority).await.unwrap();
        let host = host.unwrap_or(authority);
        sock.write_all(format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes()).await.unwrap();
        let mut out = String::new();
        sock.read_to_string(&mut out).await.unwrap();
        out
    }

    #[tokio::test]
    async fn serves_project_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("my app");
        std::fs::create_dir_all(root.join("web/sub")).unwrap();
        std::fs::write(root.join("web/index.html"), "<h1>hi</h1>").unwrap();
        std::fs::write(root.join("web/sub/a b.js"), "export {}").unwrap();
        std::fs::write(dir.path().join("secret.txt"), "no").unwrap();

        let server = WebServer::new();
        let url = server.url_for(Some(&root), &root.join("web/index.html")).await.unwrap();
        assert!(url.ends_with("/my_app/web/index.html"), "{url}");
        let page = get(&url, None).await;
        assert!(page.starts_with("HTTP/1.1 200"), "{page}");
        assert!(page.contains("text/html") && page.ends_with("<h1>hi</h1>"));

        let base = url.trim_end_matches("/web/index.html");
        assert!(get(&format!("{base}/web/sub/a%20b.js"), None).await.contains("text/javascript"));
        assert!(get(&format!("{base}/web"), None).await.contains("Location: /"));
        assert!(get(&format!("{base}/web/"), None).await.ends_with("<h1>hi</h1>"));
        assert!(get(&format!("{base}/../secret.txt"), None).await.starts_with("HTTP/1.1 404"));
        assert!(get(&format!("{base}/%2e%2e/secret.txt"), None).await.starts_with("HTTP/1.1 404"));
        assert!(get(&format!("{base}/web/..%2f..%2fsecret.txt"), None).await.starts_with("HTTP/1.1 404"));
        // Wrong token, foreign Host (DNS rebinding).
        let other = url.replacen(&server.shared.token, "0123", 1);
        assert!(get(&other, None).await.starts_with("HTTP/1.1 404"));
        assert!(get(&url, Some("evil.example:80")).await.starts_with("HTTP/1.1 403"));
    }

    #[tokio::test]
    async fn files_outside_the_project_get_their_own_root() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("x/site"), dir.path().join("y/site"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let server = WebServer::new();
        let ua = server.url_for(None, &a.join("p.html")).await.unwrap();
        let ub = server.url_for(Some(&a), &b.join("p.html")).await.unwrap();
        assert!(ua.ends_with("/site/p.html") && ub.ends_with("/site-2/p.html"), "{ua} {ub}");
        assert_eq!(server.url_for(None, &a.join("q.html")).await.unwrap(), ua.replace("p.html", "q.html"));
    }

    #[tokio::test]
    async fn lightedit_does_not_serve_private_directory_as_root() {
        let tmp = tempfile::tempdir().unwrap();
        let private = tmp.path().join("project/.git");
        std::fs::create_dir_all(&private).unwrap();
        let config = private.join("config");
        std::fs::write(&config, "private").unwrap();
        let server = WebServer::new();

        assert!(server.url_for(None, &config).await.is_err());
        assert!(server.port.get().is_none(), "reject before starting the preview server");
    }

    #[tokio::test]
    async fn refuses_known_secret_metadata_but_serves_ordinary_assets() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("project");
        std::fs::create_dir_all(root.join("web/.git")).unwrap();
        std::fs::create_dir_all(root.join("web/.ssh")).unwrap();
        std::fs::create_dir_all(root.join("web/.aws")).unwrap();
        std::fs::create_dir_all(root.join("web/.well-known")).unwrap();
        std::fs::write(root.join("web/index.html"), "ok").unwrap();
        std::fs::write(root.join("web/.env.local"), "secret").unwrap();
        std::fs::write(root.join("web/.git/config"), "secret").unwrap();
        std::fs::write(root.join("web/.ssh/id_ed25519"), "secret").unwrap();
        std::fs::write(root.join("web/.aws/credentials"), "secret").unwrap();
        std::fs::write(root.join("web/.netrc"), "secret").unwrap();
        std::fs::write(root.join("web/.npmrc"), "secret").unwrap();
        std::fs::write(root.join("web/.well-known/security.txt"), "contact").unwrap();

        let server = WebServer::new();
        let url = server.url_for(Some(&root), &root.join("web/index.html")).await.unwrap();
        let base = url.trim_end_matches("/web/index.html");
        assert!(get(&url, None).await.ends_with("ok"));
        assert!(get(&format!("{base}/web/.well-known/security.txt"), None).await.ends_with("contact"));
        for path in [
            "/web/.env.local",
            "/web/.git/config",
            "/web/.ssh/id_ed25519",
            "/web/.aws/credentials",
            "/web/.netrc",
            "/web/.npmrc",
        ] {
            assert!(get(&format!("{base}{path}"), None).await.starts_with("HTTP/1.1 404"), "{path}");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn refuses_file_and_directory_symlinks_outside_project_root() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("project");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(root.join("web")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(root.join("web/index.html"), "ok").unwrap();
        std::fs::write(outside.join("secret.txt"), "secret").unwrap();
        symlink(outside.join("secret.txt"), root.join("web/secret-link.txt")).unwrap();
        symlink(&outside, root.join("web/outside-link")).unwrap();

        let server = WebServer::new();
        let url = server.url_for(Some(&root), &root.join("web/index.html")).await.unwrap();
        let base = url.trim_end_matches("/web/index.html");
        assert!(get(&format!("{base}/web/secret-link.txt"), None).await.starts_with("HTTP/1.1 404"));
        assert!(get(&format!("{base}/web/outside-link/secret.txt"), None).await.starts_with("HTTP/1.1 404"));
    }
}
