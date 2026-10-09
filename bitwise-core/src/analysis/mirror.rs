//! # Mirror: clonar un sitio y servirlo localmente con túnel temporal
//!
//! `bitwise mirror <url>`:
//!  1. Descarga el HTML de la página
//!  2. Descarga TODOS los assets referenciados (JS, CSS, imágenes, fuentes,
//!     sourcemaps) reescribiendo los paths para que la copia funcione offline
//!  3. Le hace ingeniería inversa a los bundles: endpoints, secrets,
//!     score de ofuscación (reusa analysis::web y analysis::js_deobf)
//!  4. Sirve la copia en un servidor HTTP local (127.0.0.1)
//!  5. Abre un túnel público temporal vía localhost.run (SSH, sin cuenta)
//!
//! Depende de `ureq` para HTTP y de `ssh` del sistema para el túnel.

use crate::analysis::web::WebClient;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub enum MirrorError {
    Http(String),
    Io(std::io::Error),
    Url(String),
}

impl std::fmt::Display for MirrorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MirrorError::Http(m) => write!(f, "http: {}", m),
            MirrorError::Io(e) => write!(f, "io: {}", e),
            MirrorError::Url(m) => write!(f, "url inválida: {}", m),
        }
    }
}

pub type Result<T> = std::result::Result<T, MirrorError>;

/// Estadísticas del mirror.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MirrorStats {
    pub pages: usize,
    pub assets: usize,
    pub bytes: u64,
    pub js_bundles: usize,
    pub endpoints_found: usize,
    pub secrets_found: usize,
    /// url → lista de endpoints dinámicos detectados en ese archivo
    pub endpoints: BTreeMap<String, Vec<String>>,
    /// secretos detectados (kind @ file)
    pub secrets: Vec<String>,
}

/// GET binario con timeout y UA de navegador.
pub fn fetch_bytes(url: &str) -> Result<Vec<u8>> {
    let resp = ureq::get(url)
        .timeout(Duration::from_secs(20))
        .set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
        .call()
        .map_err(|e| MirrorError::Http(e.to_string()))?;
    let mut buf = Vec::new();
    resp.into_reader()
        .take(64 * 1024 * 1024) // 64 MB cap por archivo
        .read_to_end(&mut buf)
        .map_err(MirrorError::Io)?;
    Ok(buf)
}

fn fetch_text(url: &str) -> Result<String> {
    let b = fetch_bytes(url)?;
    // from_utf8_lossy nunca falla; si hay bytes inválidos se reemplazan
    Ok(String::from_utf8_lossy(&b).into_owned())
}

/// Parsea una URL en (scheme://host, path).
fn split_url(url: &str) -> Result<(String, String)> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| MirrorError::Url(format!("falta scheme: {}", url)))?;
    let (host, path) = match rest.split_once('/') {
        Some((h, p)) => (h.to_string(), format!("/{}", p)),
        None => (rest.to_string(), "/".to_string()),
    };
    Ok((format!("{}://{}", scheme, host), path))
}

/// Convierte una URL remota en ruta local relativa dentro del mirror.
/// Regla: se preserva el path (sin query), escapando `..`.
fn url_to_local(url: &str) -> Result<String> {
    let (_origin, path) = split_url(url)?;
    let path = path.split(['?', '#']).next().unwrap_or("/");
    let mut clean = PathBuf::from(path.trim_start_matches('/'));
    if clean.as_os_str().is_empty() || path.ends_with('/') {
        clean.push("index.html");
    }
    // aplanar .. para no escapar del directorio del mirror
    let mut safe = PathBuf::new();
    for c in clean.components() {
        match c {
            std::path::Component::ParentDir => {
                safe.pop();
            }
            std::path::Component::CurDir => {}
            other => safe.push(other.as_os_str()),
        }
    }
    let s = safe.to_string_lossy().into_owned();
    if s.is_empty() {
        return Ok("index.html".into());
    }
    Ok(s)
}

fn local_to_url(base: &str, local: &str) -> String {
    format!("{}/{}", base.trim_end_matches('/'), local)
}

/// Extrae URLs de assets del HTML: <script src>, <link href>, <img src>,
/// <source src>, <video src>, <a href> (solo misma página de nivel 1).
pub fn extract_asset_urls(html: &str, page_url: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut push = |attr_val: &str, out: &mut Vec<String>| {
        let v = attr_val.trim().trim_matches(|c| c == '"' || c == '\'');
        if v.is_empty() || v.starts_with("data:") || v.starts_with("javascript:") || v.starts_with('#') {
            return;
        }
        out.push(crate::analysis::web::resolve_url(v, page_url));
    };

    // escaneo simple por tags (sin parser HTML completo)
    let lower = html.to_lowercase();
    let mut search_from = 0usize;
    while let Some(rel) = lower[search_from..].find('<').map(|i| i + search_from) {
        let end = lower[rel..].find('>').map(|i| i + rel).unwrap_or(lower.len());
        let tag = &lower[rel..end];
        let raw_tag = &html[rel..end.min(html.len())];
        if tag.starts_with("<script") || tag.starts_with("<link") || tag.starts_with("<img")
            || tag.starts_with("<source") || tag.starts_with("<video")
        {
            for (key, pref) in [("src=\"", "src=\""), ("href=\"", "href=\"")] {
                if let Some(kpos) = tag.find(key) {
                    // extraer el valor del atributo del HTML original (mismo offset por lower)
                    let vstart = rel + kpos + pref.len();
                    if let Some(vend) = html[vstart..].find('"').map(|i| i + vstart) {
                        push(&html[vstart..vend], &mut out);
                    }
                }
            }
        }
        let _ = raw_tag;
        search_from = end;
        if out.len() > 200 {
            break; // cap de 200 assets
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Reescribe las URLs de assets en el HTML a rutas locales.
pub fn rewrite_html(html: &str, page_url: &str, local_root_label: &str) -> String {
    let assets = extract_asset_urls(html, page_url);
    let mut out = html.to_string();
    for url in assets {
        let local = match url_to_local(&url) {
            Ok(l) => l,
            Err(_) => continue,
        };
        // reemplazar la URL absoluta por la ruta local relativa
        let rel = format!("/{}/{}", local_root_label.trim_matches('/'), local);
        // el path original de la URL (lo que aparece en el HTML)
        if let Ok((_origin, path)) = split_url(&url) {
            let path_q = path.split(['?', '#']).next().unwrap_or(&path);
            out = out.replace(&url, &rel);
            if path_q != "/" && !path_q.is_empty() {
                out = out.replace(path_q, &rel);
            }
        }
    }
    out
}

/// Realiza el mirror completo de una página + assets.
pub fn mirror(url: &str, out_dir: &Path) -> Result<MirrorStats> {
    let mut stats = MirrorStats::default();
    let start = Instant::now();

    let html = fetch_text(url)?;
    stats.pages = 1;

    // HTML reescrito a rutas locales
    let rewritten = rewrite_html(&html, url, "assets");
    let index_local = url_to_local(url).unwrap_or_else(|_| "index.html".into());
    let index_path = out_dir.join(&index_local);
    if let Some(parent) = index_path.parent() {
        std::fs::create_dir_all(parent).map_err(MirrorError::Io)?;
    }
    std::fs::write(&index_path, rewritten).map_err(MirrorError::Io)?;
    stats.bytes += html.len() as u64;

    // ingeniería inversa del HTML/inline scripts
    let client = WebClient::new();
    let _ = client; // (endpoints/secrets del HTML se suman abajo vía detectores)

    let inline_eps = crate::analysis::web::extract_endpoints(&html);
    if !inline_eps.is_empty() {
        stats.endpoints.insert("(inline)".into(), inline_eps.iter().take(50).cloned().collect());
    }
    for s in crate::analysis::web::detect_secrets(&html) {
        stats.secrets.push(format!("{} @ {}", s.kind, "(inline)"));
    }

    // descargar assets
    let assets = extract_asset_urls(&html, url);
    for asset_url in &assets {
        let local = match url_to_local(asset_url) {
            Ok(l) => l,
            Err(_) => continue,
        };
        let dest = out_dir.join("assets").join(&local);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(MirrorError::Io)?;
        }
        let data = match fetch_bytes(asset_url) {
            Ok(d) => d,
            Err(_) => continue, // assets rotos no frenan el mirror
        };
        stats.bytes += data.len() as u64;
        stats.assets += 1;

        let is_js = local.ends_with(".js") || local.ends_with(".mjs");
        if is_js {
            stats.js_bundles += 1;
            let src = String::from_utf8_lossy(&data).into_owned();
            // ingeniería inversa del bundle
            let eps = crate::analysis::web::extract_endpoints(&src);
            if !eps.is_empty() {
                stats.endpoints.insert(local.clone(), eps.iter().take(50).cloned().collect());
                stats.endpoints_found += eps.len().min(50);
            }
            for s in crate::analysis::web::detect_secrets(&src) {
                stats.secrets.push(format!("{} @ {}", s.kind, local));
            }
        }

        std::fs::write(&dest, &data).map_err(MirrorError::Io)?;
    }

    stats.endpoints_found += inline_eps.len().min(50);
    stats.secrets_found = stats.secrets.len();
    let _ = start;
    Ok(stats)
}

/// Servidor HTTP estático simple (un hilo, responde lo que hay en root).
/// Bloquea hasta que `stop_rx` reciba o el listener muera.
pub fn serve_blocking(root: &Path, port: u16, stop_rx: std::sync::mpsc::Receiver<()>) -> Result<()> {
    use std::io::Write;

    let listener = std::net::TcpListener::bind(("127.0.0.1", port)).map_err(MirrorError::Io)?;
    println!("  sirviendo {} en http://127.0.0.1:{}", root.display(), port);
    listener
        .set_nonblocking(true)
        .map_err(MirrorError::Io)?;

    loop {
        if stop_rx.try_recv().is_ok() {
            return Ok(());
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                // leer request line (buffer chico, GET sin body)
                let mut buf = [0u8; 4096];
                use std::io::Read;
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let path = req
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("/")
                    .split(['?', '#'])
                    .next()
                    .unwrap_or("/")
                    .to_string();

                // mapear a archivo local
                let rel = url_to_local(&format!("http://x/{}", path.trim_start_matches('/')))
                    .unwrap_or_else(|_| "index.html".into());
                let mut file_path = root.join(rel.trim_start_matches('/'));
                if file_path.is_dir() {
                    file_path.push("index.html");
                }

                let (status, content_type, body) = if file_path.exists() {
                    let data = std::fs::read(&file_path).unwrap_or_default();
                    let ct = content_type_for(&file_path);
                    ("200 OK", ct, data)
                } else if root.join("index.html").exists() && !path.contains('.') {
                    // SPA fallback
                    let data = std::fs::read(root.join("index.html")).unwrap_or_default();
                    ("200 OK", "text/html; charset=utf-8", data)
                } else {
                    ("404 Not Found", "text/plain", b"404".to_vec())
                };

                let resp = format!(
                    "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    status, content_type, body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.write_all(&body);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(MirrorError::Io(e)),
        }
    }
}

fn content_type_for(p: &Path) -> &'static str {
    match p.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "html" | "htm" => "text/html; charset=utf-8",
        "js" | "mjs" => "application/javascript",
        "css" => "text/css",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "json" => "application/json",
        "map" => "application/json",
        _ => "application/octet-stream",
    }
}

/// Abre un túnel público temporal. Devuelve el proceso hijo del ssh y la URL.
///
/// Proveedor: pinggy (ssh -p 80 a.pinggy.io, sin cuenta). Se intenta primero
/// con subdominio fijo derivado del puerto para poder reusar la URL.
pub fn open_tunnel(local_port: u16) -> Result<(std::process::Child, String)> {
    use std::process::{Command, Stdio};

    let mut child = Command::new("ssh")
        .args([
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "ExitOnForwardFailure=yes",
            "-p",
            "80",
            "-R",
            &format!("0:127.0.0.1:{}", local_port),
            "a.pinggy.io",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| {
            MirrorError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("ssh no disponible: {}", e),
            ))
        })?;

    // pinggy imprime la URL pública en stdout del ssh
    let stdout = child.stdout.take().expect("stdout piped");
    use std::io::BufRead;
    let reader = std::io::BufReader::new(stdout);
    let mut tunnel_url = String::new();
    let deadline = Instant::now() + Duration::from_secs(25);
    for line in reader.lines() {
        let Ok(line) = line else { break };
        if let Some(s) = line.find("https://") {
            let rest = &line[s..];
            let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
            let cand = rest[..end].trim_end_matches('.').to_string();
            // descartar links de dashboard/docs, quedarnos con el túnel
            if cand.contains(".pinggy") && !cand.contains("dashboard") && !cand.contains("pinggy.io") {
                tunnel_url = cand;
                break;
            }
        }
        if Instant::now() > deadline {
            break;
        }
    }

    if tunnel_url.is_empty() {
        let _ = child.kill();
        return Err(MirrorError::Http(
            "no se pudo obtener la URL del túnel (pinggy no respondió)".into(),
        ));
    }

    Ok((child, tunnel_url))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_to_local_basic() {
        assert_eq!(url_to_local("https://x.com/").unwrap(), "index.html");
        assert_eq!(url_to_local("https://x.com/app.js").unwrap(), "app.js");
        assert_eq!(
            url_to_local("https://x.com/static/app.js?v=1").unwrap(),
            "static/app.js"
        );
    }

    #[test]
    fn url_to_local_no_escapa() {
        let l = url_to_local("https://x.com/../../etc/passwd").unwrap();
        assert!(!l.contains(".."));
    }

    #[test]
    fn extract_assets_encuentra_script() {
        let html = r#"<html><head><script src="/app.js"></script><link href="/s.css" rel="stylesheet"></head><body><img src="https://cdn.x.com/i.png"></body></html>"#;
        let urls = extract_asset_urls(html, "https://x.com/");
        assert!(urls.iter().any(|u| u.ends_with("/app.js")));
        assert!(urls.iter().any(|u| u.ends_with("/s.css")));
        assert!(urls.iter().any(|u| u.contains("cdn.x.com")));
        assert!(!urls.iter().any(|u| u.starts_with("data:")));
    }

    #[test]
    fn rewrite_html_cambia_src() {
        let html = r#"<script src="https://x.com/app.js"></script>"#;
        let out = rewrite_html(html, "https://x.com/", "assets");
        assert!(out.contains("/assets/app.js"), "got: {}", out);
        assert!(!out.contains("https://x.com/app.js"));
    }
}
