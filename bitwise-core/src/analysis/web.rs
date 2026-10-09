//! # Análisis web — ingeniería inversa de superficie estática
//!
//! Descarga una página, sigue sus scripts y extrae inteligencia:
//!  - endpoints de API (rutas /api/..., fetch/axios/XHR)
//!  - secrets hardcodeados (API keys, tokens, JWTs)
//!  - stack fingerprint (React/Vue/Angular/jQuery, CDNs)
//!  - formularios y métodos
//!  - headers del servidor
//!
//! Es análisis ESTÁTICO del cliente: no ejecuta JS ni renderiza el DOM.
//! Para SPAs que cargan todo por XHR se necesita un navegador real
//! (integrable después vía Puppeteer/Playwright como dependencia opcional).

use std::collections::BTreeSet;
use std::io::Read;
use std::time::Duration;

pub struct WebClient {
    agent: ureq::Agent,
}

#[derive(Debug, Clone, Default)]
pub struct WebReport {
    pub url: String,
    pub status: u16,
    pub server_header: Option<String>,
    pub title: Option<String>,
    pub frameworks: Vec<String>,
    pub scripts: Vec<String>,
    pub inline_script_count: usize,
    pub endpoints: Vec<String>,
    pub secrets: Vec<SecretFinding>,
    pub forms: Vec<FormInfo>,
}

#[derive(Debug, Clone)]
pub struct SecretFinding {
    pub kind: String,
    pub value: String,
    pub context: String,
}

#[derive(Debug, Clone)]
pub struct FormInfo {
    pub action: String,
    pub method: String,
    pub inputs: Vec<String>,
}

#[derive(Debug)]
pub enum WebError {
    Network(String),
    Io(std::io::Error),
}

impl std::fmt::Display for WebError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebError::Network(e) => write!(f, "red: {}", e),
            WebError::Io(e) => write!(f, "io: {}", e),
        }
    }
}

impl WebClient {
    pub fn new() -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_read(Duration::from_secs(20))
            .timeout_write(Duration::from_secs(10))
            .user_agent("Mozilla/5.0 (X11; Linux x86_64) bitwise-framework/0.5 (recon)")
            .build();
        Self { agent }
    }

    fn get(&self, url: &str) -> Result<(u16, Option<String>, String), WebError> {
        let resp = self
            .agent
            .get(url)
            .call()
            .map_err(|e| WebError::Network(e.to_string()))?;
        let status = resp.status();
        let server = resp.header("server").map(|s| s.to_string());
        let mut body = String::new();
        resp.into_reader()
            .take(5_000_000) // 5 MB max por recurso
            .read_to_string(&mut body)
            .map_err(WebError::Io)?;
        Ok((status, server, body))
    }

    /// Analiza una URL: HTML + todos los scripts referenciados.
    pub fn analyze(&self, url: &str, deep: bool) -> Result<WebReport, WebError> {
        let (status, server, html) = self.get(url)?;
        let mut report = WebReport {
            url: url.to_string(),
            status,
            server_header: server,
            ..Default::default()
        };

        report.title = extract_title(&html);
        report.frameworks = detect_frameworks(&html);
        report.forms = extract_forms(&html);
        report.inline_script_count = count_inline_scripts(&html);

        // recolectar código JS a analizar (inline + externo)
        let inline_js = extract_inline_scripts(&html);
        let script_urls = extract_script_urls(&html, url);
        report.scripts = script_urls.clone();

        let mut all_js = inline_js;

        // descargar scripts externos si deep
        if deep {
            for s in &script_urls {
                if let Ok((_, _, body)) = self.get(s) {
                    all_js.push(body);
                }
            }
        }

        // extraer endpoints y secrets de todo el JS
        let mut endpoints = BTreeSet::new();
        let mut secrets = Vec::new();
        for js in &all_js {
            for ep in extract_endpoints(js) {
                endpoints.insert(ep);
            }
            secrets.extend(detect_secrets(js));
        }
        report.endpoints = endpoints.into_iter().collect();
        report.secrets = secrets;

        Ok(report)
    }
}

impl Default for WebClient {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Extractores
// ============================================================================

pub fn extract_title(html: &str) -> Option<String> {
    let lower = html.to_lowercase();
    let start = lower.find("<title")?;
    let content_start = html[start..].find('>')? + start + 1;
    let end = lower[content_start..].find("</title")? + content_start;
    Some(html[content_start..end].trim().to_string())
}

/// URLs de <script src=...> resueltas contra la página base.
pub fn extract_script_urls(html: &str, base_url: &str) -> Vec<String> {
    let mut out = Vec::new();
    let lower = html.to_lowercase();
    let mut pos = 0;
    while let Some(start) = lower[pos..].find("<script") {
        let tag_start = pos + start;
        let tag_end = match lower[tag_start..].find('>') {
            Some(e) => tag_start + e,
            None => break,
        };
        let tag = &html[tag_start..tag_end];
        // buscar src=
        if let Some(src_pos) = tag.find("src=\"") {
            let rest = &tag[src_pos + 5..];
            if let Some(q) = rest.find('"') {
                let src = &rest[..q];
                let resolved = resolve_url(src, base_url);
                out.push(resolved);
            }
        } else if let Some(src_pos) = tag.find("src='") {
            let rest = &tag[src_pos + 5..];
            if let Some(q) = rest.find('\'') {
                let src = &rest[..q];
                let resolved = resolve_url(src, base_url);
                out.push(resolved);
            }
        }
        pos = tag_end;
    }
    out
}

/// Contenido de los <script> inline (sin src).
pub fn extract_inline_scripts(html: &str) -> Vec<String> {
    let mut out = Vec::new();
    let lower = html.to_lowercase();
    let mut pos = 0;
    while let Some(start) = lower[pos..].find("<script") {
        let tag_start = pos + start;
        let content_start = match lower[tag_start..].find('>') {
            Some(e) => tag_start + e + 1,
            None => break,
        };
        let end = match lower[content_start..].find("</script") {
            Some(e) => content_start + e,
            None => break,
        };
        let tag = &html[tag_start..content_start];
        if !tag.contains("src=") {
            out.push(html[content_start..end].to_string());
        }
        pos = end;
    }
    out
}

pub fn count_inline_scripts(html: &str) -> usize {
    extract_inline_scripts(html).len()
}

/// Resuelve una URL relativa contra la base (versión simple).
pub fn resolve_url(src: &str, base: &str) -> String {
    if src.starts_with("http://") || src.starts_with("https://") || src.starts_with("//") {
        if let Some(stripped) = src.strip_prefix("//") {
            return format!("https://{}", stripped);
        }
        return src.to_string();
    }
    // extraer origen de la base
    if let Some(scheme_end) = base.find("://") {
        let after = &base[scheme_end + 3..];
        if let Some(path_start) = after.find('/') {
            let origin = &base[..scheme_end + 3 + path_start];
            if src.starts_with('/') {
                return format!("{}{}", origin, src);
            }
            return format!("{}/{}", origin, src);
        }
    }
    src.to_string()
}

/// Detecta frameworks por sus firmas en el HTML.
pub fn detect_frameworks(html: &str) -> Vec<String> {
    let mut out = Vec::new();
    let lower = html.to_lowercase();
    let checks: &[(&str, &str)] = &[
        ("react", "React"),
        ("__next", "Next.js"),
        ("nuxt", "Nuxt"),
        ("vue", "Vue.js"),
        ("angular", "Angular"),
        ("svelte", "Svelte"),
        ("jquery", "jQuery"),
        ("bootstrap", "Bootstrap"),
        ("tailwind", "Tailwind"),
        ("wordpress", "WordPress"),
        ("drupal", "Drupal"),
        ("wix", "Wix"),
        ("shopify", "Shopify"),
        ("gatsby", "Gatsby"),
    ];
    for (sig, name) in checks {
        if lower.contains(sig) {
            out.push(name.to_string());
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Extrae formularios con su action, method e inputs.
pub fn extract_forms(html: &str) -> Vec<FormInfo> {
    let mut out = Vec::new();
    let lower = html.to_lowercase();
    let mut pos = 0;
    while let Some(start) = lower[pos..].find("<form") {
        let tag_start = pos + start;
        let tag_end = match lower[tag_start..].find('>') {
            Some(e) => tag_start + e,
            None => break,
        };
        let tag = &html[tag_start..tag_end];

        let action = extract_attr(tag, "action").unwrap_or_default();
        let method = extract_attr(tag, "method")
            .unwrap_or_else(|| "get".to_string())
            .to_uppercase();

        // inputs dentro del form
        let body_end = lower[tag_end..].find("</form").map(|e| tag_end + e).unwrap_or(html.len());
        let body = &html[tag_end..body_end];
        let mut inputs = Vec::new();
        let mut p2 = 0;
        let lbody = body.to_lowercase();
        while let Some(s2) = lbody[p2..].find("<input") {
            let t2 = p2 + s2;
            let te2 = match lbody[t2..].find('>') {
                Some(e) => t2 + e,
                None => break,
            };
            if let Some(name) = extract_attr(&body[t2..te2], "name") {
                inputs.push(format!(
                    "{} ({})",
                    name,
                    extract_attr(&body[t2..te2], "type").unwrap_or_else(|| "text".into())
                ));
            }
            p2 = te2;
        }

        out.push(FormInfo {
            action,
            method,
            inputs,
        });
        pos = body_end;
    }
    out
}

fn extract_attr(tag: &str, attr: &str) -> Option<String> {
    let lower = tag.to_lowercase();
    let needle = format!("{}=\"", attr);
    if let Some(p) = lower.find(&needle) {
        let rest = &tag[p + needle.len()..];
        if let Some(q) = rest.find('"') {
            return Some(rest[..q].to_string());
        }
    }
    // variante comilla simple
    let needle = format!("{}='", attr);
    if let Some(p) = lower.find(&needle) {
        let rest = &tag[p + needle.len()..];
        if let Some(q) = rest.find('\'') {
            return Some(rest[..q].to_string());
        }
    }
    None
}

/// Extrae endpoints de API del código JS: rutas citadas en strings.
pub fn extract_endpoints(js: &str) -> Vec<String> {
    let mut out = BTreeSet::new();
    // patrones: "/api/...", fetch("/x"), axios.get("/x"), url: "/x"
    for line in js.split(|c: char| c == '"' || c == '\'' || c == '`' || c == '\n') {
        let line = line.trim();
        // rutas absolutas con 2+ segmentos
        if line.starts_with('/') && line.len() > 3 {
            let clean: String = line
                .chars()
                .take_while(|c| c.is_ascii_graphic())
                .collect();
            if clean.len() > 3 && !clean.contains(' ') && looks_like_path(&clean) {
                out.insert(clean);
            }
        }
        // urls completas http(s)
        if line.starts_with("https://") || line.starts_with("http://") {
            let clean: String = line.chars().take_while(|c| c.is_ascii_graphic()).collect();
            out.insert(clean);
        }
    }
    out.into_iter().take(500).collect()
}

fn looks_like_path(s: &str) -> bool {
    // debe tener al menos un / interno y no ser solo formato
    let segments: Vec<&str> = s.split('/').filter(|x| !x.is_empty()).collect();
    if segments.is_empty() {
        return false;
    }
    // excluir extensiones de archivos estáticos comunes
    let static_exts = [
        ".css", ".png", ".jpg", ".svg", ".woff", ".woff2", ".ttf", ".ico", ".gif", ".map",
    ];
    let lower = s.to_lowercase();
    !static_exts.iter().any(|e| lower.ends_with(e))
}

/// Detecta secrets hardcodeados en el JS.
pub fn detect_secrets(js: &str) -> Vec<SecretFinding> {
    let mut out = Vec::new();
    // (nombre, prefijo de búsqueda simple) — sin motor regex completo
    let patterns: &[(&str, &str)] = &[
        ("aws_access_key", r"AKIA[0-9A-Z]{16}"),
        ("google_api_key", r"AIza[0-9A-Za-z\-_]{35}"),
        ("github_token", r"gh[pousr]_[A-Za-z0-9]{36,}"),
        ("jwt", r"eyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}"),
        ("slack_token", r"xox[baprs]-[A-Za-z0-9-]{10,}"),
        ("private_key_pem", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        ("firebase", r"[a-z0-9-]+\.firebaseapp\.com"),
        ("mongodb_uri", r"mongodb+srv://[^\s]+"),
        ("postgres_uri", r"postgresql://[^\s]+"),
        ("mysql_uri", r"mysql://[^\s]+"),
        ("sendgrid_key", r"SG\.[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{30,}"),
        ("stripe_key", r"sk_live_[A-Za-z0-9]{20,}"),
        ("twilio_key", r"SK[0-9a-fA-F]{32}"),
    ];
    for (kind, pat) in patterns {
        // regex-lite: búsqueda simple por prefijos sin motor regex completo
        for (idx, _) in js.match_indices(pat.split('[').next().unwrap_or(pat)) {
            let ctx_start = idx.saturating_sub(40);
            let ctx_end = (idx + 120).min(js.len());
            let context: String = js[ctx_start..ctx_end].chars().filter(|c| c.is_ascii_graphic() || *c == ' ').collect();
            let value: String = js[idx..ctx_end]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.' || *c == ':' || *c == '/')
                .collect();
            if value.len() > 10 {
                out.push(SecretFinding {
                    kind: kind.to_string(),
                    value: value.chars().take(60).collect(),
                    context: context.chars().take(100).collect(),
                });
            }
            if out.len() > 100 {
                return out;
            }
        }
    }
    out
}

/// Formatea el reporte legible.
pub fn format_report(r: &WebReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("═══ Bitwise Web Recon: {} ═══\n\n", r.url));
    out.push_str(&format!("  status: {}\n", r.status));
    if let Some(s) = &r.server_header {
        out.push_str(&format!("  server: {}\n", s));
    }
    if let Some(t) = &r.title {
        out.push_str(&format!("  title:  {}\n", t));
    }
    if !r.frameworks.is_empty() {
        out.push_str(&format!("\n  stack: {}\n", r.frameworks.join(", ")));
    }
    out.push_str(&format!("\n  scripts externos: {}\n", r.scripts.len()));
    for s in r.scripts.iter().take(20) {
        out.push_str(&format!("    {}\n", s));
    }
    out.push_str(&format!("  scripts inline:   {}\n", r.inline_script_count));

    if !r.endpoints.is_empty() {
        out.push_str(&format!("\n  endpoints ({}):\n", r.endpoints.len()));
        for e in r.endpoints.iter().take(50) {
            out.push_str(&format!("    {}\n", e));
        }
    }
    if !r.secrets.is_empty() {
        out.push_str("\n  ⚠ SECRETS ENCONTRADOS:\n");
        for s in &r.secrets {
            out.push_str(&format!("    [{}] {}\n", s.kind, s.value));
        }
    }
    if !r.forms.is_empty() {
        out.push_str("\n  formularios:\n");
        for f in &r.forms {
            out.push_str(&format!("    {} {} → {} inputs\n", f.method, f.action, f.inputs.len()));
            for i in &f.inputs {
                out.push_str(&format!("      · {}\n", i));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn title_extraction() {
        assert_eq!(
            extract_title("<html><head><title>Mi Sitio</title></head></html>"),
            Some("Mi Sitio".into())
        );
        assert_eq!(extract_title("<html>sin title</html>"), None);
    }

    #[test]
    fn script_urls_extraction() {
        let html = r#"<script src="/app.js"></script><script src="https://cdn.x.com/lib.min.js"></script>"#;
        let urls = extract_script_urls(html, "https://example.com/page");
        assert_eq!(urls.len(), 2);
        assert_eq!(urls[0], "https://example.com/app.js");
        assert!(urls[1].contains("cdn.x.com"));
    }

    #[test]
    fn frameworks_detection() {
        let f = detect_frameworks("<div data-reactroot></div><script>jQuery</script>");
        assert!(f.contains(&"React".to_string()));
        assert!(f.contains(&"jQuery".to_string()));
    }

    #[test]
    fn endpoints_from_js() {
        let js = r#"fetch("/api/users/42").then(r => r.json()); const u = "https://api.example.com/v2/data";"#;
        let eps = extract_endpoints(js);
        assert!(eps.contains(&"/api/users/42".to_string()));
        assert!(eps.iter().any(|e| e.contains("api.example.com")));
    }

    #[test]
    fn secrets_detection() {
        let js = "const key = 'AKIAIOSFODNN7EXAMPLE';";
        let s = detect_secrets(js);
        assert!(s.iter().any(|x| x.kind == "aws_access_key"));
    }

    #[test]
    fn resolve_relative() {
        assert_eq!(
            resolve_url("/x.js", "https://a.com/p/q"),
            "https://a.com/x.js"
        );
        assert_eq!(
            resolve_url("//cdn.com/x", "https://a.com/"),
            "https://cdn.com/x"
        );
    }

    #[test]
    fn forms_extraction() {
        let html = r#"<form action="/login" method="POST"><input name="user" type="text"><input name="pass" type="password"></form>"#;
        let forms = extract_forms(html);
        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0].method, "POST");
        assert_eq!(forms[0].inputs.len(), 2);
    }
}