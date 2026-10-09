//! # Análisis dinámico web vía CDP (Chrome DevTools Protocol)
//!
//! Controla un navegador headless (Chrome/Chromium) por WebSocket para:
//!  - renderizar SPAs (React/Vue/Angular) que el recon estático no ve
//!  - capturar TODAS las requests de red (XHR, fetch, scripts, imágenes)
//!  - extraer el DOM renderizado final (post-JS)
//!  - ejecutar JavaScript arbitrario en la página
//!  - capturar screenshots
//!
//! Requiere: un Chrome/Chromium instalado. Se lanza con --headless
//! --remote-debugging-port y se habla CDP sobre WebSocket.
//!
//! Dependencia de red: usa el crate `tungstenite` para WebSocket y
//! `serde_json` para los mensajes CDP (todos JSON-RPC).

use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub enum CdpError {
    NoBrowser(String),
    WebSocket(String),
    Timeout,
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl std::fmt::Display for CdpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CdpError::NoBrowser(m) => write!(f, "navegador no encontrado: {}", m),
            CdpError::WebSocket(m) => write!(f, "websocket: {}", m),
            CdpError::Timeout => write!(f, "timeout esperando respuesta CDP"),
            CdpError::Io(e) => write!(f, "io: {}", e),
            CdpError::Json(e) => write!(f, "json: {}", e),
        }
    }
}

pub type Result<T> = std::result::Result<T, CdpError>;

/// Una request de red capturada durante la carga.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedRequest {
    pub url: String,
    pub method: String,
    pub resource_type: String,
    pub status: Option<i64>,
}

/// Resultado del análisis dinámico.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DynamicReport {
    pub url: String,
    pub title: String,
    pub requests: Vec<CapturedRequest>,
    pub final_html_len: usize,
    pub scripts_executed: usize,
    pub console_errors: Vec<String>,
}

/// Navegador headless controlado por CDP.
pub struct HeadlessBrowser {
    child: Child,
    port: u16,
    ws: Option<tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>>,
    msg_id: u64,
    /// Eventos CDP acumulados (Network.*, Log.*) mientras se esperaban respuestas.
    pending_events: Vec<serde_json::Value>,
}

/// Busca un Chrome/Chromium en el sistema.
pub fn find_browser() -> Option<String> {
    let candidates = [
        "google-chrome",
        "google-chrome-stable",
        "chromium",
        "chromium-browser",
        "chrome",
        // macOS
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    ];
    for c in candidates {
        if which(c) {
            return Some(c.to_string());
        }
    }
    None
}

fn which(cmd: &str) -> bool {
    if cmd.starts_with('/') {
        return std::path::Path::new(cmd).exists();
    }
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(':') {
            let p = std::path::Path::new(dir).join(cmd);
            if p.exists() {
                return true;
            }
        }
    }
    false
}

impl HeadlessBrowser {
    /// Lanza el navegador headless con debugging remoto.
    pub fn launch() -> Result<Self> {
        let browser = find_browser().ok_or_else(|| {
            CdpError::NoBrowser(
                "instalá google-chrome o chromium (apt install chromium-browser)".into(),
            )
        })?;

        // puerto libre efímero
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .map_err(CdpError::Io)?;
        let port = listener.local_addr().map_err(CdpError::Io)?.port();
        drop(listener);

        let user_data_dir = std::env::temp_dir().join(format!("bitwise-cdp-{}", std::process::id()));
        let child = Command::new(&browser)
            .args([
                "--headless=new",
                "--disable-gpu",
                "--no-first-run",
                "--no-default-browser-check",
                &format!("--remote-debugging-port={}", port),
                &format!("--user-data-dir={}", user_data_dir.display()),
                "about:blank",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(CdpError::Io)?;

        let mut browser = Self {
            child,
            port,
            ws: None,
            msg_id: 0,
            pending_events: Vec::new(),
        };

        // esperar a que el endpoint HTTP de debug esté listo
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut ws_url = None;
        while Instant::now() < deadline {
            if let Ok(url) = browser.fetch_ws_url() {
                ws_url = Some(url);
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        let ws_url = ws_url.ok_or(CdpError::Timeout)?;

        browser.connect_ws(&ws_url)?;
        Ok(browser)
    }

    /// Consulta http://127.0.0.1:port/json para el webSocketDebuggerUrl.
    fn fetch_ws_url(&self) -> Result<String> {
        let resp = ureq::get(&format!("http://127.0.0.1:{}/json", self.port))
            .timeout(Duration::from_secs(2))
            .call()
            .map_err(|e| CdpError::WebSocket(e.to_string()))?;
        let mut body = String::new();
        use std::io::Read;
        resp.into_reader()
            .read_to_string(&mut body)
            .map_err(CdpError::Io)?;

        #[derive(Deserialize)]
        struct Target {
            #[serde(rename = "webSocketDebuggerUrl")]
            ws: String,
        }
        let targets: Vec<Target> = serde_json::from_str(&body).map_err(CdpError::Json)?;
        targets
            .into_iter()
            .next()
            .map(|t| t.ws)
            .ok_or(CdpError::WebSocket("sin targets".into()))
    }

    fn connect_ws(&mut self, url: &str) -> Result<()> {
        use tungstenite::connect;

        // `connect` parsea el host:puerto del URL y abre el WebSocket
        let (ws, _resp) = connect(url)
            .map_err(|e| CdpError::WebSocket(e.to_string()))?;
        self.ws = Some(ws);
        Ok(())
    }

    /// Envía un comando CDP y espera su respuesta (por id).
    fn send(&mut self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        use tungstenite::Message;
        let ws = self
            .ws
            .as_mut()
            .ok_or(CdpError::WebSocket("no conectado".into()))?;

        self.msg_id += 1;
        let id = self.msg_id;
        let msg = serde_json::json!({
            "id": id,
            "method": method,
            "params": params,
        });
        ws.write(Message::Text(msg.to_string().into()))
            .map_err(|e| CdpError::WebSocket(e.to_string()))?;

        // buffer de eventos (Network.requestWillBeSent etc.) durante la espera
        let mut events: Vec<serde_json::Value> = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if Instant::now() > deadline {
                return Err(CdpError::Timeout);
            }
            // tungstenite 0.21 no expone set_read_timeout público;
            // usamos un sleep corto entre polls para no hacer busy-loop.
            std::thread::sleep(Duration::from_millis(20));
            match ws.read() {
                Ok(Message::Text(text)) => {
                    let v: serde_json::Value =
                        serde_json::from_str(&text).map_err(CdpError::Json)?;
                    if v.get("id").and_then(|i| i.as_u64()) == Some(id) {
                        // es la respuesta — guardar eventos acumulados
                        self.pending_events.append(&mut events);
                        if let Some(err) = v.get("error") {
                            return Err(CdpError::WebSocket(err.to_string()));
                        }
                        return Ok(v.get("result").cloned().unwrap_or(serde_json::Value::Null));
                    }
                    // evento: guardarlo
                    events.push(v);
                }
                Ok(_) => {}
                Err(e) => {
                    return Err(CdpError::WebSocket(e.to_string()));
                }
            }
        }
    }

    /// Eventos acumulados mientras se esperaban respuestas.
    pub fn drain_events(&mut self) -> Vec<serde_json::Value> {
        std::mem::take(&mut self.pending_events)
    }

    /// Analiza una URL: navega, espera el render, captura red y DOM.
    pub fn analyze(&mut self, url: &str, wait_ms: u64) -> Result<DynamicReport> {
        let mut report = DynamicReport {
            url: url.to_string(),
            ..Default::default()
        };

        // habilitar Network + Page + Runtime + Log
        self.send("Network.enable", serde_json::json!({}))?;
        self.send("Page.enable", serde_json::json!({}))?;
        self.send("Runtime.enable", serde_json::json!({}))?;
        self.send("Log.enable", serde_json::json!({}))?;

        // navegar
        self.send("Page.navigate", serde_json::json!({ "url": url }))?;

        // esperar el render
        std::thread::sleep(Duration::from_millis(wait_ms.max(1000)));

        // drenar TODOS los eventos pendientes adicionales
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            match self.send_noop() {
                Ok(_) => {}
                Err(_) => break,
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        let events = self.drain_events();
        for ev in &events {
            let method = ev.get("method").and_then(|m| m.as_str()).unwrap_or("");
            let params = ev.get("params").cloned().unwrap_or(serde_json::Value::Null);
            match method {
                "Network.requestWillBeSent" => {
                    let req = params.get("request").cloned().unwrap_or_default();
                    report.requests.push(CapturedRequest {
                        url: req.get("url").and_then(|u| u.as_str()).unwrap_or("").to_string(),
                        method: req.get("method").and_then(|m| m.as_str()).unwrap_or("GET").to_string(),
                        resource_type: params
                            .get("type")
                            .and_then(|t| t.as_str())
                            .unwrap_or("Other")
                            .to_string(),
                        status: None,
                    });
                }
                "Network.responseReceived" => {
                    // matchear por requestId para llenar status
                    let rid = params.get("requestId").and_then(|r| r.as_str()).unwrap_or("");
                    let status = params
                        .get("response")
                        .and_then(|r| r.get("status"))
                        .and_then(|s| s.as_i64());
                    if let (false, Some(st)) = (rid.is_empty(), status) {
                        // buscar la request con ese id — como no guardamos el id,
                        // matchear por URL (suficiente para reporte)
                        let url = params
                            .get("response")
                            .and_then(|r| r.get("url"))
                            .and_then(|u| u.as_str())
                            .unwrap_or("");
                        for r in report.requests.iter_mut() {
                            if r.url == url && r.status.is_none() {
                                r.status = Some(st);
                                break;
                            }
                        }
                    }
                }
                "Log.entryAdded" => {
                    let entry = params.get("entry").cloned().unwrap_or_default();
                    let level = entry.get("level").and_then(|l| l.as_str()).unwrap_or("");
                    if level == "error" {
                        report
                            .console_errors
                            .push(entry.get("text").and_then(|t| t.as_str()).unwrap_or("").to_string());
                    }
                }
                _ => {}
            }
        }
        report.scripts_executed = report
            .requests
            .iter()
            .filter(|r| r.resource_type == "Script")
            .count();

        // título
        let title_res = self.send(
            "Runtime.evaluate",
            serde_json::json!({ "expression": "document.title", "returnByValue": true }),
        )?;
        report.title = title_res
            .get("result")
            .and_then(|r| r.get("value"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // HTML final (post-render)
        let html_res = self.send(
            "Runtime.evaluate",
            serde_json::json!({ "expression": "document.documentElement.outerHTML", "returnByValue": true }),
        )?;
        report.final_html_len = html_res
            .get("result")
            .and_then(|r| r.get("value"))
            .and_then(|v| v.as_str())
            .map(|s| s.len())
            .unwrap_or(0);

        // renombrar título del reporte si está vacío
        if report.title.is_empty() {
            report.title = "(sin título)".into();
        }

        Ok(report)
    }

    /// Comando vacío para drenar eventos.
    fn send_noop(&mut self) -> Result<serde_json::Value> {
        self.send("Runtime.evaluate", serde_json::json!({ "expression": "1" }))
    }

    /// Ejecuta JS arbitrario en la página actual y devuelve el resultado como string.
    pub fn evaluate(&mut self, expression: &str) -> Result<String> {
        let res = self.send(
            "Runtime.evaluate",
            serde_json::json!({ "expression": expression, "returnByValue": true }),
        )?;
        Ok(res
            .get("result")
            .and_then(|r| r.get("value"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string())
    }

    /// Captura un screenshot PNG (retorna los bytes).
    pub fn screenshot(&mut self) -> Result<Vec<u8>> {
        let res = self.send(
            "Page.captureScreenshot",
            serde_json::json!({ "format": "png" }),
        )?;
        let b64 = res
            .get("data")
            .and_then(|d| d.as_str())
            .ok_or(CdpError::WebSocket("sin data de screenshot".into()))?;
        // decodificar base64 a mano (sin depender de base64 crate)
        decode_base64(b64).ok_or_else(|| CdpError::WebSocket("base64 inválido".into()))
    }
}

impl Drop for HeadlessBrowser {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Decodificador base64 minimal (estándar, con padding).
fn decode_base64(s: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut vals = Vec::with_capacity(s.len());
    for c in s.bytes() {
        if c == b'=' || c == b'\n' || c == b'\r' {
            continue;
        }
        let idx = TABLE.iter().position(|&t| t == c)?;
        vals.push(idx as u8);
    }
    let mut out = Vec::with_capacity(vals.len() * 3 / 4);
    for chunk in vals.chunks(4) {
        match chunk.len() {
            4 => {
                out.push((chunk[0] << 2) | (chunk[1] >> 4));
                out.push((chunk[1] << 4) | (chunk[2] >> 2));
                out.push((chunk[2] << 6) | chunk[3]);
            }
            3 => {
                out.push((chunk[0] << 2) | (chunk[1] >> 4));
                out.push((chunk[1] << 4) | (chunk[2] >> 2));
            }
            2 => {
                out.push((chunk[0] << 2) | (chunk[1] >> 4));
            }
            _ => {}
        }
    }
    Some(out)
}

/// Formatea el reporte dinámico.
pub fn format_dynamic_report(r: &DynamicReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("═══ Bitwise Web Dinámico: {} ═══\n\n", r.url));
    out.push_str(&format!("  título:   {}\n", r.title));
    out.push_str(&format!("  HTML final: {} bytes (post-JS)\n", r.final_html_len));
    out.push_str(&format!("  scripts cargados: {}\n", r.scripts_executed));
    out.push_str(&format!("  requests totales: {}\n", r.requests.len()));

    // agrupar por tipo
    let mut by_type: std::collections::BTreeMap<String, usize> = Default::default();
    for req in &r.requests {
        *by_type.entry(req.resource_type.clone()).or_insert(0) += 1;
    }
    out.push_str("\n  por tipo de recurso:\n");
    for (t, n) in &by_type {
        out.push_str(&format!("    {:12} {}\n", t, n));
    }

    // listar XHR/Fetch (las APIs que el estático no ve)
    let apis: Vec<&CapturedRequest> = r
        .requests
        .iter()
        .filter(|r| r.resource_type == "XHR" || r.resource_type == "Fetch")
        .collect();
    if !apis.is_empty() {
        out.push_str(&format!("\n  endpoints dinámicos (XHR/Fetch) — invisibles al análisis estático:\n"));
        for a in apis.iter().take(50) {
            let status = a.status.map(|s| s.to_string()).unwrap_or_else(|| "...".into());
            out.push_str(&format!("    [{}] {} {}\n", status, a.method, a.url));
        }
    }

    // scripts
    let scripts: Vec<&CapturedRequest> = r
        .requests
        .iter()
        .filter(|r| r.resource_type == "Script")
        .collect();
    if !scripts.is_empty() {
        out.push_str("\n  scripts:\n");
        for s in scripts.iter().take(20) {
            out.push_str(&format!("    {}\n", s.url));
        }
    }

    if !r.console_errors.is_empty() {
        out.push_str("\n  ⚠ errores de consola:\n");
        for e in r.console_errors.iter().take(10) {
            out.push_str(&format!("    {}\n", e));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_decode_works() {
        // "Hello" → SGVsbG8=
        let decoded = decode_base64("SGVsbG8=").unwrap();
        assert_eq!(decoded, b"Hello");
    }

    #[test]
    fn base64_decode_binary() {
        // screenshot PNG header /9j/ = ff d8 ff (JPEG)
        let decoded = decode_base64("/9j/").unwrap();
        assert_eq!(decoded, vec![0xff, 0xd8, 0xff]);
    }

    #[test]
    fn base64_invalid_returns_none() {
        assert!(decode_base64("!!!").is_none());
    }

    #[test]
    fn find_browser_does_not_panic() {
        let _ = find_browser();
    }
}