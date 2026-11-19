//! HTTP client setup shared by the NVR, router and Telegram clients.

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

/// Overall timeout for one request to an NVR or the router.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(25);

/// TLS client configuration. With `ca_file` only that CA is trusted, which
/// is how the router's own certificate authority is pinned. Without it the
/// bundled Mozilla roots are used (the configuration only allows that for
/// the router when it says `ca_file = public`). There is deliberately no way
/// to turn certificate verification off.
pub fn tls_config(ca_file: Option<&Path>) -> Result<Arc<rustls::ClientConfig>, String> {
    let mut roots = rustls::RootCertStore::empty();
    match ca_file {
        Some(path) => {
            let pem = std::fs::read(path)
                .map_err(|e| format!("cannot read CA file {}: {}", path.display(), e.kind()))?;
            let mut added = 0;
            for cert in CertificateDer::pem_slice_iter(&pem) {
                let cert = cert.map_err(|e| format!("bad CA file {}: {:?}", path.display(), e))?;
                roots
                    .add(cert)
                    .map_err(|e| format!("bad certificate in {}: {}", path.display(), e))?;
                added += 1;
            }
            if added == 0 {
                return Err(format!("no certificates found in {}", path.display()));
            }
        }
        None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS setup failed: {}", e))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// An agent with timeouts and with redirects disabled, so credentials are
/// never replayed to a host the configuration did not name. `overall`
/// bounds one whole request, so a peer that accepts the connection and then
/// stalls cannot hold up the poll loop for longer than that.
pub fn agent(url: &str, ca_file: Option<&Path>, overall: Duration) -> Result<ureq::Agent, String> {
    let mut builder = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10).min(overall))
        .timeout(overall)
        .redirects(0)
        .max_idle_connections(2)
        .user_agent(concat!("hik-f2b/", env!("CARGO_PKG_VERSION")));
    if url.starts_with("https://") {
        builder = builder.tls_config(tls_config(ca_file)?);
    }
    Ok(builder.build())
}

/// Reads a response body, refusing anything larger than `limit` bytes.
/// Invalid UTF-8 is replaced rather than rejected: NVR logs carry text an
/// attacker typed, and one odd byte must not make the whole reply (and so
/// every later poll of the same log window) unusable.
pub fn read_body(resp: ureq::Response, limit: u64) -> Result<String, String> {
    let mut buf = Vec::new();
    resp.into_reader()
        .take(limit + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("reading response failed: {}", e.kind()))?;
    if buf.len() as u64 > limit {
        return Err("response is too large".to_string());
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}
