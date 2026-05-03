use anyhow::Result;
use rustls::server::Acceptor;
use std::io::Cursor;

/// Result of attempting to extract SNI from a buffer.
pub enum SniResult {
    /// Found an SNI hostname in the ClientHello.
    Hostname(String),
    /// ClientHello was valid but contained no SNI extension.
    NoSni,
    /// Buffer does not yet contain a complete ClientHello.
    Incomplete,
}

/// Attempt to extract the SNI hostname from a TLS ClientHello in `buf`.
///
/// Returns `SniResult::Incomplete` if the buffer doesn't contain a full
/// ClientHello yet, allowing the caller to read more bytes and retry.
pub fn extract_sni(buf: &[u8]) -> Result<SniResult> {
    let mut acceptor = Acceptor::default();
    let mut cursor = Cursor::new(buf);
    acceptor.read_tls(&mut cursor)?;
    match acceptor.accept() {
        Ok(Some(accepted)) => match accepted.client_hello().server_name() {
            Some(name) => Ok(SniResult::Hostname(name.to_string())),
            None => Ok(SniResult::NoSni),
        },
        Ok(None) => Ok(SniResult::Incomplete),
        Err((e, _)) => Err(e.into()),
    }
}
