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

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::ClientConnection;
    use std::sync::Arc;

    fn make_client_hello(server_name: &str) -> Vec<u8> {
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let name: rustls::pki_types::ServerName<'static> =
            server_name.to_string().try_into().unwrap();
        let mut conn = ClientConnection::new(Arc::new(config), name).unwrap();
        let mut buf = Vec::new();
        conn.write_tls(&mut buf).unwrap();
        buf
    }

    #[test]
    fn extracts_sni_from_valid_client_hello() {
        let buf = make_client_hello("example.com");
        match extract_sni(&buf).unwrap() {
            SniResult::Hostname(name) => assert_eq!(name, "example.com"),
            other => panic!("expected Hostname, got {:?}", variant_name(&other)),
        }
    }

    #[test]
    fn incomplete_buffer_returns_incomplete() {
        let buf = make_client_hello("example.com");
        // Truncate to half — should be incomplete
        let partial = &buf[..buf.len() / 2];
        match extract_sni(partial).unwrap() {
            SniResult::Incomplete => {}
            other => panic!("expected Incomplete, got {:?}", variant_name(&other)),
        }
    }

    #[test]
    fn garbage_bytes_returns_error() {
        assert!(extract_sni(b"this is not TLS at all").is_err());
    }

    #[test]
    fn empty_buffer_returns_incomplete() {
        match extract_sni(b"").unwrap() {
            SniResult::Incomplete => {}
            other => panic!("expected Incomplete, got {:?}", variant_name(&other)),
        }
    }

    fn variant_name(r: &SniResult) -> &'static str {
        match r {
            SniResult::Hostname(_) => "Hostname",
            SniResult::NoSni => "NoSni",
            SniResult::Incomplete => "Incomplete",
        }
    }
}
