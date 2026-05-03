//! Canned error responses written to the client when the proxy refuses
//! a request before forwarding upstream.

use anyhow::{Context, Result};
use tokio::io::{AsyncWrite, AsyncWriteExt};

/// Write an HTTP 403 Forbidden response.
pub async fn write_403<W: AsyncWrite + Unpin>(writer: &mut W, reason: &str) -> Result<()> {
    let body = format!("403 Forbidden: {}\r\n", reason);
    let response = format!(
        "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    writer.write_all(response.as_bytes()).await.context("writing 403 response")?;
    writer.flush().await.context("flushing 403 response")?;
    Ok(())
}

/// Write an HTTP 421 Misdirected Request response. Used by the
/// MITM engine when the inner `Host:` header doesn't match the
/// SNI hostname the TLS connection was minted for — RFC 7540 §9.1.2
/// is the closest fit for "this connection isn't authoritative for
/// the host you asked about."
pub async fn write_421<W: AsyncWrite + Unpin>(writer: &mut W, reason: &str) -> Result<()> {
    let body = format!("421 Misdirected Request: {}\r\n", reason);
    let response = format!(
        "HTTP/1.1 421 Misdirected Request\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    writer.write_all(response.as_bytes()).await.context("writing 421 response")?;
    writer.flush().await.context("flushing 421 response")?;
    Ok(())
}
