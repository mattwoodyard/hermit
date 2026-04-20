//! Minimal HTTP/1.1 request parsing and forwarding.
//!
//! Uses `httparse` for zero-copy header parsing. Bodies are streamed
//! (not buffered) using Content-Length or chunked transfer encoding.

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// A parsed HTTP request line + headers.
#[derive(Debug)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub version: u8, // 0 = HTTP/1.0, 1 = HTTP/1.1
    /// Raw header bytes (request line + headers + \r\n\r\n), ready to forward.
    pub head_bytes: Vec<u8>,
    /// Content-Length if present, None otherwise.
    pub content_length: Option<u64>,
    /// Whether Transfer-Encoding: chunked is set.
    pub chunked: bool,
    /// The Host header value.
    pub host: Option<String>,
}

/// Read and parse an HTTP request from the stream.
///
/// Returns `None` if the connection was cleanly closed (EOF before any data).
/// Returns `Err` if the request is malformed or the connection drops mid-request.
pub async fn read_request<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<Request>> {
    let mut buf = Vec::with_capacity(8192);

    loop {
        let mut tmp = [0u8; 4096];
        let n = reader.read(&mut tmp).await.context("reading request")?;
        if n == 0 {
            if buf.is_empty() {
                return Ok(None); // Clean close
            }
            bail!("connection closed mid-request");
        }
        buf.extend_from_slice(&tmp[..n]);

        // Try to parse headers
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        match req.parse(&buf) {
            Ok(httparse::Status::Complete(head_len)) => {
                let method = req.method.unwrap_or("").to_string();
                let path = req.path.unwrap_or("/").to_string();
                let version = req.version.unwrap_or(1);

                let mut content_length = None;
                let mut chunked = false;
                let mut host = None;

                for h in req.headers.iter() {
                    if h.name.eq_ignore_ascii_case("content-length") {
                        let val = std::str::from_utf8(h.value)
                            .context("invalid content-length")?;
                        content_length = Some(val.trim().parse::<u64>()
                            .context("invalid content-length value")?);
                    } else if h.name.eq_ignore_ascii_case("transfer-encoding") {
                        let val = std::str::from_utf8(h.value)
                            .context("invalid transfer-encoding")?;
                        chunked = val.to_ascii_lowercase().contains("chunked");
                    } else if h.name.eq_ignore_ascii_case("host") {
                        host = Some(
                            std::str::from_utf8(h.value)
                                .context("invalid host header")?
                                .to_string(),
                        );
                    }
                }

                let head_bytes = buf[..head_len].to_vec();

                return Ok(Some(Request {
                    method,
                    path,
                    version,
                    head_bytes,
                    content_length,
                    chunked,
                    host,
                }));
            }
            Ok(httparse::Status::Partial) => {
                if buf.len() > 64 * 1024 {
                    bail!("request headers too large (>64KB)");
                }
                continue;
            }
            Err(e) => bail!("HTTP parse error: {}", e),
        }
    }
}

/// Forward exactly `len` bytes from `reader` to `writer`.
pub async fn forward_body_content_length<R, W>(
    reader: &mut R,
    writer: &mut W,
    remaining: u64,
    // Any leftover bytes from the header read buffer
    leftover: &[u8],
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut remaining = remaining;

    // First, write any leftover bytes from the header buffer
    let to_write = std::cmp::min(leftover.len() as u64, remaining) as usize;
    if to_write > 0 {
        writer.write_all(&leftover[..to_write]).await.context("writing leftover body")?;
        remaining -= to_write as u64;
    }

    // Stream the rest
    let mut buf = [0u8; 8192];
    while remaining > 0 {
        let to_read = std::cmp::min(buf.len() as u64, remaining) as usize;
        let n = reader.read(&mut buf[..to_read]).await.context("reading body")?;
        if n == 0 {
            bail!("connection closed with {} bytes remaining", remaining);
        }
        writer.write_all(&buf[..n]).await.context("writing body")?;
        remaining -= n as u64;
    }

    Ok(())
}

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

/// Read the full HTTP response headers from upstream, returning the raw
/// head bytes and parsed content-length/chunked info.
pub struct Response {
    pub head_bytes: Vec<u8>,
    pub content_length: Option<u64>,
    pub chunked: bool,
}

pub async fn read_response<R: AsyncRead + Unpin>(reader: &mut R) -> Result<(Response, Vec<u8>)> {
    let mut buf = Vec::with_capacity(8192);

    loop {
        let mut tmp = [0u8; 4096];
        let n = reader.read(&mut tmp).await.context("reading response")?;
        if n == 0 {
            if buf.is_empty() {
                bail!("upstream closed before sending response");
            }
            bail!("upstream closed mid-response headers");
        }
        buf.extend_from_slice(&tmp[..n]);

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut resp = httparse::Response::new(&mut headers);
        match resp.parse(&buf) {
            Ok(httparse::Status::Complete(head_len)) => {
                let mut content_length = None;
                let mut chunked = false;

                for h in resp.headers.iter() {
                    if h.name.eq_ignore_ascii_case("content-length") {
                        let val = std::str::from_utf8(h.value)
                            .context("invalid content-length")?;
                        content_length = Some(val.trim().parse::<u64>()
                            .context("invalid content-length value")?);
                    } else if h.name.eq_ignore_ascii_case("transfer-encoding") {
                        let val = std::str::from_utf8(h.value)
                            .context("invalid transfer-encoding")?;
                        chunked = val.to_ascii_lowercase().contains("chunked");
                    }
                }

                let head_bytes = buf[..head_len].to_vec();
                let leftover = buf[head_len..].to_vec();

                return Ok((
                    Response {
                        head_bytes,
                        content_length,
                        chunked,
                    },
                    leftover,
                ));
            }
            Ok(httparse::Status::Partial) => {
                if buf.len() > 64 * 1024 {
                    bail!("response headers too large (>64KB)");
                }
                continue;
            }
            Err(e) => bail!("HTTP response parse error: {}", e),
        }
    }
}

/// Set a header on a raw HTTP head-bytes buffer.
///
/// The buffer must end with `\r\n\r\n` (head terminator). Any existing
/// header with the same name (case-insensitive) is removed; the new
/// header is inserted just before the terminating blank line.
///
/// Returns an error if the buffer does not contain `\r\n\r\n`.
pub fn set_header(head: &mut Vec<u8>, name: &str, value: &str) -> Result<()> {
    let terminator = find_headers_terminator(head)
        .context("head bytes missing terminating CRLF CRLF")?;

    // Drop any existing header line with this name, starting after the
    // request line and ending just before the terminator.
    let first_line_end = find_crlf(head, 0)
        .context("head bytes missing request-line CRLF")?;
    let body_start = first_line_end + 2;

    let mut cursor = body_start;
    while cursor < terminator {
        let line_end = find_crlf(head, cursor).unwrap_or(terminator);
        if header_name_matches(&head[cursor..line_end], name) {
            // Remove line including its CRLF
            let drop_end = line_end + 2;
            head.drain(cursor..drop_end);
            // Restart scan (indices shifted)
            return set_header(head, name, value);
        }
        cursor = line_end + 2;
    }

    let terminator = find_headers_terminator(head)
        .context("head bytes missing terminating CRLF CRLF after edits")?;
    let line = format!("{name}: {value}\r\n");
    head.splice(terminator..terminator, line.bytes());
    Ok(())
}

fn find_crlf(buf: &[u8], from: usize) -> Option<usize> {
    buf[from..]
        .windows(2)
        .position(|w| w == b"\r\n")
        .map(|i| from + i)
}

fn find_headers_terminator(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 2)
}

fn header_name_matches(line: &[u8], name: &str) -> bool {
    let colon = match line.iter().position(|&b| b == b':') {
        Some(i) => i,
        None => return false,
    };
    let line_name = &line[..colon];
    line_name.eq_ignore_ascii_case(name.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn parse_simple_get() {
        let data = b"GET /foo HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut reader = &data[..];
        let req = read_request(&mut reader).await.unwrap().unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/foo");
        assert_eq!(req.host.as_deref(), Some("example.com"));
        assert!(req.content_length.is_none());
        assert!(!req.chunked);
    }

    #[tokio::test]
    async fn parse_post_with_content_length() {
        let data = b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello";
        let mut reader = &data[..];
        let req = read_request(&mut reader).await.unwrap().unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/upload");
        assert_eq!(req.content_length, Some(5));
    }

    #[tokio::test]
    async fn parse_eof_returns_none() {
        let data: &[u8] = b"";
        let mut reader = data;
        let req = read_request(&mut reader).await.unwrap();
        assert!(req.is_none());
    }

    #[tokio::test]
    async fn write_403_response() {
        let (mut client, mut server) = duplex(1024);
        tokio::spawn(async move {
            write_403(&mut server, "blocked by policy").await.unwrap();
        });
        let mut buf = Vec::new();
        client.read_to_end(&mut buf).await.unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.starts_with("HTTP/1.1 403"));
        assert!(s.contains("blocked by policy"));
    }

    #[test]
    fn set_header_inserts_new() {
        let mut h = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec();
        set_header(&mut h, "Authorization", "Bearer abc").unwrap();
        assert_eq!(
            std::str::from_utf8(&h).unwrap(),
            "GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer abc\r\n\r\n"
        );
    }

    #[test]
    fn set_header_replaces_existing_case_insensitive() {
        let mut h = b"GET / HTTP/1.1\r\nHost: x\r\nauthorization: old\r\n\r\n".to_vec();
        set_header(&mut h, "Authorization", "Bearer new").unwrap();
        assert_eq!(
            std::str::from_utf8(&h).unwrap(),
            "GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer new\r\n\r\n"
        );
    }

    #[test]
    fn set_header_replaces_all_duplicates() {
        let mut h =
            b"GET / HTTP/1.1\r\nHost: x\r\nCookie: a=1\r\nCookie: b=2\r\n\r\n".to_vec();
        set_header(&mut h, "Cookie", "only=this").unwrap();
        let out = std::str::from_utf8(&h).unwrap();
        assert_eq!(out.matches("Cookie:").count(), 1);
        assert!(out.contains("Cookie: only=this"));
    }

    #[test]
    fn set_header_preserves_body() {
        let mut h =
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello".to_vec();
        set_header(&mut h, "X-Injected", "yes").unwrap();
        let out = std::str::from_utf8(&h).unwrap();
        assert!(out.ends_with("\r\n\r\nhello"));
        assert!(out.contains("X-Injected: yes"));
    }

    #[test]
    fn set_header_errors_without_terminator() {
        let mut h = b"GET / HTTP/1.1\r\nHost: x\r\n".to_vec();
        assert!(set_header(&mut h, "X", "y").is_err());
    }

    #[tokio::test]
    async fn forward_content_length_body() {
        let body = b"hello";
        let (mut tx, mut rx) = duplex(1024);
        let (mut out_tx, mut out_rx) = duplex(1024);

        tokio::spawn(async move {
            tx.write_all(body).await.unwrap();
            tx.shutdown().await.unwrap();
        });

        tokio::spawn(async move {
            forward_body_content_length(&mut rx, &mut out_tx, 5, &[])
                .await
                .unwrap();
            out_tx.shutdown().await.unwrap();
        });

        let mut result = Vec::new();
        out_rx.read_to_end(&mut result).await.unwrap();
        assert_eq!(result, b"hello");
    }
}
