//! Minimal HTTP/1.1 request parsing and forwarding.
//!
//! Uses `httparse` for zero-copy header parsing. Bodies are streamed
//! (not buffered) using Content-Length or chunked transfer encoding.

use anyhow::{bail, Context, Result};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

/// Maximum time a single read on an active body/header transfer may stall.
/// Bounds Slowloris-style drip attacks on both request and response paths.
pub const IO_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

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
    /// Whether this connection should be closed after the response.
    /// Derived from the Connection header plus HTTP version default
    /// (1.0 closes unless Keep-Alive; 1.1 keeps unless Close).
    pub connection_close: bool,
}

/// Read and parse an HTTP request from the stream.
///
/// Returns `None` if the connection was cleanly closed (EOF before any data).
/// Returns `Err` if the request is malformed or the connection drops mid-request.
///
/// On success returns the parsed [`Request`] alongside any *body* bytes that
/// arrived in the same read as the headers — the caller MUST forward those
/// before draining the rest of the body, otherwise small POST bodies that
/// fit in the same TCP segment as the headers are silently lost.
pub async fn read_request<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<(Request, Vec<u8>)>> {
    let mut buf = Vec::with_capacity(8192);

    loop {
        let mut tmp = [0u8; 4096];
        let n = read_with_idle_timeout(reader, &mut tmp)
            .await
            .context("reading request")?;
        if n == 0 {
            if buf.is_empty() {
                return Ok(None); // Clean close
            }
            bail!("connection closed mid-request");
        }
        buf.extend_from_slice(&tmp[..n]);

        // Try to parse headers
        let mut headers = [httparse::EMPTY_HEADER; 128];
        let mut req = httparse::Request::new(&mut headers);
        match req.parse(&buf) {
            Ok(httparse::Status::Complete(head_len)) => {
                let method = req.method.unwrap_or("").to_string();
                let path = req.path.unwrap_or("/").to_string();
                let version = req.version.unwrap_or(1);

                let mut content_length = None;
                let mut chunked = false;
                let mut host = None;
                let mut has_close = false;
                let mut has_keep_alive = false;

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
                    } else if h.name.eq_ignore_ascii_case("connection") {
                        if let Ok(val) = std::str::from_utf8(h.value) {
                            for token in val.split(',') {
                                let t = token.trim();
                                if t.eq_ignore_ascii_case("close") {
                                    has_close = true;
                                } else if t.eq_ignore_ascii_case("keep-alive") {
                                    has_keep_alive = true;
                                }
                            }
                        }
                    }
                }

                // RFC 7230 §3.3.3: if both CL and TE:chunked are present the
                // message is ambiguous and MUST be treated as an error — this
                // is the classic request-smuggling surface.
                if chunked && content_length.is_some() {
                    bail!("request has both Content-Length and Transfer-Encoding: chunked");
                }

                // HTTP/1.0 closes by default unless explicit Keep-Alive.
                // HTTP/1.1 keeps alive by default unless explicit Close.
                let connection_close = match version {
                    0 => !has_keep_alive,
                    _ => has_close,
                };

                let head_bytes = buf[..head_len].to_vec();
                let leftover = buf[head_len..].to_vec();

                return Ok(Some((
                    Request {
                        method,
                        path,
                        version,
                        head_bytes,
                        content_length,
                        chunked,
                        host,
                        connection_close,
                    },
                    leftover,
                )));
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

/// Extract the host portion of a `Host:`-header value, dropping any `:port`
/// suffix. Handles bracketed IPv6 literals (`[::1]:8080` → `[::1]`). The
/// returned slice keeps the brackets so it remains a valid URL authority.
pub fn host_without_port(h: &str) -> &str {
    if let Some(stripped) = h.strip_prefix('[') {
        if let Some(end) = stripped.find(']') {
            return &h[..=end + 1];
        }
        return h;
    }
    // A bare IPv6 literal (e.g. "::1") has multiple colons — never split it.
    // Malformed input per RFC 3986 (should be bracketed), but we'd rather
    // pass it through intact than mangle it into the empty string.
    if h.bytes().filter(|&b| b == b':').count() > 1 {
        return h;
    }
    match h.split_once(':') {
        Some((host, _)) => host,
        None => h,
    }
}

/// Read into `buf` with an idle timeout. Returns `Err` if no byte arrives
/// within [`IO_IDLE_TIMEOUT`].
async fn read_with_idle_timeout<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
) -> Result<usize> {
    match timeout(IO_IDLE_TIMEOUT, reader.read(buf)).await {
        Ok(r) => Ok(r?),
        Err(_) => bail!("idle timeout after {}s", IO_IDLE_TIMEOUT.as_secs()),
    }
}

/// Forward a chunked-encoded body from `reader` to `writer`, stopping after
/// the terminating zero-length chunk and its (possibly-empty) trailer.
///
/// `leftover` is any bytes already buffered after the headers — they are
/// interpreted as the start of the chunked body.
///
/// Payload bytes are streamed through a fixed-size scratch buffer so a
/// single large chunk does not force the whole chunk into memory.
pub async fn forward_chunked_body<R, W>(
    reader: &mut R,
    writer: &mut W,
    leftover: &[u8],
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // `buf` holds unconsumed bytes from reads that overshot the current
    // boundary (chunk header, payload tail, trailer). It is compacted
    // between chunks so it never grows larger than the largest header
    // line we accept.
    let mut buf: Vec<u8> = leftover.to_vec();
    let mut consumed = 0usize;

    loop {
        // Parse chunk size line from buf[consumed..].
        let size_line_end = loop {
            if let Some(pos) = find_crlf(&buf, consumed) {
                break pos;
            }
            if buf.len() - consumed > 64 * 1024 {
                bail!("chunk size line too long");
            }
            read_more(reader, &mut buf).await?;
        };

        let size_line = std::str::from_utf8(&buf[consumed..size_line_end])
            .context("invalid chunk size encoding")?;
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size = u64::from_str_radix(size_hex, 16)
            .with_context(|| format!("invalid chunk size: {size_line:?}"))?;

        // Forward chunk size line + CRLF verbatim.
        let hdr_end = size_line_end + 2;
        writer.write_all(&buf[consumed..hdr_end]).await.context("writing chunk header")?;
        consumed = hdr_end;

        if size == 0 {
            // Last-chunk: read trailers (lines until a bare CRLF) and forward.
            loop {
                let line_end = loop {
                    if let Some(pos) = find_crlf(&buf, consumed) {
                        break pos;
                    }
                    if buf.len() - consumed > 64 * 1024 {
                        bail!("trailer line too long");
                    }
                    read_more(reader, &mut buf).await?;
                };
                let line_total = line_end + 2;
                writer.write_all(&buf[consumed..line_total]).await.context("writing trailer")?;
                let was_empty = line_end == consumed;
                consumed = line_total;
                if was_empty {
                    return Ok(());
                }
            }
        }

        // Stream `size` payload bytes. First drain whatever's already in
        // buf (bounded by size so we don't eat into the trailing CRLF),
        // then copy the rest directly reader → writer without buffering.
        let mut remaining = size;
        let avail = (buf.len() - consumed) as u64;
        let from_buf = std::cmp::min(avail, remaining) as usize;
        if from_buf > 0 {
            writer
                .write_all(&buf[consumed..consumed + from_buf])
                .await
                .context("writing chunk body from buffer")?;
            consumed += from_buf;
            remaining -= from_buf as u64;
        }

        let mut scratch = [0u8; 8192];
        while remaining > 0 {
            let to_read = std::cmp::min(scratch.len() as u64, remaining) as usize;
            let n = read_with_idle_timeout(reader, &mut scratch[..to_read])
                .await
                .context("reading chunk payload")?;
            if n == 0 {
                bail!("connection closed mid-chunked-body (payload)");
            }
            writer
                .write_all(&scratch[..n])
                .await
                .context("writing chunk body")?;
            remaining -= n as u64;
        }

        // Consume the trailing CRLF after the payload.
        while buf.len() - consumed < 2 {
            read_more(reader, &mut buf).await?;
        }
        if &buf[consumed..consumed + 2] != b"\r\n" {
            bail!("chunk not terminated by CRLF");
        }
        writer
            .write_all(b"\r\n")
            .await
            .context("writing chunk CRLF")?;
        consumed += 2;

        // Compact: drop already-consumed bytes so `buf` doesn't grow
        // unboundedly over a long-lived stream of small chunks.
        if consumed > 0 {
            buf.drain(..consumed);
            consumed = 0;
        }
    }
}

async fn read_more<R: AsyncRead + Unpin>(reader: &mut R, buf: &mut Vec<u8>) -> Result<()> {
    let mut tmp = [0u8; 8192];
    let n = read_with_idle_timeout(reader, &mut tmp)
        .await
        .context("reading chunked body")?;
    if n == 0 {
        bail!("connection closed mid-chunked-body");
    }
    buf.extend_from_slice(&tmp[..n]);
    Ok(())
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
        let n = read_with_idle_timeout(reader, &mut buf[..to_read])
            .await
            .context("reading body")?;
        if n == 0 {
            bail!("connection closed with {} bytes remaining", remaining);
        }
        writer.write_all(&buf[..n]).await.context("writing body")?;
        remaining -= n as u64;
    }

    Ok(())
}

/// Forward bytes from `reader` to `writer` until EOF, bounded by
/// [`IO_IDLE_TIMEOUT`] per read and a hard `max_bytes` ceiling. Used for
/// HTTP responses that don't advertise a length or chunked framing — they
/// terminate only on connection close, so we need an independent bound.
pub async fn forward_until_eof<R, W>(
    reader: &mut R,
    writer: &mut W,
    leftover: &[u8],
    max_bytes: u64,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut forwarded: u64 = 0;

    if !leftover.is_empty() {
        if leftover.len() as u64 > max_bytes {
            bail!("response body exceeded {} bytes", max_bytes);
        }
        writer
            .write_all(leftover)
            .await
            .context("writing leftover body")?;
        forwarded = leftover.len() as u64;
    }

    let mut buf = [0u8; 8192];
    loop {
        let n = read_with_idle_timeout(reader, &mut buf)
            .await
            .context("reading close-delimited body")?;
        if n == 0 {
            return Ok(());
        }
        forwarded = forwarded
            .checked_add(n as u64)
            .ok_or_else(|| anyhow::anyhow!("response body length overflow"))?;
        if forwarded > max_bytes {
            bail!("response body exceeded {} bytes", max_bytes);
        }
        writer.write_all(&buf[..n]).await.context("writing body")?;
    }
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
        let n = read_with_idle_timeout(reader, &mut tmp)
            .await
            .context("reading response")?;
        if n == 0 {
            if buf.is_empty() {
                bail!("upstream closed before sending response");
            }
            bail!("upstream closed mid-response headers");
        }
        buf.extend_from_slice(&tmp[..n]);

        let mut headers = [httparse::EMPTY_HEADER; 128];
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
        let (req, leftover) = read_request(&mut reader).await.unwrap().unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/foo");
        assert_eq!(req.host.as_deref(), Some("example.com"));
        assert!(req.content_length.is_none());
        assert!(!req.chunked);
        assert!(leftover.is_empty());
    }

    #[tokio::test]
    async fn parse_post_with_content_length() {
        let data = b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello";
        let mut reader = &data[..];
        let (req, leftover) = read_request(&mut reader).await.unwrap().unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/upload");
        assert_eq!(req.content_length, Some(5));
        assert_eq!(leftover, b"hello");
    }

    #[tokio::test]
    async fn parse_eof_returns_none() {
        let data: &[u8] = b"";
        let mut reader = data;
        let req = read_request(&mut reader).await.unwrap();
        assert!(req.is_none());
    }

    #[test]
    fn host_without_port_plain() {
        assert_eq!(host_without_port("example.com"), "example.com");
        assert_eq!(host_without_port("example.com:8080"), "example.com");
    }

    #[test]
    fn host_without_port_ipv6() {
        assert_eq!(host_without_port("[::1]"), "[::1]");
        assert_eq!(host_without_port("[::1]:8080"), "[::1]");
        assert_eq!(host_without_port("[2001:db8::1]:443"), "[2001:db8::1]");
    }

    #[test]
    fn host_without_port_bare_ipv6_kept_intact() {
        // Bare IPv6 in Host is malformed, but we shouldn't mangle it by
        // splitting at the first colon.
        assert_eq!(host_without_port("::1"), "::1");
    }

    #[tokio::test]
    async fn forward_chunked_simple() {
        let body = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let (mut reader, mut writer) = duplex(1024);
        let (mut out_tx, mut out_rx) = duplex(1024);

        tokio::spawn(async move {
            writer.write_all(body).await.unwrap();
            writer.shutdown().await.unwrap();
        });

        tokio::spawn(async move {
            forward_chunked_body(&mut reader, &mut out_tx, &[])
                .await
                .unwrap();
            out_tx.shutdown().await.unwrap();
        });

        let mut result = Vec::new();
        out_rx.read_to_end(&mut result).await.unwrap();
        assert_eq!(result, body);
    }

    #[tokio::test]
    async fn forward_chunked_with_leftover() {
        // Client already buffered the full body — no more reads required.
        let body = b"3\r\nfoo\r\n0\r\n\r\n";
        let (mut reader, _writer) = duplex(64);
        let (mut out_tx, mut out_rx) = duplex(1024);

        tokio::spawn(async move {
            forward_chunked_body(&mut reader, &mut out_tx, body)
                .await
                .unwrap();
            out_tx.shutdown().await.unwrap();
        });

        let mut result = Vec::new();
        out_rx.read_to_end(&mut result).await.unwrap();
        assert_eq!(result, body);
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

    #[tokio::test]
    async fn rejects_cl_plus_chunked_smuggling_attempt() {
        // RFC 7230 §3.3.3: ambiguous framing must be rejected.
        let data =
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut reader = &data[..];
        let err = read_request(&mut reader).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("Content-Length") && msg.contains("chunked"), "got: {msg}");
    }

    #[tokio::test]
    async fn http11_default_keep_alive() {
        let data = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        let mut reader = &data[..];
        let (req, _) = read_request(&mut reader).await.unwrap().unwrap();
        assert!(!req.connection_close);
    }

    #[tokio::test]
    async fn http11_connection_close_honored() {
        let data = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
        let mut reader = &data[..];
        let (req, _) = read_request(&mut reader).await.unwrap().unwrap();
        assert!(req.connection_close);
    }

    #[tokio::test]
    async fn http10_default_closes() {
        let data = b"GET / HTTP/1.0\r\nHost: x\r\n\r\n";
        let mut reader = &data[..];
        let (req, _) = read_request(&mut reader).await.unwrap().unwrap();
        assert_eq!(req.version, 0);
        assert!(req.connection_close);
    }

    #[tokio::test]
    async fn http10_keep_alive_opt_in() {
        let data = b"GET / HTTP/1.0\r\nHost: x\r\nConnection: keep-alive\r\n\r\n";
        let mut reader = &data[..];
        let (req, _) = read_request(&mut reader).await.unwrap().unwrap();
        assert!(!req.connection_close);
    }

    #[tokio::test]
    async fn connection_header_multi_token() {
        // Clients sometimes stack Connection tokens, e.g. "keep-alive, Upgrade".
        let data = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade, close\r\n\r\n";
        let mut reader = &data[..];
        let (req, _) = read_request(&mut reader).await.unwrap().unwrap();
        assert!(req.connection_close);
    }

    #[tokio::test]
    async fn forward_until_eof_caps_runaway_response() {
        // An unbounded source would pin us forever; cap at 16 bytes and
        // the forwarder should abort once 16 are exceeded.
        let (mut tx, mut rx) = duplex(1024);
        let (mut out_tx, _out_rx) = duplex(1024);

        tokio::spawn(async move {
            // Write 64 bytes then hang the writer end open.
            let _ = tx.write_all(&[b'a'; 64]).await;
            // Keep tx alive so the reader doesn't see EOF.
            std::mem::forget(tx);
        });

        let err = forward_until_eof(&mut rx, &mut out_tx, &[], 16)
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("exceeded"));
    }

    #[tokio::test]
    async fn forward_until_eof_passes_short_body() {
        let (mut tx, mut rx) = duplex(1024);
        let (mut out_tx, mut out_rx) = duplex(1024);
        tokio::spawn(async move {
            tx.write_all(b"short body").await.unwrap();
            tx.shutdown().await.unwrap();
        });
        tokio::spawn(async move {
            forward_until_eof(&mut rx, &mut out_tx, b"[prefix] ", 1024)
                .await
                .unwrap();
            out_tx.shutdown().await.unwrap();
        });
        let mut got = Vec::new();
        out_rx.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"[prefix] short body");
    }

    #[tokio::test]
    async fn forward_chunked_streams_large_single_chunk() {
        // One 256KB chunk — previous implementation buffered the whole
        // thing. The forwarder should now pass bytes through in smaller
        // writes without holding the whole chunk in memory.
        let size = 256 * 1024usize;
        let mut wire: Vec<u8> = Vec::new();
        wire.extend_from_slice(format!("{size:x}\r\n").as_bytes());
        wire.extend(std::iter::repeat_n(b'x', size));
        wire.extend_from_slice(b"\r\n0\r\n\r\n");

        let (mut tx, mut rx) = duplex(64 * 1024);
        let (mut out_tx, mut out_rx) = duplex(64 * 1024);

        let wire_clone = wire.clone();
        tokio::spawn(async move {
            tx.write_all(&wire_clone).await.unwrap();
            tx.shutdown().await.unwrap();
        });

        tokio::spawn(async move {
            forward_chunked_body(&mut rx, &mut out_tx, &[]).await.unwrap();
            out_tx.shutdown().await.unwrap();
        });

        let mut got = Vec::new();
        out_rx.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, wire);
    }
}
