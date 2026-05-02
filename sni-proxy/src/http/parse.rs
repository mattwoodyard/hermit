//! Request and response head parsing.
//!
//! Uses `httparse` for zero-copy header iteration. Handles both
//! origin-form (`/foo`) and absolute-form (`http://host/foo`) request
//! lines — the latter is what proxy-aware clients (HTTP_PROXY) emit.

use anyhow::{bail, Context, Result};
use tokio::io::AsyncRead;

use super::body::read_with_idle_timeout;

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
                return Ok(None);
            }
            bail!("connection closed mid-request");
        }
        buf.extend_from_slice(&tmp[..n]);

        let mut headers = [httparse::EMPTY_HEADER; 128];
        let mut req = httparse::Request::new(&mut headers);
        match req.parse(&buf) {
            Ok(httparse::Status::Complete(head_len)) => {
                let method = req.method.unwrap_or("").to_string();
                let raw_path = req.path.unwrap_or("/").to_string();
                let version = req.version.unwrap_or(1);

                // Proxy-aware clients (those honoring HTTP_PROXY) send the
                // request line in absolute-form: `GET http://host/p HTTP/1.1`.
                // RFC 7230 §5.3.2. For the rest of hermit — policy lookups,
                // upstream forwarding — we want the origin-form (`/p`) with
                // an authoritative Host header. Normalize here so downstream
                // code never has to care about the two forms. CONNECT uses
                // authority-form (`host:port`) and is left as-is.
                let (path, authority_from_uri) = if method.eq_ignore_ascii_case("CONNECT") {
                    (raw_path.clone(), None)
                } else {
                    split_absolute_form(&raw_path)
                };

                let mut content_length: Option<u64> = None;
                let mut chunked = false;
                let mut transfer_encoding_seen = false;
                let mut host = None;
                let mut has_close = false;
                let mut has_keep_alive = false;

                for h in req.headers.iter() {
                    if h.name.eq_ignore_ascii_case("content-length") {
                        let val = std::str::from_utf8(h.value)
                            .context("invalid content-length")?;
                        let parsed = val.trim().parse::<u64>()
                            .context("invalid content-length value")?;
                        // RFC 9112 §6.1: multiple Content-Length headers
                        // with non-identical values are unrecoverable —
                        // the proxy and the upstream may pick different
                        // values, opening a smuggling window.
                        if let Some(prev) = content_length {
                            if prev != parsed {
                                bail!(
                                    "request has conflicting Content-Length values \
                                     ({prev} vs {parsed})"
                                );
                            }
                        }
                        content_length = Some(parsed);
                    } else if h.name.eq_ignore_ascii_case("transfer-encoding") {
                        if transfer_encoding_seen {
                            bail!("request has multiple Transfer-Encoding headers");
                        }
                        transfer_encoding_seen = true;
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

                // RFC 7230 §3.3.3: ambiguous CL+TE framing is the classic
                // smuggling surface — reject outright.
                if chunked && content_length.is_some() {
                    bail!("request has both Content-Length and Transfer-Encoding: chunked");
                }

                let connection_close = match version {
                    0 => !has_keep_alive,
                    _ => has_close,
                };

                let (head_bytes, host) = if let Some(authority) = authority_from_uri {
                    let host = host.or_else(|| Some(authority.clone()));
                    let rewritten =
                        rewrite_absolute_form_head(&buf[..head_len], &raw_path, &path, &host)?;
                    (rewritten, host)
                } else {
                    (buf[..head_len].to_vec(), host)
                };
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

/// If `target` is an absolute-form request-URI (`http://host/path?q`),
/// return `(origin_path, Some(authority))`. Otherwise return
/// `(target.to_string(), None)`. Per RFC 7230 §5.3.2 this form is what
/// clients use when pointed at an HTTP proxy (e.g. `HTTP_PROXY` set).
///
/// Only `http://` is recognised — TLS never reaches this code path.
/// A missing path component becomes `/` so downstream matching against
/// `path_prefix = "/"` still works.
fn split_absolute_form(target: &str) -> (String, Option<String>) {
    let rest = match target.strip_prefix("http://") {
        Some(r) => r,
        None => return (target.to_string(), None),
    };
    let end = rest
        .find(|c| c == '/' || c == '?' || c == '#')
        .unwrap_or(rest.len());
    let authority = rest[..end].to_string();
    let path = if end == rest.len() {
        "/".to_string()
    } else {
        rest[end..].to_string()
    };
    (path, Some(authority))
}

/// Rebuild the head_bytes so the request line uses `new_path` instead of
/// the original absolute-form URI. The rest of the headers (including any
/// caller-provided Host) are preserved verbatim. If `host` is set and the
/// original request had no Host header, one is inserted.
fn rewrite_absolute_form_head(
    head: &[u8],
    old_target: &str,
    new_path: &str,
    host: &Option<String>,
) -> Result<Vec<u8>> {
    let line_end = head
        .windows(2)
        .position(|w| w == b"\r\n")
        .context("request has no request-line terminator")?;
    let request_line = std::str::from_utf8(&head[..line_end])
        .context("non-utf8 request line")?;
    let new_request_line = request_line.replacen(old_target, new_path, 1);

    let mut out = Vec::with_capacity(head.len() + 64);
    out.extend_from_slice(new_request_line.as_bytes());
    out.extend_from_slice(b"\r\n");

    let header_block = &head[line_end + 2..];
    let mut has_host = false;
    let mut i = 0;
    while i < header_block.len() {
        let line_end = header_block[i..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .map(|p| i + p)
            .unwrap_or(header_block.len());
        let line = &header_block[i..line_end];
        if line.len() >= 5 && line[..5].eq_ignore_ascii_case(b"host:") {
            has_host = true;
        }
        i = line_end + 2;
        if line.is_empty() {
            break;
        }
    }

    if !has_host {
        if let Some(h) = host {
            out.extend_from_slice(b"Host: ");
            out.extend_from_slice(h.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
    }
    out.extend_from_slice(header_block);
    Ok(out)
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
    if h.bytes().filter(|&b| b == b':').count() > 1 {
        return h;
    }
    match h.split_once(':') {
        Some((host, _)) => host,
        None => h,
    }
}

/// Read the full HTTP response headers from upstream, returning the raw
/// head bytes and parsed content-length/chunked info.
pub struct Response {
    pub head_bytes: Vec<u8>,
    pub content_length: Option<u64>,
    pub chunked: bool,
    /// HTTP status code (e.g. 200, 401, 500). Used by callers
    /// that act on auth failures — see `CredentialResolver::invalidate`
    /// in `mitm::run` for the 401-triggered cache invalidation.
    pub status: u16,
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
                let mut content_length: Option<u64> = None;
                let mut chunked = false;
                let mut transfer_encoding_seen = false;

                for h in resp.headers.iter() {
                    if h.name.eq_ignore_ascii_case("content-length") {
                        let val = std::str::from_utf8(h.value)
                            .context("invalid content-length")?;
                        let parsed = val.trim().parse::<u64>()
                            .context("invalid content-length value")?;
                        if let Some(prev) = content_length {
                            if prev != parsed {
                                bail!(
                                    "response has conflicting Content-Length values \
                                     ({prev} vs {parsed})"
                                );
                            }
                        }
                        content_length = Some(parsed);
                    } else if h.name.eq_ignore_ascii_case("transfer-encoding") {
                        if transfer_encoding_seen {
                            bail!("response has multiple Transfer-Encoding headers");
                        }
                        transfer_encoding_seen = true;
                        let val = std::str::from_utf8(h.value)
                            .context("invalid transfer-encoding")?;
                        chunked = val.to_ascii_lowercase().contains("chunked");
                    }
                }

                let head_bytes = buf[..head_len].to_vec();
                let leftover = buf[head_len..].to_vec();
                let status = resp.code.unwrap_or(0);

                return Ok((
                    Response {
                        head_bytes,
                        content_length,
                        chunked,
                        status,
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

#[cfg(test)]
mod tests {
    use super::*;

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

    #[tokio::test]
    async fn parse_rejects_conflicting_content_length() {
        let data = b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 0\r\n\r\nhello";
        let mut reader = &data[..];
        let err = read_request(&mut reader).await.unwrap_err();
        assert!(
            err.to_string().contains("conflicting Content-Length"),
            "expected smuggling guard, got: {err}"
        );
    }

    #[tokio::test]
    async fn parse_accepts_identical_duplicate_content_length() {
        let data = b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello";
        let mut reader = &data[..];
        let (req, _) = read_request(&mut reader).await.unwrap().unwrap();
        assert_eq!(req.content_length, Some(5));
    }

    #[tokio::test]
    async fn parse_rejects_multiple_transfer_encoding_headers() {
        let data = b"POST /x HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n";
        let mut reader = &data[..];
        let err = read_request(&mut reader).await.unwrap_err();
        assert!(
            err.to_string().contains("multiple Transfer-Encoding"),
            "expected smuggling guard, got: {err}"
        );
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
        assert_eq!(host_without_port("::1"), "::1");
    }

    #[test]
    fn split_absolute_form_extracts_authority_and_path() {
        let (path, auth) = split_absolute_form("http://example.com/foo?q=1");
        assert_eq!(path, "/foo?q=1");
        assert_eq!(auth.as_deref(), Some("example.com"));
    }

    #[test]
    fn split_absolute_form_handles_port_in_authority() {
        let (path, auth) = split_absolute_form("http://example.com:8080/bar");
        assert_eq!(path, "/bar");
        assert_eq!(auth.as_deref(), Some("example.com:8080"));
    }

    #[test]
    fn split_absolute_form_defaults_missing_path_to_root() {
        let (path, auth) = split_absolute_form("http://example.com");
        assert_eq!(path, "/");
        assert_eq!(auth.as_deref(), Some("example.com"));
    }

    #[test]
    fn split_absolute_form_leaves_origin_form_unchanged() {
        let (path, auth) = split_absolute_form("/foo");
        assert_eq!(path, "/foo");
        assert!(auth.is_none());
    }

    #[tokio::test]
    async fn parse_absolute_form_normalizes_to_origin_form() {
        let data = b"GET http://example.com/foo HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut reader = &data[..];
        let (req, _) = read_request(&mut reader).await.unwrap().unwrap();
        assert_eq!(req.path, "/foo");
        assert_eq!(req.host.as_deref(), Some("example.com"));
        let head = std::str::from_utf8(&req.head_bytes).unwrap();
        assert!(
            head.starts_with("GET /foo HTTP/1.1\r\n"),
            "rewritten request line must be origin-form: {head:?}"
        );
    }

    #[tokio::test]
    async fn parse_absolute_form_backfills_missing_host_header() {
        let data = b"GET http://example.com/ HTTP/1.1\r\n\r\n";
        let mut reader = &data[..];
        let (req, _) = read_request(&mut reader).await.unwrap().unwrap();
        assert_eq!(req.host.as_deref(), Some("example.com"));
        let head = std::str::from_utf8(&req.head_bytes).unwrap();
        assert!(head.contains("\r\nHost: example.com\r\n"),
            "rewrite must insert Host header: {head:?}");
    }

    #[tokio::test]
    async fn parse_connect_keeps_authority_form_path() {
        let data = b"CONNECT example.com:443 HTTP/1.1\r\n\r\n";
        let mut reader = &data[..];
        let (req, _) = read_request(&mut reader).await.unwrap().unwrap();
        assert_eq!(req.method, "CONNECT");
        assert_eq!(req.path, "example.com:443");
    }

    #[tokio::test]
    async fn rejects_cl_plus_chunked_smuggling_attempt() {
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
        let data = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade, close\r\n\r\n";
        let mut reader = &data[..];
        let (req, _) = read_request(&mut reader).await.unwrap().unwrap();
        assert!(req.connection_close);
    }
}
