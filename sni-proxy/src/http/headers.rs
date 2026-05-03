//! Header-block manipulation: insert/replace, validation, scanners.

use anyhow::{bail, Context, Result};

/// Set a header on a raw HTTP head-bytes buffer.
///
/// The buffer must end with `\r\n\r\n` (head terminator). Any existing
/// header with the same name (case-insensitive) is removed; the new
/// header is inserted just before the terminating blank line.
///
/// Returns an error if the buffer does not contain `\r\n\r\n`, or if
/// `name`/`value` contain bytes that would let an attacker forge
/// header structure (CR, LF, NUL; `:` or any non-tchar in the name).
/// Credential values flow into this from `render_inject_value` —
/// without this check, a script source emitting `\r\n` would be
/// spliced verbatim into `head_bytes` and become header smuggling.
pub fn set_header(head: &mut Vec<u8>, name: &str, value: &str) -> Result<()> {
    validate_header_name(name)?;
    validate_header_value(value)?;
    let terminator = find_headers_terminator(head)
        .context("head bytes missing terminating CRLF CRLF")?;

    let first_line_end = find_crlf(head, 0)
        .context("head bytes missing request-line CRLF")?;
    let body_start = first_line_end + 2;

    let mut cursor = body_start;
    while cursor < terminator {
        let line_end = find_crlf(head, cursor).unwrap_or(terminator);
        if header_name_matches(&head[cursor..line_end], name) {
            let drop_end = line_end + 2;
            head.drain(cursor..drop_end);
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

/// RFC 7230 token: ALPHA / DIGIT and a fixed punctuation set. We
/// also forbid empty names and the `:` separator. This is stricter
/// than necessary for security alone — CR/LF/NUL would suffice —
/// but rejecting the whole non-tchar set is defence-in-depth and
/// matches what an upstream parser will accept anyway.
fn validate_header_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("header name must not be empty");
    }
    for &b in name.as_bytes() {
        let is_tchar = b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'!' | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
            );
        if !is_tchar {
            bail!(
                "header name contains invalid byte 0x{:02x} (must be RFC 7230 tchar)",
                b
            );
        }
    }
    Ok(())
}

/// Header values: forbid CR, LF, and NUL. The first two would let
/// a credential value carrying `\r\n...` inject extra header lines
/// when spliced into `head_bytes`; NUL is rejected because some
/// upstream parsers treat it as a terminator and split the value
/// in surprising ways.
fn validate_header_value(value: &str) -> Result<()> {
    for &b in value.as_bytes() {
        if b == b'\r' || b == b'\n' || b == 0 {
            bail!(
                "header value contains forbidden byte 0x{:02x} (CR/LF/NUL would forge header structure)",
                b
            );
        }
    }
    Ok(())
}

pub(super) fn find_crlf(buf: &[u8], from: usize) -> Option<usize> {
    buf[from..]
        .windows(2)
        .position(|w| w == b"\r\n")
        .map(|i| from + i)
}

pub(super) fn find_headers_terminator(buf: &[u8]) -> Option<usize> {
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

