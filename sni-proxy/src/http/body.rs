//! Streaming body forwarders shared by the request and response paths.
//!
//! Each forwarder copies through a fixed-size scratch buffer so a single
//! large chunk or content-length body never has to be held in memory.

use anyhow::{bail, Context, Result};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use super::headers::find_crlf;

/// Maximum time a single read on an active body/header transfer may stall.
/// Bounds Slowloris-style drip attacks on both request and response paths.
pub const IO_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Read into `buf` with an idle timeout. Returns `Err` if no byte arrives
/// within [`IO_IDLE_TIMEOUT`].
pub(super) async fn read_with_idle_timeout<R: AsyncRead + Unpin>(
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
    let mut buf: Vec<u8> = leftover.to_vec();
    let mut consumed = 0usize;

    loop {
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

        let hdr_end = size_line_end + 2;
        writer.write_all(&buf[consumed..hdr_end]).await.context("writing chunk header")?;
        consumed = hdr_end;

        if size == 0 {
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

/// Forward exactly `remaining` bytes from `reader` to `writer`.
pub async fn forward_body_content_length<R, W>(
    reader: &mut R,
    writer: &mut W,
    remaining: u64,
    leftover: &[u8],
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut remaining = remaining;

    let to_write = std::cmp::min(leftover.len() as u64, remaining) as usize;
    if to_write > 0 {
        writer.write_all(&leftover[..to_write]).await.context("writing leftover body")?;
        remaining -= to_write as u64;
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

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
    async fn forward_until_eof_caps_runaway_response() {
        let (mut tx, mut rx) = duplex(1024);
        let (mut out_tx, _out_rx) = duplex(1024);

        tokio::spawn(async move {
            let _ = tx.write_all(&[b'a'; 64]).await;
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
