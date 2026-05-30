//! Centralised timeout constants shared across listeners and engines.
//!
//! These values were duplicated across `proxy.rs`, `dispatch.rs`,
//! `forward.rs`, `mitm.rs`, and `bypass_tcp.rs` before this module
//! existed. Drift would mean a slow-upstream hardening could be
//! tightened in one file and silently skipped in another. Anything
//! a listener or engine waits on that's NOT specific to one engine
//! belongs here.
//!
//! Engine-internal timers (e.g. `splice::SPLICE_IDLE_TIMEOUT`,
//! `splice::REPLAY_WRITE_TIMEOUT`, `http::IO_IDLE_TIMEOUT`) stay
//! with their engine — they're not shared.

use std::time::Duration;

/// Max time to wait for the TLS ClientHello from the client.
/// A client that opens a socket and never sends must not park a
/// tokio task forever; the SNI peek has to complete inside this
/// window or the connection is dropped.
pub const CLIENT_HELLO_TIMEOUT: Duration = Duration::from_secs(15);

/// Max time for the upstream TCP connect. Bounds the case where
/// the upstream's network is reachable but the host or service
/// is not (e.g. SYN drops, half-open). All listeners and bypass
/// relays use this.
pub const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Max time to wait for a single HTTP request/response head from
/// the wire. Used by the forward listener while reading the
/// client's CONNECT/GET line + headers, and by the MITM engine
/// while reading the upstream response head. Slow-loris guard.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Max time for the upstream TLS handshake on the MITM engine's
/// upstream half. The MITM engine has to TLS-connect the upstream
/// after the upstream TCP-connect succeeds; if the upstream's TLS
/// stack accepts but never completes (a known DoS shape against
/// some servers), this trips before the rest of the request can
/// be parked behind it.
pub const UPSTREAM_TLS_TIMEOUT: Duration = Duration::from_secs(15);

/// Max idle window on a bypass-tcp splice. If neither direction
/// has moved a byte for this long, the relay aborts the splice
/// instead of holding the connection open forever. Bounds the
/// "well-behaved silent peer" case where `copy_bidirectional`
/// would otherwise wait indefinitely. Generous default (10 min)
/// so legitimately idle SSH / persistent LDAP doesn't trip.
pub const BYPASS_TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(600);
