//! End-to-end integration test for the MITM engine.
//!
//! Exercises the full pipeline: client TLS handshake → SNI peek →
//! hostname policy → leaf cert minted → client TLS terminates →
//! request parsed → credential injection → upstream TLS handshake
//! → request forwarded → response copied back. The TLS side is
//! real — `rustls` on both ends — so this is the test that pins
//! "the wire actually carries an injected `Authorization` header"
//! rather than just "`apply_injection` mutates `head_bytes`".
//!
//! Mechanics: two pairs of sockets are created up front. A test
//! client connects to one end of `pair_a`; the other end is fed
//! to `dispatch::https_after_tcp`, which represents what
//! `transparent::run` or `forward::handle_connect` would deliver.
//! The MITM engine then dials the test upstream through a custom
//! `UpstreamConnector` that ignores the hostname and routes to
//! the upstream's local port.
//!
//! `MitmConfig::upstream_roots` lets the test inject the test
//! CA so the MITM engine accepts the synthetic upstream chain
//! without modifying production verification.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use sni_proxy::block_log::BlockLogger;
use sni_proxy::ca::CertificateAuthority;
use sni_proxy::connector::UpstreamConnector;
use sni_proxy::dispatch::https_after_tcp;
use sni_proxy::mitm::MitmConfig;
use sni_proxy::network_policy::NetworkPolicy;
use sni_proxy::policy::{AccessRule, RuleSet};

const TEST_HOST: &str = "localhost";

fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Generate a self-signed CA + a leaf cert for `hostname`.
/// Returns the leaf chain (leaf only — no intermediates), the leaf
/// key, and a `RootCertStore` containing the CA so a TLS client
/// (or the MITM engine's upstream verifier) trusts the chain.
fn make_test_ca_and_leaf(
    hostname: &str,
) -> (Arc<RootCertStore>, Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let ca_key = KeyPair::generate().expect("ca keypair");
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "mitm e2e test CA");
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign ca");

    let leaf_key = KeyPair::generate().expect("leaf keypair");
    let mut leaf_params = CertificateParams::default();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, hostname);
    leaf_params
        .subject_alt_names
        .push(SanType::DnsName(hostname.try_into().unwrap()));
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &ca_cert, &ca_key)
        .expect("sign leaf");

    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca_cert.der().to_vec()))
        .expect("add ca to root store");

    let chain = vec![CertificateDer::from(leaf_cert.der().to_vec())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    (Arc::new(roots), chain, key)
}

/// A test connector that ignores the hostname and always dials the
/// configured local address. Lets us avoid DNS while still letting
/// the MITM engine think it's contacting `TEST_HOST`.
struct FixedConnector(SocketAddr);

impl UpstreamConnector for FixedConnector {
    fn connect(
        &self,
        _hostname: &str,
        _port: u16,
        _original_dst: Option<SocketAddr>,
    ) -> impl Future<Output = Result<TcpStream>> + Send {
        let addr = self.0;
        async move {
            TcpStream::connect(addr)
                .await
                .with_context(|| format!("FixedConnector dialing {addr}"))
        }
    }
}

/// Stand up a fake HTTPS upstream that:
///  - accepts a single TLS connection
///  - reads the request head (until `\r\n\r\n`)
///  - responds with `200` and the request head as the body
///  - closes
///
/// Returns `(addr, join_handle)`. The handle resolves to the raw
/// request head bytes the upstream observed — that's what the
/// test inspects for header injection.
async fn fake_upstream(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    response_status: u16,
) -> (SocketAddr, tokio::task::JoinHandle<Result<Vec<u8>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind upstream");
    let addr = listener.local_addr().expect("upstream addr");

    let server_config = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("upstream tls protocol versions")
    .with_no_client_auth()
    .with_single_cert(chain, key)
    .expect("upstream tls cert");
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let join = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.context("upstream accept")?;
        let mut tls = acceptor.accept(tcp).await.context("upstream tls accept")?;

        // Read request head.
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = tls.read(&mut chunk).await.context("upstream read")?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }

        // Respond with the recorded request head as the body. That
        // way the test client sees what arrived — no separate
        // out-of-band channel needed.
        let body = buf.clone();
        let status_line = match response_status {
            200 => "HTTP/1.1 200 OK",
            401 => "HTTP/1.1 401 Unauthorized",
            other => panic!("unexpected response_status in fixture: {other}"),
        };
        let response = format!(
            "{status_line}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        tls.write_all(response.as_bytes()).await.context("upstream write hdr")?;
        tls.write_all(&body).await.context("upstream write body")?;
        tls.shutdown().await.ok();
        Ok(buf)
    });

    (addr, join)
}

/// Send an HTTPS request through the MITM engine and return the
/// response body the test client received. The body is whatever
/// the upstream echoed (i.e., the request head as it arrived
/// upstream — that's what we assert on for injection).
async fn send_through_mitm(
    config: Arc<MitmConfig<RuleSet, FixedConnector>>,
    request_head: &[u8],
) -> Result<Vec<u8>> {
    install_crypto_provider();

    // The MITM engine reads from a TcpStream that the listener has
    // peeked the ClientHello off. We give it a fresh TcpStream (no
    // peek), and `dispatch::https_after_tcp` does the SNI peek
    // itself by calling `read_sni_with_buffer`.
    let pair = TcpListener::bind("127.0.0.1:0").await?;
    let pair_addr = pair.local_addr()?;
    let (accept_res, connect_res) = tokio::join!(
        pair.accept(),
        TcpStream::connect(pair_addr),
    );
    let (server_side, _) = accept_res?;
    let client_side = connect_res?;

    let mitm_done = tokio::spawn({
        let config = Arc::clone(&config);
        async move {
            let _ = https_after_tcp(server_side, pair_addr, None, &*config).await;
        }
    });

    // Build a TLS client that trusts the hermit CA used by the
    // MITM engine for its leaf certs.
    let mut client_roots = RootCertStore::empty();
    client_roots.add(config.ca.ca_cert_der().clone())?;
    let client_config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(client_roots)
    .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name: ServerName<'static> = TEST_HOST.try_into()?;

    let mut tls = connector.connect(server_name, client_side).await?;
    tls.write_all(request_head).await?;

    // rustls-on-client errors on UnexpectedEof if the peer closes
    // the TCP connection without first sending a TLS close_notify.
    // The MITM engine teardown doesn't always emit close_notify on
    // the client half (it follows the upstream's behaviour, and
    // many real upstreams cut the TCP connection directly). Treat
    // UnexpectedEof as a clean end-of-response for this test.
    let mut response = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match tls.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
    }

    mitm_done.await?;

    // Strip the response status line + headers; return the body.
    let body_start = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .ok_or_else(|| anyhow::anyhow!("no body in response"))?;
    Ok(response[body_start..].to_vec())
}

#[tokio::test]
async fn mitm_injects_authorization_header_on_wire() {
    install_crypto_provider();

    let (upstream_roots, leaf_chain, leaf_key) = make_test_ca_and_leaf(TEST_HOST);
    let (upstream_addr, upstream_handle) = fake_upstream(leaf_chain, leaf_key, 200).await;

    let np = NetworkPolicy::from_toml(&format!(
        r#"
[[rule]]
match = 'url.host == "{TEST_HOST}"'
credential = "tok"

[credential.tok]
source = {{ type = "env", name = "MITM_E2E_INJECT" }}
inject = [{{ header = "Authorization", value = "Bearer {{cred}}" }}]
"#
    ))
    .expect("build network policy");
    // SAFETY: set in single-threaded test startup.
    unsafe { std::env::set_var("MITM_E2E_INJECT", "secret-on-the-wire") };

    let policy = RuleSet::new(vec![AccessRule::host_only(TEST_HOST)]);
    let ca = Arc::new(CertificateAuthority::new().expect("hermit ca"));

    let config = Arc::new(MitmConfig {
        policy: Arc::new(policy),
        connector: Arc::new(FixedConnector(upstream_addr)),
        ca,
        upstream_port: upstream_addr.port(),
        network_policy: Some(Arc::new(np)),
        block_log: BlockLogger::disabled(),
        access_log: BlockLogger::disabled(),
        upstream_roots: Some(upstream_roots),
    });

    let request_head = format!(
        "GET / HTTP/1.1\r\nHost: {TEST_HOST}\r\nConnection: close\r\n\r\n"
    );
    let echoed_head = send_through_mitm(config, request_head.as_bytes())
        .await
        .expect("mitm round-trip");

    let upstream_received = upstream_handle
        .await
        .expect("upstream task")
        .expect("upstream result");
    let upstream_text = String::from_utf8(upstream_received).expect("utf8 head");
    let echoed_text = String::from_utf8(echoed_head).expect("utf8 body");

    assert!(
        upstream_text.contains("Authorization: Bearer secret-on-the-wire\r\n"),
        "upstream must have received the injected header on the wire:\n{upstream_text}"
    );
    assert!(
        echoed_text.contains("Authorization: Bearer secret-on-the-wire\r\n"),
        "client must have read back the injected header (via upstream echo):\n{echoed_text}"
    );
    // Sanity: the original Host header survives the rewrite.
    assert!(upstream_text.contains(&format!("Host: {TEST_HOST}\r\n")));
}

#[tokio::test]
async fn mitm_injection_does_not_run_when_no_rule_matches() {
    install_crypto_provider();

    let (upstream_roots, leaf_chain, leaf_key) = make_test_ca_and_leaf(TEST_HOST);
    let (upstream_addr, upstream_handle) = fake_upstream(leaf_chain, leaf_key, 200).await;

    // NetworkPolicy that only matches a different host — our request
    // must arrive at the upstream unchanged.
    // SAFETY: set in single-threaded test startup.
    unsafe { std::env::set_var("MITM_E2E_NEVER", "should-not-appear") };
    let np = NetworkPolicy::from_toml(
        r#"
[[rule]]
match = 'url.host == "elsewhere.example"'
credential = "tok"

[credential.tok]
source = { type = "env", name = "MITM_E2E_NEVER" }
inject = [{ header = "Authorization", value = "Bearer {cred}" }]
"#,
    )
    .expect("build network policy");

    let policy = RuleSet::new(vec![AccessRule::host_only(TEST_HOST)]);
    let ca = Arc::new(CertificateAuthority::new().expect("hermit ca"));

    let config = Arc::new(MitmConfig {
        policy: Arc::new(policy),
        connector: Arc::new(FixedConnector(upstream_addr)),
        ca,
        upstream_port: upstream_addr.port(),
        network_policy: Some(Arc::new(np)),
        block_log: BlockLogger::disabled(),
        access_log: BlockLogger::disabled(),
        upstream_roots: Some(upstream_roots),
    });

    let request_head = format!(
        "GET / HTTP/1.1\r\nHost: {TEST_HOST}\r\nUser-Agent: e2e\r\nConnection: close\r\n\r\n"
    );
    let _ = send_through_mitm(config, request_head.as_bytes())
        .await
        .expect("mitm round-trip");

    let upstream_received = upstream_handle
        .await
        .expect("upstream task")
        .expect("upstream result");
    let upstream_text = String::from_utf8(upstream_received).expect("utf8 head");

    assert!(
        !upstream_text.contains("Authorization:"),
        "no Authorization header should leak through when no rule matches:\n{upstream_text}"
    );
    assert!(
        !upstream_text.contains("should-not-appear"),
        "literal credential value must not appear when its rule didn't match:\n{upstream_text}"
    );
    // The original headers still flow.
    assert!(upstream_text.contains("User-Agent: e2e\r\n"));
}
