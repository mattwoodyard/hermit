//! Tests for `sni_proxy::block_log`. All exercised types are part
//! of the public API — no `__test_internals` wrappers needed.

use sni_proxy::block_log::{now_unix_ms, BlockEvent, BlockKind, BlockLogger};
use tempfile::NamedTempFile;
use tokio::io::AsyncReadExt;

/// Build a minimal test event of a given kind.
fn evt(kind: BlockKind) -> BlockEvent {
    BlockEvent {
        time_unix_ms: 1700000000000,
        kind,
        client: Some("127.0.0.1:1234".to_string()),
        hostname: Some("example.com".to_string()),
        method: None,
        path: None,
        port: None,
        reason: None,
    }
}

#[tokio::test]
async fn disabled_logger_is_noop() {
    // A disabled logger must accept events without error and without
    // touching the filesystem — otherwise opt-out would still cost
    // disk IO.
    let log = BlockLogger::disabled();
    log.log(evt(BlockKind::Dns));
    // No panic, no side effect: success is silence.
}

#[tokio::test]
async fn enabled_logger_writes_json_line() {
    let tmp = NamedTempFile::new().unwrap();
    let log = BlockLogger::to_file(tmp.path()).await.unwrap();
    log.log(evt(BlockKind::Dns));
    // Give the writer task a moment to flush.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let mut contents = String::new();
    tokio::fs::File::open(tmp.path())
        .await
        .unwrap()
        .read_to_string(&mut contents)
        .await
        .unwrap();

    assert!(contents.ends_with('\n'), "each event must be newline-terminated");
    let parsed: serde_json::Value =
        serde_json::from_str(contents.trim()).expect("must be valid JSON");
    assert_eq!(parsed["type"], "dns");
    assert_eq!(parsed["hostname"], "example.com");
    assert_eq!(parsed["client"], "127.0.0.1:1234");
}

#[tokio::test]
async fn multiple_events_one_per_line() {
    let tmp = NamedTempFile::new().unwrap();
    let log = BlockLogger::to_file(tmp.path()).await.unwrap();
    log.log(evt(BlockKind::Dns));
    log.log(evt(BlockKind::Https));
    log.log(evt(BlockKind::Http));
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    let contents = tokio::fs::read_to_string(tmp.path()).await.unwrap();
    let lines: Vec<&str> = contents.lines().collect();
    assert_eq!(lines.len(), 3);
    for line in &lines {
        let _: serde_json::Value = serde_json::from_str(line).unwrap();
    }
    assert!(lines[0].contains("\"type\":\"dns\""));
    assert!(lines[1].contains("\"type\":\"https\""));
    assert!(lines[2].contains("\"type\":\"http\""));
}

#[tokio::test]
async fn append_does_not_truncate_existing() {
    let tmp = NamedTempFile::new().unwrap();
    tokio::fs::write(tmp.path(), b"pre-existing\n").await.unwrap();

    let log = BlockLogger::to_file(tmp.path()).await.unwrap();
    log.log(evt(BlockKind::Dns));
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let contents = tokio::fs::read_to_string(tmp.path()).await.unwrap();
    assert!(contents.starts_with("pre-existing\n"), "existing content preserved");
    assert!(contents.lines().count() >= 2);
}

#[cfg(unix)]
#[tokio::test]
async fn open_refuses_to_follow_a_symlink() {
    // The default block-log path lives in user-writable space.
    // If an attacker can plant a symlink at that path, we don't
    // want hermit to start happily appending JSON to whatever
    // file the symlink points at. The O_NOFOLLOW open should
    // surface ELOOP rather than create the file.
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target.txt");
    tokio::fs::write(&target, b"original\n").await.unwrap();
    let link = dir.path().join("blocks.jsonl");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let result = BlockLogger::to_file(&link).await;
    let err = match result {
        Ok(_) => panic!("expected open() through symlink to fail"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("opening block log"),
        "expected open-failure context, got: {err:#}"
    );

    // The symlink target must not have been touched.
    let still = tokio::fs::read_to_string(&target).await.unwrap();
    assert_eq!(still, "original\n");
}

#[test]
fn now_ms_is_plausible() {
    // Guard against a regression where we accidentally return 0 or
    // a pre-epoch value.
    let t = now_unix_ms();
    assert!(t > 1_700_000_000_000, "clock appears to be wildly wrong: {t}");
}

#[test]
fn default_is_disabled() {
    // The `Default` impl is used when proxy configs don't explicitly
    // wire in a logger — it must be the no-op variant.
    let log = BlockLogger::default();
    log.log(evt(BlockKind::Dns));
}

#[test]
fn block_kind_wire_names_are_stable() {
    // Downstream tooling depends on these exact strings. A rename
    // here is a breaking change and must be intentional.
    let cases = [
        (BlockKind::Dns, "\"dns\""),
        (BlockKind::TlsNoSni, "\"tls_no_sni\""),
        (BlockKind::TlsHostname, "\"tls_hostname\""),
        (BlockKind::HttpNoHost, "\"http_no_host\""),
        (BlockKind::Http, "\"http\""),
        (BlockKind::Https, "\"https\""),
    ];
    for (kind, expected) in cases {
        assert_eq!(serde_json::to_string(&kind).unwrap(), expected);
    }
}

#[test]
fn missing_fields_are_omitted_from_json() {
    // `skip_serializing_if` matters: a `null` value in the log file
    // would be noise. An event with only the required fields should
    // produce a tight object.
    let evt = BlockEvent {
        time_unix_ms: 42,
        kind: BlockKind::Dns,
        client: None,
        hostname: None,
        method: None,
        path: None,
        port: None,
        reason: None,
    };
    let s = serde_json::to_string(&evt).unwrap();
    assert!(!s.contains("null"), "no null fields expected, got: {s}");
    assert!(!s.contains("client"));
    assert!(!s.contains("hostname"));
}
