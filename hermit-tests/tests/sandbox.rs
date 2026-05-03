//! Tests for `hermit::sandbox`.
//!
//! Reaches into private items via `hermit::sandbox::__test_internals`
//! (only available because hermit-tests turns on the
//! `__test_internals` feature).

use hermit::config::Config;
use hermit::home_files::HomeFileDirective;
use hermit::sandbox::__test_internals::{
    build_rw_paths, drop_missing_home_files, drop_missing_passthrough, resolve_block_log,
    xdg_state_home_from,
};
use hermit::sandbox::run_sandboxed;
use std::path::{Path, PathBuf};

#[test]
fn test_empty_command_fails() {
    let config = Config::default();
    let result = run_sandboxed(Path::new("/tmp"), &[], &config, None, false, None, false);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("no command specified"));
}

#[test]
fn test_empty_command_fails_net_isolate() {
    let config = Config::parse("[sandbox]\nnet = \"isolate\"\n").unwrap();
    let result = run_sandboxed(Path::new("/tmp"), &[], &config, None, false, None, false);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("no command specified"));
}

#[test]
fn resolve_block_log_honors_override() {
    let dir = tempfile::tempdir().unwrap();
    let want = dir.path().join("sub").join("custom.jsonl");
    let got = resolve_block_log(Some(&want), false).unwrap();
    assert_eq!(got, Some(want.clone()));
    assert!(want.parent().unwrap().is_dir(),
        "override path's parent must be created if missing");
}

#[test]
fn resolve_block_log_disabled_returns_none() {
    // --no-block-log must short-circuit before any filesystem side
    // effect. We can't easily assert "no XDG dir was created"
    // without mutating env vars (racy across tests), so the
    // side-effect-free guarantee is tested at the pure layer
    // (default_block_log_path resolution) below.
    let got = resolve_block_log(None, true).unwrap();
    assert_eq!(got, None);
}

#[test]
fn xdg_state_home_respects_absolute_override() {
    use std::ffi::OsStr;
    let got = xdg_state_home_from(
        Some(OsStr::new("/var/lib/state")),
        Some(OsStr::new("/home/someone")),
    );
    assert_eq!(got, PathBuf::from("/var/lib/state"));
}

#[test]
fn xdg_state_home_ignores_relative_override() {
    use std::ffi::OsStr;
    // The XDG spec says relative XDG_STATE_HOME values must be
    // ignored — otherwise a malicious or confused env would land
    // the block log in CWD.
    let got = xdg_state_home_from(
        Some(OsStr::new("relative/path")),
        Some(OsStr::new("/home/someone")),
    );
    assert_eq!(got, PathBuf::from("/home/someone/.local/state"));
}

#[test]
fn xdg_state_home_falls_back_to_home() {
    use std::ffi::OsStr;
    let got = xdg_state_home_from(None, Some(OsStr::new("/home/someone")));
    assert_eq!(got, PathBuf::from("/home/someone/.local/state"));
}

#[test]
fn xdg_state_home_missing_home_uses_root_default() {
    // Matches the `HOME` fallback used elsewhere in hermit
    // (see run_sandboxed's `unwrap_or_else(|| "/root")`).
    let got = xdg_state_home_from(None, None);
    assert_eq!(got, PathBuf::from("/root/.local/state"));
}

#[test]
fn test_build_rw_paths_includes_defaults() {
    let home = Path::new("/home/test");
    let project = Path::new("/tmp/project");
    let paths = build_rw_paths(home, project, &[], &[]);
    assert!(paths.contains(&Path::new("/tmp")));
    assert!(paths.contains(&home));
    assert!(paths.contains(&project));
    assert!(paths.contains(&Path::new("/dev/null")));
}

#[test]
fn test_build_rw_paths_includes_passthrough() {
    let home = Path::new("/home/test");
    let project = Path::new("/tmp/project");
    let extra = vec![PathBuf::from("/opt/extra")];
    let paths = build_rw_paths(home, project, &extra, &[]);
    assert!(paths.contains(&extra[0].as_path()));
}

#[test]
fn drop_missing_home_files_keeps_existing_drops_absent() {
    let dir = tempfile::tempdir().unwrap();
    let existing = dir.path().join("exists.txt");
    std::fs::write(&existing, "").unwrap();
    let absent = dir.path().join("nope.txt");

    let input = vec![
        HomeFileDirective::Copy(existing.clone()),
        HomeFileDirective::Pass(absent.clone()),
        HomeFileDirective::Read(existing.clone()),
    ];
    let kept = drop_missing_home_files(input);
    assert_eq!(kept.len(), 2);
    assert!(matches!(kept[0], HomeFileDirective::Copy(_)));
    assert!(matches!(kept[1], HomeFileDirective::Read(_)));
}

#[test]
fn drop_missing_home_files_keeps_broken_symlink() {
    // A dangling symlink still "exists" at the directive level — the
    // user asked for that path and the sandbox layer will handle it.
    // We only filter when there's no entry at all.
    let dir = tempfile::tempdir().unwrap();
    let link = dir.path().join("dangling");
    std::os::unix::fs::symlink("/nonexistent-target-for-hermit-test", &link).unwrap();
    let kept = drop_missing_home_files(vec![HomeFileDirective::Pass(link.clone())]);
    assert_eq!(kept.len(), 1);
}

#[test]
fn drop_missing_passthrough_keeps_existing_drops_absent() {
    let dir = tempfile::tempdir().unwrap();
    let existing = dir.path().to_path_buf();
    let absent = dir.path().join("nope");
    let kept = drop_missing_passthrough(vec![existing.clone(), absent]);
    assert_eq!(kept, vec![existing]);
}

#[test]
fn test_build_rw_paths_includes_pass_directives() {
    let home = Path::new("/home/test");
    let project = Path::new("/tmp/project");
    let home_files = vec![
        HomeFileDirective::Pass(PathBuf::from("/opt/data")),
        HomeFileDirective::Copy(PathBuf::from("/home/test/.bashrc")),
        HomeFileDirective::Read(PathBuf::from("/home/test/.config")),
    ];
    let paths = build_rw_paths(home, project, &[], &home_files);
    // Pass directives should be included
    assert!(paths.contains(&Path::new("/opt/data")));
    // Copy and Read directives should not grant rw
    assert!(!paths.contains(&Path::new("/home/test/.bashrc")));
    assert!(!paths.contains(&Path::new("/home/test/.config")));
}
