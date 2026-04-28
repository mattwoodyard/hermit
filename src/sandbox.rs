use anyhow::{bail, Context, Result};
use log::{debug, info, warn};
use sni_proxy::policy::RuleSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use crate::cli::NetMode;
use crate::config::{Config, PortForwardSpec};
use crate::home_files::HomeFileDirective;
use crate::landlock::apply_landlock;
use crate::namespace::setup_namespace;
use crate::process;

/// Drop `home_file` entries whose source path doesn't exist on the host.
///
/// A common failure mode before this filter: a shared config lists
/// `~/.cargo`, `~/.rustup`, `~/.ssh`, etc., but the user has never
/// installed some of those tools. Previously hermit would refuse to start;
/// now we log a warning per missing entry and continue with what exists.
fn drop_missing_home_files(home_files: Vec<HomeFileDirective>) -> Vec<HomeFileDirective> {
    home_files
        .into_iter()
        .filter(|d| {
            let path = match d {
                HomeFileDirective::Copy(p)
                | HomeFileDirective::Pass(p)
                | HomeFileDirective::Read(p) => p,
            };
            if path.symlink_metadata().is_ok() {
                true
            } else {
                warn!(
                    "home_file source {} does not exist on host; skipping",
                    path.display()
                );
                false
            }
        })
        .collect()
}

/// Drop `[sandbox].passthrough` entries whose source path doesn't exist.
///
/// Same spirit as [`drop_missing_home_files`] — paths that mean nothing on
/// this host get logged and ignored rather than blocking startup.
fn drop_missing_passthrough(passthrough: Vec<PathBuf>) -> Vec<PathBuf> {
    passthrough
        .into_iter()
        .filter(|p| {
            if p.symlink_metadata().is_ok() {
                true
            } else {
                warn!("passthrough {} does not exist on host; skipping", p.display());
                false
            }
        })
        .collect()
}

/// Build the read-write path list for landlock from the sandbox parameters.
fn build_rw_paths<'a>(
    home_path: &'a Path,
    project_dir: &'a Path,
    passthrough: &'a [PathBuf],
    home_files: &'a [HomeFileDirective],
) -> Vec<&'a Path> {
    let mut rw_paths: Vec<&Path> = vec![
        Path::new("/tmp"),
        home_path,
        project_dir,
        Path::new("/dev/null"),
    ];
    for p in passthrough {
        rw_paths.push(p.as_path());
    }
    for d in home_files {
        if let HomeFileDirective::Pass(ref p) = d {
            rw_paths.push(p.as_path());
        }
    }
    rw_paths
}

/// Run a command inside the sandbox using a verified config. Returns
/// the child's exit code.
///
/// Network mode is taken from `config.sandbox.net`:
///   * `host` — share the host network, no isolation.
///   * `isolate` with access rules — run a network namespace with the
///     hermit proxy enforcing the rules (plus optional credential
///     injection from `[[rule]]` + `[credential.*]`).
///   * `isolate` without access rules — empty network namespace, zero
///     connectivity.
pub fn run_sandboxed(
    project_dir: &Path,
    command: &[String],
    config: &Config,
    block_log_override: Option<&Path>,
    block_log_disabled: bool,
    // `hermit learn` passes the JSONL trace path here. `None` for
    // `hermit run`. The proxies' `access_log` is disabled when
    // this is None, so production runs pay nothing for it.
    access_log_path: Option<&Path>,
    // `true` for `hermit learn`. Switches the RuleSet into
    // `permit_all` so every check returns Allow — the proxies
    // observe and log without enforcing.
    permit_all: bool,
) -> Result<i32> {
    if command.is_empty() {
        bail!("no command specified");
    }

    // Distinguish "user explicitly requested a path" from "took the default".
    // The former is load-bearing: if a user passes --block-log in a mode
    // where no proxy runs, we surface that as an info line so they know
    // the flag had no effect. Taking the default is silent.
    let block_log_user_explicit = block_log_override.is_some();

    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    let home_path = Path::new(&home);

    let home_files = config.home_file_directives(home_path)?;
    let home_files = drop_missing_home_files(home_files);
    debug!("home-files entries: {}", home_files.len());
    for d in &home_files {
        debug!("  home-file: {:?}", d);
    }

    let sandbox_cfg = config.sandbox();
    let passthrough: Vec<PathBuf> = drop_missing_passthrough(sandbox_cfg.passthrough.clone());
    let rw_paths = build_rw_paths(home_path, project_dir, &passthrough, &home_files);

    // Learn mode (`permit_all`) forces `net = isolate` so the
    // proxies actually run. A user who declared `net = "host"`
    // expecting passthrough gets a warning here; without the
    // override, learn mode would silently observe nothing.
    let mut net = sandbox_cfg.net.to_cli();
    if permit_all && net != NetMode::Isolate {
        info!("learn mode: overriding net to `isolate` so the proxies can observe");
        net = NetMode::Isolate;
    }
    let access_rules = config.access_rules()?;

    match net {
        NetMode::Host => {
            if !access_rules.is_empty() {
                info!(
                    "net=host: ignoring {} access_rule entries (only meaningful in net=isolate)",
                    access_rules.len()
                );
            }
            if block_log_user_explicit {
                info!("net=host: --block-log has no effect (no proxy is running)");
            }
            run_sandboxed_direct(home_path, project_dir, &passthrough, &home_files, &rw_paths, command)
        }
        // Proxied path: triggered when there are explicit rules OR
        // when learn mode wants to observe (which has no rules of
        // its own but still needs the proxy listeners running).
        NetMode::Isolate if !access_rules.is_empty() || permit_all => {
            info!(
                "using proxied sandbox with network isolation ({} rules, {} extra port_forwards)",
                access_rules.len(),
                config.port_forwards.len()
            );
            let block_log_path =
                resolve_block_log(block_log_override, block_log_disabled)?;
            if let Some(ref p) = block_log_path {
                info!("block log: {}", p.display());
            }
            let ip_rules = config.ip_rules()?;
            // Log the effective ruleset at debug level so the user
            // can verify every rule landed in the expected bucket
            // by running hermit with `-vv`. This is also the best
            // place to notice a misordered merge through `include`.
            debug!("effective access rules ({}):", access_rules.len());
            for (i, r) in access_rules.iter().enumerate() {
                debug!("  [{i}] host={:?} mechanism={} path_prefix={:?} methods={:?}",
                    r.hostname, r.mechanism, r.path_prefix,
                    r.methods.as_ref().map(|m| m.len()));
            }
            debug!("effective ip rules ({}):", ip_rules.len());
            for (i, r) in ip_rules.iter().enumerate() {
                debug!("  [{i}] ip={} mechanism={}", r.ip, r.mechanism);
            }
            let policy = Arc::new(
                RuleSet::new(access_rules)
                    .with_ip_rules(ip_rules)
                    .with_permit_all(permit_all),
            );
            let network_policy = config.network_policy()?.map(Arc::new);
            let port_forwards: Vec<PortForwardSpec> = config.port_forwards.clone();
            let dns_upstream = config.dns().upstream_addr()?;
            process::run_forked_proxied(
                home_path,
                project_dir,
                &passthrough,
                &home_files,
                &rw_paths,
                command,
                policy,
                network_policy,
                &port_forwards,
                block_log_path.as_deref(),
                dns_upstream,
                access_log_path,
            )
        }
        NetMode::Isolate => {
            if block_log_user_explicit {
                info!(
                    "net=isolate with no access_rules: --block-log has no effect (zero-connectivity mode)"
                );
            }
            info!("using forked sandbox with full network isolation");
            process::run_forked(
                home_path, project_dir, &passthrough, &home_files, &rw_paths, command, &net,
            )
        }
    }
}

/// Resolve the final block-log path and ensure its parent directory
/// exists. Returns `None` when block logging was disabled by the user.
///
/// When `override_path` is `None` and logging isn't disabled, the path
/// defaults to `$XDG_STATE_HOME/hermit/blocks.jsonl` (falling back to
/// `$HOME/.local/state/hermit/blocks.jsonl`). The parent is created
/// with `create_dir_all` so a first-time run "just works".
fn resolve_block_log(
    override_path: Option<&Path>,
    disabled: bool,
) -> Result<Option<PathBuf>> {
    if disabled {
        return Ok(None);
    }
    let path = override_path
        .map(Path::to_path_buf)
        .unwrap_or_else(default_block_log_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating block-log directory {}", parent.display()))?;
    }
    Ok(Some(path))
}

/// XDG state directory for hermit's own default logs. Per the XDG
/// spec, `XDG_STATE_HOME` is the right bucket for "state data that
/// should persist between application restarts, but ... not important
/// or portable enough to store in $XDG_DATA_HOME"; logs are listed
/// explicitly as an example.
fn default_block_log_path() -> PathBuf {
    xdg_state_home_from(
        std::env::var_os("XDG_STATE_HOME").as_deref(),
        std::env::var_os("HOME").as_deref(),
    )
    .join("hermit")
    .join("blocks.jsonl")
}

/// Sibling of [`default_block_log_path`] for the access-trace
/// produced by `hermit learn`. Lives next to `blocks.jsonl` so an
/// operator running both `run` and `learn` finds both files in
/// one place.
pub fn default_access_log_path() -> PathBuf {
    xdg_state_home_from(
        std::env::var_os("XDG_STATE_HOME").as_deref(),
        std::env::var_os("HOME").as_deref(),
    )
    .join("hermit")
    .join("access.jsonl")
}

/// Pure resolver for `$XDG_STATE_HOME` given the two env vars it
/// depends on. Relative `XDG_STATE_HOME` values are ignored per spec;
/// missing `HOME` falls back to `/root`, matching the rest of hermit.
fn xdg_state_home_from(
    xdg_state_home: Option<&std::ffi::OsStr>,
    home: Option<&std::ffi::OsStr>,
) -> PathBuf {
    if let Some(v) = xdg_state_home {
        let p = PathBuf::from(v);
        if p.is_absolute() {
            return p;
        }
    }
    let home = home
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/root"));
    home.join(".local").join("state")
}

/// Direct (non-forked) sandbox path: namespace + landlock + exec.
fn run_sandboxed_direct(
    home_path: &Path,
    project_dir: &Path,
    passthrough: &[PathBuf],
    home_files: &[crate::home_files::HomeFileDirective],
    rw_paths: &[&Path],
    command: &[String],
) -> Result<i32> {
    info!("setting up namespace isolation");
    setup_namespace(home_path, project_dir, passthrough, home_files, false)?;

    info!("applying landlock MAC policy");
    for p in rw_paths {
        debug!("  rw: {}", p.display());
    }
    apply_landlock(rw_paths)?;

    info!("executing: {}", command.join(" "));
    let status = Command::new(&command[0])
        .args(&command[1..])
        .status()
        .with_context(|| format!("failed to execute '{}'", command[0]))?;

    let code = status.code().unwrap_or(1);
    info!("process exited with code {}", code);
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
