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
) -> Result<i32> {
    if command.is_empty() {
        bail!("no command specified");
    }

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

    let net = sandbox_cfg.net.to_cli();
    let access_rules = config.access_rules()?;

    match net {
        NetMode::Host => {
            if !access_rules.is_empty() {
                info!(
                    "net=host: ignoring {} access_rule entries (only meaningful in net=isolate)",
                    access_rules.len()
                );
            }
            run_sandboxed_direct(home_path, project_dir, &passthrough, &home_files, &rw_paths, command)
        }
        NetMode::Isolate if !access_rules.is_empty() => {
            info!(
                "using proxied sandbox with network isolation ({} rules, {} extra port_forwards)",
                access_rules.len(),
                config.port_forwards.len()
            );
            let policy = Arc::new(RuleSet::new(access_rules));
            let network_policy = config.network_policy()?.map(Arc::new);
            let port_forwards: Vec<PortForwardSpec> = config.port_forwards.clone();
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
            )
        }
        NetMode::Isolate => {
            info!("using forked sandbox with full network isolation");
            process::run_forked(
                home_path, project_dir, &passthrough, &home_files, &rw_paths, command, &net,
            )
        }
    }
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
        let result = run_sandboxed(Path::new("/tmp"), &[], &config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no command specified"));
    }

    #[test]
    fn test_empty_command_fails_net_isolate() {
        let config = Config::parse("[sandbox]\nnet = \"isolate\"\n").unwrap();
        let result = run_sandboxed(Path::new("/tmp"), &[], &config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no command specified"));
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
