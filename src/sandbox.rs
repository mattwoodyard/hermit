use anyhow::{bail, Context, Result};
use log::{debug, info};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::cli::NetMode;
use crate::home_files::load_home_files;
use crate::landlock::apply_landlock;
use crate::namespace::setup_namespace;
use crate::process;

/// Build the read-write path list for landlock from the sandbox parameters.
fn build_rw_paths<'a>(
    home_path: &'a Path,
    project_dir: &'a Path,
    passthrough: &'a [PathBuf],
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
    rw_paths
}

/// Run a command inside the sandbox and return its exit code.
///
/// When `net` is `Isolate`, the command runs in a forked child with an empty
/// network namespace. In `Host` mode, the command runs directly in-process
/// with the host network.
pub fn run_sandboxed(
    project_dir: &Path,
    passthrough: &[PathBuf],
    command: &[String],
    net: &NetMode,
) -> Result<i32> {
    if command.is_empty() {
        bail!("no command specified");
    }

    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    let home_path = Path::new(&home);

    info!("loading home-files config");
    let home_files = load_home_files(project_dir, home_path)
        .context("failed to load home-files config")?;
    debug!("home-files entries: {}", home_files.len());

    let rw_paths = build_rw_paths(home_path, project_dir, passthrough);

    match net {
        NetMode::Host => {
            run_sandboxed_direct(home_path, project_dir, passthrough, &home_files, &rw_paths, command)
        }
        NetMode::Isolate => {
            info!("using forked sandbox with network isolation (mode: {})", net);
            process::run_forked(
                home_path, project_dir, passthrough, &home_files, &rw_paths, command, net,
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
        let result = run_sandboxed(Path::new("/tmp"), &[], &[], &NetMode::Host);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no command specified"));
    }

    #[test]
    fn test_empty_command_fails_net_isolate() {
        let result = run_sandboxed(Path::new("/tmp"), &[], &[], &NetMode::Isolate);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no command specified"));
    }

    #[test]
    fn test_build_rw_paths_includes_defaults() {
        let home = Path::new("/home/test");
        let project = Path::new("/tmp/project");
        let paths = build_rw_paths(home, project, &[]);
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
        let paths = build_rw_paths(home, project, &extra);
        assert!(paths.contains(&extra[0].as_path()));
    }
}
