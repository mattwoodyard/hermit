use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

/// A directive from a `home-files` config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HomeFileDirective {
    /// Copy a file or directory from real $HOME into the sandbox (read-only snapshot).
    Copy(PathBuf),
    /// Bind-mount (passthrough) a file or directory writably into the sandbox.
    Pass(PathBuf),
    /// Bind-mount a file or directory read-only into the sandbox (live, not a snapshot).
    Read(PathBuf),
}

/// Parse a single `home-files` config file into directives.
///
/// Returns `Ok(vec![])` if `config_path` does not exist.
/// Errors on I/O failures other than NotFound, or on malformed content.
pub fn parse_home_files_from(
    config_path: &Path,
    home_dir: &Path,
) -> Result<Vec<HomeFileDirective>> {
    let content = match std::fs::read_to_string(config_path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(e)
                .with_context(|| format!("failed to read {}", config_path.display()));
        }
    };

    parse_home_files_content(&content, home_dir)
}

/// Load home-file directives using multi-source resolution.
///
/// Resolution order:
/// 1. If `HERMIT_HOME_FILES` is set → parse only that single file (error if missing).
/// 2. Otherwise → parse `{project_dir}/.hermit/home-files` (project-level) and
///    `{home_dir}/.hermit/home-files` (user-level), concatenating directives.
///    Either or both may be absent.
pub fn load_home_files(
    project_dir: &Path,
    home_dir: &Path,
) -> Result<Vec<HomeFileDirective>> {
    if let Ok(env_path) = std::env::var("HERMIT_HOME_FILES") {
        let path = PathBuf::from(&env_path);
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("HERMIT_HOME_FILES={}: failed to read", env_path))?;
        return parse_home_files_content(&content, home_dir);
    }

    let project_config = project_dir.join(".hermit/home-files");
    let user_config = home_dir.join(".hermit/home-files");

    let mut directives = parse_home_files_from(&project_config, home_dir)
        .with_context(|| "failed to parse project-level home-files")?;
    let user_directives = parse_home_files_from(&user_config, home_dir)
        .with_context(|| "failed to parse user-level home-files")?;
    directives.extend(user_directives);

    Ok(directives)
}

/// Parse the content of a home-files config string.
fn parse_home_files_content(
    content: &str,
    home_dir: &Path,
) -> Result<Vec<HomeFileDirective>> {
    let mut directives = Vec::new();

    for (line_num, raw_line) in content.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let (verb, rest) = line.split_once(char::is_whitespace).with_context(|| {
            format!(
                "line {}: expected 'copy|pass|read <path>', got: {}",
                line_num + 1,
                line
            )
        })?;
        let raw_path = rest.trim();
        if raw_path.is_empty() {
            bail!("line {}: missing path after '{}'", line_num + 1, verb);
        }

        let expanded = expand_tilde(raw_path, home_dir);
        reject_dotdot(&expanded, line_num + 1)?;

        match verb {
            "copy" => directives.push(HomeFileDirective::Copy(expanded)),
            "pass" => directives.push(HomeFileDirective::Pass(expanded)),
            "read" => directives.push(HomeFileDirective::Read(expanded)),
            other => bail!(
                "line {}: unknown directive '{}', expected 'copy', 'pass', or 'read'",
                line_num + 1,
                other
            ),
        }
    }

    Ok(directives)
}

/// Expand a leading `~` or `~/` to `home_dir`.
fn expand_tilde(raw: &str, home_dir: &Path) -> PathBuf {
    if raw == "~" {
        home_dir.to_path_buf()
    } else if let Some(rest) = raw.strip_prefix("~/") {
        home_dir.join(rest)
    } else {
        PathBuf::from(raw)
    }
}

/// Reject paths containing `..` components.
fn reject_dotdot(path: &Path, line_num: usize) -> Result<()> {
    for component in path.components() {
        if let std::path::Component::ParentDir = component {
            bail!(
                "line {}: path must not contain '..': {}",
                line_num,
                path.display()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty_content() {
        let result = parse_home_files_content("", Path::new("/home/user")).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_comments_and_blanks() {
        let content = "# this is a comment\n\n  # indented comment\n  \n";
        let result = parse_home_files_content(content, Path::new("/home/user")).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_copy_directive() {
        let content = "copy ~/.bashrc\n";
        let result = parse_home_files_content(content, Path::new("/home/user")).unwrap();
        assert_eq!(
            result,
            vec![HomeFileDirective::Copy(PathBuf::from("/home/user/.bashrc"))]
        );
    }

    #[test]
    fn test_parse_pass_directive() {
        let content = "pass ~/.config/git\n";
        let result = parse_home_files_content(content, Path::new("/home/user")).unwrap();
        assert_eq!(
            result,
            vec![HomeFileDirective::Pass(PathBuf::from(
                "/home/user/.config/git"
            ))]
        );
    }

    #[test]
    fn test_parse_read_directive() {
        let content = "read ~/.config/git\n";
        let result = parse_home_files_content(content, Path::new("/home/user")).unwrap();
        assert_eq!(
            result,
            vec![HomeFileDirective::Read(PathBuf::from(
                "/home/user/.config/git"
            ))]
        );
    }

    #[test]
    fn test_parse_multiple_directives() {
        let content = "copy ~/.bashrc\npass ~/.ssh\ncopy ~/.gitconfig\n";
        let result = parse_home_files_content(content, Path::new("/home/user")).unwrap();
        assert_eq!(
            result,
            vec![
                HomeFileDirective::Copy(PathBuf::from("/home/user/.bashrc")),
                HomeFileDirective::Pass(PathBuf::from("/home/user/.ssh")),
                HomeFileDirective::Copy(PathBuf::from("/home/user/.gitconfig")),
            ]
        );
    }

    #[test]
    fn test_parse_mixed_with_comments() {
        let content = "# SSH keys\npass ~/.ssh\n\n# Shell config\ncopy ~/.bashrc\n";
        let result = parse_home_files_content(content, Path::new("/home/user")).unwrap();
        assert_eq!(
            result,
            vec![
                HomeFileDirective::Pass(PathBuf::from("/home/user/.ssh")),
                HomeFileDirective::Copy(PathBuf::from("/home/user/.bashrc")),
            ]
        );
    }

    #[test]
    fn test_parse_all_three_directives() {
        let content = "copy ~/.bashrc\npass ~/.ssh\nread ~/.config/git\n";
        let result = parse_home_files_content(content, Path::new("/home/user")).unwrap();
        assert_eq!(
            result,
            vec![
                HomeFileDirective::Copy(PathBuf::from("/home/user/.bashrc")),
                HomeFileDirective::Pass(PathBuf::from("/home/user/.ssh")),
                HomeFileDirective::Read(PathBuf::from("/home/user/.config/git")),
            ]
        );
    }

    #[test]
    fn test_tilde_expansion() {
        assert_eq!(
            expand_tilde("~/foo/bar", Path::new("/home/user")),
            PathBuf::from("/home/user/foo/bar")
        );
        assert_eq!(
            expand_tilde("~", Path::new("/home/user")),
            PathBuf::from("/home/user")
        );
        // No tilde — returned as-is
        assert_eq!(
            expand_tilde("/absolute/path", Path::new("/home/user")),
            PathBuf::from("/absolute/path")
        );
    }

    #[test]
    fn test_reject_dotdot() {
        assert!(reject_dotdot(Path::new("/home/user/safe"), 1).is_ok());
        assert!(reject_dotdot(Path::new("/home/user/../etc/passwd"), 1).is_err());
        assert!(reject_dotdot(Path::new("../escape"), 1).is_err());
    }

    #[test]
    fn test_parse_rejects_dotdot_in_path() {
        let content = "copy ~/.config/../../../etc/passwd\n";
        let result = parse_home_files_content(content, Path::new("/home/user"));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains(".."), "error should mention '..': {}", err);
    }

    #[test]
    fn test_parse_rejects_unknown_directive() {
        let content = "link ~/.bashrc\n";
        let result = parse_home_files_content(content, Path::new("/home/user"));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("unknown directive"), "got: {}", err);
    }

    #[test]
    fn test_parse_rejects_missing_path() {
        let content = "copy \n";
        let result = parse_home_files_content(content, Path::new("/home/user"));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_rejects_bare_verb() {
        let content = "copy\n";
        let result = parse_home_files_content(content, Path::new("/home/user"));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_home_files_from_missing_file() {
        // Non-existent config path → empty vec, no error
        let result = parse_home_files_from(
            Path::new("/nonexistent_home_for_hermit_test/.hermit/home-files"),
            Path::new("/nonexistent_home_for_hermit_test"),
        )
        .unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_absolute_path_without_tilde() {
        let content = "copy /etc/hostname\n";
        let result = parse_home_files_content(content, Path::new("/home/user")).unwrap();
        assert_eq!(
            result,
            vec![HomeFileDirective::Copy(PathBuf::from("/etc/hostname"))]
        );
    }

    #[test]
    fn test_load_env_var_override() {
        // HERMIT_HOME_FILES selects only that file
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("custom-home-files");
        std::fs::write(&config, "copy ~/.bashrc\n").unwrap();

        // Also create a project-level config that should be ignored
        let project = dir.path().join("proj");
        std::fs::create_dir_all(project.join(".hermit")).unwrap();
        std::fs::write(project.join(".hermit/home-files"), "pass ~/.ssh\n").unwrap();

        // Also create a user-level config that should be ignored
        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join(".hermit")).unwrap();
        std::fs::write(home.join(".hermit/home-files"), "copy ~/.gitconfig\n").unwrap();

        // Temporarily set HERMIT_HOME_FILES
        let _guard = EnvGuard::set("HERMIT_HOME_FILES", config.to_str().unwrap());

        let result = load_home_files(&project, &home).unwrap();
        assert_eq!(
            result,
            vec![HomeFileDirective::Copy(PathBuf::from(
                home.join(".bashrc")
            ))]
        );
    }

    #[test]
    fn test_load_project_and_user_merge() {
        let dir = tempfile::tempdir().unwrap();

        let project = dir.path().join("proj");
        std::fs::create_dir_all(project.join(".hermit")).unwrap();
        std::fs::write(project.join(".hermit/home-files"), "copy ~/.project_rc\n").unwrap();

        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join(".hermit")).unwrap();
        std::fs::write(home.join(".hermit/home-files"), "pass ~/.ssh\n").unwrap();

        let _guard = EnvGuard::remove("HERMIT_HOME_FILES");

        let result = load_home_files(&project, &home).unwrap();
        assert_eq!(
            result,
            vec![
                HomeFileDirective::Copy(PathBuf::from(home.join(".project_rc"))),
                HomeFileDirective::Pass(PathBuf::from(home.join(".ssh"))),
            ]
        );
    }

    #[test]
    fn test_load_project_only_no_user() {
        let dir = tempfile::tempdir().unwrap();

        let project = dir.path().join("proj");
        std::fs::create_dir_all(project.join(".hermit")).unwrap();
        std::fs::write(project.join(".hermit/home-files"), "copy ~/.bashrc\n").unwrap();

        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        // No user-level config

        let _guard = EnvGuard::remove("HERMIT_HOME_FILES");

        let result = load_home_files(&project, &home).unwrap();
        assert_eq!(
            result,
            vec![HomeFileDirective::Copy(PathBuf::from(home.join(".bashrc")))]
        );
    }

    #[test]
    fn test_load_user_only_no_project() {
        let dir = tempfile::tempdir().unwrap();

        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        // No project-level config

        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join(".hermit")).unwrap();
        std::fs::write(home.join(".hermit/home-files"), "pass ~/.ssh\n").unwrap();

        let _guard = EnvGuard::remove("HERMIT_HOME_FILES");

        let result = load_home_files(&project, &home).unwrap();
        assert_eq!(
            result,
            vec![HomeFileDirective::Pass(PathBuf::from(home.join(".ssh")))]
        );
    }

    #[test]
    fn test_load_env_var_nonexistent_file_errors() {
        let _guard = EnvGuard::set("HERMIT_HOME_FILES", "/nonexistent/path/home-files");

        let result = load_home_files(Path::new("/tmp"), Path::new("/tmp"));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("HERMIT_HOME_FILES"),
            "error should mention env var: {}",
            err
        );
    }

    /// RAII guard for setting/unsetting an env var in a test, restoring on drop.
    struct EnvGuard {
        key: String,
        prev: Option<String>,
    }

    impl EnvGuard {
        fn set(key: &str, value: &str) -> Self {
            let prev = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self {
                key: key.to_string(),
                prev,
            }
        }

        fn remove(key: &str) -> Self {
            let prev = std::env::var(key).ok();
            std::env::remove_var(key);
            Self {
                key: key.to_string(),
                prev,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var(&self.key, v),
                None => std::env::remove_var(&self.key),
            }
        }
    }
}
