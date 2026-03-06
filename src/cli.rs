use clap::{Parser, ValueEnum};
use std::path::PathBuf;

/// Network isolation mode for the sandbox.
#[derive(ValueEnum, Clone, Debug, Default, PartialEq, Eq)]
pub enum NetMode {
    /// Share the host network namespace (no isolation)
    #[default]
    Host,
    /// Empty network namespace with zero connectivity
    Isolate,
}

impl std::fmt::Display for NetMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetMode::Host => write!(f, "host"),
            NetMode::Isolate => write!(f, "isolate"),
        }
    }
}

#[derive(Parser, Debug)]
#[command(name = "hermit", about = "Lightweight container/sandbox for build commands")]
pub struct Cli {
    /// Enable verbose output (-v info, -vv debug, -vvv trace)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Project directory (read-write access granted inside sandbox)
    #[arg(long, default_value = ".")]
    pub project_dir: PathBuf,

    /// Additional file or directory to pass through with read-write access. Repeatable.
    #[arg(long)]
    pub passthrough: Vec<PathBuf>,

    /// Network mode: host (default) or isolate
    #[arg(long, value_enum, default_value_t)]
    pub net: NetMode,

    /// Command and arguments to run inside the sandbox
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defaults() {
        let cli = Cli::parse_from(["hermit", "--", "make"]);
        assert_eq!(cli.project_dir, PathBuf::from("."));
        assert_eq!(cli.command, vec!["make"]);
    }

    #[test]
    fn test_project_dir_flag() {
        let cli = Cli::parse_from([
            "hermit",
            "--project-dir",
            "/tmp/proj",
            "--",
            "cargo",
            "build",
        ]);
        assert_eq!(cli.project_dir, PathBuf::from("/tmp/proj"));
        assert_eq!(cli.command, vec!["cargo", "build"]);
    }

    #[test]
    fn test_command_required() {
        let result = Cli::try_parse_from(["hermit"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_passthrough_single() {
        let cli = Cli::parse_from(["hermit", "--passthrough", "/tmp/extra", "--", "make"]);
        assert_eq!(cli.passthrough, vec![PathBuf::from("/tmp/extra")]);
    }

    #[test]
    fn test_passthrough_multiple() {
        let cli = Cli::parse_from([
            "hermit",
            "--passthrough",
            "/tmp/a",
            "--passthrough",
            "/tmp/b",
            "--",
            "make",
        ]);
        assert_eq!(
            cli.passthrough,
            vec![PathBuf::from("/tmp/a"), PathBuf::from("/tmp/b")]
        );
    }

    #[test]
    fn test_passthrough_default_empty() {
        let cli = Cli::parse_from(["hermit", "--", "make"]);
        assert!(cli.passthrough.is_empty());
    }

    #[test]
    fn test_verbose_default_zero() {
        let cli = Cli::parse_from(["hermit", "--", "make"]);
        assert_eq!(cli.verbose, 0);
    }

    #[test]
    fn test_verbose_short_flag() {
        let cli = Cli::parse_from(["hermit", "-v", "--", "make"]);
        assert_eq!(cli.verbose, 1);
    }

    #[test]
    fn test_verbose_stacks() {
        let cli = Cli::parse_from(["hermit", "-vvv", "--", "make"]);
        assert_eq!(cli.verbose, 3);
    }

    #[test]
    fn test_verbose_long_flag() {
        let cli = Cli::parse_from(["hermit", "--verbose", "--", "make"]);
        assert_eq!(cli.verbose, 1);
    }

    #[test]
    fn test_net_default_host() {
        let cli = Cli::parse_from(["hermit", "--", "make"]);
        assert_eq!(cli.net, NetMode::Host);
    }

    #[test]
    fn test_net_host_explicit() {
        let cli = Cli::parse_from(["hermit", "--net", "host", "--", "make"]);
        assert_eq!(cli.net, NetMode::Host);
    }

    #[test]
    fn test_net_isolate() {
        let cli = Cli::parse_from(["hermit", "--net", "isolate", "--", "make"]);
        assert_eq!(cli.net, NetMode::Isolate);
    }

    #[test]
    fn test_net_invalid_value() {
        let result = Cli::try_parse_from(["hermit", "--net", "bogus", "--", "make"]);
        assert!(result.is_err());
    }
}
