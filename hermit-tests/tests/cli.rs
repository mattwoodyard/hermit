//! Tests for `hermit::cli`. These exercise the clap derive layer
//! through `Cli::parse_from` / `Cli::try_parse_from` — the only
//! surface is public, so no `__test_internals` wrappers are needed.

use std::path::PathBuf;

use clap::Parser;
use hermit::cli::{
    Cli, Command, EditConfigAction, EditConfigArgs,
};

#[test]
fn parse_run_minimal() {
    let cli = Cli::parse_from([
        "hermit",
        "run",
        "--config",
        "file:///tmp/hermit.toml",
        "--",
        "make",
    ]);
    match cli.command {
        Command::Run(args) => {
            assert_eq!(args.config, "file:///tmp/hermit.toml");
            assert_eq!(args.project_dir, PathBuf::from("."));
            assert_eq!(args.command, vec!["make"]);
            assert_eq!(args.verbose, 0);
        }
        _ => panic!("wrong subcommand"),
    }
}

#[test]
fn parse_run_with_all_flags() {
    let cli = Cli::parse_from([
        "hermit",
        "run",
        "--config",
        "https://example.com/h.toml",
        "-vv",
        "--project-dir",
        "/tmp/proj",
        "--",
        "cargo",
        "build",
    ]);
    match cli.command {
        Command::Run(args) => {
            assert_eq!(args.config, "https://example.com/h.toml");
            assert_eq!(args.project_dir, PathBuf::from("/tmp/proj"));
            assert_eq!(args.command, vec!["cargo", "build"]);
            assert_eq!(args.verbose, 2);
        }
        _ => panic!("wrong subcommand"),
    }
}

#[test]
fn run_requires_config_url() {
    assert!(Cli::try_parse_from(["hermit", "run", "--", "make"]).is_err());
}

#[test]
fn run_requires_command() {
    assert!(Cli::try_parse_from([
        "hermit", "run", "--config", "file:///x",
    ])
    .is_err());
}

#[test]
fn parse_sign() {
    let cli = Cli::parse_from([
        "hermit",
        "sign",
        "--cert",
        "/tmp/cert.pem",
        "--key",
        "/tmp/key.pem",
        "config.toml",
    ]);
    match cli.command {
        Command::Sign(args) => {
            assert_eq!(args.cert, Some(PathBuf::from("/tmp/cert.pem")));
            assert_eq!(args.key, Some(PathBuf::from("/tmp/key.pem")));
            assert_eq!(args.config, PathBuf::from("config.toml"));
            assert!(args.output.is_none());
        }
        _ => panic!("wrong subcommand"),
    }
}

#[test]
fn parse_sign_with_output() {
    let cli = Cli::parse_from([
        "hermit",
        "sign",
        "--cert",
        "/tmp/c.pem",
        "--key",
        "/tmp/k.pem",
        "--output",
        "/tmp/out.toml",
        "in.toml",
    ]);
    match cli.command {
        Command::Sign(args) => {
            assert_eq!(args.output, Some(PathBuf::from("/tmp/out.toml")));
        }
        _ => panic!("wrong subcommand"),
    }
}

#[test]
fn parse_sign_uses_defaults_when_flags_omitted() {
    // No --cert, --key, or positional config: clap should accept
    // the call so the runtime can substitute the default paths.
    let cli = Cli::parse_from(["hermit", "sign"]);
    match cli.command {
        Command::Sign(args) => {
            assert!(args.cert.is_none());
            assert!(args.key.is_none());
            assert_eq!(args.config, PathBuf::from("hermit.toml"));
            assert!(args.output.is_none());
        }
        _ => panic!("wrong subcommand"),
    }
}

#[test]
fn parse_verify() {
    let cli = Cli::parse_from(["hermit", "verify", "file:///tmp/h.toml"]);
    match cli.command {
        Command::Verify(args) => {
            assert_eq!(args.config, "file:///tmp/h.toml");
            assert!(args.trust_dir.is_none());
        }
        _ => panic!("wrong subcommand"),
    }
}

#[test]
fn parse_verify_with_trust_dir() {
    let cli = Cli::parse_from([
        "hermit",
        "verify",
        "--trust-dir",
        "/etc/hermit-keys",
        "file:///t/c.toml",
    ]);
    match cli.command {
        Command::Verify(args) => {
            assert_eq!(args.trust_dir, Some(PathBuf::from("/etc/hermit-keys")));
        }
        _ => panic!("wrong subcommand"),
    }
}

#[test]
fn no_subcommand_is_error() {
    assert!(Cli::try_parse_from(["hermit"]).is_err());
}

#[test]
fn parse_run_allow_unsigned() {
    let cli = Cli::parse_from([
        "hermit",
        "run",
        "--config",
        "file:///x.toml",
        "--allow-unsigned",
        "--",
        "true",
    ]);
    match cli.command {
        Command::Run(args) => {
            assert!(args.allow_unsigned);
        }
        _ => panic!("wrong subcommand"),
    }
}

#[test]
fn parse_run_with_block_log() {
    let cli = Cli::parse_from([
        "hermit",
        "run",
        "--config",
        "file:///x.toml",
        "--block-log",
        "/tmp/hermit-blocks.jsonl",
        "--",
        "true",
    ]);
    match cli.command {
        Command::Run(args) => {
            assert_eq!(args.block_log, Some(PathBuf::from("/tmp/hermit-blocks.jsonl")));
        }
        _ => panic!("wrong subcommand"),
    }
}

#[test]
fn parse_run_with_log_file() {
    let cli = Cli::parse_from([
        "hermit",
        "run",
        "--config",
        "file:///x.toml",
        "--log-file",
        "/tmp/hermit.log",
        "--",
        "true",
    ]);
    match cli.command {
        Command::Run(args) => {
            assert_eq!(args.log_file, Some(PathBuf::from("/tmp/hermit.log")));
        }
        _ => panic!("wrong subcommand"),
    }
}

#[test]
fn parse_run_log_file_defaults_to_none() {
    let cli = Cli::parse_from([
        "hermit",
        "run",
        "--config",
        "file:///x.toml",
        "--",
        "true",
    ]);
    match cli.command {
        Command::Run(args) => assert!(args.log_file.is_none()),
        _ => panic!("wrong subcommand"),
    }
}

#[test]
fn parse_run_log_file_and_block_log_independent() {
    let cli = Cli::parse_from([
        "hermit",
        "run",
        "--config",
        "file:///x.toml",
        "--block-log",
        "/tmp/blocks.jsonl",
        "--log-file",
        "/tmp/hermit.log",
        "--",
        "true",
    ]);
    match cli.command {
        Command::Run(args) => {
            assert_eq!(args.log_file, Some(PathBuf::from("/tmp/hermit.log")));
            assert_eq!(args.block_log, Some(PathBuf::from("/tmp/blocks.jsonl")));
        }
        _ => panic!("wrong subcommand"),
    }
}

#[test]
fn parse_run_block_log_defaults_to_none() {
    // `block_log` holds only the user's explicit override — when the
    // flag is omitted it is None, and the sandbox layer substitutes
    // `$XDG_STATE_HOME/hermit/blocks.jsonl`. `no_block_log` defaults
    // to false, i.e. logging is on by default.
    let cli = Cli::parse_from([
        "hermit",
        "run",
        "--config",
        "file:///x.toml",
        "--",
        "true",
    ]);
    match cli.command {
        Command::Run(args) => {
            assert!(args.block_log.is_none());
            assert!(!args.no_block_log);
        }
        _ => panic!("wrong subcommand"),
    }
}

#[test]
fn parse_run_no_block_log_sets_flag() {
    let cli = Cli::parse_from([
        "hermit",
        "run",
        "--config",
        "file:///x.toml",
        "--no-block-log",
        "--",
        "true",
    ]);
    match cli.command {
        Command::Run(args) => {
            assert!(args.no_block_log);
            assert!(args.block_log.is_none());
        }
        _ => panic!("wrong subcommand"),
    }
}

#[test]
fn parse_run_block_log_and_no_block_log_conflict() {
    // Passing both is ambiguous — clap should reject it. Without
    // this guard, the opt-out flag would silently win over the
    // explicit path (or vice versa) depending on ordering.
    let err = Cli::try_parse_from([
        "hermit",
        "run",
        "--config",
        "file:///x.toml",
        "--block-log",
        "/tmp/b.jsonl",
        "--no-block-log",
        "--",
        "true",
    ])
    .expect_err("clap must reject --block-log with --no-block-log");
    let msg = err.to_string();
    assert!(
        msg.contains("cannot be used with") || msg.contains("conflict"),
        "expected a conflict error, got: {msg}"
    );
}

#[test]
fn parse_run_defaults_to_signed() {
    let cli = Cli::parse_from([
        "hermit",
        "run",
        "--config",
        "file:///x.toml",
        "--",
        "true",
    ]);
    match cli.command {
        Command::Run(args) => assert!(!args.allow_unsigned),
        _ => panic!("wrong subcommand"),
    }
}

#[test]
fn parse_keygen_with_explicit_paths() {
    let cli = Cli::parse_from([
        "hermit",
        "keygen",
        "--cert",
        "/tmp/c.pem",
        "--key",
        "/tmp/k.pem",
    ]);
    match cli.command {
        Command::Keygen(args) => {
            assert_eq!(args.cert, Some(PathBuf::from("/tmp/c.pem")));
            assert_eq!(args.key, Some(PathBuf::from("/tmp/k.pem")));
            assert_eq!(args.subject, "hermit-signer");
            assert!(!args.force);
        }
        _ => panic!("wrong subcommand"),
    }
}

#[test]
fn parse_keygen_with_all_flags() {
    let cli = Cli::parse_from([
        "hermit", "keygen",
        "--cert", "/t/c.pem",
        "--key", "/t/k.pem",
        "--subject", "ci-bot",
        "--force",
    ]);
    match cli.command {
        Command::Keygen(args) => {
            assert_eq!(args.subject, "ci-bot");
            assert!(args.force);
        }
        _ => panic!("wrong subcommand"),
    }
}

#[test]
fn parse_keygen_uses_defaults_when_flags_omitted() {
    // `hermit keygen` with no flags now succeeds; both --cert and
    // --key fall back to ~/.hermit/signer.{cert,key}.pem at
    // runtime.
    let cli = Cli::parse_from(["hermit", "keygen"]);
    match cli.command {
        Command::Keygen(args) => {
            assert!(args.cert.is_none());
            assert!(args.key.is_none());
            assert_eq!(args.subject, "hermit-signer");
            assert!(!args.force);
        }
        _ => panic!("wrong subcommand"),
    }
}

#[test]
fn parse_keygen_partial_flags_are_independent() {
    // Either flag on its own is legal — the missing one falls
    // back to its default.
    let cli = Cli::parse_from(["hermit", "keygen", "--cert", "/x"]);
    match cli.command {
        Command::Keygen(args) => {
            assert_eq!(args.cert, Some(PathBuf::from("/x")));
            assert!(args.key.is_none());
        }
        _ => panic!("wrong subcommand"),
    }
    let cli = Cli::parse_from(["hermit", "keygen", "--key", "/x"]);
    match cli.command {
        Command::Keygen(args) => {
            assert!(args.cert.is_none());
            assert_eq!(args.key, Some(PathBuf::from("/x")));
        }
        _ => panic!("wrong subcommand"),
    }
}

#[test]
fn parse_learn_with_config() {
    let cli = Cli::parse_from([
        "hermit",
        "learn",
        "--config",
        "file:///tmp/wip.toml",
        "--",
        "make",
    ]);
    match cli.command {
        Command::Learn(args) => {
            assert_eq!(args.config.as_deref(), Some("file:///tmp/wip.toml"));
            assert_eq!(args.command, vec!["make"]);
        }
        _ => panic!("wrong subcommand"),
    }
}

#[test]
fn parse_learn_without_config() {
    // The whole point of making --config optional: a fresh
    // user with no rules yet should be able to invoke learn
    // and have hermit synthesize a passthrough config.
    let cli = Cli::parse_from(["hermit", "learn", "--", "make"]);
    match cli.command {
        Command::Learn(args) => {
            assert!(args.config.is_none());
            assert_eq!(args.command, vec!["make"]);
        }
        _ => panic!("wrong subcommand"),
    }
}

#[test]
fn learn_requires_command() {
    assert!(Cli::try_parse_from(["hermit", "learn"]).is_err());
}

#[test]
fn legacy_flags_are_gone() {
    // The old positional mode (`hermit -- cmd`) and flags like
    // --net, --allow must no longer parse at top level.
    assert!(Cli::try_parse_from(["hermit", "--net", "isolate", "--", "make"]).is_err());
    assert!(Cli::try_parse_from(["hermit", "--allow", "x", "--", "make"]).is_err());
    assert!(Cli::try_parse_from(["hermit", "--", "make"]).is_err());
}

#[test]
fn parse_edit_config_show_defaults_to_local_hermit_toml() {
    // edit-config show / add-rule / remove-rule: the positional
    // <CONFIG> defaults to `hermit.toml` so the common case
    // (operating on the project's config) needs no argument.
    let cli = Cli::parse_from(["hermit", "edit-config", "show"]);
    match cli.command {
        Command::EditConfig(EditConfigArgs {
            action: EditConfigAction::Show(args),
        }) => assert_eq!(args.config, PathBuf::from("hermit.toml")),
        _ => panic!("wrong subcommand"),
    }
}

#[test]
fn parse_edit_config_add_rule_defaults_config_path() {
    let cli = Cli::parse_from(["hermit", "edit-config", "add-rule", "--host", "x.example"]);
    match cli.command {
        Command::EditConfig(EditConfigArgs {
            action: EditConfigAction::AddRule(args),
        }) => {
            assert_eq!(args.config, PathBuf::from("hermit.toml"));
            assert_eq!(args.host.as_deref(), Some("x.example"));
        }
        _ => panic!("wrong subcommand"),
    }
}

#[test]
fn parse_edit_config_remove_rule_defaults_config_path() {
    let cli =
        Cli::parse_from(["hermit", "edit-config", "remove-rule", "--host", "x.example"]);
    match cli.command {
        Command::EditConfig(EditConfigArgs {
            action: EditConfigAction::RemoveRule(args),
        }) => {
            assert_eq!(args.config, PathBuf::from("hermit.toml"));
            assert_eq!(args.host.as_deref(), Some("x.example"));
        }
        _ => panic!("wrong subcommand"),
    }
}

#[test]
fn parse_proxy_minimal_uses_defaults() {
    let cli = Cli::parse_from([
        "hermit", "proxy", "--config", "file:///tmp/hermit.toml",
    ]);
    match cli.command {
        Command::Proxy(args) => {
            assert_eq!(args.config, "file:///tmp/hermit.toml");
            assert_eq!(args.listen_https, "127.0.0.1:1443");
            assert_eq!(args.listen_http, "127.0.0.1:1080");
            assert!(args.listen_dns.is_none());
            assert!(args.ca_cert.is_none());
            assert!(!args.permit_all);
            assert!(!args.allow_unsigned);
            assert!(!args.no_block_log);
            assert!(args.block_log.is_none());
            assert!(args.access_log.is_none());
            assert!(args.log_file.is_none());
            assert_eq!(args.verbose, 0);
            assert!(!args.trace);
        }
        _ => panic!("wrong subcommand"),
    }
}

#[test]
fn parse_proxy_requires_config() {
    // Same shape as `run`: no positional fallback, --config
    // is the only way to point at a TOML.
    assert!(Cli::try_parse_from(["hermit", "proxy"]).is_err());
}

#[test]
fn parse_proxy_with_all_flags() {
    let cli = Cli::parse_from([
        "hermit", "proxy",
        "--config", "https://example.com/h.toml",
        "--allow-unsigned",
        "--listen-https", "0.0.0.0:1443",
        "--listen-http", "0.0.0.0:1080",
        "--listen-dns", "127.0.0.1:5353",
        "--ca-cert", "/tmp/ca.pem",
        "--permit-all",
        "--access-log", "/tmp/access.jsonl",
        "--log-file", "/tmp/proxy.log",
        "-vv",
        "--trace",
    ]);
    match cli.command {
        Command::Proxy(args) => {
            assert_eq!(args.config, "https://example.com/h.toml");
            assert!(args.allow_unsigned);
            assert_eq!(args.listen_https, "0.0.0.0:1443");
            assert_eq!(args.listen_http, "0.0.0.0:1080");
            assert_eq!(args.listen_dns.as_deref(), Some("127.0.0.1:5353"));
            assert_eq!(args.ca_cert, Some(PathBuf::from("/tmp/ca.pem")));
            assert!(args.permit_all);
            assert_eq!(args.access_log, Some(PathBuf::from("/tmp/access.jsonl")));
            assert_eq!(args.log_file, Some(PathBuf::from("/tmp/proxy.log")));
            assert_eq!(args.verbose, 2);
            assert!(args.trace);
        }
        _ => panic!("wrong subcommand"),
    }
}

#[test]
fn parse_proxy_trace_defaults_off() {
    let cli = Cli::parse_from([
        "hermit", "proxy", "--config", "file:///x.toml",
    ]);
    match cli.command {
        Command::Proxy(args) => assert!(!args.trace),
        _ => panic!("wrong subcommand"),
    }
}

#[test]
fn parse_proxy_block_log_no_block_log_conflict() {
    // Same belt-and-suspenders rule as `run`: passing both
    // is ambiguous so clap rejects it up front.
    let err = Cli::try_parse_from([
        "hermit", "proxy",
        "--config", "file:///x.toml",
        "--block-log", "/tmp/b.jsonl",
        "--no-block-log",
    ])
    .expect_err("clap must reject --block-log with --no-block-log");
    let msg = err.to_string();
    assert!(
        msg.contains("cannot be used with") || msg.contains("conflict"),
        "expected a conflict error, got: {msg}"
    );
}

#[test]
fn parse_init_no_args_uses_default_trust_dir() {
    // `hermit init` with no flags falls back to
    // $HERMIT_TRUST_DIR / ~/.hermit/keys at runtime; the CLI
    // layer just records `trust_dir = None`.
    let cli = Cli::parse_from(["hermit", "init"]);
    match cli.command {
        Command::Init(args) => assert!(args.trust_dir.is_none()),
        _ => panic!("wrong subcommand"),
    }
}

#[test]
fn parse_init_with_explicit_trust_dir() {
    let cli = Cli::parse_from([
        "hermit", "init", "--trust-dir", "/etc/hermit-keys",
    ]);
    match cli.command {
        Command::Init(args) => {
            assert_eq!(args.trust_dir, Some(PathBuf::from("/etc/hermit-keys")));
        }
        _ => panic!("wrong subcommand"),
    }
}
