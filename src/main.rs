use anyhow::{Context, Result};
use clap::Parser;
use log::info;
use sni_proxy::policy::AccessRule;
use std::path::PathBuf;
use std::process;

use hermit::cli::{Cli, NetMode};
use hermit::sandbox::run_sandboxed;

fn main() {
    let exit_code = match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("hermit: {:#}", e);
            1
        }
    };

    process::exit(exit_code);
}

fn run() -> Result<i32> {
    let cli = Cli::parse();

    let log_level = match cli.verbose {
        0 => log::LevelFilter::Warn,
        1 => log::LevelFilter::Info,
        2 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };
    env_logger::Builder::new()
        .filter_level(log_level)
        .format_target(false)
        .format_timestamp(None)
        .init();

    let project_dir = cli
        .project_dir
        .canonicalize()
        .with_context(|| format!("--project-dir '{}' does not exist", cli.project_dir.display()))?;

    info!("project dir: {}", project_dir.display());

    let passthrough: Vec<PathBuf> = cli
        .passthrough
        .iter()
        .map(|p| {
            p.canonicalize()
                .with_context(|| format!("--passthrough '{}' does not exist", p.display()))
        })
        .collect::<Result<_>>()?;

    for p in &passthrough {
        info!("passthrough: {}", p.display());
    }

    // Build access rules from --allowed-hosts (hostname-only) and --allow (full rules)
    let rules = build_rules(&cli.allowed_hosts, &cli.allow)?;

    // --allow or --allowed-hosts implies --net isolate
    let net = if !rules.is_empty() && cli.net == NetMode::Host {
        info!("access rules set, implying --net isolate");
        NetMode::Isolate
    } else {
        cli.net
    };

    info!("command: {}", cli.command.join(" "));

    run_sandboxed(&project_dir, &passthrough, &cli.command, &net, rules)
}

/// Merge --allowed-hosts and --allow into a single list of AccessRules.
fn build_rules(allowed_hosts: &[String], allow: &[String]) -> Result<Vec<AccessRule>> {
    let mut rules: Vec<AccessRule> = Vec::new();

    for host in allowed_hosts {
        rules.push(AccessRule::host_only(host));
    }

    for raw in allow {
        let rule: AccessRule = raw
            .parse()
            .with_context(|| format!("invalid --allow rule: '{}'", raw))?;
        rules.push(rule);
    }

    Ok(rules)
}
