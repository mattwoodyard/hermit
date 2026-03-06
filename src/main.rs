use anyhow::{Context, Result};
use clap::Parser;
use log::info;
use std::path::PathBuf;
use std::process;

use hermit::cli::Cli;
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

    info!("command: {}", cli.command.join(" "));

    run_sandboxed(&project_dir, &passthrough, &cli.command, &cli.net)
}
