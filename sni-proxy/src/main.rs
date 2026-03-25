use anyhow::Result;
use clap::Parser;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::info;

use sni_proxy::connector::DirectConnector;
use sni_proxy::policy::AllowList;
use sni_proxy::proxy::{self, ProxyConfig};

#[derive(Parser)]
#[command(
    name = "sni-proxy",
    about = "SNI-sniffing TCP proxy with hostname whitelisting"
)]
struct Args {
    /// Address to listen on (e.g., 127.0.0.1:8443)
    #[arg(long)]
    listen: String,

    /// Comma-separated list of allowed hostnames
    #[arg(long, value_delimiter = ',')]
    allowed_hosts: Vec<String>,

    /// Upstream port to connect to
    #[arg(long, default_value_t = 443)]
    upstream_port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let allowed: HashSet<String> = args.allowed_hosts.into_iter().collect();

    info!(
        listen = %args.listen,
        ?allowed,
        upstream_port = args.upstream_port,
        "starting SNI proxy"
    );

    let listener = TcpListener::bind(&args.listen).await?;

    let config = Arc::new(ProxyConfig {
        policy: Arc::new(AllowList::new(allowed)),
        connector: Arc::new(DirectConnector),
        upstream_port: args.upstream_port,
    });

    proxy::run(listener, config).await
}
