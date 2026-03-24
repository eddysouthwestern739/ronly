use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

mod audit;
mod sandbox;
mod server;
mod shims;

#[derive(Parser, Clone)]
#[command(name = "rosshd", about = "Read-only SSH server")]
pub struct Args {
    /// Port to listen on
    #[arg(long, default_value = "2222")]
    pub port: u16,

    /// Path to host key (generated if missing)
    #[arg(long, default_value = "/etc/rosshd/host_key")]
    pub host_key: PathBuf,

    /// Path to authorized_keys file
    #[arg(long, default_value = "/etc/rosshd/authorized_keys")]
    pub authorized_keys: PathBuf,

    /// tmpfs size in MB for /tmp
    #[arg(long, default_value = "64")]
    pub tmpfs_size_mb: u64,

    /// Log file path (stdout if not set)
    #[arg(long)]
    pub log: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    server::run(args).await
}
