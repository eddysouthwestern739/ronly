use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

mod sandbox;
mod shims;

#[derive(Parser)]
#[command(
    name = "ronly",
    about = "Read-only sandbox for shells",
    long_about = include_str!("../README.md"),
    version
)]
pub struct Args {
    /// Shell to exec (default: $SHELL or /bin/bash)
    pub shell: Option<String>,

    /// Run a single command instead of interactive shell
    #[arg(last = true)]
    pub command: Vec<String>,

    /// Size of writable /tmp (e.g. 64M, 1G)
    #[arg(long, default_value = "64M")]
    pub tmpfs_size: String,

    /// Additional shim directory
    #[arg(long)]
    pub extra_shims: Vec<PathBuf>,

    /// Disable all shims (kernel isolation only)
    #[arg(long)]
    pub no_shims: bool,

    /// Additional writable tmpfs overlay
    #[arg(long)]
    pub writable: Vec<PathBuf>,
}

fn main() -> Result<()> {
    // Shim dispatch: if argv[0] is "docker", "kubectl",
    // etc. (because we were invoked via a bind-mount in
    // the shims dir), handle it and exit. See shims.rs.
    if let Some(code) = shims::maybe_run_as_shim() {
        std::process::exit(code);
    }

    let args = Args::parse();
    sandbox::run(args)
}
