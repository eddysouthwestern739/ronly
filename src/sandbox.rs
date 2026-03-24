#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::spawn_exec;
#[cfg(target_os = "linux")]
pub use linux::spawn_shell;

#[cfg(not(target_os = "linux"))]
pub fn spawn_shell(
    _tmpfs_size_mb: u64,
    _cmd: Option<&str>,
) -> anyhow::Result<(u32, std::os::unix::io::OwnedFd)> {
    anyhow::bail!("rosshd only runs on Linux")
}

#[cfg(not(target_os = "linux"))]
pub fn spawn_exec(
    _tmpfs_size_mb: u64,
    _cmd: &str,
) -> anyhow::Result<(
    u32,
    std::os::unix::io::OwnedFd,
    std::os::unix::io::OwnedFd,
)> {
    anyhow::bail!("rosshd only runs on Linux")
}
