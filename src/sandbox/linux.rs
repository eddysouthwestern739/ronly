use anyhow::Result;
use nix::mount::MsFlags;
use nix::sched::CloneFlags;
use std::collections::BTreeMap;
use std::ffi::CString;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;

use crate::shims;

fn setup_namespaces() -> Result<()> {
    // Mount namespace for read-only FS.
    // PID namespace deferred — seccomp blocks kill.
    nix::sched::unshare(CloneFlags::CLONE_NEWNS)?;
    Ok(())
}

fn setup_mounts(tmpfs_size_mb: u64) -> Result<()> {
    // Create dirs we need before going read-only
    std::fs::create_dir_all(shims::SHIMS_DIR).ok();

    // Make mount tree private
    nix::mount::mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )?;

    // Remount root read-only
    nix::mount::mount(
        Some("/"),
        "/",
        None::<&str>,
        MsFlags::MS_BIND
            | MsFlags::MS_REMOUNT
            | MsFlags::MS_RDONLY
            | MsFlags::MS_REC,
        None::<&str>,
    )?;

    // Writable /tmp
    let opts = format!("size={}m", tmpfs_size_mb);
    nix::mount::mount(
        Some("tmpfs"),
        "/tmp",
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some(opts.as_str()),
    )?;

    // Writable shims dir (tmpfs over read-only mount)
    nix::mount::mount(
        Some("tmpfs"),
        shims::SHIMS_DIR,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some("size=4m"),
    )?;

    Ok(())
}

fn setup_seccomp() -> Result<()> {
    use seccompiler::SeccompAction;
    use seccompiler::SeccompFilter;
    use seccompiler::SeccompRule;

    #[allow(unused_mut)]
    let mut blocked: Vec<i64> = vec![
        libc::SYS_kill,
        libc::SYS_tkill,
        libc::SYS_tgkill,
        libc::SYS_unlinkat,
        libc::SYS_renameat,
        libc::SYS_renameat2,
        libc::SYS_truncate,
        libc::SYS_ftruncate,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_reboot,
        libc::SYS_ptrace,
    ];
    #[cfg(target_arch = "x86_64")]
    blocked.extend_from_slice(&[
        libc::SYS_unlink,
        libc::SYS_rmdir,
        libc::SYS_rename,
    ]);

    let rules: BTreeMap<i64, Vec<SeccompRule>> =
        blocked.into_iter().map(|sc| (sc, vec![])).collect();

    let arch =
        std::env::consts::ARCH.try_into().map_err(|e| {
            anyhow::anyhow!("unsupported arch: {}", e)
        })?;

    let filter = SeccompFilter::new(
        rules,
        // Default: allow unlisted syscalls
        SeccompAction::Allow,
        // Match: block listed destructive syscalls
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )?;

    let bpf: seccompiler::BpfProgram = filter.try_into()?;
    seccompiler::apply_filter(&bpf)?;
    Ok(())
}

fn die(msg: &str) -> ! {
    eprintln!("{}", msg);
    unsafe { libc::_exit(1) }
}

fn sandbox_or_die(tmpfs_size_mb: u64) {
    if let Err(e) = setup_namespaces() {
        die(&format!("rosshd: namespace: {}", e));
    }
    if let Err(e) = setup_mounts(tmpfs_size_mb) {
        die(&format!("rosshd: mounts: {}", e));
    }
    if let Err(e) = shims::install_shims() {
        die(&format!("rosshd: shims: {}", e));
    }
    let path =
        std::env::var("PATH").unwrap_or_default();
    std::env::set_var(
        "PATH",
        format!("{}:{}", shims::SHIMS_DIR, path),
    );
    if let Err(e) = setup_seccomp() {
        die(&format!("rosshd: seccomp: {}", e));
    }
}

/// Common child setup: sandbox + exec shell.
fn child_setup_and_exec(
    tmpfs_size_mb: u64,
    cmd: Option<&str>,
) -> ! {
    sandbox_or_die(tmpfs_size_mb);

    let shell = std::env::var("SHELL")
        .unwrap_or_else(|_| "/bin/bash".to_string());

    match cmd {
        Some(c) => {
            let sh = CString::new(shell).unwrap();
            let flag = CString::new("-c").unwrap();
            let c = CString::new(c).unwrap();
            nix::unistd::execvp(
                &sh,
                &[&sh, &flag, &c],
            )
            .unwrap();
        }
        None => {
            let sh = CString::new(shell).unwrap();
            nix::unistd::execvp(&sh, &[&sh]).unwrap();
        }
    }
    unreachable!()
}

/// Spawn a sandboxed child with a PTY (for interactive).
pub fn spawn_shell(
    tmpfs_size_mb: u64,
    cmd: Option<&str>,
) -> Result<(nix::unistd::Pid, OwnedFd)> {
    use nix::pty::openpty;
    use nix::unistd::ForkResult;
    use std::os::fd::IntoRawFd;

    let pty = openpty(None, None)?;
    let master_raw = pty.master.into_raw_fd();
    let slave_raw = pty.slave.into_raw_fd();

    match unsafe { nix::unistd::fork()? } {
        ForkResult::Parent { child } => {
            unsafe { libc::close(slave_raw) };
            let master = unsafe {
                OwnedFd::from_raw_fd(master_raw)
            };
            Ok((child, master))
        }
        ForkResult::Child => {
            unsafe { libc::close(master_raw) };
            nix::unistd::setsid().unwrap();
            unsafe {
                libc::ioctl(
                    slave_raw,
                    libc::TIOCSCTTY,
                    0,
                );
            }
            nix::unistd::dup2(slave_raw, 0).unwrap();
            nix::unistd::dup2(slave_raw, 1).unwrap();
            nix::unistd::dup2(slave_raw, 2).unwrap();
            if slave_raw > 2 {
                unsafe { libc::close(slave_raw) };
            }
            child_setup_and_exec(tmpfs_size_mb, cmd);
        }
    }
}

/// Spawn child with pipes (for exec, no PTY).
/// Returns (pid, stdout_fd, stdin_fd).
pub fn spawn_exec(
    tmpfs_size_mb: u64,
    cmd: &str,
) -> Result<(nix::unistd::Pid, OwnedFd, OwnedFd)> {
    use nix::unistd::ForkResult;
    use std::os::fd::IntoRawFd;

    // stdout pipe: child writes, parent reads
    let (stdout_r, stdout_w) = nix::unistd::pipe()?;
    // stdin pipe: parent writes, child reads
    let (stdin_r, stdin_w) = nix::unistd::pipe()?;
    // stderr goes to stdout
    let stdout_r_raw = stdout_r.into_raw_fd();
    let stdout_w_raw = stdout_w.into_raw_fd();
    let stdin_r_raw = stdin_r.into_raw_fd();
    let stdin_w_raw = stdin_w.into_raw_fd();

    match unsafe { nix::unistd::fork()? } {
        ForkResult::Parent { child } => {
            unsafe {
                libc::close(stdout_w_raw);
                libc::close(stdin_r_raw);
            }
            let out = unsafe {
                OwnedFd::from_raw_fd(stdout_r_raw)
            };
            let inp = unsafe {
                OwnedFd::from_raw_fd(stdin_w_raw)
            };
            Ok((child, out, inp))
        }
        ForkResult::Child => {
            unsafe {
                libc::close(stdout_r_raw);
                libc::close(stdin_w_raw);
            }
            nix::unistd::dup2(stdin_r_raw, 0).unwrap();
            nix::unistd::dup2(stdout_w_raw, 1).unwrap();
            nix::unistd::dup2(stdout_w_raw, 2).unwrap();
            if stdin_r_raw > 2 {
                unsafe { libc::close(stdin_r_raw) };
            }
            if stdout_w_raw > 2 {
                unsafe { libc::close(stdout_w_raw) };
            }
            child_setup_and_exec(
                tmpfs_size_mb, Some(cmd),
            );
        }
    }
}
