use anyhow::Result;
use nix::mount::MsFlags;
use nix::sched::CloneFlags;
use std::collections::BTreeMap;
use std::ffi::CString;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;

use crate::shims;

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
    use seccompiler::SeccompCmpArgLen;
    use seccompiler::SeccompCmpOp;
    use seccompiler::SeccompCondition;
    use seccompiler::SeccompFilter;
    use seccompiler::SeccompRule;

    // Unconditionally blocked syscalls
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
    ];
    #[cfg(target_arch = "x86_64")]
    blocked.extend_from_slice(&[
        libc::SYS_unlink,
        libc::SYS_rmdir,
        libc::SYS_rename,
    ]);

    let mut rules: BTreeMap<i64, Vec<SeccompRule>> =
        blocked
            .into_iter()
            .map(|sc| (sc, vec![]))
            .collect();

    // ptrace: block write ops, allow read ops.
    // Read-only strace needs ATTACH, PEEKDATA,
    // PEEKTEXT, PEEKUSER, SYSCALL, CONT, DETACH,
    // GETREGSET, GETEVENTMSG, SEIZE, INTERRUPT.
    // Block: POKETEXT, POKEDATA, POKEUSER, SETREGS,
    // SETFPREGS, SETREGSET, SETSIGINFO.
    #[allow(unused_mut)]
    let mut ptrace_write_ops: Vec<u64> = vec![
        libc::PTRACE_POKETEXT as u64,
        libc::PTRACE_POKEDATA as u64,
        libc::PTRACE_POKEUSER as u64,
        libc::PTRACE_SETREGSET as u64,
    ];
    #[cfg(target_arch = "x86_64")]
    ptrace_write_ops.extend_from_slice(&[
        libc::PTRACE_SETREGS as u64,
        libc::PTRACE_SETFPREGS as u64,
    ]);
    let ptrace_rules: Vec<SeccompRule> = ptrace_write_ops
        .into_iter()
        .map(|op| {
            SeccompRule::new(vec![SeccompCondition::new(
                0, // arg 0 = ptrace request
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                op,
            )
            .unwrap()])
            .unwrap()
        })
        .collect();
    rules.insert(libc::SYS_ptrace, ptrace_rules);

    let arch =
        std::env::consts::ARCH.try_into().map_err(|e| {
            anyhow::anyhow!("unsupported arch: {}", e)
        })?;

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
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

/// Set up the sandbox. Does a double-fork for PID namespace:
/// - Caller (child A) unshares mount+PID, sets up mounts/shims
/// - Forks again: child B is PID 1 in new PID namespace
/// - Child A closes stdio, waits for B, exits with B's code
/// - Child B applies seccomp and returns (caller execs shell)
///
/// Host /proc remains mounted read-only so ps/top show real
/// processes. kill fails because target PIDs don't exist in
/// the agent's PID namespace (seccomp also blocks as backup).
fn sandbox_or_die(
    tmpfs_size_mb: u64,
    extra_shim_dirs: &[std::path::PathBuf],
) {
    // Unshare mount + PID namespace
    if let Err(e) = nix::sched::unshare(
        CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWPID,
    ) {
        die(&format!("rosshd: namespace: {}", e));
    }

    // Set up mounts, shims (before second fork)
    if let Err(e) = setup_mounts(tmpfs_size_mb) {
        die(&format!("rosshd: mounts: {}", e));
    }
    if let Err(e) = shims::install_shims() {
        die(&format!("rosshd: shims: {}", e));
    }
    // Build PATH: extra shims > built-in shims > system
    let sys_path =
        std::env::var("PATH").unwrap_or_default();
    let mut path_parts: Vec<String> = extra_shim_dirs
        .iter()
        .map(|d| d.to_string_lossy().into_owned())
        .collect();
    path_parts.push(shims::SHIMS_DIR.to_string());
    path_parts.push(sys_path);
    std::env::set_var("PATH", path_parts.join(":"));

    // Double-fork for PID namespace.
    // Child B becomes PID 1 in the new namespace.
    use nix::unistd::ForkResult;
    match unsafe { nix::unistd::fork() } {
        Ok(ForkResult::Parent { child }) => {
            // Child A: close stdio so pipe/PTY sees EOF
            // when child B exits (not when we exit)
            unsafe {
                libc::close(0);
                libc::close(1);
                libc::close(2);
            }
            // Wait for child B, propagate exit code
            match nix::sys::wait::waitpid(child, None) {
                Ok(
                    nix::sys::wait::WaitStatus::Exited(
                        _, code,
                    ),
                ) => unsafe { libc::_exit(code) },
                _ => unsafe { libc::_exit(1) },
            }
        }
        Ok(ForkResult::Child) => {
            // Child B: PID 1 in new namespace.
            // /proc still shows host processes (good).
            // Apply seccomp and return to caller.
        }
        Err(e) => {
            die(&format!("rosshd: pid fork: {}", e));
        }
    }

    // Now in child B. Apply seccomp last.
    if let Err(e) = setup_seccomp() {
        die(&format!("rosshd: seccomp: {}", e));
    }
}

/// Common child setup: sandbox + exec shell.
fn child_setup_and_exec(
    tmpfs_size_mb: u64,
    cmd: Option<&str>,
    extra_shim_dirs: &[std::path::PathBuf],
) -> ! {
    sandbox_or_die(tmpfs_size_mb, extra_shim_dirs);

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
    extra_shim_dirs: &[std::path::PathBuf],
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
            child_setup_and_exec(
                tmpfs_size_mb, cmd, extra_shim_dirs,
            );
        }
    }
}

/// Spawn child with pipes (for exec, no PTY).
/// Returns (pid, stdout_fd, stdin_fd).
pub fn spawn_exec(
    tmpfs_size_mb: u64,
    cmd: &str,
    extra_shim_dirs: &[std::path::PathBuf],
) -> Result<(nix::unistd::Pid, OwnedFd, OwnedFd)> {
    use nix::unistd::ForkResult;
    use std::os::fd::IntoRawFd;

    let (stdout_r, stdout_w) = nix::unistd::pipe()?;
    let (stdin_r, stdin_w) = nix::unistd::pipe()?;
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
                tmpfs_size_mb,
                Some(cmd),
                extra_shim_dirs,
            );
        }
    }
}
