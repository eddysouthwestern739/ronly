use nix::mount::MsFlags;
use nix::sched::CloneFlags;
use nix::unistd::ForkResult;
use std::collections::BTreeMap;
use std::ffi::CString;

use crate::shims;
use crate::Args;

fn die(msg: &str) -> ! {
    eprintln!("{}", msg);
    unsafe { libc::_exit(1) }
}

fn setup_mounts(
    args: &Args,
    self_exe: Option<&std::path::Path>,
) -> crate::Result<()> {
    // Create dirs before going read-only
    std::fs::create_dir_all(shims::SHIMS_DIR).ok();
    for p in &args.writable {
        std::fs::create_dir_all(p).ok();
    }

    // Private mount tree
    nix::mount::mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )?;

    // Read-only root
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

    // Writable shims dir — mount BEFORE /tmp so the
    // binary (which may live under /tmp) is still visible
    // for bind-mounting.
    nix::mount::mount(
        Some("tmpfs"),
        shims::SHIMS_DIR,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some("size=1m"),
    )?;

    // Install shims via bind-mount while exe is visible
    if let Some(exe) = self_exe {
        shims::install_shims(exe)?;
    }

    // Writable /tmp (may shadow the binary's location)
    let size = &args.tmpfs_size;
    nix::mount::mount(
        Some("tmpfs"),
        "/tmp",
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some(format!("size={}", size).as_str()),
    )?;

    // Additional writable paths
    for p in &args.writable {
        let p = p.to_string_lossy();
        nix::mount::mount(
            Some("tmpfs"),
            p.as_ref(),
            Some("tmpfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            Some(format!("size={}", size).as_str()),
        )?;
    }

    Ok(())
}

fn setup_seccomp() -> crate::Result<()> {
    use seccompiler::SeccompAction;
    use seccompiler::SeccompCmpArgLen;
    use seccompiler::SeccompCmpOp;
    use seccompiler::SeccompCondition;
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

    // ptrace: block write ops, allow read ops
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
                0,
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
            format!("unsupported arch: {}", e)
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

pub fn run(args: Args) -> crate::Result<()> {
    // Resolve exe path before mounts change the FS
    let self_exe = if !args.no_shims {
        Some(std::fs::read_link("/proc/self/exe")?)
    } else {
        None
    };

    if let Err(_) = nix::sched::unshare(
        CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWPID,
    ) {
        eprintln!("ronly: requires root (or CAP_SYS_ADMIN)");
        std::process::exit(1);
    }

    match unsafe { nix::unistd::fork()? } {
        ForkResult::Parent { child } => {
            let status =
                nix::sys::wait::waitpid(child, None)?;
            let code = match status {
                nix::sys::wait::WaitStatus::Exited(
                    _, c,
                ) => c,
                _ => 1,
            };
            std::process::exit(code);
        }
        ForkResult::Child => {
            child_main(args, self_exe);
        }
    }
}

fn child_main(
    args: Args,
    self_exe: Option<std::path::PathBuf>,
) -> ! {
    if let Err(e) =
        setup_mounts(&args, self_exe.as_deref())
    {
        die(&format!("ronly: mounts: {}", e));
    }

    if self_exe.is_some() {
        // PATH: extra shims > built-in shims > system
        let sys_path =
            std::env::var("PATH").unwrap_or_default();
        let mut parts: Vec<String> = args
            .extra_shims
            .iter()
            .map(|d| d.to_string_lossy().into_owned())
            .collect();
        parts.push(shims::SHIMS_DIR.to_string());
        parts.push(sys_path);
        std::env::set_var("PATH", parts.join(":"));
    }

    if let Err(e) = setup_seccomp() {
        die(&format!("ronly: seccomp: {}", e));
    }

    // Default to $SHELL or /bin/bash
    let command = if args.command.is_empty() {
        vec![std::env::var("SHELL")
            .unwrap_or_else(|_| "/bin/bash".into())]
    } else {
        args.command
    };
    let argv: Vec<CString> = command
        .iter()
        .map(|s| CString::new(s.as_str()).unwrap())
        .collect();
    let argv_refs: Vec<&CString> = argv.iter().collect();
    nix::unistd::execvp(&argv[0], &argv_refs).unwrap();
    unreachable!()
}
