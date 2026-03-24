use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::os::fd::OwnedFd;
use std::sync::Arc;

use anyhow::Result;
use log::error;
use log::info;
use russh::keys::load_secret_key;
use russh::keys::parse_public_key_base64;
use russh::keys::PublicKey;
use russh::server::Auth;
use russh::server::Handler;
use russh::server::Msg;
use russh::server::Server;
use russh::server::Session;
use russh::Channel;
use crate::audit::AuditEntry;
use crate::Args;

struct SshroServer {
    authorized_keys: Arc<Vec<PublicKey>>,
    args: Args,
}

impl Server for SshroServer {
    type Handler = SshroHandler;

    fn new_client(
        &mut self,
        addr: Option<SocketAddr>,
    ) -> SshroHandler {
        let session_id = crate::audit::new_session_id();
        info!(
            "new client from {:?} session={}",
            addr, session_id
        );
        SshroHandler {
            session_id,
            user: String::new(),
            addr,
            authorized_keys: self.authorized_keys.clone(),
            tmpfs_size_mb: self.args.tmpfs_size_mb,
        }
    }

    fn handle_session_error(
        &mut self,
        error: <Self::Handler as Handler>::Error,
    ) {
        error!("session error: {}", error);
    }
}

struct SshroHandler {
    session_id: String,
    user: String,
    addr: Option<SocketAddr>,
    authorized_keys: Arc<Vec<PublicKey>>,
    tmpfs_size_mb: u64,
}

impl Handler for SshroHandler {
    type Error = anyhow::Error;

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: &PublicKey,
    ) -> Result<Auth> {
        let accepted =
            self.authorized_keys.iter().any(|k| k == key);
        if accepted {
            self.user = user.to_string();
            AuditEntry::log(
                &self.session_id,
                user,
                self.addr,
                "auth",
                "",
                "accepted",
                None,
            );
            Ok(Auth::Accept)
        } else {
            AuditEntry::log(
                &self.session_id,
                user,
                self.addr,
                "auth",
                "",
                "rejected",
                Some("key not in authorized_keys"),
            );
            Ok(Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            })
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool> {
        let session_id = self.session_id.clone();
        let user = self.user.clone();
        let addr = self.addr;
        let tmpfs_size_mb = self.tmpfs_size_mb;

        tokio::spawn(async move {
            if let Err(e) = handle_channel(
                channel,
                session_id.clone(),
                user.clone(),
                addr,
                tmpfs_size_mb,
            )
            .await
            {
                error!(
                    "channel err session={} user={}: {}",
                    session_id, user, e
                );
            }
        });

        Ok(true)
    }
}

async fn handle_channel(
    mut channel: Channel<Msg>,
    session_id: String,
    user: String,
    addr: Option<SocketAddr>,
    tmpfs_size_mb: u64,
) -> Result<()> {
    use tokio::io::unix::AsyncFd;

    // Wait for shell/exec request
    loop {
        match channel.wait().await {
            Some(russh::ChannelMsg::Exec {
                command,
                ..
            }) => {
                let cmd =
                    String::from_utf8_lossy(&command)
                        .to_string();
                AuditEntry::log(
                    &session_id,
                    &user,
                    addr,
                    "command",
                    &cmd,
                    "allowed",
                    None,
                );
                let (child, stdout_fd, _stdin_fd) =
                    crate::sandbox::spawn_exec(
                        tmpfs_size_mb,
                        &cmd,
                    )?;
                set_nonblocking(&stdout_fd);
                relay_pipe(
                    stdout_fd,
                    &mut channel,
                )
                .await?;
                wait_and_exit(child, &channel).await?;
                channel.eof().await?;
                channel.close().await?;
                return Ok(());
            }
            Some(russh::ChannelMsg::RequestShell {
                ..
            }) => {
                AuditEntry::log(
                    &session_id,
                    &user,
                    addr,
                    "shell",
                    "",
                    "allowed",
                    None,
                );
                let (child, master) =
                    crate::sandbox::spawn_shell(
                        tmpfs_size_mb,
                        None,
                    )?;
                set_nonblocking(&master);
                let afd = AsyncFd::new(master)?;
                relay_pty(
                    afd,
                    &mut channel,
                )
                .await?;
                wait_and_exit(child, &channel).await?;
                channel.eof().await?;
                channel.close().await?;
                return Ok(());
            }
            Some(russh::ChannelMsg::RequestPty {
                ..
            }) => {
                // Accept PTY request, continue waiting
            }
            Some(russh::ChannelMsg::SetEnv { .. }) => {}
            Some(russh::ChannelMsg::WindowAdjusted {
                ..
            }) => {}
            None => return Ok(()),
            Some(other) => {
                info!("pre-shell msg: {:?}", other);
            }
        }
    }
}

/// Relay data from a pipe (exec mode, no input).
async fn relay_pipe(
    stdout_fd: OwnedFd,
    channel: &mut Channel<Msg>,
) -> Result<()> {
    use tokio::io::unix::AsyncFd;

    let afd = AsyncFd::new(stdout_fd)?;
    let mut buf = [0u8; 4096];

    loop {
        let readable = afd.readable().await?;
        let mut guard = readable;
        match guard.try_io(|fd| {
            let n = unsafe {
                libc::read(
                    fd.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            if n < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }) {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                channel.data(&buf[..n]).await?;
            }
            Ok(Err(e)) => {
                if e.raw_os_error() == Some(libc::EIO) {
                    break;
                }
                return Err(e.into());
            }
            Err(_would_block) => continue,
        }
    }

    Ok(())
}

/// Relay data between PTY and channel (shell mode).
async fn relay_pty(
    afd: tokio::io::unix::AsyncFd<OwnedFd>,
    channel: &mut Channel<Msg>,
) -> Result<()> {
    let mut buf = [0u8; 4096];

    loop {
        tokio::select! {
            readable = afd.readable() => {
                let mut guard = readable?;
                match guard.try_io(|fd| {
                    let n = unsafe {
                        libc::read(
                            fd.as_raw_fd(),
                            buf.as_mut_ptr()
                                as *mut libc::c_void,
                            buf.len(),
                        )
                    };
                    if n < 0 {
                        Err(
                            std::io::Error
                                ::last_os_error()
                        )
                    } else {
                        Ok(n as usize)
                    }
                }) {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => {
                        channel.data(
                            &buf[..n]
                        ).await?;
                    }
                    Ok(Err(e)) => {
                        if e.raw_os_error()
                            == Some(libc::EIO)
                        {
                            break;
                        }
                        return Err(e.into());
                    }
                    Err(_) => continue,
                }
            }
            msg = channel.wait() => {
                match msg {
                    Some(
                        russh::ChannelMsg::Data { data }
                    ) => {
                        let fd = afd.as_raw_fd();
                        unsafe {
                            libc::write(
                                fd,
                                data.as_ptr()
                                    as *const _,
                                data.len(),
                            );
                        }
                    }
                    Some(
                        russh::ChannelMsg::Eof
                    ) | None => break,
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

#[cfg(target_os = "linux")]
async fn wait_and_exit(
    child: nix::unistd::Pid,
    channel: &Channel<Msg>,
) -> Result<()> {
    let status = tokio::task::spawn_blocking(move || {
        nix::sys::wait::waitpid(child, None)
    })
    .await??;
    let code = match status {
        nix::sys::wait::WaitStatus::Exited(_, c) => {
            c as u32
        }
        _ => 1,
    };
    channel.exit_status(code).await?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
async fn wait_and_exit(
    _child: u32,
    _channel: &Channel<Msg>,
) -> Result<()> {
    Ok(())
}

fn set_nonblocking(fd: &OwnedFd) {
    let raw = fd.as_raw_fd();
    unsafe {
        let flags = libc::fcntl(raw, libc::F_GETFL);
        libc::fcntl(
            raw,
            libc::F_SETFL,
            flags | libc::O_NONBLOCK,
        );
    }
}

fn load_authorized_keys(
    path: &std::path::Path,
) -> Result<Vec<PublicKey>> {
    let content = std::fs::read_to_string(path)?;
    let mut keys = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> =
            line.splitn(3, ' ').collect();
        if parts.len() >= 2 {
            match parse_public_key_base64(parts[1]) {
                Ok(key) => keys.push(key),
                Err(e) => {
                    log::warn!(
                        "skipping key: {} ({})",
                        &line[..40.min(line.len())],
                        e
                    );
                }
            }
        }
    }
    info!("loaded {} authorized keys", keys.len());
    Ok(keys)
}

pub async fn run(args: Args) -> Result<()> {
    if !args.host_key.exists() {
        info!(
            "generating host key at {}",
            args.host_key.display()
        );
        if let Some(parent) = args.host_key.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let status =
            std::process::Command::new("ssh-keygen")
                .args([
                    "-t",
                    "ed25519",
                    "-f",
                    &args.host_key.to_string_lossy(),
                    "-N",
                    "",
                    "-q",
                ])
                .status()?;
        anyhow::ensure!(
            status.success(),
            "ssh-keygen failed"
        );
    }
    let host_key =
        load_secret_key(&args.host_key, None)?;

    let authorized_keys =
        load_authorized_keys(&args.authorized_keys)?;

    let config = russh::server::Config {
        keys: vec![host_key],
        ..Default::default()
    };

    let port = args.port;
    let mut server = SshroServer {
        authorized_keys: Arc::new(authorized_keys),
        args,
    };

    info!("rosshd listening on 0.0.0.0:{}", port);
    server
        .run_on_address(
            Arc::new(config),
            ("0.0.0.0", port),
        )
        .await?;

    Ok(())
}
