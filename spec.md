# rosshd — Read-Only SSH for Production Systems

## Problem

AI agents increasingly need to interact with production systems to diagnose issues — reading logs, checking process state, querying databases, inspecting Kubernetes clusters. But giving an agent full SSH access to a production machine is terrifying. One bad tool call and it's `rm -rf /` or `kill -9` on a critical process.

Today, teams solve this with ad-hoc approaches: LLM-based command review (slow, unreliable, expensive), manually curated command allowlists (brittle, incomplete), or just giving agents full access and hoping the prompt says "be careful." None of these are satisfactory.

`rosshd` is a standalone SSH server that provides **read-only access to a Linux system**. Agents (or humans) SSH in and get a shell that looks and feels completely normal — `top` works, `cat /var/log/syslog` works, `kubectl get pods` works — but any destructive operation is blocked at the kernel level. No LLM in the loop. No allowlists to maintain. The kernel just says no.

## Design Principles

**Kernel-level enforcement, not application-level filtering.** The security model does not depend on parsing commands, maintaining allowlists, or asking an LLM whether something is safe. Enforcement happens via Linux namespaces and seccomp-bpf, below the shell layer. No amount of prompt injection, shell escaping, or clever command chaining can bypass `unshare` and `seccomp`.

**Transparent to the user.** The agent doesn't need to know it's in a sandbox. Standard tools work. `top` shows real processes. `cat` reads real files. `kubectl` talks to the real cluster. The only observable difference is that writes fail — with a clear error message.

**Single binary, zero dependencies.** `rosshd` is a self-contained Rust binary. No runtime, no sidecar processes, no Go services to deploy on Kubernetes. You scp it onto a server, run it, and it works.

**Unopinionated about what "read-only" means for each tool.** The base layer (filesystem, processes, syscalls) is enforced by the kernel. Higher-level tools (Docker, kubectl, psql) are handled by shims that understand the tool's read/write semantics. Shims are small, auditable, and composable.

## Architecture

When a client connects to `rosshd`, the server authenticates via SSH keys, then forks a new session into a sandboxed environment composed of four isolation layers:

### Layer 1: Read-Only Filesystem (Mount Namespace)

The session runs in a new mount namespace. The host filesystem is bind-mounted read-only:

```
mount --bind -o ro / /sandbox/root
```

The agent can read any file on the system — logs, configs, `/proc`, `/sys` — but any write operation fails with `EROFS` (Read-only file system). This is enforced by the kernel's VFS layer. There is no command that can bypass a read-only mount from within the namespace.

A small tmpfs is mounted at `/tmp` and the user's home directory so the agent has scratch space for temporary files (e.g., command output piped to a file for processing). This tmpfs is size-limited (default: 64MB) and destroyed when the session ends.

### Layer 2: Process Isolation (PID Namespace)

The session runs in a new PID namespace, but the **host's `/proc` is bind-mounted read-only** into the sandbox. This gives the agent full visibility into host processes:

- `top`, `htop`, `ps aux` — all show real host processes with real PIDs, CPU, memory
- `cat /proc/<pid>/status` — works for any host process
- `kill <pid>` — fails, because the target PID doesn't exist in the agent's PID namespace

The agent sees everything. It can signal nothing.

### Layer 3: Syscall Filtering (seccomp-bpf)

A seccomp-bpf profile blocks destructive syscalls as a defense-in-depth backstop:

**Blocked:**
- `kill`, `tkill`, `tgkill` — can't signal processes
- `unlink`, `unlinkat`, `rmdir`, `rename`, `renameat`, `renameat2` — can't delete/move files (also blocked by read-only FS, but belt-and-suspenders)
- `truncate`, `ftruncate` — can't truncate files
- `mount`, `umount2` — can't modify mount table
- `reboot` — obvious
- `ptrace` (write operations) — can't attach to processes to modify them
- `open`/`openat` with `O_WRONLY`, `O_RDWR`, `O_CREAT`, `O_TRUNC` flags — blocked except on the tmpfs paths

**Explicitly allowed:**
- `perf_event_open` — needed for `perf top`, `perf stat`, `perf record`. Requires `CAP_PERFMON`. This is safe because perf can observe but never modify.
- `ptrace` (read-only, `PTRACE_ATTACH` + `PTRACE_PEEKDATA`) — enables read-only `strace`. The seccomp filter distinguishes read vs write ptrace operations.

### Layer 4: Network Containment (Network Namespace)

The session runs in a new network namespace with controlled outbound access to prevent data exfiltration:

- Outbound connections are routed through a lightweight local proxy
- The proxy enforces a destination allowlist configured by the admin
- Default: allow connections only to RFC 1918 / internal addresses, block public internet
- Configurable: `--allow-egress 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16`
- Inbound listening is blocked entirely — the agent cannot bind ports

This prevents an agent from reading sensitive files and exfiltrating them via `curl https://evil.com`.

## Tool Shims

The base isolation layers handle filesystem, processes, syscalls, and network. But many tools that agents use have their own read/write semantics that don't map cleanly onto filesystem operations. `rosshd` ships with **shims** — small wrapper scripts placed on the PATH that shadow real binaries and enforce read-only semantics at the application level.

### docker

The Docker socket (`/var/run/docker.sock`) is a REST API, not a file — read-only filesystem mounts don't restrict it. The `docker` shim intercepts Docker CLI commands:

**Allowed (pass-through to real Docker):**
`ps`, `logs`, `inspect`, `stats`, `top`, `images`, `network ls`, `network inspect`, `volume ls`, `volume inspect`, `info`, `version`, `events`, `diff`

**Blocked:**
`exec`, `run`, `stop`, `start`, `restart`, `kill`, `rm`, `rmi`, `pull`, `push`, `build`, `commit`, `tag`, `create`, `update`, `pause`, `unpause`, `attach`, `cp`, `export`, `import`, `load`, `save`, `deploy`, `service`, `stack`, `swarm`, `node`, `config`, `secret`, `plugin`, `system prune`, `network create`, `network rm`, `volume create`, `volume rm`

Everything not explicitly allowed is blocked by default.

### kubectl

The `kubectl` shim allows read-only Kubernetes operations:

**Allowed:**
`get`, `describe`, `logs`, `top`, `explain`, `api-resources`, `api-versions`, `cluster-info`, `config view`, `version`, `auth can-i`

**Blocked:**
`apply`, `create`, `delete`, `edit`, `patch`, `replace`, `rollout`, `scale`, `autoscale`, `expose`, `run`, `set`, `taint`, `drain`, `cordon`, `uncordon`, `label`, `annotate`, `exec`, `cp`, `attach`, `port-forward`

### psql / mysql

Database shims connect through a wrapper that forces read-only transactions:

- **psql:** Wraps the connection to issue `SET default_transaction_read_only = ON;` on connect. Any INSERT/UPDATE/DELETE/DROP/CREATE/ALTER fails at the database level. The agent can run arbitrary SELECT queries.
- **mysql:** Wraps with `SET SESSION TRANSACTION READ ONLY;`

This is enforced by the database server, not by parsing SQL. The agent can write any SQL it wants — the database rejects mutations.

### systemctl

**Allowed:** `status`, `list-units`, `list-unit-files`, `show`, `is-active`, `is-enabled`, `is-failed`, `cat`

**Blocked:** `start`, `stop`, `restart`, `reload`, `enable`, `disable`, `mask`, `unmask`, `daemon-reload`, `edit`, `set-property`, `kill`, `reset-failed`

### General pattern

Each shim follows the same pattern:
1. Parse the subcommand from the CLI arguments
2. Check against an allowlist of read-only subcommands
3. If allowed, exec the real binary with the original arguments
4. If blocked, print `rosshd: <tool> <subcommand> is blocked (read-only session)` and exit 1

Shims are intentionally simple — typically 20-50 lines of shell script. They are auditable by anyone.

### Custom shims

Admins can add custom shims for tools specific to their environment by placing scripts in `/etc/rosshd/shims/`. These are prepended to the PATH alongside the built-in shims.

## Configuration

`rosshd` is configured via command-line flags and an optional config file. It does **not** read `sshd_config` — the standard sshd configuration model is deeply tied to OpenSSH internals (PAM, privilege separation, subsystems) that don't apply here. Sharing the config would create confusion about which options are honored.

### Command-line

```
rosshd \
  --port 2222 \
  --host-key /etc/rosshd/host_key \
  --authorized-keys /etc/rosshd/authorized_keys \
  --allow-egress 10.0.0.0/8,172.16.0.0/12 \
  --tmpfs-size 64M \
  --shims /etc/rosshd/shims \
  --log /var/log/rosshd.log
```

### Config file (/etc/rosshd/config.toml)

```toml
port = 2222
host_key = "/etc/rosshd/host_key"
authorized_keys = "/etc/rosshd/authorized_keys"

[network]
allow_egress = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

[filesystem]
tmpfs_size = "64M"
# Additional read-write paths (mounted as tmpfs overlays)
writable_paths = ["/tmp"]

[shims]
# Built-in shims are always loaded
# Additional shim directories:
extra = ["/etc/rosshd/shims"]

[capabilities]
# Additional Linux capabilities to grant
# Default: CAP_PERFMON only
allow = ["CAP_PERFMON"]

[logging]
file = "/var/log/rosshd.log"
# Log all commands executed in the session
audit_commands = true
```

### Auth

`rosshd` uses SSH public key authentication only. No passwords, no PAM, no certificates (in MVP). The `authorized_keys` file uses the same format as OpenSSH's `~/.ssh/authorized_keys`. This means existing SSH keys work with zero setup — if an agent can SSH into a machine today, it can SSH into `rosshd` by adding its public key.

## Error Handling

When rosshd blocks an operation, the error messages are clear and machine-parseable:

```
$ rm /etc/hosts
rosshd: write operation blocked (read-only filesystem)

$ kill 1234
rosshd: kill syscall blocked (read-only session)

$ docker exec -it abc123 bash
rosshd: docker exec is blocked (read-only session)

$ kubectl delete pod my-pod
rosshd: kubectl delete is blocked (read-only session)
```

All blocked operations are logged to the audit log with timestamp, session ID, user, and the full command attempted.

## Audit Logging

Every session is logged:

```json
{
  "timestamp": "2026-03-23T10:15:30Z",
  "session_id": "a1b2c3d4",
  "user": "agent-kaju",
  "client_ip": "10.0.1.50",
  "event": "command",
  "command": "kubectl get pods -n production",
  "result": "allowed"
}
```

```json
{
  "timestamp": "2026-03-23T10:15:35Z",
  "session_id": "a1b2c3d4",
  "user": "agent-kaju",
  "client_ip": "10.0.1.50",
  "event": "command",
  "command": "kubectl delete pod payment-svc-7f8b9",
  "result": "blocked",
  "reason": "kubectl delete is not in read-only allowlist"
}
```

This gives full visibility into what agents are doing and attempting to do on production systems.

## MVP — What to Build First

The MVP should be useful for Deno's own agents (Kaju, Avocet) within a week of development. It should be a single Rust binary that can be built with `cargo build` and deployed by copying it onto a server.

### MVP Scope

**In scope:**
- SSH server (using `russh` crate) with public key authentication
- Read-only filesystem via mount namespace
- PID namespace with host `/proc` mounted read-only
- seccomp-bpf filter blocking destructive syscalls (with `CAP_PERFMON` allowed)
- Writable `/tmp` on tmpfs
- Shims for `docker` and `kubectl` (the two most common tools our agents use)
- Basic command audit logging to stdout/file
- `--port`, `--host-key`, `--authorized-keys` flags

**Deferred to v2:**
- Network namespace / egress filtering
- Database shims (psql, mysql)
- systemctl shim
- Config file (flags only in MVP)
- Custom shim directories
- Session recording / replay

### MVP Implementation Notes

**Rust crates:**
- `russh` — SSH server implementation
- `nix` — Linux namespace and syscall wrappers
- `seccompiler` or `libseccomp` — seccomp-bpf filter construction
- `clap` — CLI argument parsing
- `tokio` — async runtime (required by russh)

**Session setup sequence:**
1. Client connects, authenticates via public key
2. Server forks
3. Child calls `unshare(CLONE_NEWNS | CLONE_NEWPID)`
4. Remount `/` as read-only bind mount
5. Mount tmpfs at `/tmp` (size-limited)
6. Bind-mount host `/proc` read-only
7. Prepend `/usr/lib/rosshd/shims` to PATH
8. Load seccomp-bpf filter
9. Exec user's shell (from `$SHELL` or `/bin/bash`)

**Shim implementation (MVP):**
Shims are statically compiled shell scripts bundled into the binary and extracted to a tmpfs at startup. Each shim is ~20 lines.

Example `docker` shim:
```bash
#!/bin/sh
case "$1" in
  ps|logs|inspect|stats|top|images|info|version|events)
    exec /usr/bin/docker "$@"
    ;;
  *)
    echo "rosshd: docker $1 is blocked (read-only session)" >&2
    exit 1
    ;;
esac
```

### MVP Validation

Test by:
1. Deploy rosshd on a dev machine running our staging Kubernetes cluster
2. Point Kaju at it (configure as SSH endpoint for diagnostic tool calls)
3. Verify: `top`, `ps`, `kubectl get pods`, `docker ps`, `docker logs`, `cat` log files all work
4. Verify: `rm`, `kill`, `kubectl delete`, `docker exec`, `docker stop` all fail with clear errors
5. Run a simulated PagerDuty investigation through the agent and confirm it can gather sufficient diagnostic information

### What Success Looks Like

An agent can SSH into a production machine via rosshd and perform a full diagnostic investigation — check process state, read logs, query Kubernetes, inspect Docker containers, run perf — without any possibility of modifying the system. The admin's confidence that the agent cannot cause harm is based on kernel enforcement, not on trusting the agent's prompt or an LLM-based reviewer.

## Implementation Status (2026-03-23)

### What's Done

The MVP core is working. Single binary, tested on aarch64 Linux
via lima:

- SSH server (`russh` 0.58) with pubkey auth
- Read-only filesystem via `unshare(CLONE_NEWNS)` + remount
- seccomp-bpf blocking kill, unlink, rename, truncate, mount,
  reboot, ptrace (via `seccompiler`)
- Writable `/tmp` on tmpfs (configurable size)
- Docker shim (ps/logs/inspect/stats/top/images/info/version/
  events/diff allowed; everything else blocked)
- kubectl shim (get/describe/logs/top/explain/version/
  cluster-info/api-resources/api-versions/config view/auth can-i
  allowed; everything else blocked)
- JSON audit logging to stdout
- Host key auto-generation via ssh-keygen
- Exec mode uses pipes (clean output), shell mode uses PTY
- CLI: `--port`, `--host-key`, `--authorized-keys`,
  `--tmpfs-size-mb`, `--log`

### What's Missing from MVP Spec

**PID namespace.** Spec calls for `CLONE_NEWPID` so `kill <pid>`
fails because the PID doesn't exist in the agent's namespace.
Currently deferred — seccomp blocks kill syscalls as defense, but
this removes a layer of defense-in-depth. The complication is that
`CLONE_NEWPID` requires a double-fork (child becomes init) and
breaks subprocesses (shims can't fork). Need to either:
- Fork twice: unshare(CLONE_NEWPID), fork, grandchild execs shell
- Or use clone3() with CLONE_NEWPID directly

**seccomp gaps:**
- No `open`/`openat` flag filtering (O_WRONLY, O_RDWR, O_CREAT,
  O_TRUNC blocked on non-tmpfs paths). Read-only FS handles this
  but seccomp would be belt-and-suspenders.
- `perf_event_open` not explicitly allowed (spec wants CAP_PERFMON
  support for `perf top`/`perf stat`)
- `ptrace` blocked entirely — spec wants read-only ptrace
  (PTRACE_ATTACH + PTRACE_PEEKDATA) for `strace`

**Audit logging:** Logs every command as "allowed" — doesn't
distinguish commands that were blocked by shims. Would need
shim-level reporting or shell exit code tracking.

**No tests.** Zero unit tests, zero integration tests.

### Roadmap

#### Phase 1: Hardening (next)

1. **Integration tests.** Spawn rosshd in a test, SSH in, verify:
   - Read commands work (echo, cat, ps, ls)
   - Write ops blocked (rm, touch, kill)
   - Shims work (docker ps allowed, docker exec blocked)
   - Exit codes propagated correctly
   - Audit log entries emitted
   Use `russh` client in-process or shell out to `ssh`.
   Run via `cargo test` — needs root, so guard with
   `#[cfg(test)]` + check for CAP_SYS_ADMIN.

2. **PID namespace.** Double-fork approach: unshare NEWPID in
   child, fork again, grandchild execs shell. Bind-mount host
   /proc read-only into sandbox so `ps`/`top` show real
   processes but `kill` fails at the namespace level.

3. **seccomp open/openat filtering.** Block O_WRONLY/O_RDWR/
   O_CREAT/O_TRUNC on openat, except when path is under /tmp
   or shims dir. Requires seccomp argument inspection on the
   flags arg (arg index 2 for openat).

4. **Allow perf_event_open and read-only ptrace.** Add seccomp
   rules that allow perf_event_open unconditionally and ptrace
   only with PTRACE_PEEKDATA/PTRACE_PEEKTEXT requests.

#### Phase 2: Usability

5. **Config file.** `/etc/rosshd/config.toml` with TOML parsing.
   CLI flags override config. Add `[filesystem].writable_paths`
   for additional tmpfs overlays.

6. **Custom shim directories.** `--shims /etc/rosshd/shims`
   flag. Prepend custom shims to PATH before built-in shims.

7. **systemctl shim.** Allow status/list-units/list-unit-files/
   show/is-active/is-enabled/is-failed/cat. Block everything
   else.

8. **Audit log improvements.** Log to file (not just stdout).
   Track shim block events. Include exit codes in audit entries.

#### Phase 3: Network & Database (v2)

9. **Network namespace.** New network namespace with veth pair.
   Lightweight proxy for egress filtering. Default: allow
   RFC 1918 only. `--allow-egress` flag.

10. **Database shims.** psql wrapper that forces
    `default_transaction_read_only = ON`. mysql wrapper that
    forces `SET SESSION TRANSACTION READ ONLY`.

11. **Session recording.** Record all I/O for replay. Store as
    asciicast or custom format.

## Future Directions

**As a product:** Every company deploying AI agents to production will need something like rosshd. The current alternatives (full access, LLM-based review, manual allowlists) are all inadequate. A single-binary tool that provides guaranteed read-only access with zero configuration overhead could see broad adoption.

**Expanded protocol support:** The shim model extends naturally to any CLI tool with read/write subcommands. Community-contributed shims for cloud CLIs (aws, gcloud, az), database clients, monitoring tools, etc.

**Agent-aware features:** Session sharing (multiple agents investigating the same incident can share a session), automatic context extraction (rosshd observes what the agent reads and builds a summary), integration with agent frameworks for structured tool-call results.

**Managed service:** A hosted version where you connect your infrastructure and get rosshd endpoints without deploying anything. This would pair naturally with Deno Deploy as the hosting layer.
