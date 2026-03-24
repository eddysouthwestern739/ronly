# ronly — Read-Only Sandbox

linux only

## Problem

AI agents need to interact with production systems to diagnose issues. They need to read logs, check process state, query Kubernetes, inspect Docker containers, run perf. But giving an agent an unrestricted shell is dangerous — one bad tool call and it's `rm -rf /` or `kill -9` on a critical process.

Current approaches are all inadequate:

- **LLM-based command review:** Slow, expensive, unreliable. An LLM judging whether `bash -c "$(curl ...)"` is safe is not a security model.
- **Command allowlists:** Brittle and incomplete. Miss edge cases, need constant maintenance, can be bypassed with pipes and subshells.
- **"Just trust the prompt:"** Not a real answer.

`ronly` is a single binary that creates a read-only sandbox and then execs your real shell inside it. Bash, zsh, fish — whatever you want. All shell features work normally. The only difference is that destructive operations are blocked at the kernel level. No LLM in the loop. No allowlists to maintain. The kernel just says no.

## What It Is

`ronly` is not a shell. It's a **jail that runs your shell inside it.**

```
ronly                        # launch $SHELL in read-only sandbox
ronly bash                   # launch bash specifically
ronly zsh                    # launch zsh
ronly fish                   # launch fish
ronly -- top                 # run a single command and exit
ronly -- kubectl get pods    # same, single command mode
```

The sequence:

1. `ronly` is invoked
2. Creates a mount namespace (user namespace for rootless, or privileged)
3. Remounts the filesystem read-only
4. Mounts a small writable tmpfs at `/tmp`
5. Copies shims into `/tmp`, prepends to `$PATH`
6. Loads seccomp-bpf filter (blocks kill, unlink, mount, etc.)
7. Execs the real shell

After step 7, `ronly` is gone — replaced by the shell process via `execve`. It doesn't interpret commands, doesn't sit in the middle, doesn't add latency. It just builds the cage and then gets out of the way.

## How It Composes

Because `ronly` is just a binary that wraps a shell, it works everywhere a shell works:

**SSH:** Set `ForceCommand /usr/local/bin/ronly` in your existing `sshd_config`. Your normal sshd handles auth, transport, key management. `ronly` handles the sandbox. No custom SSH server needed.

```
# /etc/ssh/sshd_config
Match User agent-kaju
    ForceCommand /usr/local/bin/ronly bash
```

**Kubernetes:** Use `ronly` as the entrypoint in a debug pod, or invoke it via `kubectl exec`:

```
kubectl exec -it debug-pod -- /usr/local/bin/ronly bash
```

Or bake it into a debug container image:

```dockerfile
FROM ubuntu:24.04
COPY ronly /usr/local/bin/ronly
ENTRYPOINT ["/usr/local/bin/ronly", "bash"]
```

**Agent frameworks:** Any agent that spawns shell processes can use `ronly` as the wrapper:

```typescript
// In agentd, OpenClaw, or any agent framework
const proc = spawn("ronly", ["bash", "-c", command]);
```

**Direct invocation:** A human can just run `ronly` on any machine to drop into a read-only session for safe exploration.

## Isolation Layers

### Layer 1: Read-Only Filesystem (Mount Namespace)

`ronly` creates a new mount namespace and remounts the root filesystem read-only (non-recursive, so `/proc` stays functional):

```
unshare(CLONE_NEWNS)       # or CLONE_NEWUSER | CLONE_NEWNS for rootless
mount --bind -o ro,remount / /
```

The agent can read everything — logs, configs, source code, `/proc`, `/sys`. Any write fails with `EROFS` (Read-only file system). This is enforced by the VFS layer in the kernel. No shell escape, pipe chain, or subshell can bypass a read-only mount from within the namespace.

A small tmpfs is mounted at `/tmp` (default 64MB, configurable) so the agent has scratch space. Command history, pipe buffers, temporary files all work. The tmpfs is destroyed when the session ends.

```
mount -t tmpfs -o size=64M tmpfs /tmp
```

**Why no PID namespace:** The original design used `CLONE_NEWPID` to isolate processes, but this requires remounting `/proc` as a fresh procfs — which only shows processes inside the sandbox, breaking the core use case of `top` and `ps` showing host processes. In containers, `/proc` remounts are also blocked by many runtimes. Instead, `kill` is blocked by seccomp, which is sufficient.

### Layer 2: Syscall Filtering (seccomp-bpf)

A seccomp-bpf profile blocks destructive syscalls as a defense-in-depth backstop.

**Blocked:**

| Syscall | Why |
|---------|-----|
| `kill`, `tkill`, `tgkill` | Can't signal host processes |
| `unlink`, `unlinkat`, `rmdir` | Can't delete (also blocked by ro fs) |
| `rename`, `renameat`, `renameat2` | Can't move files |
| `truncate`, `ftruncate` | Can't truncate |
| `mount`, `umount2` | Can't modify mounts |
| `reboot` | Obvious |
| `open`/`openat` with write flags | Blocked except on tmpfs paths |

**Explicitly allowed:**

| Syscall | Why |
|---------|-----|
| `perf_event_open` | Needed for `perf top`, `perf stat`. Requires `CAP_PERFMON`. Can observe, never modify. |
| `ptrace` (read ops only) | Enables read-only `strace`. Write operations filtered out. |

The seccomp filter complements the read-only filesystem. The filesystem blocks file modifications; seccomp blocks operations that don't touch the filesystem (like `kill`, which works via syscall, not file I/O).

### Rootless Operation

`ronly` supports two modes:

- **Rootless (default):** Uses `CLONE_NEWUSER` to create a user namespace. No root required. Works on any kernel 4.6+ with unprivileged user namespaces enabled (Debian 11+, RHEL 8+, Ubuntu 16.04+). Note: Ubuntu 24.04's AppArmor restricts unprivileged userns by default — requires `kernel.apparmor_restrict_unprivileged_userns=0` or an AppArmor profile.
- **Privileged:** Uses `CLONE_NEWNS` directly. Requires root or `CAP_SYS_ADMIN`. Needed in environments that disable unprivileged user namespaces (hardened servers, some container runtimes).

By default, ronly tries rootless first and falls back to privileged. Use `--rootless` or `--privileged` to force a mode. The active mode is printed to stderr.

### Interaction of Layers

The layers are redundant by design. To delete a file, an agent would need to bypass the read-only mount (layer 1) AND the seccomp filter blocking `unlink` (layer 2). To kill a host process, the agent would need to bypass the seccomp filter blocking `kill`. No single layer failing compromises the system.

## Tool Shims

The kernel-level isolation handles filesystem, processes, and syscalls. But some tools have their own read/write semantics that bypass the filesystem — they talk to sockets, APIs, or daemons directly. `ronly` ships with **shims**: small wrapper scripts placed ahead of the real binaries on `$PATH`.

### docker

The Docker socket (`/var/run/docker.sock`) is a REST API. Read-only filesystem mounts don't restrict API calls over a socket. The `docker` shim intercepts CLI commands:

```bash
#!/bin/sh
# /usr/lib/ronly/shims/docker
case "$1" in
  ps|logs|inspect|stats|top|images|info|version|events|diff)
    exec /usr/bin/docker "$@" ;;
  network)
    case "$2" in
      ls|inspect) exec /usr/bin/docker "$@" ;;
      *) echo "ronly: docker network $2 is blocked (read-only session)" >&2; exit 1 ;;
    esac ;;
  volume)
    case "$2" in
      ls|inspect) exec /usr/bin/docker "$@" ;;
      *) echo "ronly: docker volume $2 is blocked (read-only session)" >&2; exit 1 ;;
    esac ;;
  *)
    echo "ronly: docker $1 is blocked (read-only session)" >&2; exit 1 ;;
esac
```

### kubectl

```bash
#!/bin/sh
# /usr/lib/ronly/shims/kubectl
case "$1" in
  get|describe|logs|top|explain|api-resources|api-versions|cluster-info|version)
    exec /usr/bin/kubectl "$@" ;;
  config)
    case "$2" in
      view|current-context|get-contexts) exec /usr/bin/kubectl "$@" ;;
      *) echo "ronly: kubectl config $2 is blocked (read-only session)" >&2; exit 1 ;;
    esac ;;
  auth)
    case "$2" in
      can-i|whoami) exec /usr/bin/kubectl "$@" ;;
      *) echo "ronly: kubectl auth $2 is blocked (read-only session)" >&2; exit 1 ;;
    esac ;;
  *)
    echo "ronly: kubectl $1 is blocked (read-only session)" >&2; exit 1 ;;
esac
```

### systemctl

```bash
#!/bin/sh
# /usr/lib/ronly/shims/systemctl
case "$1" in
  status|list-units|list-unit-files|show|is-active|is-enabled|is-failed|cat)
    exec /usr/bin/systemctl "$@" ;;
  *)
    echo "ronly: systemctl $1 is blocked (read-only session)" >&2; exit 1 ;;
esac
```

### psql

Database shims force read-only transactions at the database level:

```bash
#!/bin/sh
# /usr/lib/ronly/shims/psql
# Prepend a read-only transaction setting to any psql invocation
# The database server enforces this — no SQL parsing needed
exec /usr/bin/psql -c "SET default_transaction_read_only = ON;" "$@"
```

Note: this simple approach works for interactive sessions. A more robust version would use a `.psqlrc`-based approach or a libpq wrapper. Deferred to v2.

### Design principles for shims

- Shims are **simple case statements**, not parsers. They match the first subcommand and allow or deny. They don't try to understand flags or arguments beyond the verb.
- Shims **exec the real binary** when allowed. No proxying, no modification of arguments, no overhead.
- Shims **fail closed**. Any subcommand not explicitly allowlisted is blocked.
- Shims produce **clear, prefixed error messages**: `ronly: <tool> <subcommand> is blocked (read-only session)`. Easily grep-able, easily parsed by LLMs.
- Shims are **small and auditable**. Each one is 10-30 lines of shell.

### Custom shims

Admins can add shims for their own tools:

```
ronly --extra-shims /opt/mycompany/ronly-shims bash
```

Scripts in the directory follow the same pattern: named after the binary they shadow, placed on PATH ahead of the real binary.

## Configuration

`ronly` is configured entirely via command-line flags. No config file in the MVP.

```
ronly [OPTIONS] [SHELL] [-- COMMAND...]

Arguments:
  SHELL                Shell to exec (default: $SHELL, fallback: /bin/bash)
  COMMAND              Run a single command instead of interactive shell

Options:
  --tmpfs-size SIZE    Size of writable /tmp (default: 64M)
  --extra-shims DIR    Additional shim directory
  --no-shims           Disable all shims (kernel isolation only)
  --allow-cap CAP      Grant additional Linux capability (can repeat)
  --writable PATH      Additional writable tmpfs overlay (can repeat)
  --audit              Log all executed commands to stderr
  --version            Print version
  --help               Print help
```

Examples:

```bash
# Basic read-only shell
ronly

# Read-only shell with perf support (on by default, but explicit)
ronly --allow-cap CAP_PERFMON

# Run a single diagnostic command
ronly -- kubectl get pods -A

# Use with SSH
# In sshd_config: ForceCommand /usr/local/bin/ronly bash

# Use with kubectl exec
kubectl exec -it pod -- /usr/local/bin/ronly

# Give the agent a writable workspace for scratch files beyond /tmp
ronly --writable /home/agent/workspace

# Add company-specific shims
ronly --extra-shims /opt/shims bash

# Audit mode for reviewing what agents do
ronly --audit 2>/var/log/ronly-audit.log
```

## Audit Logging

When `--audit` is enabled, `ronly` logs all commands to stderr (which can be redirected to a file). The audit log captures what happens inside the shell by using bash's `PROMPT_COMMAND` / `trap DEBUG` mechanism (for bash) or equivalent shell hooks.

```
2026-03-23T10:15:30Z [ronly] session start user=agent-kaju shell=/bin/bash
2026-03-23T10:15:31Z [ronly] cmd: kubectl get pods -n production
2026-03-23T10:15:32Z [ronly] cmd: docker logs payment-svc-7f8b9 --tail 100
2026-03-23T10:15:35Z [ronly] cmd: kubectl delete pod payment-svc-7f8b9
2026-03-23T10:15:35Z [ronly] blocked: kubectl delete (read-only session)
2026-03-23T10:20:00Z [ronly] session end duration=270s
```

## Trust Model

`ronly` protects against:

- **Accidental destruction.** An agent that tries to `rm`, `kill`, restart, or modify anything. The primary use case.
- **Prompt injection leading to destructive commands.** Even if an attacker injects "now run rm -rf /" into context the agent reads, the kernel blocks it.
- **Shell escapes and creative bypasses.** Pipes, subshells, backticks, `$(...)`, `eval`, `exec` — none of these can bypass a read-only mount or a seccomp filter. The agent has a real shell with full syntax; the enforcement is below the shell layer.
- **Shim bypasses via absolute paths.** If an agent runs `/usr/bin/docker exec` instead of `docker exec`, it bypasses the shim. This is addressed by also restricting the Docker socket itself — see "Known Limitations" below.

`ronly` does NOT protect against:

- **Data exfiltration.** The agent can read sensitive files and transmit their contents over the network. The MVP does not include network namespace isolation. This is deferred to v2.
- **Resource exhaustion.** The agent could fork-bomb or consume excessive CPU/memory. This can be mitigated externally with cgroups or container resource limits. `ronly` doesn't manage this in the MVP.
- **Socket-based writes bypassing shims.** If the agent knows the Docker socket path and uses raw HTTP over the socket (e.g., `curl --unix-socket /var/run/docker.sock ...`), it can bypass the Docker shim. Mitigation: mount the Docker socket through a read-only proxy (see Future Work), or don't expose the socket at all if Docker write access is a concern.
- **Kernel exploits.** If the kernel has a privilege escalation vulnerability, namespaces and seccomp can potentially be escaped. This is true of all container-based isolation. Keep the kernel patched.

The shims are a **usability layer**, not a security boundary. The real security comes from namespaces and seccomp. Shims exist to give clear error messages and to handle tools that talk to sockets/APIs rather than the filesystem. For tools where the shim can be bypassed (Docker, databases), admins should also apply the appropriate external controls (read-only socket proxy, read-only DB user) if the threat model requires it.

## MVP

### Scope

**Build:**
- Mount namespace with read-only root and writable `/tmp`
- Rootless via user namespaces, privileged fallback
- seccomp-bpf filter (kill, unlink, mount, etc. blocked)
- Shims for `docker` and `kubectl` (copy + hard-link into /tmp)
- Single command mode (`ronly -- command`)
- Interactive mode (`ronly` / `ronly bash` / `ronly zsh`)

**Don't build:**
- Network namespace / egress filtering
- Database shims (psql, mysql)
- systemctl shim
- Config file
- Session recording / replay
- Custom shim directories (just `--extra-shims`)

### Implementation

Rust. Estimated ~500-800 lines of actual logic.

**Crates:**
- `nix` — namespace and mount wrappers (`unshare`, `mount`)
- `seccompiler` — seccomp-bpf filter construction
- `lexopt` — minimal CLI argument parsing

Note: no async runtime needed. `ronly` does synchronous setup and then execs. No SSH server, no event loop, no tokio.

**Build:**
```
cargo build --release
# produces a single static binary
```

**Install:**
```
cp target/release/ronly /usr/local/bin/ronly
# or: cargo install ronly
```

### What the Implementation Looks Like

Pseudocode for the core:

```rust
fn main() {
    let args = parse_args();

    // 1. Create mount namespace (try rootless first)
    //    Rootless: CLONE_NEWUSER | CLONE_NEWNS
    //    Privileged: CLONE_NEWNS (requires root)
    unshare(namespace_flags)?;

    // 2. If rootless, set up uid/gid mapping
    if rootless {
        write("/proc/self/setgroups", "deny");
        write("/proc/self/uid_map", "0 <real_uid> 1");
        write("/proc/self/gid_map", "0 <real_gid> 1");
    }

    // 3. Remount root read-only (non-recursive)
    mount_readonly("/")?;

    // 4. Mount tmpfs at /tmp
    mount_tmpfs("/tmp", &args.tmpfs_size)?;

    // 5. Copy shims into /tmp, prepend to PATH
    copy_shims("/proc/self/exe", "/tmp/.ronly-shims")?;

    // 6. Load seccomp filter (must be last before exec)
    load_seccomp_filter()?;

    // 7. Exec the shell (ronly is replaced)
    execvp(shell, args)?;
}
```

### Validation

1. Build `ronly` and copy to a dev machine with Kubernetes access
2. Basic checks:
   - `ronly -- ls /` works
   - `ronly -- cat /etc/hosts` works
   - `ronly -- rm /etc/hosts` fails with EROFS
   - `ronly -- kill 1` fails
   - `ronly -- top` shows real host processes
   - `ronly -- kubectl get pods` works
   - `ronly -- kubectl delete pod foo` blocked by shim
   - `ronly -- docker ps` works
   - `ronly -- docker exec foo bash` blocked by shim
   - `ronly -- perf top` works
3. Deploy on staging, configure Kaju to use it for diagnostic tool calls
4. Run a simulated PagerDuty investigation and verify the agent can diagnose the issue using only read-only access

## Future Work

**v2: Network namespace.** Add `--allow-egress` for destination allowlisting to prevent data exfiltration. Create a network namespace, route outbound traffic through a local proxy that checks destinations against the allowlist.

**v2: Read-only socket proxies.** Ship lightweight proxies for Docker socket (GET-only HTTP filter) and database connections (read-only transaction enforcement) that provide hard isolation beyond what shims offer.

**v2: Database shims.** psql, mysql, sqlite3 wrappers that force read-only transactions.

**v2: cgroups integration.** Resource limits (CPU, memory, PIDs) to prevent resource exhaustion.

**Community shims.** Accept contributions for cloud CLIs (aws, gcloud, az), monitoring tools (datadog, newrelic), and other common operational tools. Each is 10-30 lines of shell — low barrier to contribution.

**Agent framework integration.** Provide libraries/examples for using ronly with popular agent frameworks — OpenClaw, agentd, Claude Code, OpenAI Codex.

**Managed offering.** A hosted version where you connect infrastructure and get ronly-protected access without deploying anything yourself.

**Secret protection.** Defense-in-depth measures to reduce accidental secret exposure. None of these are secure against a determined adversary — they raise the bar for accidental leaks.
- `--mask` flag and auto-masking of common secret paths (`~/.ssh/*`, `~/.aws/credentials`, `~/.config/gcloud/`, etc.) — bind-mount `/dev/null` over them
- Env var scrubbing — blocklist of known secret env vars (`AWS_SECRET_ACCESS_KEY`, `DATABASE_URL`, etc.), stripped before exec
- Output scrubbing — aho-corasick redaction of known secret values in stdout/stderr, for agents that might echo secrets in logs
