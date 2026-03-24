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
2. Creates Linux namespaces (mount, PID)
3. Remounts the filesystem read-only
4. Mounts a small writable tmpfs at `/tmp`
5. Bind-mounts host `/proc` read-only
6. Prepends shim directory to `$PATH`
7. Loads seccomp-bpf filter
8. Execs the real shell

After step 8, `ronly` is gone — replaced by the shell process via `execve`. It doesn't interpret commands, doesn't sit in the middle, doesn't add latency. It just builds the cage and then gets out of the way.

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

`ronly` creates a new mount namespace and remounts the root filesystem read-only:

```
unshare(CLONE_NEWNS)
mount --bind -o ro,remount / /
```

The agent can read everything — logs, configs, source code, `/proc`, `/sys`. Any write fails with `EROFS` (Read-only file system). This is enforced by the VFS layer in the kernel. No shell escape, pipe chain, or subshell can bypass a read-only mount from within the namespace.

A small tmpfs is mounted at `/tmp` (default 64MB, configurable) so the agent has scratch space. Command history, pipe buffers, temporary files all work. The tmpfs is destroyed when the session ends.

```
mount -t tmpfs -o size=64M tmpfs /tmp
```

### Layer 2: Process Isolation (PID Namespace)

`ronly` creates a new PID namespace but bind-mounts the **host's `/proc`** read-only into the sandbox.

What this gives you:

- `top`, `htop`, `ps aux` show real host processes with real PIDs, CPU, memory usage
- `cat /proc/<pid>/status` works for any host process
- `kill <pid>` fails — the target PID doesn't exist in the agent's PID namespace
- `kill` on processes the agent itself spawned (within the sandbox) works normally

The agent sees everything. It can signal nothing outside its own session.

### Layer 3: Syscall Filtering (seccomp-bpf)

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

The seccomp filter is the backstop — most operations are already blocked by the read-only filesystem and PID namespace. seccomp catches the things that slip through the cracks (like `kill`, which doesn't touch the filesystem).

### Interaction of Layers

The layers are redundant by design. To delete a file, an agent would need to bypass the read-only mount (layer 1) AND the seccomp filter blocking `unlink` (layer 3). To kill a host process, it would need to bypass the PID namespace (layer 2) AND the seccomp filter blocking `kill` (layer 3). No single layer failing compromises the system.

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
- Namespace setup (mount, PID) with read-only root and writable `/tmp`
- Host `/proc` bind-mounted read-only
- seccomp-bpf filter (destructive syscalls blocked, `CAP_PERFMON` allowed)
- Shims for `docker` and `kubectl`
- `--audit` flag for command logging
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
- `nix` — namespace and syscall wrappers (`unshare`, `mount`, `execve`)
- `seccompiler` — seccomp-bpf filter construction
- `clap` — CLI argument parsing

Note: no async runtime needed. `ronly` does synchronous setup and then execs. No SSH server, no event loop, no tokio.

**Build:**
```
cargo build --release
# produces a single static binary
```

**Install:**
```
cp target/release/ronly /usr/local/bin/ronly
cp shims/* /usr/lib/ronly/shims/
```

### What the Implementation Looks Like

Pseudocode for the core:

```rust
fn main() {
    let args = parse_args();

    // 1. Create new mount and PID namespaces
    unshare(CLONE_NEWNS | CLONE_NEWPID)?;

    // Must fork after CLONE_NEWPID — child becomes PID 1 in new namespace
    match fork()? {
        Parent(child_pid) => {
            // Wait for child
            waitpid(child_pid)?;
        }
        Child => {
            // 2. Remount root read-only
            mount_readonly("/")?;

            // 3. Mount tmpfs at /tmp
            mount_tmpfs("/tmp", &args.tmpfs_size)?;

            // 4. Additional writable paths as tmpfs overlays
            for path in &args.writable_paths {
                mount_tmpfs(path, &args.tmpfs_size)?;
            }

            // 5. Bind-mount host /proc read-only
            mount_proc_readonly()?;

            // 6. Prepend shims to PATH
            prepend_shims_to_path(&args.extra_shims)?;

            // 7. Set up audit logging if requested
            if args.audit {
                setup_audit_hooks()?;
            }

            // 8. Load seccomp filter (must be last before exec)
            load_seccomp_filter(&args.allowed_caps)?;

            // 9. Exec the shell (ronly process is replaced)
            let shell = args.shell.unwrap_or(env::var("SHELL").unwrap_or("/bin/bash"));
            match &args.command {
                Some(cmd) => exec_command(&shell, cmd),
                None => exec_interactive(&shell),
            }
        }
    }
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
