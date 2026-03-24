# ronly

Read-only sandbox for untrustworthy agents. Drop into a bash/zsh/fish session
where everything looks normal — `top`, `cat /var/log/syslog`, `kubectl get pods`
all work — but destructive operations are blocked at the kernel level.

```
ronly                        # launch $SHELL in read-only sandbox
ronly bash                   # launch bash specifically
ronly -- kubectl get pods    # run a single command and exit
ronly -- top                 # same
```

## How it works

`ronly` creates a sandbox, then execs your shell or command. After exec, ronly
is gone — replaced by the shell process. No overhead, no interception.

1. **Read-only filesystem** — Mount namespace with root bind-mounted
   read-only. Writes fail with `EROFS`. Writable tmpfs at `/tmp` for
   scratch space.

2. **PID namespace** — Host `/proc` mounted read-only. `ps` and `top`
   show real host processes. `kill` fails because target PIDs don't
   exist in the agent's namespace.

3. **seccomp-bpf** — Blocks `kill`, `unlink`, `rename`, `truncate`,
   `mount`, `reboot`. `ptrace` write ops blocked but read ops allowed
   (so `strace` works). Defense in depth.

4. **Tool shims** — The ronly binary is bind-mounted into a shims
   directory on PATH under names like `docker` and `kubectl`. When
   the shell runs `docker ps`, it finds the shim, which is ronly
   itself — ronly checks `argv[0]`, sees `"docker"`, and either
   execs the real `/usr/bin/docker` (for read-only subcommands)
   or prints an error and exits (for write subcommands). No shell
   scripts, no extra binaries, zero disk overhead.

## Usage

```
ronly [OPTIONS] [SHELL] [-- COMMAND...]
```

Options:

```
--tmpfs-size SIZE    Size of writable /tmp (default: 64M)
--extra-shims DIR    Additional shim directory
--no-shims           Disable all shims
--writable PATH      Additional writable tmpfs overlay
```

## Composability

Works everywhere a shell works:

**SSH:**
```
# /etc/ssh/sshd_config
Match User agent-kaju
    ForceCommand /usr/local/bin/ronly bash
```

**Kubernetes:**
```
kubectl exec -it debug-pod -- /usr/local/bin/ronly bash
```

**Docker:**
```dockerfile
FROM ubuntu:24.04
COPY ronly /usr/local/bin/ronly
ENTRYPOINT ["/usr/local/bin/ronly", "bash"]
```

**Agent frameworks:**
```typescript
const proc = spawn("ronly", ["bash", "-c", command]);
```

## What's allowed vs blocked

**Works normally:** `cat`, `ls`, `ps`, `top`, `htop`, `grep`, `find`,
`kubectl get`, `kubectl describe`, `kubectl logs`, `docker ps`,
`docker logs`, `docker inspect`, `perf stat`, `strace`

**Blocked:**
```
$ rm /etc/hosts
rm: cannot remove '/etc/hosts': Read-only file system

$ docker exec -it abc123 bash
ronly: docker exec is blocked (read-only session)

$ kubectl delete pod my-pod
ronly: kubectl delete is blocked (read-only session)

$ kill 1
bash: kill: (1) - Operation not permitted
```

## Built-in shims

Some tools talk to sockets or APIs rather than the filesystem, so
a read-only mount doesn't stop them. Shims handle these.

The shim mechanism uses an `argv[0]` dispatch trick: during sandbox
setup, ronly bind-mounts its own binary into `/usr/lib/ronly/shims/`
under each tool's name (e.g., `docker`, `kubectl`). This directory
is prepended to `$PATH`. When the shell resolves `docker`, it finds
the shim — which is just ronly. ronly checks `argv[0]`, recognizes
it's being invoked as `docker`, and applies the allowlist. If the
subcommand is read-only, ronly execs the real binary at `/usr/bin/docker`.
Otherwise it prints an error and exits.

No shell scripts. No copies of the binary (bind-mounts share the
same inode). Zero disk overhead.

**docker** — allows `ps`, `logs`, `inspect`, `stats`, `top`,
`images`, `info`, `version`, `events`, `diff`,
`network ls/inspect`, `volume ls/inspect`

**kubectl** — allows `get`, `describe`, `logs`, `top`, `explain`,
`version`, `cluster-info`, `api-resources`, `api-versions`,
`config view/current-context/get-contexts`, `auth can-i/whoami`

Everything not listed is blocked by default.

Custom shims can be added with `--extra-shims DIR`.
