#!/bin/bash
set -euo pipefail

# Integration tests for rosshd.
# Must run as root (needs CAP_SYS_ADMIN for namespaces).
# Usage: sudo ./tests/integration.sh

if [ "$(id -u)" -ne 0 ]; then
  echo "error: must run as root" >&2
  exit 1
fi

TMPDIR=$(mktemp -d)
cleanup() { kill $SSHRO_PID 2>/dev/null || true; wait $SSHRO_PID 2>/dev/null || true; rm -rf $TMPDIR; }
trap cleanup EXIT

# Generate keys
ssh-keygen -t ed25519 -f "$TMPDIR/host_key" -N "" -q
ssh-keygen -t ed25519 -f "$TMPDIR/client_key" -N "" -q
cp "$TMPDIR/client_key.pub" "$TMPDIR/authorized_keys"

# Find free port
PORT=$(python3 -c \
  'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')

BINARY="${ROSSHD_BIN:-./target/release/rosshd}"
if [ ! -x "$BINARY" ]; then
  echo "error: $BINARY not found. Run cargo build --release first." >&2
  exit 1
fi

# Start rosshd
RUST_LOG=warn "$BINARY" \
  --port "$PORT" \
  --host-key "$TMPDIR/host_key" \
  --authorized-keys "$TMPDIR/authorized_keys" \
  --tmpfs-size-mb 16 \
  >"$TMPDIR/rosshd.log" 2>&1 &
SSHRO_PID=$!

# Wait for server
for i in $(seq 1 30); do
  if ssh -p "$PORT" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o BatchMode=yes \
    -i "$TMPDIR/client_key" \
    localhost true </dev/null 2>/dev/null; then
    break
  fi
  sleep 0.2
done

SSH="ssh -p $PORT
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o BatchMode=yes
  -i $TMPDIR/client_key
  localhost"

PASS=0
FAIL=0

# Run a test, check exit code
run_test() {
  local name="$1" expected_rc="$2"
  shift 2
  local output rc
  output=$($SSH "$@" </dev/null 2>&1) && rc=0 || rc=$?
  if [ "$rc" -eq "$expected_rc" ]; then
    echo "  ok  $name"
    PASS=$((PASS + 1))
  else
    echo "FAIL  $name (rc=$rc, want $expected_rc)"
    echo "      $output"
    FAIL=$((FAIL + 1))
  fi
}

# Run a test, check exit code + grep output
run_test_grep() {
  local name="$1" expected_rc="$2" pattern="$3"
  shift 3
  local output rc
  output=$($SSH "$@" </dev/null 2>&1) && rc=0 || rc=$?
  if [ "$rc" -eq "$expected_rc" ] && \
     echo "$output" | grep -qi "$pattern"; then
    echo "  ok  $name"
    PASS=$((PASS + 1))
  else
    echo "FAIL  $name (rc=$rc, want $expected_rc, grep=$pattern)"
    echo "      $output"
    FAIL=$((FAIL + 1))
  fi
}

echo "--- read operations ---"
run_test_grep "echo hello" 0 "hello" "echo hello"
run_test "cat /etc/hostname" 0 "cat /etc/hostname"
run_test "ls /" 0 "ls /"
run_test "ps aux" 0 "ps aux | head -3"

echo "--- write operations blocked ---"
run_test "rm blocked" 1 "rm /etc/hostname 2>&1"
run_test_grep "rm error" 1 \
  "read-only\|not permitted" "rm /etc/hostname 2>&1"
run_test "touch blocked" 1 "touch /etc/rosshd_test 2>&1"
run_test "mkdir blocked" 1 "mkdir /etc/rosshd_test 2>&1"

echo "--- /tmp writable ---"
run_test "/tmp write+read" 0 \
  "echo test > /tmp/rosshd_test && cat /tmp/rosshd_test"

echo "--- seccomp ---"
run_test_grep "kill blocked" 1 \
  "not permitted" "kill 1 2>&1"

echo "--- shims ---"
run_test_grep "docker exec blocked" 1 \
  "blocked" "docker exec foo bar 2>&1"
run_test_grep "docker stop blocked" 1 \
  "blocked" "docker stop foo 2>&1"
run_test_grep "kubectl delete blocked" 1 \
  "blocked" "kubectl delete pod foo 2>&1"
run_test_grep "kubectl apply blocked" 1 \
  "blocked" "kubectl apply -f foo 2>&1"

echo "--- exit codes ---"
run_test "exit 0" 0 "true"
run_test "exit 1" 1 "false"
run_test "exit 42" 42 "exit 42"

echo ""
echo "$PASS passed, $FAIL failed"

if [ "$FAIL" -ne 0 ]; then
  echo ""
  echo "--- server log ---"
  cat "$TMPDIR/rosshd.log"
  exit 1
fi
