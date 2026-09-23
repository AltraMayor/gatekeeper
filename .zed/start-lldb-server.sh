#!/bin/bash
#
# This script starts `lldb-server` as root in the background so that Zed's
# CodeLLDB debug adapter can attach to it to launch and debug Gatekeeper.
#
# Why this helper script is needed:
# 1. Gatekeeper requires root privileges for hugepages and direct hardware access.
# 2. CodeLLDB communicates over the Debug Adapter Protocol (DAP) headlessly and
#    cannot interactively prompt for a sudo password inside the editor.
# 3. Zed's pre-debug "build" tasks block and wait for the process to exit before
#    launching the debugger. Running `lldb-server` directly in the task would
#    hang indefinitely because `lldb-server` is a persistent daemon.
#
# This script solves these problems by:
# - Verifying Linux Yama ptrace_scope is not set to 3 ("No Attach").
# - Checking if `lldb-server` is already listening on PORT (exiting 0 immediately).
# - Resolving `lldb-server` to its canonical real executable path (bypassing symlinks)
#   so the platform server can locate its versioned worker stub (e.g. `lldb-server-18.1.3`).
# - Checking if sudo can run `lldb-server` without prompting (NOPASSWD mode).
# - If password authentication is needed, calling `sudo -v` in the foreground terminal
#   and then launching `sudo setsid` so sudo validates the ticket on the active TTY.
# - Detaching `lldb-server` in a new session via `setsid` so Zed does not kill it
#   when the task finishes.
# - Polling until the port is open and responding, then exiting 0 promptly so
#   Zed can proceed with launching CodeLLDB.

PORT=12345
LOG_FILE="/tmp/lldb-server-$PORT.log"

# Check Linux Yama ptrace_scope.
# Scope 0 (classic), 1 (restricted), and 2 (admin-only) allow ptrace when
# running lldb-server as root. However, scope 3 (no attach) disables all ptrace
# system-wide (even for root) and cannot be lowered without rebooting.
if [ -f /proc/sys/kernel/yama/ptrace_scope ]; then
    PTRACE_SCOPE="$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null)"
    if [ "$PTRACE_SCOPE" -eq 3 ] 2>/dev/null; then
        echo "Error: kernel.yama.ptrace_scope is set to 3 ('No Attach')." >&2
        echo "All process tracing is permanently disabled system-wide (even for root)." >&2
        echo "A system reboot is required to lower this security restriction." >&2
        exit 1
    fi
fi

# Check if lldb-server is already running
if ss -tln 2>/dev/null | grep -q ":$PORT "; then
    echo "lldb-server is already running on port $PORT."
    exit 0
fi

# Locate lldb-server
LLDB_SERVER="$(which lldb-server 2>/dev/null)"
if [ -z "$LLDB_SERVER" ]; then
    LLDB_SERVER="$(which lldb-server-* 2>/dev/null | head -n1)"
fi

if [ -z "$LLDB_SERVER" ]; then
    echo "Error: lldb-server not found. Please install lldb (e.g. sudo apt install lldb)." >&2
    exit 1
fi

# Resolve symlinks to the canonical real binary path (e.g. /usr/lib/llvm-18/bin/lldb-server).
# LLDB's platform server computes its helper directory relative to the binary path.
# Invoking it through a symlink in /usr/bin causes it to fail locating lldb-server-<version>
# when spawning the gdbserver worker stub ("unable to launch a GDB server on <host>").
LLDB_SERVER="$(readlink -f "$LLDB_SERVER")"

# Check if sudo can already execute lldb-server non-interactively
# (e.g. via NOPASSWD in /etc/sudoers).
if sudo -n "$LLDB_SERVER" v >/dev/null 2>&1; then
    echo "Starting $LLDB_SERVER on port $PORT..."
    # In NOPASSWD mode, setsid can run on the outside because sudo does not
    # need a controlling terminal to check or prompt for passwords.
    setsid sudo "$LLDB_SERVER" platform --server --listen 127.0.0.1:$PORT >"$LOG_FILE" 2>&1 &
else
    # Interactive password mode: authenticate in the foreground terminal.
    if ! sudo -v; then
        echo "Error: Failed to obtain sudo privileges for $LLDB_SERVER." >&2
        exit 1
    fi

    echo "Starting $LLDB_SERVER on port $PORT..."
    # In password mode, sudo MUST run first so it has access to the active
    # terminal (TTY) to verify the cached ticket from sudo -v. Running
    # 'setsid sudo' here would strip the TTY, invalidate the ticket, and fail.
    # Once sudo validates, setsid detaches lldb-server into its own session
    # so Zed's task runner does not kill it when this script finishes.
    sudo setsid "$LLDB_SERVER" platform --server --listen 127.0.0.1:$PORT >"$LOG_FILE" 2>&1 &
fi

# Wait up to 3 seconds for port to open.
for _ in {1..15}; do
    if ss -tln 2>/dev/null | grep -q ":$PORT "; then
        echo "lldb-server is ready on port $PORT."
        exit 0
    fi
    sleep 0.2
done

echo "Timed out waiting for lldb-server on port $PORT." >&2
if [ -f "$LOG_FILE" ]; then
    echo "--- Server log ($LOG_FILE) ---" >&2
    cat "$LOG_FILE" >&2
fi
exit 1
