#!/usr/bin/env bash
# Acquire or inspect the per-home firstmate session lock.
# Writes the harness (agent) process PID found by walking the shell's ancestry,
# which lives as long as the firstmate session - unlike the transient subshell
# PID of any one tool call, which is dead moments after it is written.
# Usage: fm-lock.sh           acquire; exit 1 if another live session holds it
#        fm-lock.sh status    print holder and liveness; always exits 0
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FM_ROOT="${FM_ROOT_OVERRIDE:-$(cd "$SCRIPT_DIR/.." && pwd)}"
FM_HOME="${FM_HOME:-${FM_ROOT_OVERRIDE:-$FM_ROOT}}"
STATE="${FM_STATE_OVERRIDE:-$FM_HOME/state}"
LOCK="$STATE/.lock"
mkdir -p "$STATE"

# Known harness command names; extend when a new adapter is verified.
HARNESS_RE='claude|codex|opencode|^pi$'

harness_pid() {
  local pid=$$ comm args
  for _ in 1 2 3 4 5 6 7 8; do
    comm=$(ps -o comm= -p "$pid" 2>/dev/null) || return 1
    args=$(ps -o args= -p "$pid" 2>/dev/null)
    if printf '%s' "$(basename "$comm")" | grep -qE "$HARNESS_RE"; then
      echo "$pid"; return 0
    fi
    # Bare interpreter (e.g. node): match the harness name in its script path.
    case "$comm" in
      *node*|*python*) printf '%s' "$args" | grep -qE "$HARNESS_RE" && { echo "$pid"; return 0; } ;;
    esac
    pid=$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ')
    [ -n "$pid" ] && [ "$pid" -gt 1 ] || return 1
  done
  return 1
}

# Stable per-process start-time token; empty if the pid is gone. A recycled PID
# (same number, a brand-new process) gets a different start time, so recording and
# comparing it stops a reused PID from being mistaken for the original holder.
pid_start_time() {  # <pid>
  local pid=$1
  case "$pid" in ''|*[!0-9]*) return 1 ;; esac
  ps -p "$pid" -o lstart= 2>/dev/null | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

holder_alive() {  # <pid> [start-time]: true if $1 is a live harness process AND,
                  # when a start-time was recorded, the live process's start time
                  # still matches it (defeats PID reuse). A legacy lock with no
                  # recorded start-time falls back to the liveness+harness check.
  local pid=$1 want_start=${2:-} comm now_start
  kill -0 "$pid" 2>/dev/null || return 1
  comm=$(ps -o comm= -p "$pid" 2>/dev/null) || return 1
  printf '%s' "$(basename "$comm") $(ps -o args= -p "$pid" 2>/dev/null)" | grep -qE "$HARNESS_RE" || return 1
  if [ -n "$want_start" ]; then
    now_start=$(pid_start_time "$pid") || return 1
    [ "$now_start" = "$want_start" ] || return 1
  fi
  return 0
}

# Lock format: line 1 = harness pid, line 2 = its start-time (added for PID-reuse
# safety; absent in legacy locks, which still parse - pid only, start empty).
if [ "${1:-}" = "status" ]; then
  if [ ! -f "$LOCK" ]; then echo "lock: free"; exit 0; fi
  old=$(head -1 "$LOCK" 2>/dev/null)
  old_start=$(sed -n '2p' "$LOCK" 2>/dev/null)
  if holder_alive "$old" "$old_start"; then echo "lock: held by live harness pid $old"; else echo "lock: stale (pid $old dead, recycled, or not a harness)"; fi
  exit 0
fi

me=$(harness_pid) || { echo "error: cannot locate harness process in ancestry" >&2; exit 1; }
me_start=$(pid_start_time "$me")
if [ -f "$LOCK" ]; then
  old=$(head -1 "$LOCK" 2>/dev/null)
  old_start=$(sed -n '2p' "$LOCK" 2>/dev/null)
  if [ "$old" != "$me" ] && holder_alive "$old" "$old_start"; then
    echo "error: another live firstmate session holds the lock (pid $old); operate read-only until resolved" >&2
    exit 1
  fi
fi
printf '%s\n%s\n' "$me" "$me_start" > "$LOCK"
echo "lock acquired: harness pid $me"
