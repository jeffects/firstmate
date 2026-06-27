#!/usr/bin/env bash
# tests/fm-watch-hardening.test.sh - security hardening in bin/fm-watch.sh:
#   1. Check-script provenance: the watcher executes a state/<id>.check.sh only
#      when its companion state/<id>.meta exists (a recorded task), plus the
#      sanctioned x-watch.check.sh shim. A planted no-meta check is ignored, so a
#      foothold in state/ cannot get arbitrary code run by the watcher.
#   2. Numeric guards on counter files (.heartbeat-streak, .count-*): a corrupted
#      or hostile value can neither break the watcher's arithmetic nor inject code
#      via bash arithmetic evaluation. Mirrors the existing .stale-since-* guard.
set -u

# shellcheck source=tests/wake-helpers.sh
. "$(dirname "${BASH_SOURCE[0]}")/wake-helpers.sh"

WATCH="$ROOT/bin/fm-watch.sh"
TMP_ROOT=$(fm_test_tmproot fm-watch-hardening-tests)

reap() { kill "$1" 2>/dev/null || true; wait "$1" 2>/dev/null || true; }

# Wait until <file> exists (up to <limit> 0.1s ticks). 0 if it appeared.
wait_for_file() {
  local file=$1 limit=${2:-50} i=0
  while [ "$i" -lt "$limit" ]; do
    [ -e "$file" ] && return 0
    sleep 0.1; i=$((i + 1))
  done
  return 1
}

# Wait until <file>'s content equals <want> (up to <limit> ticks).
wait_for_value() {
  local file=$1 want=$2 limit=${3:-50} i=0
  while [ "$i" -lt "$limit" ]; do
    [ "$(cat "$file" 2>/dev/null || true)" = "$want" ] && return 0
    sleep 0.1; i=$((i + 1))
  done
  return 1
}

wait_for_exit() {
  local pid=$1 limit=${2:-50} i=0
  while [ "$i" -lt "$limit" ]; do
    kill -0 "$pid" 2>/dev/null || { wait "$pid" 2>/dev/null; return 0; }
    sleep 0.1; i=$((i + 1))
  done
  return 1
}

# --- check-script provenance ------------------------------------------------

test_planted_no_meta_check_is_ignored() {
  local dir state fakebin out sentinel
  dir=$(make_case provenance-planted); state="$dir/state"; fakebin="$dir/fakebin"
  out="$dir/watch.out"
  sentinel="$dir/PWNED-check"
  # A planted check with NO companion task meta - the attack the guard blocks.
  cat > "$state/zz-pwn.check.sh" <<SH
#!/usr/bin/env bash
: > "$sentinel"
printf 'merged: pwned\n'
SH
  chmod +x "$state/zz-pwn.check.sh"
  PATH="$fakebin:$PATH" FM_STATE_OVERRIDE="$state" FM_POLL=1 FM_SIGNAL_GRACE=1 \
    FM_CHECK_INTERVAL=0 FM_HEARTBEAT=999999 "$WATCH" > "$out" &
  local pid=$!
  # A completed check sweep touches .last-check; wait for it, then assert the
  # planted check never ran and never produced a wake.
  wait_for_file "$state/.last-check" 50 || { reap "$pid"; fail "watcher never completed a check sweep"; }
  sleep 0.3
  reap "$pid"
  assert_absent "$sentinel" "planted no-meta check must NOT be executed"
  assert_no_grep "check:" "$out" "planted no-meta check must NOT produce a check wake"
  pass "watcher ignores a planted state/<id>.check.sh with no companion task meta"
}

test_x_watch_shim_still_runs() {
  local dir state fakebin out
  dir=$(make_case provenance-xwatch); state="$dir/state"; fakebin="$dir/fakebin"
  out="$dir/watch.out"
  # The sanctioned X-mode shim has no <id>.meta and must remain exempt.
  cat > "$state/x-watch.check.sh" <<'SH'
#!/usr/bin/env bash
printf 'x-mention req-1\n'
SH
  chmod +x "$state/x-watch.check.sh"
  PATH="$fakebin:$PATH" FM_STATE_OVERRIDE="$state" FM_POLL=1 FM_SIGNAL_GRACE=1 \
    FM_CHECK_INTERVAL=0 FM_HEARTBEAT=999999 "$WATCH" > "$out" &
  local pid=$!
  wait_for_exit "$pid" 60 || { reap "$pid"; fail "watcher did not exit for the x-watch shim wake"; }
  grep -F "check: $state/x-watch.check.sh: x-mention req-1" "$out" >/dev/null \
    || fail "the x-watch shim must still run despite having no task meta"
  pass "watcher still runs the sanctioned x-watch.check.sh shim (allowlisted, no meta)"
}

test_check_with_companion_meta_runs() {
  local dir state fakebin out
  dir=$(make_case provenance-meta); state="$dir/state"; fakebin="$dir/fakebin"
  out="$dir/watch.out"
  cat > "$state/task.check.sh" <<'SH'
#!/usr/bin/env bash
printf 'merged: https://example.test/pr/1\n'
SH
  chmod +x "$state/task.check.sh"
  printf 'window=sess:fm-task\nkind=ship\n' > "$state/task.meta"
  PATH="$fakebin:$PATH" FM_STATE_OVERRIDE="$state" FM_POLL=1 FM_SIGNAL_GRACE=1 \
    FM_CHECK_INTERVAL=0 FM_HEARTBEAT=999999 "$WATCH" > "$out" &
  local pid=$!
  wait_for_exit "$pid" 60 || { reap "$pid"; fail "watcher did not exit for a check with companion meta"; }
  grep -F "check: $state/task.check.sh: merged: https://example.test/pr/1" "$out" >/dev/null \
    || fail "a check with a companion task meta must run"
  pass "watcher runs a check that has a companion task meta"
}

# --- numeric guards ---------------------------------------------------------

test_corrupt_heartbeat_streak_no_injection() {
  local dir state fakebin out sentinel
  dir=$(make_case numeric-streak); state="$dir/state"; fakebin="$dir/fakebin"
  out="$dir/watch.out"
  sentinel="$dir/PWNED-streak"
  # Arithmetic-injection payload: without the numeric guard, reading this into the
  # streak arithmetic ([ "$streak" -gt 12 ] / $((1 << streak))) would run the
  # command substitution in the array subscript.
  # shellcheck disable=SC2016  # the literal $(...) IS the payload; it must not expand here
  printf 'x[$(touch %q)]' "$sentinel" > "$state/.heartbeat-streak"
  PATH="$fakebin:$PATH" FM_STATE_OVERRIDE="$state" FM_POLL=1 FM_SIGNAL_GRACE=1 \
    FM_CHECK_INTERVAL=999999 FM_HEARTBEAT=1 "$WATCH" > "$out" &
  local pid=$!
  # The absorbed heartbeat rewrites the streak to a clean "1" (read_counter(poison)=0).
  wait_for_value "$state/.heartbeat-streak" 1 60 || { reap "$pid"; fail "watcher did not normalize a corrupt .heartbeat-streak"; }
  reap "$pid"
  assert_absent "$sentinel" "corrupt .heartbeat-streak must not inject via arithmetic"
  pass "numeric guard neutralizes a corrupt/hostile .heartbeat-streak"
}

test_corrupt_count_file_no_injection() {
  local dir state fakebin out sentinel win key cap h
  dir=$(make_case numeric-count); state="$dir/state"; fakebin="$dir/fakebin"
  out="$dir/watch.out"
  sentinel="$dir/PWNED-count"
  win="sess:fm-cnt"
  key="sess_fm-cnt"  # tr ':/.' '___' of the window name
  cap="$dir/capture.txt"
  printf 'idle prompt $\n' > "$cap"
  # Seed .hash-<key> to the capture's hash so poll 1 takes the stable-pane branch
  # (h == prev) and reads the poisoned .count-<key> into n=$(( ... + 1 )).
  h=$(hash_text 'idle prompt $')
  printf '%s' "$h" > "$state/.hash-$key"
  # shellcheck disable=SC2016  # the literal $(...) IS the payload; it must not expand here
  printf 'x[$(touch %q)]' "$sentinel" > "$state/.count-$key"
  printf 'window=%s\nkind=ship\n' "$win" > "$state/cnt.meta"
  PATH="$fakebin:$PATH" FM_FAKE_TMUX_WINDOW="$win" FM_FAKE_TMUX_CAPTURE="$cap" \
    FM_STATE_OVERRIDE="$state" FM_POLL=1 FM_SIGNAL_GRACE=1 FM_STALE_ESCALATE_SECS=999 \
    FM_CHECK_INTERVAL=999999 FM_HEARTBEAT=999999 "$WATCH" > "$out" &
  local pid=$!
  # With the guard the stable-pane branch rewrites .count-<key> to a clean "1".
  wait_for_value "$state/.count-$key" 1 60 || { reap "$pid"; fail "watcher did not normalize a corrupt .count-* file"; }
  reap "$pid"
  assert_absent "$sentinel" "corrupt .count-* must not inject via arithmetic"
  pass "numeric guard neutralizes a corrupt/hostile .count-* file"
}

test_planted_no_meta_check_is_ignored
test_x_watch_shim_still_runs
test_check_with_companion_meta_runs
test_corrupt_heartbeat_streak_no_injection
test_corrupt_count_file_no_injection
