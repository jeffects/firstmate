#!/usr/bin/env bash
# tests/fm-pr-check.test.sh - the PR-URL allowlist and data-file indirection in
# bin/fm-pr-check.sh. The PR URL becomes the input to a generated
# state/<id>.check.sh the watcher later runs through bash, so a URL containing
# $(...) or "; would be RCE. These tests assert a valid GitHub PR URL is accepted,
# malicious/non-GitHub URLs are rejected before anything is written, and the
# generated check reads the URL as DATA (from a sibling file) rather than embedding
# it as code.
set -u

# shellcheck source=tests/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

PR_CHECK="$ROOT/bin/fm-pr-check.sh"
TMP_ROOT=$(fm_test_tmproot fm-pr-check-tests)

# Run fm-pr-check.sh in an isolated state dir. FM_ROOT_OVERRIDE points at a
# non-repo dir so the script's fm-guard.sh call is a no-op (its path is absent and
# the script swallows that with `|| true`), keeping the test free of guard noise.
run_pr_check() {  # <state-dir> <id> <url>
  local state=$1 id=$2 url=$3 guard_root
  guard_root="$TMP_ROOT/noguard"
  mkdir -p "$state" "$guard_root"
  FM_ROOT_OVERRIDE="$guard_root" FM_STATE_OVERRIDE="$state" "$PR_CHECK" "$id" "$url"
}

test_accepts_valid_github_pr_url() {
  local state out rc url
  state="$TMP_ROOT/accept/state"
  url="https://github.com/owner/repo/pull/123"
  out=$(run_pr_check "$state" "valid-x1" "$url" 2>&1); rc=$?
  [ "$rc" -eq 0 ] || fail "valid GitHub PR URL was rejected (rc=$rc): $out"
  assert_present "$state/valid-x1.check.sh" "valid URL must arm the check"
  assert_present "$state/valid-x1.pr-url" "valid URL must be stored in the sibling data file"
  assert_grep "$url" "$state/valid-x1.pr-url" "the data file must hold the PR URL"
  # Belt-and-suspenders: the URL must NOT be embedded literally in the generated
  # check script; it is read from the data file as data.
  assert_no_grep "$url" "$state/valid-x1.check.sh" "the generated check must NOT embed the URL literally"
  assert_grep "valid-x1.pr-url" "$state/valid-x1.check.sh" "the generated check must read the URL data file"
  pass "fm-pr-check accepts a valid GitHub PR URL and stores it as data"
}

# A malicious URL must be rejected with a non-zero exit and write NOTHING, so no
# attacker-controlled bytes ever reach a generated, watcher-executed script.
assert_rejected() {  # <id> <url> <label>
  local id=$1 url=$2 label=$3 state out rc
  state="$TMP_ROOT/reject-$id/state"
  out=$(run_pr_check "$state" "$id" "$url" 2>&1); rc=$?
  [ "$rc" -ne 0 ] || fail "$label: expected non-zero exit, got 0 (out: $out)"
  assert_absent "$state/$id.check.sh" "$label: a rejected URL must not arm a check"
  assert_absent "$state/$id.pr-url" "$label: a rejected URL must not write a data file"
}

test_rejects_command_substitution() {
  # shellcheck disable=SC2016  # the literal $(...) IS the malicious payload under test
  assert_rejected "cmdsub" 'https://github.com/o/r/pull/1$(touch /tmp/fm-pwn)' "command substitution"
  pass "fm-pr-check rejects a URL containing \$(...)"
}

test_rejects_semicolon_injection() {
  assert_rejected "semi" 'https://github.com/o/r/pull/1;touch /tmp/fm-pwn' "semicolon injection"
  assert_rejected "quote" 'https://github.com/o/r/pull/1";touch x;"' "quote-break injection"
  pass "fm-pr-check rejects URLs containing ; and quote-break payloads"
}

test_rejects_non_github_url() {
  assert_rejected "evil" 'https://evil.com/owner/repo/pull/1' "non-github host"
  assert_rejected "noproto" 'github.com/owner/repo/pull/1' "missing https scheme"
  assert_rejected "notpr" 'https://github.com/owner/repo/issues/1' "not a pull URL"
  pass "fm-pr-check rejects non-GitHub and non-PR URLs"
}

test_generated_check_emits_only_on_merged() {
  # Drive the generated check with a fake gh to confirm the contract survives the
  # data-file indirection: one line iff MERGED, silent otherwise.
  local state fakebin out url
  state="$TMP_ROOT/contract/state"
  fakebin="$TMP_ROOT/contract/fakebin"
  mkdir -p "$fakebin"
  url="https://github.com/owner/repo/pull/9"
  run_pr_check "$state" "merged-x2" "$url" >/dev/null 2>&1 || fail "arming the check failed"
  cat > "$fakebin/gh" <<'SH'
#!/usr/bin/env bash
# Echo the state requested via the FM_FAKE_PR_STATE env, ignoring args.
printf '%s\n' "${FM_FAKE_PR_STATE:-OPEN}"
SH
  chmod +x "$fakebin/gh"
  out=$(PATH="$fakebin:$PATH" FM_FAKE_PR_STATE=MERGED bash "$state/merged-x2.check.sh")
  [ "$out" = "merged" ] || fail "merged PR must print 'merged' (got: '$out')"
  out=$(PATH="$fakebin:$PATH" FM_FAKE_PR_STATE=OPEN bash "$state/merged-x2.check.sh")
  [ -z "$out" ] || fail "open PR must print nothing (got: '$out')"
  pass "generated check prints one line iff merged, reading the URL as data"
}

test_accepts_valid_github_pr_url
test_rejects_command_substitution
test_rejects_semicolon_injection
test_rejects_non_github_url
test_generated_check_emits_only_on_merged
