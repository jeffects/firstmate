#!/usr/bin/env bash
# tests/fm-merge-local.test.sh - the review->merge SHA bind for local-only ship
# tasks (bin/fm-review-diff.sh records reviewed_head=<sha>; bin/fm-merge-local.sh
# refuses unless the branch HEAD still equals it). Closes the TOCTOU where a crew
# pushes new commits between the captain approving the diff and the local merge.
# Also checks the existing clean-fast-forward-only behavior is preserved.
set -u

# shellcheck source=tests/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

REVIEW="$ROOT/bin/fm-review-diff.sh"
MERGE="$ROOT/bin/fm-merge-local.sh"
TMP_ROOT=$(fm_test_tmproot fm-merge-local-tests)

# FM_ROOT_OVERRIDE -> a non-repo dir so the scripts' fm-guard.sh call is a no-op
# (absent path, swallowed by `|| true`), keeping these tests free of guard noise.
noguard() { local d="$TMP_ROOT/noguard"; mkdir -p "$d"; printf '%s' "$d"; }
run_review() { local state=$1 id=$2; FM_ROOT_OVERRIDE="$(noguard)" FM_STATE_OVERRIDE="$state" "$REVIEW" "$id"; }
run_merge()  { local state=$1 id=$2; FM_ROOT_OVERRIDE="$(noguard)" FM_STATE_OVERRIDE="$state" "$MERGE" "$id"; }

# Build a local-only project on its default branch plus a worktree on fm/<id> that
# is one commit ahead (so a clean fast-forward is possible). Echoes "<repo> <wt>
# <default>".
build_case() {  # <name> <id>
  local name=$1 id=$2 repo wt default
  repo="$TMP_ROOT/$name/proj"; wt="$TMP_ROOT/$name/wt"
  fm_git_worktree "$repo" "$wt" "fm/$id"
  default=$(git -C "$repo" symbolic-ref --short HEAD)
  printf 'feature\n' > "$wt/feature.txt"
  git -C "$wt" add feature.txt
  git -C "$wt" commit -qm feature
  printf '%s %s %s' "$repo" "$wt" "$default"
}

write_meta() {  # <state> <id> <repo> <wt>
  local state=$1 id=$2 repo=$3 wt=$4
  mkdir -p "$state"
  fm_write_meta "$state/$id.meta" \
    "window=sess:fm-$id" "worktree=$wt" "project=$repo" "harness=echo" \
    "kind=ship" "mode=local-only" "yolo=off"
}

test_merge_succeeds_when_head_matches_review() {
  local id state repo wt default before after out
  id="loc-ok1"; state="$TMP_ROOT/ok/state"
  fm_git_identity fmtest fmtest@example.invalid
  read -r repo wt default <<<"$(build_case ok "$id")"
  write_meta "$state" "$id" "$repo" "$wt"
  run_review "$state" "$id" >/dev/null 2>&1 || fail "review-diff failed"
  assert_grep "reviewed_head=" "$state/$id.meta" "review-diff must record reviewed_head"
  before=$(git -C "$repo" rev-parse "$default")
  out=$(run_merge "$state" "$id" 2>&1) || fail "merge-local refused a matching HEAD: $out"
  after=$(git -C "$repo" rev-parse "$default")
  [ "$after" = "$(git -C "$wt" rev-parse "fm/$id")" ] || fail "default not fast-forwarded to the reviewed tip"
  [ "$before" != "$after" ] || fail "default branch did not advance on merge"
  pass "merge-local fast-forwards when branch HEAD still equals reviewed_head"
}

test_merge_refused_when_head_moved_after_review() {
  local id state repo wt default before out rc
  id="loc-move1"; state="$TMP_ROOT/move/state"
  fm_git_identity fmtest fmtest@example.invalid
  read -r repo wt default <<<"$(build_case move "$id")"
  write_meta "$state" "$id" "$repo" "$wt"
  run_review "$state" "$id" >/dev/null 2>&1 || fail "review-diff failed"
  # The crew pushes a new commit AFTER the captain reviewed/approved the diff.
  printf 'sneaky\n' > "$wt/sneaky.txt"
  git -C "$wt" add sneaky.txt
  git -C "$wt" commit -qm sneaky
  before=$(git -C "$repo" rev-parse "$default")
  out=$(run_merge "$state" "$id" 2>&1); rc=$?
  [ "$rc" -ne 0 ] || fail "merge-local must refuse after the branch HEAD moved"
  printf '%s' "$out" | grep -F "has moved since review" >/dev/null || fail "refusal message missing: $out"
  [ "$(git -C "$repo" rev-parse "$default")" = "$before" ] || fail "default advanced despite refusal"
  pass "merge-local refuses and does not merge when HEAD moved since review"
}

test_merge_refused_without_recorded_review() {
  local id state repo wt default out rc
  id="loc-noreview1"; state="$TMP_ROOT/noreview/state"
  fm_git_identity fmtest fmtest@example.invalid
  read -r repo wt default <<<"$(build_case noreview "$id")"
  write_meta "$state" "$id" "$repo" "$wt"
  # Deliberately skip review-diff: no reviewed_head recorded.
  out=$(run_merge "$state" "$id" 2>&1); rc=$?
  [ "$rc" -ne 0 ] || fail "merge-local must refuse without a recorded reviewed_head"
  printf '%s' "$out" | grep -F "no reviewed_head recorded" >/dev/null || fail "missing-review refusal message missing: $out"
  pass "merge-local refuses when review was never run (no reviewed_head)"
}

test_merge_refused_when_branch_diverged() {
  local id state repo wt default before out rc
  id="loc-div1"; state="$TMP_ROOT/div/state"
  fm_git_identity fmtest fmtest@example.invalid
  read -r repo wt default <<<"$(build_case div "$id")"
  write_meta "$state" "$id" "$repo" "$wt"
  run_review "$state" "$id" >/dev/null 2>&1 || fail "review-diff failed"
  # The default branch advances independently so the reviewed branch is no longer a
  # fast-forward of it (diverged), while the branch HEAD still equals reviewed_head
  # (so the SHA-bind passes and we reach the ancestor/fast-forward check).
  printf 'mainline\n' > "$repo/mainline.txt"
  git -C "$repo" add mainline.txt
  git -C "$repo" commit -qm mainline
  before=$(git -C "$repo" rev-parse "$default")
  out=$(run_merge "$state" "$id" 2>&1); rc=$?
  [ "$rc" -ne 0 ] || fail "merge-local must refuse a diverged (non-fast-forward) branch"
  printf '%s' "$out" | grep -F "is not a fast-forward" >/dev/null || fail "diverged refusal message missing: $out"
  [ "$(git -C "$repo" rev-parse "$default")" = "$before" ] || fail "default advanced despite diverged refusal"
  pass "merge-local refuses a diverged branch (clean fast-forward-only preserved)"
}

test_merge_succeeds_when_head_matches_review
test_merge_refused_when_head_moved_after_review
test_merge_refused_without_recorded_review
test_merge_refused_when_branch_diverged
