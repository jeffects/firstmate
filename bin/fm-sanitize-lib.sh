#!/usr/bin/env bash
# fm-sanitize-lib.sh - the canonical boundary for UNTRUSTED CREW TEXT.
#
# Crewmate status-line text and tmux pane content are attacker-influenceable:
# whoever drives a crew's pane or writes its state/<id>.status controls those
# bytes, and they flow into firstmate's own LLM context (fm-crew-state, fm-peek,
# the durable wake queue) and into the away-mode daemon's MARKED escalation
# injections. Two dangers ride along:
#
#   1. The 0x1f ASCII unit separator. Both trust markers depend on 0x1f being
#      untypable on a normal keyboard: the from-firstmate marker
#      (bin/fm-marker-lib.sh, label + 0x1f) and the afk daemon marker
#      (bin/fm-supervise-daemon.sh, a bare leading 0x1f). If raw crew text
#      carrying a 0x1f reached firstmate's context it could FORGE a marker and be
#      mistaken for a trusted from-firstmate request or an internal escalation.
#   2. Other control bytes (terminal escapes, NUL, DEL) plus overlong text, which
#      can corrupt the terminal, the wake queue's TAB-delimited records, or simply
#      flood the LLM's view.
#
# fm_sanitize_untrusted is the one chokepoint every such crossing routes through.
# It is for INBOUND UNTRUSTED text only; the legitimate marker-APPLICATION path
# (bin/fm-send.sh prepending bin/fm-marker-lib.sh's marker to a genuine
# from-firstmate request) is never sanitized.
#
# Control-byte policy: we delete every C0 control byte (0x00-0x1f, which covers
# the 0x1f trust-marker separator AND ESC 0x1b, the byte that starts terminal
# escape sequences) and DEL (0x7f), after folding TAB/CR/LF to spaces. We
# deliberately do NOT blanket-delete the raw 0x80-0x9f (C1) byte range: in this
# codebase's UTF-8 world those byte values appear only as continuation bytes
# inside legitimate multibyte characters (box drawing in a captured pane, accented
# text in a status note), so deleting them would mangle ordinary printable text
# while removing no marker (markers are built from the untypable 0x1f, which is
# C0 and always stripped). Keeping printable UTF-8 intact wins; the marker and
# escape threat is fully covered by the C0+DEL strip.
#
# No side effects on source. set -u / set -e safe.

if [ -n "${FM_SANITIZE_LIB_SOURCED:-}" ]; then
  return 0
fi
FM_SANITIZE_LIB_SOURCED=1

FM_SANITIZE_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The marker constant we key off (FM_FROMFIRST_MARK / FM_FROMFIRST_LABEL). Read
# from the lib so this stays correct if the marker ever changes; never guessed.
# shellcheck source=bin/fm-marker-lib.sh
. "$FM_SANITIZE_LIB_DIR/fm-marker-lib.sh"

# Default output length bound (characters). Generous enough for a status line or a
# distilled digest, tight enough to stop an overlong paste from flooding context.
# Override per call (arg 2) or globally via FM_SANITIZE_MAX.
FM_SANITIZE_MAX_DEFAULT="${FM_SANITIZE_MAX:-2000}"

# Visibly defanged replacement for a forged from-firstmate marker. By
# construction it carries no 0x1f, so it can never be re-read as the real marker.
FM_SANITIZE_MARKER_REPLACEMENT='[untrusted:fm-from-firstmate]'

# fm_sanitize_untrusted <text> [max_len]
# Clean attacker-influenceable text for safe inclusion in firstmate's context or a
# marked injection:
#   - neutralize any literal from-firstmate marker (label + 0x1f), keyed off the
#     bin/fm-marker-lib.sh constant, so untrusted text cannot forge it;
#   - fold TAB/CR/LF to single spaces (single-line use); callers that want a
#     different newline separator, e.g. the daemon's " - ", collapse newlines
#     themselves first, leaving none for this step;
#   - delete every remaining C0 control byte (incl. the 0x1f separator and ESC)
#     and DEL, so no trust-marker separator or terminal-escape byte survives;
#   - bound the result to max_len characters.
# Prints the cleaned text with no added trailing newline.
fm_sanitize_untrusted() {
  local text=${1-} max=${2:-$FM_SANITIZE_MAX_DEFAULT}
  case "$max" in ''|*[!0-9]*) max=$FM_SANITIZE_MAX_DEFAULT ;; esac
  # 1. Neutralize the exact from-firstmate marker (label immediately followed by
  #    the 0x1f separator). The generic C0 strip below also removes the 0x1f, but
  #    rewriting the whole token keeps the visible label from reading as trusted.
  text=${text//"$FM_FROMFIRST_MARK"/$FM_SANITIZE_MARKER_REPLACEMENT}
  # 2. Fold whitespace controls to spaces, then delete all other C0 controls and
  #    DEL. LC_ALL=C so the byte ranges are bytes, not locale collating elements.
  text=$(printf '%s' "$text" | LC_ALL=C tr '\t\r\n' '   ' | LC_ALL=C tr -d '\000-\037\177')
  # 3. Bound length.
  if [ "${#text}" -gt "$max" ]; then
    text=${text:0:max}
  fi
  printf '%s' "$text"
}

# fm_sanitize_untrusted_stream [per_line_max]
# Filter form for inherently MULTI-LINE untrusted blobs whose line breaks carry
# meaning (e.g. a captured tmux pane in fm-peek): sanitize each input line
# independently while PRESERVING the line structure. Single-line consumers use
# fm_sanitize_untrusted directly, which folds newlines into spaces.
# per_line_max is optional (defaults below); callers like fm-peek pipe with no
# args, so silence SC2120/SC2119 for this intentionally-optional parameter.
# shellcheck disable=SC2120
fm_sanitize_untrusted_stream() {
  local max=${1:-$FM_SANITIZE_MAX_DEFAULT} line
  case "$max" in ''|*[!0-9]*) max=$FM_SANITIZE_MAX_DEFAULT ;; esac
  while IFS= read -r line || [ -n "$line" ]; do
    fm_sanitize_untrusted "$line" "$max"
    printf '\n'
  done
}
