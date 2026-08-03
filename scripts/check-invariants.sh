#!/usr/bin/env bash
# G0/G1a invariant sweep for the v2 handshake repo.
#
#   --allow-pending   permit declared reason-code sites whose files have
#                     not landed yet (G0 only). Once any of src/relay,
#                     src/roles, or src/verifier exists, the sweep runs
#                     strict unless this flag is passed explicitly.
#
# Sections:
#   1. AUTHORIZED containment (single gated emission site + allowlist)
#   2. No OS-specific secret stores
#   3. Wait-identifier sweep (named allowlist with reasons)
#   4. Reason-code emission-site checklist
#   5. Single release-pin writer
#   6. Canonical byte-diff vs donor (npm run port:check)
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

ALLOW_PENDING=0
for arg in "$@"; do
  case "$arg" in
    --allow-pending) ALLOW_PENDING=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

# Once delivery-shell code starts landing, strictness is the default and
# --allow-pending must be a deliberate choice.
SHELL_CODE_PRESENT=0
for dir in src/relay src/roles src/verifier; do
  if [ -n "$(find "$dir" -name '*.mjs' -print -quit 2>/dev/null)" ]; then
    SHELL_CODE_PRESENT=1
  fi
done
if [ "$ALLOW_PENDING" -eq 0 ] && [ "$SHELL_CODE_PRESENT" -eq 1 ]; then
  echo "FAIL: delivery-shell code exists; the pending-site allowance" \
    "is G0-only. Re-run with --allow-pending only while that" \
    "milestone is open." >&2
  exit 1
fi

FAILURES=0
fail() { echo "FAIL: $1" >&2; FAILURES=$((FAILURES + 1)); }
note() { echo "note: $1"; }

section() { echo "-- $1"; }

# --- 1. AUTHORIZED containment ---------------------------------------
section "AUTHORIZED containment"

EMISSION='outcome: "AUTHORIZED"'
emission_files="$(grep -rl --include='*.mjs' -F "$EMISSION" src scripts 2>/dev/null || true)"
if [ "$emission_files" != "src/core/verdict.mjs" ]; then
  fail "AUTHORIZED emission must live only in src/core/verdict.mjs; found: ${emission_files:-none}"
fi
emission_count="$(grep -c -F "$EMISSION" src/core/verdict.mjs 2>/dev/null || true)"
if [ "$emission_count" != "1" ]; then
  fail "expected exactly one AUTHORIZED emission expression in verdict.mjs, found $emission_count"
fi

if ! grep -q 'requiredSubjectRun === "stakeholder"' src/core/verdict.mjs; then
  fail "subjectRun gate missing at the verdict emission path"
fi

# Every other occurrence of the literal (word-boundary) must be on the
# named allowlist:
#   src/core/verdict.mjs        — emission + validatePublishedBilateralVerdict
#   src/core/evidence.mjs       — AUTHORIZING_WORD_PATTERN ban (anti-false-authorization guard)
#   scripts/verify-bilateral-results.mjs — ported verifier CLI harness; prints the
#                                 outcome only after the gated verifier returns;
#                                 byte-pinned by port:check
#   scripts/check-invariants.sh — this sweep's own patterns
#   monitor/stakeholder/*       — display maps fed only by the signed publication (M1b)
#   monitor/control-plane/*     — display maps fed only by the signed publication (M1b)
#   test/**                     — tests
literal_hits="$(grep -rl -E '\bAUTHORIZED\b' src scripts prompts monitor 2>/dev/null | sort || true)"
for hit in $literal_hits; do
  case "$hit" in
    src/core/verdict.mjs|src/core/evidence.mjs) ;;
    scripts/verify-bilateral-results.mjs) ;;
    scripts/check-invariants.sh) ;;
    monitor/stakeholder/*|monitor/control-plane/*) ;;
    *) fail "unallowlisted AUTHORIZED literal in $hit" ;;
  esac
done

# --- 2. No OS-specific secret stores ----------------------------------
section "secret-store sweep"
# Allowlisted references (documentation of the deleted path only):
#   scripts/port-tests.mjs      — RENAMED_DONOR_TESTS registry records the
#                                 donor's deleted Keychain-coupled titles
#   scripts/check-invariants.sh — this sweep's own pattern
secret_hits="$(grep -rniE 'keychain|find-generic-password|security[[:space:]]+find|wincred|libsecret|secret-tool' src scripts prompts monitor 2>/dev/null | grep -v -e '^scripts/check-invariants.sh:' -e '^scripts/port-tests.mjs:' || true)"
if [ -n "$secret_hits" ]; then
  fail "OS-specific secret store reference(s):"$'\n'"$secret_hits"
fi

# --- 3. Wait-identifier sweep -----------------------------------------
section "wait-identifier sweep"
# Named allowlist (file: reason). Every entry's file must exist.
WAIT_ALLOWLIST=(
  "src/core/blocktime.mjs:EXPIRY_WINDOW_MS — ported, byte-pinned by port:check"
  "src/core/runner.mjs:poll cadence and completion bounds — ported, byte-pinned by port:check"
  "src/core/clockchain.mjs:HTTP client bounds — ported, byte-pinned by port:check"
  "src/core/deadline.mjs:M0 budget constants — reviewed two-regime derivation"
  "src/core/roles-core.mjs:ported wait plumbing — byte-pinned by port:check"
  "src/relay/server.mjs:long-poll waiter cap (MAX_POLL_WAIT_MS) and waiter timers — reviewed relay cadence"
  "src/relay/client.mjs:HTTP request timeout and long-poll slack — reviewed client bounds"
)
wait_allowlisted_file() {
  local file="$1" entry
  for entry in "${WAIT_ALLOWLIST[@]}"; do
    if [ "${entry%%:*}" = "$file" ]; then return 0; fi
  done
  return 1
}
for entry in "${WAIT_ALLOWLIST[@]}"; do
  if [ ! -f "${entry%%:*}" ]; then
    fail "stale wait allowlist entry: $entry"
  fi
done
wait_hits="$(grep -rnE '[A-Z_]*_MS[[:space:]]*=[[:space:]]*[0-9]' --include='*.mjs' src scripts 2>/dev/null || true)"
while IFS= read -r line; do
  [ -z "$line" ] && continue
  file="${line%%:*}"
  if ! wait_allowlisted_file "$file"; then
    fail "unreviewed wait constant: $line"
  fi
done <<< "$wait_hits"
timer_hits="$(grep -rnE 'setTimeout|setInterval' --include='*.mjs' src/relay src/roles src/verifier src/monitor scripts 2>/dev/null || true)"
while IFS= read -r line; do
  [ -z "$line" ] && continue
  file="${line%%:*}"
  if ! wait_allowlisted_file "$file"; then
    fail "unreviewed timer in delivery-shell code: $line"
  fi
done <<< "$timer_hits"

# --- 4. Reason-code emission-site checklist ---------------------------
section "reason-code site checklist"
# Frozen public set; each code names its declared emission file.
REASON_SITES=(
  "RENDEZVOUS_UNAVAILABLE:src/core/protocol.mjs"
  "EXPIRED:src/core/verdict.mjs"
  "MISSING:src/core/verdict.mjs"
  "DUPLICATE:src/core/verdict.mjs"
  "REORDERED:src/verifier/run.mjs"
  "MALFORMED:src/core/verdict.mjs"
  "AMBIGUOUS_WRITE:src/core/runner.mjs"
  "BINDING_MISMATCH:src/core/verdict.mjs"
  "ANCHOR_UNVERIFIED:src/core/verdict.mjs"
  "ROLE_ALREADY_BOUND:src/relay/server.mjs"
  "RATE_BLOCKED:src/core/verdict.mjs"
  "AMOUNT_UNRESOLVED:src/core/protocol.mjs"
  "FUNDING_REPLAYED:src/roles/operator.mjs"
  "FAILED:src/core/verdict.mjs"
)
for entry in "${REASON_SITES[@]}"; do
  code="${entry%%:*}"
  file="${entry#*:}"
  if [ ! -f "$file" ]; then
    if [ "$ALLOW_PENDING" -eq 1 ] || [ "$SHELL_CODE_PRESENT" -eq 0 ]; then
      note "PENDING $code — declared site $file not yet landed"
    else
      fail "$code has no emission site ($file missing)"
    fi
    continue
  fi
  if ! grep -q "\"$code\"" "$file"; then
    fail "$code literal not found in declared site $file"
  fi
done

# --- 5. Single release-pin writer --------------------------------------
section "release-pin single writer"
if [ ! -f scripts/release-pin.mjs ]; then
  fail "scripts/release-pin.mjs missing"
fi
pin_refs="$(grep -rl --include='*.mjs' -F 'release.json' src scripts 2>/dev/null || true)"
for ref in $pin_refs; do
  case "$ref" in
    scripts/release-pin.mjs) ;;
    *) fail "unallowlisted release.json reference in $ref (release-pin.mjs is the only writer)" ;;
  esac
done

# --- 6. Canonical byte-diff vs donor -----------------------------------
section "port byte-diff"
if ! npm run --silent port:check > /tmp/check-invariants-port.log 2>&1; then
  cat /tmp/check-invariants-port.log >&2
  fail "port:check not clean"
fi

if [ "$FAILURES" -gt 0 ]; then
  echo "check-invariants: $FAILURES failure(s)" >&2
  exit 1
fi
echo "check-invariants: clean"
