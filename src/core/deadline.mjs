import { types } from "node:util";

import {
  BilateralProtocolError,
  ProtocolFailureError,
} from "./protocol.mjs";
import {
  MIN_POLL_INTERVAL_MS,
} from "./runner.mjs";

// Single source for the in-window budget arithmetic of the bilateral
// handshake. The signed window stays EXPIRY_WINDOW_MS (600 s, pinned by
// the canonical descriptor field expirySeconds "600"); safety comes from
// sequencing. Worst case under maximal throttling is ~609 s > 600 s, so a
// depleted window must close with the named EXPIRED code, never a zombie
// and never a generic FAILED.

// Worst-case budget reserved for the ACKNOWLEDGED write inside the
// window (the rate-ceiling figure from the two-regime derivation).
export const ACK_WRITE_BUDGET_MS = 223_500;

// The payer mandate must leave a human-paced window for the requestor
// between issuance and expiry.
export const MANDATE_MIN_WINDOW_MS = 1_800_000;

const BOUND_INPUT_KEYS = Object.freeze([
  "nowMs",
  "proposalDeadlineMs",
]);
const MANDATE_WINDOW_KEYS = Object.freeze([
  "expiresAtMs",
  "issuedAtMs",
]);

function inputFailure(code) {
  return new BilateralProtocolError(
    "Deadline input is invalid.",
    code,
  );
}

function readExactKeys(input, expectedKeys, code) {
  if (
    input === null ||
    typeof input !== "object" ||
    types.isProxy(input) ||
    (
      Object.getPrototypeOf(input) !== Object.prototype &&
      Object.getPrototypeOf(input) !== null
    )
  ) {
    throw inputFailure(code);
  }
  const keys = Object.keys(input);
  if (
    keys.length !== expectedKeys.length ||
    !expectedKeys.every((key) => keys.includes(key))
  ) {
    throw inputFailure(code);
  }
  return input;
}

function safeIntegerMs(value, code) {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 0
  ) {
    throw inputFailure(code);
  }
  return BigInt(value);
}

function decimalMs(value, code) {
  if (
    typeof value === "string" &&
    /^(0|[1-9][0-9]*)$/.test(value)
  ) {
    return BigInt(value);
  }
  return safeIntegerMs(value, code);
}

// The poll bound for watching the next in-window anchor: the remaining
// window minus the reserved ACKNOWLEDGED write budget. Never merely
// bounded by EXPIRY_WINDOW_MS.
export function inWindowPollBoundMs(input) {
  const snapshot = readExactKeys(
    input,
    BOUND_INPUT_KEYS,
    "DEADLINE_INPUT",
  );
  const nowMs = safeIntegerMs(snapshot.nowMs, "DEADLINE_INPUT");
  const proposalDeadlineMs = safeIntegerMs(
    snapshot.proposalDeadlineMs,
    "DEADLINE_INPUT",
  );
  const bound =
    proposalDeadlineMs - nowMs - BigInt(ACK_WRITE_BUDGET_MS);
  return Number(bound);
}

// Caller-side floor check. The ported pollDuration() helper throws a
// generic terminal("FAILED") below MIN_POLL_INTERVAL_MS, which would
// violate the named-failure contract; the caller must run this check
// first so a depleted window closes named EXPIRED.
export function assertInWindowPollBound(input) {
  const bound = inWindowPollBoundMs(input);
  if (bound < MIN_POLL_INTERVAL_MS) {
    throw new ProtocolFailureError(
      "The remaining window is too depleted to complete the handshake safely.",
      "EXPIRED",
    );
  }
  return bound;
}

// Mandate construction guard: the human-paced window between issuance
// and expiry must be at least MANDATE_MIN_WINDOW_MS. Accepts the
// canonical decimal-string form used by the signed mandate as well as
// safe-integer milliseconds.
export function assertMandateConstructionWindow(input) {
  const snapshot = readExactKeys(
    input,
    MANDATE_WINDOW_KEYS,
    "DEADLINE_MANDATE_INPUT",
  );
  const issuedAtMs = decimalMs(
    snapshot.issuedAtMs,
    "DEADLINE_MANDATE_INPUT",
  );
  const expiresAtMs = decimalMs(
    snapshot.expiresAtMs,
    "DEADLINE_MANDATE_INPUT",
  );
  if (
    expiresAtMs - issuedAtMs < BigInt(MANDATE_MIN_WINDOW_MS)
  ) {
    throw new BilateralProtocolError(
      "The payer mandate does not leave a human-paced window.",
      "DEADLINE_MANDATE_WINDOW",
    );
  }
}
