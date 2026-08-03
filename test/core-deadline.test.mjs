import assert from "node:assert/strict";
import test from "node:test";

import {
  EXPIRY_WINDOW_MS,
} from "../src/core/blocktime.mjs";
import {
  ACK_WRITE_BUDGET_MS,
  assertInWindowPollBound,
  assertMandateConstructionWindow,
  inWindowPollBoundMs,
  MANDATE_MIN_WINDOW_MS,
} from "../src/core/deadline.mjs";
import {
  DESCRIPTOR_EXPIRY_SECONDS,
} from "../src/core/descriptor.mjs";
import {
  BilateralProtocolError,
  ProtocolFailureError,
} from "../src/core/protocol.mjs";
import {
  MIN_POLL_INTERVAL_MS,
} from "../src/core/runner.mjs";

const PROPOSED_BLOCK_TIME_MS = 1_800_000_000_000;

test("pins the budget constants of the two-regime deadline derivation", () => {
  assert.equal(EXPIRY_WINDOW_MS, 600_000);
  assert.equal(DESCRIPTOR_EXPIRY_SECONDS, "600");
  assert.equal(
    EXPIRY_WINDOW_MS,
    Number(DESCRIPTOR_EXPIRY_SECONDS) * 1_000,
  );
  assert.equal(ACK_WRITE_BUDGET_MS, 223_500);
  assert.equal(MIN_POLL_INTERVAL_MS, 20_000);
  assert.equal(MANDATE_MIN_WINDOW_MS, 1_800_000);
  assert.ok(MANDATE_MIN_WINDOW_MS >= 30 * 60 * 1_000);
});

test("bounds the in-window poll by the remaining window minus the ACK budget", () => {
  const proposalDeadlineMs =
    PROPOSED_BLOCK_TIME_MS + EXPIRY_WINDOW_MS;
  const bound = inWindowPollBoundMs({
    nowMs: PROPOSED_BLOCK_TIME_MS,
    proposalDeadlineMs,
  });

  assert.equal(bound, EXPIRY_WINDOW_MS - ACK_WRITE_BUDGET_MS);
  assert.equal(bound, 376_500);
  // The bound must never reach the bare window size: the
  // 600_000 <= 600_000 comparison is explicitly insufficient.
  assert.ok(bound < EXPIRY_WINDOW_MS);
  assert.ok(bound >= MIN_POLL_INTERVAL_MS);
});

test("leaves the full ACK budget after a late ACCEPTED discovery", () => {
  const proposalDeadlineMs =
    PROPOSED_BLOCK_TIME_MS + EXPIRY_WINDOW_MS;
  // The latest discovery time that still admits polling.
  const nowMs =
    proposalDeadlineMs -
    ACK_WRITE_BUDGET_MS -
    MIN_POLL_INTERVAL_MS;
  const bound = assertInWindowPollBound({
    nowMs,
    proposalDeadlineMs,
  });

  assert.equal(bound, MIN_POLL_INTERVAL_MS);
  assert.equal(
    proposalDeadlineMs - nowMs - bound,
    ACK_WRITE_BUDGET_MS,
  );
});

test("closes a sub-floor bound with named EXPIRED, never generic FAILED", () => {
  const proposalDeadlineMs =
    PROPOSED_BLOCK_TIME_MS + EXPIRY_WINDOW_MS;
  const nowMs =
    proposalDeadlineMs -
    ACK_WRITE_BUDGET_MS -
    MIN_POLL_INTERVAL_MS +
    1;

  assert.equal(
    inWindowPollBoundMs({ nowMs, proposalDeadlineMs }),
    MIN_POLL_INTERVAL_MS - 1,
  );
  assert.throws(
    () =>
      assertInWindowPollBound({ nowMs, proposalDeadlineMs }),
    (error) => {
      assert.ok(error instanceof ProtocolFailureError);
      assert.equal(error.terminalCode, "EXPIRED");
      assert.equal(error.code, "EXPIRED");
      assert.notEqual(error.terminalCode, "FAILED");
      return true;
    },
  );
});

test("closes an already-elapsed deadline with named EXPIRED", () => {
  const proposalDeadlineMs =
    PROPOSED_BLOCK_TIME_MS + EXPIRY_WINDOW_MS;
  assert.throws(
    () =>
      assertInWindowPollBound({
        nowMs: proposalDeadlineMs,
        proposalDeadlineMs,
      }),
    (error) => {
      assert.ok(error instanceof ProtocolFailureError);
      assert.equal(error.terminalCode, "EXPIRED");
      return true;
    },
  );
});

test("admits mandate windows of at least thirty minutes in either numeric form", () => {
  const issuedAtMs = PROPOSED_BLOCK_TIME_MS;
  for (const form of [
    {
      expiresAtMs: issuedAtMs + MANDATE_MIN_WINDOW_MS,
      issuedAtMs,
    },
    {
      expiresAtMs: String(issuedAtMs + MANDATE_MIN_WINDOW_MS),
      issuedAtMs: String(issuedAtMs),
    },
    {
      expiresAtMs: String(issuedAtMs + 3_600_000),
      issuedAtMs: String(issuedAtMs),
    },
  ]) {
    assert.equal(
      assertMandateConstructionWindow(form),
      undefined,
    );
  }
});

test("refuses mandate windows below the human-paced floor", () => {
  const issuedAtMs = PROPOSED_BLOCK_TIME_MS;
  for (const form of [
    {
      expiresAtMs: issuedAtMs + MANDATE_MIN_WINDOW_MS - 1,
      issuedAtMs,
    },
    {
      expiresAtMs: String(issuedAtMs),
      issuedAtMs: String(issuedAtMs),
    },
    {
      expiresAtMs: String(issuedAtMs - 1),
      issuedAtMs: String(issuedAtMs),
    },
  ]) {
    assert.throws(
      () => assertMandateConstructionWindow(form),
      (error) => {
        assert.ok(error instanceof BilateralProtocolError);
        assert.equal(error.code, "DEADLINE_MANDATE_WINDOW");
        return true;
      },
    );
  }
});

test("rejects hostile deadline inputs without reading stray keys", () => {
  const valid = {
    nowMs: PROPOSED_BLOCK_TIME_MS,
    proposalDeadlineMs:
      PROPOSED_BLOCK_TIME_MS + EXPIRY_WINDOW_MS,
  };
  for (const input of [
    null,
    42,
    "600000",
    [],
    new Proxy(valid, {}),
    { ...valid, extra: 1 },
    { nowMs: valid.nowMs },
    { nowMs: -1, proposalDeadlineMs: valid.proposalDeadlineMs },
    { nowMs: 1.5, proposalDeadlineMs: valid.proposalDeadlineMs },
    { nowMs: "1", proposalDeadlineMs: valid.proposalDeadlineMs },
    { nowMs: valid.nowMs, proposalDeadlineMs: 2n ** 60n },
  ]) {
    assert.throws(
      () => inWindowPollBoundMs(input),
      (error) => {
        assert.ok(error instanceof BilateralProtocolError);
        assert.equal(error.code, "DEADLINE_INPUT");
        return true;
      },
    );
  }
});
