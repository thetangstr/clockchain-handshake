import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  BLOCK_TIME_PATTERN,
  BlockTimeParseError,
  EXPIRY_WINDOW_MS,
  LIVE_UPPER_BOUND_SLACK_MS,
  deadlineMs,
  isWithinDeadline,
  liveUpperBoundMs,
  parseBlockTime,
  verifierUpperBoundMs,
} from "../src/core/blocktime.mjs";

const MODULE_URL = new URL(
  "../src/core/blocktime.mjs",
  import.meta.url,
);

// The only accepted shape is the one get_block returns: RFC3339 with a
// 1-9 digit fraction and a literal uppercase Z. Everything else observed
// from the gateway, and everything Date.parse would tolerate, is rejected.
const REJECTED_INPUTS = [
  // Gateway formats from OTHER endpoints, each a banned clock.
  "24-07-2026_19:27:50:981",
  "23-07-2026 19:00:52:165 UTC",
  // Date.parse-accepted garbage: MM-DD-YYYY in the host local zone.
  "07-08-2026",
  // Bare ISO without an offset.
  "2026-07-24T19:27:49.556",
  "2026-07-24T19:27:49",
  // Numeric offsets instead of Z.
  "2026-07-24T19:27:49.556+00:00",
  "2026-07-24T19:27:49.556-05:00",
  // Missing mandatory fraction.
  "2026-07-24T19:27:49Z",
  // Fraction too long or empty.
  "2026-07-24T19:27:49.5560279123Z",
  "2026-07-24T19:27:49.Z",
  // Lowercase z, trailing or leading noise, embedded newline.
  "2026-07-24T19:27:49.556027912z",
  " 2026-07-24T19:27:49.556027912Z",
  "2026-07-24T19:27:49.556027912Z ",
  "2026-07-24T19:27:49.556027912Z\n",
  "x2026-07-24T19:27:49.556027912Z",
  // Space separator instead of T.
  "2026-07-24 19:27:49.556027912Z",
  // Calendar-invalid components that Date.UTC would silently roll over.
  "2026-02-29T00:00:00.000000000Z",
  "2100-02-29T00:00:00.000000000Z",
  "2026-13-01T00:00:00.000000000Z",
  "2026-00-01T00:00:00.000000000Z",
  "2026-07-32T00:00:00.000000000Z",
  "2026-07-00T00:00:00.000000000Z",
  "2026-07-24T24:00:00.000000000Z",
  "2026-07-24T19:60:00.000000000Z",
  // Leap seconds are rejected: fail closed on anything unobserved.
  "2026-07-24T19:27:60.000000000Z",
  // Unicode confusable digit (fullwidth 2) and empty string.
  "２026-07-24T19:27:49.556027912Z",
  "",
];

test("rejects every non-canonical block time with a typed error", () => {
  for (const input of REJECTED_INPUTS) {
    assert.throws(
      () => parseBlockTime(input),
      BlockTimeParseError,
      `expected rejection for ${JSON.stringify(input)}`,
    );
  }
});

test("rejects non-string inputs with a typed error", () => {
  for (const input of [
    1784921269556,
    null,
    undefined,
    {},
    ["2026-07-24T19:27:49.556027912Z"],
    new String("2026-07-24T19:27:49.556027912Z"),
  ]) {
    assert.throws(() => parseBlockTime(input), BlockTimeParseError);
  }
});

test("BlockTimeParseError is typed and never echoes the raw input", () => {
  const error = (() => {
    try {
      parseBlockTime("24-07-2026_19:27:50:981");
    } catch (thrown) {
      return thrown;
    }
    assert.fail("expected parseBlockTime to throw");
  })();

  assert.equal(error.name, "BlockTimeParseError");
  assert.equal(error.code, "BLOCK_TIME_UNPARSEABLE");
  assert.ok(!error.message.includes("24-07-2026"));
});

test("parses the exact get_block shape, truncating the fraction toward zero", () => {
  // Observed live: get_block returns nine fractional digits.
  assert.equal(
    parseBlockTime("2026-07-24T19:27:49.556027912Z"),
    1784921269556,
  );
  // Truncation, never rounding: .5569... stays 556.
  assert.equal(
    parseBlockTime("2026-07-24T19:27:49.556999999Z"),
    1784921269556,
  );
  // Short fractions are right-padded with zeros before truncation.
  assert.equal(parseBlockTime("2026-07-24T19:27:49.5Z"), 1784921269500);
  assert.equal(parseBlockTime("2026-07-24T19:27:49.55Z"), 1784921269550);
  // The epoch itself.
  assert.equal(parseBlockTime("1970-01-01T00:00:00.000000000Z"), 0);
  // Leap-day handling: 2028 and 2000 are leap years.
  assert.equal(parseBlockTime("2028-02-29T00:00:00.0Z"), 1835395200000);
  assert.equal(parseBlockTime("2000-02-29T12:30:45.999999999Z"), 951827445999);
  // The two live-observed anchors from the probe.
  assert.equal(
    parseBlockTime("2026-07-24T20:08:13.788993755Z"),
    1784923693788,
  );
  assert.equal(
    parseBlockTime("2026-07-23T19:04:41.057495507Z"),
    1784833481057,
  );
});

test("parse results are safe integers", () => {
  const parsed = parseBlockTime("2026-07-24T19:27:49.556027912Z");
  assert.ok(Number.isSafeInteger(parsed));
});

test("BLOCK_TIME_PATTERN is exactly the spec regex", () => {
  assert.equal(
    BLOCK_TIME_PATTERN.source,
    "^(\\d{4})-(\\d{2})-(\\d{2})T(\\d{2}):(\\d{2}):(\\d{2})\\.(\\d{1,9})Z$",
  );
  assert.equal(BLOCK_TIME_PATTERN.flags, "");
});

test("Date.parse and the Date constructor are unreachable from the module", () => {
  const source = readFileSync(MODULE_URL, "utf8");
  assert.ok(!source.includes("Date.parse"));
  assert.ok(!source.includes("new Date("));
  // Pure epoch-ms arithmetic: the module never touches Date at all.
  assert.ok(!source.includes("Date."));
});

test("expiry constants are pinned to the spec", () => {
  // Descriptor expirySeconds "600" measured in block time.
  assert.equal(EXPIRY_WINDOW_MS, 600000);
  // Section 5.3 live-path upper-bound slack.
  assert.equal(LIVE_UPPER_BOUND_SLACK_MS, 1100);
});

test("deadlineMs is truncate(blockTime(h1)) + 600000", () => {
  const h1 = parseBlockTime("2026-07-24T19:27:49.556027912Z");
  assert.equal(deadlineMs(h1), 1784921269556 + 600000);
  assert.equal(deadlineMs(0), 600000);
});

test("liveUpperBoundMs sides blockTime(h) up by exactly 1100 ms", () => {
  assert.equal(liveUpperBoundMs(1784921269556), 1784921269556 + 1100);
  assert.equal(liveUpperBoundMs(0), 1100);
});

test("verifierUpperBoundMs is blockTime(h + 1) taken verbatim", () => {
  // The verifier's sharper form: the NEXT block's own time, no constant.
  assert.equal(verifierUpperBoundMs(1784923693788), 1784923693788);
});

test("bound helpers reject non-integer injected values", () => {
  for (const helper of [
    deadlineMs,
    liveUpperBoundMs,
    verifierUpperBoundMs,
  ]) {
    assert.throws(() => helper("1784921269556"), TypeError);
    assert.throws(() => helper(1.5), TypeError);
    assert.throws(() => helper(NaN), TypeError);
    assert.throws(() => helper(-1), TypeError);
    assert.throws(() => helper(Number.MAX_SAFE_INTEGER + 1), TypeError);
  }
  assert.throws(() => isWithinDeadline("1", 2), TypeError);
  assert.throws(() => isWithinDeadline(1, NaN), TypeError);
  assert.throws(() => isWithinDeadline(1.5, 2), TypeError);
  assert.throws(() => isWithinDeadline(-1, 2), TypeError);
});

test("isWithinDeadline is inclusive at the deadline: <= per section 5.3", () => {
  const h1 = parseBlockTime("2026-07-24T19:27:49.556027912Z");
  const deadline = deadlineMs(h1);

  // Spec: "Require upperBound(h2) <= deadlineMs" — all three transitions
  // anchor AT or before the deadline; exactly-at PASSES, one past FAILS.
  assert.equal(isWithinDeadline(deadline - 1, deadline), true);
  assert.equal(isWithinDeadline(deadline, deadline), true);
  assert.equal(isWithinDeadline(deadline + 1, deadline), false);
});

test("the full live siding composes: upper bound, not raw block time", () => {
  const h1 = parseBlockTime("2026-07-24T19:27:49.556027912Z");
  const deadline = deadlineMs(h1);

  // A raw blockTime(h2) landing inside the last 1100 ms of the window is
  // optimistic; the sided upper bound correctly fails it.
  const lateAnchor = deadline - 1100 + 1;
  assert.equal(isWithinDeadline(lateAnchor, deadline), true);
  assert.equal(isWithinDeadline(liveUpperBoundMs(lateAnchor), deadline), false);

  // Exactly 1100 ms of headroom still passes.
  const boundaryAnchor = deadline - 1100;
  assert.equal(
    isWithinDeadline(liveUpperBoundMs(boundaryAnchor), deadline),
    true,
  );
});
