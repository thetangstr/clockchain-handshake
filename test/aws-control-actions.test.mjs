import assert from "node:assert/strict";
import { test } from "node:test";

import {
  ACTION_TYPES,
  applyControlAction,
  createInitialControlState,
  validateControlAction,
  validateControlState,
} from "../src/bilateral/aws/control-actions.mjs";

const REPOSITORY_SHA =
  "abcdef0123456789abcdef0123456789abcdef01";
const RELEASE_ID = "release-0123456789abcdef";
const SESSION_ID =
  "11111111-2222-4333-8444-555555555555";
const PAYER_FINGERPRINT = "a".repeat(64);
const REQUESTOR_FINGERPRINT = "b".repeat(64);
const IDS = Object.freeze([
  "11111111-1111-4111-8111-111111111111",
  "22222222-2222-4222-8222-222222222222",
  "33333333-3333-4333-8333-333333333333",
  "44444444-4444-4444-8444-444444444444",
  "55555555-5555-4555-8555-555555555555",
  "66666666-6666-4666-8666-666666666666",
]);

function start(overrides = {}) {
  return {
    actionId: IDS[0],
    expectedRevision: 0,
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    type: "START_RUN",
    ...overrides,
  };
}

function later(type, revision, id, overrides = {}) {
  return {
    actionId: id,
    expectedRevision: revision,
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
    type,
    ...overrides,
  };
}

function approval(
  type,
  revision,
  id,
  claimFingerprint,
  overrides = {},
) {
  return {
    actionId: id,
    claimFingerprint,
    expectedRevision: revision,
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
    type,
    ...overrides,
  };
}

function apply(state, action, options = {}) {
  return applyControlAction({
    action,
    state,
    ...options,
  });
}

test("accepts only the six exact action types", () => {
  assert.deepEqual(ACTION_TYPES, [
    "START_RUN",
    "APPROVE_PAYER",
    "APPROVE_REQUESTOR",
    "FUND",
    "VERIFY",
    "ABORT",
  ]);
  assert.deepEqual(validateControlAction(start()), start());
  for (const hostile of [
    { ...start(), extra: false },
    { ...start(), paymentMoved: true },
    { ...start(), type: "AUTHORIZE" },
    { ...start(), expectedRevision: 1 },
    {
      ...later("FUND", 3, IDS[3]),
      addresses: ["0xprivate"],
    },
  ]) {
    assert.throws(
      () => validateControlAction(hostile),
      /AWS control action failed safely/,
    );
  }
});

test("rejects accessor-backed actions without invoking them", () => {
  let accessed = false;
  const hostile = {
    actionId: IDS[0],
    expectedRevision: 0,
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    get type() {
      accessed = true;
      return "START_RUN";
    },
  };
  assert.throws(
    () => validateControlAction(hostile),
    /AWS control action failed safely/,
  );
  assert.equal(accessed, false);
});

test("advances the exact operator sequence and stores no authority material", () => {
  let state = createInitialControlState();
  state = apply(state, start(), {
    createdSessionId: SESSION_ID,
  });
  assert.equal(state.status, "RUN_STARTED");
  state = apply(
    state,
    approval(
      "APPROVE_PAYER",
      1,
      IDS[1],
      PAYER_FINGERPRINT,
    ),
    { expectedClaimFingerprint: PAYER_FINGERPRINT },
  );
  assert.equal(state.status, "PAYER_APPROVED");
  state = apply(
    state,
    approval(
      "APPROVE_REQUESTOR",
      2,
      IDS[2],
      REQUESTOR_FINGERPRINT,
    ),
    {
      expectedClaimFingerprint:
        REQUESTOR_FINGERPRINT,
    },
  );
  assert.equal(state.status, "REQUESTOR_APPROVED");
  state = apply(
    state,
    later("FUND", 3, IDS[3]),
  );
  assert.equal(state.status, "FUND_REQUESTED");
  state = apply(
    state,
    later("VERIFY", 4, IDS[4]),
  );
  assert.equal(state.status, "VERIFY_REQUESTED");
  assert.equal(state.revision, 5);
  assert.equal(state.paymentMoved, false);
  assert.equal(
    JSON.stringify(state).includes(PAYER_FINGERPRINT),
    false,
  );
  assert.equal(
    JSON.stringify(state).includes(
      REQUESTOR_FINGERPRINT,
    ),
    false,
  );
});

test("returns the identical state for an exact idempotent retry and rejects changed reuse", () => {
  const initial = createInitialControlState();
  const once = apply(initial, start(), {
    createdSessionId: SESSION_ID,
  });
  assert.equal(
    apply(once, start(), {
      createdSessionId: SESSION_ID,
    }),
    once,
  );
  for (const changed of [
    start({ repositorySha: "f".repeat(40) }),
    start({ releaseId: "release-fedcba9876543210" }),
    start({ type: "ABORT" }),
  ]) {
    assert.throws(
      () => apply(once, changed, {
        createdSessionId: SESSION_ID,
      }),
      /AWS control action failed safely/,
    );
  }
});

test("rejects stale, cross-session, changed-fingerprint, skipped, and duplicate actions", () => {
  const started = apply(
    createInitialControlState(),
    start(),
    { createdSessionId: SESSION_ID },
  );
  for (const action of [
    approval(
      "APPROVE_PAYER",
      0,
      IDS[1],
      PAYER_FINGERPRINT,
    ),
    approval(
      "APPROVE_PAYER",
      1,
      IDS[1],
      PAYER_FINGERPRINT,
      {
        sessionId:
          "77777777-7777-4777-8777-777777777777",
      },
    ),
    approval(
      "APPROVE_PAYER",
      1,
      IDS[1],
      REQUESTOR_FINGERPRINT,
    ),
    later("FUND", 1, IDS[3]),
    later("VERIFY", 1, IDS[4]),
  ]) {
    assert.throws(
      () => apply(started, action, {
        expectedClaimFingerprint:
          PAYER_FINGERPRINT,
      }),
      /AWS control action failed safely/,
    );
  }

  const payerApproved = apply(
    started,
    approval(
      "APPROVE_PAYER",
      1,
      IDS[1],
      PAYER_FINGERPRINT,
    ),
    { expectedClaimFingerprint: PAYER_FINGERPRINT },
  );
  assert.throws(
    () => apply(
      payerApproved,
      approval(
        "APPROVE_PAYER",
        2,
        IDS[5],
        PAYER_FINGERPRINT,
      ),
      { expectedClaimFingerprint: PAYER_FINGERPRINT },
    ),
    /AWS control action failed safely/,
  );
});

test("ABORT is terminal and no new action follows a verification request", () => {
  const started = apply(
    createInitialControlState(),
    start(),
    { createdSessionId: SESSION_ID },
  );
  const aborted = apply(
    started,
    later("ABORT", 1, IDS[5]),
  );
  assert.equal(aborted.status, "ABORTED");
  assert.throws(
    () => apply(
      aborted,
      later("FUND", 2, IDS[3]),
    ),
    /AWS control action failed safely/,
  );

  let verified = apply(
    started,
    approval(
      "APPROVE_PAYER",
      1,
      IDS[1],
      PAYER_FINGERPRINT,
    ),
    { expectedClaimFingerprint: PAYER_FINGERPRINT },
  );
  verified = apply(
    verified,
    approval(
      "APPROVE_REQUESTOR",
      2,
      IDS[2],
      REQUESTOR_FINGERPRINT,
    ),
    {
      expectedClaimFingerprint:
        REQUESTOR_FINGERPRINT,
    },
  );
  verified = apply(
    verified,
    later("FUND", 3, IDS[3]),
  );
  verified = apply(
    verified,
    later("VERIFY", 4, IDS[4]),
  );
  for (const action of [
    later("VERIFY", 5, IDS[5]),
    later("FUND", 5, IDS[5]),
    later("ABORT", 5, IDS[5]),
  ]) {
    assert.throws(
      () => apply(verified, action),
      /AWS control action failed safely/,
    );
  }
});

test("validates canonical control states and rejects forged history", () => {
  let valid = apply(
    createInitialControlState(),
    start(),
    { createdSessionId: SESSION_ID },
  );
  valid = apply(
    valid,
    approval(
      "APPROVE_PAYER",
      1,
      IDS[1],
      PAYER_FINGERPRINT,
    ),
    { expectedClaimFingerprint: PAYER_FINGERPRINT },
  );
  assert.deepEqual(
    validateControlState(valid),
    valid,
  );
  const cases = [
    {
      ...valid,
      status: "VERIFY_REQUESTED",
    },
    {
      ...valid,
      status: "AUTHORIZED",
    },
    {
      ...valid,
      actionHistory: [
        ...valid.actionHistory,
        {
          actionDigest: "c".repeat(64),
          actionId: IDS[2],
        },
      ],
      revision: 3,
    },
    {
      ...valid,
      actionHistory: [
        valid.actionHistory[0],
        {
          ...valid.actionHistory[1],
          actionId:
            valid.actionHistory[0].actionId,
        },
      ],
    },
    {
      ...valid,
      actionHistory: [
        valid.actionHistory[1],
        valid.actionHistory[0],
      ],
    },
  ];
  for (const forged of cases) {
    assert.throws(
      () => validateControlState(forged),
      /AWS control action failed safely/,
    );
  }
});
