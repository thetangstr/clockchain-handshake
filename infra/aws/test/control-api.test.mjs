import assert from "node:assert/strict";
import { test } from "node:test";

import {
  CONTROL_API_BODY_LOGGING,
  createControlApiHandler,
} from "../lambda/control-api.mjs";
import {
  applyControlAction,
  controlActionBytes,
  createInitialControlState,
} from "../../../src/bilateral/aws/control-actions.mjs";

const ORIGIN = "https://clockchain.example";
const ISSUER =
  "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_example";
const AUDIENCE = "clockchain-console-client";
const REPOSITORY_SHA =
  "abcdef0123456789abcdef0123456789abcdef01";
const RELEASE_ID = "release-0123456789abcdef";
const ACTION_ID =
  "11111111-1111-4111-8111-111111111111";
const NOW_MS = 2_000_000_000_000;

function action(overrides = {}) {
  return {
    actionId: ACTION_ID,
    expectedRevision: 0,
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    type: "START_RUN",
    ...overrides,
  };
}

function event(
  value = action(),
  overrides = {},
) {
  return {
    body: controlActionBytes(value).toString("utf8"),
    headers: {
      authorization: "Bearer signed-jwt-canary",
      "content-type": "application/json",
      origin: ORIGIN,
    },
    httpMethod: "POST",
    path: "/actions",
    ...overrides,
  };
}

function fixture({
  claims = {
    aud: AUDIENCE,
    exp: Math.floor(NOW_MS / 1000) + 60,
    groups: ["clockchain-operators"],
    iss: ISSUER,
    sub: "operator-1",
  },
  idempotency = "CREATED",
  state = createInitialControlState(),
} = {}) {
  const calls = [];
  const handler = createControlApiHandler({
    allowedOrigin: ORIGIN,
    audience: AUDIENCE,
    issuer: ISSUER,
    nowMs: () => NOW_MS,
    operatorGroup: "clockchain-operators",
    putIdempotency: async (input) => {
      calls.push(["idempotency", input]);
      return idempotency;
    },
    readSessionState: async (input) => {
      calls.push(["state", input]);
      return {
        expectedClaimFingerprint: null,
        state,
      };
    },
    sendMessage: async (input) => {
      calls.push(["send", input]);
    },
    verifyJwt: async (token) => {
      calls.push(["jwt", token]);
      return claims;
    },
  });
  return { calls, handler };
}

test("accepts one canonical allowlisted action and returns only redacted queue status", async () => {
  assert.equal(CONTROL_API_BODY_LOGGING, false);
  const { calls, handler } = fixture();
  const response = await handler(event());
  assert.equal(response.statusCode, 202);
  assert.equal(
    response.headers["access-control-allow-origin"],
    ORIGIN,
  );
  const body = JSON.parse(response.body);
  assert.deepEqual(body, {
    actionId: ACTION_ID,
    revision: 1,
    status: "QUEUED",
  });
  assert.deepEqual(
    calls.filter(([name]) => name === "send")
      .map(([, input]) => input),
    [{
      body: controlActionBytes(action()),
      deduplicationId: ACTION_ID,
      groupId: RELEASE_ID,
    }],
  );
  assert.equal(
    response.body.includes("signed-jwt-canary"),
    false,
  );
});

test("serves only a same-origin bounded CORS preflight", async () => {
  const { calls, handler } = fixture();
  const response = await handler({
    body: "",
    headers: { origin: ORIGIN },
    httpMethod: "OPTIONS",
    path: "/actions",
  });
  assert.equal(response.statusCode, 204);
  assert.equal(
    response.headers["access-control-allow-origin"],
    ORIGIN,
  );
  assert.equal(
    response.headers["access-control-allow-methods"],
    "POST,OPTIONS",
  );
  assert.deepEqual(calls, []);
  assert.equal(
    (await handler({
      body: "",
      headers: {
        origin: "https://evil.example",
      },
      httpMethod: "OPTIONS",
      path: "/actions",
    })).statusCode,
    400,
  );
});

test("same-action idempotent retry is safely resent through FIFO deduplication and conflicting reuse fails", async () => {
  const same = fixture({ idempotency: "SAME" });
  assert.equal(
    (await same.handler(event())).statusCode,
    202,
  );
  assert.equal(
    same.calls.some(([name]) => name === "send"),
    true,
  );
  const conflict = fixture({
    idempotency: "CONFLICT",
  });
  const response = await conflict.handler(event());
  assert.equal(response.statusCode, 409);
  assert.deepEqual(JSON.parse(response.body), {
    actionId: null,
    revision: null,
    status: "REJECTED",
  });
});

test("accepts an exact retry after the durable session revision has advanced", async () => {
  const started = applyControlAction({
    action: action(),
    createdSessionId:
      "11111111-2222-4333-8444-555555555555",
    state: createInitialControlState(),
  });
  const same = fixture({
    idempotency: "SAME",
    state: started,
  });
  const response = await same.handler(event());
  assert.equal(response.statusCode, 202);
  assert.deepEqual(JSON.parse(response.body), {
    actionId: ACTION_ID,
    revision: 1,
    status: "QUEUED",
  });
});

test("rejects wrong issuer, audience, expiry, or operator group before state lookup", async () => {
  for (const claims of [
    {
      aud: "other",
      exp: Math.floor(NOW_MS / 1000) + 60,
      groups: ["clockchain-operators"],
      iss: ISSUER,
      sub: "operator-1",
    },
    {
      aud: AUDIENCE,
      exp: Math.floor(NOW_MS / 1000) + 60,
      groups: ["clockchain-operators"],
      iss: `${ISSUER}/other`,
      sub: "operator-1",
    },
    {
      aud: AUDIENCE,
      exp: Math.floor(NOW_MS / 1000),
      groups: ["clockchain-operators"],
      iss: ISSUER,
      sub: "operator-1",
    },
    {
      aud: AUDIENCE,
      exp: Math.floor(NOW_MS / 1000) + 60,
      groups: ["viewer"],
      iss: ISSUER,
      sub: "operator-1",
    },
  ]) {
    const { calls, handler } = fixture({ claims });
    assert.equal(
      (await handler(event())).statusCode,
      401,
    );
    assert.equal(
      calls.some(([name]) => name === "state"),
      false,
    );
  }
});

test("rejects cross-origin, noncanonical, oversized, duplicate, and forbidden fields", async () => {
  const cases = [
    event(action(), {
      headers: {
        authorization: "Bearer token",
        "content-type": "application/json",
        origin: "https://evil.example",
      },
    }),
    event(action(), {
      body: ` ${controlActionBytes(action()).toString("utf8")}`,
    }),
    event(action(), {
      body: `{"actionId":"${ACTION_ID}","actionId":"${ACTION_ID}","expectedRevision":0,"paymentMoved":false,"releaseId":"${RELEASE_ID}","repositorySha":"${REPOSITORY_SHA}","type":"START_RUN"}`,
    }),
    event(action(), {
      body: JSON.stringify({
        ...action(),
        token: "cc_secret_control_canary",
      }),
    }),
    event(action(), {
      body: "x".repeat(16_385),
    }),
  ];
  for (const candidate of cases) {
    const { calls, handler } = fixture();
    const response = await handler(candidate);
    assert.equal(response.statusCode, 400);
    assert.deepEqual(JSON.parse(response.body), {
      actionId: null,
      revision: null,
      status: "REJECTED",
    });
    assert.equal(
      calls.some(([name]) => name === "send"),
      false,
    );
  }
});

test("rejects stale state without enqueueing and never exposes storage errors", async () => {
  const staleState = {
    ...createInitialControlState(),
    revision: 1,
  };
  const stale = fixture({ state: staleState });
  assert.equal(
    (await stale.handler(event())).statusCode,
    409,
  );

  const handler = createControlApiHandler({
    allowedOrigin: ORIGIN,
    audience: AUDIENCE,
    issuer: ISSUER,
    nowMs: () => NOW_MS,
    operatorGroup: "clockchain-operators",
    putIdempotency: async () => {
      throw new Error(
        "private /mnt/operator token-canary",
      );
    },
    readSessionState: async () => ({
      expectedClaimFingerprint: null,
      state: createInitialControlState(),
    }),
    sendMessage: async () => {},
    verifyJwt: async () => ({
      aud: AUDIENCE,
      exp: Math.floor(NOW_MS / 1000) + 60,
      groups: ["clockchain-operators"],
      iss: ISSUER,
      sub: "operator-1",
    }),
  });
  const response = await handler(event());
  assert.equal(response.statusCode, 500);
  assert.equal(response.body.includes("/mnt/"), false);
  assert.equal(
    response.body.includes("token-canary"),
    false,
  );
});
