import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test, { mock } from "node:test";

import {
  McpConfigurationError,
  McpNetworkError,
  McpProtocolError,
  McpRateLimitedError,
  McpVerificationError,
  READ_RETRY_TOOL_NAMES,
  WRITE_TOOL_NAMES,
  assertAnchoredReceipt,
  assertCrossPartyVerification,
  assertReceiptVerification,
  assertResolvedIdentity,
  completeReceipt,
  createMcpClient,
  mintDemoToken,
  parseSseJsonRpc,
  parseToolResult,
} from "../src/core/clockchain.mjs";

// Transport bounds observed by the tests below. Each term is pinned by its own
// test, so the composite worst case cannot drift silently:
//   DEFAULT_REQUEST_TIMEOUT_MS  10_000 ("times out a default request ...")
//   DEFAULT_MAX_ATTEMPTS             4 ("retries a throttled read ...")
//   MAX_TOTAL_RETRY_WAIT_MS     62_000 ("bounds cumulative retry waiting ...")
const DEFAULT_REQUEST_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_ATTEMPTS = 4;
const MAX_TOTAL_RETRY_WAIT_MS = 62_000;
const TRANSPORT_WORST_CASE_MS =
  DEFAULT_MAX_ATTEMPTS * DEFAULT_REQUEST_TIMEOUT_MS +
  MAX_TOTAL_RETRY_WAIT_MS;

const MCP_BASE_URL = "https://mcp.clockchain.network";
const TOKEN = `cc_${"A".repeat(88)}.${"b".repeat(89)}`;
const RECEIPT_EVENT_HASH = "a".repeat(64);

function agentReceipt({
  anchor = {},
  payload = {
    inputs: null,
    outputs: null,
  },
  status = "pending",
  ...receipt
} = {}) {
  const anchored = status === "anchored";

  return {
    schema: "clockchain.receipt/v1",
    network: "testnet",
    status,
    agentId: "agent:demo",
    action: "trust_handshake",
    eventHash: RECEIPT_EVENT_HASH,
    hashType: "SHA-256",
    payload,
    anchor: {
      ledgerId: "ledger-1",
      assetReferenceId: "agent:demo:trust_handshake:1",
      blockHeight: anchored ? "12" : null,
      recordedAt: "2026-07-23T07:00:00Z",
      consensusTime: anchored
        ? "1753228800.123456789"
        : null,
      confirmed: anchored,
      ...anchor,
    },
    attestation: {
      validators: 1,
      trustPct: null,
      status: "single-validator-testnet",
      note: "test fixture",
    },
    identity: {
      resolved: true,
      status: "active",
      note: "test fixture",
    },
    verify: {
      how: "test fixture",
    },
    disclaimer: "test fixture",
    ...receipt,
  };
}

function loadSseFixture() {
  return readFileSync(
    new URL("./fixtures/mcp-sse.txt", import.meta.url),
    "utf8",
  );
}

function toolEnvelope(id, value, { structured = false } = {}) {
  return {
    jsonrpc: "2.0",
    id,
    result: structured
      ? { structuredContent: value }
      : {
          content: [
            {
              type: "text",
              text: JSON.stringify(value),
            },
          ],
        },
  };
}

function jsonToolResponse(id, value, options = {}) {
  const {
    headers = {},
    status = 200,
    structured = true,
  } = options;
  return new Response(
    JSON.stringify(toolEnvelope(id, value, { structured })),
    {
      status,
      headers: {
        "content-type": "application/json",
        ...headers,
      },
    },
  );
}

function sseToolResponse(id, value, newline = "\n") {
  const payload = JSON.stringify(toolEnvelope(id, value));
  return new Response(
    `event: message${newline}data: ${payload}${newline}${newline}`,
    {
      status: 200,
      headers: { "content-type": "text/event-stream" },
    },
  );
}

function captureThrow(operation) {
  let thrown;

  try {
    operation();
  } catch (error) {
    thrown = error;
  }

  assert.ok(thrown instanceof Error, "expected operation to throw");
  return thrown;
}

async function captureRejection(operation) {
  let rejection;

  try {
    await operation();
  } catch (error) {
    rejection = error;
  }

  assert.ok(rejection instanceof Error, "expected operation to reject");
  return rejection;
}

function assertErrorOmits(error, ...values) {
  const diagnostic = `${error.message}\n${error.stack ?? ""}`;

  for (const value of values) {
    assert.equal(
      diagnostic.includes(value),
      false,
      "error diagnostic must not echo sensitive input",
    );
  }
}

function injectedClock(startMs = 1_000) {
  let current = startMs;
  const delays = [];

  return {
    advance: (milliseconds) => {
      current += milliseconds;
    },
    delays,
    elapsedSince: (start) => current - start,
    now: () => current,
    sleeper: async (milliseconds) => {
      delays.push(milliseconds);
      current += milliseconds;
    },
  };
}

async function flushMicrotasks() {
  for (let index = 0; index < 4; index += 1) {
    await new Promise((resolve) => {
      setImmediate(resolve);
    });
  }
}

test("selects a matching multiline SSE JSON-RPC event and parses nested tool JSON", () => {
  const jsonRpc = parseSseJsonRpc(loadSseFixture(), {
    expectedId: 7,
  });

  assert.deepEqual(parseToolResult(jsonRpc), { status: "active" });
  assert.deepEqual(
    parseToolResult(
      parseSseJsonRpc(loadSseFixture(), { expectedId: 99 }),
    ),
    { status: "ignored" },
  );
});

test("parses LF and CRLF SSE framing without choosing a nonmatching event", () => {
  for (const newline of ["\n", "\r\n"]) {
    const unrelated = JSON.stringify(toolEnvelope(1, {
      status: "ignored",
    }));
    const expected = JSON.stringify(toolEnvelope("request-2", {
      status: "active",
    }));
    const raw = [
      `event: message${newline}data: ${unrelated}${newline}${newline}`,
      `event: message${newline}data: ${expected}${newline}${newline}`,
    ].join("");

    assert.deepEqual(
      parseToolResult(
        parseSseJsonRpc(raw, { expectedId: "request-2" }),
      ),
      { status: "active" },
    );
  }
});

test("parses direct JSON responses and rejects JSON-RPC errors", () => {
  const direct = JSON.stringify(toolEnvelope(3, { ok: true }));

  assert.deepEqual(
    parseToolResult(parseSseJsonRpc(direct, { expectedId: 3 })),
    { ok: true },
  );
  const error = captureThrow(() =>
    parseSseJsonRpc(
      JSON.stringify({
        jsonrpc: "2.0",
        id: 3,
        error: { code: -32_000, message: "resolver failed" },
      }),
      { expectedId: 3 },
    ),
  );
  assert.ok(error instanceof McpProtocolError);
  assert.equal(error.category, "protocol");
  assert.match(error.message, /resolver failed/);
  assert.throws(
    () =>
      parseSseJsonRpc(
        'data: {"jsonrpc":"2.0","id":1,"error":{"message":"no"}}\n\n',
        { expectedId: 1 },
      ),
    /no/,
  );

  const secretError = captureThrow(() =>
    parseSseJsonRpc(
      JSON.stringify({
        jsonrpc: "2.0",
        id: 4,
        error: { message: `upstream echoed ${TOKEN}` },
      }),
      { expectedId: 4 },
    ),
  );
  assert.ok(secretError instanceof McpProtocolError);
  assertErrorOmits(secretError, TOKEN);
});

test("handles an empty notification response but requires a matching call response", () => {
  assert.equal(parseSseJsonRpc(""), undefined);
  assert.throws(
    () => parseSseJsonRpc("", { expectedId: 1 }),
    /empty|matching/i,
  );
  assert.throws(
    () =>
      parseSseJsonRpc(JSON.stringify(toolEnvelope(2, {})), {
        expectedId: 1,
      }),
    /matching/i,
  );
});

test("rejects malformed, ambiguous, and oversized JSON-RPC responses", () => {
  assert.throws(
    () => parseSseJsonRpc("data: {not-json}\n\n"),
    /malformed/i,
  );
  assert.throws(
    () =>
      parseSseJsonRpc(
        [
          `data: ${JSON.stringify(toolEnvelope(1, { one: true }))}`,
          "",
          `data: ${JSON.stringify(toolEnvelope(1, { two: true }))}`,
          "",
        ].join("\n"),
        { expectedId: 1 },
      ),
    /multiple|ambiguous/i,
  );
  assert.throws(
    () => parseSseJsonRpc(`data: ${"x".repeat(1_048_577)}\n\n`),
    /large|size/i,
  );
});

test("prefers optional structuredContent and rejects tool-level errors", () => {
  assert.deepEqual(
    parseToolResult({
      jsonrpc: "2.0",
      id: 1,
      result: {
        structuredContent: { source: "structured" },
        content: [
          {
            type: "text",
            text: JSON.stringify({ source: "text" }),
          },
        ],
      },
    }),
    { source: "structured" },
  );
  assert.throws(
    () =>
      parseToolResult({
        jsonrpc: "2.0",
        id: 1,
        result: {
          isError: true,
          content: [{ type: "text", text: "sensitive failure" }],
        },
      }),
    /tool reported an error/i,
  );
  assert.throws(
    () =>
      parseToolResult({
        jsonrpc: "2.0",
        id: 1,
        result: {
          content: [{ type: "text", text: "not-json" }],
        },
      }),
    /tool result/i,
  );
});

test("mints a no-store token with an empty body and sanitized subject header", async () => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ init, url });
    return new Response(JSON.stringify({ token: TOKEN }), {
      status: 200,
      headers: {
        "cache-control": "private, no-store",
        "content-type": "application/json",
      },
    });
  };

  const token = await mintDemoToken({
    fetchImpl,
    subject: "  agent 42\r\nunsafe/segment  ",
  });

  assert.equal(token, TOKEN);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, `${MCP_BASE_URL}/token`);
  assert.equal(calls[0].init.method, "POST");
  assert.equal(Object.hasOwn(calls[0].init, "body"), false);
  assert.equal(calls[0].init.cache, "no-store");
  assert.equal(
    calls[0].init.headers["x-clockchain-sub"],
    "agent-42-unsafe/segment",
  );
  assert.equal(
    Object.hasOwn(calls[0].init.headers, "content-type"),
    false,
  );
});

test("omits an absent subject and rejects unsafe token responses", async () => {
  let headers;
  const fetchImpl = async (_url, init) => {
    headers = init.headers;
    return new Response(JSON.stringify({ token: TOKEN }), {
      status: 200,
      headers: { "cache-control": "no-store" },
    });
  };

  assert.equal(await mintDemoToken({ fetchImpl }), TOKEN);
  assert.equal(Object.hasOwn(headers, "x-clockchain-sub"), false);

  await assert.rejects(
    mintDemoToken({
      fetchImpl: async () =>
        new Response(JSON.stringify({ token: TOKEN }), {
          status: 200,
        }),
    }),
    /no-store|cache/i,
  );
  await assert.rejects(
    mintDemoToken({
      fetchImpl: async () =>
        new Response('{"notToken":true}', {
          status: 200,
          headers: { "cache-control": "no-store" },
        }),
    }),
    /invalid token response/i,
  );
  await assert.rejects(
    mintDemoToken({ fetchImpl, subject: "\r\n" }),
    /subject/i,
  );
});

test("bounds token responses and redacts token-like transport failures", async () => {
  const oversizedError = await captureRejection(() =>
    mintDemoToken({
      fetchImpl: async () =>
        new Response(JSON.stringify({ token: "x".repeat(256) }), {
          status: 200,
          headers: { "cache-control": "no-store" },
        }),
      maxResponseBytes: 32,
    }),
  );
  assert.match(oversizedError.message, /large|size/i);

  const transportError = await captureRejection(() =>
    mintDemoToken({
      fetchImpl: async () => {
        throw new Error(`upstream echoed ${TOKEN}`);
      },
    }),
  );
  assert.match(transportError.message, /token request failed/i);
  assertErrorOmits(transportError, TOKEN);
});

test("maps every public wrapper to exact snake-case arguments and deterministic ids", async () => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    const request = JSON.parse(init.body);
    calls.push({ init, request, url });
    return jsonToolResponse(request.id, {
      arguments: request.params.arguments,
      name: request.params.name,
    });
  };
  const client = createMcpClient({ fetchImpl, token: TOKEN });

  await client.resolveAgent(42n);
  await client.getTimestamp();
  await client.attestAction({
    agent_id: 42n,
    action: "trust_handshake",
    inputs: { amount: "100" },
    outputs: { decision: "approved" },
    wait: true,
    wait_ms: 500,
    idempotency_key: "run-1",
    allow_degraded: false,
  });
  await client.completeAttestation({ status: "pending" });
  await client.verifyReceipt({ status: "anchored" });
  await client.verifyCrossParty({
    ledgerId: "ledger-1",
    blockHeight: 12n,
    hash: "abc123",
  });

  assert.deepEqual(
    calls.map(({ request }) => ({
      arguments: request.params.arguments,
      id: request.id,
      method: request.method,
      name: request.params.name,
    })),
    [
      {
        arguments: { agent_id: "42" },
        id: 1,
        method: "tools/call",
        name: "resolve_agent",
      },
      {
        arguments: {},
        id: 2,
        method: "tools/call",
        name: "get_timestamp",
      },
      {
        arguments: {
          agent_id: "42",
          action: "trust_handshake",
          inputs: { amount: "100" },
          outputs: { decision: "approved" },
          wait: true,
          wait_ms: 500,
          idempotency_key: "run-1",
          allow_degraded: false,
        },
        id: 3,
        method: "tools/call",
        name: "attest_action",
      },
      {
        arguments: { receipt: { status: "pending" } },
        id: 4,
        method: "tools/call",
        name: "complete_attestation",
      },
      {
        arguments: { receipt: { status: "anchored" } },
        id: 5,
        method: "tools/call",
        name: "verify_receipt",
      },
      {
        arguments: {
          ledger_id: "ledger-1",
          block_height: "12",
          hash: "abc123",
        },
        id: 6,
        method: "tools/call",
        name: "verify_cross_party",
      },
    ],
  );

  for (const { init, url } of calls) {
    assert.equal(url, `${MCP_BASE_URL}/mcp`);
    assert.deepEqual(init.headers, {
      accept: "application/json, text/event-stream",
      "content-type": "application/json",
      "x-api-key": TOKEN,
    });
    assert.equal(
      Object.keys(init.headers).some(
        (name) => name.toLowerCase() === "mcp-session-id",
      ),
      false,
    );
  }
});

test("parses SSE tool calls and rejects empty 202 or tool-error responses", async () => {
  const responses = [
    sseToolResponse(1, { status: "active" }, "\r\n"),
    new Response(null, { status: 202 }),
    new Response(
      JSON.stringify({
        jsonrpc: "2.0",
        id: 3,
        result: { isError: true },
      }),
      { status: 200 },
    ),
  ];
  const client = createMcpClient({
    fetchImpl: async () => responses.shift(),
    token: TOKEN,
  });

  assert.deepEqual(await client.resolveAgent("42"), {
    status: "active",
  });
  const emptyError = await captureRejection(() =>
    client.getTimestamp(),
  );
  assert.ok(emptyError instanceof McpProtocolError);
  assert.equal(emptyError.category, "protocol");
  assert.match(emptyError.message, /empty|response/i);

  const toolError = await captureRejection(() =>
    client.verifyReceipt({ receipt: true }),
  );
  assert.ok(toolError instanceof McpProtocolError);
  assert.equal(toolError.category, "protocol");
  assert.match(toolError.message, /tool reported an error/i);
});

test("fails immediately on 401 and 403 without retrying", async () => {
  for (const status of [401, 403]) {
    let attempts = 0;
    const client = createMcpClient({
      fetchImpl: async () => {
        attempts += 1;
        return new Response(`denied ${TOKEN}`, { status });
      },
      sleeper: async () => {
        throw new Error("authorization failures must not sleep");
      },
      token: TOKEN,
    });

    const error = await captureRejection(() =>
      client.resolveAgent("42"),
    );
    assert.ok(error instanceof McpConfigurationError);
    assert.equal(error.category, "configuration");
    assert.match(error.message, /authorization/i);
    assert.equal(attempts, 1);
    assertErrorOmits(error, TOKEN);
  }
});

test("does not wait for an authorization response body before failing", async () => {
  const client = createMcpClient({
    fetchImpl: async () => ({
      status: 401,
      headers: new Headers(),
      body: {
        getReader() {
          return {
            read: async () => new Promise(() => {}),
            releaseLock() {},
          };
        },
      },
    }),
    requestTimeoutMs: 10,
    token: TOKEN,
  });

  const error = await captureRejection(() =>
    client.resolveAgent("42"),
  );
  assert.ok(error instanceof McpConfigurationError);
  assert.equal(error.code, "MCP_AUTHORIZATION");
});

test("honors Retry-After on 429 with the same token and request id", async () => {
  const calls = [];
  const delays = [];
  const client = createMcpClient({
    fetchImpl: async (_url, init) => {
      calls.push({
        id: JSON.parse(init.body).id,
        token: init.headers["x-api-key"],
      });
      if (calls.length === 1) {
        return new Response(null, {
          status: 429,
          headers: { "retry-after": "2" },
        });
      }
      return jsonToolResponse(1, { status: "active" });
    },
    sleeper: async (milliseconds) => {
      delays.push(milliseconds);
    },
    token: TOKEN,
  });

  assert.deepEqual(await client.resolveAgent("42"), {
    status: "active",
  });
  assert.deepEqual(calls, [
    { id: 1, token: TOKEN },
    { id: 1, token: TOKEN },
  ]);
  assert.deepEqual(delays, [2_000]);
});

test("classifies an exhausted 429 as a network failure", async () => {
  const client = createMcpClient({
    fetchImpl: async () =>
      new Response(null, {
        status: 429,
        headers: { "retry-after": "0" },
      }),
    maxAttempts: 1,
    token: TOKEN,
  });

  const error = await captureRejection(() =>
    client.resolveAgent("42"),
  );
  assert.ok(error instanceof McpNetworkError);
  assert.equal(error.category, "network");
  assert.match(error.message, /rate limit/i);
  assertErrorOmits(error, TOKEN);
});

test("retries only eligible calls for bounded network and 5xx failures", async () => {
  const readBodies = [];
  const delays = [];
  const readClient = createMcpClient({
    fetchImpl: async (_url, init) => {
      readBodies.push(init.body);
      if (readBodies.length === 1) {
        throw new Error(`network echoed ${TOKEN}`);
      }
      if (readBodies.length === 2) {
        return new Response(null, { status: 503 });
      }
      return jsonToolResponse(1, { status: "active" });
    },
    sleeper: async (milliseconds) => {
      delays.push(milliseconds);
    },
    token: TOKEN,
  });

  assert.deepEqual(await readClient.resolveAgent("42"), {
    status: "active",
  });
  assert.equal(readBodies.length, 3);
  assert.equal(new Set(readBodies).size, 1);
  assert.equal(delays.length, 2);

  let writeAttempts = 0;
  const writeClient = createMcpClient({
    fetchImpl: async () => {
      writeAttempts += 1;
      return new Response(null, { status: 503 });
    },
    token: TOKEN,
  });
  const writeError = await captureRejection(() =>
    writeClient.call("unknown_write", { value: true }),
  );
  assert.ok(writeError instanceof McpNetworkError);
  assert.equal(writeError.category, "network");
  assert.match(writeError.message, /unavailable|failed/i);
  assert.equal(writeAttempts, 1);
});

test("retries read-only complete_attestation across transient 5xx failures", async () => {
  const bodies = [];
  const pending = agentReceipt({
    status: "pending",
  });
  const anchored = {
    ...pending,
    status: "anchored",
    anchor: {
      ...pending.anchor,
      blockHeight: "12",
      confirmed: true,
      consensusTime: "2026-07-22T12:00:00Z",
    },
  };
  const client = createMcpClient({
    fetchImpl: async (_url, init) => {
      bodies.push(init.body);
      if (bodies.length === 1) {
        return new Response(null, { status: 503 });
      }
      return jsonToolResponse(1, anchored);
    },
    sleeper: async () => {},
    token: TOKEN,
  });

  assert.deepEqual(
    await client.completeAttestation(pending),
    anchored,
  );
  assert.equal(bodies.length, 2);
  assert.equal(new Set(bodies).size, 1);
  assert.equal(
    JSON.parse(bodies[0]).params.name,
    "complete_attestation",
  );
});

test("never automatically retries attest_action across ambiguous failures", async (t) => {
  const argumentCases = [
    {
      name: "without an idempotency key",
      value: {
        agent_id: "42",
        action: "trust_handshake",
      },
    },
    {
      name: "with an idempotency key",
      value: {
        agent_id: "42",
        action: "trust_handshake",
        idempotency_key: "run-1",
      },
    },
  ];
  const failureCases = [
    {
      name: "network failure",
      respond: async () => {
        throw new Error(`network echoed ${TOKEN}`);
      },
    },
    {
      name: "timeout",
      requestTimeoutMs: 1,
      respond: async (_url, { signal }) =>
        new Promise((_resolve, reject) => {
          signal.addEventListener(
            "abort",
            () => reject(new Error(`timeout echoed ${TOKEN}`)),
            { once: true },
          );
        }),
    },
    {
      name: "429",
      respond: async () =>
        new Response(null, {
          status: 429,
          headers: { "retry-after": "0" },
        }),
    },
    {
      name: "5xx",
      respond: async () => new Response(null, { status: 503 }),
    },
  ];

  for (const argumentCase of argumentCases) {
    for (const failureCase of failureCases) {
      await t.test(
        `${argumentCase.name} after ${failureCase.name}`,
        async () => {
          let attempts = 0;
          const bodies = [];
          const client = createMcpClient({
            fetchImpl: async (...fetchArguments) => {
              attempts += 1;
              bodies.push(fetchArguments[1].body);
              return failureCase.respond(...fetchArguments);
            },
            requestTimeoutMs: failureCase.requestTimeoutMs,
            sleeper: async () => {},
            token: TOKEN,
          });

          const error = await captureRejection(() =>
            client.attestAction(argumentCase.value),
          );
          assert.ok(error instanceof McpNetworkError);
          assert.equal(attempts, 1);
          assert.equal(bodies.length, 1);
          assert.deepEqual(
            JSON.parse(bodies[0]).params.arguments,
            argumentCase.value,
          );
        },
      );
    }
  }
});

test("bounds MCP response size and request time without exposing the token", async () => {
  const oversizedClient = createMcpClient({
    fetchImpl: async () =>
      new Response(
        JSON.stringify(toolEnvelope(1, {
          payload: "x".repeat(256),
        })),
      ),
    maxResponseBytes: 64,
    token: TOKEN,
  });
  const oversizedError = await captureRejection(() =>
    oversizedClient.resolveAgent("42"),
  );
  assert.ok(oversizedError instanceof McpProtocolError);
  assert.equal(oversizedError.category, "protocol");
  assert.match(oversizedError.message, /large|size/i);
  assertErrorOmits(oversizedError, TOKEN);

  const timeoutClient = createMcpClient({
    fetchImpl: async (_url, { signal }) =>
      new Promise((_resolve, reject) => {
        signal.addEventListener(
          "abort",
          () => reject(new Error(`timeout echoed ${TOKEN}`)),
          { once: true },
        );
      }),
    maxAttempts: 1,
    requestTimeoutMs: 10,
    token: TOKEN,
  });
  const timeoutError = await captureRejection(() =>
    timeoutClient.resolveAgent("42"),
  );
  assert.ok(timeoutError instanceof McpNetworkError);
  assert.equal(timeoutError.category, "network");
  assert.match(timeoutError.message, /timed out/i);
  assertErrorOmits(timeoutError, TOKEN);
});

test("classifies invalid UTF-8 response bytes as a protocol failure", async () => {
  const client = createMcpClient({
    fetchImpl: async () =>
      new Response(new Uint8Array([0xff]), { status: 200 }),
    maxAttempts: 1,
    token: TOKEN,
  });

  const error = await captureRejection(() =>
    client.resolveAgent("42"),
  );
  assert.ok(error instanceof McpProtocolError);
  assert.equal(error.category, "protocol");
  assert.match(error.message, /encoding|response body/i);
});

test("validates client and wrapper inputs before making a request", async () => {
  const tokenError = captureThrow(() =>
    createMcpClient({ token: "" }),
  );
  assert.ok(tokenError instanceof McpConfigurationError);
  assert.equal(tokenError.category, "configuration");
  assert.match(tokenError.message, /token/i);
  assert.throws(
    () => createMcpClient({ token: `bad\r\n${TOKEN}` }),
    /token/i,
  );
  assert.throws(
    () => createMcpClient({ fetchImpl: null, token: TOKEN }),
    /fetch/i,
  );

  let requests = 0;
  const client = createMcpClient({
    fetchImpl: async () => {
      requests += 1;
      throw new Error("must not be reached");
    },
    token: TOKEN,
  });

  await assert.rejects(client.resolveAgent(""), /agent/i);
  await assert.rejects(
    client.attestAction({
      agent_id: "42",
      action: "",
      idempotency_key: "run-1",
    }),
    /action/i,
  );
  await assert.rejects(
    client.attestAction({
      agent_id: "42",
      action: "trust_handshake",
      idempotency_key: "run-1",
      unexpected: true,
    }),
    /unexpected|fields/i,
  );
  await assert.rejects(client.verifyCrossParty({}), /identifier/i);

  const symbolArguments = {};
  symbolArguments[Symbol("hidden")] = true;
  const symbolError = await captureRejection(() =>
    client.call("unknown_write", symbolArguments),
  );
  assert.ok(symbolError instanceof McpConfigurationError);

  assert.equal(requests, 0);
});

test("classifies malformed option bags without leaking native TypeErrors", async () => {
  const clientError = captureThrow(() => createMcpClient(null));
  assert.ok(clientError instanceof McpConfigurationError);

  const parserError = captureThrow(() =>
    parseSseJsonRpc("{}", null),
  );
  assert.ok(parserError instanceof McpConfigurationError);

  const tokenError = await captureRejection(() =>
    mintDemoToken(null),
  );
  assert.ok(tokenError instanceof McpConfigurationError);

  const completionError = await captureRejection(() =>
    completeReceipt(
      { completeAttestation: async () => ({}) },
      { status: "pending" },
      null,
    ),
  );
  assert.ok(completionError instanceof McpConfigurationError);
});

test("redacts a token echoed by a final MCP network failure", async () => {
  const client = createMcpClient({
    fetchImpl: async () => {
      throw new Error(`transport failed with ${TOKEN}`);
    },
    token: TOKEN,
  });

  const error = await captureRejection(() =>
    client.call("unknown_write", {}),
  );
  assert.match(error.message, /request failed/i);
  assertErrorOmits(error, TOKEN);

  let requests = 0;
  const getterClient = createMcpClient({
    fetchImpl: async () => {
      requests += 1;
      throw new Error("must not be reached");
    },
    token: TOKEN,
  });
  const getterArguments = {};
  Object.defineProperty(getterArguments, "value", {
    enumerable: true,
    get() {
      throw new Error(`getter echoed ${TOKEN}`);
    },
  });

  const getterError = await captureRejection(() =>
    getterClient.call("unknown_write", getterArguments),
  );
  assert.ok(getterError instanceof McpConfigurationError);
  assertErrorOmits(getterError, TOKEN);
  assert.equal(requests, 0);
});

test("requires an active resolved identity and matches expected identity fields", () => {
  const identity = {
    status: "active",
    agent_id: "42",
    owner: "0x1111111111111111111111111111111111111111",
  };

  assert.equal(
    assertResolvedIdentity(identity, {
      agentId: 42n,
      owner: identity.owner,
    }),
    identity,
  );
  const error = captureThrow(() =>
    assertResolvedIdentity({ ...identity, status: "unknown" }, 42n),
  );
  assert.ok(error instanceof McpVerificationError);
  assert.equal(error.category, "verification");
  assert.match(error.message, /active/i);
  assert.throws(
    () => assertResolvedIdentity(identity, { agentId: "43" }),
    /identity|match/i,
  );
});

test("requires trimmed deployed anchor block height and consensus time strings", async (t) => {
  const receipt = {
    status: "anchored",
    anchor: {
      blockHeight: "12",
      confirmed: true,
      consensusTime: "1753228800.123456789",
      ledgerId: "ledger-1",
    },
  };

  assert.equal(assertAnchoredReceipt(receipt), receipt);
  for (const malformed of [
    { ...receipt, status: "pending" },
    {
      ...receipt,
      anchor: { ...receipt.anchor, confirmed: false },
    },
    {
      ...receipt,
      blockHeight: "12",
      anchor: { ...receipt.anchor, blockHeight: null },
    },
  ]) {
    assert.throws(
      () => assertAnchoredReceipt(malformed),
      /anchored|confirmed|block height|consensus time/i,
    );
  }

  for (const field of ["blockHeight", "consensusTime"]) {
    await t.test(`${field} is a required trimmed string`, () => {
      const missingAnchor = { ...receipt.anchor };
      delete missingAnchor[field];
      assert.throws(
        () =>
          assertAnchoredReceipt({
            ...receipt,
            anchor: missingAnchor,
          }),
        /block height|consensus time/i,
        `${field} must be present`,
      );

      for (const [label, value] of [
        ["null", null],
        ["number", 12],
        ["empty", ""],
        ["whitespace", " \t "],
        ["untrimmed", ` ${receipt.anchor[field]} `],
      ]) {
        assert.throws(
          () =>
            assertAnchoredReceipt({
              ...receipt,
              anchor: {
                ...receipt.anchor,
                [field]: value,
              },
            }),
          /block height|consensus time/i,
          `${field} must reject ${label}`,
        );
      }
    });
  }

  await t.test("blockHeight uses canonical unsigned-decimal syntax", () => {
    for (const [label, blockHeight] of [
      ["nonnumeric", "twelve"],
      ["leading-zero", "012"],
    ]) {
      assert.throws(
        () =>
          assertAnchoredReceipt({
            ...receipt,
            anchor: {
              ...receipt.anchor,
              blockHeight,
            },
          }),
        /block height/i,
        `blockHeight must reject ${label} values`,
      );
    }
  });

  await t.test("consensusTime rejects control characters", () => {
    for (const [label, consensusTime] of [
      ["control-only", "\u0000"],
      ["interior-control", "1753228800.\u0000123456789"],
    ]) {
      assert.throws(
        () =>
          assertAnchoredReceipt({
            ...receipt,
            anchor: {
              ...receipt.anchor,
              consensusTime,
            },
          }),
        /consensus time/i,
        `consensusTime must reject ${label} values`,
      );
    }
  });
});

test("requires receipt verification against an on-chain block", () => {
  const result = {
    match: true,
    verifiedAgainst: "on-chain block",
  };

  assert.equal(assertReceiptVerification(result), result);
  assert.throws(
    () => assertReceiptVerification({ ...result, match: false }),
    /match/i,
  );
  assert.throws(
    () =>
      assertReceiptVerification({
        ...result,
        verifiedAgainst: "cache",
      }),
    /on-chain block/i,
  );
});

test("requires keyless cross-party verification against an on-chain block", () => {
  const result = {
    onChain: {
      keyless: true,
      verifiedAgainst: "on-chain block",
      ledgerId: "ledger-1",
      blockHeight: 12,
      anchoredHash: RECEIPT_EVENT_HASH,
      assetReferenceId: "agent:demo:trust_handshake:1",
    },
  };
  const expected = {
    ledgerId: "ledger-1",
    blockHeight: "12",
    anchoredHash: RECEIPT_EVENT_HASH,
    assetReferenceId: "agent:demo:trust_handshake:1",
  };

  assert.equal(
    assertCrossPartyVerification(result, expected),
    result,
  );
  assert.throws(
    () =>
      assertCrossPartyVerification({
        onChain: { ...result.onChain, keyless: false },
      }, expected),
    /keyless/i,
  );
  assert.throws(
    () =>
      assertCrossPartyVerification({
        onChain: {
          ...result.onChain,
          verifiedAgainst: "cache",
        },
      }, expected),
    /on-chain block/i,
  );
});

test("requires an expected binding for cross-party verification", () => {
  const result = {
    onChain: {
      keyless: true,
      verifiedAgainst: "on-chain block",
      ledgerId: "ledger-1",
      blockHeight: "12",
      anchoredHash: RECEIPT_EVENT_HASH,
    },
  };

  assert.throws(
    () => assertCrossPartyVerification(result, undefined),
    (error) => {
      assert.ok(error instanceof McpVerificationError);
      assert.equal(
        error.code,
        "MCP_CROSS_PARTY_BINDING_REQUIRED",
      );
      return true;
    },
  );
});

test("rejects cross-party evidence that differs from the expected receipt binding", async (t) => {
  const expected = {
    ledgerId: "ledger-1",
    blockHeight: "12",
    anchoredHash: RECEIPT_EVENT_HASH,
    assetReferenceId: "agent:demo:trust_handshake:1",
  };
  const onChain = {
    keyless: true,
    verifiedAgainst: "on-chain block",
    ...expected,
  };
  const cases = [
    ["ledger ID", "ledgerId", "untrusted-ledger-canary"],
    [
      "block height",
      "blockHeight",
      "98765432109876543210",
    ],
    ["anchored hash", "anchoredHash", "b".repeat(64)],
    [
      "asset reference",
      "assetReferenceId",
      "untrusted-asset-reference-canary",
    ],
  ];

  for (const [name, key, value] of cases) {
    await t.test(name, () => {
      const error = captureThrow(() =>
        assertCrossPartyVerification(
          {
            onChain: {
              ...onChain,
              [key]: value,
            },
          },
          expected,
        ));

      assert.ok(error instanceof McpVerificationError);
      assert.equal(
        error.code,
        "MCP_CROSS_PARTY_BINDING_MISMATCH",
      );
      assertErrorOmits(error, String(value));
    });
  }
});

test("returns full deployed response objects without dropping receipt evidence", async () => {
  const deployed = {
    status: "anchored",
    eventHash: "event-hash",
    anchor: {
      blockHeight: "12",
      confirmed: true,
      consensusTime: "2026-07-22T12:00:00Z",
      ledgerId: "ledger-1",
      proof: { path: ["a", "b"] },
    },
  };
  const client = createMcpClient({
    fetchImpl: async (_url, init) => {
      const { id } = JSON.parse(init.body);
      return jsonToolResponse(id, deployed);
    },
    token: TOKEN,
  });

  assert.deepEqual(
    await client.attestAction({
      agent_id: "42",
      action: "trust_handshake",
      idempotency_key: "run-raw-object",
    }),
    deployed,
  );
});

test("polls a pending receipt with an injectable sleeper until it anchors", async () => {
  const initial = agentReceipt({
    id: "receipt-1",
    payload: {
      inputs: {
        legitimateJson: [1, null, false, "value"],
      },
      outputs: 42,
    },
    status: "pending",
  });
  const pending = { ...initial, stage: 2 };
  const anchored = {
    ...initial,
    status: "anchored",
    anchor: {
      blockHeight: "12",
      confirmed: true,
      consensusTime: "2026-07-22T12:00:00Z",
      ledgerId: "ledger-1",
    },
  };
  const calls = [];
  const delays = [];
  const responses = [pending, anchored];
  const client = {
    async completeAttestation(receipt) {
      calls.push(receipt);
      return responses.shift();
    },
  };

  assert.equal(
    await completeReceipt(client, initial, {
      attempts: 3,
      intervalMs: 25,
      sleeper: async (milliseconds) => {
        delays.push(milliseconds);
      },
    }),
    anchored,
  );
  assert.deepEqual(calls, [initial, pending]);
  assert.deepEqual(delays, [25, 25]);
});

test("polls degraded receipts until strict anchored evidence arrives", async () => {
  const initial = agentReceipt({
    id: "receipt-degraded",
    status: "degraded",
  });
  const degraded = { ...initial, stage: 2 };
  const anchored = {
    ...initial,
    status: "anchored",
    anchor: {
      ...initial.anchor,
      blockHeight: "13",
      confirmed: true,
      consensusTime: "1753228800.123456789",
    },
  };
  const calls = [];
  const delays = [];
  const responses = [degraded, anchored];
  const client = {
    async completeAttestation(receipt) {
      calls.push(receipt);
      return responses.shift();
    },
  };

  assert.equal(
    await completeReceipt(client, initial, {
      attempts: 3,
      intervalMs: 25,
      sleeper: async (milliseconds) => {
        delays.push(milliseconds);
      },
    }),
    anchored,
  );
  assert.deepEqual(calls, [initial, degraded]);
  assert.deepEqual(delays, [25, 25]);
});

test("polls an initially anchored receipt while consensus time enrichment is null", async () => {
  const awaitingTime = agentReceipt({
    anchor: {
      blockHeight: "14",
      consensusTime: null,
    },
    id: "receipt-awaiting-time",
    status: "anchored",
  });
  const anchored = {
    ...awaitingTime,
    anchor: {
      ...awaitingTime.anchor,
      consensusTime: "1753228800.123456789",
    },
  };
  const calls = [];
  const delays = [];
  const client = {
    async completeAttestation(receipt) {
      calls.push(receipt);
      return anchored;
    },
  };

  assert.equal(
    await completeReceipt(client, awaitingTime, {
      attempts: 2,
      intervalMs: 25,
      sleeper: async (milliseconds) => {
        delays.push(milliseconds);
      },
    }),
    anchored,
  );
  assert.deepEqual(calls, [awaitingTime]);
  assert.deepEqual(delays, [25]);
});

test("continues polling when an intermediate anchored receipt is missing consensus time", async () => {
  const initial = agentReceipt({
    id: "receipt-intermediate-time",
    status: "pending",
  });
  const awaitingAnchor = {
    ...agentReceipt({
      anchor: {
        blockHeight: "15",
      },
      status: "anchored",
    }).anchor,
  };
  delete awaitingAnchor.consensusTime;
  const awaitingTime = {
    ...initial,
    status: "anchored",
    anchor: awaitingAnchor,
  };
  const anchored = {
    ...awaitingTime,
    anchor: {
      ...awaitingTime.anchor,
      consensusTime: "1753228801.123456789",
    },
  };
  const calls = [];
  const responses = [awaitingTime, anchored];
  const client = {
    async completeAttestation(receipt) {
      calls.push(receipt);
      return responses.shift();
    },
  };

  assert.equal(
    await completeReceipt(client, initial, {
      attempts: 2,
      intervalMs: 0,
      sleeper: async () => {},
    }),
    anchored,
  );
  assert.deepEqual(calls, [initial, awaitingTime]);
});

test("bounds polling while anchored consensus time enrichment remains unavailable", async () => {
  for (const label of ["null", "missing"]) {
    const awaitingTime = agentReceipt({
      anchor: {
        blockHeight: "16",
        consensusTime: null,
      },
      id: `receipt-awaiting-${label}`,
      status: "anchored",
    });
    if (label === "missing") {
      delete awaitingTime.anchor.consensusTime;
    }
    let calls = 0;
    const client = {
      async completeAttestation(receipt) {
        calls += 1;
        return receipt;
      },
    };

    await assert.rejects(
      completeReceipt(client, awaitingTime, {
        attempts: 2,
        intervalMs: 0,
        sleeper: async () => {},
      }),
      /consensus time|anchored|attempt/i,
    );
    assert.equal(calls, 2, `${label} must exhaust bounded attempts`);
  }
});

test("requires a completion-ready receipt before polling every supported state", async (t) => {
  for (const status of ["pending", "degraded", "anchored"]) {
    await t.test(status, async () => {
      const receipt = agentReceipt({
        anchor: status === "anchored"
          ? { consensusTime: null }
          : {},
        status,
      });
      delete receipt.payload;
      let calls = 0;
      const client = {
        async completeAttestation() {
          calls += 1;
          return receipt;
        },
      };

      const error = await captureRejection(() =>
        completeReceipt(client, receipt, {
          attempts: 1,
          intervalMs: 0,
          sleeper: async () => {},
        }),
      );
      assert.ok(error instanceof McpVerificationError);
      assert.equal(error.code, "MCP_INVALID_RECEIPT");
      assert.equal(calls, 0);
    });
  }
});

test("rejects malformed completion fields without polling", async (t) => {
  const valid = agentReceipt({ status: "pending" });
  const omit = (object, key) => {
    const copy = { ...object };
    delete copy[key];
    return copy;
  };
  const malformed = [
    ["missing ledgerId", {
      ...valid,
      anchor: omit(valid.anchor, "ledgerId"),
    }],
    ["missing payload", omit(valid, "payload")],
    ["null payload", { ...valid, payload: null }],
    ["array payload", { ...valid, payload: [] }],
    ["missing payload inputs", {
      ...valid,
      payload: omit(valid.payload, "inputs"),
    }],
    ["missing payload outputs", {
      ...valid,
      payload: omit(valid.payload, "outputs"),
    }],
    ["missing eventHash", omit(valid, "eventHash")],
    ["short eventHash", {
      ...valid,
      eventHash: "a".repeat(63),
    }],
    ["uppercase eventHash", {
      ...valid,
      eventHash: "A".repeat(64),
    }],
    ["prefixed eventHash", {
      ...valid,
      eventHash: `0x${RECEIPT_EVENT_HASH}`,
    }],
    ["nonhex eventHash", {
      ...valid,
      eventHash: "g".repeat(64),
    }],
    ["confirmed pending anchor", {
      ...valid,
      anchor: { ...valid.anchor, confirmed: true },
    }],
    ["block-bearing pending anchor", {
      ...valid,
      anchor: { ...valid.anchor, blockHeight: "12" },
    }],
  ];

  for (const field of ["agentId", "action", "network"]) {
    malformed.push([`missing ${field}`, omit(valid, field)]);
    for (const [label, value] of [
      ["empty", ""],
      ["whitespace", " \t "],
      ["untrimmed", ` ${valid[field]} `],
      ["control", `${valid[field]}\u0000`],
    ]) {
      malformed.push([
        `${label} ${field}`,
        { ...valid, [field]: value },
      ]);
    }
  }

  for (const [label, ledgerId] of [
    ["empty", ""],
    ["whitespace", " \t "],
    ["untrimmed", " ledger-1 "],
    ["control", "ledger-\u00001"],
  ]) {
    malformed.push([
      `${label} ledgerId`,
      {
        ...valid,
        anchor: { ...valid.anchor, ledgerId },
      },
    ]);
  }

  for (const [label, receipt] of malformed) {
    await t.test(label, async () => {
      let calls = 0;
      const client = {
        async completeAttestation() {
          calls += 1;
          return valid;
        },
      };

      const error = await captureRejection(() =>
        completeReceipt(client, receipt, {
          attempts: 1,
          intervalMs: 0,
          sleeper: async () => {},
        }),
      );
      assert.ok(error instanceof McpVerificationError);
      assert.equal(error.code, "MCP_INVALID_RECEIPT");
      assert.equal(calls, 0);
    });
  }
});

test("rejects malformed intermediate receipts before another poll", async (t) => {
  for (const status of ["pending", "degraded", "anchored"]) {
    await t.test(status, async () => {
      const malformed = agentReceipt({
        anchor: status === "anchored"
          ? { consensusTime: null }
          : {},
        status,
      });
      delete malformed.network;
      let calls = 0;
      const client = {
        async completeAttestation() {
          calls += 1;
          if (calls > 1) {
            throw new Error("malformed receipt must not be re-polled");
          }
          return malformed;
        },
      };

      const error = await captureRejection(() =>
        completeReceipt(
          client,
          agentReceipt({ status: "pending" }),
          {
            attempts: 2,
            intervalMs: 0,
            sleeper: async () => {},
          },
        ),
      );
      assert.ok(error instanceof McpVerificationError);
      assert.equal(error.code, "MCP_INVALID_RECEIPT");
      assert.equal(calls, 1);
    });
  }
});

test("rejects malformed anchored receipts without polling", async (t) => {
  const valid = agentReceipt({
    anchor: {
      blockHeight: "17",
    },
    status: "anchored",
  });
  const malformed = [
    ["consensus time number", {
      ...valid,
      anchor: { ...valid.anchor, consensusTime: 17 },
    }],
    ["consensus time undefined", {
      ...valid,
      anchor: { ...valid.anchor, consensusTime: undefined },
    }],
    ["empty consensus time", {
      ...valid,
      anchor: { ...valid.anchor, consensusTime: "" },
    }],
    ["whitespace consensus time", {
      ...valid,
      anchor: { ...valid.anchor, consensusTime: " \t " },
    }],
    ["control consensus time", {
      ...valid,
      anchor: { ...valid.anchor, consensusTime: "1753228802.\u0000123456789" },
    }],
    ["untrimmed consensus time", {
      ...valid,
      anchor: { ...valid.anchor, consensusTime: " 1753228802.123456789 " },
    }],
    ["unconfirmed anchor", {
      ...valid,
      anchor: { ...valid.anchor, confirmed: false },
    }],
    ["malformed block height", {
      ...valid,
      anchor: { ...valid.anchor, blockHeight: "017" },
    }],
    ["missing anchor", {
      ...valid,
      anchor: undefined,
    }],
    ["array anchor", {
      ...valid,
      anchor: [],
    }],
  ];

  for (const [label, receipt] of malformed) {
    await t.test(label, async () => {
      let calls = 0;
      const client = {
        async completeAttestation() {
          calls += 1;
          return valid;
        },
      };

      await assert.rejects(
        completeReceipt(client, receipt, {
          attempts: 2,
          intervalMs: 0,
          sleeper: async () => {},
        }),
        /anchored|confirmed|block height|consensus time/i,
      );
      assert.equal(calls, 0);
    });
  }
});

test("returns an already anchored receipt and bounds pollable completion attempts", async () => {
  const anchored = {
    status: "anchored",
    anchor: {
      blockHeight: "0",
      confirmed: true,
      consensusTime: "2026-07-22T12:00:00Z",
    },
  };
  let anchoredCalls = 0;
  const anchoredClient = {
    async completeAttestation() {
      anchoredCalls += 1;
      throw new Error("an anchored receipt must not be completed");
    },
  };

  assert.equal(
    await completeReceipt(anchoredClient, anchored, {
      sleeper: async () => {
        throw new Error("an anchored receipt must not sleep");
      },
    }),
    anchored,
  );
  assert.equal(anchoredCalls, 0);

  for (const status of ["pending", "degraded"]) {
    let calls = 0;
    const pollable = agentReceipt({ status });
    const pollingClient = {
      async completeAttestation(receipt) {
        calls += 1;
        return receipt;
      },
    };

    await assert.rejects(
      completeReceipt(pollingClient, pollable, {
        attempts: 2,
        intervalMs: 0,
        sleeper: async () => {},
      }),
      /pending|degraded|unanchored|attempt/i,
    );
    assert.equal(calls, 2, `${status} must exhaust bounded attempts`);
  }
});

test("rejects invalid options and unknown initial or intermediate statuses", async () => {
  let calls = 0;
  const client = {
    async completeAttestation() {
      calls += 1;
      return { status: "rejected" };
    },
  };

  await assert.rejects(
    completeReceipt(client, { status: "rejected" }, {
      sleeper: async () => {},
    }),
    /anchored|status/i,
  );
  assert.equal(calls, 0);
  await assert.rejects(
    completeReceipt(client, agentReceipt({
      status: "degraded",
    }), {
      attempts: 1,
      intervalMs: 0,
      sleeper: async () => {},
    }),
    /anchored|status/i,
  );
  assert.equal(calls, 1);
  await assert.rejects(
    completeReceipt(client, { status: "pending" }, {
      attempts: 0,
      sleeper: async () => {},
    }),
    /attempts/i,
  );
  await assert.rejects(
    completeReceipt(client, { status: "pending" }, {
      intervalMs: -1,
      sleeper: async () => {},
    }),
    /interval/i,
  );
});

test("rejects an in-body rate_limited tool result instead of returning it", () => {
  const throttled = {
    error: "rate_limited",
    retry_after_seconds: 31,
  };

  for (const structured of [true, false]) {
    const error = captureThrow(() =>
      parseToolResult(toolEnvelope(1, throttled, { structured })),
    );
    assert.ok(error instanceof McpRateLimitedError);
    assert.ok(error instanceof McpNetworkError);
    assert.equal(error.category, "network");
    assert.equal(error.code, "MCP_RATE_LIMITED_BODY");
    assert.match(error.message, /rate limit/i);
    assert.equal(error.retryAfterMs, 31_000);
  }

  const isErrorWrapped = captureThrow(() =>
    parseToolResult({
      jsonrpc: "2.0",
      id: 1,
      result: {
        isError: true,
        content: [
          { type: "text", text: JSON.stringify(throttled) },
        ],
      },
    }),
  );
  assert.ok(isErrorWrapped instanceof McpRateLimitedError);
  assert.equal(isErrorWrapped.retryAfterMs, 31_000);

  const withoutHint = captureThrow(() =>
    parseToolResult(toolEnvelope(1, { error: "rate_limited" })),
  );
  assert.ok(withoutHint instanceof McpRateLimitedError);
  assert.equal(withoutHint.retryAfterMs, null);

  assert.deepEqual(
    parseToolResult(
      toolEnvelope(1, { error: "not_found", retry_after_seconds: 31 }),
    ),
    { error: "not_found", retry_after_seconds: 31 },
  );
});

test("waits out an in-body rate limit before retrying a read-only call", async () => {
  const bodies = [];
  const delays = [];
  const client = createMcpClient({
    fetchImpl: async (_url, init) => {
      bodies.push(init.body);
      const { id } = JSON.parse(init.body);
      if (bodies.length === 1) {
        return jsonToolResponse(id, {
          error: "rate_limited",
          retry_after_seconds: 31,
        });
      }
      return jsonToolResponse(id, { status: "active" });
    },
    sleeper: async (milliseconds) => {
      delays.push(milliseconds);
    },
    token: TOKEN,
  });

  assert.deepEqual(await client.resolveAgent("42"), {
    status: "active",
  });
  assert.deepEqual(delays, [31_000]);
  assert.equal(bodies.length, 2);
  assert.equal(new Set(bodies).size, 1);
});

test("never retries a write tool throttled inside a success body", async () => {
  let attempts = 0;
  const client = createMcpClient({
    fetchImpl: async (_url, init) => {
      attempts += 1;
      const { id } = JSON.parse(init.body);
      return jsonToolResponse(id, {
        error: "rate_limited",
        retry_after_seconds: 31,
      });
    },
    sleeper: async () => {
      throw new Error("write tools must not wait and retry");
    },
    token: TOKEN,
  });

  const error = await captureRejection(() =>
    client.attestAction({
      agent_id: "42",
      action: "trust_handshake",
      idempotency_key: "run-throttled",
    }),
  );
  assert.ok(error instanceof McpRateLimitedError);
  assert.equal(error.code, "MCP_RATE_LIMITED_BODY");
  assert.equal(error.retryAfterMs, 31_000);
  assert.equal(attempts, 1);
  assertErrorOmits(error, TOKEN);
});

test("types an HTTP 429 as a rate limit that carries retry_after", async () => {
  const client = createMcpClient({
    fetchImpl: async () =>
      new Response(null, {
        status: 429,
        headers: { "retry-after": "31" },
      }),
    maxAttempts: 1,
    token: TOKEN,
  });

  const error = await captureRejection(() =>
    client.resolveAgent("42"),
  );
  assert.ok(error instanceof McpRateLimitedError);
  assert.equal(error.code, "MCP_RATE_LIMIT");
  assert.equal(error.retryAfterMs, 31_000);

  const tokenError = await captureRejection(() =>
    mintDemoToken({
      fetchImpl: async () =>
        new Response(null, {
          status: 429,
          headers: { "retry-after": "31" },
        }),
    }),
  );
  assert.ok(tokenError instanceof McpRateLimitedError);
  assert.equal(tokenError.retryAfterMs, 31_000);
  assert.match(tokenError.message, /rate limit/i);
});

test("honors a Retry-After above the previously capped wait", async () => {
  const delays = [];
  const client = createMcpClient({
    fetchImpl: async (_url, init) => {
      const { id } = JSON.parse(init.body);
      if (delays.length === 0) {
        return new Response(null, {
          status: 429,
          headers: { "retry-after": "31" },
        });
      }
      return jsonToolResponse(id, { status: "active" });
    },
    sleeper: async (milliseconds) => {
      delays.push(milliseconds);
    },
    token: TOKEN,
  });

  assert.deepEqual(await client.resolveAgent("42"), {
    status: "active",
  });
  assert.deepEqual(delays, [31_000]);
});

test("accepts every RFC 9110 HTTP-date Retry-After shape and no other", async () => {
  const cases = [
    { expected: 31_000, header: "31" },
    // IMF-fixdate, the preferred shape.
    { expected: 62_000, header: "Sun, 06 Nov 2044 08:49:37 GMT" },
    { expected: 0, header: "Sun, 06 Nov 1994 08:49:37 GMT" },
    // RFC 850, which RFC 9110 5.6.7 says a recipient MUST accept. The
    // two-digit year uses the 50-year sliding window, so 44 is 2044 and 94
    // is 1994.
    { expected: 62_000, header: "Sunday, 06-Nov-2044 08:49:37 GMT" },
    { expected: 62_000, header: "Sunday, 06-Nov-44 08:49:37 GMT" },
    { expected: 0, header: "Wednesday, 24-Jul-1994 19:27:50 GMT" },
    { expected: 0, header: "Sunday, 06-Nov-94 08:49:37 GMT" },
    // asctime, the third shape RFC 9110 requires a recipient to accept.
    { expected: 62_000, header: "Sun Nov  6 08:49:37 2044" },
    { expected: 0, header: "Sun Nov  6 08:49:37 1994" },
    // The two Clockchain stamp shapes must stay rejected: a lenient
    // Date.parse would invent a wait from them. A rejected header falls back
    // to the rate-limit floor, never to a sub-second backoff.
    { expected: 5_000, header: "2026-07-24T19:27:49.556027912Z" },
    { expected: 5_000, header: "24-07-2026_19:27:50:981" },
    { expected: 5_000, header: "" },
    { expected: 5_000, header: "Funday, 06-Nov-2044 08:49:37 GMT" },
    { expected: 5_000, header: "Sun, 06 Nov 2044 08:49:37 PST" },
  ];

  for (const { expected, header } of cases) {
    const delays = [];
    const client = createMcpClient({
      fetchImpl: async (_url, init) => {
        const { id } = JSON.parse(init.body);
        if (delays.length === 0) {
          return new Response(null, {
            status: 429,
            headers: { "retry-after": header },
          });
        }
        return jsonToolResponse(id, { status: "active" });
      },
      sleeper: async (milliseconds) => {
        delays.push(milliseconds);
      },
      token: TOKEN,
    });

    assert.deepEqual(await client.resolveAgent("42"), {
      status: "active",
    });
    assert.deepEqual(
      delays,
      [expected],
      `Retry-After ${JSON.stringify(header)} must wait ${expected}ms`,
    );
  }
});

test("bounds cumulative retry waiting to a budget that binds at the default attempt cap", async () => {
  const delays = [];
  let attempts = 0;
  const client = createMcpClient({
    fetchImpl: async () => {
      attempts += 1;
      return new Response(null, {
        status: 429,
        headers: { "retry-after": "120" },
      });
    },
    sleeper: async (milliseconds) => {
      delays.push(milliseconds);
    },
    token: TOKEN,
  });

  const error = await captureRejection(() =>
    client.resolveAgent("42"),
  );
  assert.ok(error instanceof McpRateLimitedError);
  // The budget, not the attempt cap, is what stops this call: the default
  // cap alone would permit three maximal waits.
  assert.deepEqual(delays, [62_000]);
  assert.equal(
    delays.reduce((total, delay) => total + delay, 0),
    MAX_TOTAL_RETRY_WAIT_MS,
  );
  assert.equal(attempts, 2);
  assert.ok(attempts < DEFAULT_MAX_ATTEMPTS);
});

test("never allows a write tool into the read-only retry set", () => {
  assert.ok(Array.isArray(READ_RETRY_TOOL_NAMES));
  assert.ok(Array.isArray(WRITE_TOOL_NAMES));
  assert.ok(Object.isFrozen(READ_RETRY_TOOL_NAMES));
  assert.ok(Object.isFrozen(WRITE_TOOL_NAMES));

  for (const name of ["attest_action", "log_action"]) {
    assert.ok(
      WRITE_TOOL_NAMES.includes(name),
      `${name} must stay listed as an irreversible write tool`,
    );
  }
  for (const name of WRITE_TOOL_NAMES) {
    assert.equal(
      READ_RETRY_TOOL_NAMES.includes(name),
      false,
      `${name} must never be retried automatically`,
    );
  }
  // The bilateral protocol's three reads must be replayable through a
  // throttle window; the write that creates the record must not be.
  for (const name of [
    "search_actions",
    "get_block",
    "generate_audit_trail",
  ]) {
    assert.ok(
      READ_RETRY_TOOL_NAMES.includes(name),
      `${name} must be retryable as a read-only tool`,
    );
  }
  assert.equal(
    READ_RETRY_TOOL_NAMES.includes("log_action"),
    false,
    "log_action must never enter the read-only retry set",
  );
  // `complete_attestation` is retry-safe because `completeReceipt` already
  // re-issues it once per poll iteration (src/mcp.mjs `completeReceipt`), so a
  // transport replay adds no duplication class the demo does not already
  // create. It anchors an existing receipt rather than minting a new one.
  assert.ok(READ_RETRY_TOOL_NAMES.includes("complete_attestation"));
});

test("honours an asctime Retry-After as UTC rather than local time", async () => {
  // asctime carries no zone; RFC 9110 5.6.7 fixes it at UTC. A local-time
  // reading would shift this by the host offset and clamp to 0 or the wait
  // ceiling. Under TZ=UTC this case cannot discriminate, so it is a floor on
  // correctness, not a proof.
  const months = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
  ];
  const days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  const target = new Date(Date.now() + 30_000);
  const pad = (value) => String(value).padStart(2, "0");
  const header = `${days[target.getUTCDay()]} ${
    months[target.getUTCMonth()]
  } ${String(target.getUTCDate()).padStart(2, " ")} ${
    pad(target.getUTCHours())
  }:${pad(target.getUTCMinutes())}:${
    pad(target.getUTCSeconds())
  } ${target.getUTCFullYear()}`;

  const delays = [];
  const client = createMcpClient({
    fetchImpl: async (_url, init) => {
      const { id } = JSON.parse(init.body);
      if (delays.length === 0) {
        return new Response(null, {
          status: 429,
          headers: { "retry-after": header },
        });
      }
      return jsonToolResponse(id, { status: "active" });
    },
    sleeper: async (milliseconds) => {
      delays.push(milliseconds);
    },
    token: TOKEN,
  });

  assert.deepEqual(await client.resolveAgent("42"), {
    status: "active",
  });
  assert.equal(delays.length, 1);
  assert.ok(
    delays[0] > 25_000 && delays[0] <= 30_000,
    `asctime ${JSON.stringify(header)} must wait about 30s, got ${delays[0]}`,
  );
});

test("times out a default request at the default request timeout", async () => {
  mock.timers.enable({ apis: ["setTimeout"] });

  try {
    const client = createMcpClient({
      fetchImpl: () => new Promise(() => {}),
      maxAttempts: 1,
      token: TOKEN,
    });
    let settled = null;
    const call = client.resolveAgent("42").then(
      (value) => {
        settled = value;
      },
      (error) => {
        settled = error;
      },
    );

    mock.timers.tick(DEFAULT_REQUEST_TIMEOUT_MS - 1);
    await flushMicrotasks();
    assert.equal(
      settled,
      null,
      `a default request must still be in flight at ${
        DEFAULT_REQUEST_TIMEOUT_MS - 1
      }ms`,
    );

    mock.timers.tick(1);
    await flushMicrotasks();
    assert.ok(
      settled instanceof McpNetworkError,
      `a default request must time out at ${DEFAULT_REQUEST_TIMEOUT_MS}ms`,
    );
    assert.equal(settled.code, "MCP_TIMEOUT");
    await call;
  } finally {
    mock.timers.reset();
  }
});

test("retries a throttled read to the default attempt cap with the rate-limit floor", async () => {
  const delays = [];
  let attempts = 0;
  const client = createMcpClient({
    fetchImpl: async () => {
      attempts += 1;
      return new Response(null, { status: 429 });
    },
    sleeper: async (milliseconds) => {
      delays.push(milliseconds);
    },
    token: TOKEN,
  });

  const error = await captureRejection(() =>
    client.resolveAgent("42"),
  );
  assert.ok(error instanceof McpRateLimitedError);
  assert.equal(error.retryAfterMs, null);
  assert.equal(attempts, DEFAULT_MAX_ATTEMPTS);
  // A throttle without a usable hint waits the observed rate-limit floor, not
  // a sub-second backoff that would retry straight back into the throttle.
  assert.deepEqual(delays, [5_000, 5_000, 5_000]);
});

test("spaces transport and 5xx retries by a reachable bounded backoff", async () => {
  const delays = [];
  let attempts = 0;
  const client = createMcpClient({
    fetchImpl: async () => {
      attempts += 1;
      return new Response(null, { status: 503 });
    },
    maxAttempts: 6,
    sleeper: async (milliseconds) => {
      delays.push(milliseconds);
    },
    token: TOKEN,
  });

  const error = await captureRejection(() =>
    client.resolveAgent("42"),
  );
  assert.ok(error instanceof McpNetworkError);
  assert.equal(error.code, "MCP_SERVICE_UNAVAILABLE");
  assert.equal(attempts, 6);
  // The ceiling must be reachable: the last delay is the cap, not 1_600.
  assert.deepEqual(delays, [100, 200, 400, 800, 1_000]);

  assert.throws(
    () => createMcpClient({ maxAttempts: 7, token: TOKEN }),
    /attempts/i,
  );
});

test("bounds one receipt completion by an explicit elapsed-time deadline", async () => {
  const pending = agentReceipt({ id: "receipt-slow", status: "pending" });
  const clock = injectedClock(0);
  const started = clock.now();
  let calls = 0;
  const client = {
    async completeAttestation(receipt) {
      calls += 1;
      // Each poll costs a whole worst-case transport call.
      clock.advance(TRANSPORT_WORST_CASE_MS);
      return { ...receipt, stage: calls };
    },
  };

  const error = await captureRejection(() =>
    completeReceipt(client, pending, {
      attempts: 8,
      intervalMs: 1_500,
      now: clock.now,
      sleeper: clock.sleeper,
    }),
  );

  assert.ok(error instanceof McpVerificationError);
  assert.equal(error.code, "MCP_RECEIPT_DEADLINE");
  assert.equal(calls, 2);
  assert.deepEqual(clock.delays, [1_500, 1_500]);
  // Worst case is the deadline plus the one poll already in flight when it
  // is crossed: 120_000 + 1_500 + 102_000.
  const worstCaseMs = 120_000 + 1_500 + TRANSPORT_WORST_CASE_MS;
  assert.equal(worstCaseMs, 223_500);
  assert.ok(
    clock.elapsedSince(started) <= worstCaseMs,
    `one receipt completion must stay inside ${worstCaseMs}ms`,
  );
  assert.equal(clock.elapsedSince(started), 207_000);
});

test("rejects an invalid completion deadline or clock", async () => {
  const pending = agentReceipt({ id: "receipt-clock", status: "pending" });
  const client = {
    async completeAttestation(receipt) {
      return receipt;
    },
  };

  await assert.rejects(
    completeReceipt(client, pending, { deadlineMs: 0 }),
    /deadline/i,
  );
  await assert.rejects(
    completeReceipt(client, pending, { now: null }),
    /clock/i,
  );

  let calls = 0;
  const clockError = await captureRejection(() =>
    completeReceipt(client, pending, {
      now: () => Number.NaN,
      sleeper: async () => {},
    }),
  );
  assert.ok(clockError instanceof McpConfigurationError);
  assert.match(clockError.message, /clock/i);
  assert.equal(calls, 0);
});

test("reads the throttle hint from either observed retry_after key", async () => {
  const cases = [
    { expected: 31_000, payload: { retry_after_seconds: 31 } },
    { expected: 31_000, payload: { retry_after: 31 } },
    { expected: 31_000, payload: { retry_after: "31" } },
    // retry_after_seconds wins when both are present.
    {
      expected: 31_000,
      payload: { retry_after: 5, retry_after_seconds: 31 },
    },
    { expected: 62_000, payload: { retry_after: 120 } },
    { expected: null, payload: { retry_after_ms: 31_000 } },
    { expected: null, payload: { retry_after: "soon" } },
    { expected: null, payload: { retry_after: -1 } },
  ];

  for (const { expected, payload } of cases) {
    const error = captureThrow(() =>
      parseToolResult(
        toolEnvelope(1, { error: "rate_limited", ...payload }),
      ),
    );
    assert.ok(error instanceof McpRateLimitedError);
    assert.equal(
      error.retryAfterMs,
      expected,
      `${JSON.stringify(payload)} must yield ${expected}`,
    );
  }
});

test("waits the rate-limit floor for an in-body throttle without a hint", async () => {
  const delays = [];
  let attempts = 0;
  const client = createMcpClient({
    fetchImpl: async (_url, init) => {
      attempts += 1;
      const { id } = JSON.parse(init.body);
      if (attempts === 1) {
        return jsonToolResponse(id, { error: "rate_limited" });
      }
      return jsonToolResponse(id, { status: "active" });
    },
    sleeper: async (milliseconds) => {
      delays.push(milliseconds);
    },
    token: TOKEN,
  });

  assert.deepEqual(await client.resolveAgent("42"), {
    status: "active",
  });
  assert.deepEqual(delays, [5_000]);
});

test("never waits or replays a write tool that is throttled", async () => {
  for (const throttle of ["header", "body"]) {
    let attempts = 0;
    const client = createMcpClient({
      fetchImpl: async (_url, init) => {
        attempts += 1;
        const { id } = JSON.parse(init.body);
        if (throttle === "header") {
          return new Response(null, {
            status: 429,
            headers: { "retry-after": "31" },
          });
        }
        return jsonToolResponse(id, {
          error: "rate_limited",
          retry_after_seconds: 31,
        });
      },
      sleeper: async () => {
        throw new Error("write tools must not wait and retry");
      },
      token: TOKEN,
    });

    const error = await captureRejection(() =>
      client.attestAction({
        agent_id: "42",
        action: "trust_handshake",
        idempotency_key: `run-throttled-${throttle}`,
      }),
    );
    assert.ok(
      error instanceof McpRateLimitedError,
      `a ${throttle} throttle on a write tool must be typed`,
    );
    assert.equal(error.retryAfterMs, 31_000);
    assert.equal(
      attempts,
      1,
      `a ${throttle} throttle must never replay a write tool`,
    );
    assertErrorOmits(error, TOKEN);
  }
});

// --- First-class bilateral tool methods -----------------------------------
//
// Fixtures below are derived from the OBSERVED responses recorded in
// .context/review-2026-07-24/capabilities.json: real field names, real value
// shapes, real hashes and heights. The operator's email in `clientId` is
// replaced by a placeholder so no personal data lands in the repository.

const OBSERVED_ASSET_HASH =
  "4c4cf3bcf8d45b7b77d2babb936fe4b4ac6271ff8d9120484870ee0257a6cbc5";
const OBSERVED_LEDGER_ID = "02313136-82d8-4eb0-a571-94c836661fc9";
// A spec-4.7 conformant bilateral key: "cbv1:" + 64-hex session digest +
// ":proposal" = 78 bytes inside the 120-byte charset bound.
const BILATERAL_REFERENCE_ID = `cbv1:${"a".repeat(64)}:proposal`;

function observedSearchRecord(overrides = {}) {
  // The verified 13-field search_actions hit. Note assetReferenceId contains
  // an underscore: response validation must accept legacy attest-generated
  // ids even though the WRITE-side charset would reject them.
  return {
    ledgerId: OBSERVED_LEDGER_ID,
    clientId: "operator@example.invalid",
    walletId: "wallet-fixture",
    assetReferenceId: "8677:trust_handshake:1784833252067",
    assetHash: OBSERVED_ASSET_HASH,
    hashType: "SHA-256",
    versionNumber: 1,
    additionalInfo: "agent attested receipt",
    blockHeight: "1781135",
    createdTimestamp: "23-07-2026 19:00:52:165 UTC",
    updatedTimestamp: null,
    assetName: null,
    type: null,
    ...overrides,
  };
}

function refusingFetch(label) {
  return async () => {
    throw new Error(`${label} must fail before any request is sent`);
  };
}

test("logs an action once with exact-key arguments and a normalized response", async () => {
  const heightCases = [
    // The log_action response shape is unverified upstream; blockHeight may
    // be pending (null or absent) or a decimal in either wire type.
    { expected: "1781135", response: { blockHeight: 1781135 } },
    { expected: "1781135", response: { blockHeight: "1781135" } },
    { expected: null, response: { blockHeight: null } },
    { expected: null, response: {} },
  ];

  for (const { expected, response } of heightCases) {
    const bodies = [];
    const client = createMcpClient({
      fetchImpl: async (_url, init) => {
        bodies.push(init.body);
        const { id } = JSON.parse(init.body);
        return jsonToolResponse(id, {
          ledgerId: OBSERVED_LEDGER_ID,
          // Hostile or unverified extra fields must be dropped untrusted.
          status: "anchored",
          clientId: "operator@example.invalid",
          ...response,
        });
      },
      token: TOKEN,
    });

    const written = await client.logAction({
      asset_reference_id: BILATERAL_REFERENCE_ID,
      asset_hash: OBSERVED_ASSET_HASH,
      hash_type: "SHA-256",
      version_number: 1,
      idempotency_key: "b".repeat(32),
      wait: true,
      wait_ms: 20_000,
      allow_degraded: true,
    });

    assert.deepEqual(written, {
      ledgerId: OBSERVED_LEDGER_ID,
      blockHeight: expected,
    });
    assert.equal(bodies.length, 1);
    const request = JSON.parse(bodies[0]);
    assert.equal(request.params.name, "log_action");
    assert.deepEqual(request.params.arguments, {
      asset_reference_id: BILATERAL_REFERENCE_ID,
      asset_hash: OBSERVED_ASSET_HASH,
      hash_type: "SHA-256",
      version_number: 1,
      idempotency_key: "b".repeat(32),
      wait: true,
      wait_ms: 20_000,
      allow_degraded: true,
    });
  }
});

test("rejects the three spec-banned log_action parameters before any request", async () => {
  // content would hash a serialization we do not control; did mutates the
  // reference id server-side; additional_info is punctuation-stripped and
  // absent from the on-chain projection (design section 4.8).
  const banned = [
    ["content", { payment: "intent" }],
    ["did", "did:agent:8677"],
    ["additional_info", "session metadata"],
  ];

  for (const [key, value] of banned) {
    const client = createMcpClient({
      fetchImpl: refusingFetch("a banned log_action parameter"),
      token: TOKEN,
    });
    const error = await captureRejection(() =>
      client.logAction({
        asset_reference_id: BILATERAL_REFERENCE_ID,
        asset_hash: OBSERVED_ASSET_HASH,
        [key]: value,
      }),
    );
    assert.ok(error instanceof McpConfigurationError);
    assert.equal(error.code, "MCP_FORBIDDEN_LOG_ACTION_FIELD");
    assert.match(error.message, new RegExp(key));
  }
});

test("enforces the reference-id charset and digest shape on log_action", async () => {
  const valid = {
    asset_reference_id: BILATERAL_REFERENCE_ID,
    asset_hash: OBSERVED_ASSET_HASH,
  };
  const invalidCases = [
    // Charset /^[0-9a-z:]{1,120}$/: lowercase, digits, colon; nothing else.
    { asset_reference_id: BILATERAL_REFERENCE_ID.toUpperCase() },
    { asset_reference_id: "cbv1:trust_handshake:proposal" },
    { asset_reference_id: `cbv1:${"a".repeat(116)}` },
    { asset_reference_id: " cbv1:a:proposal" },
    { asset_reference_id: "" },
    { asset_reference_id: 8677 },
    { asset_reference_id: undefined },
    // asset_hash must be exactly 64 lowercase hex characters.
    { asset_hash: OBSERVED_ASSET_HASH.toUpperCase() },
    { asset_hash: OBSERVED_ASSET_HASH.slice(0, 63) },
    { asset_hash: `${OBSERVED_ASSET_HASH}0` },
    { asset_hash: "g".repeat(64) },
    { asset_hash: 1234 },
    { asset_hash: undefined },
    // Exact-key allowlist and typed optionals.
    { surprise: true },
    { hash_type: "MD5" },
    { version_number: 0 },
    { wait: "yes" },
    { wait_ms: -1 },
    { allow_degraded: "sure" },
    { idempotency_key: "" },
  ];

  for (const overrides of invalidCases) {
    const client = createMcpClient({
      fetchImpl: refusingFetch("invalid log_action arguments"),
      token: TOKEN,
    });
    const error = await captureRejection(() =>
      client.logAction({ ...valid, ...overrides }),
    );
    assert.ok(
      error instanceof McpConfigurationError,
      `${JSON.stringify(overrides)} must be rejected before the request`,
    );
  }

  // The bound is 120 bytes exactly: 120 passes, 121 fails above.
  let sent = 0;
  const boundaryClient = createMcpClient({
    fetchImpl: async (_url, init) => {
      sent += 1;
      const { id } = JSON.parse(init.body);
      return jsonToolResponse(id, { ledgerId: OBSERVED_LEDGER_ID });
    },
    token: TOKEN,
  });
  await boundaryClient.logAction({
    ...valid,
    asset_reference_id: `cbv1:${"a".repeat(115)}`,
  });
  assert.equal(sent, 1);
});

test("never retries or waits for a throttled log_action", async () => {
  for (const throttle of ["header", "body"]) {
    let attempts = 0;
    const client = createMcpClient({
      fetchImpl: async (_url, init) => {
        attempts += 1;
        const { id } = JSON.parse(init.body);
        if (throttle === "header") {
          return new Response(null, {
            status: 429,
            headers: { "retry-after": "31" },
          });
        }
        return jsonToolResponse(id, {
          error: "rate_limited",
          retry_after_seconds: 31,
        });
      },
      sleeper: async () => {
        throw new Error("log_action must not wait and retry");
      },
      token: TOKEN,
    });

    const error = await captureRejection(() =>
      client.logAction({
        asset_reference_id: BILATERAL_REFERENCE_ID,
        asset_hash: OBSERVED_ASSET_HASH,
        idempotency_key: "c".repeat(32),
      }),
    );
    assert.ok(
      error instanceof McpRateLimitedError,
      `a ${throttle} throttle on log_action must be typed`,
    );
    assert.equal(error.retryAfterMs, 31_000);
    assert.equal(
      attempts,
      1,
      `a ${throttle} throttle must never replay log_action`,
    );
    assertErrorOmits(error, TOKEN);
  }
});

test("rejects a malformed log_action response", async () => {
  const responses = [
    { blockHeight: "1781135" },
    { ledgerId: "", blockHeight: "1781135" },
    { ledgerId: 42, blockHeight: "1781135" },
    { ledgerId: OBSERVED_LEDGER_ID, blockHeight: "03" },
    { ledgerId: OBSERVED_LEDGER_ID, blockHeight: "soon" },
    { ledgerId: OBSERVED_LEDGER_ID, blockHeight: -1 },
    { ledgerId: OBSERVED_LEDGER_ID, blockHeight: 1.5 },
  ];

  for (const payload of responses) {
    const client = createMcpClient({
      fetchImpl: async (_url, init) => {
        const { id } = JSON.parse(init.body);
        return jsonToolResponse(id, payload);
      },
      token: TOKEN,
    });
    const error = await captureRejection(() =>
      client.logAction({
        asset_reference_id: BILATERAL_REFERENCE_ID,
        asset_hash: OBSERVED_ASSET_HASH,
      }),
    );
    assert.ok(
      error instanceof McpProtocolError,
      `${JSON.stringify(payload)} must be rejected`,
    );
    assert.equal(error.code, "MCP_INVALID_LOG_RESULT");
  }
});

test("returns a search_actions hit as normalized records and a miss as an empty array", async () => {
  const client = createMcpClient({
    fetchImpl: async (_url, init) => {
      const { id, params } = JSON.parse(init.body);
      assert.equal(params.name, "search_actions");
      assert.deepEqual(params.arguments, {
        asset_reference_id: BILATERAL_REFERENCE_ID,
      });
      return jsonToolResponse(id, [
        observedSearchRecord({ forged: "extra keys must not crash" }),
      ]);
    },
    token: TOKEN,
  });

  const records = await client.searchActions({
    asset_reference_id: BILATERAL_REFERENCE_ID,
  });
  // Only the five fields the verification recipe reads survive; hostile
  // extras — including the operator email in clientId — are dropped.
  assert.deepEqual(records, [
    {
      ledgerId: OBSERVED_LEDGER_ID,
      assetReferenceId: "8677:trust_handshake:1784833252067",
      assetHash: OBSERVED_ASSET_HASH,
      blockHeight: "1781135",
      hashType: "SHA-256",
    },
  ]);

  const missClient = createMcpClient({
    fetchImpl: async (_url, init) => {
      const { id } = JSON.parse(init.body);
      return jsonToolResponse(id, []);
    },
    token: TOKEN,
  });
  assert.deepEqual(
    await missClient.searchActions({
      asset_reference_id: BILATERAL_REFERENCE_ID,
    }),
    [],
  );
});

test("hard-fails a non-array search_actions result and keeps a throttle typed", async () => {
  // Matrix row 2: a non-array is a HARD error, never "absent". The in-body
  // rate-limit shape is ALSO a non-array object, and it must surface as the
  // rate-limit error, not as the shape error — ordering is load-bearing.
  const nonArrays = [
    {},
    { records: [] },
    "no results",
    null,
  ];

  for (const payload of nonArrays) {
    const client = createMcpClient({
      fetchImpl: async (_url, init) => {
        const { id } = JSON.parse(init.body);
        return jsonToolResponse(id, payload);
      },
      token: TOKEN,
    });
    const error = await captureRejection(() =>
      client.searchActions({
        asset_reference_id: BILATERAL_REFERENCE_ID,
      }),
    );
    assert.ok(
      error instanceof McpProtocolError,
      `${JSON.stringify(payload)} must be a hard protocol error`,
    );
  }

  const throttledClient = createMcpClient({
    fetchImpl: async (_url, init) => {
      const { id } = JSON.parse(init.body);
      return jsonToolResponse(id, {
        error: "rate_limited",
        retry_after_seconds: 31,
      });
    },
    maxAttempts: 1,
    token: TOKEN,
  });
  const throttled = await captureRejection(() =>
    throttledClient.searchActions({
      asset_reference_id: BILATERAL_REFERENCE_ID,
    }),
  );
  assert.ok(throttled instanceof McpRateLimitedError);
  assert.equal(throttled instanceof McpProtocolError, false);
  assert.equal(throttled.code, "MCP_RATE_LIMITED_BODY");
  assert.equal(throttled.retryAfterMs, 31_000);
});

test("retries a throttled search_actions read before returning the result", async () => {
  const delays = [];
  let attempts = 0;
  const client = createMcpClient({
    fetchImpl: async (_url, init) => {
      attempts += 1;
      const { id } = JSON.parse(init.body);
      if (attempts === 1) {
        return new Response(null, {
          status: 429,
          headers: { "retry-after": "2" },
        });
      }
      return jsonToolResponse(id, []);
    },
    sleeper: async (milliseconds) => {
      delays.push(milliseconds);
    },
    token: TOKEN,
  });

  assert.deepEqual(
    await client.searchActions({
      asset_reference_id: BILATERAL_REFERENCE_ID,
    }),
    [],
  );
  assert.deepEqual(delays, [2_000]);
  assert.equal(attempts, 2);
});

test("rejects hostile search_actions records on every field the recipe reads", async () => {
  const hostileCases = [
    [observedSearchRecord({ ledgerId: undefined })],
    [observedSearchRecord({ ledgerId: "" })],
    [observedSearchRecord({ assetReferenceId: undefined })],
    [observedSearchRecord({ assetHash: OBSERVED_ASSET_HASH.toUpperCase() })],
    [observedSearchRecord({ assetHash: null })],
    [observedSearchRecord({ blockHeight: "03" })],
    [observedSearchRecord({ blockHeight: null })],
    [observedSearchRecord({ blockHeight: "soon" })],
    [observedSearchRecord({ hashType: "MD5" })],
    ["not-a-record"],
    [null],
    [observedSearchRecord(), "trailing junk"],
  ];

  for (const payload of hostileCases) {
    const client = createMcpClient({
      fetchImpl: async (_url, init) => {
        const { id } = JSON.parse(init.body);
        return jsonToolResponse(id, payload);
      },
      token: TOKEN,
    });
    const error = await captureRejection(() =>
      client.searchActions({
        asset_reference_id: BILATERAL_REFERENCE_ID,
      }),
    );
    assert.ok(
      error instanceof McpProtocolError,
      `${JSON.stringify(payload)} must be rejected`,
    );
    assert.equal(error.code, "MCP_INVALID_SEARCH_RECORD");
  }
});

test("asserts the reference-id charset before every search or audit-trail read", async () => {
  // Spec 4.7 requires the charset before every search. The observed legacy
  // id "8677:trust_handshake:1784833252067" contains an underscore and is
  // deliberately rejected as an ARGUMENT even though it is accepted inside
  // responses: the bilateral protocol only ever searches its own keys.
  const invalidIds = [
    "8677:trust_handshake:1784833252067",
    "CBV1:aa:proposal",
    `cbv1:${"a".repeat(116)}`,
    "",
    undefined,
    42,
  ];

  for (const method of ["searchActions", "generateAuditTrail"]) {
    for (const referenceId of invalidIds) {
      const client = createMcpClient({
        fetchImpl: refusingFetch("an invalid reference id"),
        token: TOKEN,
      });
      const error = await captureRejection(() =>
        client[method]({ asset_reference_id: referenceId }),
      );
      assert.ok(
        error instanceof McpConfigurationError,
        `${method} must reject ${JSON.stringify(referenceId)}`,
      );
    }

    const extraKey = await captureRejection(() => {
      const client = createMcpClient({
        fetchImpl: refusingFetch("unexpected arguments"),
        token: TOKEN,
      });
      return client[method]({
        asset_reference_id: BILATERAL_REFERENCE_ID,
        limit: 10,
      });
    });
    assert.ok(extraKey instanceof McpConfigurationError);
  }
});

test("fetches a block by latest or decimal height with a verbatim blockTime", async () => {
  // Observed get_block shapes: blockHeight is a NUMBER here (a STRING in
  // every other endpoint) and blockTime is RFC3339 with nine fractional
  // digits, returned VERBATIM — src/bilateral/blocktime.mjs owns parsing.
  const observedBlock = {
    blockHeight: 1781136,
    proposerAddress: "FE0A68F799E7D16B719B8AA82126D4C5D5352A21",
    blockTime: "2026-07-23T19:00:52.738107464Z",
  };
  const heightCases = [
    { requested: "latest", sent: "latest" },
    { requested: "1781136", sent: "1781136" },
    { requested: 1781136, sent: "1781136" },
    { requested: 1781136n, sent: "1781136" },
  ];

  for (const { requested, sent } of heightCases) {
    const client = createMcpClient({
      fetchImpl: async (_url, init) => {
        const { id, params } = JSON.parse(init.body);
        assert.equal(params.name, "get_block");
        assert.deepEqual(params.arguments, { height: sent });
        return jsonToolResponse(id, observedBlock);
      },
      token: TOKEN,
    });

    const block = await client.getBlock({ height: requested });
    assert.deepEqual(block, {
      blockHeight: "1781136",
      proposerAddress: "FE0A68F799E7D16B719B8AA82126D4C5D5352A21",
      blockTime: "2026-07-23T19:00:52.738107464Z",
    });
  }

  const invalidHeights = [
    "01",
    "-1",
    "latest ",
    "0x10",
    1.5,
    "",
    undefined,
    null,
  ];
  for (const height of invalidHeights) {
    const client = createMcpClient({
      fetchImpl: refusingFetch("an invalid block height"),
      token: TOKEN,
    });
    const error = await captureRejection(() =>
      client.getBlock({ height }),
    );
    assert.ok(
      error instanceof McpConfigurationError,
      `height ${JSON.stringify(height)} must be rejected`,
    );
  }
  const extraKey = await captureRejection(() => {
    const client = createMcpClient({
      fetchImpl: refusingFetch("unexpected arguments"),
      token: TOKEN,
    });
    return client.getBlock({ height: "latest", full: true });
  });
  assert.ok(extraKey instanceof McpConfigurationError);
});

test("rejects a malformed get_block response and retries a throttled one", async () => {
  const malformed = [
    { proposerAddress: "FE0A", blockTime: "2026-07-23T19:00:52.738107464Z" },
    { blockHeight: "soon", proposerAddress: "FE0A", blockTime: "2026-07-23T19:00:52.738107464Z" },
    { blockHeight: 1781136, blockTime: "2026-07-23T19:00:52.738107464Z" },
    { blockHeight: 1781136, proposerAddress: "", blockTime: "2026-07-23T19:00:52.738107464Z" },
    { blockHeight: 1781136, proposerAddress: "FE0A", blockTime: 1753297252738 },
    { blockHeight: 1781136, proposerAddress: "FE0A", blockTime: "" },
    "block",
  ];

  for (const payload of malformed) {
    const client = createMcpClient({
      fetchImpl: async (_url, init) => {
        const { id } = JSON.parse(init.body);
        return jsonToolResponse(id, payload);
      },
      token: TOKEN,
    });
    const error = await captureRejection(() =>
      client.getBlock({ height: "latest" }),
    );
    assert.ok(
      error instanceof McpProtocolError,
      `${JSON.stringify(payload)} must be rejected`,
    );
  }

  const delays = [];
  let attempts = 0;
  const throttledClient = createMcpClient({
    fetchImpl: async (_url, init) => {
      attempts += 1;
      const { id } = JSON.parse(init.body);
      if (attempts === 1) {
        return jsonToolResponse(id, {
          error: "rate_limited",
          retry_after_seconds: 31,
        });
      }
      return jsonToolResponse(id, {
        blockHeight: 1869480,
        proposerAddress: "FE0A68F799E7D16B719B8AA82126D4C5D5352A21",
        blockTime: "2026-07-24T20:08:13.788993755Z",
      });
    },
    sleeper: async (milliseconds) => {
      delays.push(milliseconds);
    },
    token: TOKEN,
  });
  assert.deepEqual(await throttledClient.getBlock({ height: "1869480" }), {
    blockHeight: "1869480",
    proposerAddress: "FE0A68F799E7D16B719B8AA82126D4C5D5352A21",
    blockTime: "2026-07-24T20:08:13.788993755Z",
  });
  assert.deepEqual(delays, [31_000]);
});

test("returns an audit trail only when its count matches its events", async () => {
  // Observed generate_audit_trail response shape. The aggregate verifier
  // gates duplicates on count === "1" per key (design section 6.5), so only
  // that surface is trusted and returned.
  const observedTrail = {
    assetReferenceId: BILATERAL_REFERENCE_ID,
    events: [
      {
        ledgerId: OBSERVED_LEDGER_ID,
        assetReferenceId: BILATERAL_REFERENCE_ID,
        assetHash: OBSERVED_ASSET_HASH,
        time: "2026-07-23T19:04:41.057495507Z",
        blockHeight: "1781359",
        additionalInfo: "agent attested receipt",
      },
    ],
    count: 1,
    builtAt: "2026-07-24T20:08:30.525Z",
  };

  const client = createMcpClient({
    fetchImpl: async (_url, init) => {
      const { id, params } = JSON.parse(init.body);
      assert.equal(params.name, "generate_audit_trail");
      assert.deepEqual(params.arguments, {
        asset_reference_id: BILATERAL_REFERENCE_ID,
      });
      return jsonToolResponse(id, observedTrail);
    },
    token: TOKEN,
  });
  assert.deepEqual(
    await client.generateAuditTrail({
      asset_reference_id: BILATERAL_REFERENCE_ID,
    }),
    {
      assetReferenceId: BILATERAL_REFERENCE_ID,
      count: "1",
    },
  );

  const emptyClient = createMcpClient({
    fetchImpl: async (_url, init) => {
      const { id } = JSON.parse(init.body);
      return jsonToolResponse(id, {
        assetReferenceId: BILATERAL_REFERENCE_ID,
        events: [],
        count: 0,
        builtAt: "2026-07-24T20:08:30.525Z",
      });
    },
    token: TOKEN,
  });
  assert.deepEqual(
    await emptyClient.generateAuditTrail({
      asset_reference_id: BILATERAL_REFERENCE_ID,
    }),
    {
      assetReferenceId: BILATERAL_REFERENCE_ID,
      count: "0",
    },
  );

  const malformed = [
    { ...observedTrail, count: 2 },
    { ...observedTrail, count: "1.0" },
    { ...observedTrail, count: undefined },
    { ...observedTrail, events: "one" },
    { ...observedTrail, events: ["not-a-record"] },
    { ...observedTrail, assetReferenceId: "" },
    [],
  ];
  for (const payload of malformed) {
    const failing = createMcpClient({
      fetchImpl: async (_url, init) => {
        const { id } = JSON.parse(init.body);
        return jsonToolResponse(id, payload);
      },
      token: TOKEN,
    });
    const error = await captureRejection(() =>
      failing.generateAuditTrail({
        asset_reference_id: BILATERAL_REFERENCE_ID,
      }),
    );
    assert.ok(
      error instanceof McpProtocolError,
      `${JSON.stringify(payload)} must be rejected`,
    );
    assert.equal(error.code, "MCP_INVALID_AUDIT_TRAIL");
  }
});
