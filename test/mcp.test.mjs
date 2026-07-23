import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  McpConfigurationError,
  McpNetworkError,
  McpProtocolError,
  McpVerificationError,
  assertAnchoredReceipt,
  assertCrossPartyVerification,
  assertReceiptVerification,
  assertResolvedIdentity,
  completeReceipt,
  createMcpClient,
  mintDemoToken,
  parseSseJsonRpc,
  parseToolResult,
} from "../src/mcp.mjs";

const MCP_BASE_URL = "https://mcp.clockchain.network";
const TOKEN = `cc_${"A".repeat(88)}.${"b".repeat(89)}`;

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
  const pending = {
    schema: "clockchain.receipt/v1",
    status: "pending",
    anchor: {
      blockHeight: null,
      confirmed: false,
      consensusTime: null,
      ledgerId: "ledger-1",
    },
  };
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
    },
  };

  assert.equal(assertCrossPartyVerification(result), result);
  assert.throws(
    () =>
      assertCrossPartyVerification({
        onChain: { ...result.onChain, keyless: false },
      }),
    /keyless/i,
  );
  assert.throws(
    () =>
      assertCrossPartyVerification({
        onChain: {
          ...result.onChain,
          verifiedAgainst: "cache",
        },
      }),
    /on-chain block/i,
  );
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
  const initial = { id: "receipt-1", status: "pending" };
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
  const initial = {
    id: "receipt-degraded",
    status: "degraded",
    anchor: {
      blockHeight: null,
      confirmed: false,
      consensusTime: null,
      ledgerId: "ledger-1",
    },
  };
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
  const awaitingTime = {
    id: "receipt-awaiting-time",
    status: "anchored",
    anchor: {
      blockHeight: "14",
      confirmed: true,
      consensusTime: null,
      ledgerId: "ledger-1",
    },
  };
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
  const initial = {
    id: "receipt-intermediate-time",
    status: "pending",
  };
  const awaitingTime = {
    ...initial,
    status: "anchored",
    anchor: {
      blockHeight: "15",
      confirmed: true,
      ledgerId: "ledger-1",
    },
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
  for (const [label, anchor] of [
    ["null", {
      blockHeight: "16",
      confirmed: true,
      consensusTime: null,
    }],
    ["missing", {
      blockHeight: "16",
      confirmed: true,
    }],
  ]) {
    const awaitingTime = {
      id: `receipt-awaiting-${label}`,
      status: "anchored",
      anchor,
    };
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

test("rejects malformed anchored receipts without polling", async (t) => {
  const valid = {
    status: "anchored",
    anchor: {
      blockHeight: "17",
      confirmed: true,
      consensusTime: "1753228802.123456789",
    },
  };
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
    const pollable = { status };
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
    completeReceipt(client, { status: "degraded" }, {
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
