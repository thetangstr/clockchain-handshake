import assert from "node:assert/strict";
import {
  mkdtemp,
  rm,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  createRelayClient,
  RelayClientError,
} from "../src/relay/client.mjs";
import {
  createRelayServer,
  MAX_EVIDENCE_JSON_BYTES,
  MAX_EVIDENCE_MARKDOWN_BYTES,
  MAX_EVIDENCE_MARKER_BYTES,
} from "../src/relay/server.mjs";

const SESSION_ID = "4a7d2e56-9c3b-4f1a-8d2e-5b6c7d8e9f0a";
const PAYER_KEY = "payer-key-01";
const PAYEE_KEY = "payee-key-01";

async function withRelay(t, run) {
  const stateDir = await mkdtemp(
    join(tmpdir(), "relay-test-"),
  );
  t.after(() => rm(stateDir, { recursive: true, force: true }));
  const server = createRelayServer({ stateDir });
  const address = await server.listen();
  t.after(() => server.close());
  const client = createRelayClient({
    relayUrl: `http://127.0.0.1:${address.port}`,
  });
  await run({ client, stateDir, server });
}

function envelope(overrides = {}) {
  return {
    body: { note: "hello" },
    kind: "status",
    role: "payer",
    senderKey: PAYER_KEY,
    seq: 0,
    sessionId: SESSION_ID,
    sig: "deadbeef",
    ...overrides,
  };
}

async function registerSession(client) {
  await client.createSession({
    senderKey: "operator-key",
    sessionId: SESSION_ID,
    sig: "cafe",
    subjectRun: "stakeholder",
  });
}

test("serves healthz and registers a session idempotently", async (t) => {
  await withRelay(t, async ({ client }) => {
    assert.deepEqual(await client.healthz(), { ok: true });
    await registerSession(client);
    await registerSession(client);
    const snapshot = await client.getSnapshot(SESSION_ID);
    assert.equal(snapshot.sessionId, SESSION_ID);
    assert.equal(snapshot.subjectRun, "stakeholder");
    assert.equal(snapshot.paymentMoved, false);
    assert.equal(snapshot.discoveryPublished, false);
    assert.equal(snapshot.verdict, null);
  });
});

test("appends, long-polls, and pages messages", async (t) => {
  await withRelay(t, async ({ client }) => {
    await registerSession(client);
    await client.sendMessage(envelope());
    await client.sendMessage(
      envelope({ role: "payee", senderKey: PAYEE_KEY }),
    );

    const first = await client.pollMessages({
      sessionId: SESSION_ID,
    });
    assert.equal(first.messages.length, 2);
    assert.equal(first.next, 2);
    assert.equal(first.messages[0].role, "payer");
    assert.equal(first.messages[1].role, "payee");

    const second = await client.pollMessages({
      sessionId: SESSION_ID,
      after: 1,
    });
    assert.equal(second.messages.length, 1);
    assert.equal(second.messages[0].index, 1);

    const started = Date.now();
    const pending = client.pollMessages({
      sessionId: SESSION_ID,
      after: 2,
      waitMs: 5_000,
    });
    setTimeout(() => {
      client.sendMessage(envelope({ seq: 1 })).catch(() => {});
    }, 25);
    const third = await pending;
    assert.ok(Date.now() - started < 2_000);
    assert.equal(third.messages.length, 1);
    assert.equal(third.messages[0].seq, 1);
  });
});

test("binds a role to its first sender key and refuses later claims", async (t) => {
  await withRelay(t, async ({ client }) => {
    await registerSession(client);
    await client.sendMessage(envelope());
    await client.sendMessage(envelope({ seq: 1 }));
    await assert.rejects(
      client.sendMessage(
        envelope({ senderKey: "impostor", seq: 2 }),
      ),
      (error) => {
        assert.ok(error instanceof RelayClientError);
        assert.equal(error.code, "ROLE_ALREADY_BOUND");
        assert.equal(error.status, 409);
        return true;
      },
    );
  });
});

test("is idempotent on message retry and conflicts on divergence", async (t) => {
  await withRelay(t, async ({ client }) => {
    await registerSession(client);
    await client.sendMessage(envelope());
    await client.sendMessage(envelope());
    let listed = await client.pollMessages({
      sessionId: SESSION_ID,
    });
    assert.equal(listed.messages.length, 1);

    await assert.rejects(
      client.sendMessage(
        envelope({ body: { note: "different" } }),
      ),
      { code: "MESSAGE_CONFLICT" },
    );
    listed = await client.pollMessages({
      sessionId: SESSION_ID,
    });
    assert.equal(listed.messages.length, 1);
  });
});

test("stores discovery and verdict with conflict-on-divergence", async (t) => {
  await withRelay(t, async ({ client }) => {
    await registerSession(client);
    const discovery = {
      schema: "handshake-discovery/v2",
      sessionId: SESSION_ID,
    };
    await client.putDiscovery(SESSION_ID, discovery);
    await client.putDiscovery(SESSION_ID, discovery);
    assert.deepEqual(
      await client.getDiscovery(SESSION_ID),
      discovery,
    );
    await assert.rejects(
      client.putDiscovery(SESSION_ID, {
        ...discovery,
        subjectRun: "rehearsal",
      }),
      { code: "DISCOVERY_CONFLICT" },
    );

    const verdict = {
      schema: "clockchain.bilateral-verdict/v1",
      signature: "abc",
    };
    await client.putVerdict(SESSION_ID, verdict);
    assert.equal(
      (await client.getSnapshot(SESSION_ID)).verdict
        .schema,
      "clockchain.bilateral-verdict/v1",
    );
    await assert.rejects(
      client.putVerdict(SESSION_ID, {
        ...verdict,
        signature: "different",
      }),
      { code: "VERDICT_CONFLICT" },
    );
  });
});

test("accepts a maximal-valid evidence triple and rejects over-cap parts", async (t) => {
  await withRelay(t, async ({ client }) => {
    await registerSession(client);
    const maximal = {
      json: "j".repeat(MAX_EVIDENCE_JSON_BYTES),
      markdown: "m".repeat(MAX_EVIDENCE_MARKDOWN_BYTES),
      marker: "k".repeat(MAX_EVIDENCE_MARKER_BYTES),
    };
    await client.putEvidence(SESSION_ID, "payer", maximal);
    assert.deepEqual(
      await client.getEvidence(SESSION_ID, "payer"),
      maximal,
    );

    for (const [part, size] of [
      ["json", MAX_EVIDENCE_JSON_BYTES + 1],
      ["markdown", MAX_EVIDENCE_MARKDOWN_BYTES + 1],
      ["marker", MAX_EVIDENCE_MARKER_BYTES + 1],
    ]) {
      await assert.rejects(
        client.putEvidence(SESSION_ID, "payee", {
          json: "",
          markdown: "",
          marker: "",
          [part]: "x".repeat(size),
        }),
        { code: "BAD_EVIDENCE_SHAPE" },
      );
    }

    await client.putEvidence(SESSION_ID, "payee", {
      json: "{}",
      markdown: "m",
      marker: "k",
    });
    await assert.rejects(
      client.putEvidence(SESSION_ID, "payee", {
        json: "{}",
        markdown: "different",
        marker: "k",
      }),
      { code: "EVIDENCE_CONFLICT" },
    );
  });
});

test("survives a restart with the journal intact", async (t) => {
  const stateDir = await mkdtemp(
    join(tmpdir(), "relay-restart-test-"),
  );
  t.after(() => rm(stateDir, { recursive: true, force: true }));

  const first = createRelayServer({ stateDir });
  const firstAddress = await first.listen();
  const firstClient = createRelayClient({
    relayUrl: `http://127.0.0.1:${firstAddress.port}`,
  });
  await registerSession(firstClient);
  await firstClient.sendMessage(envelope());
  await firstClient.putDiscovery(SESSION_ID, {
    schema: "handshake-discovery/v2",
  });
  await firstClient.putEvidence(SESSION_ID, "payer", {
    json: "{}",
    markdown: "m",
    marker: "k",
  });
  await firstClient.putVerdict(SESSION_ID, {
    schema: "clockchain.bilateral-verdict/v1",
  });
  await firstClient.putStatus(SESSION_ID, "payer", {
    phase: "DONE",
  });
  await first.close();

  const second = createRelayServer({ stateDir });
  const secondAddress = await second.listen();
  t.after(() => second.close());
  const secondClient = createRelayClient({
    relayUrl: `http://127.0.0.1:${secondAddress.port}`,
  });

  const listed = await secondClient.pollMessages({
    sessionId: SESSION_ID,
  });
  assert.equal(listed.messages.length, 1);
  assert.deepEqual(
    await secondClient.getDiscovery(SESSION_ID),
    { schema: "handshake-discovery/v2" },
  );
  assert.deepEqual(
    await secondClient.getEvidence(SESSION_ID, "payer"),
    { json: "{}", markdown: "m", marker: "k" },
  );
  const snapshot = await secondClient.getSnapshot(SESSION_ID);
  assert.equal(
    snapshot.verdict.schema,
    "clockchain.bilateral-verdict/v1",
  );
  assert.deepEqual(snapshot.roles.payer, { phase: "DONE" });

  // Role binding survives the restart too.
  await assert.rejects(
    secondClient.sendMessage(
      envelope({ senderKey: "impostor", seq: 7 }),
    ),
    { code: "ROLE_ALREADY_BOUND" },
  );
});

test("fails closed on bad shapes and unknown sessions", async (t) => {
  await withRelay(t, async ({ client }) => {
    await assert.rejects(
      client.sendMessage(envelope()),
      { code: "UNKNOWN_SESSION" },
    );
    await registerSession(client);
    await assert.rejects(
      client.sendMessage(envelope({ seq: -1 })),
      { code: "BAD_MESSAGE_SHAPE" },
    );
    await assert.rejects(
      client.sendMessage(envelope({ role: "nobody", seq: 1 })),
      { code: "BAD_MESSAGE_SHAPE" },
    );
    await assert.rejects(
      client.pollMessages({ sessionId: SESSION_ID, after: -1 }),
      { code: "BAD_QUERY" },
    );
    await assert.rejects(
      client.getEvidence(SESSION_ID, "payee"),
      { code: "NO_EVIDENCE" },
    );
  });
});

test("maps an unreachable relay to RENDEZVOUS_UNAVAILABLE", async () => {
  const client = createRelayClient({
    relayUrl: "http://127.0.0.1:1",
  });
  await assert.rejects(client.healthz(), (error) => {
    assert.ok(error instanceof RelayClientError);
    assert.equal(error.code, "RENDEZVOUS_UNAVAILABLE");
    return true;
  });
});

test("rejects non-loopback plain-http relay URLs", () => {
  assert.throws(
    () =>
      createRelayClient({
        relayUrl: "http://relay.example.com",
      }),
    { code: "BAD_RELAY_URL" },
  );
  assert.doesNotThrow(() =>
    createRelayClient({
      relayUrl: "https://relay.example.com",
    })
  );
});
