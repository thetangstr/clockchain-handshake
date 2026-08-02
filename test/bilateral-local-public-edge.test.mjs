import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, X509Certificate } from "node:crypto";
import { readFile, rm, mkdtemp } from "node:fs/promises";
import https from "node:https";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  HybridPublicEdgeError,
  buildPublicEdgeArguments,
  probePinnedTlsEndpoint,
  waitForPublicEdge,
} from "../src/bilateral/local-demo/public-edge.mjs";

const SESSION_ID = "11111111-1111-4111-8111-111111111111";
const REPOSITORY_SHA = "b".repeat(40);

function edgeConfig(root) {
  return Object.freeze({
    coordinationPublicUrl: "https://32.186.198.119:8443",
    host: "32.186.198.119",
    hostKeyFile: join(root, "known-hosts"),
    identityFile: join(root, "identity"),
    payerMcpRemotePort: 9443,
    port: 22,
    relayRemotePort: 8443,
    user: "clockchain-tunnel",
  });
}

function fixedFailure(error) {
  assert.equal(error instanceof HybridPublicEdgeError, true);
  assert.match(error.code, /^HYBRID_PUBLIC_EDGE_/);
  assert.equal(error.category, "network");
  assert.equal(error.message, "Hybrid public edge failed safely.");
  return true;
}

async function tlsFixture(t) {
  const root = await mkdtemp(join(tmpdir(), "clockchain-public-edge-"));
  t.after(() => rm(root, { force: true, recursive: true }));
  const certificatePath = join(root, "server.crt");
  const keyPath = join(root, "server.key");
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "ed25519", "-nodes",
    "-keyout", keyPath,
    "-out", certificatePath,
    "-days", "1",
    "-subj", "/CN=127.0.0.1",
    "-addext", "subjectAltName=IP:127.0.0.1",
  ], { stdio: "ignore" });
  const [certificate, key] = await Promise.all([
    readFile(certificatePath, "utf8"),
    readFile(keyPath, "utf8"),
  ]);
  const server = https.createServer({ cert: certificate, key }, (request, response) => {
    response.setHeader("content-type", "application/json");
    response.setHeader("cache-control", "no-store");
    if (request.method === "GET" && request.url === "/mcp") {
      response.statusCode = 405;
      response.setHeader("allow", "POST, DELETE");
      response.end('{"error":"PAYER_MCP_PROTOCOL_FAILED","paymentMoved":false}\n');
      return;
    }
    if (request.method === "GET" && request.url === "/") {
      response.statusCode = 400;
      response.end('{"code":"COORDINATION_RELAY_REQUEST_INVALID","paymentMoved":false}\n');
      return;
    }
    if (
      request.method === "GET" &&
      request.url === `/v1/sessions/${SESSION_ID}/enrollment-readiness?waitMs=0`
    ) {
      response.statusCode = 200;
      response.end(`${JSON.stringify({
        paymentMoved: false,
        ready: false,
        releaseId: "release-aaaaaaaaaaaaaaaa",
        repositorySha: REPOSITORY_SHA,
        schema: "clockchain.bilateral-enrollment-readiness/v1",
        sessionId: SESSION_ID,
      })}\n`);
      return;
    }
    response.statusCode = 404;
    response.end('{"paymentMoved":false}\n');
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const address = server.address();
  assert.equal(typeof address, "object");
  return Object.freeze({
    fingerprint: createHash("sha256").update(new X509Certificate(certificate).raw).digest("hex"),
    host: "127.0.0.1",
    port: address.port,
  });
}

test("builds only the two fixed reverse forwards with noninteractive SSH restrictions", () => {
  const root = "/private/tmp/clockchain-edge-fixture";
  const config = edgeConfig(root);
  const args = buildPublicEdgeArguments(config, { payerMcp: 9443, relay: 8443 });

  assert.deepEqual(args, [
    "-N", "-T",
    "-o", "BatchMode=yes",
    "-o", "ExitOnForwardFailure=yes",
    "-o", "ForwardAgent=no",
    "-o", "ControlMaster=no",
    "-o", "ControlPath=none",
    "-o", `UserKnownHostsFile=${config.hostKeyFile}`,
    "-o", "StrictHostKeyChecking=yes",
    "-o", "ServerAliveInterval=15",
    "-o", "ServerAliveCountMax=2",
    "-i", config.identityFile,
    "-p", "22",
    "-R", "0.0.0.0:8443:127.0.0.1:8443",
    "-R", "0.0.0.0:9443:127.0.0.1:9443",
    "clockchain-tunnel@32.186.198.119",
  ]);
  assert.equal(Object.isFrozen(args), true);
  assert.equal(args.includes("-A"), false);
  assert.equal(args.includes("-tt"), false);
});

test("rejects remote port drift, arbitrary destinations, and unsafe SSH metadata", () => {
  const root = "/private/tmp/clockchain-edge-fixture";
  const config = edgeConfig(root);
  const cases = [
    [{ ...config, relayRemotePort: 8444 }, { payerMcp: 9443, relay: 8443 }],
    [{ ...config, payerMcpRemotePort: 9444 }, { payerMcp: 9443, relay: 8443 }],
    [{ ...config, user: "root" }, { payerMcp: 9443, relay: 8443 }],
    [{ ...config, host: "32.186.198.119;id" }, { payerMcp: 9443, relay: 8443 }],
    [{ ...config, identityFile: "identity" }, { payerMcp: 9443, relay: 8443 }],
    [config, { payerMcp: 9443, relay: 0 }],
    [config, { payerMcp: 9443, relay: 8443, extra: 1 }],
  ];
  for (const [candidate, ports] of cases) {
    assert.throws(() => buildPublicEdgeArguments(candidate, ports), fixedFailure);
  }
});

test("proves Payer MCP and relay readiness over exact certificate pins", async (t) => {
  const fixture = await tlsFixture(t);
  const payer = await probePinnedTlsEndpoint({
    expectedFingerprint: fixture.fingerprint,
    host: fixture.host,
    path: "/mcp",
    port: fixture.port,
  });
  const coordinationListener = await probePinnedTlsEndpoint({
    expectedFingerprint: fixture.fingerprint,
    host: fixture.host,
    path: "/",
    port: fixture.port,
  });
  const relay = await probePinnedTlsEndpoint({
    expectedFingerprint: fixture.fingerprint,
    host: fixture.host,
    path: `/v1/sessions/${SESSION_ID}/enrollment-readiness?waitMs=0`,
    port: fixture.port,
  });

  assert.deepEqual(payer, { paymentMoved: false, ready: true });
  assert.deepEqual(coordinationListener, { paymentMoved: false, ready: true });
  assert.deepEqual(relay, { paymentMoved: false, ready: true });
  assert.deepEqual(await waitForPublicEdge({
    coordination: {
      expectedFingerprint: fixture.fingerprint,
      host: fixture.host,
      path: `/v1/sessions/${SESSION_ID}/enrollment-readiness?waitMs=0`,
      port: fixture.port,
    },
    deadlineMs: 1_000,
    payerMcp: {
      expectedFingerprint: fixture.fingerprint,
      host: fixture.host,
      path: "/mcp",
      port: fixture.port,
    },
  }), {
    coordinationReady: true,
    payerMcpReady: true,
    paymentMoved: false,
  });
  await assert.rejects(
    probePinnedTlsEndpoint({
      expectedFingerprint: "0".repeat(64),
      host: fixture.host,
      path: "/mcp",
      port: fixture.port,
    }),
    (error) => {
      fixedFailure(error);
      assert.equal(error.code, "HYBRID_PUBLIC_EDGE_IDENTITY_MISMATCH");
      return true;
    },
  );
});

test("fails boundedly on connection refusal, stalled TLS, and unsupported probe paths", async (t) => {
  const sockets = new Set();
  const stalled = net.createServer((socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  await new Promise((resolve, reject) => {
    stalled.once("error", reject);
    stalled.listen(0, "127.0.0.1", resolve);
  });
  t.after(() => new Promise((resolve) => {
    for (const socket of sockets) socket.destroy();
    stalled.close(resolve);
  }));
  const address = stalled.address();
  assert.equal(typeof address, "object");

  await assert.rejects(
    probePinnedTlsEndpoint({
      expectedFingerprint: "0".repeat(64),
      host: "127.0.0.1",
      path: "/mcp",
      port: address.port,
      timeoutMs: 50,
    }),
    fixedFailure,
  );
  await assert.rejects(
    probePinnedTlsEndpoint({
      expectedFingerprint: "0".repeat(64),
      host: "127.0.0.1",
      path: "/admin",
      port: address.port,
      timeoutMs: 50,
    }),
    fixedFailure,
  );
});

test("requires both public probes to pass in the same attempt", async () => {
  const attempts = [];
  let clock = 0;
  const result = await waitForPublicEdge({
    coordination: { expectedFingerprint: "a".repeat(64), host: "relay.example", path: `/v1/sessions/${SESSION_ID}/enrollment-readiness?waitMs=0`, port: 8443 },
    deadlineMs: 1_000,
    payerMcp: { expectedFingerprint: "b".repeat(64), host: "payer.example", path: "/mcp", port: 9443 },
  }, {
    now: () => clock,
    async probe(input) {
      attempts.push(input.path);
      if (attempts.length === 1) {
        const error = new HybridPublicEdgeError("HYBRID_PUBLIC_EDGE_UNAVAILABLE");
        throw error;
      }
      return Object.freeze({ paymentMoved: false, ready: true });
    },
    async sleep(delayMs) {
      clock += delayMs;
    },
  });

  assert.deepEqual(result, {
    coordinationReady: true,
    payerMcpReady: true,
    paymentMoved: false,
  });
  assert.deepEqual(attempts, [
    `/v1/sessions/${SESSION_ID}/enrollment-readiness?waitMs=0`,
    `/v1/sessions/${SESSION_ID}/enrollment-readiness?waitMs=0`,
    "/mcp",
  ]);
});

test("stops immediately on identity mismatch and fails when the deadline expires", async () => {
  let probes = 0;
  await assert.rejects(
    waitForPublicEdge({
      coordination: { expectedFingerprint: "a".repeat(64), host: "relay.example", path: `/v1/sessions/${SESSION_ID}/enrollment-readiness?waitMs=0`, port: 8443 },
      deadlineMs: 1_000,
      payerMcp: { expectedFingerprint: "b".repeat(64), host: "payer.example", path: "/mcp", port: 9443 },
    }, {
      now: () => 0,
      async probe() {
        probes += 1;
        throw new HybridPublicEdgeError("HYBRID_PUBLIC_EDGE_IDENTITY_MISMATCH");
      },
      async sleep() {},
    }),
    fixedFailure,
  );
  assert.equal(probes, 1);

  let clock = 0;
  await assert.rejects(
    waitForPublicEdge({
      coordination: { expectedFingerprint: "a".repeat(64), host: "relay.example", path: `/v1/sessions/${SESSION_ID}/enrollment-readiness?waitMs=0`, port: 8443 },
      deadlineMs: 200,
      payerMcp: { expectedFingerprint: "b".repeat(64), host: "payer.example", path: "/mcp", port: 9443 },
    }, {
      now: () => clock,
      async probe() {
        throw new HybridPublicEdgeError("HYBRID_PUBLIC_EDGE_UNAVAILABLE");
      },
      async sleep(delayMs) {
        clock += delayMs;
      },
    }),
    (error) => {
      fixedFailure(error);
      assert.equal(error.code, "HYBRID_PUBLIC_EDGE_DEADLINE");
      return true;
    },
  );
});
