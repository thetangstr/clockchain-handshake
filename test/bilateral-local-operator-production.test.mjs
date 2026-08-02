import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import test from "node:test";

import { createProductionHybridOperatorDependencies } from "../src/bilateral/local-demo/operator-production.mjs";
import { HybridPublicEdgeError } from "../src/bilateral/local-demo/public-edge.mjs";

const REPOSITORY_SHA = "b".repeat(40);
const RELEASE_ID = "release-aaaaaaaaaaaaaaaa";
const SESSION_ID = "11111111-1111-4111-8111-111111111111";

function config(root) {
  return Object.freeze({
    console: Object.freeze({ host: "127.0.0.1", port: 8787 }),
    funding: Object.freeze({
      journalDirectory: join(root, "funding-journal"),
      keystoreFile: join(root, "treasury.json"),
      mode: "fund-on-ready",
    }),
    operator: Object.freeze({
      clockchainTokenFile: join(root, "clockchain-token"),
      keyId: "operator-yang",
      privateKeyFile: join(root, "operator-private.pem"),
      rpcUrlFile: join(root, "sepolia-rpc"),
    }),
    payerMcp: Object.freeze({
      host: "127.0.0.1",
      port: 9443,
      publicUrl: "https://32.186.198.119:9443/mcp",
      tlsCertificateFile: join(root, "payer-mcp.crt"),
      tlsPrivateKeyFile: join(root, "payer-mcp.key"),
    }),
    paymentMoved: false,
    publicEdge: Object.freeze({
      coordinationPublicUrl: "https://32.186.198.119:8443",
      host: "32.186.198.119",
      hostKeyFile: join(root, "edge-known-hosts"),
      identityFile: join(root, "edge-identity"),
      payerMcpRemotePort: 9443,
      port: 22,
      relayRemotePort: 8443,
      user: "clockchain-tunnel",
    }),
    publishing: Object.freeze({
      bucket: "clockchain-handshake-monitor-570035913370-us-west-2",
      imageDigest: `570035913370.dkr.ecr.us-west-2.amazonaws.com/clockchain-handshake@sha256:${"c".repeat(64)}`,
      receiptEmailUrl: "https://anhgkkcm46.execute-api.us-west-2.amazonaws.com/v1/receipt-email",
      region: "us-west-2",
      requestorDiscoveryUrl: "https://clockchain-handshake-monitor-570035913370-us-west-2.s3.us-west-2.amazonaws.com/requestor-discovery.json",
    }),
    relay: Object.freeze({
      advertisedHost: "32.186.198.119",
      host: "127.0.0.1",
      port: 8443,
      tlsCertificateFile: join(root, "relay.crt"),
      tlsFingerprint: "a".repeat(64),
      tlsPrivateKeyFile: join(root, "relay.key"),
    }),
    repositorySha: REPOSITORY_SHA,
    schema: "clockchain.hybrid-local-operator-config/v1",
  });
}

function fakeService(script, calls) {
  return Object.freeze({
    async stop() { calls.push(["stop", script]); },
    async waitForExit() { return 0; },
    async waitForLine() {
      if (script === "handshake-relay.mjs") {
        return JSON.stringify({
          host: "127.0.0.1",
          paymentMoved: false,
          pid: 123,
          port: 8443,
          schema: "clockchain.bilateral-relay-ready/v1",
        });
      }
      if (script === "handshake-console.mjs") return "Handshake console listening.";
      if (script === "handshake-bootstrap-broker.mjs") {
        return JSON.stringify({
          host: "127.0.0.1",
          paymentMoved: false,
          port: 9555,
          status: "BOOTSTRAP_BROKER_READY",
          url: "http://127.0.0.1:9555",
        });
      }
      if (script === "handshake-supervisor.mjs") {
        return JSON.stringify({
          paymentMoved: false,
          role: "payer",
          status: "PAYER_MCP_READY",
          url: "https://32.186.198.119:9443/mcp",
        });
      }
      if (script === "publish-requestor-discovery.mjs") {
        return JSON.stringify({
          discoveryUrl: "https://clockchain-handshake-monitor-570035913370-us-west-2.s3.us-west-2.amazonaws.com/requestor-discovery.json",
          paymentMoved: false,
          status: "REQUESTOR_DISCOVERY_PUBLISHED",
        });
      }
      throw new Error(`unexpected wait line: ${script}`);
    },
  });
}

test("wires each existing CLI with exact private paths and public metadata", async (t) => {
  const privateRoot = await mkdtemp(join(tmpdir(), "clockchain-production-config-"));
  const stateRoot = join(privateRoot, "state");
  t.after(() => rm(privateRoot, { force: true, recursive: true }));
  const activeConfig = config(privateRoot);
  const calls = [];
  const release = Object.freeze({
    manifests: Object.freeze([
      Object.freeze({ path: join(stateRoot, "release", "payee.launch.json"), role: "payee" }),
      Object.freeze({ path: join(stateRoot, "release", "payer.launch.json"), role: "payer" }),
    ]),
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
  });
  const dependencies = createProductionHybridOperatorDependencies({
    async approveBootstrapClaim(input) {
      calls.push(["approve", input]);
      return Object.freeze({ paymentMoved: false, status: "APPROVED" });
    },
    now: () => 2_000_000_000_000,
    async probePinnedTlsEndpoint(input) {
      calls.push(["probe", input]);
      return Object.freeze({ paymentMoved: false, ready: true });
    },
    async spawnService({ args, command }) {
      const script = command === "ssh" ? "ssh" : basename(args[0]);
      calls.push(["spawn", script, args]);
      return fakeService(script, calls);
    },
    stdout: { write(line) { calls.push(["stdout", line]); } },
    async waitForCoordinatorRelease(input) {
      calls.push(["release", input]);
      return release;
    },
    async waitForPendingBootstrapClaim(input) {
      calls.push(["pending", input]);
      return "d".repeat(64);
    },
    async waitForPublicEdge(input) {
      calls.push(["edge-ready", input]);
      return Object.freeze({
        coordinationReady: true,
        payerMcpReady: true,
        paymentMoved: false,
      });
    },
  });

  const paths = await dependencies.createStateRoot({ config: activeConfig, stateRoot });
  const relay = await dependencies.startRelay({ config: activeConfig, paths });
  const edge = await dependencies.startPublicEdge({ config: activeConfig, paths });
  await dependencies.probeCoordinationEdge({ config: activeConfig, paths });
  const coordinator = await dependencies.startCoordinator({ config: activeConfig, paths });
  const consoleServer = await dependencies.startConsole({ config: activeConfig, paths, release });
  const broker = await dependencies.startBootstrapBroker({ config: activeConfig, paths, release });
  const payer = await dependencies.startPayer({ broker, config: activeConfig, paths, release });
  await dependencies.waitForPayerMcpReady({ config: activeConfig, payer, release });
  await dependencies.waitForPublicEdge({ config: activeConfig, release });
  const discovery = await dependencies.publishRequestorDiscovery({ config: activeConfig, release });
  await broker.approveRequestor({ config: activeConfig, release });
  assert.deepEqual(
    await dependencies.runFunding({ config: activeConfig, paths, release }),
    { paymentMoved: false, status: "FUNDING_CONFIRMED" },
  );
  assert.deepEqual(await coordinator.waitForTerminal(), {
    paymentMoved: false,
    status: "VERIFICATION_PASSED",
  });
  dependencies.writeStatus(Object.freeze({ paymentMoved: false, stage: "TEST" }));

  assert.equal(discovery.discoveryUrl, activeConfig.publishing.requestorDiscoveryUrl);
  const spawns = calls.filter(([kind]) => kind === "spawn");
  assert.deepEqual(spawns.map(([, script]) => script), [
    "handshake-relay.mjs",
    "ssh",
    "handshake-coordinator.mjs",
    "handshake-console.mjs",
    "handshake-bootstrap-broker.mjs",
    "handshake-supervisor.mjs",
    "publish-requestor-discovery.mjs",
    "fund-bilateral-addresses.mjs",
  ]);
  const argsFor = (script) => spawns.find(([, name]) => name === script)[2];
  assert.deepEqual(argsFor("handshake-relay.mjs").slice(1), [
    "--advertised-host", "32.186.198.119",
    "--host", "127.0.0.1",
    "--port", "8443",
    "--repository-sha", REPOSITORY_SHA,
    "--state", paths.relayStateRoot,
    "--tls-certificate", activeConfig.relay.tlsCertificateFile,
    "--tls-private-key", activeConfig.relay.tlsPrivateKeyFile,
  ]);
  assert.deepEqual(argsFor("handshake-coordinator.mjs").slice(1), [
    "--clockchain-token-file", activeConfig.operator.clockchainTokenFile,
    "--operator-key-id", activeConfig.operator.keyId,
    "--operator-private-key", activeConfig.operator.privateKeyFile,
    "--release-root", paths.releaseRoot,
    "--relay-url", activeConfig.publicEdge.coordinationPublicUrl,
    "--repository-sha", REPOSITORY_SHA,
    "--rpc-url-file", activeConfig.operator.rpcUrlFile,
    "--tls-certificate", activeConfig.relay.tlsCertificateFile,
    "--tls-fingerprint", activeConfig.relay.tlsFingerprint,
  ]);
  assert.equal(argsFor("handshake-supervisor.mjs").includes(paths.bootstrapBrokerCapabilityFile), true);
  assert.deepEqual(
    argsFor("handshake-supervisor.mjs").slice(
      argsFor("handshake-supervisor.mjs").indexOf("--run-mode"),
      argsFor("handshake-supervisor.mjs").indexOf("--run-mode") + 2,
    ),
    ["--run-mode", "local-two-run"],
  );
  assert.equal(argsFor("publish-requestor-discovery.mjs").includes("hybrid-local"), true);
  assert.deepEqual(argsFor("fund-bilateral-addresses.mjs").slice(1), [
    "--funding-record", join(paths.releaseRoot, "funding-addresses.json"),
    "--journal-directory", activeConfig.funding.journalDirectory,
    "--keystore", activeConfig.funding.keystoreFile,
    "--rpc-url-file", activeConfig.operator.rpcUrlFile,
  ]);
  assert.equal(calls.some(([kind, value]) => kind === "stdout" && value.includes("AUTHORIZED")), false);

  await payer.stop();
  await broker.stop();
  await consoleServer.stop();
  await coordinator.stop();
  await edge.stop();
  await relay.stop();
});

test("waits for the coordinator-owned funding record before launching funding", async (t) => {
  const privateRoot = await mkdtemp(join(tmpdir(), "clockchain-production-funding-"));
  const stateRoot = join(privateRoot, "state");
  t.after(() => rm(privateRoot, { force: true, recursive: true }));
  const activeConfig = config(privateRoot);
  const calls = [];
  const dependencies = createProductionHybridOperatorDependencies({
    async spawnService({ args, command }) {
      const script = command === "ssh" ? "ssh" : basename(args[0]);
      calls.push(["spawn", script, args]);
      return fakeService(script, calls);
    },
    async waitForStableFundingRecord(path) {
      calls.push(["wait-funding-record", path]);
    },
  });

  const paths = await dependencies.createStateRoot({ config: activeConfig, stateRoot });
  assert.deepEqual(
    await dependencies.runFunding({ config: activeConfig, paths }),
    { paymentMoved: false, status: "FUNDING_CONFIRMED" },
  );

  assert.deepEqual(calls.map(([kind, value]) => [kind, value]), [
    ["wait-funding-record", join(paths.releaseRoot, "funding-addresses.json")],
    ["spawn", "fund-bilateral-addresses.mjs"],
  ]);
});

test("probeCoordinationEdge retries transient failures until the public tunnel is ready", async (t) => {
  const privateRoot = await mkdtemp(join(tmpdir(), "clockchain-production-probe-retry-"));
  const stateRoot = join(privateRoot, "state");
  t.after(() => rm(privateRoot, { force: true, recursive: true }));
  const activeConfig = config(privateRoot);
  const calls = [];
  let failures = 2;
  const dependencies = createProductionHybridOperatorDependencies({
    async probePinnedTlsEndpoint(input) {
      calls.push(input);
      if (failures > 0) {
        failures -= 1;
        throw new HybridPublicEdgeError("HYBRID_PUBLIC_EDGE_UNAVAILABLE");
      }
      return Object.freeze({ paymentMoved: false, ready: true });
    },
    async sleep() {},
  });

  assert.deepEqual(
    await dependencies.probeCoordinationEdge({ config: activeConfig }),
    { paymentMoved: false, ready: true },
  );
  assert.equal(calls.length, 3);
  assert.deepEqual(calls[0], {
    expectedFingerprint: activeConfig.relay.tlsFingerprint,
    host: activeConfig.publicEdge.host,
    path: "/",
    port: activeConfig.publicEdge.relayRemotePort,
  });
});

test("probeCoordinationEdge fails fast on certificate identity mismatch", async (t) => {
  const privateRoot = await mkdtemp(join(tmpdir(), "clockchain-production-probe-mismatch-"));
  const stateRoot = join(privateRoot, "state");
  t.after(() => rm(privateRoot, { force: true, recursive: true }));
  const activeConfig = config(privateRoot);
  const calls = [];
  const dependencies = createProductionHybridOperatorDependencies({
    async probePinnedTlsEndpoint(input) {
      calls.push(input);
      throw new HybridPublicEdgeError("HYBRID_PUBLIC_EDGE_IDENTITY_MISMATCH");
    },
    async sleep() {},
  });

  await assert.rejects(
    dependencies.probeCoordinationEdge({ config: activeConfig }),
    (error) =>
      error instanceof HybridPublicEdgeError &&
      error.code === "HYBRID_PUBLIC_EDGE_IDENTITY_MISMATCH",
  );
  assert.equal(calls.length, 1);
});

test("probeCoordinationEdge stops safely after bounded attempts", async (t) => {
  const privateRoot = await mkdtemp(join(tmpdir(), "clockchain-production-probe-bound-"));
  const stateRoot = join(privateRoot, "state");
  t.after(() => rm(privateRoot, { force: true, recursive: true }));
  const activeConfig = config(privateRoot);
  let attempts = 0;
  const dependencies = createProductionHybridOperatorDependencies({
    async probePinnedTlsEndpoint() {
      attempts += 1;
      throw new HybridPublicEdgeError("HYBRID_PUBLIC_EDGE_UNAVAILABLE");
    },
    async sleep() {},
  });

  await assert.rejects(
    dependencies.probeCoordinationEdge({ config: activeConfig }),
    (error) =>
      error instanceof HybridPublicEdgeError &&
      error.code === "HYBRID_PUBLIC_EDGE_UNAVAILABLE",
  );
  assert.equal(attempts > 1 && attempts <= 40, true);
  assert.equal(attempts, 40);
});
