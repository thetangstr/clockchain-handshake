import assert from "node:assert/strict";
import test from "node:test";

import {
  HYBRID_OPERATOR_STATUS_SCHEMA,
  HybridOperatorRuntimeError,
  runHybridLocalOperator,
} from "../src/bilateral/local-demo/operator-runtime.mjs";

const REPOSITORY_SHA = "b".repeat(40);
const RELEASE_ID = "release-aaaaaaaaaaaaaaaa";
const SESSION_ID = "11111111-1111-4111-8111-111111111111";

function config() {
  return Object.freeze({
    console: Object.freeze({ host: "127.0.0.1", port: 8787 }),
    funding: Object.freeze({
      journalDirectory: "/private/operator/funding-journal",
      keystoreFile: "/private/operator/treasury.json",
      mode: "fund-on-ready",
    }),
    operator: Object.freeze({
      clockchainTokenFile: "/private/operator/clockchain-token",
      keyId: "operator-yang",
      privateKeyFile: "/private/operator/operator-private.pem",
      rpcUrlFile: "/private/operator/sepolia-rpc",
    }),
    payerMcp: Object.freeze({
      host: "127.0.0.1",
      port: 9443,
      publicUrl: "https://32.186.198.119:9443/mcp",
      tlsCertificateFile: "/private/operator/payer-mcp.crt",
      tlsPrivateKeyFile: "/private/operator/payer-mcp.key",
    }),
    paymentMoved: false,
    publicEdge: Object.freeze({
      coordinationPublicUrl: "https://32.186.198.119:8443",
      host: "32.186.198.119",
      hostKeyFile: "/private/operator/edge-known-hosts",
      identityFile: "/private/operator/edge-identity",
      payerMcpRemotePort: 9443,
      port: 22,
      relayRemotePort: 8443,
      user: "clockchain-tunnel",
    }),
    publishing: Object.freeze({
      bucket: "clockchain-handshake-monitor-570035913370-us-west-2",
      receiptEmailUrl: "https://anhgkkcm46.execute-api.us-west-2.amazonaws.com/v1/receipt-email",
      region: "us-west-2",
      requestorDiscoveryUrl: "https://clockchain-handshake-monitor-570035913370-us-west-2.s3.us-west-2.amazonaws.com/requestor-discovery.json",
    }),
    relay: Object.freeze({
      advertisedHost: "32.186.198.119",
      host: "127.0.0.1",
      port: 8443,
      tlsCertificateFile: "/private/operator/relay.crt",
      tlsFingerprint: "a".repeat(64),
      tlsPrivateKeyFile: "/private/operator/relay.key",
    }),
    repositorySha: REPOSITORY_SHA,
    schema: "clockchain.hybrid-local-operator-config/v1",
  });
}

function fixture({ failAt = null } = {}) {
  const events = [];
  const failureRecords = [];
  const statuses = [];
  const resource = (name, extra = {}) => Object.freeze({
    ...extra,
    async stop() {
      events.push(`stop:${name}`);
    },
    waitForExit() {
      return new Promise(() => {});
    },
  });
  const step = async (name, result) => {
    events.push(name);
    if (failAt === name) throw new Error(`failed:${name}`);
    return result;
  };
  const release = Object.freeze({
    manifests: Object.freeze([
      Object.freeze({ path: "/private/state/release/payee.launch.json", role: "payee" }),
      Object.freeze({ path: "/private/state/release/payer.launch.json", role: "payer" }),
    ]),
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
  });
  const dependencies = Object.freeze({
    async createStateRoot() {
      return step("create-state", Object.freeze({
        bootstrapBrokerCapabilityFile: "/private/state/broker.capability",
        bootstrapBrokerStateRoot: "/private/state/broker",
        payerStateRoot: "/private/state/payer",
        relayStateRoot: "/private/state/relay",
        releaseRoot: "/private/state/release",
      }));
    },
    async startRelay() {
      return step("start-relay", resource("relay"));
    },
    async startPublicEdge() {
      return step("start-edge", resource("edge"));
    },
    async probeCoordinationEdge() {
      return step("probe-coordination", Object.freeze({ paymentMoved: false, ready: true }));
    },
    async startCoordinator() {
      return step("start-coordinator", resource("coordinator", {
        release,
        async waitForTerminal() {
          return step("wait-coordinator", Object.freeze({
            paymentMoved: false,
            status: "VERIFICATION_PASSED",
          }));
        },
      }));
    },
    async startConsole() {
      return step("start-console", resource("console"));
    },
    async startBootstrapBroker() {
      return step("start-broker", resource("broker", {
        async approveRequestor() {
          return step("approve-requestor", Object.freeze({
            paymentMoved: false,
            status: "APPROVED",
          }));
        },
        capabilityFile: "/private/state/broker.capability",
        url: "http://127.0.0.1:9555",
      }));
    },
    async startPayer() {
      return step("start-payer", resource("payer"));
    },
    async waitForPayerMcpReady() {
      return step("wait-payer", Object.freeze({
        paymentMoved: false,
        status: "PAYER_MCP_READY",
        url: "https://32.186.198.119:9443/mcp",
      }));
    },
    async waitForPublicEdge() {
      return step("wait-edge", Object.freeze({
        coordinationReady: true,
        payerMcpReady: true,
        paymentMoved: false,
      }));
    },
    async publishRequestorDiscovery() {
      return step("publish-discovery", Object.freeze({
        discoveryUrl: "https://clockchain-handshake-monitor-570035913370-us-west-2.s3.us-west-2.amazonaws.com/requestor-discovery.json",
        paymentMoved: false,
      }));
    },
    async runFunding() {
      return step("run-funding", Object.freeze({
        paymentMoved: false,
        status: "FUNDING_CONFIRMED",
      }));
    },
    writeFailureRecord(record) {
      failureRecords.push(record);
    },
    writeStatus(status) {
      statuses.push(status);
    },
  });
  return { dependencies, events, failureRecords, statuses };
}

function stages(statuses) {
  return statuses.map(({ stage }) => stage);
}

function assertPublicStatus(status) {
  assert.equal(status.schema, HYBRID_OPERATOR_STATUS_SCHEMA);
  assert.equal(status.paymentMoved, false);
  assert.equal(typeof status.message, "string");
  assert.doesNotMatch(JSON.stringify(status), /AUTHORIZED/);
  assert.doesNotMatch(JSON.stringify(status), /\/private\//);
}

test("runs the local authority in public-reachable order and remains attached through verification", async () => {
  const { dependencies, events, statuses } = fixture();
  const result = await runHybridLocalOperator({
    config: config(),
    stateRoot: "/private/state",
  }, dependencies);

  assert.deepEqual(result, {
    paymentMoved: false,
    status: "VERIFICATION_PASSED",
  });
  assert.deepEqual(events, [
    "create-state",
    "start-relay",
    "start-edge",
    "probe-coordination",
    "start-coordinator",
    "start-console",
    "start-broker",
    "start-payer",
    "wait-payer",
    "wait-edge",
    "publish-discovery",
    "approve-requestor",
    "run-funding",
    "wait-coordinator",
    "stop:payer",
    "stop:broker",
    "stop:console",
    "stop:coordinator",
    "stop:edge",
    "stop:relay",
  ]);
  assert.deepEqual(stages(statuses), [
    "STATE_ROOT_CREATED",
    "RELAY_LISTENING",
    "PUBLIC_EDGE_STARTED",
    "PUBLIC_EDGE_COORDINATION_READY",
    "COORDINATOR_RELEASE_CREATED",
    "CONSOLE_LISTENING",
    "BOOTSTRAP_BROKER_LISTENING",
    "PAYER_SUPERVISOR_STARTED",
    "PAYER_MCP_READY",
    "PUBLIC_EDGE_READY",
    "REQUESTOR_DISCOVERY_PUBLISHED",
    "REQUESTOR_HANDOFF_READY",
    "BOOTSTRAP_APPROVED",
    "FUNDING_CONFIRMED",
    "VERIFICATION_PASSED",
  ]);
  statuses.forEach(assertPublicStatus);
  assert.equal(statuses.at(-1).message, "Fresh independent verification passed. Open the public receipts for the result.");
});

test("publishes only public handoff fields and never serializes config or private state paths", async () => {
  const { dependencies, statuses } = fixture();
  await runHybridLocalOperator({ config: config(), stateRoot: "/private/state" }, dependencies);
  const handoff = statuses.find(({ stage }) => stage === "REQUESTOR_HANDOFF_READY");
  assert.deepEqual(handoff, {
    message: "The Payer is ready. The stakeholder may now use the single Requestor prompt.",
    paymentMoved: false,
    payerMcpUrl: "https://32.186.198.119:9443/mcp",
    repositorySha: REPOSITORY_SHA,
    requestorDiscoveryUrl: "https://clockchain-handshake-monitor-570035913370-us-west-2.s3.us-west-2.amazonaws.com/requestor-discovery.json",
    schema: HYBRID_OPERATOR_STATUS_SCHEMA,
    stage: "REQUESTOR_HANDOFF_READY",
  });
});

test("stops every started resource in reverse order and emits one fixed safe failure", async (t) => {
  for (const failAt of [
    "probe-coordination",
    "start-broker",
    "wait-payer",
    "wait-edge",
    "publish-discovery",
    "approve-requestor",
    "run-funding",
    "wait-coordinator",
  ]) {
    await t.test(failAt, async () => {
      const { dependencies, events, statuses } = fixture({ failAt });
      await assert.rejects(
        runHybridLocalOperator({ config: config(), stateRoot: "/private/state" }, dependencies),
        (error) => {
          assert.equal(error instanceof HybridOperatorRuntimeError, true);
          assert.equal(error.code, "HYBRID_OPERATOR_RUN_FAILED");
          assert.equal(error.category, "protocol");
          assert.equal(error.message, "Hybrid local operator stopped safely.");
          return true;
        },
      );
      const failures = statuses.filter(({ stage }) => stage === "RUN_STOPPED_SAFELY");
      assert.equal(failures.length, 1);
      assert.deepEqual(failures[0], {
        message: "The run stopped safely before authorization. Review the local operator log.",
        paymentMoved: false,
        schema: HYBRID_OPERATOR_STATUS_SCHEMA,
        stage: "RUN_STOPPED_SAFELY",
      });
      statuses.forEach(assertPublicStatus);
      const stops = events.filter((event) => event.startsWith("stop:"));
      const failureIndex = events.indexOf(failAt);
      const started = events
        .slice(0, failureIndex === -1 ? events.length : failureIndex)
        .filter((event) => event.startsWith("start-"))
        .map((event) => event.slice("start-".length));
      assert.deepEqual(stops.map((event) => event.slice("stop:".length)), started.reverse());
    });
  }
});

test("rejects dependency drift and non-false terminal results before reporting success", async () => {
  const base = fixture();
  await assert.rejects(
    runHybridLocalOperator({ config: config(), stateRoot: "/private/state" }, {
      ...base.dependencies,
      unexpected() {},
    }),
    HybridOperatorRuntimeError,
  );

  const wrong = fixture();
  await assert.rejects(
    runHybridLocalOperator({ config: config(), stateRoot: "/private/state" }, {
      ...wrong.dependencies,
      async startCoordinator() {
        wrong.events.push("start-coordinator");
        return Object.freeze({
          release: Object.freeze({
            manifests: Object.freeze([]),
            paymentMoved: false,
            releaseId: RELEASE_ID,
            repositorySha: REPOSITORY_SHA,
            sessionId: SESSION_ID,
          }),
          async stop() {},
          async waitForTerminal() {
            return { paymentMoved: true, status: "VERIFICATION_PASSED" };
          },
        });
      },
    }),
    HybridOperatorRuntimeError,
  );
  assert.equal(wrong.statuses.some(({ stage }) => stage === "VERIFICATION_PASSED"), false);
});

test("fails fast with the service name when a supervised service exits unexpectedly mid-run", async () => {
  const base = fixture();
  let exitPayer;
  const payerExit = new Promise((resolve) => {
    exitPayer = resolve;
  });
  const dependencies = Object.freeze({
    ...base.dependencies,
    async startBootstrapBroker() {
      base.events.push("start-broker");
      return Object.freeze({
        async approveRequestor() {
          base.events.push("approve-requestor");
          setImmediate(() => exitPayer(1));
          return new Promise(() => {});
        },
        capabilityFile: "/private/state/broker.capability",
        async stop() {
          base.events.push("stop:broker");
        },
        url: "http://127.0.0.1:9555",
        waitForExit() {
          return new Promise(() => {});
        },
      });
    },
    async startPayer() {
      base.events.push("start-payer");
      return Object.freeze({
        readStderrTail() {
          return "payer crashed: relay connection refused";
        },
        async stop() {
          base.events.push("stop:payer");
        },
        waitForExit() {
          return payerExit;
        },
      });
    },
  });
  await assert.rejects(
    runHybridLocalOperator({ config: config(), stateRoot: "/private/state" }, dependencies),
    HybridOperatorRuntimeError,
  );
  const serviceFailed = base.statuses.filter(({ stage }) => stage === "SERVICE_FAILED");
  assert.equal(serviceFailed.length, 1);
  assert.equal(serviceFailed[0].service, "payer-supervisor");
  assert.equal(serviceFailed[0].paymentMoved, false);
  assert.equal(serviceFailed[0].schema, HYBRID_OPERATOR_STATUS_SCHEMA);
  assert.deepEqual(base.failureRecords, [
    {
      exitCode: 1,
      service: "payer-supervisor",
      stateRoot: "/private/state",
      stderrTail: "payer crashed: relay connection refused",
    },
  ]);
  assert.equal(
    base.statuses.filter(({ stage }) => stage === "RUN_STOPPED_SAFELY").length,
    1,
  );
  assert.equal(
    base.statuses.some(({ stage }) => stage === "VERIFICATION_PASSED"),
    false,
  );
  base.statuses.forEach(assertPublicStatus);
  const stops = base.events.filter((event) => event.startsWith("stop:"));
  assert.deepEqual(stops, [
    "stop:payer",
    "stop:broker",
    "stop:console",
    "stop:coordinator",
    "stop:edge",
    "stop:relay",
  ]);
});

test("never raises the service-failure path for a clean exit before shutdown", async () => {
  const base = fixture();
  let exitPayer;
  const payerExit = new Promise((resolve) => {
    exitPayer = resolve;
  });
  const dependencies = Object.freeze({
    ...base.dependencies,
    async startPayer() {
      base.events.push("start-payer");
      setImmediate(() => exitPayer(0));
      return Object.freeze({
        readStderrTail() {
          return "";
        },
        async stop() {
          base.events.push("stop:payer");
        },
        waitForExit() {
          return payerExit;
        },
      });
    },
  });
  const result = await runHybridLocalOperator(
    { config: config(), stateRoot: "/private/state" },
    dependencies,
  );
  assert.deepEqual(result, { paymentMoved: false, status: "VERIFICATION_PASSED" });
  assert.equal(
    base.statuses.some(({ stage }) => stage === "SERVICE_FAILED"),
    false,
  );
  assert.deepEqual(base.failureRecords, []);
});
