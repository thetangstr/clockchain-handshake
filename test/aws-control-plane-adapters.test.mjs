import assert from "node:assert/strict";
import { test } from "node:test";

import {
  launchExternalVerifier,
} from "../src/bilateral/coordination/coordinator-runtime.mjs";
import {
  createHeartbeatOwnerLease,
} from "../src/bilateral/aws/efs-lease.mjs";
import {
  runAwsCoordinatorCycle,
} from "../scripts/run-aws-coordinator.mjs";
import {
  runAwsRelay,
} from "../scripts/run-aws-relay.mjs";

const REPOSITORY_SHA =
  "abcdef0123456789abcdef0123456789abcdef01";
const RELEASE_ID = "release-0123456789abcdef";
const SESSION_ID =
  "11111111-2222-4333-8444-555555555555";

test("relay adapter injects only the Fargate lease and immutable provenance for its assigned mount", async () => {
  const calls = [];
  const ownerLease = {
    acquire: async () => ({
      assertCurrent: async () => {},
      heartbeat: async () => {},
      release: async () => {},
    }),
  };
  const provenanceProvider = {
    assertRepository: async () => ({}),
    verify: async () => ({}),
  };
  const argv = [
    "--advertised-host", "relay.example.com",
    "--host", "0.0.0.0",
    "--port", "8443",
    "--repository-sha", REPOSITORY_SHA,
    "--state", "/mnt/relay",
    "--tls-certificate", "/run/secrets/relay.crt",
    "--tls-private-key", "/run/secrets/relay.key",
  ];
  const result = await runAwsRelay({
    argv,
    mount: {
      path: "/mnt/relay",
      purpose: "relay-state",
      readOnly: false,
    },
    ownerLease,
    provenanceProvider,
    relayMain: async (receivedArgv, dependencies) => {
      calls.push([receivedArgv, dependencies]);
      return { close: async () => {} };
    },
  });
  assert.equal(typeof result.close, "function");
  assert.deepEqual(calls[0][0], argv);
  assert.notEqual(
    calls[0][1].ownerLease,
    ownerLease,
  );
  assert.equal(
    typeof calls[0][1].ownerLease.acquire,
    "function",
  );
  assert.equal(
    calls[0][1].provenanceProvider,
    provenanceProvider,
  );
  await assert.rejects(runAwsRelay({
    argv,
    mount: {
      path: "/mnt/operator",
      purpose: "operator-state",
      readOnly: false,
    },
    ownerLease,
    provenanceProvider,
    relayMain: async () => ({}),
  }), /AWS relay adapter failed safely/);
});

test("coordinator remains waiting at package completion until an exact VERIFY action", async () => {
  const projections = [];
  const leaseCalls = [];
  let runtimeCalls = 0;
  let stepCalls = 0;
  const release = {
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
    state: "STAKEHOLDER_PACKAGES_READY",
  };
  const base = {
    config: {
      releaseRoot: { path: "/mnt/operator/release" },
      repositorySha: REPOSITORY_SHA,
    },
    createRuntime: (input) => {
      runtimeCalls += 1;
      return input;
    },
    loadRelease: async () => release,
    mounts: [
      {
        path: "/mnt/operator",
        purpose: "operator-state",
        readOnly: false,
      },
      {
        path: "/mnt/operator/release/verifier",
        purpose: "verdict-output",
        readOnly: true,
      },
    ],
    ownerLease: {
      async acquire(input) {
        leaseCalls.push(["acquire", input]);
        return {
          async assertCurrent() {
            leaseCalls.push(["assert"]);
          },
          async heartbeat() {
            leaseCalls.push(["heartbeat"]);
          },
          async release() {
            leaseCalls.push(["release"]);
          },
        };
      },
    },
    runStep: async ({ release: current }) => {
      stepCalls += 1;
      return {
        ...current,
        state: "STAKEHOLDER_VERIFIED",
      };
    },
    verifierLauncher: { launch: async () => ({}) },
    writeProjection: async (projection) => {
      projections.push(projection);
    },
  };
  const waiting = await runAwsCoordinatorCycle({
    ...base,
    readVerifyAction: async () => null,
  });
  assert.equal(waiting.state, "STAKEHOLDER_PACKAGES_READY");
  assert.equal(runtimeCalls, 0);
  assert.equal(stepCalls, 0);
  assert.deepEqual(leaseCalls[0], [
    "acquire",
    { root: "/mnt/operator/release" },
  ]);
  assert.deepEqual(
    leaseCalls.at(-1),
    ["release"],
  );
  assert.equal(
    projections.at(-1).status,
    "WAITING_FOR_OPERATOR_VERIFY",
  );
  assert.equal(projections.at(-1).paymentMoved, false);

  const action = {
    action: "VERIFY",
    expectedRevision: 7,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
    subjectRun: "stakeholder",
  };
  const advanced = await runAwsCoordinatorCycle({
    ...base,
    readVerifyAction: async () => action,
  });
  assert.equal(advanced.state, "STAKEHOLDER_VERIFIED");
  assert.equal(runtimeCalls, 1);
  assert.equal(stepCalls, 1);
  assert.equal(projections.at(-1).status, "ADVANCED");
});

test("heartbeat owner wrapper renews an idle Fargate lease and fences heartbeat failure", async () => {
  let scheduled;
  let cancelled = false;
  const calls = [];
  const wrapped = createHeartbeatOwnerLease({
    cancel: () => {
      cancelled = true;
    },
    intervalMs: 1_000,
    lease: {
      async acquire() {
        return {
          async assertCurrent() {
            calls.push("assert");
          },
          async heartbeat() {
            calls.push("heartbeat");
          },
          async release() {
            calls.push("release");
          },
        };
      },
    },
    schedule: (callback) => {
      scheduled = callback;
      return {};
    },
  });
  const handle = await wrapped.acquire({
    root: "/mnt/relay",
  });
  await scheduled();
  await handle.assertCurrent();
  await handle.release();
  assert.deepEqual(calls, [
    "heartbeat",
    "assert",
    "release",
  ]);
  assert.equal(cancelled, true);

  let failingTick;
  let releasedAfterFailure = false;
  const failing = createHeartbeatOwnerLease({
    cancel: () => {},
    intervalMs: 1_000,
    lease: {
      async acquire() {
        return {
          async assertCurrent() {},
          async heartbeat() {
            throw new Error("heartbeat canary");
          },
          async release() {
            releasedAfterFailure = true;
          },
        };
      },
    },
    schedule: (callback) => {
      failingTick = callback;
      return {};
    },
  });
  const failed = await failing.acquire({
    root: "/mnt/relay",
  });
  await failingTick();
  await assert.rejects(
    failed.assertCurrent(),
    /AWS EFS lease failed safely/,
  );
  await assert.rejects(
    failed.release(),
    /AWS EFS lease failed safely/,
  );
  assert.equal(releasedAfterFailure, true);
});

test("external verifier injection launches from exact evidence without running the local child", async () => {
  const calls = [];
  const verifierLauncher = {
    async launch(input) {
      calls.push(input);
      return {
        attemptId:
          "11111111-1111-4111-8111-111111111111",
        publicationDigest: "c".repeat(64),
        status: "VERIFICATION_PASSED",
        taskArn:
          "arn:aws:ecs:us-west-2:123456789012:task/clockchain/11111111111111111111111111111111",
      };
    },
  };
  const result = await launchExternalVerifier({
    evidenceDescriptor: {
      descriptorDigest: "d".repeat(64),
      evidenceDigest: "e".repeat(64),
      paymentMoved: false,
      schema: "clockchain.aws-verifier-evidence/v1",
      subjectRun: "stakeholder",
    },
    expectedRevision: 7,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
    verifierLauncher,
  });
  assert.deepEqual(result, {
    exitCode: 0,
    publicationDigest: "c".repeat(64),
    status: "VERIFICATION_PASSED",
    stderr: "",
    stdout: "",
  });
  assert.equal(calls.length, 1);
  assert.equal(
    JSON.stringify(calls).includes("private"),
    false,
  );
  assert.equal(
    JSON.stringify(calls).includes("treasury"),
    false,
  );
});
