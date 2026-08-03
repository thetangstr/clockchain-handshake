import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
  createLocalPublicMonitorPublisher,
  snapshotFromConsoleState,
} from "../src/bilateral/local-demo/public-monitor-publisher.mjs";
import { observePublicMonitorSnapshot } from "../src/bilateral/coordination/public-monitor.mjs";

const RELEASE_ID = "release-3d335cd009ac685b";
const RUN_ID = "run-3d335cd009ac685b";
const SESSION_ID = "c6b907e6-43f5-47c0-b85d-e421e9378cdf";
const SHA = "613a79c5c0e91d685bb0551472271e1ec638596b";

function anchor(block, kind, ledgerId) {
  return {
    block,
    cardinality: "1",
    digest: "a".repeat(64),
    kind,
    ledgerId,
    verified: true,
  };
}

const ANCHORS = [
  anchor("2650112", "PROPOSED", "c316ef68-f9db-46a1-bf3b-ec1fd97cf298"),
  anchor("2650130", "ACCEPTED", "b7994e52-4952-4b05-a938-5281ca302bbd"),
  anchor("2650134", "ACKNOWLEDGED", "721dbcd6-712c-4f4d-a810-ac5480f87c04"),
];

function consoleState(overrides = {}) {
  return {
    lifecycleView: {
      facts: {
        payerMandateReady: { stakeholder: true },
        paymentRequestMatched: { stakeholder: true },
        paymentRequestReady: { stakeholder: true },
      },
      health: {
        actors: { operator: "READY", payee: "READY", payer: "READY" },
        expiresAtMs: "1785722979556",
        observedAtMs: "1785722919556",
        schema: "clockchain.bilateral-console-health/v1",
        services: { relay: "READY", watcher: "READY" },
      },
      releaseId: RELEASE_ID,
      repositorySha: SHA,
      sessionId: SESSION_ID,
      state: "STAKEHOLDER_PACKAGES_READY",
    },
    nowMs: "1785722919556",
    ...overrides,
  };
}

function verifiedConsoleState() {
  return consoleState({
    lifecycleView: { ...consoleState().lifecycleView, state: "COMPLETE" },
    verifierPublication: {
      paymentMoved: false,
      publicationDigest: "7".repeat(64),
      releaseId: RELEASE_ID,
      repositorySha: SHA,
      schema: "clockchain.bilateral-verifier-publication/v1",
      sessionId: SESSION_ID,
      status: "VERIFICATION_PASSED",
      subjectRun: "stakeholder",
    },
    watcherSnapshot: { anchors: ANCHORS, descriptorDigest: "d".repeat(64) },
  });
}

test("maps a verified console state onto the exact v3 public snapshot", () => {
  const snapshot = snapshotFromConsoleState(verifiedConsoleState(), { nowMs: 1785722920000 });
  const validated = observePublicMonitorSnapshot(snapshot, { nowMs: 1785722920000 });
  assert.equal(validated.schema, "clockchain.bilateral-public-monitor/v3");
  assert.equal(validated.runId, RUN_ID);
  assert.equal(validated.runStatus, "VERIFIED");
  assert.equal(validated.verifier.status, "VERIFIED");
  assert.equal(validated.paymentMoved, false);
  assert.equal(validated.funding.status, "READY");
  assert.equal(validated.mcp.status, "READY");
  assert.equal(validated.anchors.length, 3);
  assert.deepEqual(
    validated.anchors.map(({ kind, signerRole }) => [kind, signerRole]),
    [["PROPOSED", "Payer"], ["ACCEPTED", "Requestor"], ["ACKNOWLEDGED", "Payer"]],
  );
  assert.equal(validated.anchors[0].explorerUrl, "https://sepolia.etherscan.io/block/2650112");
  assert.equal(validated.anchors[1].ledgerId, "b7994e52-4952-4b05-a938-5281ca302bbd");
  assert.equal(validated.anchors.every((entry) => entry.cardinality === "1" && entry.verified === true), true);
  assert.equal("digest" in validated.anchors[0], false);
  assert.match(validated.currentStep, /fresh verifier confirmed/);
});

test("maps early and mid-run states to WAITING and RUNNING consistently", () => {
  const waiting = snapshotFromConsoleState(
    consoleState({ lifecycleView: { ...consoleState().lifecycleView, facts: {}, state: "BOOTSTRAPPING" } }),
    { nowMs: 100_000 },
  );
  assert.equal(waiting.runStatus, "WAITING");
  assert.equal(waiting.anchors.length, 0);
  assert.equal(waiting.verifier.status, "NOT_STARTED");
  assert.equal(waiting.funding.status, "NOT_STARTED");
  assert.equal(waiting.mcp.status, "WAITING");
  const running = snapshotFromConsoleState(
    consoleState({ watcherSnapshot: { anchors: ANCHORS.slice(0, 1), descriptorDigest: "d".repeat(64) } }),
    { nowMs: 100_000 },
  );
  assert.equal(running.runStatus, "RUNNING");
  assert.equal(running.verifier.status, "NOT_STARTED");
  assert.equal(running.funding.status, "READY");
  const verifying = snapshotFromConsoleState(
    consoleState({ watcherSnapshot: { anchors: ANCHORS, descriptorDigest: "d".repeat(64) } }),
    { nowMs: 100_000 },
  );
  assert.equal(verifying.runStatus, "RUNNING");
  assert.equal(verifying.verifier.status, "RUNNING");
  for (const snapshot of [waiting, running, verifying]) {
    observePublicMonitorSnapshot(snapshot, { nowMs: 100_000 });
  }
});

test("fails closed on payment movement, malformed anchors, unknown states, and bad release ids", () => {
  const moved = verifiedConsoleState();
  moved.verifierPublication = { ...moved.verifierPublication, paymentMoved: true };
  assert.throws(() => snapshotFromConsoleState(moved, { nowMs: 1 }), { code: "LOCAL_PUBLIC_MONITOR_INVALID" });
  const badAnchor = consoleState({ watcherSnapshot: { anchors: [{ ...ANCHORS[0], verified: false }], descriptorDigest: "d".repeat(64) } });
  assert.throws(() => snapshotFromConsoleState(badAnchor, { nowMs: 1 }), { code: "LOCAL_PUBLIC_MONITOR_INVALID" });
  const badState = consoleState();
  badState.lifecycleView = { ...badState.lifecycleView, state: "MADE_UP" };
  assert.throws(() => snapshotFromConsoleState(badState, { nowMs: 1 }), { code: "LOCAL_PUBLIC_MONITOR_INVALID" });
  const badRelease = consoleState();
  badRelease.lifecycleView = { ...badRelease.lifecycleView, releaseId: "something-else" };
  assert.throws(() => snapshotFromConsoleState(badRelease, { nowMs: 1 }), { code: "LOCAL_PUBLIC_MONITOR_INVALID" });
  const reordered = consoleState({ watcherSnapshot: { anchors: [ANCHORS[1], ANCHORS[0], ANCHORS[2]], descriptorDigest: "d".repeat(64) } });
  assert.throws(
    () => observePublicMonitorSnapshot(snapshotFromConsoleState(reordered, { nowMs: 1 }), { nowMs: 1 }),
  );
});

test("publisher stages latest.json and, once verified, the immutable run history", async () => {
  const root = await mkdtemp(join(tmpdir(), "local-public-monitor-"));
  const consoleStatePath = join(root, "console-state.json");
  await writeFile(consoleStatePath, JSON.stringify(verifiedConsoleState()));
  const uploads = [];
  const stageRoot = join(root, "stage");
  const publisher = createLocalPublicMonitorPublisher({
    bucketPrefix: "s3://example-bucket",
    consoleStatePath,
    now: () => 1785722920000,
    publicBaseUrl: "https://public.example.com",
    secretCanaries: ["canary-token-value"],
    stageRoot,
    transport: async (localPath, bucketKey) => uploads.push([localPath, bucketKey]),
  });
  const result = await publisher.publishOnce();
  assert.equal(result.published, true);
  assert.equal(result.runStatus, "VERIFIED");
  assert.equal(result.historyWritten, true);
  const latest = JSON.parse(await readFile(join(stageRoot, "latest.json"), "utf8"));
  assert.equal(latest.runStatus, "VERIFIED");
  assert.equal(latest.anchors.length, 3);
  const summary = JSON.parse(await readFile(join(stageRoot, "runs", `${RUN_ID}.json`), "utf8"));
  assert.equal(summary.schema, "clockchain.aws-public-run-summary/v2");
  assert.equal(summary.runStatus, "VERIFIED");
  assert.equal(summary.summaryUrl, `https://public.example.com/runs/${RUN_ID}.json`);
  assert.match(summary.businessResult, /independently verified/);
  const index = JSON.parse(await readFile(join(stageRoot, "runs", "index.json"), "utf8"));
  assert.equal(index.schema, "clockchain.aws-public-run-index/v2");
  assert.equal(index.entries.length, 1);
  assert.equal(index.entries[0].runId, RUN_ID);
  assert.deepEqual(uploads.map(([, key]) => key), [
    "s3://example-bucket/latest.json",
    `s3://example-bucket/runs/${RUN_ID}.json`,
    "s3://example-bucket/runs/index.json",
  ]);
  const second = await publisher.publishOnce();
  assert.equal(second.historyWritten, true);
  assert.equal(uploads.length, 4);
  const indexAfter = JSON.parse(await readFile(join(stageRoot, "runs", "index.json"), "utf8"));
  assert.equal(indexAfter.entries.length, 1);
});

test("publisher reports no console state without writing anything", async () => {
  const root = await mkdtemp(join(tmpdir(), "local-public-monitor-empty-"));
  const uploads = [];
  const publisher = createLocalPublicMonitorPublisher({
    bucketPrefix: "s3://example-bucket",
    consoleStatePath: join(root, "missing.json"),
    now: () => 100_000,
    publicBaseUrl: "https://public.example.com",
    stageRoot: join(root, "stage"),
    transport: async () => uploads.push(1),
  });
  const result = await publisher.publishOnce();
  assert.equal(result.published, false);
  assert.equal(result.reason, "NO_CONSOLE_STATE");
  assert.equal(uploads.length, 0);
});

test("publisher refuses to ship a payload containing a secret canary", async () => {
  const root = await mkdtemp(join(tmpdir(), "local-public-monitor-canary-"));
  const consoleStatePath = join(root, "console-state.json");
  const state = verifiedConsoleState();
  state.watcherSnapshot = {
    ...state.watcherSnapshot,
    anchors: state.watcherSnapshot.anchors.map((entry, index) =>
      index === 0 ? { ...entry, ledgerId: "leaked-canary-token-value" } : entry),
  };
  await writeFile(consoleStatePath, JSON.stringify(state));
  const uploads = [];
  const publisher = createLocalPublicMonitorPublisher({
    bucketPrefix: "s3://example-bucket",
    consoleStatePath,
    now: () => 1785722920000,
    publicBaseUrl: "https://public.example.com",
    secretCanaries: ["leaked-canary-token-value"],
    stageRoot: join(root, "stage"),
    transport: async () => uploads.push(1),
  });
  await assert.rejects(publisher.publishOnce(), { code: "LOCAL_PUBLIC_MONITOR_INVALID" });
  assert.equal(uploads.length, 0);
});
