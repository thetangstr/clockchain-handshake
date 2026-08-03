import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { main } from "../bin/handshake-public-monitor.mjs";

const RELEASE_ID = "release-3d335cd009ac685b";
const SESSION_ID = "c6b907e6-43f5-47c0-b85d-e421e9378cdf";
const SHA = "2abc12ff1f88e43bb493f064b719d4771d5ca0e1";

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

function verifiedConsoleState() {
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
      state: "COMPLETE",
    },
    nowMs: "1785722919556",
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
  };
}

function argvFor(root, extra = []) {
  return [
    "--console-state", join(root, "console-state.json"),
    "--stage-root", join(root, "stage"),
    "--bucket-prefix", "s3://example-bucket",
    "--public-base-url", "https://example-bucket.s3.us-west-2.amazonaws.com",
    "--canary", "/private/operator",
    "--poll-ms", "1000",
    "--grace-ms", "1000",
    "--max-ms", "60000",
    ...extra,
  ];
}

test("publishes the public snapshot and immutable history through the injected transport", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "public-monitor-cli-"));
  t.after(() => rm(root, { force: true, recursive: true }));
  await writeFile(join(root, "console-state.json"), JSON.stringify(verifiedConsoleState()));
  const uploads = [];
  const lines = [];
  const code = await main(argvFor(root), {
    now: (() => { let tick = 1785722920000; return () => (tick += 1000); })(),
    sleeper: async () => {},
    stdout: { write(line) { lines.push(line); } },
    async transport(localPath, s3Uri) {
      uploads.push([localPath, s3Uri]);
    },
  });
  assert.equal(code, 0);
  assert.deepEqual(
    uploads.slice(0, 3).map(([, uri]) => uri),
    [
      "s3://example-bucket/latest.json",
      "s3://example-bucket/runs/run-3d335cd009ac685b.json",
      "s3://example-bucket/runs/index.json",
    ],
  );
  const historyUploads = uploads.filter(([, uri]) => uri.includes("/runs/"));
  assert.equal(historyUploads.length, 2);
  assert.equal(uploads.every(([, uri]) => uri.startsWith("s3://example-bucket/")), true);
  const heartbeats = lines.map((line) => JSON.parse(line));
  assert.equal(heartbeats.at(-1).paymentMoved, false);
  assert.equal(heartbeats.at(-1).runStatus, "VERIFIED");
  assert.equal(heartbeats.at(-1).historyWritten, true);
  assert.equal(JSON.stringify(heartbeats).includes("AUTHORIZED"), false);
  assert.equal(JSON.stringify(heartbeats).includes("/private/operator"), false);
  const latest = JSON.parse(await readFile(join(root, "stage", "latest.json"), "utf8"));
  assert.equal(latest.schema, "clockchain.bilateral-public-monitor/v3");
  assert.equal(latest.runStatus, "VERIFIED");
  assert.equal(latest.anchors.length, 3);
});

test("keeps polling without console state and exits non-zero when the verdict never arrives", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "public-monitor-cli-"));
  t.after(() => rm(root, { force: true, recursive: true }));
  const lines = [];
  const code = await main(argvFor(root, ["--max-ms", "1000"]), {
    now: (() => { let tick = 1785722920000; return () => (tick += 1000); })(),
    sleeper: async () => {},
    stdout: { write(line) { lines.push(line); } },
    async transport() {
      assert.fail("no console state means no upload");
    },
  });
  assert.equal(code, 1);
  const heartbeats = lines.map((line) => JSON.parse(line));
  assert.equal(heartbeats.at(-1).published, false);
  assert.equal(heartbeats.at(-1).reason, "NO_CONSOLE_STATE");
});

test("fails closed on invalid arguments and on canary leakage", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "public-monitor-cli-"));
  t.after(() => rm(root, { force: true, recursive: true }));
  await assert.rejects(main(["--console-state", join(root, "x.json")], {}));
  const poisoned = verifiedConsoleState();
  poisoned.lifecycleView.releaseId = "/private/operator";
  await writeFile(join(root, "console-state.json"), JSON.stringify(poisoned));
  await assert.rejects(main(argvFor(root), {
    now: () => 1785722920000,
    sleeper: async () => {},
    stdout: { write() {} },
    async transport() {},
  }));
});
