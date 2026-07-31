import assert from "node:assert/strict";
import { test } from "node:test";

import {
  appendPublicRunIndex,
  createImmutableRunSummary,
  publicArtifactKeys,
} from "../src/bilateral/aws/public-history.mjs";

const RUN_ID = "run-0123456789abcdef";
const COMPLETED_AT_MS = 2_000_000_000_500;

function projection(overrides = {}) {
  return {
    anchors: [
      {
        block: "101",
        explorerUrl:
          "https://sepolia.etherscan.io/block/101",
        kind: "PROPOSED",
        signerRole: "Payer",
      },
      {
        block: "102",
        explorerUrl:
          "https://sepolia.etherscan.io/block/102",
        kind: "ACCEPTED",
        signerRole: "Requestor",
      },
      {
        block: "103",
        explorerUrl:
          "https://sepolia.etherscan.io/block/103",
        kind: "ACKNOWLEDGED",
        signerRole: "Payer",
      },
    ],
    currentStep: "Fresh verification passed.",
    funding: { status: "READY" },
    mcp: { status: "READY" },
    paymentMoved: false,
    payer: { status: "READY" },
    publishedAtMs: "2000000000000",
    relay: { status: "READY" },
    requestor: { status: "READY" },
    runId: RUN_ID,
    runStatus: "VERIFIED",
    schema:
      "clockchain.bilateral-public-monitor/v2",
    staleAfterMs: 10_000,
    verifier: { status: "VERIFIED" },
    ...overrides,
  };
}

test("creates an immutable business summary only from a terminal validated projection", () => {
  const summary = createImmutableRunSummary({
    completedAtMs: COMPLETED_AT_MS,
    projection: projection(),
    secretCanaries: ["private-canary"],
    summaryUrl:
      `https://monitor.example/runs/${RUN_ID}.json`,
    verifierPublicationValidated: true,
  });
  assert.deepEqual(summary, {
    anchors: projection().anchors,
    businessResult:
      "The Requestor followed the Payer mandate and all three Clockchain anchors were independently verified.",
    completedAtMs: String(COMPLETED_AT_MS),
    paymentMoved: false,
    runId: RUN_ID,
    runStatus: "VERIFIED",
    schema:
      "clockchain.aws-public-run-summary/v1",
    summaryUrl:
      `https://monitor.example/runs/${RUN_ID}.json`,
  });
  assert.deepEqual(
    publicArtifactKeys({
      certificateFingerprint:
        "a".repeat(64),
      runId: RUN_ID,
    }),
    {
      certificate:
        `certificates/${"a".repeat(64)}.crt`,
      index: "runs/index.json",
      latest: "latest.json",
      payerDiscovery: "discoveries/payer.json",
      requestorDiscovery:
        "discoveries/requestor.json",
      summary: `runs/${RUN_ID}.json`,
    },
  );
});

test("keeps failed and expired summaries non-green and preserves only the authenticated prefix", () => {
  for (const runStatus of [
    "FAILED",
    "EXPIRED",
  ]) {
    const source = projection({
      anchors: projection().anchors.slice(0, 2),
      runStatus,
      verifier: { status: runStatus },
    });
    const summary = createImmutableRunSummary({
      completedAtMs: COMPLETED_AT_MS,
      projection: source,
      secretCanaries: [],
      summaryUrl:
        `https://monitor.example/runs/${RUN_ID}.json`,
      verifierPublicationValidated: false,
    });
    assert.equal(summary.runStatus, runStatus);
    assert.equal(
      summary.businessResult.includes(
        "independently verified",
      ),
      false,
    );
    assert.equal(summary.anchors.length, 2);
  }
});

test("rejects nonterminal, unvalidated green, malformed prefix, secret-bearing, and changed payment summaries", () => {
  for (const input of [
    {
      projection: projection({
        runStatus: "RUNNING",
        verifier: { status: "RUNNING" },
      }),
      verifierPublicationValidated: false,
    },
    {
      projection: projection(),
      verifierPublicationValidated: false,
    },
    {
      projection: projection({
        anchors: [
          projection().anchors[1],
        ],
        runStatus: "FAILED",
        verifier: { status: "FAILED" },
      }),
      verifierPublicationValidated: false,
    },
    {
      projection: projection({
        currentStep: "private-canary",
      }),
      verifierPublicationValidated: true,
    },
    {
      projection: projection({
        paymentMoved: true,
      }),
      verifierPublicationValidated: true,
    },
  ]) {
    assert.throws(
      () =>
        createImmutableRunSummary({
          completedAtMs:
            COMPLETED_AT_MS,
          secretCanaries: [
            "private-canary",
          ],
          summaryUrl:
            `https://monitor.example/runs/${RUN_ID}.json`,
          ...input,
        }),
      /AWS public history failed safely/,
    );
  }
});

test("maintains a bounded newest-first unique run index", () => {
  const first = createImmutableRunSummary({
    completedAtMs: COMPLETED_AT_MS,
    projection: projection(),
    secretCanaries: [],
    summaryUrl:
      `https://monitor.example/runs/${RUN_ID}.json`,
    verifierPublicationValidated: true,
  });
  const index = appendPublicRunIndex({
    index: null,
    summary: first,
    updatedAtMs: COMPLETED_AT_MS,
  });
  assert.equal(index.entries.length, 1);
  assert.equal(index.entries[0].runId, RUN_ID);

  const secondRun = "run-fedcba9876543210";
  const second = createImmutableRunSummary({
    completedAtMs: COMPLETED_AT_MS + 1,
    projection: projection({
      runId: secondRun,
    }),
    secretCanaries: [],
    summaryUrl:
      `https://monitor.example/runs/${secondRun}.json`,
    verifierPublicationValidated: true,
  });
  const next = appendPublicRunIndex({
    index,
    summary: second,
    updatedAtMs: COMPLETED_AT_MS + 1,
  });
  assert.deepEqual(
    next.entries.map(({ runId }) => runId),
    [secondRun, RUN_ID],
  );
  assert.throws(
    () =>
      appendPublicRunIndex({
        index: next,
        summary: second,
        updatedAtMs:
          COMPLETED_AT_MS + 2,
      }),
    /AWS public history failed safely/,
  );
  assert.throws(
    () =>
      appendPublicRunIndex({
        index: {
          ...next,
          entries: Array.from(
            { length: 26 },
            (_, index_) => ({
              ...next.entries[0],
              completedAtMs: String(
                COMPLETED_AT_MS - index_,
              ),
              runId:
                `run-${index_.toString(16).padStart(16, "0")}`,
            }),
          ),
        },
        summary: first,
        updatedAtMs:
          COMPLETED_AT_MS + 3,
      }),
    /AWS public history failed safely/,
  );
});
