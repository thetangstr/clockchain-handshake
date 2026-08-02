import assert from "node:assert/strict";
import { test } from "node:test";

import {
  appendPublicRunIndex,
  createImmutableRunSummary,
  observeImmutableRunSummary,
  publicArtifactKeys,
} from "../src/bilateral/aws/public-history.mjs";

const RUN_ID = "run-0123456789abcdef";
const COMPLETED_AT_MS = 2_000_000_000_500;
const LEDGER_IDS = [
  "00000000-0000-4000-8000-000000000001",
  "00000000-0000-4000-8000-000000000002",
  "00000000-0000-4000-8000-000000000003",
];

function projection(overrides = {}) {
  return {
    anchors: [
      {
        block: "101",
        cardinality: "1",
        explorerUrl:
          "https://sepolia.etherscan.io/block/101",
        kind: "PROPOSED",
        ledgerId: LEDGER_IDS[0],
        signerRole: "Payer",
        verified: true,
      },
      {
        block: "102",
        cardinality: "1",
        explorerUrl:
          "https://sepolia.etherscan.io/block/102",
        kind: "ACCEPTED",
        ledgerId: LEDGER_IDS[1],
        signerRole: "Requestor",
        verified: true,
      },
      {
        block: "103",
        cardinality: "1",
        explorerUrl:
          "https://sepolia.etherscan.io/block/103",
        kind: "ACKNOWLEDGED",
        ledgerId: LEDGER_IDS[2],
        signerRole: "Payer",
        verified: true,
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
      "clockchain.bilateral-public-monitor/v3",
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
      "clockchain.aws-public-run-summary/v2",
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

test("observes only exact receipt-complete immutable summaries", () => {
  const summary = createImmutableRunSummary({
    completedAtMs: COMPLETED_AT_MS,
    projection: projection(),
    secretCanaries: [],
    summaryUrl:
      `https://monitor.example/runs/${RUN_ID}.json`,
    verifierPublicationValidated: true,
  });
  assert.deepEqual(
    observeImmutableRunSummary(summary),
    summary,
  );
  for (const malformed of [
    { ...summary, schema: "clockchain.aws-public-run-summary/v1" },
    { ...summary, paymentMoved: true },
    { ...summary, anchors: summary.anchors.slice(0, 2) },
    {
      ...summary,
      anchors: summary.anchors.map((anchor, index) =>
        index === 1 ? { ...anchor, ledgerId: LEDGER_IDS[0] } : anchor),
    },
    { ...summary, receiptHtml: "not-public" },
  ]) {
    assert.throws(
      () => observeImmutableRunSummary(malformed),
      /AWS public history failed safely/,
    );
  }
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
  assert.equal(index.schema, "clockchain.aws-public-run-index/v2");

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

test("migrates a valid legacy v1 run index to v2 while preserving entries", () => {
  const legacyRunId = "run-1111111111111111";
  const legacyEntry = {
    anchors: [],
    businessResult:
      "The run stopped safely because the available evidence did not satisfy every required check.",
    completedAtMs: "1999999999000",
    runId: legacyRunId,
    runStatus: "FAILED",
    summaryUrl:
      `https://monitor.example/runs/${legacyRunId}.json`,
  };
  const nextSummary = createImmutableRunSummary({
    completedAtMs: COMPLETED_AT_MS,
    projection: projection(),
    secretCanaries: [],
    summaryUrl:
      `https://monitor.example/runs/${RUN_ID}.json`,
    verifierPublicationValidated: true,
  });

  const migrated = appendPublicRunIndex({
    index: {
      entries: [legacyEntry],
      paymentMoved: false,
      schema:
        "clockchain.aws-public-run-index/v1",
      updatedAtMs: "1999999999000",
    },
    summary: nextSummary,
    updatedAtMs: COMPLETED_AT_MS,
  });

  assert.equal(
    migrated.schema,
    "clockchain.aws-public-run-index/v2",
  );
  assert.deepEqual(
    migrated.entries.map(({ runId }) => runId),
    [RUN_ID, legacyRunId],
  );
  assert.deepEqual(
    migrated.entries[1],
    legacyEntry,
  );
});

test("rejects malformed legacy v1 run indexes instead of migrating them", () => {
  const legacyRunId = "run-1111111111111111";
  const legacyEntry = {
    anchors: [],
    businessResult:
      "The run stopped safely because the available evidence did not satisfy every required check.",
    completedAtMs: "1999999999000",
    runId: legacyRunId,
    runStatus: "FAILED",
    summaryUrl:
      `https://monitor.example/runs/${legacyRunId}.json`,
  };
  const nextSummary = createImmutableRunSummary({
    completedAtMs: COMPLETED_AT_MS,
    projection: projection(),
    secretCanaries: [],
    summaryUrl:
      `https://monitor.example/runs/${RUN_ID}.json`,
    verifierPublicationValidated: true,
  });
  for (const index of [
    {
      entries: [legacyEntry],
      paymentMoved: true,
      schema:
        "clockchain.aws-public-run-index/v1",
      updatedAtMs: "1999999999000",
    },
    {
      entries: [
        legacyEntry,
        { ...legacyEntry },
      ],
      paymentMoved: false,
      schema:
        "clockchain.aws-public-run-index/v1",
      updatedAtMs: "1999999999000",
    },
    {
      entries: [
        {
          ...legacyEntry,
          completedAtMs: "1999999998000",
        },
        legacyEntry,
      ],
      paymentMoved: false,
      schema:
        "clockchain.aws-public-run-index/v1",
      updatedAtMs: "1999999999000",
    },
    {
      entries: [
        {
          ...legacyEntry,
          businessResult:
            "The run expired before fresh independent verification completed.",
        },
      ],
      paymentMoved: false,
      schema:
        "clockchain.aws-public-run-index/v1",
      updatedAtMs: "1999999999000",
    },
    {
      entries: [legacyEntry],
      paymentMoved: false,
      schema:
        "clockchain.aws-public-run-index/v0",
      updatedAtMs: "1999999999000",
    },
  ]) {
    assert.throws(
      () =>
        appendPublicRunIndex({
          index,
          summary: nextSummary,
          updatedAtMs:
            COMPLETED_AT_MS,
        }),
      /AWS public history failed safely/,
    );
  }
});
