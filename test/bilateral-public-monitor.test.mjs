import assert from "node:assert/strict";
import { test } from "node:test";

import {
  buildPublicMonitorSnapshot,
  buildUnavailablePublicMonitorSnapshot,
  observePublicMonitorSnapshot,
} from "../src/bilateral/coordination/public-monitor.mjs";

const RUN_ID = "run-0123456789abcdef";
const PUBLISHED_AT_MS = 2_000_000_000_000;
const EXPLORER_URLS = Object.freeze([
  "https://sepolia.etherscan.io/block/101",
  "https://sepolia.etherscan.io/block/102",
  "https://sepolia.etherscan.io/block/103",
]);

function projection() {
  return {
    actors: {
      operator: {
        health: "READY",
        label: "Operator",
        role: "operator",
      },
      payer: {
        health: "READY",
        label: "Payer",
        role: "payer",
      },
      payee: {
        health: "READY",
        label: "Requestor",
        role: "payee",
      },
    },
    anchors: [
      {
        actor: "Payer",
        block: "101",
        digest: "d".repeat(64),
        kind: "PROPOSED",
        sequence: 1,
        stage: "proposal",
        verified: true,
      },
      {
        actor: "Requestor",
        block: "102",
        digest: "e".repeat(64),
        kind: "ACCEPTED",
        sequence: 2,
        stage: "acceptance",
        verified: true,
      },
      {
        actor: "Payer",
        block: "103",
        digest: "f".repeat(64),
        kind: "ACKNOWLEDGED",
        sequence: 3,
        stage: "acknowledgment",
        verified: true,
      },
    ],
    deadline: {
      expiresAtMs: "2000000060000",
      freshness: "FRESH",
      nowMs: PUBLISHED_AT_MS,
    },
    failure: null,
    mandate: {
      amount: { currency: "USD", value: "100" },
      digest: "b".repeat(64),
      kind: "pre-protocol",
      matched: true,
      purpose: "private-purpose",
      received: true,
    },
    paymentMoved: false,
    phase: {
      advisory: true,
      value: "STAKEHOLDER_RUNNING",
    },
    request: {
      amount: { currency: "USD", value: "100" },
      digest: "c".repeat(64),
      invoiceReference: "private-invoice",
      kind: "pre-protocol",
      received: true,
    },
    schema:
      "clockchain.bilateral-console-projection/v1",
    session: {
      advisory: true,
      observations: {
        relay: {
          advisory: true,
          health: "READY",
          label: "relay advisory",
        },
        watcher: {
          advisory: true,
          health: "READY",
          label: "watcher advisory",
        },
      },
      releaseId: "private-release",
      repositorySha: "a".repeat(40),
      sessionId:
        "11111111-2222-4333-8444-555555555555",
    },
    verifier: {
      advisory: false,
      publicationDigest: "9".repeat(64),
      status: "VERIFICATION_PASSED",
    },
  };
}

function options(overrides = {}) {
  return {
    anchorExplorerUrls: [...EXPLORER_URLS],
    nowMs: PUBLISHED_AT_MS,
    payerMcpReady: true,
    publishedAtMs: PUBLISHED_AT_MS,
    runId: RUN_ID,
    sourceObservedAtMs: PUBLISHED_AT_MS - 100,
    staleAfterMs: 10_000,
    verifierPublicationValidated: true,
    ...overrides,
  };
}

test("builds one exact secret-free business monitor with three independently verifiable anchors", () => {
  const value = buildPublicMonitorSnapshot(
    projection(),
    options(),
  );
  assert.deepEqual(value, {
    anchors: [
      {
        block: "101",
        explorerUrl: EXPLORER_URLS[0],
        kind: "PROPOSED",
        signerRole: "Payer",
      },
      {
        block: "102",
        explorerUrl: EXPLORER_URLS[1],
        kind: "ACCEPTED",
        signerRole: "Requestor",
      },
      {
        block: "103",
        explorerUrl: EXPLORER_URLS[2],
        kind: "ACKNOWLEDGED",
        signerRole: "Payer",
      },
    ],
    currentStep:
      "Fresh independent verification confirmed all three Clockchain anchors.",
    funding: { status: "READY" },
    mcp: { status: "READY" },
    paymentMoved: false,
    payer: { status: "READY" },
    publishedAtMs: String(PUBLISHED_AT_MS),
    relay: { status: "READY" },
    requestor: { status: "READY" },
    runId: RUN_ID,
    runStatus: "VERIFIED",
    schema:
      "clockchain.bilateral-public-monitor/v2",
    staleAfterMs: 10_000,
    verifier: { status: "VERIFIED" },
  });
  const serialized = JSON.stringify(value);
  for (const forbidden of [
    "private-release",
    "private-purpose",
    "private-invoice",
    "11111111-2222-4333-8444-555555555555",
    "bbbbbbbb",
    "cccccccc",
    "dddddddd",
  ]) {
    assert.doesNotMatch(
      serialized,
      new RegExp(forbidden),
    );
  }
});

test("publishes only the authenticated Payer-Requestor-Payer prefix", () => {
  for (let length = 0; length <= 3; length += 1) {
    const source = projection();
    source.verifier = {
      advisory: true,
      publicationDigest: null,
      status: "PENDING",
    };
    source.anchors = source.anchors.map(
      (anchor, index) => ({
        ...anchor,
        block:
          index < length ? anchor.block : null,
        verified: index < length,
      }),
    );
    const snapshot = buildPublicMonitorSnapshot(
      source,
      options({
        anchorExplorerUrls:
          EXPLORER_URLS.map(
            (url, index) =>
              index < length ? url : null,
          ),
        verifierPublicationValidated: false,
      }),
    );
    assert.deepEqual(
      snapshot.anchors.map(
        ({ kind }) => kind,
      ),
      [
        "PROPOSED",
        "ACCEPTED",
        "ACKNOWLEDGED",
      ].slice(0, length),
    );
    assert.notEqual(
      snapshot.runStatus,
      "VERIFIED",
    );
  }
});

test("rejects extra, reordered, role-mismatched, unlinked, stale, private, and non-false source data", () => {
  const cases = [
    [
      {
        ...projection(),
        paymentMoved: true,
      },
      options(),
    ],
    [
      {
        ...projection(),
        anchors: [
          ...projection().anchors,
          projection().anchors[0],
        ],
      },
      options(),
    ],
    [
      {
        ...projection(),
        anchors: projection().anchors.map(
          (anchor, index) =>
            index === 1
              ? {
                  ...anchor,
                  kind: "ACKNOWLEDGED",
                }
              : anchor,
        ),
      },
      options(),
    ],
    [
      {
        ...projection(),
        anchors: projection().anchors.map(
          (anchor, index) =>
            index === 1
              ? { ...anchor, actor: "Payer" }
              : anchor,
        ),
      },
      options(),
    ],
    [
      projection(),
      options({
        anchorExplorerUrls: [
          EXPLORER_URLS[0],
          null,
          EXPLORER_URLS[2],
        ],
      }),
    ],
    [
      projection(),
      options({
        anchorExplorerUrls: [
          EXPLORER_URLS[0],
          "http://127.0.0.1/private",
          EXPLORER_URLS[2],
        ],
      }),
    ],
    [
      projection(),
      options({
        sourceObservedAtMs:
          PUBLISHED_AT_MS - 10_001,
      }),
    ],
    [
      projection(),
      options({
        verifierPublicationValidated: false,
      }),
    ],
  ];
  for (const [source, input] of cases) {
    assert.throws(
      () =>
        buildPublicMonitorSnapshot(
          source,
          input,
        ),
      /Public monitor projection failed safely/,
    );
  }
});

test("turns a previously verified snapshot visibly stale after its freshness window", () => {
  const fresh = buildPublicMonitorSnapshot(
    projection(),
    options(),
  );
  assert.equal(
    observePublicMonitorSnapshot(fresh, {
      nowMs: PUBLISHED_AT_MS + 10_000,
    }).runStatus,
    "VERIFIED",
  );
  const stale = observePublicMonitorSnapshot(
    fresh,
    {
      nowMs: PUBLISHED_AT_MS + 10_001,
    },
  );
  assert.equal(stale.runStatus, "EXPIRED");
  assert.equal(
    stale.verifier.status,
    "EXPIRED",
  );
  assert.match(stale.currentStep, /expired/i);
  assert.deepEqual(stale.anchors, fresh.anchors);
});

test("builds a safe empty waiting snapshot", () => {
  assert.deepEqual(
    buildUnavailablePublicMonitorSnapshot({
      publishedAtMs: PUBLISHED_AT_MS,
      runId: RUN_ID,
      staleAfterMs: 10_000,
    }),
    {
      anchors: [],
      currentStep:
        "Waiting for the Payer and Requestor to join the run.",
      funding: { status: "NOT_STARTED" },
      mcp: { status: "WAITING" },
      paymentMoved: false,
      payer: { status: "WAITING" },
      publishedAtMs: String(PUBLISHED_AT_MS),
      relay: { status: "WAITING" },
      requestor: { status: "WAITING" },
      runId: RUN_ID,
      runStatus: "WAITING",
      schema:
        "clockchain.bilateral-public-monitor/v2",
      staleAfterMs: 10_000,
      verifier: { status: "NOT_STARTED" },
    },
  );
});
