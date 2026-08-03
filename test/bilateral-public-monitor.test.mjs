import assert from "node:assert/strict";
import { test } from "node:test";

import {
  observeImmutableRunSummary,
} from "../src/bilateral/aws/public-history.mjs";
import {
  renderVerifiedReceiptEmail,
} from "../src/bilateral/aws/receipt-email.mjs";
import {
  buildAwsWatcherPublicMonitorSnapshot,
  buildPublicMonitorSnapshot,
  buildUnavailablePublicMonitorSnapshot,
  observePublicMonitorSnapshot,
} from "../src/bilateral/coordination/public-monitor.mjs";
import { publishOnce } from "../scripts/publish-public-monitor.mjs";

const RUN_ID = "run-0123456789abcdef";
const PUBLISHED_AT_MS = 2_000_000_000_000;
const EXPLORER_URLS = Object.freeze([
  "https://sepolia.etherscan.io/block/101",
  "https://sepolia.etherscan.io/block/102",
  "https://sepolia.etherscan.io/block/103",
]);
const LEDGER_IDS = Object.freeze([
  "00000000-0000-4000-8000-000000000001",
  "00000000-0000-4000-8000-000000000002",
  "00000000-0000-4000-8000-000000000003",
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
        cardinality: "1",
        digest: "d".repeat(64),
        kind: "PROPOSED",
        ledgerId: LEDGER_IDS[0],
        sequence: 1,
        stage: "proposal",
        verified: true,
      },
      {
        actor: "Requestor",
        block: "102",
        cardinality: "1",
        digest: "e".repeat(64),
        kind: "ACCEPTED",
        ledgerId: LEDGER_IDS[1],
        sequence: 2,
        stage: "acceptance",
        verified: true,
      },
      {
        actor: "Payer",
        block: "103",
        cardinality: "1",
        digest: "f".repeat(64),
        kind: "ACKNOWLEDGED",
        ledgerId: LEDGER_IDS[2],
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

function awsWatcherProjection(overrides = {}) {
  return {
    observedAtMs: String(PUBLISHED_AT_MS - 100),
    paymentMoved: false,
    releaseId: "release-0123456789abcdef",
    repositorySha: "a".repeat(40),
    schema: "clockchain.aws-watcher-projection/v1",
    sessionId: "11111111-2222-4333-8444-555555555555",
    state: "ACCEPTED",
    subjectRun: "stakeholder",
    terminal: null,
    transitions: [
      {
        blockHeight: "101",
        cardinality: "1",
        ledgerId: LEDGER_IDS[0],
        slot: "proposal",
        verified: true,
      },
      {
        blockHeight: "102",
        cardinality: "1",
        ledgerId: LEDGER_IDS[1],
        slot: "acceptance",
        verified: true,
      },
      {
        blockHeight: null,
        cardinality: "0",
        ledgerId: null,
        slot: "acknowledgment",
        verified: false,
      },
    ],
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
        cardinality: "1",
        explorerUrl: EXPLORER_URLS[0],
        kind: "PROPOSED",
        ledgerId: LEDGER_IDS[0],
        signerRole: "Payer",
        verified: true,
      },
      {
        block: "102",
        cardinality: "1",
        explorerUrl: EXPLORER_URLS[1],
        kind: "ACCEPTED",
        ledgerId: LEDGER_IDS[1],
        signerRole: "Requestor",
        verified: true,
      },
      {
        block: "103",
        cardinality: "1",
        explorerUrl: EXPLORER_URLS[2],
        kind: "ACKNOWLEDGED",
        ledgerId: LEDGER_IDS[2],
        signerRole: "Payer",
        verified: true,
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
      "clockchain.bilateral-public-monitor/v3",
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

test("publisher timestamps a verified snapshot after the console observation", async () => {
  const source = projection();
  source.deadline.nowMs = PUBLISHED_AT_MS + 100;
  let consoleObserved = false;
  const uploads = [];

  const snapshot = await publishOnce(
    {
      bucket: "clockchain-public-monitor",
      consoleUrl: "http://127.0.0.1:8788/v1/console/session",
      intervalMs: 2_000,
      payerMcpHost: "127.0.0.1",
      payerMcpPort: 9_443,
      region: "us-west-2",
    },
    {
      fetch: async () => {
        consoleObserved = true;
        return {
          json: async () => source,
          ok: true,
        };
      },
      now: () => {
        assert.equal(consoleObserved, true);
        return PUBLISHED_AT_MS + 200;
      },
      probeTcp: async () => false,
      uploadSnapshot: async (value) => uploads.push(value),
    },
  );

  assert.equal(snapshot.runStatus, "VERIFIED");
  assert.equal(snapshot.publishedAtMs, String(PUBLISHED_AT_MS + 200));
  assert.equal(snapshot.anchors.length, 3);
  assert.equal(snapshot.verifier.status, "VERIFIED");
  assert.deepEqual(uploads, [snapshot]);
});

test("publisher preserves a verified terminal snapshot as immutable public history", async () => {
  const puts = [];
  const snapshot = await publishOnce(
    {
      bucket: "clockchain-public-monitor",
      consoleUrl: "http://127.0.0.1:8788/v1/console/session",
      intervalMs: 2_000,
      payerMcpHost: "127.0.0.1",
      payerMcpPort: 9_443,
      region: "us-west-2",
    },
    {
      fetch: async () => ({
        json: async () => projection(),
        ok: true,
      }),
      now: () => PUBLISHED_AT_MS + 500,
      probeTcp: async () => true,
      publicObjectUrl: ({ key }) =>
        `https://monitor.example/${key}`,
      readRunIndex: async () => null,
      putObject: async (entry) => {
        puts.push(entry);
        return { status: "CREATED" };
      },
    },
  );

  assert.equal(snapshot.runStatus, "VERIFIED");
  assert.deepEqual(
    puts.map(({ key }) => key),
    [
      "latest.json",
      `runs/${snapshot.runId}.json`,
      "runs/index.json",
    ],
  );
  const latest = observePublicMonitorSnapshot(
    JSON.parse(puts[0].body),
    { nowMs: PUBLISHED_AT_MS + 500 },
  );
  assert.equal(latest.runStatus, "VERIFIED");
  assert.equal(latest.paymentMoved, false);
  const summary = observeImmutableRunSummary(
    JSON.parse(puts[1].body),
  );
  assert.equal(summary.runId, snapshot.runId);
  assert.equal(summary.runStatus, "VERIFIED");
  assert.equal(summary.paymentMoved, false);
  assert.equal(summary.anchors.length, 3);
  assert.deepEqual(
    summary.anchors.map(({ explorerUrl }) => explorerUrl),
    EXPLORER_URLS,
  );
  const index = JSON.parse(puts[2].body);
  assert.equal(index.schema, "clockchain.aws-public-run-index/v2");
  assert.equal(index.paymentMoved, false);
  assert.equal(index.entries.length, 1);
  assert.equal(index.entries[0].runId, snapshot.runId);

  const receipt = renderVerifiedReceiptEmail(summary);
  assert.match(receipt.html, new RegExp(snapshot.runId));
  for (const expected of [
    "Payer",
    "Requestor",
    "PROPOSED",
    "ACCEPTED",
    "ACKNOWLEDGED",
    ...EXPLORER_URLS,
    "No represented payment moved.",
  ]) {
    assert.match(receipt.html, new RegExp(expected));
  }
});

test("publisher updates only latest for nonterminal or unverified snapshots", async () => {
  const cases = [
    {
      name: "unavailable",
      response: async () => {
        throw new Error("console down");
      },
    },
    {
      name: "nonterminal",
      response: async () => {
        const source = projection();
        source.verifier = {
          advisory: true,
          publicationDigest: null,
          status: "PENDING",
        };
        source.anchors = source.anchors.slice(0, 2);
        return source;
      },
    },
    {
      name: "unvalidated verifier",
      response: async () => {
        const source = projection();
        source.verifier = {
          advisory: true,
          publicationDigest: null,
          status: "VERIFICATION_PASSED",
        };
        return source;
      },
    },
    {
      name: "wrong cardinality",
      response: async () => {
        const source = projection();
        source.anchors[1] = {
          ...source.anchors[1],
          cardinality: "2",
        };
        return source;
      },
    },
    {
      name: "stale",
      response: async () => {
        const source = projection();
        source.deadline.nowMs =
          PUBLISHED_AT_MS - 20_000;
        return source;
      },
    },
  ];

  for (const candidate of cases) {
    const puts = [];
    await publishOnce(
      {
        bucket: "clockchain-public-monitor",
        consoleUrl: "http://127.0.0.1:8788/v1/console/session",
        intervalMs: 2_000,
        payerMcpHost: "127.0.0.1",
        payerMcpPort: 9_443,
        region: "us-west-2",
      },
      {
        fetch: async () => ({
          json: candidate.response,
          ok: true,
        }),
        now: () => PUBLISHED_AT_MS + 500,
        probeTcp: async () => true,
        publicObjectUrl: ({ key }) =>
          `https://monitor.example/${key}`,
        readRunIndex: async () => null,
        putObject: async (entry) => {
          puts.push(entry);
          return { status: "CREATED" };
        },
      },
    );
    assert.deepEqual(
      puts.map(({ key }) => key),
      ["latest.json"],
      candidate.name,
    );
  }
});

test("publisher fails visibly when verified immutable history cannot be preserved", async () => {
  const writes = [];
  await assert.rejects(
    publishOnce(
      {
        bucket: "clockchain-public-monitor",
        consoleUrl: "http://127.0.0.1:8788/v1/console/session",
        intervalMs: 2_000,
        payerMcpHost: "127.0.0.1",
        payerMcpPort: 9_443,
        region: "us-west-2",
      },
      {
        fetch: async () => ({ json: async () => projection(), ok: true }),
        now: () => PUBLISHED_AT_MS + 500,
        probeTcp: async () => true,
        publicObjectUrl: ({ key }) => `https://monitor.example/${key}`,
        readObject: async () => '{"different":"immutable receipt"}\n',
        readRunIndex: async () => null,
        putObject: async (entry) => {
          writes.push(entry.key);
          if (entry.key.startsWith("runs/run-")) {
            const error = new Error("summary already exists");
            error.code = "OBJECT_EXISTS";
            throw error;
          }
          return { status: "CREATED" };
        },
      },
    ),
  );
  assert.equal(writes[0], "latest.json");
  assert.match(writes[1], /^runs\/run-[0-9a-f]{16}\.json$/);
  assert.equal(writes.length, 2);
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
        cardinality:
          index < length ? "1" : "0",
        ledgerId:
          index < length ? anchor.ledgerId : null,
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
      {
        ...projection(),
        anchors: projection().anchors.map(
          (anchor, index) => {
            if (index !== 0) return anchor;
            const { ledgerId: _ledgerId, ...withoutLedgerId } = anchor;
            return withoutLedgerId;
          },
        ),
      },
      options(),
    ],
    [
      {
        ...projection(),
        anchors: projection().anchors.map(
          (anchor, index) => index === 0 ? { ...anchor, cardinality: "2" } : anchor,
        ),
      },
      options(),
    ],
    [
      {
        ...projection(),
        anchors: projection().anchors.map(
          (anchor, index) => index === 0 ? { ...anchor, verified: false } : anchor,
        ),
      },
      options(),
    ],
    [
      {
        ...projection(),
        anchors: projection().anchors.map(
          (anchor, index) => index === 1 ? { ...anchor, ledgerId: LEDGER_IDS[0] } : anchor,
        ),
      },
      options(),
    ],
    [
      {
        ...projection(),
        anchors: projection().anchors.map(
          (anchor, index) => index === 0 ? { ...anchor, extra: "not-public" } : anchor,
        ),
      },
      options(),
    ],
    [
      {
        ...projection(),
        anchors: [
          projection().anchors[1],
          projection().anchors[0],
          projection().anchors[2],
        ],
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

test("maps exact aws watcher projection into a running public monitor without private evidence", () => {
  const snapshot = buildAwsWatcherPublicMonitorSnapshot(
    awsWatcherProjection(),
    {
      nowMs: PUBLISHED_AT_MS,
      publishedAtMs: PUBLISHED_AT_MS,
      releaseId: "release-0123456789abcdef",
      repositorySha: "a".repeat(40),
      runId: "run-0123456789abcdef",
      sessionId: "11111111-2222-4333-8444-555555555555",
      staleAfterMs: 60_000,
      subjectRun: "stakeholder",
    },
  );

  assert.deepEqual(snapshot, {
    anchors: [
      {
        block: "101",
        cardinality: "1",
        explorerUrl: "https://sepolia.etherscan.io/block/101",
        kind: "PROPOSED",
        ledgerId: LEDGER_IDS[0],
        signerRole: "Payer",
        verified: true,
      },
      {
        block: "102",
        cardinality: "1",
        explorerUrl: "https://sepolia.etherscan.io/block/102",
        kind: "ACCEPTED",
        ledgerId: LEDGER_IDS[1],
        signerRole: "Requestor",
        verified: true,
      },
    ],
    currentStep:
      "The Payer is reviewing the Requestor acceptance before acknowledgment.",
    funding: { status: "READY" },
    mcp: { status: "READY" },
    paymentMoved: false,
    payer: { status: "READY" },
    publishedAtMs: String(PUBLISHED_AT_MS),
    relay: { status: "READY" },
    requestor: { status: "READY" },
    runId: "run-0123456789abcdef",
    runStatus: "RUNNING",
    schema: "clockchain.bilateral-public-monitor/v3",
    staleAfterMs: 60_000,
    verifier: { status: "NOT_STARTED" },
  });

  const serialized = JSON.stringify(snapshot);
  for (const forbidden of [
    "11111111-2222-4333-8444-555555555555",
    "aaaaaaaa",
    "release-0123456789abcdef",
    "AUTHORIZED",
  ]) {
    assert.doesNotMatch(serialized, new RegExp(forbidden, "i"));
  }
});

test("keeps aws watcher three-anchor progress non-authorizing until the fresh verifier publishes", () => {
  const snapshot = buildAwsWatcherPublicMonitorSnapshot(
    awsWatcherProjection({
      state: "ACKNOWLEDGED",
      transitions: [
        {
          blockHeight: "101",
          cardinality: "1",
          ledgerId: LEDGER_IDS[0],
          slot: "proposal",
          verified: true,
        },
        {
          blockHeight: "102",
          cardinality: "1",
          ledgerId: LEDGER_IDS[1],
          slot: "acceptance",
          verified: true,
        },
        {
          blockHeight: "103",
          cardinality: "1",
          ledgerId: LEDGER_IDS[2],
          slot: "acknowledgment",
          verified: true,
        },
      ],
    }),
    {
      nowMs: PUBLISHED_AT_MS,
      publishedAtMs: PUBLISHED_AT_MS,
      releaseId: "release-0123456789abcdef",
      repositorySha: "a".repeat(40),
      runId: "run-0123456789abcdef",
      sessionId: "11111111-2222-4333-8444-555555555555",
      staleAfterMs: 60_000,
      subjectRun: "stakeholder",
    },
  );

  assert.equal(snapshot.runStatus, "RUNNING");
  assert.equal(snapshot.verifier.status, "RUNNING");
  assert.equal(snapshot.anchors.length, 3);
});

test("rejects unsafe aws watcher projections and mismatched run scope", () => {
  const cases = [
    {
      ...awsWatcherProjection(),
      paymentMoved: true,
    },
    {
      ...awsWatcherProjection(),
      subjectRun: "rehearsal",
    },
    {
      ...awsWatcherProjection(),
      terminal: "FAILED",
    },
    {
      ...awsWatcherProjection(),
      state: "ACKNOWLEDGED",
    },
    {
      ...awsWatcherProjection(),
      transitions: awsWatcherProjection().transitions.map((transition, index) =>
        index === 1
          ? { ...transition, slot: "acknowledgment" }
          : transition,
      ),
    },
    {
      ...awsWatcherProjection(),
      transitions: awsWatcherProjection().transitions.map((transition, index) =>
        index === 2
          ? {
              ...transition,
              blockHeight: "103",
              cardinality: "1",
              ledgerId: LEDGER_IDS[2],
              verified: true,
            }
          : transition,
      ),
    },
    {
      ...awsWatcherProjection(),
      transitions: awsWatcherProjection().transitions.map((transition, index) =>
        index === 1
          ? { ...transition, cardinality: "2" }
          : transition,
      ),
    },
    {
      ...awsWatcherProjection(),
      transitions: awsWatcherProjection().transitions.map((transition, index) =>
        index === 1
          ? { ...transition, blockHeight: "0" }
          : transition,
      ),
    },
    {
      ...awsWatcherProjection({
        state: "ACKNOWLEDGED",
        transitions: [
          {
            blockHeight: "101",
            cardinality: "1",
            ledgerId: LEDGER_IDS[0],
            slot: "proposal",
            verified: true,
          },
          {
            blockHeight: "101",
            cardinality: "1",
            ledgerId: LEDGER_IDS[1],
            slot: "acceptance",
            verified: true,
          },
          {
            blockHeight: "103",
            cardinality: "1",
            ledgerId: LEDGER_IDS[2],
            slot: "acknowledgment",
            verified: true,
          },
        ],
      }),
    },
    {
      ...awsWatcherProjection({
        state: "ACKNOWLEDGED",
        transitions: [
          {
            blockHeight: "101",
            cardinality: "1",
            ledgerId: LEDGER_IDS[0],
            slot: "proposal",
            verified: true,
          },
          {
            blockHeight: "102",
            cardinality: "1",
            ledgerId: LEDGER_IDS[0],
            slot: "acceptance",
            verified: true,
          },
          {
            blockHeight: "103",
            cardinality: "1",
            ledgerId: LEDGER_IDS[2],
            slot: "acknowledgment",
            verified: true,
          },
        ],
      }),
    },
    Object.fromEntries(
      Object.entries(awsWatcherProjection()).reverse(),
    ),
  ];

  for (const source of cases) {
    assert.throws(
      () =>
        buildAwsWatcherPublicMonitorSnapshot(source, {
          nowMs: PUBLISHED_AT_MS,
          publishedAtMs: PUBLISHED_AT_MS,
          releaseId: "release-0123456789abcdef",
          repositorySha: "a".repeat(40),
          runId: "run-0123456789abcdef",
          sessionId: "11111111-2222-4333-8444-555555555555",
          staleAfterMs: 60_000,
          subjectRun: "stakeholder",
        }),
      /Public monitor projection failed safely/,
    );
  }

  assert.throws(
    () =>
      buildAwsWatcherPublicMonitorSnapshot(
        awsWatcherProjection(),
        {
          nowMs: PUBLISHED_AT_MS,
          publishedAtMs: PUBLISHED_AT_MS,
          releaseId: "release-0123456789abcdef",
          repositorySha: "a".repeat(40),
          runId: "run-fedcba9876543210",
          sessionId: "11111111-2222-4333-8444-555555555555",
          staleAfterMs: 60_000,
          subjectRun: "stakeholder",
        },
      ),
    /Public monitor projection failed safely/,
  );
});

test("binds aws watcher mapping to exact expected release, repository, session, and subject", () => {
  const source = awsWatcherProjection();
  for (const override of [
    { releaseId: "release-fedcba9876543210" },
    { repositorySha: "b".repeat(40) },
    { sessionId: "22222222-3333-4444-8555-666666666666" },
    { subjectRun: "rehearsal" },
  ]) {
    assert.throws(
      () =>
        buildAwsWatcherPublicMonitorSnapshot(source, {
          nowMs: PUBLISHED_AT_MS,
          publishedAtMs: PUBLISHED_AT_MS,
          releaseId: "release-0123456789abcdef",
          repositorySha: "a".repeat(40),
          runId: "run-0123456789abcdef",
          sessionId: "11111111-2222-4333-8444-555555555555",
          staleAfterMs: 60_000,
          subjectRun: "stakeholder",
          ...override,
        }),
      /Public monitor projection failed safely/,
    );
  }
  assert.throws(
    () =>
      buildAwsWatcherPublicMonitorSnapshot(source, {
        subjectRun: "stakeholder",
        staleAfterMs: 60_000,
        sessionId: "11111111-2222-4333-8444-555555555555",
        runId: "run-0123456789abcdef",
        repositorySha: "a".repeat(40),
        releaseId: "release-0123456789abcdef",
        publishedAtMs: PUBLISHED_AT_MS,
        nowMs: PUBLISHED_AT_MS,
      }),
    /Public monitor projection failed safely/,
  );
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
        "clockchain.bilateral-public-monitor/v3",
      staleAfterMs: 10_000,
      verifier: { status: "NOT_STARTED" },
    },
  );
});
