import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import {
  publishAwsPublicMonitor,
} from "../scripts/publish-aws-public-monitor.mjs";

const RUN_ID = "run-0123456789abcdef";
const REPOSITORY_SHA =
  "abcdef0123456789abcdef0123456789abcdef01";
const SESSION_ID =
  "11111111-2222-4333-8444-555555555555";
const CERTIFICATE_FINGERPRINT =
  "a".repeat(64);

function snapshot(overrides = {}) {
  return {
    anchors: [],
    currentStep:
      "Waiting for the Payer and Requestor to join the run.",
    funding: { status: "NOT_STARTED" },
    mcp: { status: "WAITING" },
    paymentMoved: false,
    payer: { status: "WAITING" },
    publishedAtMs: "2000000000000",
    relay: { status: "READY" },
    requestor: { status: "WAITING" },
    runId: RUN_ID,
    runStatus: "WAITING",
    schema:
      "clockchain.bilateral-public-monitor/v3",
    staleAfterMs: 10_000,
    verifier: { status: "NOT_STARTED" },
    ...overrides,
  };
}

function fixture({
  gate = {
    payerClaimApproved: true,
    payerDiscoveryReady: true,
    payerMcpReady: true,
    requestorDiscoveryReady: true,
    runStarted: true,
    tunnelTlsHealthy: true,
  },
} = {}) {
  const calls = [];
  const staged = {
    certificate: {
      body:
        "-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----\n",
      contentType: "application/x-pem-file",
    },
    payerDiscovery: {
      body: "{\"paymentMoved\":false,\"schema\":\"clockchain.payer-bootstrap-discovery/v1\"}\n",
      contentType: "application/json",
    },
    requestorDiscovery: {
      body: "{\"paymentMoved\":false,\"runMode\":\"aws-stakeholder-only\",\"schema\":\"clockchain.requestor-discovery/v3\"}\n",
      contentType: "application/json",
    },
  };
  return {
    calls,
    dependencies: {
      putObject: async (input) => {
        calls.push(["put", input]);
        return {
          etag:
            `"${input.key.replaceAll("/", "-")}"`,
        };
      },
      readIndex: async () => null,
      readPublicationGate: async () => gate,
      readStagedPublicObject: async (name) =>
        staged[name],
      validateStagedCertificate: async ({
        body,
        certificateFingerprint,
      }) => {
        assert.equal(
          certificateFingerprint,
          CERTIFICATE_FINGERPRINT,
        );
        assert.match(body, /CERTIFICATE/);
      },
      validateStagedPayerDiscovery:
        async ({ body }) => {
          assert.match(
            body,
            /payer-bootstrap-discovery/,
          );
        },
      validateStagedRequestorDiscovery:
        async ({ body }) => {
          assert.match(
            body,
            /requestor-discovery\/v3/,
          );
        },
      writePublicationRecord:
        async (record) => {
          calls.push(["record", record]);
        },
    },
  };
}

function input(overrides = {}) {
  return {
    certificateFingerprint:
      CERTIFICATE_FINGERPRINT,
    completedAtMs: null,
    imageDigest: `123456789012.dkr.ecr.us-west-2.amazonaws.com/clockchain@sha256:${"b".repeat(64)}`,
    releaseId: "release-0123456789abcdef",
    repositorySha: REPOSITORY_SHA,
    secretCanaries: ["private-canary"],
    sessionId: SESSION_ID,
    snapshot: snapshot(),
    verifierPublicationValidated: false,
    ...overrides,
  };
}

function requestorDiscoveryBody({ runMode }) {
  return `${JSON.stringify({
    schema: "clockchain.requestor-discovery/v3",
    paymentMoved: false,
    imageDigest: input().imageDigest,
    releaseId: input().releaseId,
    sessionId: input().sessionId,
    repositorySha: input().repositorySha,
    publicUrl: "https://32.186.198.119:9443/mcp",
    certificateUrl: "https://public.example.test/payer-mcp.crt",
    certificateFingerprint: CERTIFICATE_FINGERPRINT,
    operatorKeyId: "operator",
    runMode,
    expiresAtMs: "2000000600000",
    signature: {
      algorithm: "ed25519",
      keyId: "operator",
      value: Buffer.alloc(64).toString("base64"),
    },
  })}\n`;
}

test("publishes latest plus staged Payer and gated Requestor artifacts without signer, port probe, or raw evidence access", async () => {
  const source = await readFile(
    new URL(
      "../scripts/publish-aws-public-monitor.mjs",
      import.meta.url,
    ),
    "utf8",
  );
  for (const forbidden of [
    "createPrivateKey",
    "createConnection",
    "privateKey",
    "localhost",
    "rawEvidence",
    "sign(",
  ]) {
    assert.equal(
      source.includes(forbidden),
      false,
    );
  }
  const fx = fixture();
  const result = await publishAwsPublicMonitor(
    input(),
    fx.dependencies,
  );
  assert.equal(result.paymentMoved, false);
  assert.deepEqual(
    fx.calls
      .filter(([name]) => name === "put")
      .map(([, value]) => value.key),
    [
      "latest.json",
      "discoveries/payer.json",
      "certificates/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.crt",
      "discoveries/requestor.json",
    ],
  );
  assert.equal(
    fx.calls.some(([name]) => name === "record"),
    true,
  );
  assert.equal(
    JSON.stringify(fx.calls).includes(
      "private-canary",
    ),
    false,
  );
});

test("default Requestor discovery validator rejects v3 non-AWS run mode", async () => {
  const fx = fixture();
  delete fx.dependencies.validateStagedRequestorDiscovery;
  const originalRead = fx.dependencies.readStagedPublicObject;
  fx.dependencies.readStagedPublicObject = async (name) => {
    if (name === "requestorDiscovery") {
      return {
        body: requestorDiscoveryBody({ runMode: "local-two-run" }),
        contentType: "application/json",
      };
    }
    return originalRead(name);
  };

  await assert.rejects(
    publishAwsPublicMonitor(
      input(),
      fx.dependencies,
    ),
    /AWS public monitor publication failed safely/,
  );
});

test("publishes an initial live snapshot and Payer discovery before a Payer certificate exists", async () => {
  const fx = fixture({
    gate: {
      payerClaimApproved: false,
      payerDiscoveryReady: true,
      payerMcpReady: false,
      requestorDiscoveryReady: false,
      runStarted: true,
      tunnelTlsHealthy: false,
    },
  });
  await publishAwsPublicMonitor(
    input({ certificateFingerprint: null }),
    fx.dependencies,
  );
  assert.deepEqual(
    fx.calls
      .filter(([name]) => name === "put")
      .map(([, value]) => value.key),
    ["latest.json", "discoveries/payer.json"],
  );
});

test("withholds Requestor discovery and certificate until every Payer readiness gate is true", async () => {
  for (const field of [
    "payerClaimApproved",
    "payerMcpReady",
    "requestorDiscoveryReady",
    "tunnelTlsHealthy",
  ]) {
    const gate = {
      payerClaimApproved: true,
      payerDiscoveryReady: true,
      payerMcpReady: true,
      requestorDiscoveryReady: true,
      runStarted: true,
      tunnelTlsHealthy: true,
      [field]: false,
    };
    const fx = fixture({ gate });
    await publishAwsPublicMonitor(
      input(),
      fx.dependencies,
    );
    const keys = fx.calls
      .filter(([name]) => name === "put")
      .map(([, value]) => value.key);
    assert.deepEqual(keys, [
      "latest.json",
      "discoveries/payer.json",
    ]);
  }
});

test("uses an immutable summary and conditional newest-first index only for a validated terminal run", async () => {
  const verified = snapshot({
    anchors: [
      {
        block: "101",
        cardinality: "1",
        explorerUrl:
          "https://sepolia.etherscan.io/block/101",
        kind: "PROPOSED",
        ledgerId: "00000000-0000-4000-8000-000000000001",
        signerRole: "Payer",
        verified: true,
      },
      {
        block: "102",
        cardinality: "1",
        explorerUrl:
          "https://sepolia.etherscan.io/block/102",
        kind: "ACCEPTED",
        ledgerId: "00000000-0000-4000-8000-000000000002",
        signerRole: "Requestor",
        verified: true,
      },
      {
        block: "103",
        cardinality: "1",
        explorerUrl:
          "https://sepolia.etherscan.io/block/103",
        kind: "ACKNOWLEDGED",
        ledgerId: "00000000-0000-4000-8000-000000000003",
        signerRole: "Payer",
        verified: true,
      },
    ],
    currentStep:
      "Fresh independent verification confirmed all three Clockchain anchors.",
    funding: { status: "READY" },
    mcp: { status: "READY" },
    payer: { status: "READY" },
    requestor: { status: "READY" },
    runStatus: "VERIFIED",
    verifier: { status: "VERIFIED" },
  });
  const fx = fixture();
  await publishAwsPublicMonitor(
    input({
      completedAtMs: 2_000_000_000_500,
      snapshot: verified,
      verifierPublicationValidated: true,
    }),
    fx.dependencies,
  );
  const puts = fx.calls
    .filter(([name]) => name === "put")
    .map(([, value]) => value);
  const summary = puts.find(
    ({ key }) =>
      key === `runs/${RUN_ID}.json`,
  );
  const index = puts.find(
    ({ key }) => key === "runs/index.json",
  );
  assert.equal(summary.ifNoneMatch, "*");
  assert.equal(index.ifNoneMatch, "*");
  assert.equal(
    JSON.parse(summary.body).runStatus,
    "VERIFIED",
  );
  assert.equal(
    JSON.parse(index.body).entries[0].runId,
    RUN_ID,
  );
});

test("migrates a valid legacy v1 run index during terminal publication", async () => {
  const legacyRunId = "run-1111111111111111";
  const legacyIndex = {
    entries: [
      {
        anchors: [],
        businessResult:
          "The run stopped safely because the available evidence did not satisfy every required check.",
        completedAtMs: "1999999999000",
        runId: legacyRunId,
        runStatus: "FAILED",
        summaryUrl:
          `https://clockchain-research.vercel.app/handshake/runs/${legacyRunId}.json`,
      },
    ],
    paymentMoved: false,
    schema: "clockchain.aws-public-run-index/v1",
    updatedAtMs: "1999999999000",
  };
  const verified = snapshot({
    anchors: [
      {
        block: "101",
        cardinality: "1",
        explorerUrl:
          "https://sepolia.etherscan.io/block/101",
        kind: "PROPOSED",
        ledgerId: "00000000-0000-4000-8000-000000000001",
        signerRole: "Payer",
        verified: true,
      },
      {
        block: "102",
        cardinality: "1",
        explorerUrl:
          "https://sepolia.etherscan.io/block/102",
        kind: "ACCEPTED",
        ledgerId: "00000000-0000-4000-8000-000000000002",
        signerRole: "Requestor",
        verified: true,
      },
      {
        block: "103",
        cardinality: "1",
        explorerUrl:
          "https://sepolia.etherscan.io/block/103",
        kind: "ACKNOWLEDGED",
        ledgerId: "00000000-0000-4000-8000-000000000003",
        signerRole: "Payer",
        verified: true,
      },
    ],
    currentStep:
      "Fresh independent verification confirmed all three Clockchain anchors.",
    funding: { status: "READY" },
    mcp: { status: "READY" },
    payer: { status: "READY" },
    requestor: { status: "READY" },
    runStatus: "VERIFIED",
    verifier: { status: "VERIFIED" },
  });
  const fx = fixture();
  fx.dependencies.readIndex = async () => ({
    body: `${JSON.stringify(legacyIndex)}\n`,
    etag: "\"legacy-index\"",
  });
  await publishAwsPublicMonitor(
    input({
      completedAtMs: 2_000_000_000_500,
      snapshot: verified,
      verifierPublicationValidated: true,
    }),
    fx.dependencies,
  );

  const indexPut = fx.calls
    .filter(([name]) => name === "put")
    .map(([, value]) => value)
    .find(({ key }) => key === "runs/index.json");
  const migrated = JSON.parse(indexPut.body);
  assert.equal(
    migrated.schema,
    "clockchain.aws-public-run-index/v2",
  );
  assert.equal(indexPut.ifMatch, "\"legacy-index\"");
  assert.deepEqual(
    migrated.entries.map(({ runId }) => runId),
    [RUN_ID, legacyRunId],
  );
});

test("rejects a changed immutable summary, any secret canary, and unvalidated green output", async () => {
  for (const overrides of [
    {
      snapshot: snapshot({
        currentStep: "private-canary",
      }),
    },
    {
      completedAtMs: 2_000_000_000_500,
      snapshot: snapshot({
        runStatus: "VERIFIED",
        verifier: { status: "VERIFIED" },
      }),
      verifierPublicationValidated: false,
    },
  ]) {
    await assert.rejects(
      publishAwsPublicMonitor(
        input(overrides),
        fixture().dependencies,
      ),
      /AWS public monitor publication failed safely/,
    );
  }

  const fx = fixture();
  fx.dependencies.putObject =
    async (value) => {
      if (
        value.key === `runs/${RUN_ID}.json`
      ) {
        throw Object.assign(
          new Error("precondition failed"),
          { code: "PreconditionFailed" },
        );
      }
      return { etag: "\"ok\"" };
    };
  await assert.rejects(
    publishAwsPublicMonitor(
      input({
        completedAtMs: 2_000_000_000_500,
        snapshot: snapshot({
          anchors: [
            {
              block: "101",
              cardinality: "1",
              explorerUrl:
                "https://sepolia.etherscan.io/block/101",
              kind: "PROPOSED",
              ledgerId: "00000000-0000-4000-8000-000000000001",
              signerRole: "Payer",
              verified: true,
            },
            {
              block: "102",
              cardinality: "1",
              explorerUrl:
                "https://sepolia.etherscan.io/block/102",
              kind: "ACCEPTED",
              ledgerId: "00000000-0000-4000-8000-000000000002",
              signerRole: "Requestor",
              verified: true,
            },
            {
              block: "103",
              cardinality: "1",
              explorerUrl:
                "https://sepolia.etherscan.io/block/103",
              kind: "ACKNOWLEDGED",
              ledgerId: "00000000-0000-4000-8000-000000000003",
              signerRole: "Payer",
              verified: true,
            },
          ],
          runStatus: "VERIFIED",
          verifier: { status: "VERIFIED" },
        }),
        verifierPublicationValidated: true,
      }),
      fx.dependencies,
    ),
    /AWS public monitor publication failed safely/,
  );
});
