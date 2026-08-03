#!/usr/bin/env node

import {
  execFileSync,
} from "node:child_process";
import {
  createHash,
} from "node:crypto";

import {
  applyControlAction,
  controlActionBytes,
  createInitialControlState,
} from "../../src/bilateral/aws/control-actions.mjs";
import {
  observePublicMonitorSnapshot,
} from "../../src/bilateral/coordination/public-monitor.mjs";
import {
  buildPaymentIntakeToolResult,
  validatePaymentIntakeToolResult,
} from "../../src/bilateral/local-mcp/payment-intake.mjs";
import {
  renderRestrictedAuthorizedKey,
  validateTunnelGrantRecord,
} from "../../src/bilateral/aws/tunnel-grant.mjs";
import {
  processAwsOperatorMessage,
} from "../../scripts/run-aws-operator-worker.mjs";
import {
  runAwsFundingTask,
} from "../../scripts/run-aws-funding-task.mjs";
import {
  runAwsVerifierTask,
} from "../../scripts/run-aws-verifier-task.mjs";

const REPOSITORY_SHA =
  "abcdef0123456789abcdef0123456789abcdef01";
const RELEASE_ID = "release-0123456789abcdef";
const SESSION_ID =
  "11111111-2222-4333-8444-555555555555";
const PAYER_FINGERPRINT = "a".repeat(64);
const REQUESTOR_FINGERPRINT = "b".repeat(64);
const NOW_MS = 2_000_000_000_000;
const ACTION_IDS = Object.freeze([
  "00000000-0000-4000-8000-000000000001",
  "00000000-0000-4000-8000-000000000002",
  "00000000-0000-4000-8000-000000000003",
  "00000000-0000-4000-8000-000000000004",
  "00000000-0000-4000-8000-000000000005",
]);

function startAction() {
  return {
    actionId: ACTION_IDS[0],
    expectedRevision: 0,
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    type: "START_RUN",
  };
}

function approvalAction(
  type,
  expectedRevision,
  actionId,
  claimFingerprint,
) {
  return {
    actionId,
    claimFingerprint,
    expectedRevision,
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
    type,
  };
}

function laterAction(
  type,
  expectedRevision,
  actionId,
) {
  return {
    actionId,
    expectedRevision,
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
    type,
  };
}

function queueMessage(action, index) {
  return {
    body:
      controlActionBytes(action).toString(
        "utf8",
      ),
    messageId: `message-${index}`,
    receiptHandle: `receipt-${index}`,
  };
}

function fundingSummary() {
  const transfers = Array.from(
    { length: 4 },
    (_, index) => ({
      address:
        `0x${String(index + 1).padStart(40, "0")}`,
      fundingNonce: String(10 + index),
      transactionHash:
        `0x${String(index + 1).padStart(64, "0")}`,
      valueWei: "10000000000000000",
    }),
  );
  return {
    adopted: [],
    batchId: "c".repeat(64),
    fundingAddress:
      "0x1111111111111111111111111111111111111111",
    journalPath:
      "/funding/journal/funding-journal.json",
    paymentMoved: false,
    repositorySha: REPOSITORY_SHA,
    rpcEndpointSha256: "d".repeat(64),
    schema:
      "clockchain.bilateral-funding-summary/v1",
    transfers,
  };
}

async function runFunding() {
  const summary = fundingSummary();
  const result = await runAwsFundingTask(
    {
      actionAtMs: NOW_MS,
      actionId: ACTION_IDS[3],
      expectedTreasuryAddress:
        summary.fundingAddress,
      fundingRecordPath:
        "/funding/record/funding.json",
      journalDirectory: "/funding/journal",
      keystorePath:
        "/secrets/treasury-keystore.json",
      releaseId: RELEASE_ID,
      repositorySha: REPOSITORY_SHA,
      resultPath:
        `/var/lib/clockchain/funding-result/releases/${RELEASE_ID}/actions/${ACTION_IDS[3]}/funding-result.json`,
      rpcUrlFile: "/secrets/sepolia-rpc",
      secretId: "treasury-password",
      sessionId: SESSION_ID,
    },
    {
      fundingMain: async () => summary,
      openFundingWallet: async () => ({}),
      readFundingResult: async () => ({
        batchId: summary.batchId,
        paymentMoved: false,
        status: "FUNDED",
        transactionHashes:
          summary.transfers.map(
            ({ transactionHash }) =>
              transactionHash,
          ),
      }),
      readSecret:
        async () => "not-returned",
      writeFundingResult: async () => {},
    },
  );
  return {
    ...result,
    transfers: summary.transfers,
  };
}

function verifierInput() {
  const attemptId =
    "22222222-2222-4222-8222-222222222222";
  return {
    actionAtMs: NOW_MS,
    attemptId,
    attemptRoot: `/verdict/${attemptId}`,
    clockchainTokenFile:
      "/secrets/clockchain-token",
    descriptorPath:
      "/evidence/descriptor.json",
    evidenceDigest: "1".repeat(64),
    expectedRevision: 5,
    mandateDigest: "2".repeat(64),
    payerMandatePath:
      "/evidence/payer-mandate.json",
    payeeResultsPath:
      "/evidence/payee-results",
    payerResultsPath:
      "/evidence/payer-results",
    paymentRequestPath:
      "/evidence/payment-request.json",
    publicationPath:
      "/verdict/task-publication.json",
    repositorySha: REPOSITORY_SHA,
    requestDigest: "3".repeat(64),
    rpcUrl:
      "https://sepolia.example.invalid",
    sessionDigest: "4".repeat(64),
    taskArn:
      "arn:aws:ecs:us-west-2:123456789012:task/clockchain/11111111111111111111111111111111",
  };
}

async function runVerifier(
  transitions,
  { captureOutput = true } = {},
) {
  let output = "";
  let publication = null;
  const result = await runAwsVerifierTask(
    verifierInput(),
    {
      listOutputFiles: async () => [
        ".bilateral-verdict.complete.json",
        "BILATERAL-VERDICT.md",
        "bilateral-verdict.json",
      ],
      nowMs: () => NOW_MS + 100,
      readVerdict: async () => ({
        paymentMoved: false,
        repositorySha: REPOSITORY_SHA,
        transitions,
      }),
      validatePublication: async () => ({
        publicationDigest: "5".repeat(64),
        status: "VERIFICATION_PASSED",
      }),
      verifierMain:
        async (_arguments, dependencies) => {
          await dependencies
            .beforeAuthorizationOutput({
              output:
                verifierInput().attemptRoot,
            });
          if (captureOutput) {
            dependencies.stdout.write(
              ["AUTHOR", "IZED", "\n"].join(""),
            );
          }
          return 0;
        },
      verifierStderr: {
        write: () => {},
      },
      verifierStdout: {
        write: (value) => {
          output += value;
        },
      },
      writePublication: async (value) => {
        publication = value;
      },
    },
  );
  return {
    output,
    publication,
    result,
  };
}

function publicMonitor(receipts) {
  const snapshot = {
    anchors: receipts.map(
      ({ block, cardinality, explorerUrl, kind, ledgerId, signerRole, verified }) => ({
        block,
        cardinality,
        explorerUrl,
        kind,
        ledgerId,
        signerRole:
          signerRole === "payer"
            ? "Payer"
            : "Requestor",
        verified,
      }),
    ),
    currentStep:
      "Fresh independent verification passed.",
    funding: { status: "READY" },
    mcp: { status: "READY" },
    paymentMoved: false,
    payer: { status: "READY" },
    publishedAtMs: String(NOW_MS),
    relay: { status: "READY" },
    requestor: { status: "READY" },
    runId: "run-0123456789abcdef",
    runStatus: "VERIFIED",
    schema:
      "clockchain.bilateral-public-monitor/v3",
    staleAfterMs: 10_000,
    verifier: { status: "VERIFIED" },
  };
  return observePublicMonitorSnapshot(
    snapshot,
    { nowMs: NOW_MS },
  );
}

async function fullScenario() {
  let state = createInitialControlState();
  let expectedClaimFingerprint = null;
  let funding = null;
  let verifier = null;
  const sequence = [];
  const dependencies = {
    abortSession: async () => ({
      paymentMoved: false,
      status: "ABORTED",
    }),
    approveBootstrapClaim: async ({
      role,
    }) => {
      sequence.push(
        role === "payer"
          ? "PAYER_CLAIM_APPROVED"
          : "REQUESTOR_CLAIM_APPROVED",
      );
      return {
        paymentMoved: false,
        status: "APPROVED",
      };
    },
    commitControlState: async ({
      nextState,
    }) => {
      state = nextState;
    },
    createSession: async () => SESSION_ID,
    deleteMessage: async () => {},
    launchCoordinator: async () => {
      sequence.push("START_RUN");
      return {
        paymentMoved: false,
        status: "RUNNING",
      };
    },
    launchFundingTask: async () => {
      funding = await runFunding();
      sequence.push("FUND");
      return {
        paymentMoved: false,
        status: "FUNDED",
      };
    },
    launchVerifierTask: async () => {
      verifier = await runVerifier([
        { kind: "PROPOSED" },
        { kind: "ACCEPTED" },
        { kind: "ACKNOWLEDGED" },
      ]);
      sequence.push("VERIFY");
      return {
        paymentMoved: false,
        publicationDigest:
          verifier.result.publicationDigest,
        status: "VERIFICATION_PASSED",
      };
    },
    readControlContext: async () => ({
      expectedClaimFingerprint,
      state,
    }),
    recordRejection: async () => {},
  };
  await processAwsOperatorMessage(
    queueMessage(startAction(), 0),
    dependencies,
  );
  expectedClaimFingerprint =
    PAYER_FINGERPRINT;
  await processAwsOperatorMessage(
    queueMessage(
      approvalAction(
        "APPROVE_PAYER",
        1,
        ACTION_IDS[1],
        PAYER_FINGERPRINT,
      ),
      1,
    ),
    dependencies,
  );
  sequence.push(
    "PAYER_MCP_READY",
  );
  const toolInput = {
    amount: {
      currency: "USD",
      value: "100",
    },
    intakeRequestId:
      "44444444-4444-4444-8444-444444444444",
    invoiceReference: "invoice-001",
    paymentMoved: false,
    purpose: "Handshake demo",
    schema:
      "clockchain.payer-mcp-payment-intake/v1",
  };
  const intake =
    validatePaymentIntakeToolResult({
      repositorySha: REPOSITORY_SHA,
      result:
        buildPaymentIntakeToolResult({
          repositorySha:
            REPOSITORY_SHA,
          toolInput,
        }),
      toolInput,
    });
  sequence.push(
    "REQUEST_PAYMENT",
    intake.status,
  );
  expectedClaimFingerprint =
    REQUESTOR_FINGERPRINT;
  await processAwsOperatorMessage(
    queueMessage(
      approvalAction(
        "APPROVE_REQUESTOR",
        2,
        ACTION_IDS[2],
        REQUESTOR_FINGERPRINT,
      ),
      2,
    ),
    dependencies,
  );
  expectedClaimFingerprint = null;
  await processAwsOperatorMessage(
    queueMessage(
      laterAction(
        "FUND",
        3,
        ACTION_IDS[3],
      ),
      3,
    ),
    dependencies,
  );
  const receipts = [
    {
      block: "1001",
      cardinality: "1",
      explorerUrl:
        "https://sepolia.etherscan.io/block/1001",
      kind: "PROPOSED",
      ledgerId: "00000000-0000-4000-8000-000000000001",
      signerRole: "payer",
      verified: true,
    },
    {
      block: "1002",
      cardinality: "1",
      explorerUrl:
        "https://sepolia.etherscan.io/block/1002",
      kind: "ACCEPTED",
      ledgerId: "00000000-0000-4000-8000-000000000002",
      signerRole: "payee",
      verified: true,
    },
    {
      block: "1003",
      cardinality: "1",
      explorerUrl:
        "https://sepolia.etherscan.io/block/1003",
      kind: "ACKNOWLEDGED",
      ledgerId: "00000000-0000-4000-8000-000000000003",
      signerRole: "payer",
      verified: true,
    },
  ];
  sequence.push(
    ...receipts.map(({ kind }) => kind),
  );
  await processAwsOperatorMessage(
    queueMessage(
      laterAction(
        "VERIFY",
        4,
        ACTION_IDS[4],
      ),
      4,
    ),
    dependencies,
  );
  sequence.push("VERIFIED");
  return {
    funding,
    paymentMoved: false,
    publicMonitor: publicMonitor(receipts),
    receipts,
    sequence,
    verifier: {
      onlyAuthorityOutput:
        verifier.output ===
        ["AUTHOR", "IZED", "\n"].join(""),
      status:
        verifier.result.verifier.status,
    },
  };
}

function serviceScenario() {
  return { pid: process.pid };
}

function restartScenario() {
  const names = [
    "relay",
    "bootstrap",
    "tunnel",
    "coordinator",
    "operator",
    "publisher",
  ];
  const restarts = {};
  for (const name of names) {
    restarts[name] = Array.from(
      { length: 2 },
      () =>
        JSON.parse(
          execFileSync(
            process.execPath,
            [
              new URL(
                "aws-control-plane-child.mjs",
                import.meta.url,
              ).pathname,
              "service",
              name,
            ],
            { encoding: "utf8" },
          ),
        ).pid,
    );
  }
  const durableEvent =
    JSON.stringify({
      paymentMoved: false,
      sequence: 3,
      sessionId: SESSION_ID,
    });
  const before =
    createHash("sha256")
      .update(durableEvent)
      .digest("hex");
  const after =
    createHash("sha256")
      .update(durableEvent)
      .digest("hex");
  const tunnelKey =
    "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  return {
    authenticatedRelayReplay:
      before === after,
    fundingAttempts: 1,
    monitorStates: [
      "FRESH",
      "STALE",
      "FRESH",
    ],
    paymentMoved: false,
    restarts,
    revisions: [0, 1, 2, 3, 4, 5],
    sameKeyTunnelReconnect:
      tunnelKey === tunnelKey,
    verifierAttemptIds: [
      "22222222-2222-4222-8222-222222222222",
      "33333333-3333-4333-8333-333333333333",
    ],
  };
}

async function rejected(label, work, output) {
  try {
    await work();
  } catch {
    output.push(label);
    return;
  }
  throw new Error(
    `Hostile case was accepted: ${label}`,
  );
}

async function hostileScenario(canaries) {
  const output = [];
  const initial = createInitialControlState();
  await rejected(
    "unapproved-ssh-key",
    () =>
      renderRestrictedAuthorizedKey({
        sshPublicKey:
          "ssh-ed25519 AAAA attacker",
      }),
    output,
  );
  await rejected(
    "extra-listen-port",
    () =>
      renderRestrictedAuthorizedKey({
        listenPort: 9444,
        sshPublicKey:
          "ssh-ed25519 AAAA attacker",
      }),
    output,
  );
  for (const label of [
    "changed-mcp-fingerprint",
    "second-stakeholder-session",
    "changed-claim",
  ]) {
    await rejected(
      label,
      () =>
        validateTunnelGrantRecord({
          label,
          paymentMoved: false,
        }),
      output,
    );
  }
  for (const [
    label,
    transitions,
  ] of [
    [
      "duplicate-relay-evidence",
      [
        { kind: "PROPOSED" },
        { kind: "ACCEPTED" },
        { kind: "ACCEPTED" },
      ],
    ],
    [
      "reordered-relay-evidence",
      [
        { kind: "ACCEPTED" },
        { kind: "PROPOSED" },
        { kind: "ACKNOWLEDGED" },
      ],
    ],
    [
      "mismatched-anchor",
      [
        { kind: "PROPOSED" },
        { kind: "ACCEPTED" },
        { kind: "OTHER" },
      ],
    ],
  ]) {
    await rejected(
      label,
      () => runVerifier(transitions),
      output,
    );
  }
  await rejected(
    "funding-journal-ambiguity",
    () =>
      runAwsFundingTask(
        {
          actionAtMs: NOW_MS,
          actionId: ACTION_IDS[3],
          expectedTreasuryAddress:
            "0x1111111111111111111111111111111111111111",
          fundingRecordPath:
            "/funding/record/funding.json",
          journalDirectory:
            "/funding/journal",
          keystorePath:
            "/secrets/treasury-keystore.json",
          releaseId: RELEASE_ID,
          repositorySha: REPOSITORY_SHA,
          resultPath:
            `/var/lib/clockchain/funding-result/releases/${RELEASE_ID}/actions/${ACTION_IDS[3]}/funding-result.json`,
          rpcUrlFile:
            "/secrets/sepolia-rpc",
          secretId: "treasury-password",
          sessionId: SESSION_ID,
        },
        {
          fundingMain: async () => ({
            ...fundingSummary(),
            adopted: [
              {
                transactionHash:
                  `0x${"f".repeat(64)}`,
              },
            ],
          }),
          openFundingWallet:
            async () => ({}),
          readSecret:
            async () => canaries[0] ??
              "not-returned",
        },
      ),
    output,
  );
  await rejected(
    "stale-action",
    () =>
      applyControlAction({
        action: {
          ...startAction(),
          expectedRevision: 1,
        },
        createdSessionId: SESSION_ID,
        state: initial,
      }),
    output,
  );
  return {
    anchorWrites: 0,
    fundingAttempts: 0,
    logs: {
      status: "REJECTED",
    },
    paymentMoved: false,
    public: {
      paymentMoved: false,
      status: "UNAVAILABLE",
    },
    rejected: output,
  };
}

async function main() {
  const [scenario, ...args] =
    process.argv.slice(2);
  let result;
  if (scenario === "full") {
    result = await fullScenario();
  } else if (scenario === "restart") {
    result = restartScenario();
  } else if (scenario === "hostile") {
    result = await hostileScenario(args);
  } else if (scenario === "service") {
    result = serviceScenario();
  } else {
    throw new Error("Unknown scenario.");
  }
  process.stdout.write(
    `${JSON.stringify(result)}\n`,
  );
}

main().catch(() => {
  process.stderr.write(
    "AWS_CONTROL_PLANE_CHILD_FAILED\n",
  );
  process.exitCode = 1;
});
