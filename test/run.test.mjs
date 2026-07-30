import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { writeFileSync } from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import {
  FAILURE_EXIT_CODES,
  FAILURE_HINTS,
  main,
} from "../bin/handshake-demo.mjs";
import {
  RESULT_SCHEMA,
  SINGLE_VALIDATOR_DISCLAIMER,
} from "../src/constants.mjs";
import {
  beginEvidenceAttempt,
  computeReceiptEventHash,
  writeEvidence,
} from "../src/evidence.mjs";
import {
  McpConfigurationError,
  McpNetworkError,
  McpVerificationError,
  assertCrossPartyVerification,
  completeReceipt,
} from "../src/mcp.mjs";
import { createRegistrationIntent } from "../src/registration-internal.mjs";
import {
  PartialRegistrationError,
  RegistrationNetworkError,
  buildRegistrationDocument,
  registrationDataUri,
} from "../src/registration.mjs";
import {
  HANDSHAKE_FAILURE_CATEGORIES,
  HANDSHAKE_FAILURE_CODES,
  HandshakeStageError,
  runHandshake,
} from "../src/run.mjs";

const RUN_ID = "123e4567-e89b-42d3-a456-426614174000";
const PRIOR_RUN_ID =
  "323e4567-e89b-42d3-a456-426614174002";
const LEDGER_ID = "223e4567-e89b-42d3-a456-426614174001";
const REGISTRY =
  "0x8004A818BFB912233c491871b3d84c89A494BD9e";
const ADDRESS = "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A";
const PRIVATE_KEY = `0x${"11".repeat(32)}`;
const REGISTER_TX = `0x${"22".repeat(32)}`;
const METADATA_TX = `0x${"33".repeat(32)}`;
const EVENT_HASH = computeReceiptEventHash({
  agentId: "42",
  action: "trust_handshake",
  inputs: receiptInputs(),
  outputs: receiptOutputs(),
});
const WRONG_EVENT_HASH = "44".repeat(32);
const INVITATION_CODE = "fresh-invitation-code-canary";
const MCP_TOKEN = `cc_${"t".repeat(48)}`;
const DISPLAY_NAME = "Billy";
const RECOVERY_FILE = ".handshake-registration-recovery.json";
const RECOVERY_SCHEMA =
  "clockchain.handshake-registration-recovery/v1";
const INTENT_SCHEMA =
  "clockchain.handshake-registration-intent/v1";
const REGISTER_CALLDATA = `0x${"ab".repeat(36)}`;
const ATTESTATION_MARKER_FILE =
  ".handshake-attestation-started.json";
const ATTESTATION_MARKER_SCHEMA =
  "clockchain.handshake-attestation-started/v1";
const REPOSITORY_ROOT = fileURLToPath(
  new URL("../", import.meta.url),
);
const execFileAsync = promisify(execFile);

function registrationRecovery({ metadata = true } = {}) {
  return {
    schema: "clockchain.handshake-registration-recovery/v1",
    chainId: 11155111,
    registryAddress: REGISTRY,
    registryNamespace: `eip155:11155111:${REGISTRY}`,
    identityReference: `eip155:11155111:${REGISTRY}:42`,
    agentId: "42",
    address: ADDRESS,
    displayName: DISPLAY_NAME,
    registerTx: REGISTER_TX,
    registerBlock: "100",
    ...(metadata
      ? {
          metadataTx: METADATA_TX,
          metadataNonce: 1,
        }
      : {}),
  };
}

function registrationIntent({
  transactionFields = {
    maxFeePerGas: 2n,
    maxPriorityFeePerGas: 1n,
  },
  ...overrides
} = {}) {
  return {
    ...createRegistrationIntent({
      address: ADDRESS,
      displayName: DISPLAY_NAME,
      registerCalldata: REGISTER_CALLDATA,
      registerGas: 226_000n,
      transactionFields,
    }),
    ...overrides,
  };
}

function withoutIntentKey(key) {
  const intent = registrationIntent();
  delete intent[key];
  return intent;
}

async function readCheckpointFile(directory) {
  return JSON.parse(
    await readFile(join(directory, RECOVERY_FILE), "utf8"),
  );
}

async function writeCheckpointFile(directory, checkpoint) {
  await writeFile(
    join(directory, RECOVERY_FILE),
    `${JSON.stringify(checkpoint, null, 2)}\n`,
    { encoding: "utf8", mode: 0o644 },
  );
}

function declaredConstant(source, name) {
  const matches = [
    ...source.matchAll(
      new RegExp(`^const ${name} = ([0-9_]+);$`, "gm"),
    ),
  ];
  assert.equal(
    matches.length,
    1,
    `src/mcp.mjs must declare ${name} exactly once`,
  );
  return Number(matches[0][1].replaceAll("_", ""));
}

function documentedMilliseconds(section, pattern) {
  const match = section.match(pattern);
  assert.ok(
    match,
    `DEMO.md must state a figure matching ${pattern}`,
  );
  return Math.round(Number(match[1]) * 1_000);
}

function completedRegistration() {
  return {
    chainId: 11155111,
    registryAddress: REGISTRY,
    registryNamespace: `eip155:11155111:${REGISTRY}`,
    identityReference: `eip155:11155111:${REGISTRY}:42`,
    agentId: "42",
    address: ADDRESS,
    displayName: DISPLAY_NAME,
    registerTx: REGISTER_TX,
    registerBlock: "100",
    metadataTx: METADATA_TX,
    metadataBlock: "101",
    document: buildRegistrationDocument({
      displayName: DISPLAY_NAME,
      agentId: 42n,
    }),
  };
}

function receiptInputs() {
  return {
    runId: RUN_ID,
    identityReference:
      `eip155:11155111:${REGISTRY}:42`,
    counterparty: "clockchain:handshake",
    authorization: {
      amount: "100",
      currency: "USD",
      settlement: "not-executed",
    },
  };
}

function receiptOutputs() {
  return {
    decision: "approved-for-demo",
    scope: "identity-and-time-receipt-only",
    paymentMoved: false,
  };
}

function submittedReceipt(eventHash = EVENT_HASH) {
  return {
    schema: "clockchain.receipt/v1",
    network: "testnet",
    status: "degraded",
    agentId: "42",
    action: "trust_handshake",
    eventHash,
    hashType: "SHA-256",
    payload: {
      inputs: receiptInputs(),
      outputs: receiptOutputs(),
    },
    poolHealth: {
      totalNodes: 1,
      nodeParticipationPct: 0,
      degraded: true,
    },
    anchor: {
      ledgerId: LEDGER_ID,
      assetReferenceId: "agent:42:trust_handshake:1",
      blockHeight: null,
      recordedAt: "2026-07-23T07:00:00.000Z",
      consensusTime: null,
      confirmed: false,
    },
    attestation: {
      validators: 1,
      trustPct: null,
      status: "single-validator-testnet",
      note: "Test fixture.",
    },
    identity: {
      resolved: true,
      status: "active",
      note: "Resolved via ERC-8004.",
    },
    verify: {
      how: "Recompute the canonical SHA-256 event hash.",
    },
    disclaimer: "Testnet receipt fixture.",
  };
}

function anchoredReceipt(eventHash = EVENT_HASH) {
  return {
    ...submittedReceipt(eventHash),
    status: "anchored",
    poolHealth: {
      totalNodes: 1,
      nodeParticipationPct: 100,
      degraded: false,
    },
    anchor: {
      ...submittedReceipt(eventHash).anchor,
      blockHeight: "321",
      consensusTime: "23-07-2026_07:00:01:234",
      confirmed: true,
    },
  };
}

function expectedPassResult() {
  return {
    schema: RESULT_SCHEMA,
    status: "PASS",
    runId: RUN_ID,
    startedAt: "2026-07-23T07:00:00.000Z",
    completedAt: "2026-07-23T07:00:01.234Z",
    elapsedMs: 1_234,
    scenario: {
      action: "trust_handshake",
      amount: {
        value: "100",
        currency: "USD",
        moved: false,
      },
      counterparty: "clockchain:handshake",
    },
    identity: {
      reference: `eip155:11155111:${REGISTRY}:42`,
      agentId: "42",
      displayName: DISPLAY_NAME,
      owner: ADDRESS,
      registerTx: REGISTER_TX,
      metadataTx: METADATA_TX,
    },
    clockchain: {
      ledgerId: LEDGER_ID,
      blockHeight: "321",
      consensusTime: "23-07-2026_07:00:01:234",
      receiptStatus: "anchored",
      receiptVerified: true,
      crossPartyVerified: true,
      verifiedAgainst: "on-chain block",
      keyless: true,
      poolHealth: {
        totalNodes: 1,
        nodeParticipationPct: 0,
        degradedAtSubmission: true,
      },
    },
    disclaimer: SINGLE_VALIDATOR_DISCLAIMER,
  };
}

async function temporaryDirectory(t) {
  const directory = await mkdtemp(
    join(tmpdir(), "handshake-run-test-"),
  );
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}

function clock() {
  const values = [
    new Date("2026-07-23T07:00:00.000Z"),
    new Date("2026-07-23T07:00:01.234Z"),
  ];
  return () => values.shift();
}

function createAdapters({
  calls,
  captured,
  eventHash = EVENT_HASH,
  failAt,
  onEvidence,
  resumed = false,
}) {
  function maybeFail(stage) {
    if (failAt === stage) {
      if (stage === "resolve") {
        throw new McpVerificationError(
          `resolver echoed ${MCP_TOKEN}`,
        );
      }
      if (stage === "timestamp") {
        throw new McpNetworkError(
          `timestamp echoed ${MCP_TOKEN}`,
        );
      }
      throw new Error(
        `unexpected adapter failure ${PRIVATE_KEY} ${MCP_TOKEN}`,
      );
    }
  }

  const client = {
    async resolveAgent(agentId) {
      calls.push("resolve");
      maybeFail("resolve");
      assert.equal(agentId, "42");
      return {
        agentId: "42",
        agentURI: registrationDataUri(
          completedRegistration().document,
        ),
        owner: ADDRESS,
        status: "active",
      };
    },
    async getTimestamp() {
      calls.push("timestamp");
      maybeFail("timestamp");
      return {
        blockHeight: "320",
        madMarzulloTime: "23-07-2026_07:00:00:500",
        nodeStatus: "Synced",
        "nodeParticipation%": 0,
        totalNodes: 1,
      };
    },
    async attestAction(args) {
      calls.push("attest");
      maybeFail("attest");
      captured.attestArguments = args;
      return submittedReceipt(eventHash);
    },
    async verifyReceipt(receipt) {
      calls.push("verify receipt");
      maybeFail("verify receipt");
      assert.deepEqual(receipt, anchoredReceipt(eventHash));
      return {
        match: true,
        verifiedAgainst: "on-chain block",
      };
    },
    async verifyCrossParty(identifiers) {
      calls.push("verify cross-party");
      maybeFail("verify cross-party");
      captured.crossPartyIdentifiers = identifiers;
      return {
        onChain: {
          keyless: true,
          verifiedAgainst: "on-chain block",
          ledgerId: identifiers.ledgerId,
          blockHeight: identifiers.blockHeight,
          anchoredHash: identifiers.hash,
          assetReferenceId:
            anchoredReceipt(eventHash).anchor.assetReferenceId,
        },
      };
    },
  };

  return {
    async readSecretInvitation(path) {
      calls.push("read invitation");
      maybeFail("read invitation");
      assert.equal(path, "/operator/invite.secret.json");
      return {
        bundle: {
          encrypted: true,
          address: ADDRESS,
          displayName: DISPLAY_NAME,
        },
        code: INVITATION_CODE,
      };
    },
    async decryptInvitation(bundle, code) {
      calls.push("decrypt");
      maybeFail("decrypt");
      assert.deepEqual(bundle, {
        encrypted: true,
        address: ADDRESS,
        displayName: DISPLAY_NAME,
      });
      assert.equal(code, INVITATION_CODE);
      return {
        privateKey: PRIVATE_KEY,
        address: ADDRESS,
        displayName: DISPLAY_NAME,
      };
    },
    async registerIdentity(options) {
      assert.equal(resumed, false, "registration write was repeated");
      calls.push("register");
      maybeFail("register");
      captured.registrationOptions = options;
      // The real registerIdentity records the pre-broadcast intent before it
      // broadcasts, then upgrades it to the public recovery checkpoint.
      await options.onCheckpoint(registrationIntent());
      await options.onCheckpoint(registrationRecovery());
      calls.push("register/checkpoint");
      return completedRegistration();
    },
    async finalizeIdentityRegistration(options) {
      assert.equal(resumed, true, "unexpected resumed registration");
      calls.push("finalize registration");
      maybeFail("finalize registration");
      captured.finalizeOptions = options;
      await options.onCheckpoint(options.recovery);
      return completedRegistration();
    },
    async mintDemoToken(options) {
      calls.push("mint token");
      maybeFail("mint token");
      captured.tokenOptions = options;
      return MCP_TOKEN;
    },
    createMcpClient(options) {
      maybeFail("create client");
      assert.deepEqual(options, { token: MCP_TOKEN });
      return client;
    },
    async completeReceipt(_client, receipt) {
      calls.push("complete");
      maybeFail("complete");
      assert.deepEqual(receipt, submittedReceipt(eventHash));
      return anchoredReceipt(eventHash);
    },
    assertCrossPartyVerification(result, expected) {
      captured.crossPartyBinding = expected;
      return assertCrossPartyVerification(result, expected);
    },
    async writeEvidence(options) {
      calls.push("write evidence");
      maybeFail("write evidence");
      captured.evidence = options;
      await onEvidence?.(options);
      return writeEvidence(options);
    },
    reportProgress(event) {
      if (event.stage === "registration-recovery-loaded") {
        calls.push("read checkpoint");
      }
    },
  };
}

test("runs the first-time flow in order and writes only strict sanitized PASS evidence", async (t) => {
  const outputDirectory = await temporaryDirectory(t);
  const calls = [];
  const captured = {};
  const adapters = createAdapters({
    calls,
    captured,
    resumed: false,
  });

  const result = await runHandshake({
    invitationFile: "/operator/invite.secret.json",
    outputDirectory,
    adapters,
    now: clock(),
    randomUUID: () => RUN_ID,
  });

  assert.deepEqual(calls, [
    "read invitation",
    "decrypt",
    "register",
    "register/checkpoint",
    "mint token",
    "resolve",
    "timestamp",
    "attest",
    "complete",
    "verify receipt",
    "verify cross-party",
    "write evidence",
  ]);
  assert.deepEqual(result, expectedPassResult());
  assert.deepEqual(captured.attestArguments, {
    agent_id: "42",
    action: "trust_handshake",
    inputs: receiptInputs(),
    outputs: receiptOutputs(),
    wait: false,
    idempotency_key: RUN_ID,
    allow_degraded: true,
  });
  assert.deepEqual(captured.crossPartyIdentifiers, {
    ledgerId: LEDGER_ID,
    blockHeight: "321",
    hash: EVENT_HASH,
  });
  assert.deepEqual(captured.crossPartyBinding, {
    ledgerId: LEDGER_ID,
    blockHeight: "321",
    anchoredHash: EVENT_HASH,
    assetReferenceId: "agent:42:trust_handshake:1",
  });
  assert.deepEqual(captured.evidence.canaries, [
    INVITATION_CODE,
    PRIVATE_KEY,
    MCP_TOKEN,
  ]);
  assert.equal(
    JSON.stringify(result).includes(INVITATION_CODE),
    false,
  );
  assert.equal(JSON.stringify(result).includes(PRIVATE_KEY), false);
  assert.equal(JSON.stringify(result).includes(MCP_TOKEN), false);
  assert.deepEqual(
    JSON.parse(
      await readFile(join(outputDirectory, RECOVERY_FILE), "utf8"),
    ),
    registrationRecovery(),
  );
  assert.deepEqual(
    JSON.parse(
      await readFile(join(outputDirectory, "result.json"), "utf8"),
    ),
    result,
  );

  const expectedUri = registrationDataUri(
    completedRegistration().document,
  );
  assert.deepEqual(
    captured.registrationOptions,
    {
      privateKey: PRIVATE_KEY,
      expectedAddress: ADDRESS,
      displayName: DISPLAY_NAME,
      onCheckpoint: captured.registrationOptions.onCheckpoint,
    },
  );
  assert.equal(
    captured.evidence.result.identity.owner,
    ADDRESS,
  );
  assert.equal(
    expectedUri,
    registrationDataUri(completedRegistration().document),
  );
});

test("refuses a rerun after PASS before archiving evidence or touching an adapter", async (t) => {
  const outputDirectory = await temporaryDirectory(t);
  const firstCalls = [];
  await runHandshake({
    invitationFile: "/operator/invite.secret.json",
    outputDirectory,
    adapters: createAdapters({
      calls: firstCalls,
      captured: {},
      resumed: false,
    }),
    now: clock(),
    randomUUID: () => RUN_ID,
  });
  const jsonPath = join(outputDirectory, "result.json");
  const markdownPath = join(outputDirectory, "RESULT.md");
  const markerPath = join(
    outputDirectory,
    ATTESTATION_MARKER_FILE,
  );
  const priorJson = await readFile(jsonPath);
  const priorMarkdown = await readFile(markdownPath);

  let evidenceAttempts = 0;
  const secondCalls = [];
  const secondAdapters = createAdapters({
    calls: secondCalls,
    captured: {},
    resumed: true,
  });
  secondAdapters.beginEvidenceAttempt = async (options) => {
    evidenceAttempts += 1;
    return beginEvidenceAttempt(options);
  };

  await assert.rejects(
    () =>
      runHandshake({
        invitationFile: "/operator/invite.secret.json",
        outputDirectory,
        adapters: secondAdapters,
        now: clock(),
        randomUUID: () => PRIOR_RUN_ID,
      }),
    (error) => {
      assert.ok(error instanceof HandshakeStageError);
      assert.equal(error.stage, "output-directory");
      assert.equal(error.category, "configuration");
      assert.equal(
        error.code,
        "HANDSHAKE_OUTPUT_DIRECTORY_IN_USE",
      );
      return true;
    },
  );

  assert.equal(evidenceAttempts, 0);
  assert.deepEqual(secondCalls, []);
  assert.equal(
    [...firstCalls, ...secondCalls].filter(
      (call) => call === "attest",
    ).length,
    1,
  );
  assert.deepEqual(await readFile(jsonPath), priorJson);
  assert.deepEqual(await readFile(markdownPath), priorMarkdown);
  assert.deepEqual(
    JSON.parse(await readFile(markerPath, "utf8")),
    {
      schema: ATTESTATION_MARKER_SCHEMA,
      runId: RUN_ID,
      agentId: "42",
      identityReference:
        `eip155:11155111:${REGISTRY}:42`,
      expectedEventHash: EVENT_HASH,
    },
  );
  assert.equal((await stat(markerPath)).mode & 0o777, 0o600);
});

test("refuses a rerun after an ambiguous attestation failure before every adapter call", async (t) => {
  const outputDirectory = await temporaryDirectory(t);
  const firstCalls = [];
  await assert.rejects(
    () =>
      runHandshake({
        invitationFile: "/operator/invite.secret.json",
        outputDirectory,
        adapters: createAdapters({
          calls: firstCalls,
          captured: {},
          failAt: "attest",
          resumed: false,
        }),
        now: clock(),
        randomUUID: () => RUN_ID,
      }),
    (error) => {
      assert.ok(error instanceof HandshakeStageError);
      assert.equal(error.stage, "attestation");
      return true;
    },
  );

  let evidenceAttempts = 0;
  const secondCalls = [];
  const secondAdapters = createAdapters({
    calls: secondCalls,
    captured: {},
    resumed: true,
  });
  secondAdapters.beginEvidenceAttempt = async (options) => {
    evidenceAttempts += 1;
    return beginEvidenceAttempt(options);
  };

  await assert.rejects(
    () =>
      runHandshake({
        invitationFile: "/operator/invite.secret.json",
        outputDirectory,
        adapters: secondAdapters,
        now: clock(),
        randomUUID: () => PRIOR_RUN_ID,
      }),
    (error) => {
      assert.ok(error instanceof HandshakeStageError);
      assert.equal(error.stage, "attestation");
      assert.equal(error.category, "protocol");
      assert.equal(error.code, "HANDSHAKE_ATTESTATION_FAILED");
      return true;
    },
  );

  assert.equal(evidenceAttempts, 0);
  assert.deepEqual(secondCalls, []);
  assert.equal(
    [...firstCalls, ...secondCalls].filter(
      (call) => call === "attest",
    ).length,
    1,
  );
});

test("treats every existing marker entry, including a dangling symlink, as attestation started", async (t) => {
  const outputDirectory = await temporaryDirectory(t);
  await symlink(
    "missing-marker-target",
    join(outputDirectory, ATTESTATION_MARKER_FILE),
  );
  const calls = [];

  await assert.rejects(
    () =>
      runHandshake({
        invitationFile: "/operator/invite.secret.json",
        outputDirectory,
        adapters: createAdapters({
          calls,
          captured: {},
          resumed: false,
        }),
        now: clock(),
        randomUUID: () => RUN_ID,
      }),
    (error) => {
      assert.ok(error instanceof HandshakeStageError);
      assert.equal(error.stage, "attestation");
      return true;
    },
  );
  assert.deepEqual(calls, []);
});

test("uses atomic marker creation to allow only one concurrent attestation", async (t) => {
  const outputDirectory = await temporaryDirectory(t);
  await writeFile(
    join(outputDirectory, RECOVERY_FILE),
    `${JSON.stringify(registrationRecovery(), null, 2)}\n`,
    { encoding: "utf8", mode: 0o644 },
  );
  const calls = [];
  const runs = await Promise.allSettled(
    [0, 1].map(() =>
      runHandshake({
        invitationFile: "/operator/invite.secret.json",
        outputDirectory,
        adapters: createAdapters({
          calls,
          captured: {},
          resumed: true,
        }),
        now: clock(),
        randomUUID: () => RUN_ID,
      }),
    ),
  );

  assert.equal(
    calls.filter((call) => call === "attest").length,
    1,
  );
  assert.equal(
    runs.filter((result) => result.status === "fulfilled").length,
    1,
  );
  const rejected = runs.find(
    (result) => result.status === "rejected",
  );
  assert.ok(rejected?.reason instanceof HandshakeStageError);
  assert.equal(rejected.reason.stage, "attestation");
});

test("ignores the exact repository-generated handshake lifecycle files", async () => {
  const { stdout } = await execFileAsync(
    "git",
    [
      "check-ignore",
      "--no-index",
      "-v",
      "--",
      RECOVERY_FILE,
      ATTESTATION_MARKER_FILE,
    ],
    { cwd: REPOSITORY_ROOT },
  );
  const matches = stdout
    .trim()
    .split("\n")
    .map((line) => {
      const [source, path] = line.split("\t");
      const [, , pattern] = source.split(":");
      return { pattern, path };
    });
  assert.deepEqual(matches, [
    { pattern: RECOVERY_FILE, path: RECOVERY_FILE },
    {
      pattern: ATTESTATION_MARKER_FILE,
      path: ATTESTATION_MARKER_FILE,
    },
  ]);
});

test("integrates the production completion gate across degraded and time-enrichment states", async (t) => {
  const outputDirectory = await temporaryDirectory(t);
  const calls = [];
  const captured = {};
  const adapters = createAdapters({
    calls,
    captured,
    resumed: false,
  });
  const awaitingTime = {
    ...anchoredReceipt(),
    anchor: {
      ...anchoredReceipt().anchor,
      consensusTime: null,
    },
  };
  const responses = [awaitingTime, anchoredReceipt()];
  adapters.completeReceipt = (client, receipt) =>
    completeReceipt(
      {
        ...client,
        async completeAttestation(current) {
          calls.push("complete attestation");
          assert.ok(
            current.status === "degraded" ||
              current.status === "anchored",
          );
          return responses.shift();
        },
      },
      receipt,
      {
        attempts: 2,
        intervalMs: 0,
        sleeper: async (milliseconds) => {
          assert.equal(milliseconds, 0);
        },
      },
    );

  const result = await runHandshake({
    invitationFile: "/operator/invite.secret.json",
    outputDirectory,
    adapters,
    now: clock(),
    randomUUID: () => RUN_ID,
  });

  assert.equal(result.status, "PASS");
  assert.equal(responses.length, 0);
  assert.equal(
    calls.filter((call) => call === "complete attestation")
      .length,
    2,
  );
  assert.equal(
    result.clockchain.consensusTime,
    anchoredReceipt().anchor.consensusTime,
  );
});

test("resumes from the retained public checkpoint without repeating registration", async (t) => {
  const outputDirectory = await temporaryDirectory(t);
  await writeFile(
    join(outputDirectory, RECOVERY_FILE),
    `${JSON.stringify(registrationRecovery(), null, 2)}\n`,
    { encoding: "utf8", mode: 0o644 },
  );
  const calls = [];
  const captured = {};
  const adapters = createAdapters({
    calls,
    captured,
    resumed: true,
  });

  await runHandshake({
    invitationFile: "/operator/invite.secret.json",
    outputDirectory,
    adapters,
    now: clock(),
    randomUUID: () => RUN_ID,
  });

  assert.deepEqual(calls, [
    "read invitation",
    "decrypt",
    "read checkpoint",
    "finalize registration",
    "mint token",
    "resolve",
    "timestamp",
    "attest",
    "complete",
    "verify receipt",
    "verify cross-party",
    "write evidence",
  ]);
  assert.deepEqual(
    captured.finalizeOptions.recovery,
    registrationRecovery(),
  );
  assert.equal(
    Object.hasOwn(captured.finalizeOptions, "registerIdentity"),
    false,
  );
});

test("records the pre-broadcast intent checkpoint and upgrades it to full recovery", async (t) => {
  const outputDirectory = await temporaryDirectory(t);
  const calls = [];
  const captured = {};
  const adapters = createAdapters({ calls, captured });
  adapters.registerIdentity = async (options) => {
    calls.push("register");
    captured.registrationOptions = options;
    await options.onCheckpoint(registrationIntent());
    captured.intentOnDisk = await readCheckpointFile(outputDirectory);
    await options.onCheckpoint(registrationRecovery());
    captured.recoveryOnDisk = await readCheckpointFile(outputDirectory);
    return completedRegistration();
  };

  const result = await runHandshake({
    invitationFile: "/operator/invite.secret.json",
    outputDirectory,
    adapters,
    now: clock(),
    randomUUID: () => RUN_ID,
  });

  assert.equal(result.status, "PASS");
  assert.deepEqual(captured.intentOnDisk, registrationIntent());
  assert.deepEqual(captured.recoveryOnDisk, registrationRecovery());
  assert.deepEqual(
    await readCheckpointFile(outputDirectory),
    registrationRecovery(),
  );
  assert.equal(
    Object.hasOwn(captured.registrationOptions, "intent"),
    false,
  );
});

test("keeps the pre-broadcast intent on disk and resumes it read-only", async (t) => {
  const outputDirectory = await temporaryDirectory(t);
  const intent = registrationIntent();
  const failedCalls = [];
  const failedAdapters = createAdapters({
    calls: failedCalls,
    captured: {},
  });
  failedAdapters.registerIdentity = async (options) => {
    failedCalls.push("register");
    await options.onCheckpoint(intent);
    throw new RegistrationNetworkError(
      `receipt wait echoed ${PRIVATE_KEY}`,
    );
  };

  await assert.rejects(
    () =>
      runHandshake({
        invitationFile: "/operator/invite.secret.json",
        outputDirectory,
        adapters: failedAdapters,
        now: clock(),
        randomUUID: () => RUN_ID,
      }),
    (error) => {
      assert.ok(error instanceof HandshakeStageError);
      assert.equal(error.stage, "registration");
      assert.equal(error.category, "network");
      assert.equal(error.message.includes(PRIVATE_KEY), false);
      return true;
    },
  );
  assert.deepEqual(
    await readCheckpointFile(outputDirectory),
    intent,
  );
  await assert.rejects(
    () => stat(join(outputDirectory, "result.json")),
    { code: "ENOENT" },
  );

  const calls = [];
  const captured = {};
  const adapters = createAdapters({
    calls,
    captured,
    resumed: true,
  });
  adapters.registerIdentity = async (options) => {
    calls.push("register");
    captured.registrationOptions = options;
    captured.intentOnEntry = await readCheckpointFile(outputDirectory);
    await options.onCheckpoint(registrationRecovery());
    return completedRegistration();
  };

  const result = await runHandshake({
    invitationFile: "/operator/invite.secret.json",
    outputDirectory,
    adapters,
    now: clock(),
    randomUUID: () => RUN_ID,
  });

  assert.equal(result.status, "PASS");
  assert.deepEqual(captured.registrationOptions.intent, intent);
  assert.deepEqual(captured.intentOnEntry, intent);
  assert.equal(calls.includes("finalize registration"), false);
  assert.equal(calls.includes("read checkpoint"), true);
  assert.deepEqual(
    await readCheckpointFile(outputDirectory),
    registrationRecovery(),
  );
});

test("resumes a legacy-priced intent checkpoint through the register path", async (t) => {
  const outputDirectory = await temporaryDirectory(t);
  const intent = registrationIntent({
    transactionFields: { gasPrice: 3_000_000_000n },
  });
  await writeCheckpointFile(outputDirectory, intent);
  const calls = [];
  const captured = {};
  const adapters = createAdapters({
    calls,
    captured,
    resumed: true,
  });
  adapters.registerIdentity = async (options) => {
    calls.push("register");
    captured.registrationOptions = options;
    await options.onCheckpoint(registrationRecovery());
    return completedRegistration();
  };

  await runHandshake({
    invitationFile: "/operator/invite.secret.json",
    outputDirectory,
    adapters,
    now: clock(),
    randomUUID: () => RUN_ID,
  });

  assert.equal(Object.hasOwn(intent, "gasPrice"), true);
  assert.deepEqual(captured.registrationOptions.intent, intent);
  assert.equal(calls.includes("finalize registration"), false);
});

test("refuses a registration that recorded only a pre-broadcast intent", async (t) => {
  const outputDirectory = await temporaryDirectory(t);
  const calls = [];
  const adapters = createAdapters({ calls, captured: {} });
  adapters.registerIdentity = async (options) => {
    calls.push("register");
    await options.onCheckpoint(registrationIntent());
    return completedRegistration();
  };

  await assert.rejects(
    () =>
      runHandshake({
        invitationFile: "/operator/invite.secret.json",
        outputDirectory,
        adapters,
        now: clock(),
        randomUUID: () => RUN_ID,
      }),
    (error) => {
      assert.ok(error instanceof HandshakeStageError);
      assert.equal(error.stage, "registration");
      assert.equal(error.code, "HANDSHAKE_REGISTRATION_FAILED");
      return true;
    },
  );
  assert.equal(calls.includes("mint token"), false);
  assert.deepEqual(
    await readCheckpointFile(outputDirectory),
    registrationIntent(),
  );
  await assert.rejects(
    () => stat(join(outputDirectory, "result.json")),
    { code: "ENOENT" },
  );
});

test("refuses a second pre-broadcast intent record in one run", async (t) => {
  const outputDirectory = await temporaryDirectory(t);
  const calls = [];
  const adapters = createAdapters({ calls, captured: {} });
  adapters.registerIdentity = async (options) => {
    calls.push("register");
    await options.onCheckpoint(registrationIntent());
    await options.onCheckpoint(
      registrationIntent({ registerGas: "300000" }),
    );
    await options.onCheckpoint(registrationRecovery());
    return completedRegistration();
  };

  await assert.rejects(
    () =>
      runHandshake({
        invitationFile: "/operator/invite.secret.json",
        outputDirectory,
        adapters,
        now: clock(),
        randomUUID: () => RUN_ID,
      }),
    (error) => {
      assert.ok(error instanceof HandshakeStageError);
      assert.equal(error.stage, "registration");
      assert.equal(error.code, "HANDSHAKE_REGISTRATION_FAILED");
      return true;
    },
  );
  assert.equal(calls.includes("mint token"), false);
});

test("mirrors the exact pre-broadcast intent key set from the registration module", () => {
  assert.deepEqual(Object.keys(registrationIntent()), [
    "schema",
    "chainId",
    "registryAddress",
    "registryNamespace",
    "address",
    "displayName",
    "registerNonce",
    "registerCalldata",
    "registerGas",
    "maxFeePerGas",
    "maxPriorityFeePerGas",
  ]);
  assert.deepEqual(
    Object.keys(
      registrationIntent({
        transactionFields: { gasPrice: 3_000_000_000n },
      }),
    ).slice(-1),
    ["gasPrice"],
  );
  assert.equal(registrationIntent().schema, INTENT_SCHEMA);
  assert.equal(registrationRecovery().schema, RECOVERY_SCHEMA);
});

test("keeps the intent and recovery checkpoint schemas exactly discriminated", async (t) => {
  const invalidCheckpoints = [
    { ...registrationIntent(), schema: RECOVERY_SCHEMA },
    { ...registrationRecovery(), schema: INTENT_SCHEMA },
    { ...registrationRecovery({ metadata: false }), schema: INTENT_SCHEMA },
    {
      ...registrationRecovery(),
      schema: `${RECOVERY_SCHEMA.slice(0, -1)}2`,
    },
    { ...registrationIntent(), extra: true },
    ...Object.keys(registrationIntent()).map((key) =>
      withoutIntentKey(key),
    ),
    registrationIntent({ chainId: 1 }),
    registrationIntent({ registryAddress: ADDRESS }),
    registrationIntent({ registryNamespace: "eip155:1:wrong" }),
    registrationIntent({ address: REGISTRY }),
    registrationIntent({ displayName: "Iris" }),
    registrationIntent({ registerNonce: 1 }),
    registrationIntent({ registerNonce: "0" }),
    registrationIntent({ registerCalldata: "0x1" }),
    registrationIntent({ registerCalldata: "not-hex" }),
    registrationIntent({ registerGas: "0" }),
    registrationIntent({ registerGas: 226_000 }),
    registrationIntent({ maxFeePerGas: "0" }),
    registrationIntent({ maxPriorityFeePerGas: "3" }),
    registrationIntent({ gasPrice: "3000000000" }),
    {
      ...registrationIntent({
        transactionFields: { gasPrice: 3_000_000_000n },
      }),
      maxFeePerGas: "2",
    },
  ];

  for (const checkpoint of invalidCheckpoints) {
    const outputDirectory = await temporaryDirectory(t);
    await writeCheckpointFile(outputDirectory, checkpoint);
    const calls = [];
    const adapters = createAdapters({
      calls,
      captured: {},
      resumed: true,
    });
    adapters.registerIdentity = async () => {
      calls.push("register");
      return completedRegistration();
    };

    await assert.rejects(
      () =>
        runHandshake({
          invitationFile: "/operator/invite.secret.json",
          outputDirectory,
          adapters,
          now: clock(),
          randomUUID: () => RUN_ID,
        }),
      (error) => {
        assert.ok(error instanceof HandshakeStageError);
        assert.equal(error.stage, "registration-recovery");
        assert.equal(error.category, "configuration");
        return true;
      },
      JSON.stringify(checkpoint),
    );
    assert.equal(calls.includes("register"), false);
    assert.equal(calls.includes("finalize registration"), false);
  }
});

test("refuses to persist a checkpoint that is neither an intent nor a recovery record", async (t) => {
  const outputDirectory = await temporaryDirectory(t);
  const calls = [];
  const adapters = createAdapters({ calls, captured: {} });
  adapters.registerIdentity = async (options) => {
    calls.push("register");
    await options.onCheckpoint({
      ...registrationIntent(),
      schema: RECOVERY_SCHEMA,
    });
    return completedRegistration();
  };

  await assert.rejects(
    () =>
      runHandshake({
        invitationFile: "/operator/invite.secret.json",
        outputDirectory,
        adapters,
        now: clock(),
        randomUUID: () => RUN_ID,
      }),
    (error) => {
      assert.ok(error instanceof HandshakeStageError);
      assert.equal(error.stage, "registration");
      assert.equal(error.code, "HANDSHAKE_REGISTRATION_FAILED");
      return true;
    },
  );
  await assert.rejects(
    () => stat(join(outputDirectory, RECOVERY_FILE)),
    { code: "ENOENT" },
  );
});

test("fails the resumed run when the public recovery file cannot be closed safely", async (t) => {
  const outputDirectory = await temporaryDirectory(t);
  await writeFile(
    join(outputDirectory, RECOVERY_FILE),
    `${JSON.stringify(registrationRecovery(), null, 2)}\n`,
    { encoding: "utf8", mode: 0o644 },
  );
  const calls = [];
  let openCalls = 0;
  const adapters = createAdapters({
    calls,
    captured: {},
    resumed: true,
  });
  adapters.openRecoveryFile = async (path, flags) => {
    openCalls += 1;
    const handle = await open(path, flags);
    return {
      stat: (...args) => handle.stat(...args),
      readFile: (...args) => handle.readFile(...args),
      async close() {
        await handle.close();
        throw new Error(`close echoed ${PRIVATE_KEY}`);
      },
    };
  };

  await assert.rejects(
    () =>
      runHandshake({
        invitationFile: "/operator/invite.secret.json",
        outputDirectory,
        adapters,
        now: clock(),
        randomUUID: () => RUN_ID,
      }),
    (error) => {
      assert.ok(error instanceof HandshakeStageError);
      assert.equal(error.stage, "registration-recovery");
      assert.equal(error.category, "configuration");
      assert.equal(error.message.includes(PRIVATE_KEY), false);
      return true;
    },
  );
  assert.equal(openCalls, 1);
  assert.equal(calls.includes("finalize registration"), false);
});

test("persists PartialRegistrationError recovery again and returns only a typed safe error", async (t) => {
  const outputDirectory = await temporaryDirectory(t);
  let evidenceWrites = 0;
  const recovery = registrationRecovery({ metadata: false });
  const partial = new PartialRegistrationError(
    recovery,
    new RegistrationNetworkError(
      `upstream echoed ${PRIVATE_KEY} ${INVITATION_CODE}`,
    ),
  );
  const adapters = createAdapters({
    calls: [],
    captured: {},
    resumed: false,
    onEvidence: async () => {
      evidenceWrites += 1;
    },
  });
  adapters.registerIdentity = async () => {
    throw partial;
  };

  await assert.rejects(
    () =>
      runHandshake({
        invitationFile: "/operator/invite.secret.json",
        outputDirectory,
        adapters,
        now: clock(),
        randomUUID: () => RUN_ID,
      }),
    (error) => {
      assert.ok(error instanceof HandshakeStageError);
      assert.equal(error.stage, "registration");
      assert.equal(error.category, "network");
      assert.equal(error.code, "HANDSHAKE_REGISTRATION_FAILED");
      assert.equal(Object.hasOwn(error, "cause"), false);
      assert.equal(error.message.includes(PRIVATE_KEY), false);
      assert.equal(error.stack.includes(INVITATION_CODE), false);
      return true;
    },
  );
  assert.deepEqual(
    JSON.parse(
      await readFile(join(outputDirectory, RECOVERY_FILE), "utf8"),
    ),
    recovery,
  );
  assert.equal(evidenceWrites, 0);
  await assert.rejects(
    () => stat(join(outputDirectory, "result.json")),
    { code: "ENOENT" },
  );
  await assert.rejects(
    () => stat(join(outputDirectory, "RESULT.md")),
    { code: "ENOENT" },
  );
});

test("refuses a legacy PASS rerun before archiving evidence or touching adapters", async (t) => {
  const outputDirectory = await temporaryDirectory(t);
  const priorResult = {
    ...expectedPassResult(),
    runId: PRIOR_RUN_ID,
  };
  await writeEvidence({
    directory: outputDirectory,
    result: priorResult,
    canaries: [],
  });
  const recovery = registrationRecovery();
  await writeFile(
    join(outputDirectory, RECOVERY_FILE),
    `${JSON.stringify(recovery, null, 2)}\n`,
    { encoding: "utf8", mode: 0o644 },
  );
  const priorJson = await readFile(
    join(outputDirectory, "result.json"),
    "utf8",
  );
  const priorMarkdown = await readFile(
    join(outputDirectory, "RESULT.md"),
    "utf8",
  );
  const calls = [];
  const adapters = createAdapters({
    calls,
    captured: {},
    resumed: false,
  });
  let evidenceAttempts = 0;
  adapters.beginEvidenceAttempt = async (options) => {
    evidenceAttempts += 1;
    return beginEvidenceAttempt(options);
  };

  await assert.rejects(
    () =>
      runHandshake({
        invitationFile: "/operator/invite.secret.json",
        outputDirectory,
        adapters,
        now: clock(),
        randomUUID: () => RUN_ID,
      }),
    (error) => {
      assert.ok(error instanceof HandshakeStageError);
      assert.equal(error.stage, "output-directory");
      assert.equal(error.category, "configuration");
      assert.equal(
        error.code,
        "HANDSHAKE_OUTPUT_DIRECTORY_IN_USE",
      );
      return true;
    },
  );

  assert.equal(
    await readFile(join(outputDirectory, "result.json"), "utf8"),
    priorJson,
  );
  assert.equal(
    await readFile(join(outputDirectory, "RESULT.md"), "utf8"),
    priorMarkdown,
  );
  assert.deepEqual(
    JSON.parse(
      await readFile(
        join(outputDirectory, RECOVERY_FILE),
        "utf8",
      ),
    ),
    recovery,
  );
  assert.equal(evidenceAttempts, 0);
  assert.deepEqual(calls, []);
  assert.equal(
    calls.filter((call) => call === "attest").length,
    0,
  );
});

test("refuses canonical evidence created by a setup callback before evidence initialization", async (t) => {
  const outputDirectory = await temporaryDirectory(t);
  const jsonPath = join(outputDirectory, "result.json");
  const priorJson = Buffer.from("legacy-final-bytes\n");
  const calls = [];
  const adapters = createAdapters({
    calls,
    captured: {},
    failAt: "read invitation",
    resumed: false,
  });
  let evidenceAttempts = 0;
  adapters.beginEvidenceAttempt = async (options) => {
    evidenceAttempts += 1;
    return beginEvidenceAttempt(options);
  };
  let injected = false;

  await assert.rejects(
    () =>
      runHandshake({
        invitationFile: "/operator/invite.secret.json",
        outputDirectory,
        adapters,
        now: () => {
          if (!injected) {
            writeFileSync(jsonPath, priorJson);
            injected = true;
          }
          return new Date("2026-07-23T07:00:00.000Z");
        },
        randomUUID: () => RUN_ID,
      }),
    (error) => {
      assert.ok(error instanceof HandshakeStageError);
      assert.equal(error.stage, "output-directory");
      assert.equal(
        error.code,
        "HANDSHAKE_OUTPUT_DIRECTORY_IN_USE",
      );
      return true;
    },
  );

  assert.equal(evidenceAttempts, 0);
  assert.deepEqual(calls, []);
  assert.deepEqual(await readFile(jsonPath), priorJson);
});

test("refuses non-regular canonical evidence entries before touching adapters", async (t) => {
  for (const entry of [
    {
      name: "result.json",
      create: (path) => symlink("missing-result-target", path),
    },
    {
      name: "RESULT.md",
      create: (path) => mkdir(path),
    },
  ]) {
    await t.test(entry.name, async () => {
      const outputDirectory = await temporaryDirectory(t);
      const entryPath = join(outputDirectory, entry.name);
      await entry.create(entryPath);
      const calls = [];
      let evidenceAttempts = 0;
      const adapters = createAdapters({
        calls,
        captured: {},
        resumed: false,
      });
      adapters.beginEvidenceAttempt = async (options) => {
        evidenceAttempts += 1;
        return beginEvidenceAttempt(options);
      };

      await assert.rejects(
        () =>
          runHandshake({
            invitationFile: "/operator/invite.secret.json",
            outputDirectory,
            adapters,
            now: clock(),
            randomUUID: () => RUN_ID,
          }),
        (error) => {
          assert.ok(error instanceof HandshakeStageError);
          assert.equal(error.stage, "output-directory");
          assert.equal(
            error.code,
            "HANDSHAKE_OUTPUT_DIRECTORY_IN_USE",
          );
          return true;
        },
      );
      assert.equal(evidenceAttempts, 0);
      assert.deepEqual(calls, []);
      await lstat(entryPath);
    });
  }
});

test("refuses canonical evidence injected after initialization without publishing PASS", async (t) => {
  const outputDirectory = await temporaryDirectory(t);
  const jsonPath = join(outputDirectory, "result.json");
  const markdownPath = join(outputDirectory, "RESULT.md");
  const priorJson = Buffer.from("late-final-bytes\n");
  const calls = [];
  const adapters = createAdapters({
    calls,
    captured: {},
    resumed: false,
  });
  const reportProgress = adapters.reportProgress;
  adapters.reportProgress = async (event) => {
    await reportProgress(event);
    if (event.stage === "evidence-writing") {
      writeFileSync(jsonPath, priorJson);
    }
  };

  await assert.rejects(
    () =>
      runHandshake({
        invitationFile: "/operator/invite.secret.json",
        outputDirectory,
        adapters,
        now: clock(),
        randomUUID: () => RUN_ID,
      }),
    (error) => {
      assert.ok(error instanceof HandshakeStageError);
      assert.equal(error.stage, "evidence");
      assert.equal(error.code, "HANDSHAKE_EVIDENCE_FAILED");
      return true;
    },
  );

  assert.deepEqual(await readFile(jsonPath), priorJson);
  await assert.rejects(readFile(markdownPath), { code: "ENOENT" });
  assert.equal(
    calls.filter((call) => call === "write evidence").length,
    1,
  );
});

test("withholds PASS artifacts after a typed MCP verification failure", async (t) => {
  const outputDirectory = await temporaryDirectory(t);
  let evidenceWrites = 0;
  const adapters = createAdapters({
    calls: [],
    captured: {},
    failAt: "resolve",
    resumed: false,
    onEvidence: async () => {
      evidenceWrites += 1;
    },
  });

  await assert.rejects(
    () =>
      runHandshake({
        invitationFile: "/operator/invite.secret.json",
        outputDirectory,
        adapters,
        now: clock(),
        randomUUID: () => RUN_ID,
      }),
    (error) => {
      assert.ok(error instanceof HandshakeStageError);
      assert.equal(error.stage, "identity-resolution");
      assert.equal(error.category, "verification");
      assert.equal(error.code, "HANDSHAKE_IDENTITY_RESOLUTION_FAILED");
      assert.equal(error.message.includes(MCP_TOKEN), false);
      return true;
    },
  );
  assert.equal(evidenceWrites, 0);
  await assert.rejects(
    () => stat(join(outputDirectory, "result.json")),
    { code: "ENOENT" },
  );
  await assert.rejects(
    () => stat(join(outputDirectory, "RESULT.md")),
    { code: "ENOENT" },
  );
});

test("never retries an ambiguous attestation write or emits PASS evidence", async (t) => {
  const outputDirectory = await temporaryDirectory(t);
  let evidenceWrites = 0;
  const calls = [];
  const adapters = createAdapters({
    calls,
    captured: {},
    failAt: "attest",
    resumed: false,
    onEvidence: async () => {
      evidenceWrites += 1;
    },
  });

  await assert.rejects(
    () =>
      runHandshake({
        invitationFile: "/operator/invite.secret.json",
        outputDirectory,
        adapters,
        now: clock(),
        randomUUID: () => RUN_ID,
      }),
    (error) => {
      assert.ok(error instanceof HandshakeStageError);
      assert.equal(error.stage, "attestation");
      assert.equal(error.category, "protocol");
      return true;
    },
  );
  assert.equal(
    calls.filter((call) => call === "attest").length,
    1,
  );
  assert.equal(evidenceWrites, 0);
  await assert.rejects(
    () => stat(join(outputDirectory, "result.json")),
    { code: "ENOENT" },
  );
  await assert.rejects(
    () => stat(join(outputDirectory, "RESULT.md")),
    { code: "ENOENT" },
  );
});

test("rejects a service-supplied event hash that does not match the canonical receipt event", async (t) => {
  const outputDirectory = await temporaryDirectory(t);
  const calls = [];
  let evidenceWrites = 0;
  const adapters = createAdapters({
    calls,
    captured: {},
    eventHash: WRONG_EVENT_HASH,
    resumed: false,
    onEvidence: async () => {
      evidenceWrites += 1;
    },
  });

  await assert.rejects(
    () =>
      runHandshake({
        invitationFile: "/operator/invite.secret.json",
        outputDirectory,
        adapters,
        now: clock(),
        randomUUID: () => RUN_ID,
      }),
    (error) => {
      assert.ok(error instanceof HandshakeStageError);
      assert.equal(error.stage, "attestation");
      assert.equal(error.category, "protocol");
      assert.equal(error.message.includes(WRONG_EVENT_HASH), false);
      return true;
    },
  );
  assert.deepEqual(calls.slice(-1), ["attest"]);
  assert.equal(calls.includes("complete"), false);
  assert.equal(calls.includes("verify receipt"), false);
  assert.equal(calls.includes("verify cross-party"), false);
  assert.equal(evidenceWrites, 0);
  await assert.rejects(
    () => stat(join(outputDirectory, "result.json")),
    { code: "ENOENT" },
  );
  await assert.rejects(
    () => stat(join(outputDirectory, "RESULT.md")),
    { code: "ENOENT" },
  );
});

test("awaits an injected anchor assertion before writing PASS evidence", async (t) => {
  const outputDirectory = await temporaryDirectory(t);
  let evidenceWrites = 0;
  const adapters = createAdapters({
    calls: [],
    captured: {},
    resumed: false,
    onEvidence: async () => {
      evidenceWrites += 1;
    },
  });
  adapters.assertAnchoredReceipt = async () => {
    throw new McpVerificationError(
      `anchor assertion echoed ${MCP_TOKEN}`,
    );
  };

  await assert.rejects(
    () =>
      runHandshake({
        invitationFile: "/operator/invite.secret.json",
        outputDirectory,
        adapters,
        now: clock(),
        randomUUID: () => RUN_ID,
      }),
    (error) => {
      assert.ok(error instanceof HandshakeStageError);
      assert.equal(error.stage, "receipt-completion");
      assert.equal(error.category, "verification");
      assert.equal(error.message.includes(MCP_TOKEN), false);
      return true;
    },
  );
  assert.equal(evidenceWrites, 0);
  await assert.rejects(
    () => stat(join(outputDirectory, "result.json")),
    { code: "ENOENT" },
  );
});

test("validates all run options and adapters before reading the invitation", async () => {
  let reads = 0;

  await assert.rejects(
    () =>
      runHandshake({
        invitationFile: "",
        adapters: {
          readSecretInvitation: async () => {
            reads += 1;
          },
        },
      }),
    (error) => {
      assert.ok(error instanceof HandshakeStageError);
      assert.equal(error.category, "configuration");
      return true;
    },
  );
  await assert.rejects(
    () =>
      runHandshake({
        invitationFile: "/operator/invite.secret.json",
        adapters: { unknownAdapter: () => {} },
      }),
    (error) => {
      assert.ok(error instanceof HandshakeStageError);
      assert.equal(error.category, "configuration");
      return true;
    },
  );
  assert.equal(reads, 0);
});

test("proves the output directory writable before the registration write", async (t) => {
  const parent = await temporaryDirectory(t);
  const outputDirectory = join(parent, "read-only");
  await mkdir(outputDirectory, { mode: 0o500 });
  t.after(() => chmod(outputDirectory, 0o700).catch(() => {}));
  let registrationWrites = 0;
  const adapters = createAdapters({
    calls: [],
    captured: {},
    resumed: false,
  });
  adapters.registerIdentity = async () => {
    registrationWrites += 1;
    throw new Error("registration must not be reached");
  };

  await assert.rejects(
    () =>
      runHandshake({
        invitationFile: "/operator/invite.secret.json",
        outputDirectory,
        adapters,
        now: clock(),
        randomUUID: () => RUN_ID,
      }),
    (error) => {
      assert.ok(error instanceof HandshakeStageError);
      assert.equal(error.category, "configuration");
      return true;
    },
  );
  assert.equal(registrationWrites, 0);
});

test("reports an unusable output path as an operator configuration fault", async (t) => {
  const parent = await temporaryDirectory(t);
  const regularFile = join(parent, "not-a-directory");
  await writeFile(regularFile, "", {
    encoding: "utf8",
    mode: 0o600,
  });
  const sealedParent = join(parent, "sealed");
  await mkdir(sealedParent, { mode: 0o700 });
  const unreachable = join(sealedParent, "evidence");
  await chmod(sealedParent, 0o000);
  t.after(() => chmod(sealedParent, 0o700).catch(() => {}));

  for (const outputDirectory of [regularFile, unreachable]) {
    const calls = [];
    const adapters = createAdapters({ calls, captured: {} });

    await assert.rejects(
      () =>
        runHandshake({
          invitationFile: "/operator/invite.secret.json",
          outputDirectory,
          adapters,
          now: clock(),
          randomUUID: () => RUN_ID,
        }),
      (error) => {
        assert.ok(error instanceof HandshakeStageError);
        assert.equal(error.stage, "configuration");
        assert.equal(error.category, "configuration");
        assert.equal(error.code, "HANDSHAKE_CONFIGURATION");
        return true;
      },
      outputDirectory,
    );
    assert.deepEqual(calls, []);
  }

  assert.equal(FAILURE_EXIT_CODES.HANDSHAKE_CONFIGURATION, 2);
});

function memoryStream() {
  let value = "";
  return {
    stream: {
      write(chunk) {
        value += String(chunk);
        return true;
      },
    },
    text() {
      return value;
    },
  };
}

test("CLI accepts only invitation/output configuration and prints PASS last", async () => {
  const stdout = memoryStream();
  const stderr = memoryStream();
  let options;

  const exitCode = await main({
    argv: [
      "--invite-file",
      "/operator/invite.secret.json",
      "--output",
      "/artifacts/billy",
    ],
    env: {},
    cwd: "/ignored",
    stdout: stdout.stream,
    stderr: stderr.stream,
    async run(received) {
      options = received;
      received.adapters.reportProgress({
        stage: "registration-complete",
      });
      return expectedPassResult();
    },
  });

  assert.equal(exitCode, 0);
  assert.equal(stderr.text(), "");
  assert.deepEqual(
    {
      invitationFile: options.invitationFile,
      outputDirectory: options.outputDirectory,
    },
    {
      invitationFile: "/operator/invite.secret.json",
      outputDirectory: "/artifacts/billy",
    },
  );
  assert.match(stdout.text(), /Registering ERC-8004 identity/);
  assert.match(stdout.text(), new RegExp(REGISTER_TX));
  assert.match(stdout.text(), new RegExp(METADATA_TX));
  assert.match(stdout.text(), new RegExp(LEDGER_ID));
  assert.equal(stdout.text().trim().endsWith("PASS"), true);
  assert.equal(stdout.text().includes(DISPLAY_NAME), false);
});

test("CLI returns deterministic typed exits without printing raw errors or secrets", async () => {
  const cases = [
    ["configuration", 2],
    ["network", 3],
    ["protocol", 4],
    ["verification", 4],
    ["redaction", 5],
  ];

  for (const [category, expectedExit] of cases) {
    const stdout = memoryStream();
    const stderr = memoryStream();
    const exitCode = await main({
      argv: [],
      env: {
        HANDSHAKE_INVITE_FILE:
          "/operator/invite.secret.json",
      },
      stdout: stdout.stream,
      stderr: stderr.stream,
      async run() {
        const error = new HandshakeStageError({
          stage: "evidence",
          category,
          code: "HANDSHAKE_EVIDENCE_FAILED",
        });
        error.untrusted = `${PRIVATE_KEY} ${MCP_TOKEN}`;
        throw error;
      },
    });

    assert.equal(exitCode, expectedExit);
    assert.equal(stdout.text().includes("PASS"), false);
    assert.equal(stderr.text().includes(PRIVATE_KEY), false);
    assert.equal(stderr.text().includes(MCP_TOKEN), false);
  }

  const deniedOutput = memoryStream();
  const deniedError = memoryStream();
  let called = false;
  assert.equal(
    await main({
      argv: ["--private-key", PRIVATE_KEY],
      env: {},
      stdout: deniedOutput.stream,
      stderr: deniedError.stream,
      async run() {
        called = true;
      },
    }),
    2,
  );
  assert.equal(called, false);
  assert.equal(deniedError.text().includes(PRIVATE_KEY), false);
});

test("names the reused directory when it already holds handshake evidence", async () => {
  const stdout = memoryStream();
  const stderr = memoryStream();

  const exitCode = await main({
    argv: ["--output", "/artifacts/billy"],
    env: {
      HANDSHAKE_INVITE_FILE: "/operator/invite.secret.json",
    },
    stdout: stdout.stream,
    stderr: stderr.stream,
    async run() {
      throw new HandshakeStageError({
        stage: "output-directory",
      });
    },
  });

  assert.equal(exitCode, 2);
  const lines = stderr.text().split("\n");
  assert.equal(
    lines[0],
    "FAILED [HANDSHAKE_OUTPUT_DIRECTORY_IN_USE]",
  );
  assert.equal(
    lines[1],
    `Hint: ${FAILURE_HINTS.HANDSHAKE_OUTPUT_DIRECTORY_IN_USE} Directory: /artifacts/billy`,
  );
  assert.deepEqual(lines.slice(2), [""]);
  assert.match(lines[1], /new empty directory/);
  assert.equal(stdout.text(), "");
});

test("omits an unprintable output directory from the operator hint", async () => {
  const forgery = "PASS Agent ID: 0xdeadbeef";

  for (const codePoint of [
    0x0a,
    0x0d,
    0x1b,
    0x7f,
    0x85,
    0x9b,
    0x2028,
    0x2029,
  ]) {
    const separator = String.fromCodePoint(codePoint);
    const stderr = memoryStream();
    const label = codePoint.toString(16);

    const exitCode = await main({
      argv: ["--output", `/artifacts/one${separator}${forgery}`],
      env: {
        HANDSHAKE_INVITE_FILE: "/operator/invite.secret.json",
      },
      stdout: memoryStream().stream,
      stderr: stderr.stream,
      async run() {
        throw new HandshakeStageError({
          stage: "output-directory",
        });
      },
    });

    assert.equal(exitCode, 2, label);
    assert.deepEqual(
      stderr.text().split("\n"),
      [
        "FAILED [HANDSHAKE_OUTPUT_DIRECTORY_IN_USE]",
        `Hint: ${FAILURE_HINTS.HANDSHAKE_OUTPUT_DIRECTORY_IN_USE}`,
        "",
      ],
      label,
    );
    assert.equal(stderr.text().includes(forgery), false, label);
    assert.doesNotMatch(
      stderr.text(),
      /[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u2028\u2029]/u,
      label,
    );
  }
});

test("publishes one operator hint and default exit for every public failure code", () => {
  const fallbackCode = new HandshakeStageError({
    stage: "unknown-stage",
  }).code;

  assert.ok(HANDSHAKE_FAILURE_CODES.length >= 15);
  assert.equal(
    new Set(HANDSHAKE_FAILURE_CODES).size,
    HANDSHAKE_FAILURE_CODES.length,
  );
  assert.equal(
    HANDSHAKE_FAILURE_CODES.includes(fallbackCode),
    true,
  );
  for (const code of HANDSHAKE_FAILURE_CODES) {
    assert.match(code, /^HANDSHAKE_[A-Z0-9_]+$/);
    assert.equal(
      typeof HANDSHAKE_FAILURE_CATEGORIES[code],
      "string",
    );
  }

  assert.deepEqual(
    Object.keys(FAILURE_HINTS).sort(),
    [
      ...HANDSHAKE_FAILURE_CODES,
      "HANDSHAKE_UNEXPECTED_FAILURE",
    ].sort(),
  );
  assert.deepEqual(
    Object.keys(FAILURE_EXIT_CODES).sort(),
    Object.keys(FAILURE_HINTS).sort(),
  );
  for (const [code, hint] of Object.entries(FAILURE_HINTS)) {
    assert.equal(typeof hint, "string");
    assert.ok(hint.length > 0);
    assert.doesNotMatch(hint, /[\r\n]/);
    assert.equal(
      [2, 3, 4, 5].includes(FAILURE_EXIT_CODES[code]),
      true,
    );
  }
});

test("prints the machine-readable failure line before a single operator hint", async () => {
  const stdout = memoryStream();
  const stderr = memoryStream();

  const exitCode = await main({
    argv: [],
    env: {
      HANDSHAKE_INVITE_FILE: "/operator/invite.secret.json",
    },
    stdout: stdout.stream,
    stderr: stderr.stream,
    async run() {
      throw new HandshakeStageError({
        stage: "token-mint",
        category: "network",
        code: "HANDSHAKE_TOKEN_MINT_FAILED",
      });
    },
  });

  assert.equal(exitCode, 3);
  assert.deepEqual(stderr.text().split("\n"), [
    "FAILED [HANDSHAKE_TOKEN_MINT_FAILED]",
    `Hint: ${FAILURE_HINTS.HANDSHAKE_TOKEN_MINT_FAILED}`,
    "",
  ]);
  assert.equal(stdout.text(), "");
});

test("keeps a spaced forgery in the directory hint off stdout and off its own line", async () => {
  const forgery = "PASS Agent ID: 0xdeadbeef";
  const stdout = memoryStream();
  const stderr = memoryStream();

  const exitCode = await main({
    argv: ["--output", `/tmp/${forgery}`],
    env: {
      HANDSHAKE_INVITE_FILE: "/operator/invite.secret.json",
    },
    stdout: stdout.stream,
    stderr: stderr.stream,
    async run() {
      throw new HandshakeStageError({
        stage: "output-directory",
      });
    },
  });

  assert.equal(exitCode, 2);
  // The real PASS marker is a standalone stdout line, so an operator-controlled
  // directory label must never reach stdout or start a stderr line of its own.
  assert.equal(stdout.text(), "");
  const lines = stderr.text().split("\n");
  assert.equal(lines.length, 3);
  assert.equal(
    lines[0],
    "FAILED [HANDSHAKE_OUTPUT_DIRECTORY_IN_USE]",
  );
  assert.ok(lines[1].startsWith("Hint: "));
  assert.deepEqual(lines.slice(2), [""]);
  for (const line of lines) {
    assert.equal(line.startsWith("PASS"), false);
    assert.equal(line.startsWith("Agent ID:"), false);
  }
});

test("refuses a fresh registration that broadcast without a pre-broadcast intent", async (t) => {
  const outputDirectory = await temporaryDirectory(t);
  const calls = [];
  const adapters = createAdapters({ calls, captured: {} });
  adapters.registerIdentity = async (options) => {
    calls.push("register");
    assert.equal(Object.hasOwn(options, "intent"), false);
    // A broadcast that never recorded the pre-broadcast intent is exactly the
    // state the checkpoint contract exists to prevent.
    await options.onCheckpoint(registrationRecovery());
    return completedRegistration();
  };

  await assert.rejects(
    () =>
      runHandshake({
        invitationFile: "/operator/invite.secret.json",
        outputDirectory,
        adapters,
        now: clock(),
        randomUUID: () => RUN_ID,
      }),
    (error) => {
      assert.ok(error instanceof HandshakeStageError);
      assert.equal(error.stage, "registration");
      assert.equal(error.code, "HANDSHAKE_REGISTRATION_FAILED");
      return true;
    },
  );
  assert.equal(calls.includes("mint token"), false);
  assert.deepEqual(
    await readCheckpointFile(outputDirectory),
    registrationRecovery(),
  );
  await assert.rejects(
    () => stat(join(outputDirectory, "result.json")),
    { code: "ENOENT" },
  );
});

test("accepts one re-recorded intent when a resumed attempt never broadcast", async (t) => {
  const outputDirectory = await temporaryDirectory(t);
  const intent = registrationIntent();
  await writeCheckpointFile(outputDirectory, intent);
  const calls = [];
  const captured = {};
  const adapters = createAdapters({
    calls,
    captured,
    resumed: true,
  });
  const repricedIntent = registrationIntent({
    registerGas: "300000",
  });
  adapters.registerIdentity = async (options) => {
    calls.push("register");
    captured.registrationOptions = options;
    // The prior attempt recorded an intent and never broadcast, so the wallet
    // nonce is still zero and registerIdentity reprices and re-records one
    // fresh pre-broadcast intent before it broadcasts.
    await options.onCheckpoint(repricedIntent);
    await options.onCheckpoint(registrationRecovery());
    return completedRegistration();
  };

  const result = await runHandshake({
    invitationFile: "/operator/invite.secret.json",
    outputDirectory,
    adapters,
    now: clock(),
    randomUUID: () => RUN_ID,
  });

  assert.equal(result.status, "PASS");
  assert.deepEqual(captured.registrationOptions.intent, intent);
  assert.equal(calls.includes("finalize registration"), false);
  assert.deepEqual(
    await readCheckpointFile(outputDirectory),
    registrationRecovery(),
  );
});

test("documents the receipt completion bound the transport actually enforces", async () => {
  const [demo, mcpSource] = await Promise.all([
    readFile(join(REPOSITORY_ROOT, "DEMO.md"), "utf8"),
    readFile(join(REPOSITORY_ROOT, "src/mcp.mjs"), "utf8"),
  ]);
  const heading = "## Timing and bounded recovery";
  const headingIndex = demo.indexOf(heading);
  assert.notEqual(headingIndex, -1);
  const timing = demo
    .slice(headingIndex)
    .split("\n## ")[0]
    .replace(/\s+/g, " ");
  assert.match(
    timing,
    /A healthy live run normally takes 30–90 seconds\./,
  );

  // The worst case for one bounded transport call, taken from the constants
  // src/mcp.mjs actually enforces rather than from a repeated literal.
  const transportWorstCaseMs =
    declaredConstant(mcpSource, "DEFAULT_MAX_ATTEMPTS") *
      declaredConstant(
        mcpSource,
        "DEFAULT_REQUEST_TIMEOUT_MS",
      ) +
    declaredConstant(mcpSource, "MAX_TOTAL_RETRY_WAIT_MS");
  const documentedTransportMs = documentedMilliseconds(
    timing,
    /bounded transport call of at most ([\d.]+) seconds/,
  );
  assert.equal(documentedTransportMs, transportWorstCaseMs);

  const pending = submittedReceipt();
  const idleClient = {
    async completeAttestation(receipt) {
      return receipt;
    },
  };
  const documentedDeadlineMs = documentedMilliseconds(
    timing,
    /elapsed-time budget of ([\d.]+) seconds/,
  );

  // The documented budget must be the ceiling completeReceipt enforces: one
  // millisecond more is refused outright.
  await assert.rejects(
    () =>
      completeReceipt(idleClient, pending, {
        attempts: 1,
        deadlineMs: documentedDeadlineMs + 1,
        intervalMs: 0,
        now: () => 0,
        sleeper: async () => {},
      }),
    (error) => {
      assert.ok(error instanceof McpConfigurationError);
      return true;
    },
  );

  // ... and it is also the default: with one whole budget consumed per poll,
  // the deadline is crossed only at the top of the third iteration.
  let polls = 0;
  let elapsedMs = 0;
  await assert.rejects(
    () =>
      completeReceipt(
        {
          async completeAttestation(receipt) {
            polls += 1;
            elapsedMs += documentedDeadlineMs;
            return receipt;
          },
        },
        pending,
        {
          attempts: 8,
          intervalMs: 0,
          now: () => elapsedMs,
          sleeper: async () => {},
        },
      ),
    (error) => {
      assert.ok(error instanceof McpVerificationError);
      assert.equal(error.code, "MCP_RECEIPT_DEADLINE");
      return true;
    },
  );
  assert.equal(polls, 2);

  // The documented poll interval must be the default one too.
  const delays = [];
  const documentedIntervalMs = documentedMilliseconds(
    timing,
    /adds a ([\d.]+) second poll interval/,
  );
  await assert.rejects(
    () =>
      completeReceipt(idleClient, pending, {
        attempts: 1,
        now: () => 0,
        sleeper: async (milliseconds) => {
          delays.push(milliseconds);
        },
      }),
    (error) => {
      assert.ok(error instanceof McpVerificationError);
      assert.equal(error.code, "MCP_RECEIPT_PENDING");
      return true;
    },
  );
  assert.deepEqual(delays, [documentedIntervalMs]);

  const worstCaseMs =
    documentedDeadlineMs +
    documentedIntervalMs +
    transportWorstCaseMs;
  assert.equal(
    documentedMilliseconds(
      timing,
      /bounded at ([\d.]+) seconds/,
    ),
    worstCaseMs,
  );
  assert.ok(
    timing.includes(
      `${Math.floor(worstCaseMs / 60_000)} minutes ${Math.floor(
        (worstCaseMs % 60_000) / 1_000,
      )} seconds`,
    ),
    "DEMO.md must state the worst case in minutes and seconds",
  );

  const documentedExit = timing.match(
    /fails closed as `(HANDSHAKE_[A-Z_]+)` with exit `(\d+)`/,
  );
  assert.ok(documentedExit);
  assert.equal(
    documentedExit[1],
    "HANDSHAKE_RECEIPT_COMPLETION_FAILED",
  );
  assert.equal(
    Number(documentedExit[2]),
    FAILURE_EXIT_CODES.HANDSHAKE_RECEIPT_COMPLETION_FAILED,
  );
  assert.match(
    timing,
    /Do not stop the process at 90 seconds/,
  );
});
