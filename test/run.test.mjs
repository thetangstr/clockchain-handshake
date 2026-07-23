import assert from "node:assert/strict";
import {
  chmod,
  mkdir,
  mkdtemp,
  open,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { main } from "../bin/handshake-demo.mjs";
import {
  RESULT_SCHEMA,
  SINGLE_VALIDATOR_DISCLAIMER,
} from "../src/constants.mjs";
import { writeEvidence } from "../src/evidence.mjs";
import {
  McpNetworkError,
  McpVerificationError,
  assertCrossPartyVerification,
  completeReceipt,
} from "../src/mcp.mjs";
import {
  PartialRegistrationError,
  RegistrationNetworkError,
  buildRegistrationDocument,
  registrationDataUri,
} from "../src/registration.mjs";
import {
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
const EVENT_HASH = "44".repeat(32);
const INVITATION_CODE = "fresh-invitation-code-canary";
const MCP_TOKEN = `cc_${"t".repeat(48)}`;
const DISPLAY_NAME = "Billy";
const RECOVERY_FILE = ".handshake-registration-recovery.json";
const EVIDENCE_HISTORY_DIRECTORY =
  ".handshake-evidence-history";

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

function submittedReceipt() {
  return {
    schema: "clockchain.receipt/v1",
    network: "testnet",
    status: "degraded",
    agentId: "42",
    action: "trust_handshake",
    eventHash: EVENT_HASH,
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

function anchoredReceipt() {
  return {
    ...submittedReceipt(),
    status: "anchored",
    poolHealth: {
      totalNodes: 1,
      nodeParticipationPct: 100,
      degraded: false,
    },
    anchor: {
      ...submittedReceipt().anchor,
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
      return submittedReceipt();
    },
    async verifyReceipt(receipt) {
      calls.push("verify receipt");
      maybeFail("verify receipt");
      assert.deepEqual(receipt, anchoredReceipt());
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
            anchoredReceipt().anchor.assetReferenceId,
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
      assert.deepEqual(receipt, submittedReceipt());
      return anchoredReceipt();
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

test("archives a seeded PASS pair before an early failed rerun", async (t) => {
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
    failAt: "read invitation",
    resumed: false,
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
      assert.equal(error.stage, "invitation-read");
      return true;
    },
  );

  await assert.rejects(
    () => stat(join(outputDirectory, "result.json")),
    { code: "ENOENT" },
  );
  await assert.rejects(
    () => stat(join(outputDirectory, "RESULT.md")),
    { code: "ENOENT" },
  );
  const archive = join(
    outputDirectory,
    EVIDENCE_HISTORY_DIRECTORY,
    RUN_ID,
  );
  assert.equal(
    await readFile(join(archive, "result.json"), "utf8"),
    priorJson,
  );
  assert.equal(
    await readFile(join(archive, "RESULT.md"), "utf8"),
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
  assert.deepEqual(calls, ["read invitation"]);
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
