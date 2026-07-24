import { randomUUID as cryptoRandomUUID } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import {
  lstat,
  mkdir,
  open,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { isDeepStrictEqual } from "node:util";

import {
  CHAIN_ID,
  REGISTRY_ADDRESS,
  RESULT_SCHEMA,
  SINGLE_VALIDATOR_DISCLAIMER,
} from "./constants.mjs";
import {
  beginEvidenceAttempt,
  computeReceiptEventHash,
  EvidenceError,
  validatePassResult,
  writeEvidence,
} from "./evidence.mjs";
import {
  decryptInvitation,
  readSecretInvitation,
} from "./invitation.mjs";
import {
  McpError,
  assertAnchoredReceipt,
  assertCrossPartyVerification,
  assertReceiptVerification,
  assertResolvedIdentity,
  completeReceipt,
  createMcpClient,
  mintDemoToken,
} from "./mcp.mjs";
import { assertSecretFree } from "./redact.mjs";
import {
  PartialRegistrationError,
  RegistrationConfigurationError,
  RegistrationNetworkError,
  buildRegistrationDocument,
  finalizeIdentityRegistration,
  registerIdentity,
  registrationDataUri,
} from "./registration.mjs";

const RECOVERY_FILE_NAME =
  ".handshake-registration-recovery.json";
const RECOVERY_SCHEMA =
  "clockchain.handshake-registration-recovery/v1";
const MAX_RECOVERY_BYTES = 16_384;
const ATTESTATION_MARKER_FILE_NAME =
  ".handshake-attestation-started.json";
const ATTESTATION_MARKER_SCHEMA =
  "clockchain.handshake-attestation-started/v1";
const FINAL_EVIDENCE_FILE_NAMES = Object.freeze([
  "result.json",
  "RESULT.md",
]);
const MAX_ATTESTATION_MARKER_BYTES = 1_024;
const RECOVERY_FILE_OPEN_FLAGS =
  fsConstants.O_RDONLY |
  (fsConstants.O_NOFOLLOW ?? 0) |
  (fsConstants.O_NONBLOCK ?? 0);
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/i;
const TRANSACTION_PATTERN = /^0x[0-9a-f]{64}$/i;
const EVENT_HASH_PATTERN = /^[0-9a-f]{64}$/i;
const BASE_RECOVERY_KEYS = Object.freeze([
  "schema",
  "chainId",
  "registryAddress",
  "registryNamespace",
  "identityReference",
  "agentId",
  "address",
  "displayName",
  "registerTx",
  "registerBlock",
]);
const METADATA_RECOVERY_KEYS = Object.freeze([
  ...BASE_RECOVERY_KEYS,
  "metadataTx",
  "metadataNonce",
]);
const REGISTRATION_KEYS = Object.freeze([
  "chainId",
  "registryAddress",
  "registryNamespace",
  "identityReference",
  "agentId",
  "address",
  "displayName",
  "registerTx",
  "registerBlock",
  "metadataTx",
  "metadataBlock",
  "document",
]);
const POOL_HEALTH_KEYS = Object.freeze([
  "totalNodes",
  "nodeParticipationPct",
  "degraded",
]);
const ADAPTER_KEYS = new Set([
  "readSecretInvitation",
  "decryptInvitation",
  "registerIdentity",
  "finalizeIdentityRegistration",
  "mintDemoToken",
  "createMcpClient",
  "assertResolvedIdentity",
  "assertAnchoredReceipt",
  "assertReceiptVerification",
  "assertCrossPartyVerification",
  "completeReceipt",
  "writeEvidence",
  "beginEvidenceAttempt",
  "openRecoveryFile",
  "reportProgress",
]);
const CATEGORY_VALUES = new Set([
  "configuration",
  "network",
  "protocol",
  "verification",
  "redaction",
]);
const STAGE_DEFINITIONS = Object.freeze({
  configuration: {
    category: "configuration",
    code: "HANDSHAKE_CONFIGURATION",
    message: "Handshake configuration is invalid.",
  },
  "invitation-read": {
    category: "configuration",
    code: "HANDSHAKE_INVITATION_READ_FAILED",
    message: "Handshake invitation could not be read safely.",
  },
  "invitation-decryption": {
    category: "configuration",
    code: "HANDSHAKE_INVITATION_DECRYPTION_FAILED",
    message: "Handshake invitation could not be authenticated.",
  },
  "registration-recovery": {
    category: "configuration",
    code: "HANDSHAKE_REGISTRATION_RECOVERY_FAILED",
    message: "Handshake registration recovery failed.",
  },
  registration: {
    category: "protocol",
    code: "HANDSHAKE_REGISTRATION_FAILED",
    message: "Handshake identity registration failed.",
  },
  "token-mint": {
    category: "network",
    code: "HANDSHAKE_TOKEN_MINT_FAILED",
    message: "Handshake Clockchain token acquisition failed.",
  },
  "mcp-client": {
    category: "configuration",
    code: "HANDSHAKE_MCP_CLIENT_FAILED",
    message: "Handshake Clockchain client setup failed.",
  },
  "identity-resolution": {
    category: "verification",
    code: "HANDSHAKE_IDENTITY_RESOLUTION_FAILED",
    message: "Handshake identity resolution failed.",
  },
  timestamp: {
    category: "network",
    code: "HANDSHAKE_TIMESTAMP_FAILED",
    message: "Handshake Clockchain timestamp acquisition failed.",
  },
  attestation: {
    category: "protocol",
    code: "HANDSHAKE_ATTESTATION_FAILED",
    message: "Handshake receipt submission failed.",
  },
  "receipt-completion": {
    category: "verification",
    code: "HANDSHAKE_RECEIPT_COMPLETION_FAILED",
    message: "Handshake receipt did not reach a verified anchor.",
  },
  "receipt-verification": {
    category: "verification",
    code: "HANDSHAKE_RECEIPT_VERIFICATION_FAILED",
    message: "Handshake receipt verification failed.",
  },
  "cross-party-verification": {
    category: "verification",
    code: "HANDSHAKE_CROSS_PARTY_VERIFICATION_FAILED",
    message: "Handshake cross-party verification failed.",
  },
  evidence: {
    category: "verification",
    code: "HANDSHAKE_EVIDENCE_FAILED",
    message: "Handshake evidence validation or persistence failed.",
  },
});
const DEFAULT_ADAPTERS = Object.freeze({
  readSecretInvitation,
  decryptInvitation,
  registerIdentity,
  finalizeIdentityRegistration,
  mintDemoToken,
  createMcpClient,
  assertResolvedIdentity,
  assertAnchoredReceipt,
  assertReceiptVerification,
  assertCrossPartyVerification,
  completeReceipt,
  writeEvidence,
  beginEvidenceAttempt,
  openRecoveryFile: open,
  reportProgress: async () => {},
});

class CheckpointError extends Error {
  constructor(category) {
    super("Registration recovery checkpoint operation failed.");
    this.name = "CheckpointError";
    this.category = category;
    this.code = "HANDSHAKE_REGISTRATION_RECOVERY";
  }
}

export class HandshakeStageError extends Error {
  constructor({ stage, category, code }) {
    const definition = STAGE_DEFINITIONS[stage];
    const safeCategory = CATEGORY_VALUES.has(category)
      ? category
      : definition?.category ?? "protocol";
    const safeCode =
      typeof code === "string" &&
      /^HANDSHAKE_[A-Z0-9_]+$/.test(code)
        ? code
        : definition?.code ?? "HANDSHAKE_STAGE_FAILED";

    super(definition?.message ?? "Handshake stage failed.");
    this.name = "HandshakeStageError";
    this.stage =
      typeof stage === "string" &&
      Object.hasOwn(STAGE_DEFINITIONS, stage)
        ? stage
        : "configuration";
    this.category = safeCategory;
    this.code = safeCode;
  }
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object") {
    return false;
  }

  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasExactKeys(value, expectedKeys) {
  if (!isPlainObject(value)) {
    return false;
  }

  const keys = Reflect.ownKeys(value);
  return (
    keys.length === expectedKeys.length &&
    expectedKeys.every((key) => keys.includes(key))
  );
}

function addressesEqual(left, right) {
  return (
    ADDRESS_PATTERN.test(left) &&
    ADDRESS_PATTERN.test(right) &&
    left.toLowerCase() === right.toLowerCase()
  );
}

function typedCategory(error) {
  if (
    error instanceof McpError ||
    error instanceof EvidenceError ||
    error instanceof CheckpointError ||
    error instanceof PartialRegistrationError ||
    error instanceof RegistrationConfigurationError ||
    error instanceof RegistrationNetworkError
  ) {
    return CATEGORY_VALUES.has(error.category)
      ? error.category
      : undefined;
  }
  return undefined;
}

function stageError(stage, error) {
  if (error instanceof HandshakeStageError) {
    return error;
  }

  const definition = STAGE_DEFINITIONS[stage] ??
    STAGE_DEFINITIONS.configuration;
  return new HandshakeStageError({
    stage,
    category: typedCategory(error) ?? definition.category,
    code: definition.code,
  });
}

async function invokeStage(stage, operation) {
  try {
    return await operation();
  } catch (error) {
    throw stageError(stage, error);
  }
}

function validatePath(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 4_096 &&
    !value.includes("\0")
  );
}

function mergeAdapters(adapters) {
  if (!isPlainObject(adapters)) {
    throw stageError("configuration");
  }

  const active = { ...DEFAULT_ADAPTERS };
  for (const key of Reflect.ownKeys(adapters)) {
    const descriptor = Object.getOwnPropertyDescriptor(
      adapters,
      key,
    );
    if (
      typeof key !== "string" ||
      !ADAPTER_KEYS.has(key) ||
      !descriptor ||
      !Object.hasOwn(descriptor, "value") ||
      typeof descriptor.value !== "function"
    ) {
      throw stageError("configuration");
    }
    active[key] = descriptor.value;
  }

  return active;
}

function validateOptions({
  invitationFile,
  outputDirectory,
  adapters,
  now,
  randomUUID,
}) {
  if (
    !validatePath(invitationFile) ||
    !validatePath(outputDirectory) ||
    typeof now !== "function" ||
    typeof randomUUID !== "function"
  ) {
    throw stageError("configuration");
  }

  return mergeAdapters(adapters);
}

function readClock(now) {
  let value;
  try {
    value = now();
  } catch {
    throw stageError("configuration");
  }
  if (
    !(value instanceof Date) ||
    !Number.isFinite(value.getTime())
  ) {
    throw stageError("configuration");
  }
  return new Date(value.getTime());
}

function createRunId(randomUUID) {
  let value;
  try {
    value = randomUUID();
  } catch {
    throw stageError("configuration");
  }
  if (
    typeof value !== "string" ||
    !UUID_PATTERN.test(value)
  ) {
    throw stageError("configuration");
  }
  return value;
}

function validateRecoveryValue(
  recovery,
  {
    expectedAddress,
    expectedDisplayName,
    category = "protocol",
  },
) {
  const hasMetadataTx =
    isPlainObject(recovery) &&
    Object.hasOwn(recovery, "metadataTx");
  const hasMetadataNonce =
    isPlainObject(recovery) &&
    Object.hasOwn(recovery, "metadataNonce");
  const keys =
    hasMetadataTx && hasMetadataNonce
      ? METADATA_RECOVERY_KEYS
      : BASE_RECOVERY_KEYS;

  if (
    hasMetadataTx !== hasMetadataNonce ||
    !hasExactKeys(recovery, keys) ||
    recovery.schema !== RECOVERY_SCHEMA ||
    recovery.chainId !== CHAIN_ID ||
    recovery.registryAddress !== REGISTRY_ADDRESS ||
    recovery.registryNamespace !==
      `eip155:${CHAIN_ID}:${REGISTRY_ADDRESS}` ||
    typeof recovery.agentId !== "string" ||
    !DECIMAL_PATTERN.test(recovery.agentId) ||
    recovery.identityReference !==
      `${recovery.registryNamespace}:${recovery.agentId}` ||
    !addressesEqual(recovery.address, expectedAddress) ||
    recovery.displayName !== expectedDisplayName ||
    typeof recovery.displayName !== "string" ||
    recovery.displayName.trim().length === 0 ||
    recovery.displayName.length > 128 ||
    !TRANSACTION_PATTERN.test(recovery.registerTx) ||
    typeof recovery.registerBlock !== "string" ||
    !DECIMAL_PATTERN.test(recovery.registerBlock) ||
    (hasMetadataTx &&
      (!TRANSACTION_PATTERN.test(recovery.metadataTx) ||
        !Number.isSafeInteger(recovery.metadataNonce) ||
        recovery.metadataNonce < 0))
  ) {
    throw new CheckpointError(category);
  }

  return { ...recovery };
}

function sameFile(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.mode === right.mode
  );
}

async function readRecoveryCheckpoint({
  outputDirectory,
  expectedAddress,
  expectedDisplayName,
  openFile,
}) {
  const path = join(outputDirectory, RECOVERY_FILE_NAME);
  let fileHandle;
  let failure;
  let result = null;

  try {
    fileHandle = await openFile(
      path,
      RECOVERY_FILE_OPEN_FLAGS,
    );
    const metadata = await fileHandle.stat();
    if (!metadata.isFile() || metadata.size > MAX_RECOVERY_BYTES) {
      throw new CheckpointError("configuration");
    }
    const serialized = await fileHandle.readFile("utf8");
    const finalMetadata = await fileHandle.stat();
    if (
      Buffer.byteLength(serialized, "utf8") >
        MAX_RECOVERY_BYTES ||
      !sameFile(metadata, finalMetadata)
    ) {
      throw new CheckpointError("configuration");
    }

    let recovery;
    try {
      recovery = JSON.parse(serialized);
    } catch {
      throw new CheckpointError("configuration");
    }
    result = validateRecoveryValue(recovery, {
      expectedAddress,
      expectedDisplayName,
      category: "configuration",
    });
  } catch (error) {
    if (error?.code !== "ENOENT") {
      failure =
        error instanceof CheckpointError
          ? error
          : new CheckpointError("configuration");
    }
  } finally {
    if (fileHandle) {
      try {
        await fileHandle.close();
      } catch {
        failure ??= new CheckpointError("configuration");
      }
    }
  }

  if (failure) {
    throw failure;
  }
  return result;
}

async function persistRecoveryCheckpoint({
  outputDirectory,
  recovery,
  expectedAddress,
  expectedDisplayName,
  canaries,
}) {
  const validated = validateRecoveryValue(recovery, {
    expectedAddress,
    expectedDisplayName,
  });
  try {
    assertSecretFree(validated, canaries);
  } catch {
    throw new CheckpointError("redaction");
  }

  const serialized = `${JSON.stringify(validated, null, 2)}\n`;
  const path = join(outputDirectory, RECOVERY_FILE_NAME);
  const temporaryPath = join(
    outputDirectory,
    `.${RECOVERY_FILE_NAME}.${cryptoRandomUUID()}.tmp`,
  );

  try {
    await mkdir(outputDirectory, { recursive: true });
    await writeFile(temporaryPath, serialized, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o644,
    });
    const handle = await open(
      temporaryPath,
      RECOVERY_FILE_OPEN_FLAGS,
    );
    let persisted;
    try {
      persisted = JSON.parse(await handle.readFile("utf8"));
    } finally {
      await handle.close();
    }
    const revalidated = validateRecoveryValue(persisted, {
      expectedAddress,
      expectedDisplayName,
    });
    if (!isDeepStrictEqual(revalidated, validated)) {
      throw new CheckpointError("verification");
    }
    await rename(temporaryPath, path);
    return validated;
  } catch (error) {
    if (error instanceof CheckpointError) {
      throw error;
    }
    throw new CheckpointError("configuration");
  } finally {
    await rm(temporaryPath, { force: true }).catch(() => {});
  }
}

async function prepareOutputDirectory(outputDirectory) {
  const probePath = join(
    outputDirectory,
    `.handshake-output-probe.${cryptoRandomUUID()}.tmp`,
  );

  try {
    await mkdir(outputDirectory, { recursive: true });
    await writeFile(probePath, "", {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
  } catch {
    throw new CheckpointError("configuration");
  } finally {
    await rm(probePath, { force: true }).catch(() => {});
  }
}

async function assertAttestationNotStarted(outputDirectory) {
  try {
    await lstat(
      join(outputDirectory, ATTESTATION_MARKER_FILE_NAME),
    );
  } catch (error) {
    if (error?.code === "ENOENT") {
      return;
    }
    throw error;
  }
  throw new Error("Handshake attestation has already started.");
}

async function assertFinalEvidenceAbsent(outputDirectory) {
  for (const fileName of FINAL_EVIDENCE_FILE_NAMES) {
    try {
      await lstat(join(outputDirectory, fileName));
    } catch (error) {
      if (error?.code === "ENOENT") {
        continue;
      }
      throw error;
    }
    throw new Error(
      `Handshake final evidence already exists: ${fileName}.`,
    );
  }
}

async function createAttestationMarker({
  outputDirectory,
  runId,
  registration,
  expectedEventHash,
  canaries,
}) {
  const marker = {
    schema: ATTESTATION_MARKER_SCHEMA,
    runId,
    agentId: registration.agentId,
    identityReference: registration.identityReference,
    expectedEventHash,
  };
  if (
    marker.agentId.length > 128 ||
    marker.identityReference.length > 512 ||
    !EVENT_HASH_PATTERN.test(marker.expectedEventHash)
  ) {
    throw new Error("Handshake attestation marker is invalid.");
  }
  assertSecretFree(marker, canaries);
  const serialized = `${JSON.stringify(marker, null, 2)}\n`;
  if (
    Buffer.byteLength(serialized, "utf8") >
    MAX_ATTESTATION_MARKER_BYTES
  ) {
    throw new Error("Handshake attestation marker is invalid.");
  }
  await writeFile(
    join(outputDirectory, ATTESTATION_MARKER_FILE_NAME),
    serialized,
    {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    },
  );
}

function validateRegistrationEvidence(
  registration,
  invitation,
) {
  if (
    !hasExactKeys(registration, REGISTRATION_KEYS) ||
    registration.chainId !== CHAIN_ID ||
    registration.registryAddress !== REGISTRY_ADDRESS ||
    registration.registryNamespace !==
      `eip155:${CHAIN_ID}:${REGISTRY_ADDRESS}` ||
    typeof registration.agentId !== "string" ||
    !DECIMAL_PATTERN.test(registration.agentId) ||
    registration.identityReference !==
      `${registration.registryNamespace}:${registration.agentId}` ||
    !addressesEqual(registration.address, invitation.address) ||
    registration.displayName !== invitation.displayName ||
    !TRANSACTION_PATTERN.test(registration.registerTx) ||
    !TRANSACTION_PATTERN.test(registration.metadataTx) ||
    typeof registration.registerBlock !== "string" ||
    !DECIMAL_PATTERN.test(registration.registerBlock) ||
    typeof registration.metadataBlock !== "string" ||
    !DECIMAL_PATTERN.test(registration.metadataBlock)
  ) {
    throw new Error("Registration evidence is invalid.");
  }

  let expectedDocument;
  try {
    expectedDocument = buildRegistrationDocument({
      displayName: invitation.displayName,
      agentId: BigInt(registration.agentId),
    });
  } catch {
    throw new Error("Registration evidence is invalid.");
  }
  if (!isDeepStrictEqual(registration.document, expectedDocument)) {
    throw new Error("Registration evidence is invalid.");
  }
  return registration;
}

function validateClient(client) {
  const methods = [
    "resolveAgent",
    "getTimestamp",
    "attestAction",
    "verifyReceipt",
    "verifyCrossParty",
  ];
  if (
    client === null ||
    (typeof client !== "object" &&
      typeof client !== "function") ||
    methods.some((method) => typeof client[method] !== "function")
  ) {
    throw new Error("Clockchain client is invalid.");
  }
  return client;
}

function validateTimestamp(timestamp) {
  if (!isPlainObject(timestamp)) {
    throw new Error("Clockchain timestamp is invalid.");
  }

  const time = [
    timestamp.madMarzulloTime,
    timestamp.systemTime,
  ].find(
    (value) =>
      typeof value === "string" &&
      value.length > 0 &&
      value.trim() === value &&
      !/[\u0000-\u001f\u007f-\u009f]/.test(value),
  );
  if (time === undefined) {
    throw new Error("Clockchain timestamp is invalid.");
  }
  return timestamp;
}

function receiptInputs(runId, identityReference) {
  return {
    runId,
    identityReference,
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

function captureSubmissionPoolHealth(receipt) {
  const poolHealth = receipt?.poolHealth;
  if (
    !hasExactKeys(poolHealth, POOL_HEALTH_KEYS) ||
    !Number.isSafeInteger(poolHealth.totalNodes) ||
    poolHealth.totalNodes < 0 ||
    typeof poolHealth.nodeParticipationPct !== "number" ||
    !Number.isFinite(poolHealth.nodeParticipationPct) ||
    poolHealth.nodeParticipationPct < 0 ||
    poolHealth.nodeParticipationPct > 100 ||
    typeof poolHealth.degraded !== "boolean" ||
    poolHealth.degraded !==
      (poolHealth.nodeParticipationPct === 0)
  ) {
    throw new Error("Clockchain submission pool health is invalid.");
  }
  return {
    totalNodes: poolHealth.totalNodes,
    nodeParticipationPct: poolHealth.nodeParticipationPct,
    degradedAtSubmission: poolHealth.degraded,
  };
}

function assertReceiptBinding(
  receipt,
  {
    agentId,
    expectedEventHash,
    inputs,
    outputs,
    initialEventHash,
  },
) {
  if (
    !isPlainObject(receipt) ||
    receipt.agentId !== agentId ||
    receipt.action !== "trust_handshake" ||
    !isPlainObject(receipt.payload) ||
    !isDeepStrictEqual(receipt.payload.inputs, inputs) ||
    !isDeepStrictEqual(receipt.payload.outputs, outputs) ||
    typeof receipt.eventHash !== "string" ||
    !EVENT_HASH_PATTERN.test(receipt.eventHash) ||
    receipt.eventHash !== expectedEventHash ||
    (initialEventHash !== undefined &&
      receipt.eventHash !== initialEventHash)
  ) {
    throw new Error("Clockchain receipt binding is invalid.");
  }
  return receipt;
}

function validateAnchoredIdentifiers(receipt) {
  if (
    !UUID_PATTERN.test(receipt.anchor?.ledgerId) ||
    typeof receipt.anchor.blockHeight !== "string" ||
    !DECIMAL_PATTERN.test(receipt.anchor.blockHeight) ||
    typeof receipt.anchor.consensusTime !== "string" ||
    receipt.anchor.consensusTime.length === 0 ||
    receipt.anchor.consensusTime.trim() !==
      receipt.anchor.consensusTime ||
    /[\u0000-\u001f\u007f-\u009f]/.test(
      receipt.anchor.consensusTime,
    )
  ) {
    throw new Error("Clockchain anchor identifiers are invalid.");
  }
  return receipt;
}

async function report(activeAdapters, stage) {
  await invokeStage("configuration", () =>
    activeAdapters.reportProgress(Object.freeze({ stage })),
  );
}

async function completeRegistration({
  activeAdapters,
  checkpoint,
  decrypted,
  outputDirectory,
  canaries,
}) {
  const checkpointWriter = async (recovery) =>
    persistRecoveryCheckpoint({
      outputDirectory,
      recovery,
      expectedAddress: decrypted.address,
      expectedDisplayName: decrypted.displayName,
      canaries,
    });

  if (checkpoint) {
    await report(
      activeAdapters,
      "registration-recovery-loaded",
    );
    try {
      return await activeAdapters.finalizeIdentityRegistration({
        privateKey: decrypted.privateKey,
        expectedAddress: decrypted.address,
        displayName: decrypted.displayName,
        recovery: checkpoint,
        onCheckpoint: checkpointWriter,
      });
    } catch (error) {
      if (error instanceof PartialRegistrationError) {
        throw error;
      }
      throw stageError("registration", error);
    }
  }

  let checkpointWrites = 0;
  const requiredCheckpointWriter = async (recovery) => {
    await checkpointWriter(recovery);
    checkpointWrites += 1;
  };
  try {
    const registration = await activeAdapters.registerIdentity({
      privateKey: decrypted.privateKey,
      expectedAddress: decrypted.address,
      displayName: decrypted.displayName,
      onCheckpoint: requiredCheckpointWriter,
    });
    if (checkpointWrites === 0) {
      throw stageError("registration");
    }
    return registration;
  } catch (error) {
    if (error instanceof PartialRegistrationError) {
      throw error;
    }
    if (
      error instanceof HandshakeStageError &&
      error.stage === "registration"
    ) {
      throw error;
    }
    throw stageError("registration", error);
  }
}

async function persistPartialRecovery({
  error,
  outputDirectory,
  decrypted,
  canaries,
}) {
  if (!(error instanceof PartialRegistrationError)) {
    return;
  }
  await invokeStage("registration-recovery", () =>
    persistRecoveryCheckpoint({
      outputDirectory,
      recovery: error.recovery,
      expectedAddress: decrypted.address,
      expectedDisplayName: decrypted.displayName,
      canaries,
    }),
  );
}

export async function runHandshake({
  invitationFile,
  outputDirectory = process.cwd(),
  adapters = {},
  now = () => new Date(),
  randomUUID = cryptoRandomUUID,
}) {
  const activeAdapters = validateOptions({
    invitationFile,
    outputDirectory,
    adapters,
    now,
    randomUUID,
  });
  await invokeStage("attestation", () =>
    assertAttestationNotStarted(outputDirectory),
  );
  await invokeStage("evidence", () =>
    assertFinalEvidenceAbsent(outputDirectory),
  );
  const started = readClock(now);
  const runId = createRunId(randomUUID);

  await invokeStage("evidence", () =>
    prepareOutputDirectory(outputDirectory),
  );
  await invokeStage("evidence", () =>
    assertFinalEvidenceAbsent(outputDirectory),
  );
  await invokeStage("evidence", () =>
    activeAdapters.beginEvidenceAttempt({
      directory: outputDirectory,
      runId,
    }),
  );
  await report(activeAdapters, "invitation-read");
  const invitation = await invokeStage(
    "invitation-read",
    () => activeAdapters.readSecretInvitation(invitationFile),
  );
  await report(activeAdapters, "invitation-decrypted");
  const decrypted = await invokeStage(
    "invitation-decryption",
    () =>
      activeAdapters.decryptInvitation(
        invitation?.bundle,
        invitation?.code,
      ),
  );
  const registrationCanaries = [
    invitation?.code,
    decrypted?.privateKey,
  ];
  if (
    registrationCanaries.some(
      (value) => typeof value !== "string" || value.length === 0,
    ) ||
    !addressesEqual(decrypted?.address, invitation?.bundle?.address) ||
    decrypted?.displayName !== invitation?.bundle?.displayName
  ) {
    throw stageError("invitation-decryption");
  }

  const checkpoint = await invokeStage(
    "registration-recovery",
    () =>
      readRecoveryCheckpoint({
        outputDirectory,
        expectedAddress: decrypted.address,
        expectedDisplayName: decrypted.displayName,
        openFile: activeAdapters.openRecoveryFile,
      }),
  );

  await report(
    activeAdapters,
    checkpoint
      ? "registration-resumed"
      : "registration-started",
  );
  let registration;
  try {
    registration = await completeRegistration({
      activeAdapters,
      checkpoint,
      decrypted,
      outputDirectory,
      canaries: registrationCanaries,
    });
  } catch (error) {
    const partial =
      error instanceof HandshakeStageError
        ? undefined
        : error;
    if (partial instanceof PartialRegistrationError) {
      await persistPartialRecovery({
        error: partial,
        outputDirectory,
        decrypted,
        canaries: registrationCanaries,
      });
    }
    throw stageError("registration", error);
  }
  registration = await invokeStage("registration", () =>
    validateRegistrationEvidence(registration, decrypted),
  );
  await report(activeAdapters, "registration-complete");

  const token = await invokeStage("token-mint", () =>
    activeAdapters.mintDemoToken({
      subject: `handshake-${runId}`,
    }),
  );
  if (typeof token !== "string" || token.length === 0) {
    throw stageError("token-mint");
  }
  await report(activeAdapters, "token-minted");

  const client = await invokeStage("mcp-client", () =>
    validateClient(
      activeAdapters.createMcpClient({ token }),
    ),
  );
  const expectedAgentUri = registrationDataUri(
    registration.document,
  );
  const resolved = await invokeStage(
    "identity-resolution",
    async () => {
      const identity = await client.resolveAgent(
        registration.agentId,
      );
      return activeAdapters.assertResolvedIdentity(identity, {
        agentId: registration.agentId,
        owner: registration.address,
        agentURI: expectedAgentUri,
      });
    },
  );
  if (!isPlainObject(resolved)) {
    throw stageError("identity-resolution");
  }
  await report(activeAdapters, "identity-resolved");

  await invokeStage("timestamp", async () =>
    validateTimestamp(await client.getTimestamp()),
  );
  await report(activeAdapters, "timestamp-received");

  const inputs = receiptInputs(
    runId,
    registration.identityReference,
  );
  const outputs = receiptOutputs();
  const expectedEventHash = await invokeStage(
    "attestation",
    () =>
      computeReceiptEventHash({
        agentId: registration.agentId,
        action: "trust_handshake",
        inputs,
        outputs,
      }),
  );
  const submitted = await invokeStage(
    "attestation",
    async () => {
      await createAttestationMarker({
        outputDirectory,
        runId,
        registration,
        expectedEventHash,
        canaries: [
          ...registrationCanaries,
          token,
        ],
      });
      const receipt = await client.attestAction({
        agent_id: registration.agentId,
        action: "trust_handshake",
        inputs,
        outputs,
        wait: false,
        idempotency_key: runId,
        allow_degraded: true,
      });
      return assertReceiptBinding(receipt, {
        agentId: registration.agentId,
        expectedEventHash,
        inputs,
        outputs,
      });
    },
  );
  const submissionPoolHealth = await invokeStage(
    "attestation",
    () => captureSubmissionPoolHealth(submitted),
  );
  await report(activeAdapters, "receipt-created");

  const receipt = await invokeStage(
    "receipt-completion",
    async () => {
      const completed = await activeAdapters.completeReceipt(
        client,
        submitted,
      );
      await activeAdapters.assertAnchoredReceipt(completed);
      assertReceiptBinding(completed, {
        agentId: registration.agentId,
        expectedEventHash,
        inputs,
        outputs,
        initialEventHash: submitted.eventHash,
      });
      return validateAnchoredIdentifiers(completed);
    },
  );
  await report(activeAdapters, "receipt-anchored");

  const receiptVerification = await invokeStage(
    "receipt-verification",
    async () => {
      const verification = await client.verifyReceipt(receipt);
      return activeAdapters.assertReceiptVerification(
        verification,
      );
    },
  );
  await report(activeAdapters, "receipt-verified");

  const crossParty = await invokeStage(
    "cross-party-verification",
    async () => {
      const verification = await client.verifyCrossParty({
        ledgerId: receipt.anchor.ledgerId,
        blockHeight: receipt.anchor.blockHeight,
        hash: expectedEventHash,
      });
      return activeAdapters.assertCrossPartyVerification(
        verification,
        {
          ledgerId: receipt.anchor.ledgerId,
          blockHeight: receipt.anchor.blockHeight,
          anchoredHash: expectedEventHash,
          assetReferenceId:
            receipt.anchor.assetReferenceId,
        },
      );
    },
  );
  await report(activeAdapters, "cross-party-verified");

  const completed = readClock(now);
  const elapsedMs = completed.getTime() - started.getTime();
  if (!Number.isSafeInteger(elapsedMs) || elapsedMs < 0) {
    throw stageError("configuration");
  }
  const result = {
    schema: RESULT_SCHEMA,
    status: "PASS",
    runId,
    startedAt: started.toISOString(),
    completedAt: completed.toISOString(),
    elapsedMs,
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
      reference: registration.identityReference,
      agentId: registration.agentId,
      displayName: registration.displayName,
      owner: registration.address,
      registerTx: registration.registerTx,
      metadataTx: registration.metadataTx,
    },
    clockchain: {
      ledgerId: receipt.anchor.ledgerId,
      blockHeight: receipt.anchor.blockHeight,
      consensusTime: receipt.anchor.consensusTime,
      receiptStatus: receipt.status,
      receiptVerified: receiptVerification.match,
      crossPartyVerified: true,
      verifiedAgainst: receiptVerification.verifiedAgainst,
      keyless: crossParty.onChain.keyless,
      poolHealth: submissionPoolHealth,
    },
    disclaimer: SINGLE_VALIDATOR_DISCLAIMER,
  };

  await invokeStage("evidence", () => validatePassResult(result));
  const canaries = [
    invitation.code,
    decrypted.privateKey,
    token,
  ];
  await report(activeAdapters, "evidence-writing");
  await invokeStage("evidence", () =>
    activeAdapters.writeEvidence({
      directory: outputDirectory,
      result,
      canaries,
    }),
  );
  await report(activeAdapters, "evidence-written");
  return result;
}
