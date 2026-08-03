import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { closeSync, constants as fsConstants, writeSync } from "node:fs";
import {
  lstat,
  mkdir,
  open,
} from "node:fs/promises";
import {
  dirname,
  join,
} from "node:path";
import { fileURLToPath } from "node:url";
import { promisify, types } from "node:util";

import {
  createPublicClient,
  http,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";

import {
  canonicalBytes,
  MAX_CANONICAL_STRING_LENGTH,
} from "./canonical.mjs";
import {
  operatorPublicKeyPath,
  verifyDescriptorEnvelope,
} from "./descriptor.mjs";
import {
  PARTY_RESULT_SCHEMA,
  partySignatureBytes,
} from "./evidence.mjs";
import {
  authoritativeTriple,
  buildAcceptance,
  buildAcknowledgment,
  buildProposal,
} from "./messages.mjs";
import {
  ProtocolFailureError,
  createRunnerStateMachine,
  recoverAnchoredProposal,
} from "./protocol.mjs";
import { sessionKey } from "./refid.mjs";
import {
  MAX_POLL_DURATION_MS,
  MIN_POLL_INTERVAL_MS,
  closePinnedOutputDirectory,
  pinOutputDirectory,
  pollForTransition,
  publishPartyEvidence,
  writeOrAdoptTransition,
} from "./runner.mjs";
import {
  McpNetworkError,
  McpRateLimitedError,
  createMcpClient,
} from "./clockchain.mjs";
import {
  decryptInvitation,
  readSecretInvitation,
} from "../invitation.mjs";
import { ERC8004_ABI } from "./registration.mjs";
import { RPC_URL } from "./constants.mjs";

export const ROLE_RESULT_KEYS = Object.freeze([
  "ackObserved",
  "deadlineMs",
  "localVerdict",
  "paymentMoved",
  "role",
  "state",
  "transitions",
]);
export const ROLE_CLI_ARGUMENTS = Object.freeze([
  "--descriptor",
  "--invitation",
  "--clockchain-token-file",
  "--output",
]);
export const ROLE_RISK_FLAG =
  "--i-understand-this-writes-to-clockchain";
export const ROLE_REPOSITORY_ROOT = dirname(
  dirname(dirname(fileURLToPath(import.meta.url))),
);
export const ROLE_READY_SCHEMA =
  "clockchain.bilateral-role-ready/v1";
const ROLE_READY_ENV = Object.freeze({
  fd: "CLOCKCHAIN_BILATERAL_ROLE_READY_FD",
  nonce: "CLOCKCHAIN_BILATERAL_ROLE_READY_NONCE",
  schema: "CLOCKCHAIN_BILATERAL_ROLE_READY_SCHEMA",
});

const SIGNATURE_PATTERN = /^0x[0-9a-f]{130}$/;
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const POOL_HEALTH = Object.freeze({
  degradedAtSubmission: true,
  nodeParticipationPct: "0.0",
  totalNodes: "1.0",
});
const RENDEZVOUS = Object.freeze({
  channel: "derived-reference-id",
  degradedAtSubmission: true,
  tenancy: "unknown",
});
const ROLE_INPUT_KEYS = new Set([
  "acknowledgmentPollDurationMs",
  "canaries",
  "client",
  "descriptorEnvelope",
  "fileSystem",
  "jitter",
  "monotonicNow",
  "now",
  "outputDirectory",
  "ownerOf",
  "notifyReady",
  "proposalPollDurationMs",
  "publishEvidence",
  "repositoryPublicKey",
  "signMessage",
  "sleeper",
]);
const execFileAsync = promisify(execFile);
const READ_FLAGS =
  fsConstants.O_RDONLY |
  (fsConstants.O_NOFOLLOW ?? 0) |
  (fsConstants.O_NONBLOCK ?? 0);
const MAX_DESCRIPTOR_BYTES = 1024 * 1024;
const MAX_PROMPT_BYTES = 1024 * 1024;
const MAX_TOKEN_BYTES = 4096;
const MAX_EVIDENCE_CANARY_LENGTH =
  MAX_CANONICAL_STRING_LENGTH;
const TOKEN_PATTERN = /^[!-~]{1,4096}$/;
const ROLE_PROMPT_PATHS = Object.freeze({
  payer: "prompts/run-payer-bilateral-demo.md",
  payee: "prompts/run-requestor-bilateral-demo.md",
});
const BUILDER_VALUE_KEYS = Object.freeze([
  "clockchainTokenPath",
  "descriptorPath",
  "invitationPath",
  "outputDirectory",
]);
const DEFAULT_BUILDER_FILE_SYSTEM = Object.freeze({
  lstat,
  mkdir,
  open,
});
const BUILDER_DEPENDENCY_KEYS = new Set([
  "createClockchainClient",
  "createIdentityClient",
  "decryptInvitation",
  "fileSystem",
  "loadInvitation",
  "repositoryPromptResolver",
  "repositoryPublicKeyResolver",
  "repositoryStateResolver",
  "verifyEnvelope",
]);

function terminal(code = "FAILED") {
  return new ProtocolFailureError(
    "Bilateral role execution failed closed.",
    code,
  );
}

function isProtocolFailure(error) {
  try {
    return error instanceof ProtocolFailureError;
  } catch {
    return false;
  }
}

function isPlainObject(value) {
  try {
    return (
      value !== null &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      !types.isProxy(value) &&
      Object.getPrototypeOf(value) === Object.prototype
    );
  } catch {
    return false;
  }
}

function exactDataSnapshot(value, keys) {
  if (!isPlainObject(value)) {
    return null;
  }
  let ownKeys;
  try {
    ownKeys = Reflect.ownKeys(value);
  } catch {
    return null;
  }
  if (
    ownKeys.length !== keys.length ||
    ownKeys.some((key) => typeof key !== "string") ||
    !keys.every((key) => ownKeys.includes(key))
  ) {
    return null;
  }
  const snapshot = {};
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(
      value,
      key,
    );
    if (
      descriptor === undefined ||
      !Object.hasOwn(descriptor, "value")
    ) {
      return null;
    }
    snapshot[key] = descriptor.value;
  }
  return snapshot;
}

function ownDataField(value, key) {
  if (!isPlainObject(value)) {
    return null;
  }
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  return descriptor !== undefined &&
    Object.hasOwn(descriptor, "value")
    ? descriptor.value
    : null;
}

function snapshotInput(input) {
  if (!isPlainObject(input)) {
    throw terminal();
  }
  const keys = Reflect.ownKeys(input);
  if (
    keys.some(
      (key) =>
        typeof key !== "string" ||
        !ROLE_INPUT_KEYS.has(key),
    ) ||
    ![
      "client",
      "descriptorEnvelope",
      "outputDirectory",
      "ownerOf",
      "repositoryPublicKey",
      "signMessage",
    ].every((key) => keys.includes(key))
  ) {
    throw terminal();
  }
  const snapshot = {};
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (
      descriptor === undefined ||
      !Object.hasOwn(descriptor, "value")
    ) {
      throw terminal();
    }
    snapshot[key] = descriptor.value;
  }
  if (
    typeof snapshot.outputDirectory !== "string" ||
    snapshot.outputDirectory.length === 0 ||
    snapshot.outputDirectory.length > 4096 ||
    snapshot.outputDirectory.includes("\0") ||
    typeof snapshot.ownerOf !== "function" ||
    typeof snapshot.signMessage !== "function" ||
    (
      snapshot.publishEvidence !== undefined &&
      typeof snapshot.publishEvidence !== "function"
    ) ||
    (
      snapshot.notifyReady !== undefined &&
      typeof snapshot.notifyReady !== "function"
    ) ||
    (
      snapshot.canaries !== undefined &&
      (
        !Array.isArray(snapshot.canaries) ||
        snapshot.canaries.some(
          (value) =>
            typeof value !== "string" ||
            value.length === 0 ||
            Buffer.byteLength(value, "utf8") >
              MAX_TOKEN_BYTES,
        )
      )
    )
  ) {
    throw terminal();
  }
  return snapshot;
}

function safeMethod(value, key) {
  try {
    if (!isPlainObject(value)) {
      return null;
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor !== undefined &&
      Object.hasOwn(descriptor, "value") &&
      typeof descriptor.value === "function"
      ? descriptor.value
      : null;
  } catch {
    return null;
  }
}

function verifiedDescriptor(snapshot) {
  try {
    const verification = verifyDescriptorEnvelope(
      snapshot.descriptorEnvelope,
      {
        repositoryPublicKey: snapshot.repositoryPublicKey,
      },
    );
    const descriptor = JSON.parse(
      JSON.stringify(snapshot.descriptorEnvelope.descriptor),
    );
    if (verification.dSession.length !== 64) {
      throw terminal();
    }
    return Object.freeze({
      descriptor,
      sessionDigest: verification.dSession,
    });
  } catch (error) {
    if (isProtocolFailure(error)) {
      throw error;
    }
    throw terminal();
  }
}

async function verifyIdentityBindings(
  client,
  descriptor,
  ownerOf,
) {
  const resolveAgent = safeMethod(client, "resolveAgent");
  if (resolveAgent === null) {
    throw terminal();
  }
  const owners = [];
  for (const party of [descriptor.payer, descriptor.payee]) {
    let resolved;
    let directOwner;
    try {
      resolved = await resolveAgent.call(
        client,
        party.agentId,
      );
      directOwner = await ownerOf({
        agentId: party.agentId,
        registry: descriptor.registry,
      });
    } catch {
      throw terminal();
    }
    const resolvedOwner = ownDataField(resolved, "owner");
    if (
      typeof resolvedOwner !== "string" ||
      typeof directOwner !== "string" ||
      resolvedOwner.toLowerCase() !== party.address ||
      directOwner.toLowerCase() !== party.address
    ) {
      throw terminal();
    }
    owners.push(party.address);
  }
  if (owners[0] === owners[1]) {
    throw terminal();
  }
}

function tripleFromOutcome(kind, outcome) {
  return authoritativeTriple({
    anchoredHash: outcome.transition.onChain.anchoredHash,
    blockHeight: outcome.transition.onChain.blockHeight,
    kind,
    ledgerId: outcome.transition.onChain.ledgerId,
  });
}

function assertLater(previous, next) {
  try {
    if (
      BigInt(previous.transition.onChain.blockHeight) >=
      BigInt(next.transition.onChain.blockHeight)
    ) {
      throw terminal();
    }
  } catch (error) {
    if (isProtocolFailure(error)) {
      throw error;
    }
    throw terminal();
  }
}

async function signatureFor(
  signMessage,
  address,
  role,
  sessionDigest,
  transitions,
) {
  let signature;
  try {
    signature = await signMessage(
      partySignatureBytes({
        role,
        sessionDigest,
        transitions,
      }),
    );
  } catch {
    throw terminal();
  }
  if (
    typeof signature !== "string" ||
    !SIGNATURE_PATTERN.test(signature)
  ) {
    throw terminal();
  }
  return Object.freeze({
    address,
    algorithm: "eip191",
    signature,
  });
}

function evidenceResult({
  ackObserved,
  deadlineMs,
  descriptor,
  role,
  sessionDigest,
  signature,
  transitions,
}) {
  return Object.freeze({
    ackObserved,
    deadlineMs,
    localVerdict: "LOCAL_OK",
    paymentMoved: false,
    poolHealth: POOL_HEALTH,
    promptSha256: descriptor.promptSha256,
    protocolVersion: descriptor.protocolVersion,
    rendezvous: RENDEZVOUS,
    repositorySha: descriptor.repositorySha,
    role,
    schema: PARTY_RESULT_SCHEMA,
    sessionDigest,
    signature,
    transitions: Object.freeze([...transitions]),
  });
}

function roleResult(evidence, state) {
  return Object.freeze({
    ackObserved: evidence.ackObserved,
    deadlineMs: evidence.deadlineMs,
    localVerdict: evidence.localVerdict,
    paymentMoved: false,
    role: evidence.role,
    state,
    transitions: evidence.transitions,
  });
}

function runnerOptions(snapshot) {
  const options = {};
  for (const key of ["jitter", "monotonicNow", "sleeper"]) {
    if (snapshot[key] !== undefined) {
      options[key] = snapshot[key];
    }
  }
  return options;
}

async function publish(snapshot, result, directoryPin) {
  const publisher =
    snapshot.publishEvidence ?? publishPartyEvidence;
  try {
    await directoryPin.assertCurrent();
    await publisher({
      canaries: snapshot.canaries ?? [],
      directory: snapshot.outputDirectory,
      directoryPin,
      result,
    });
    await directoryPin.assertCurrent();
  } catch (error) {
    if (isProtocolFailure(error)) {
      throw error;
    }
    throw terminal();
  }
}

function announceReady(snapshot) {
  if (snapshot.notifyReady === undefined) {
    return;
  }
  try {
    snapshot.notifyReady();
  } catch {
    throw terminal();
  }
}

export async function runPayerRole(input) {
  let directoryPin;
  let primaryFailure;
  try {
    const snapshot = snapshotInput(input);
    directoryPin = await pinOutputDirectory({
      directory: snapshot.outputDirectory,
      fileSystem: snapshot.fileSystem,
    });
    const { descriptor, sessionDigest } =
      verifiedDescriptor(snapshot);
    await verifyIdentityBindings(
      snapshot.client,
      descriptor,
      snapshot.ownerOf,
    );
    if (
      !descriptor.amountOptions.some(
        (option) =>
          option.currency === "USD" &&
          option.value === "100",
      )
    ) {
      throw terminal("AMOUNT_UNRESOLVED");
    }
    const stateMachine = createRunnerStateMachine();
    const proposal = buildProposal({
      amount: { currency: "USD", value: "100" },
      descriptor,
      sessionDigest,
    });
    announceReady(snapshot);
    const proposed = await writeOrAdoptTransition({
      client: snapshot.client,
      directoryPin,
      fileSystem: snapshot.fileSystem,
      markerPath: join(
        snapshot.outputDirectory,
        "proposal.intent.json",
      ),
      message: proposal,
      stateMachine,
    });
    const proposalTriple = tripleFromOutcome(
      "proposal",
      proposed,
    );
    const acceptance = buildAcceptance({
      proposal,
      proposalTriple,
    });
    const accepted = await pollForTransition({
      client: snapshot.client,
      message: acceptance,
      proposalDeadlineMs: proposed.deadlineMs,
      stateMachine,
      ...runnerOptions(snapshot),
    });
    assertLater(proposed, accepted);
    const acceptanceTriple = tripleFromOutcome(
      "acceptance",
      accepted,
    );
    const acknowledgment = buildAcknowledgment({
      acceptance,
      acceptanceTriple,
      proposalTriple,
    });
    const acknowledged = await writeOrAdoptTransition({
      client: snapshot.client,
      directoryPin,
      fileSystem: snapshot.fileSystem,
      markerPath: join(
        snapshot.outputDirectory,
        "acknowledgment.intent.json",
      ),
      message: acknowledgment,
      proposalDeadlineMs: proposed.deadlineMs,
      stateMachine,
    });
    assertLater(accepted, acknowledged);
    const transitions = [
      proposed.transition,
      accepted.transition,
      acknowledged.transition,
    ];
    const signature = await signatureFor(
      snapshot.signMessage,
      descriptor.payer.address,
      "payer",
      sessionDigest,
      transitions,
    );
    const result = evidenceResult({
      ackObserved: true,
      deadlineMs: proposed.deadlineMs,
      descriptor,
      role: "payer",
      sessionDigest,
      signature,
      transitions,
    });
    await publish(snapshot, result, directoryPin);
    return roleResult(result, "ACKNOWLEDGED");
  } catch (error) {
    primaryFailure =
      isProtocolFailure(error) ? error : terminal();
    throw primaryFailure;
  } finally {
    if (directoryPin !== undefined) {
      try {
        await closePinnedOutputDirectory(directoryPin);
      } catch (error) {
        if (primaryFailure === undefined) {
          throw error;
        }
      }
    }
  }
}

function monotonic(now) {
  let value;
  try {
    value = now();
  } catch {
    throw terminal();
  }
  if (
    typeof value !== "number" ||
    !Number.isFinite(value) ||
    value < 0
  ) {
    throw terminal();
  }
  return value;
}

async function discoverProposal(
  snapshot,
  descriptor,
  sessionDigest,
) {
  const searchActions = safeMethod(
    snapshot.client,
    "searchActions",
  );
  if (searchActions === null) {
    throw terminal();
  }
  const now = snapshot.monotonicNow ?? (() => performance.now());
  const sleeper =
    snapshot.sleeper ??
    ((milliseconds) =>
      new Promise((resolve) =>
        setTimeout(resolve, milliseconds)));
  const jitter = snapshot.jitter ?? (() => 0);
  const duration =
    snapshot.proposalPollDurationMs ??
    MAX_POLL_DURATION_MS;
  if (
    !Number.isSafeInteger(duration) ||
    duration < MIN_POLL_INTERVAL_MS ||
    duration > MAX_POLL_DURATION_MS
  ) {
    throw terminal();
  }
  const started = monotonic(now);
  const referenceId = sessionKey(
    sessionDigest,
    "proposal",
  );
  let lastObservation = "empty";
  while (true) {
    if (monotonic(now) - started >= duration) {
      throw terminal(
        lastObservation === "rate"
          ? "RATE_BLOCKED"
          : lastObservation === "network"
            ? "FAILED"
            : "EXPIRED",
      );
    }
    let records;
    let retryAfterMs = 0;
    let currentObservation = "empty";
    try {
      records = await searchActions.call(snapshot.client, {
        asset_reference_id: referenceId,
      });
    } catch (error) {
      if (
        error instanceof McpRateLimitedError ||
        error instanceof McpNetworkError
      ) {
        currentObservation =
          error instanceof McpRateLimitedError
            ? "rate"
            : "network";
        retryAfterMs =
          Number.isSafeInteger(error.retryAfterMs)
            ? error.retryAfterMs
            : 0;
        records = [];
      } else {
        throw terminal();
      }
    }
    if (!Array.isArray(records)) {
      throw terminal(
        records?.error === "rate_limited"
          ? "RATE_BLOCKED"
          : "FAILED",
      );
    }
    if (records.length > 1) {
      throw terminal("DUPLICATE");
    }
    if (records.length === 1) {
      const record = records[0];
      if (
        !isPlainObject(record) ||
        record.assetReferenceId !== referenceId ||
        typeof record.assetHash !== "string"
      ) {
        throw terminal("BINDING_MISMATCH");
      }
      return recoverAnchoredProposal({
        anchoredHash: record.assetHash,
        descriptor,
        sessionDigest,
      });
    }
    lastObservation = currentObservation;
    const elapsed = monotonic(now) - started;
    const remaining = duration - elapsed;
    if (remaining <= 0) {
      throw terminal(
        lastObservation === "rate"
          ? "RATE_BLOCKED"
          : lastObservation === "network"
            ? "FAILED"
            : "EXPIRED",
      );
    }
    let jitterMs;
    try {
      jitterMs = jitter();
    } catch {
      throw terminal();
    }
    if (
      !Number.isSafeInteger(jitterMs) ||
      jitterMs < 0 ||
      jitterMs > MIN_POLL_INTERVAL_MS
    ) {
      throw terminal();
    }
    const delay = Math.min(
      remaining,
      Math.max(MIN_POLL_INTERVAL_MS, retryAfterMs) +
        jitterMs,
    );
    try {
      await sleeper(delay);
    } catch {
      throw terminal();
    }
  }
}

export async function runPayeeRole(input) {
  let directoryPin;
  let primaryFailure;
  try {
    const snapshot = snapshotInput(input);
    directoryPin = await pinOutputDirectory({
      directory: snapshot.outputDirectory,
      fileSystem: snapshot.fileSystem,
    });
    const { descriptor, sessionDigest } =
      verifiedDescriptor(snapshot);
    await verifyIdentityBindings(
      snapshot.client,
      descriptor,
      snapshot.ownerOf,
    );
    announceReady(snapshot);
    const proposal = await discoverProposal(
      snapshot,
      descriptor,
      sessionDigest,
    );
    const stateMachine = createRunnerStateMachine();
    const proposed = await pollForTransition({
      client: snapshot.client,
      message: proposal,
      stateMachine,
      ...runnerOptions(snapshot),
    });
    const wallNow = snapshot.now ?? Date.now;
    if (monotonic(wallNow) > Number(proposed.deadlineMs)) {
      throw terminal("EXPIRED");
    }
    const proposalTriple = tripleFromOutcome(
      "proposal",
      proposed,
    );
    const acceptance = buildAcceptance({
      proposal,
      proposalTriple,
    });
    const accepted = await writeOrAdoptTransition({
      client: snapshot.client,
      directoryPin,
      fileSystem: snapshot.fileSystem,
      markerPath: join(
        snapshot.outputDirectory,
        "acceptance.intent.json",
      ),
      message: acceptance,
      proposalDeadlineMs: proposed.deadlineMs,
      stateMachine,
    });
    assertLater(proposed, accepted);
    const acceptanceTriple = tripleFromOutcome(
      "acceptance",
      accepted,
    );
    const acknowledgment = buildAcknowledgment({
      acceptance,
      acceptanceTriple,
      proposalTriple,
    });
    let observed = null;
    const observationState = createRunnerStateMachine();
    observationState.advance("RENDEZVOUS_OK");
    observationState.advance("PROPOSED");
    observationState.advance("ACCEPTED");
    try {
      observed = await pollForTransition({
        client: snapshot.client,
        message: acknowledgment,
        pollDurationMs:
          snapshot.acknowledgmentPollDurationMs ??
          120_000,
        proposalDeadlineMs: proposed.deadlineMs,
        stateMachine: observationState,
        ...runnerOptions(snapshot),
      });
      assertLater(accepted, observed);
    } catch (error) {
      if (
        !isProtocolFailure(error) ||
        error.terminalCode !== "EXPIRED"
      ) {
        throw error;
      }
    }
    const transitions = [
      proposed.transition,
      accepted.transition,
      ...(observed === null ? [] : [observed.transition]),
    ];
    const signature = await signatureFor(
      snapshot.signMessage,
      descriptor.payee.address,
      "payee",
      sessionDigest,
      transitions,
    );
    const result = evidenceResult({
      ackObserved: observed !== null,
      deadlineMs: proposed.deadlineMs,
      descriptor,
      role: "payee",
      sessionDigest,
      signature,
      transitions,
    });
    await publish(snapshot, result, directoryPin);
    return roleResult(result, "ACCEPTED");
  } catch (error) {
    primaryFailure =
      isProtocolFailure(error) ? error : terminal();
    throw primaryFailure;
  } finally {
    if (directoryPin !== undefined) {
      try {
        await closePinnedOutputDirectory(directoryPin);
      } catch (error) {
        if (primaryFailure === undefined) {
          throw error;
        }
      }
    }
  }
}

function parseRoleArguments(arguments_) {
  if (
    !Array.isArray(arguments_) ||
    arguments_.length !==
      ROLE_CLI_ARGUMENTS.length * 2 + 1 ||
    arguments_.some((value) => typeof value !== "string")
  ) {
    throw terminal();
  }
  const values = new Map();
  let riskSeen = false;
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (argument === ROLE_RISK_FLAG) {
      if (riskSeen) {
        throw terminal();
      }
      riskSeen = true;
      continue;
    }
    if (
      !ROLE_CLI_ARGUMENTS.includes(argument) ||
      values.has(argument)
    ) {
      throw terminal();
    }
    const value = arguments_[index + 1];
    if (
      typeof value !== "string" ||
      value.length === 0 ||
      value.startsWith("--") ||
      value.includes("\0")
    ) {
      throw terminal();
    }
    values.set(argument, value);
    index += 1;
  }
  if (
    !riskSeen ||
    !ROLE_CLI_ARGUMENTS.every((flag) => values.has(flag))
  ) {
    throw terminal();
  }
  return Object.freeze({
    clockchainTokenPath: values.get(
      "--clockchain-token-file",
    ),
    descriptorPath: values.get("--descriptor"),
    invitationPath: values.get("--invitation"),
    outputDirectory: values.get("--output"),
  });
}

function readinessNotifier(role) {
  const values = Object.freeze({
    fd: process.env[ROLE_READY_ENV.fd],
    nonce: process.env[ROLE_READY_ENV.nonce],
    schema: process.env[ROLE_READY_ENV.schema],
  });
  if (Object.values(values).every((value) => value === undefined)) {
    return undefined;
  }
  if (
    values.fd !== "3" ||
    values.schema !== ROLE_READY_SCHEMA ||
    typeof values.nonce !== "string" ||
    !/^[0-9a-f]{64}$/.test(values.nonce)
  ) {
    throw terminal();
  }
  const bytes = Buffer.from(`${JSON.stringify({
    nonce: values.nonce,
    role,
    schema: values.schema,
  })}\n`, "utf8");
  let announced = false;
  return () => {
    if (announced || writeSync(3, bytes) !== bytes.length) {
      throw terminal();
    }
    try {
      closeSync(3);
      announced = true;
    } catch {
      throw terminal();
    }
  };
}

function sameFile(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.nlink === right.nlink &&
    left.uid === right.uid &&
    left.gid === right.gid &&
    left.rdev === right.rdev &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs
  );
}

async function readAtMost(handle, maximum) {
  const bytes = Buffer.alloc(maximum + 1);
  let offset = 0;
  while (offset < bytes.length) {
    const result = await handle.read(
      bytes,
      offset,
      bytes.length - offset,
      offset,
    );
    if (
      result === null ||
      typeof result !== "object" ||
      !Number.isSafeInteger(result.bytesRead) ||
      result.bytesRead < 0 ||
      result.bytesRead > bytes.length - offset
    ) {
      throw terminal();
    }
    if (result.bytesRead === 0) {
      break;
    }
    offset += result.bytesRead;
  }
  return bytes.subarray(0, offset);
}

async function readBoundedFile(
  path,
  maximum,
  secret,
  fileSystem,
) {
  let handle;
  try {
    handle = await fileSystem.open(path, READ_FLAGS);
    if (
      handle === null ||
      typeof handle !== "object" ||
      typeof handle.stat !== "function" ||
      typeof handle.read !== "function" ||
      typeof handle.close !== "function"
    ) {
      throw terminal();
    }
    const before = await handle.stat();
    if (
      !before.isFile() ||
      before.size <= 0 ||
      before.size > maximum ||
      (
        secret &&
        process.platform !== "win32" &&
        (
          (before.mode & 0o777) !== 0o600 ||
          (
            typeof process.getuid === "function" &&
            Number.isSafeInteger(before.uid) &&
            before.uid !== process.getuid()
          )
        )
      )
    ) {
      throw terminal();
    }
    const bytes = await readAtMost(handle, maximum);
    const after = await handle.stat();
    if (
      bytes.length > maximum ||
      bytes.length !== before.size ||
      !sameFile(before, after)
    ) {
      throw terminal();
    }
    return bytes;
  } catch (error) {
    if (isProtocolFailure(error)) {
      throw error;
    }
    throw terminal();
  } finally {
    try {
      await handle?.close();
    } catch {
      throw terminal();
    }
  }
}

async function defaultRepositoryPublicKeyResolver({
  repositoryPath,
  repositoryRoot,
  repositorySha,
}) {
  try {
    const result = await execFileAsync(
      "git",
      ["show", `${repositorySha}:${repositoryPath}`],
      {
        cwd: repositoryRoot,
        encoding: "utf8",
        maxBuffer: 4096,
      },
    );
    return result.stdout.trim();
  } catch {
    throw terminal();
  }
}

async function defaultRepositoryPromptResolver({
  repositoryPath,
  repositoryRoot,
  repositorySha,
}) {
  try {
    const result = await execFileAsync(
      "git",
      ["show", `${repositorySha}:${repositoryPath}`],
      {
        cwd: repositoryRoot,
        encoding: "buffer",
        maxBuffer: MAX_PROMPT_BYTES + 1,
      },
    );
    return result.stdout;
  } catch {
    throw terminal();
  }
}

async function defaultRepositoryStateResolver({
  repositoryRoot,
}) {
  try {
    const [head, status] = await Promise.all([
      execFileAsync(
        "git",
        ["rev-parse", "HEAD"],
        {
          cwd: repositoryRoot,
          encoding: "utf8",
          maxBuffer: 128,
        },
      ),
      execFileAsync(
        "git",
        [
          "status",
          "--porcelain=v1",
          "--untracked-files=all",
        ],
        {
          cwd: repositoryRoot,
          encoding: "utf8",
          maxBuffer: 1024 * 1024,
        },
      ),
    ]);
    return {
      headSha: head.stdout.trim(),
      worktreeStatus: status.stdout,
    };
  } catch {
    throw terminal();
  }
}

async function repositoryPublicKey(envelope, resolver) {
  const repositorySha = envelope?.descriptor?.repositorySha;
  const keyId = envelope?.operator?.keyId;
  if (
    typeof repositorySha !== "string" ||
    !/^[0-9a-f]{40}$/.test(repositorySha)
  ) {
    throw terminal();
  }
  let repositoryPath;
  try {
    repositoryPath = operatorPublicKeyPath(keyId);
  } catch {
    throw terminal();
  }
  let value;
  try {
    value = await resolver({
      repositoryPath,
      repositoryRoot: ROLE_REPOSITORY_ROOT,
      repositorySha,
    });
  } catch {
    throw terminal();
  }
  if (typeof value !== "string" || value.length === 0) {
    throw terminal();
  }
  return value.trim();
}

async function verifyRepositoryProvenance(
  descriptor,
  stateResolver,
  promptResolver,
) {
  let state;
  try {
    state = exactDataSnapshot(
      await stateResolver({
        repositoryRoot: ROLE_REPOSITORY_ROOT,
      }),
      ["headSha", "worktreeStatus"],
    );
  } catch {
    throw terminal();
  }
  if (
    state === null ||
    typeof state.headSha !== "string" ||
    !/^[0-9a-f]{40}$/.test(state.headSha) ||
    state.headSha !== descriptor.repositorySha ||
    state.worktreeStatus !== ""
  ) {
    throw terminal();
  }

  const promptDigests = {};
  for (const role of ["payer", "payee"]) {
    let bytes;
    try {
      bytes = await promptResolver({
        repositoryPath: ROLE_PROMPT_PATHS[role],
        repositoryRoot: ROLE_REPOSITORY_ROOT,
        repositorySha: descriptor.repositorySha,
      });
    } catch {
      throw terminal();
    }
    if (
      !Buffer.isBuffer(bytes) ||
      bytes.length === 0 ||
      bytes.length > MAX_PROMPT_BYTES
    ) {
      throw terminal();
    }
    promptDigests[role] = createHash("sha256")
      .update(bytes)
      .digest("hex");
  }
  let promptSha256;
  try {
    promptSha256 = createHash("sha256")
      .update(canonicalBytes(promptDigests))
      .digest("hex");
  } catch {
    throw terminal();
  }
  if (promptSha256 !== descriptor.promptSha256) {
    throw terminal();
  }
}

function activeBuilderDependencies(dependencies) {
  if (!isPlainObject(dependencies)) {
    throw terminal();
  }
  for (const key of Reflect.ownKeys(dependencies)) {
    if (
      typeof key !== "string" ||
      !BUILDER_DEPENDENCY_KEYS.has(key)
    ) {
      throw terminal();
    }
  }
  const fileSystem = {
    ...DEFAULT_BUILDER_FILE_SYSTEM,
    ...(dependencies.fileSystem ?? {}),
  };
  for (const operation of ["lstat", "mkdir", "open"]) {
    if (typeof fileSystem[operation] !== "function") {
      throw terminal();
    }
  }
  const active = {
    createClockchainClient:
      dependencies.createClockchainClient ??
      createMcpClient,
    createIdentityClient:
      dependencies.createIdentityClient ??
      (() =>
        createPublicClient({
          transport: http(RPC_URL),
        })),
    decryptInvitation:
      dependencies.decryptInvitation ??
      decryptInvitation,
    fileSystem,
    loadInvitation:
      dependencies.loadInvitation ??
      readSecretInvitation,
    repositoryPromptResolver:
      dependencies.repositoryPromptResolver ??
      defaultRepositoryPromptResolver,
    repositoryPublicKeyResolver:
      dependencies.repositoryPublicKeyResolver ??
      defaultRepositoryPublicKeyResolver,
    repositoryStateResolver:
      dependencies.repositoryStateResolver ??
      defaultRepositoryStateResolver,
    verifyEnvelope:
      dependencies.verifyEnvelope ??
      verifyDescriptorEnvelope,
  };
  if (
    Object.entries(active).some(
      ([key, value]) =>
        key !== "fileSystem" && typeof value !== "function",
    )
  ) {
    throw terminal();
  }
  return active;
}

function safeFsCode(error) {
  try {
    return typeof error?.code === "string"
      ? error.code
      : null;
  } catch {
    return null;
  }
}

async function ensureOutputDirectory(path, fileSystem) {
  let stats;
  try {
    stats = await fileSystem.lstat(path);
  } catch (error) {
    if (safeFsCode(error) !== "ENOENT") {
      throw terminal();
    }
    try {
      await fileSystem.mkdir(path, {
        mode: 0o700,
        recursive: false,
      });
      stats = await fileSystem.lstat(path);
    } catch {
      throw terminal();
    }
  }
  try {
    if (
      stats === null ||
      typeof stats !== "object" ||
      typeof stats.isDirectory !== "function" ||
      stats.isDirectory() !== true ||
      (
        process.platform !== "win32" &&
        (stats.mode & 0o077) !== 0
      ) ||
      (
        typeof process.getuid === "function" &&
        Number.isSafeInteger(stats.uid) &&
        stats.uid !== process.getuid()
      )
    ) {
      throw terminal();
    }
  } catch (error) {
    throw isProtocolFailure(error) ? error : terminal();
  }
}

function normalizedChainId(value) {
  if (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= 0
  ) {
    return String(value);
  }
  if (typeof value === "bigint" && value >= 0n) {
    return value.toString(10);
  }
  if (
    typeof value === "string" &&
    DECIMAL_PATTERN.test(value)
  ) {
    return value;
  }
  throw terminal();
}

function evidenceCanaryFragments(secrets) {
  const canaries = [];
  for (const secret of secrets) {
    if (secret.length <= MAX_EVIDENCE_CANARY_LENGTH) {
      canaries.push(secret);
      continue;
    }
    for (
      let offset = 0;
      offset + MAX_EVIDENCE_CANARY_LENGTH <= secret.length;
      offset += MAX_EVIDENCE_CANARY_LENGTH
    ) {
      canaries.push(
        secret.slice(
          offset,
          offset + MAX_EVIDENCE_CANARY_LENGTH,
        ),
      );
    }
    if (
      secret.length % MAX_EVIDENCE_CANARY_LENGTH !== 0
    ) {
      canaries.push(
        secret.slice(-MAX_EVIDENCE_CANARY_LENGTH),
      );
    }
  }
  return canaries;
}

export async function buildDefaultRoleInput(
  values,
  role,
  dependencies = {},
) {
  const active = activeBuilderDependencies(dependencies);
  const valueSnapshot = exactDataSnapshot(
    values,
    BUILDER_VALUE_KEYS,
  );
  if (
    valueSnapshot === null ||
    BUILDER_VALUE_KEYS.some(
      (key) =>
        typeof valueSnapshot[key] !== "string" ||
        valueSnapshot[key].length === 0 ||
        valueSnapshot[key].length > 4096 ||
        valueSnapshot[key].includes("\0"),
    ) ||
    !["payer", "payee"].includes(role)
  ) {
    throw terminal();
  }
  let descriptorEnvelope;
  try {
    descriptorEnvelope = JSON.parse(
      (
        await readBoundedFile(
          valueSnapshot.descriptorPath,
          MAX_DESCRIPTOR_BYTES,
          false,
          active.fileSystem,
        )
      ).toString("utf8"),
    );
  } catch (error) {
    if (isProtocolFailure(error)) {
      throw error;
    }
    throw terminal();
  }
  const repositoryKey =
    await repositoryPublicKey(
      descriptorEnvelope,
      active.repositoryPublicKeyResolver,
    );
  try {
    await active.verifyEnvelope(descriptorEnvelope, {
      repositoryPublicKey: repositoryKey,
    });
  } catch {
    throw terminal();
  }
  await verifyRepositoryProvenance(
    descriptorEnvelope.descriptor,
    active.repositoryStateResolver,
    active.repositoryPromptResolver,
  );
  await ensureOutputDirectory(
    valueSnapshot.outputDirectory,
    active.fileSystem,
  );
  let publicClient;
  let getChainId;
  try {
    publicClient = active.createIdentityClient();
    getChainId = safeMethod(publicClient, "getChainId");
  } catch {
    throw terminal();
  }
  if (
    !isPlainObject(publicClient) ||
    getChainId === null ||
    safeMethod(publicClient, "readContract") === null
  ) {
    throw terminal();
  }
  let chainId;
  try {
    chainId = normalizedChainId(
      await getChainId.call(publicClient),
    );
  } catch {
    throw terminal();
  }
  if (chainId !== descriptorEnvelope.descriptor.chainId) {
    throw terminal();
  }
  let token;
  try {
    const tokenText = (
      await readBoundedFile(
        valueSnapshot.clockchainTokenPath,
        MAX_TOKEN_BYTES,
        true,
        active.fileSystem,
      )
    ).toString("utf8");
    token = tokenText.endsWith("\n")
      ? tokenText.slice(0, -1)
      : tokenText;
  } catch {
    throw terminal();
  }
  if (!TOKEN_PATTERN.test(token)) {
    throw terminal();
  }
  let invitation;
  let decrypted;
  let privateKey;
  try {
    invitation = await active.loadInvitation(
      valueSnapshot.invitationPath,
    );
    if (
      !isPlainObject(invitation) ||
      typeof invitation.code !== "string" ||
      !isPlainObject(invitation.bundle)
    ) {
      throw terminal();
    }
    decrypted = await active.decryptInvitation(
      invitation.bundle,
      invitation.code,
    );
    if (
      !isPlainObject(decrypted) ||
      typeof decrypted.privateKey !== "string" ||
      typeof decrypted.address !== "string"
    ) {
      throw terminal();
    }
    privateKey = decrypted.privateKey;
  } catch {
    throw terminal();
  }
  if (!/^0x[0-9a-f]{64}$/.test(privateKey)) {
    throw terminal();
  }
  let account;
  try {
    account = privateKeyToAccount(privateKey);
  } catch {
    throw terminal();
  }
  const party =
    role === "payer"
      ? descriptorEnvelope.descriptor.payer
      : descriptorEnvelope.descriptor.payee;
  if (
    account.address.toLowerCase() !== party.address ||
    decrypted.address.toLowerCase() !== party.address
  ) {
    throw terminal();
  }
  let client;
  try {
    client = active.createClockchainClient({ token });
  } catch {
    throw terminal();
  }
  if (!isPlainObject(client)) {
    throw terminal();
  }
  return {
    canaries: evidenceCanaryFragments([
      invitation.code,
      invitation.bundle.crypto.ciphertext,
      privateKey,
      token,
    ]),
    client,
    descriptorEnvelope,
    outputDirectory: valueSnapshot.outputDirectory,
    ownerOf: ({ agentId, registry }) =>
      publicClient.readContract({
        abi: ERC8004_ABI,
        address: registry,
        args: [BigInt(agentId)],
        functionName: "ownerOf",
      }),
    repositoryPublicKey: repositoryKey,
    signMessage: (bytes) =>
      account.signMessage({ message: { raw: bytes } }),
  };
}

export async function runRoleCli(
  role,
  arguments_,
  dependencies = {},
) {
  let stdout = process.stdout;
  let stderr = process.stderr;
  try {
    if (
      !["payer", "payee"].includes(role) ||
      !isPlainObject(dependencies)
    ) {
      throw terminal();
    }
    stdout = dependencies.stdout ?? stdout;
    stderr = dependencies.stderr ?? stderr;
    const buildRoleInput =
      dependencies.buildRoleInput ??
      buildDefaultRoleInput;
    const runRole =
      dependencies.runRole ??
      (role === "payer" ? runPayerRole : runPayeeRole);
    if (
      typeof stdout?.write !== "function" ||
      typeof stderr?.write !== "function" ||
      typeof buildRoleInput !== "function" ||
      typeof runRole !== "function"
    ) {
      throw terminal();
    }
    const values = parseRoleArguments(arguments_);
    const input = await buildRoleInput(values, role);
    const notifier = readinessNotifier(role);
    const roleInput = notifier === undefined
      ? input
      : { ...input, notifyReady: notifier };
    const result = await runRole(roleInput);
    const publicResult = {
      localVerdict: result.localVerdict,
      paymentMoved: false,
      role,
      state: result.state,
    };
    stdout.write(`${JSON.stringify(publicResult)}\n`);
    return 0;
  } catch (error) {
    const localVerdict = isProtocolFailure(error)
      ? error.terminalCode
      : "FAILED";
    try {
      stdout.write(
        `${JSON.stringify({
          localVerdict,
          paymentMoved: false,
          role,
        })}\n`,
      );
      stderr.write("BILATERAL_ROLE_FAILED\n");
    } catch {
      return 1;
    }
    return 1;
  }
}
