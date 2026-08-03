import {
  dirname,
  join,
} from "node:path";
import { fileURLToPath } from "node:url";
import { types } from "node:util";

import {
  verifyDescriptorEnvelope,
} from "./descriptor.mjs";
import {
  assertInWindowPollBound,
} from "./deadline.mjs";
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
} from "./clockchain.mjs";

export const ROLE_RESULT_KEYS = Object.freeze([
  "ackObserved",
  "deadlineMs",
  "localVerdict",
  "paymentMoved",
  "role",
  "state",
  "transitions",
]);
export const ROLE_REPOSITORY_ROOT = dirname(
  dirname(dirname(fileURLToPath(import.meta.url))),
);
export const ROLE_READY_SCHEMA =
  "clockchain.bilateral-role-ready/v1";

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
const MAX_TOKEN_BYTES = 4096;

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
      pollDurationMs: assertInWindowPollBound({
        nowMs: monotonic(snapshot.now ?? Date.now),
        proposalDeadlineMs: Number(proposed.deadlineMs),
      }),
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
