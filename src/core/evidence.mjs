import { createHash, randomUUID } from "node:crypto";
import {
  link,
  lstat,
  mkdir,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { isDeepStrictEqual, types } from "node:util";

import {
  deadlineMs,
  isWithinDeadline,
  liveUpperBoundMs,
  parseBlockTime,
} from "./blocktime.mjs";
import {
  canonicalBytes,
  MAX_CANONICAL_STRING_LENGTH,
} from "./canonical.mjs";
import {
  transitionDigest,
  validateTransition,
} from "./messages.mjs";
import {
  assertSecretFree,
  highEntropySecretAssignmentPattern,
  redact,
  SENSITIVE_KEY,
} from "./redact.mjs";

export const PARTY_RESULT_SCHEMA =
  "clockchain.bilateral-party-result/v1";
export const PARTY_SIGNATURE_SCHEMA =
  "clockchain.bilateral-party-signature/v1";
export const PARTY_ROLES = Object.freeze(["payer", "payee"]);
export const LOCAL_VERDICTS = Object.freeze([
  "LOCAL_OK",
  "RENDEZVOUS_UNAVAILABLE",
  "EXPIRED",
  "DUPLICATE",
  "AMBIGUOUS_WRITE",
  "BINDING_MISMATCH",
  "ANCHOR_UNVERIFIED",
  "RATE_BLOCKED",
  "AMOUNT_UNRESOLVED",
  "FAILED",
]);
export const RENDEZVOUS_CHANNELS = Object.freeze([
  "derived-reference-id",
  "digest-hash",
  "out-of-band-pointer",
]);
export const RENDEZVOUS_TENANCIES = Object.freeze([
  "same-client",
  "cross-client",
  "unknown",
]);
export const PARTY_RESULT_KEYS = Object.freeze([
  "ackObserved",
  "deadlineMs",
  "localVerdict",
  "paymentMoved",
  "poolHealth",
  "promptSha256",
  "protocolVersion",
  "rendezvous",
  "repositorySha",
  "role",
  "schema",
  "sessionDigest",
  "signature",
  "transitions",
]);
export const TRANSITION_ENTRY_KEYS = Object.freeze([
  "blockTimeMs",
  "blockTimeRaw",
  "digest",
  "message",
  "onChain",
  "upperBoundMs",
]);
export const RENDEZVOUS_KEYS = Object.freeze([
  "channel",
  "degradedAtSubmission",
  "tenancy",
]);
export const SIGNATURE_KEYS = Object.freeze([
  "address",
  "algorithm",
  "signature",
]);
export const PARTY_SIGNATURE_PREIMAGE_KEYS = Object.freeze([
  "messages",
  "role",
  "schema",
  "sessionDigest",
]);

const POOL_HEALTH_KEYS = Object.freeze([
  "degradedAtSubmission",
  "nodeParticipationPct",
  "totalNodes",
]);
const ON_CHAIN_KEYS = Object.freeze([
  "anchoredHash",
  "blockHeight",
  "ledgerId",
]);
const COMPLETION_MARKER_KEYS = Object.freeze([
  "jsonSha256",
  "markdownSha256",
  "schema",
]);
const COMPLETION_MARKER_SCHEMA =
  "clockchain.bilateral-party-result-completion/v1";
// The JSON and Markdown links are necessarily published sequentially.
// They are therefore not a physically atomic pair. This hidden marker is
// the fail-closed completeness boundary: consumers must ignore either
// artifact unless the exclusive marker exists and its two SHA-256 values
// match the exact final bytes. The writer creates the marker exclusively
// only after both finals have been re-read and revalidated and all unique
// temporary paths have been removed.
const TRANSITION_KINDS = Object.freeze([
  "proposal",
  "acceptance",
  "acknowledgment",
]);
const PARTY_SIGNATURE_INPUT_KEYS = Object.freeze([
  "role",
  "sessionDigest",
  "transitions",
]);
const COMMON_MESSAGE_KEYS = Object.freeze([
  "amount",
  "expirySeconds",
  "payee",
  "payer",
  "protocol",
  "schema",
  "sessionDigest",
]);
const FILE_SYSTEM_KEYS = new Set([
  "link",
  "lstat",
  "mkdir",
  "readFile",
  "rm",
  "writeFile",
]);
const WRITE_OPTION_KEYS = new Set([
  "canaries",
  "directory",
  "directoryPin",
  "fileSystem",
  "result",
]);
const DEFAULT_FILE_SYSTEM = Object.freeze({
  link,
  lstat,
  mkdir,
  readFile,
  rm,
  writeFile,
});

const HASH_PATTERN = /^[0-9a-f]{64}$/;
const REPOSITORY_SHA_PATTERN = /^[0-9a-f]{40}$/;
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const SIGNATURE_PATTERN = /^0x[0-9a-f]{130}$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DECIMAL_INTEGER_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const DECIMAL_QUANTITY_PATTERN =
  /^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/;
const INTEGER_LIKE_KEY_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const PRINTABLE_ASCII_PATTERN = /^[ -~]*$/;
const AUTHORIZING_WORD_PATTERN = /\bAUTHORIZED\b/i;
const PRIVATE_KEY_MATERIAL_PATTERN =
  /-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----/i;
const HIGH_ENTROPY_SECRET_ASSIGNMENT_PATTERN =
  highEntropySecretAssignmentPattern();
const ARRAY_INDEX_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const MAX_SNAPSHOT_DEPTH = 32;
const MAX_SNAPSHOT_OBJECTS = 256;
const MAX_TRANSITIONS = 3;
// Role builders preserve every accepted secret as <=256-character fragments:
// a 1024-character invitation code (4), 8192-character ciphertext (32),
// private key (1), and 4096-character token (16) require at most 53.
const MAX_CANARIES = 64;
const MAX_DIRECTORY_LENGTH = 4096;

export class BilateralPartyResultValidationError extends Error {
  constructor() {
    super("Bilateral party-result evidence is invalid.");
    this.name = new.target.name;
    this.category = "verification";
    this.code = "BILATERAL_PARTY_RESULT_INVALID";
  }
}

export class BilateralEvidenceRedactionError extends Error {
  constructor() {
    super("Bilateral evidence failed the secret-redaction gate.");
    this.name = new.target.name;
    this.category = "redaction";
    this.code = "BILATERAL_EVIDENCE_REDACTION";
  }
}

export class BilateralEvidenceConfigurationError extends Error {
  constructor() {
    super("Bilateral evidence output configuration is invalid.");
    this.name = new.target.name;
    this.category = "configuration";
    this.code = "BILATERAL_EVIDENCE_CONFIGURATION";
  }
}

export class BilateralEvidenceAmbiguousPublicationError
  extends Error {
  constructor() {
    super(
      "Bilateral evidence publication outcome is ambiguous; a valid completion marker is required.",
    );
    this.name = new.target.name;
    this.category = "publication";
    this.code =
      "BILATERAL_EVIDENCE_PUBLICATION_AMBIGUOUS";
  }
}

function invalid() {
  throw new BilateralPartyResultValidationError();
}

function redactionFailure() {
  throw new BilateralEvidenceRedactionError();
}

class SnapshotFailure extends Error {}

function snapshotFailure() {
  throw new SnapshotFailure();
}

function snapshotValue(value, state, depth) {
  if (
    value === null ||
    value === undefined ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    typeof value === "number" ||
    typeof value === "bigint"
  ) {
    return value;
  }
  if (
    typeof value !== "object" ||
    types.isProxy(value) ||
    depth > MAX_SNAPSHOT_DEPTH ||
    state.remainingObjects === 0 ||
    state.ancestors.has(value)
  ) {
    snapshotFailure();
  }

  state.remainingObjects -= 1;
  state.ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const keys = Reflect.ownKeys(value);
      const lengthProperty =
        Object.getOwnPropertyDescriptor(value, "length");
      const length = lengthProperty?.value;
      if (
        !lengthProperty ||
        lengthProperty.enumerable ||
        !Object.hasOwn(lengthProperty, "value") ||
        !Number.isSafeInteger(length) ||
        length < 0 ||
        length > MAX_TRANSITIONS ||
        keys.length !== length + 1 ||
        keys.some(
          (key) =>
            key !== "length" &&
            (typeof key !== "string" ||
              !ARRAY_INDEX_PATTERN.test(key) ||
              Number(key) >= length),
        )
      ) {
        snapshotFailure();
      }
      const result = new Array(length);
      for (let index = 0; index < length; index += 1) {
        const property = Object.getOwnPropertyDescriptor(
          value,
          String(index),
        );
        if (
          property?.enumerable !== true ||
          !Object.hasOwn(property, "value")
        ) {
          snapshotFailure();
        }
        result[index] = snapshotValue(
          property.value,
          state,
          depth + 1,
        );
      }
      return Object.freeze(result);
    }

    const prototype = Object.getPrototypeOf(value);
    if (
      prototype !== Object.prototype &&
      prototype !== null
    ) {
      snapshotFailure();
    }
    const result = Object.create(null);
    for (const key of Reflect.ownKeys(value)) {
      const property = Object.getOwnPropertyDescriptor(value, key);
      if (
        typeof key !== "string" ||
        property?.enumerable !== true ||
        !Object.hasOwn(property, "value")
      ) {
        snapshotFailure();
      }
      result[key] = snapshotValue(
        property.value,
        state,
        depth + 1,
      );
    }
    return Object.freeze(result);
  } catch (error) {
    if (error instanceof SnapshotFailure) {
      throw error;
    }
    snapshotFailure();
  } finally {
    state.ancestors.delete(value);
  }
}

function materializeSnapshot(value) {
  try {
    return snapshotValue(
      value,
      {
        ancestors: new Set(),
        remainingObjects: MAX_SNAPSHOT_OBJECTS,
      },
      1,
    );
  } catch {
    invalid();
  }
}

function isPlainSnapshotObject(value) {
  if (value === null || typeof value !== "object") {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasExactKeys(value, expectedKeys) {
  if (!isPlainSnapshotObject(value)) {
    return false;
  }
  const keys = Reflect.ownKeys(value);
  return (
    keys.length === expectedKeys.length &&
    keys.every(
      (key) =>
        typeof key === "string" &&
        expectedKeys.includes(key) &&
        Object.getOwnPropertyDescriptor(value, key)?.enumerable ===
          true &&
        Object.hasOwn(
          Object.getOwnPropertyDescriptor(value, key),
          "value",
        ),
    )
  );
}

function validateBilateralDomain(value, depth = 1) {
  if (value === null || typeof value === "boolean") {
    return;
  }
  if (typeof value === "string") {
    if (
      value.length > MAX_CANONICAL_STRING_LENGTH ||
      value.trim() !== value ||
      !PRINTABLE_ASCII_PATTERN.test(value)
    ) {
      invalid();
    }
    return;
  }
  if (typeof value !== "object" || depth > MAX_SNAPSHOT_DEPTH) {
    invalid();
  }
  if (Array.isArray(value)) {
    for (const entry of value) {
      validateBilateralDomain(entry, depth + 1);
    }
    return;
  }
  for (const key of Reflect.ownKeys(value)) {
    if (
      typeof key !== "string" ||
      key.length === 0 ||
      key.length > MAX_CANONICAL_STRING_LENGTH ||
      key.trim() !== key ||
      !PRINTABLE_ASCII_PATTERN.test(key) ||
      INTEGER_LIKE_KEY_PATTERN.test(key)
    ) {
      invalid();
    }
    validateBilateralDomain(value[key], depth + 1);
  }
}

function scanDisallowedText(value, canaries = []) {
  const visit = (entry) => {
    if (typeof entry === "string") {
      if (AUTHORIZING_WORD_PATTERN.test(entry)) {
        invalid();
      }
      if (
        PRIVATE_KEY_MATERIAL_PATTERN.test(entry) ||
        HIGH_ENTROPY_SECRET_ASSIGNMENT_PATTERN.test(entry)
      ) {
        redactionFailure();
      }
      try {
        assertSecretFree(entry, canaries);
      } catch {
        redactionFailure();
      }
      return;
    }
    if (entry === null || typeof entry !== "object") {
      return;
    }
    if (Array.isArray(entry)) {
      for (const item of entry) {
        visit(item);
      }
      return;
    }
    for (const key of Reflect.ownKeys(entry)) {
      if (
        AUTHORIZING_WORD_PATTERN.test(key)
      ) {
        invalid();
      }
      if (SENSITIVE_KEY.test(key)) {
        redactionFailure();
      }
      try {
        assertSecretFree(key, canaries);
      } catch {
        redactionFailure();
      }
      visit(entry[key]);
    }
  };
  visit(value);
}

function isCanonicalDecimalInteger(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= MAX_CANONICAL_STRING_LENGTH &&
    DECIMAL_INTEGER_PATTERN.test(value)
  );
}

function isCanonicalDecimalQuantity(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= MAX_CANONICAL_STRING_LENGTH &&
    DECIMAL_QUANTITY_PATTERN.test(value)
  );
}

function decimalQuantityAtMost100(value) {
  if (!isCanonicalDecimalQuantity(value)) {
    return false;
  }
  const [integer, fraction = ""] = value.split(".");
  const integerValue = BigInt(integer);
  return (
    integerValue < 100n ||
    (integerValue === 100n && !/[1-9]/.test(fraction))
  );
}

function tripleFor(entry, kind) {
  const triple = Object.create(null);
  triple.anchoredHash = entry.onChain.anchoredHash;
  triple.blockHeight = entry.onChain.blockHeight;
  triple.kind = kind;
  triple.ledgerId = entry.onChain.ledgerId;
  return triple;
}

function validatePoolHealth(poolHealth) {
  if (
    !hasExactKeys(poolHealth, POOL_HEALTH_KEYS) ||
    typeof poolHealth.degradedAtSubmission !== "boolean" ||
    !decimalQuantityAtMost100(
      poolHealth.nodeParticipationPct,
    ) ||
    !isCanonicalDecimalQuantity(poolHealth.totalNodes)
  ) {
    invalid();
  }
}

function validateRendezvousSnapshot(rendezvous) {
  if (
    !hasExactKeys(rendezvous, RENDEZVOUS_KEYS) ||
    !RENDEZVOUS_CHANNELS.includes(rendezvous.channel) ||
    !RENDEZVOUS_TENANCIES.includes(rendezvous.tenancy) ||
    typeof rendezvous.degradedAtSubmission !== "boolean"
  ) {
    invalid();
  }
}

function validateSignature(signature) {
  if (
    !hasExactKeys(signature, SIGNATURE_KEYS) ||
    signature.algorithm !== "eip191" ||
    typeof signature.address !== "string" ||
    !ADDRESS_PATTERN.test(signature.address) ||
    typeof signature.signature !== "string" ||
    !SIGNATURE_PATTERN.test(signature.signature)
  ) {
    invalid();
  }
}

function validateOnChain(onChain) {
  if (
    !hasExactKeys(onChain, ON_CHAIN_KEYS) ||
    typeof onChain.anchoredHash !== "string" ||
    !HASH_PATTERN.test(onChain.anchoredHash) ||
    !isCanonicalDecimalInteger(onChain.blockHeight) ||
    typeof onChain.ledgerId !== "string" ||
    !UUID_PATTERN.test(onChain.ledgerId)
  ) {
    invalid();
  }
}

function commonHeadMatches(left, right) {
  return COMMON_MESSAGE_KEYS.every((key) =>
    isDeepStrictEqual(left[key], right[key]),
  );
}

function validateTransitionEntries(
  transitions,
  packageSessionDigest,
  deadlineValue,
) {
  if (!Array.isArray(transitions)) {
    invalid();
  }

  const blockTimes = [];
  const observedLedgerIds = new Set();
  const observedTriples = new Set();
  for (let index = 0; index < transitions.length; index += 1) {
    const entry = transitions[index];
    if (!hasExactKeys(entry, TRANSITION_ENTRY_KEYS)) {
      invalid();
    }
    validateOnChain(entry.onChain);
    try {
      validateTransition(entry.message);
    } catch {
      invalid();
    }
    if (
      entry.message.kind !== TRANSITION_KINDS[index] ||
      entry.message.sequence !== String(index + 1) ||
      entry.message.sessionDigest !== packageSessionDigest ||
      typeof entry.digest !== "string" ||
      !HASH_PATTERN.test(entry.digest)
    ) {
      invalid();
    }

    let digest;
    try {
      digest = transitionDigest(entry.message);
    } catch {
      invalid();
    }
    if (
      digest !== entry.digest ||
      digest !== entry.onChain.anchoredHash
    ) {
      invalid();
    }
    const authoritativeIdentity = [
      entry.onChain.ledgerId,
      entry.onChain.blockHeight,
      entry.onChain.anchoredHash,
    ].join("\u0000");
    if (
      observedLedgerIds.has(entry.onChain.ledgerId) ||
      observedTriples.has(authoritativeIdentity)
    ) {
      invalid();
    }
    observedLedgerIds.add(entry.onChain.ledgerId);
    observedTriples.add(authoritativeIdentity);

    let parsedBlockTime;
    try {
      parsedBlockTime = parseBlockTime(entry.blockTimeRaw);
    } catch {
      invalid();
    }
    if (
      !isCanonicalDecimalInteger(entry.blockTimeMs) ||
      entry.blockTimeMs !== String(parsedBlockTime)
    ) {
      invalid();
    }
    blockTimes.push(parsedBlockTime);

    if (index === 0) {
      if (entry.upperBoundMs !== null) {
        invalid();
      }
    } else {
      const upperBound = liveUpperBoundMs(parsedBlockTime);
      if (
        entry.upperBoundMs !== String(upperBound) ||
        !isWithinDeadline(upperBound, deadlineValue)
      ) {
        invalid();
      }
    }

    if (index > 0) {
      const previous = transitions[index - 1];
      if (
        BigInt(previous.onChain.blockHeight) >=
          BigInt(entry.onChain.blockHeight) ||
        blockTimes[index - 1] >= parsedBlockTime ||
        !commonHeadMatches(
          transitions[0].message,
          entry.message,
        ) ||
        !isDeepStrictEqual(
          entry.message.predecessor,
          tripleFor(previous, TRANSITION_KINDS[index - 1]),
        )
      ) {
        invalid();
      }
    }
  }

  if (
    transitions.length === 3 &&
    !isDeepStrictEqual(
      transitions[2].message.proposal,
      tripleFor(transitions[0], "proposal"),
    )
  ) {
    invalid();
  }
}

function validatePartyResultSnapshot(snapshot) {
  if (
    !hasExactKeys(snapshot, PARTY_RESULT_KEYS) ||
    snapshot.schema !== PARTY_RESULT_SCHEMA ||
    !PARTY_ROLES.includes(snapshot.role) ||
    !LOCAL_VERDICTS.includes(snapshot.localVerdict) ||
    snapshot.paymentMoved !== false ||
    snapshot.protocolVersion !== "1" ||
    typeof snapshot.sessionDigest !== "string" ||
    !HASH_PATTERN.test(snapshot.sessionDigest) ||
    typeof snapshot.repositorySha !== "string" ||
    !REPOSITORY_SHA_PATTERN.test(snapshot.repositorySha) ||
    typeof snapshot.promptSha256 !== "string" ||
    !HASH_PATTERN.test(snapshot.promptSha256) ||
    typeof snapshot.ackObserved !== "boolean"
  ) {
    invalid();
  }

  validatePoolHealth(snapshot.poolHealth);
  validateRendezvousSnapshot(snapshot.rendezvous);
  validateSignature(snapshot.signature);
  if (
    snapshot.poolHealth.degradedAtSubmission !==
      snapshot.rendezvous.degradedAtSubmission
  ) {
    invalid();
  }

  let computedDeadline = null;
  if (snapshot.transitions.length > 0) {
    try {
      computedDeadline = deadlineMs(
        parseBlockTime(snapshot.transitions[0].blockTimeRaw),
      );
    } catch {
      invalid();
    }
    if (snapshot.deadlineMs !== String(computedDeadline)) {
      invalid();
    }
  } else if (snapshot.deadlineMs !== null) {
    invalid();
  }

  validateTransitionEntries(
    snapshot.transitions,
    snapshot.sessionDigest,
    computedDeadline,
  );

  if (
    snapshot.ackObserved !==
      (snapshot.transitions.length === 3) ||
    (
      snapshot.localVerdict === "LOCAL_OK" &&
      (
        (snapshot.role === "payer" &&
          snapshot.transitions.length !== 3) ||
        (snapshot.role === "payee" &&
          snapshot.transitions.length < 2)
      )
    )
  ) {
    invalid();
  }

  if (snapshot.transitions.length > 0) {
    const firstMessage = snapshot.transitions[0].message;
    const roleAddress =
      snapshot.role === "payer"
        ? firstMessage.payer.address
        : firstMessage.payee.address;
    if (snapshot.signature.address !== roleAddress) {
      invalid();
    }
  }
}

function validatedPartyResultSnapshot(result, canaries = []) {
  try {
    const snapshot = materializeSnapshot(result);
    scanDisallowedText(snapshot, canaries);
    validateBilateralDomain(snapshot);
    validatePartyResultSnapshot(snapshot);
    return snapshot;
  } catch (error) {
    if (
      error instanceof BilateralPartyResultValidationError ||
      error instanceof BilateralEvidenceRedactionError
    ) {
      throw error;
    }
    throw new BilateralPartyResultValidationError();
  }
}

export function validatePartyResult(result) {
  validatedPartyResultSnapshot(result);
  return result;
}

export function buildPartySignaturePreimage(input) {
  try {
    const snapshot = materializeSnapshot(input);
    scanDisallowedText(snapshot);
    validateBilateralDomain(snapshot);
    if (
      !hasExactKeys(snapshot, PARTY_SIGNATURE_INPUT_KEYS) ||
      !PARTY_ROLES.includes(snapshot.role) ||
      typeof snapshot.sessionDigest !== "string" ||
      !HASH_PATTERN.test(snapshot.sessionDigest) ||
      !Array.isArray(snapshot.transitions)
    ) {
      invalid();
    }

    let computedDeadline = null;
    if (snapshot.transitions.length > 0) {
      computedDeadline = deadlineMs(
        parseBlockTime(snapshot.transitions[0].blockTimeRaw),
      );
    }
    validateTransitionEntries(
      snapshot.transitions,
      snapshot.sessionDigest,
      computedDeadline,
    );

    if (
      (snapshot.role === "payer" &&
        snapshot.transitions.length !== 3) ||
      (snapshot.role === "payee" &&
        (
          snapshot.transitions.length < 2 ||
          snapshot.transitions.length > 3
        ))
    ) {
      invalid();
    }

    const messages =
      snapshot.role === "payer"
        ? [
          snapshot.transitions[0].message,
          snapshot.transitions[2].message,
        ]
        : [snapshot.transitions[1].message];
    const preimage = Object.create(null);
    preimage.messages = Object.freeze(messages);
    preimage.role = snapshot.role;
    preimage.schema = PARTY_SIGNATURE_SCHEMA;
    preimage.sessionDigest = snapshot.sessionDigest;
    return Object.freeze(preimage);
  } catch (error) {
    if (
      error instanceof BilateralPartyResultValidationError ||
      error instanceof BilateralEvidenceRedactionError
    ) {
      throw error;
    }
    throw new BilateralPartyResultValidationError();
  }
}

export function partySignatureBytes(input) {
  try {
    return canonicalBytes(buildPartySignaturePreimage(input));
  } catch (error) {
    if (
      error instanceof BilateralPartyResultValidationError ||
      error instanceof BilateralEvidenceRedactionError
    ) {
      throw error;
    }
    throw new BilateralPartyResultValidationError();
  }
}

function rendezvousSentence(snapshot) {
  if (
    snapshot.channel === "derived-reference-id" &&
    snapshot.tenancy === "cross-client"
  ) {
    return "Peer evidence was discovered by derived reference ID across separate client tenancies.";
  }
  if (snapshot.channel === "derived-reference-id") {
    return "Peer evidence was discovered by derived reference ID; separate-client tenancy was not proven.";
  }
  if (snapshot.channel === "digest-hash") {
    return "Peer evidence was discovered by digest hash; Clockchain reference-ID rendezvous was not proven.";
  }
  return "Peer evidence was exchanged by out-of-band pointer; Clockchain rendezvous was not proven.";
}

export function rendezvousClaimSentence(rendezvous) {
  try {
    const snapshot = materializeSnapshot(rendezvous);
    scanDisallowedText(snapshot);
    validateBilateralDomain(snapshot);
    validateRendezvousSnapshot(snapshot);
    return rendezvousSentence(snapshot);
  } catch (error) {
    if (
      error instanceof BilateralPartyResultValidationError ||
      error instanceof BilateralEvidenceRedactionError
    ) {
      throw error;
    }
    throw new BilateralPartyResultValidationError();
  }
}

function canonicalPrettyJson(snapshot) {
  const canonical = JSON.parse(
    canonicalBytes(snapshot).toString("utf8"),
  );
  return `${JSON.stringify(canonical, null, 2)}\n`;
}

function sha256Hex(bytes) {
  return createHash("sha256").update(bytes, "utf8").digest("hex");
}

function completionMarkerBytes(json, markdown) {
  const marker = Object.create(null);
  marker.jsonSha256 = sha256Hex(json);
  marker.markdownSha256 = sha256Hex(markdown);
  marker.schema = COMPLETION_MARKER_SCHEMA;
  if (!hasExactKeys(marker, COMPLETION_MARKER_KEYS)) {
    throw new BilateralEvidenceConfigurationError();
  }
  return `${canonicalBytes(marker).toString("utf8")}\n`;
}

function renderValidatedSnapshot(snapshot) {
  const transitionLines = snapshot.transitions.flatMap(
    (entry, index) => [
      `### ${index + 1}. ${entry.message.kind}`,
      "",
      `- Ledger ID: \`${entry.onChain.ledgerId}\``,
      `- Block height: \`${entry.onChain.blockHeight}\``,
      `- Digest: \`${entry.digest}\``,
      `- Block time: \`${entry.blockTimeRaw}\``,
      `- Upper bound: ${entry.upperBoundMs === null ? "not applicable" : `\`${entry.upperBoundMs}\``}`,
      "",
    ],
  );
  const lines = [
    "# Bilateral party result",
    "",
    `- Role: \`${snapshot.role}\``,
    `- Local verdict: \`${snapshot.localVerdict}\``,
    "- Payment moved: no",
    `- Session digest: \`${snapshot.sessionDigest}\``,
    `- Repository SHA: \`${snapshot.repositorySha}\``,
    `- Prompt SHA-256: \`${snapshot.promptSha256}\``,
    `- Protocol version: \`${snapshot.protocolVersion}\``,
    "",
    "## Rendezvous",
    "",
    rendezvousSentence(snapshot.rendezvous),
    "",
    `- Channel: \`${snapshot.rendezvous.channel}\``,
    `- Tenancy: \`${snapshot.rendezvous.tenancy}\``,
    `- Degraded at submission: ${snapshot.rendezvous.degradedAtSubmission ? "yes" : "no"}`,
    "",
    "## Transition chain",
    "",
    `- Observed transitions: ${snapshot.transitions.length}`,
    `- Deadline: ${snapshot.deadlineMs === null ? "not established" : `\`${snapshot.deadlineMs}\``}`,
    `- Acknowledgment observed: ${snapshot.ackObserved ? "yes" : "no"}`,
    "",
    ...transitionLines,
    "## Validated JSON",
    "",
    "```json",
    canonicalPrettyJson(snapshot).trimEnd(),
    "```",
    "",
  ];
  return lines.join("\n");
}

export function renderPartyResultMarkdown(result) {
  const snapshot = validatedPartyResultSnapshot(result);
  return renderValidatedSnapshot(snapshot);
}

function readDataOption(options, key, fallback) {
  const property = Object.getOwnPropertyDescriptor(options, key);
  if (property === undefined) {
    return fallback;
  }
  if (
    property.enumerable !== true ||
    !Object.hasOwn(property, "value")
  ) {
    throw new BilateralEvidenceConfigurationError();
  }
  return property.value;
}

function validateWriteOptions(options) {
  if (
    options === null ||
    typeof options !== "object" ||
    types.isProxy(options) ||
    (
      Object.getPrototypeOf(options) !== Object.prototype &&
      Object.getPrototypeOf(options) !== null
    )
  ) {
    throw new BilateralEvidenceConfigurationError();
  }
  const keys = Reflect.ownKeys(options);
  if (
    keys.some(
      (key) =>
        typeof key !== "string" ||
        !WRITE_OPTION_KEYS.has(key),
    ) ||
    !keys.includes("directory") ||
    !keys.includes("result")
  ) {
    throw new BilateralEvidenceConfigurationError();
  }

  const directory = readDataOption(options, "directory");
  const result = readDataOption(options, "result");
  const canaries = readDataOption(options, "canaries", []);
  const directoryPin = readDataOption(
    options,
    "directoryPin",
    undefined,
  );
  const fileSystem = readDataOption(options, "fileSystem", {});
  if (
    typeof directory !== "string" ||
    directory.length === 0 ||
    directory.length > MAX_DIRECTORY_LENGTH ||
    directory.includes("\0")
  ) {
    throw new BilateralEvidenceConfigurationError();
  }
  if (directoryPin !== undefined) {
    if (
      directoryPin === null ||
      typeof directoryPin !== "object" ||
      types.isProxy(directoryPin) ||
      readDataOption(directoryPin, "directory") !== directory ||
      typeof readDataOption(
        directoryPin,
        "assertCurrent",
      ) !== "function" ||
      typeof readDataOption(directoryPin, "sync") !== "function"
    ) {
      throw new BilateralEvidenceConfigurationError();
    }
  }
  return {
    activeFileSystem: mergeFileSystem(fileSystem),
    canaries: validateCanaries(canaries),
    directory,
    directoryPin,
    result,
  };
}

function validateCanaries(canaries) {
  if (
    !Array.isArray(canaries) ||
    types.isProxy(canaries)
  ) {
    throw new BilateralEvidenceConfigurationError();
  }
  const keys = Reflect.ownKeys(canaries);
  const lengthProperty =
    Object.getOwnPropertyDescriptor(canaries, "length");
  const length = lengthProperty?.value;
  if (
    !lengthProperty ||
    lengthProperty.enumerable ||
    !Object.hasOwn(lengthProperty, "value") ||
    !Number.isSafeInteger(length) ||
    length < 0 ||
    length > MAX_CANARIES ||
    keys.length !== length + 1
  ) {
    throw new BilateralEvidenceConfigurationError();
  }
  const result = [];
  for (let index = 0; index < length; index += 1) {
    const property = Object.getOwnPropertyDescriptor(
      canaries,
      String(index),
    );
    if (
      property?.enumerable !== true ||
      !Object.hasOwn(property, "value") ||
      typeof property.value !== "string" ||
      property.value.length === 0 ||
      property.value.length > MAX_CANONICAL_STRING_LENGTH
    ) {
      throw new BilateralEvidenceConfigurationError();
    }
    result.push(property.value);
  }
  return Object.freeze(result);
}

function mergeFileSystem(fileSystem) {
  if (
    fileSystem === null ||
    typeof fileSystem !== "object" ||
    types.isProxy(fileSystem) ||
    (
      Object.getPrototypeOf(fileSystem) !== Object.prototype &&
      Object.getPrototypeOf(fileSystem) !== null
    )
  ) {
    throw new BilateralEvidenceConfigurationError();
  }
  const active = { ...DEFAULT_FILE_SYSTEM };
  for (const key of Reflect.ownKeys(fileSystem)) {
    const property = Object.getOwnPropertyDescriptor(
      fileSystem,
      key,
    );
    if (
      typeof key !== "string" ||
      !FILE_SYSTEM_KEYS.has(key) ||
      property?.enumerable !== true ||
      !Object.hasOwn(property, "value") ||
      typeof property.value !== "function"
    ) {
      throw new BilateralEvidenceConfigurationError();
    }
    active[key] = property.value;
  }
  return Object.freeze(active);
}

async function pinnedOperation(directoryPin, operation) {
  if (directoryPin !== undefined) {
    await directoryPin.assertCurrent();
  }
  const result = await operation();
  if (directoryPin !== undefined) {
    await directoryPin.assertCurrent();
  }
  return result;
}

async function assertAbsent(
  fileSystem,
  paths,
  directoryPin,
) {
  for (const path of paths) {
    try {
      await pinnedOperation(
        directoryPin,
        () => fileSystem.lstat(path),
      );
    } catch (error) {
      if (error?.code === "ENOENT") {
        continue;
      }
      throw new BilateralEvidenceConfigurationError();
    }
    throw new BilateralEvidenceConfigurationError();
  }
}

async function lstatForCleanup(
  fileSystem,
  path,
  directoryPin,
) {
  try {
    return await pinnedOperation(
      directoryPin,
      () => fileSystem.lstat(path),
    );
  } catch (error) {
    if (error?.code === "ENOENT") {
      return null;
    }
    throw new BilateralEvidenceAmbiguousPublicationError();
  }
}

async function cleanupTemporaryFiles(
  fileSystem,
  paths,
  directoryPin,
) {
  let failed = false;
  for (const path of paths) {
    try {
      await pinnedOperation(
        directoryPin,
        () => fileSystem.rm(path, { force: true }),
      );
      if (
        (
          await lstatForCleanup(
            fileSystem,
            path,
            directoryPin,
          )
        ) !== null
      ) {
        failed = true;
      }
    } catch {
      failed = true;
    }
  }
  return failed;
}

export async function writePartyResult(options) {
  const {
    activeFileSystem,
    canaries,
    directory,
    directoryPin,
    result,
  } = validateWriteOptions(options);

  const snapshot = validatedPartyResultSnapshot(
    result,
    canaries,
  );
  try {
    const sanitized = redact(snapshot, canaries);
    scanDisallowedText(sanitized, canaries);
    if (
      !canonicalBytes(sanitized).equals(
        canonicalBytes(snapshot),
      )
    ) {
      redactionFailure();
    }
  } catch (error) {
    if (
      error instanceof BilateralEvidenceRedactionError
    ) {
      throw error;
    }
    throw new BilateralEvidenceRedactionError();
  }

  const json = canonicalPrettyJson(snapshot);
  const markdown = renderValidatedSnapshot(snapshot);
  const suffix = randomUUID();
  const jsonPath = join(directory, "party-result.json");
  const markdownPath = join(directory, "PARTY-RESULT.md");
  const markerPath = join(
    directory,
    ".party-result.complete.json",
  );
  const temporaryJsonPath = join(
    directory,
    `.party-result.${suffix}.json.tmp`,
  );
  const temporaryMarkdownPath = join(
    directory,
    `.party-result.${suffix}.md.tmp`,
  );
  const temporaryPaths = [
    temporaryJsonPath,
    temporaryMarkdownPath,
  ];
  let finalPublicationAttempted = false;

  try {
    if (directoryPin === undefined) {
      await activeFileSystem.mkdir(directory, {
        recursive: true,
      });
    } else {
      await directoryPin.assertCurrent();
    }
    await assertAbsent(
      activeFileSystem,
      [jsonPath, markdownPath, markerPath],
      directoryPin,
    );
    await pinnedOperation(
      directoryPin,
      () =>
        activeFileSystem.writeFile(temporaryJsonPath, json, {
          encoding: "utf8",
          flag: "wx",
          mode: 0o600,
        }),
    );
    await pinnedOperation(
      directoryPin,
      () =>
        activeFileSystem.writeFile(
          temporaryMarkdownPath,
          markdown,
          {
            encoding: "utf8",
            flag: "wx",
            mode: 0o600,
          },
        ),
    );

    if (
      await pinnedOperation(
        directoryPin,
        () =>
          activeFileSystem.readFile(
            temporaryJsonPath,
            "utf8",
          ),
      ) !== json ||
      await pinnedOperation(
        directoryPin,
        () =>
          activeFileSystem.readFile(
            temporaryMarkdownPath,
            "utf8",
          ),
      ) !== markdown
    ) {
      throw new Error("temporary evidence mismatch");
    }
    finalPublicationAttempted = true;
    await pinnedOperation(
      directoryPin,
      () => activeFileSystem.link(temporaryJsonPath, jsonPath),
    );
    await pinnedOperation(
      directoryPin,
      () =>
        activeFileSystem.link(
          temporaryMarkdownPath,
          markdownPath,
        ),
    );

    const finalJson = await pinnedOperation(
      directoryPin,
      () => activeFileSystem.readFile(jsonPath, "utf8"),
    );
    const finalMarkdown = await pinnedOperation(
      directoryPin,
      () => activeFileSystem.readFile(markdownPath, "utf8"),
    );
    const rereadSnapshot = validatedPartyResultSnapshot(
      JSON.parse(finalJson),
      canaries,
    );
    if (
      finalJson !== json ||
      finalMarkdown !== markdown ||
      canonicalPrettyJson(rereadSnapshot) !== finalJson ||
      renderValidatedSnapshot(rereadSnapshot) !== finalMarkdown
    ) {
      throw new Error("final evidence mismatch");
    }
    if (directoryPin !== undefined) {
      await directoryPin.sync();
    }

    const marker = completionMarkerBytes(
      finalJson,
      finalMarkdown,
    );
    if (
      await cleanupTemporaryFiles(
        activeFileSystem,
        temporaryPaths,
        directoryPin,
      )
    ) {
      throw new BilateralEvidenceAmbiguousPublicationError();
    }

    await pinnedOperation(
      directoryPin,
      () =>
        activeFileSystem.writeFile(markerPath, marker, {
          encoding: "utf8",
          flag: "wx",
          mode: 0o600,
        }),
    );
    if (directoryPin !== undefined) {
      await directoryPin.sync();
    }
    return { jsonPath, markdownPath, markerPath };
  } catch (error) {
    await cleanupTemporaryFiles(
      activeFileSystem,
      temporaryPaths,
      directoryPin,
    );
    if (
      finalPublicationAttempted ||
      error instanceof
        BilateralEvidenceAmbiguousPublicationError
    ) {
      throw new BilateralEvidenceAmbiguousPublicationError();
    }
    if (error instanceof BilateralEvidenceConfigurationError) {
      throw error;
    }
    throw new BilateralEvidenceConfigurationError();
  }
}
