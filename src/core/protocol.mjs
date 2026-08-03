// Shared verification core for clockchain.bilateral-authorization/v1
// (design sections 4.11-4.13 and 5.1-5.3). Both role runners AND the
// operator's aggregate verifier import from here, so everything is
// fail-closed and deterministic: typed errors with terminal codes,
// decimal-string block heights, and the trust-path ban list enforced by
// never reading the banned fields at all. The one authorizing state of
// the protocol is deliberately not spelled anywhere in this file — a
// companion test scans the source to keep it that way — because only
// the operator's aggregate verifier may ever emit it (section 5.1).

import { parseBlockTime } from "./blocktime.mjs";
import { canonicalBytes } from "./canonical.mjs";
import {
  ProposalAmountAmbiguousError,
  ProposalAmountNotFoundError,
  recoverProposalByDigest,
  transitionDigest,
} from "./messages.mjs";
import {
  assertByteEqualReferenceId,
  sessionKey,
} from "./refid.mjs";
import {
  McpRateLimitedError,
  McpVerificationError,
  assertCrossPartyVerification,
} from "./clockchain.mjs";

const HASH_PATTERN = /^[0-9a-f]{64}$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/i;
const MAX_TEXT_LENGTH = 256;
const VERIFY_INPUT_KEYS = Object.freeze([
  "client",
  "expectedDigest",
  "message",
  "referenceId",
]);
const VERIFY_REQUIRED_KEYS = Object.freeze([
  "client",
  "message",
  "referenceId",
]);
const CLIENT_METHODS = Object.freeze([
  "getBlock",
  "resolveAgent",
  "searchActions",
  "verifyCrossParty",
]);

export const RUNNER_STATES = Object.freeze([
  "UNSTARTED",
  "RENDEZVOUS_OK",
  "PROPOSED",
  "ACCEPTED",
  "ACKNOWLEDGED",
]);

export const TERMINAL_FAILURE_CODES = Object.freeze([
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

export class BilateralProtocolError extends Error {
  constructor(message, code) {
    super(message);
    this.name = new.target.name;
    this.category = "verification";
    this.code = code;
  }
}

export class ProtocolFailureError extends BilateralProtocolError {
  constructor(message, terminalCode) {
    if (!TERMINAL_FAILURE_CODES.includes(terminalCode)) {
      throw new BilateralProtocolError(
        "Terminal code is outside the frozen failure list.",
        "PROTOCOL_TERMINAL_CODE",
      );
    }
    super(message, terminalCode);
    this.terminalCode = terminalCode;
  }
}

export class WriteIntentMarkerExistsError extends BilateralProtocolError {
  constructor() {
    super(
      "A write-intent marker already exists for this session and slot; " +
        "the runner must not write and may only re-discover.",
      "WRITE_INTENT_EXISTS",
    );
  }
}

export function createRunnerStateMachine() {
  let stateIndex = 0;
  let failureCode = null;

  return {
    get state() {
      return RUNNER_STATES[stateIndex];
    },
    get failureCode() {
      return failureCode;
    },
    isTerminal() {
      return failureCode !== null;
    },
    advance(nextState) {
      if (failureCode !== null) {
        throw new BilateralProtocolError(
          "A failed runner can never advance again.",
          "PROTOCOL_STATE_TERMINAL",
        );
      }
      if (
        stateIndex + 1 >= RUNNER_STATES.length ||
        nextState !== RUNNER_STATES[stateIndex + 1]
      ) {
        throw new BilateralProtocolError(
          "Runner states advance one ladder step at a time.",
          "PROTOCOL_STATE_ORDER",
        );
      }
      stateIndex += 1;
    },
    fail(code) {
      if (failureCode !== null) {
        throw new BilateralProtocolError(
          "A failed runner keeps its first terminal code.",
          "PROTOCOL_STATE_TERMINAL",
        );
      }
      if (!TERMINAL_FAILURE_CODES.includes(code)) {
        throw new BilateralProtocolError(
          "Terminal code is outside the frozen failure list.",
          "PROTOCOL_TERMINAL_CODE",
        );
      }
      failureCode = code;
    },
  };
}

const INTERNAL_FAILURES = new WeakSet();

function terminal(code) {
  const error = new ProtocolFailureError(
    "Bilateral transition verification failed closed.",
    code,
  );
  INTERNAL_FAILURES.add(error);
  return error;
}

function safeInstanceOf(value, constructor) {
  try {
    return value instanceof constructor;
  } catch {
    return false;
  }
}

export function mapProposalRecoveryFailure(error) {
  if (
    safeInstanceOf(error, ProposalAmountNotFoundError) ||
    safeInstanceOf(error, ProposalAmountAmbiguousError)
  ) {
    return terminal("AMOUNT_UNRESOLVED");
  }
  return terminal("FAILED");
}

export function recoverAnchoredProposal(input) {
  try {
    return recoverProposalByDigest(input);
  } catch (error) {
    throw mapProposalRecoveryFailure(error);
  }
}

function isProtocolFailure(value) {
  return (
    value !== null &&
    (
      typeof value === "object" ||
      typeof value === "function"
    ) &&
    INTERNAL_FAILURES.has(value)
  );
}

function isRateLimited(value) {
  return safeInstanceOf(value, McpRateLimitedError);
}

function isMcpVerification(value) {
  return safeInstanceOf(value, McpVerificationError);
}

function safeErrorCode(value) {
  try {
    const descriptor = Object.getOwnPropertyDescriptor(value, "code");
    return (
      descriptor !== undefined &&
      Object.hasOwn(descriptor, "value") &&
      typeof descriptor.value === "string"
    )
      ? descriptor.value
      : null;
  } catch {
    return null;
  }
}

function isPlainRecord(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function dataFields(value, requiredKeys) {
  if (!isPlainRecord(value)) {
    return null;
  }
  const snapshot = {};
  for (const key of requiredKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
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

function verifyInputSnapshot(input) {
  if (!isPlainRecord(input)) {
    throw terminal("FAILED");
  }
  const keys = Reflect.ownKeys(input);
  if (
    keys.some((key) => typeof key !== "string") ||
    !keys.every((key) => VERIFY_INPUT_KEYS.includes(key)) ||
    !VERIFY_REQUIRED_KEYS.every((key) => keys.includes(key))
  ) {
    throw terminal("FAILED");
  }
  const snapshot = {};
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (
      descriptor === undefined ||
      !Object.hasOwn(descriptor, "value")
    ) {
      throw terminal("FAILED");
    }
    snapshot[key] = descriptor.value;
  }
  if (
    typeof snapshot.referenceId !== "string" ||
    snapshot.referenceId.length === 0 ||
    snapshot.referenceId.length > 120 ||
    (
      Object.hasOwn(snapshot, "expectedDigest") &&
      (
        typeof snapshot.expectedDigest !== "string" ||
        !HASH_PATTERN.test(snapshot.expectedDigest)
      )
    )
  ) {
    throw terminal("FAILED");
  }
  if (!isPlainRecord(snapshot.client)) {
    throw terminal("FAILED");
  }
  const methods = {};
  for (const name of CLIENT_METHODS) {
    const descriptor = Object.getOwnPropertyDescriptor(
      snapshot.client,
      name,
    );
    if (
      descriptor === undefined ||
      !Object.hasOwn(descriptor, "value") ||
      typeof descriptor.value !== "function"
    ) {
      throw terminal("FAILED");
    }
    methods[name] = descriptor.value;
  }
  return { ...snapshot, methods };
}

function canonicalHeight(value) {
  if (
    typeof value === "string" &&
    value.length <= MAX_TEXT_LENGTH &&
    DECIMAL_PATTERN.test(value)
  ) {
    return value;
  }
  if (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= 0
  ) {
    return String(value);
  }
  return null;
}

function rateLimitBody(value) {
  try {
    const fields = dataFields(value, ["error"]);
    return fields?.error === "rate_limited";
  } catch {
    return false;
  }
}

function singleSearchRecord(result) {
  if (!Array.isArray(result)) {
    throw terminal(
      rateLimitBody(result) ? "RATE_BLOCKED" : "FAILED",
    );
  }
  const lengthProperty = Object.getOwnPropertyDescriptor(
    result,
    "length",
  );
  const length = lengthProperty?.value;
  if (
    lengthProperty === undefined ||
    lengthProperty.enumerable ||
    !Object.hasOwn(lengthProperty, "value") ||
    !Number.isSafeInteger(length) ||
    length < 0
  ) {
    throw terminal("FAILED");
  }
  if (length === 0) {
    throw terminal("EXPIRED");
  }
  if (length > 1) {
    throw terminal("DUPLICATE");
  }
  const recordProperty = Object.getOwnPropertyDescriptor(result, "0");
  if (
    recordProperty?.enumerable !== true ||
    !Object.hasOwn(recordProperty, "value")
  ) {
    throw terminal("FAILED");
  }
  return recordProperty.value;
}

function searchRecordSnapshot(record) {
  const snapshot = dataFields(record, [
    "assetHash",
    "assetReferenceId",
    "blockHeight",
    "hashType",
    "ledgerId",
  ]);
  const blockHeight =
    snapshot === null ? null : canonicalHeight(snapshot.blockHeight);
  if (
    snapshot === null ||
    typeof snapshot.ledgerId !== "string" ||
    !UUID_PATTERN.test(snapshot.ledgerId) ||
    typeof snapshot.assetReferenceId !== "string" ||
    snapshot.assetReferenceId.length === 0 ||
    snapshot.assetReferenceId.length > 120 ||
    typeof snapshot.assetHash !== "string" ||
    !HASH_PATTERN.test(snapshot.assetHash) ||
    blockHeight === null ||
    typeof snapshot.hashType !== "string" ||
    snapshot.hashType.length > MAX_TEXT_LENGTH
  ) {
    throw terminal("FAILED");
  }
  return { ...snapshot, blockHeight };
}

function crossPartySnapshot(result) {
  const root = dataFields(result, ["onChain"]);
  if (root === null || !isPlainRecord(root.onChain)) {
    throw terminal("FAILED");
  }
  const onChain = dataFields(root.onChain, [
    "assetReferenceId",
    "anchoredHash",
    "blockHeight",
    "keyless",
    "ledgerId",
    "verifiedAgainst",
  ]);
  if (onChain === null) {
    throw terminal("FAILED");
  }
  if (
    onChain.verifiedAgainst !== "on-chain block" ||
    onChain.keyless !== true
  ) {
    throw terminal("ANCHOR_UNVERIFIED");
  }
  if (
    typeof onChain.ledgerId !== "string" ||
    !UUID_PATTERN.test(onChain.ledgerId) ||
    canonicalHeight(onChain.blockHeight) === null ||
    typeof onChain.anchoredHash !== "string" ||
    !HASH_PATTERN.test(onChain.anchoredHash) ||
    typeof onChain.assetReferenceId !== "string" ||
    onChain.assetReferenceId.length === 0 ||
    onChain.assetReferenceId.length > 120
  ) {
    throw terminal("FAILED");
  }
  return { onChain };
}

function blockSnapshot(block) {
  const snapshot = dataFields(block, [
    "blockHeight",
    "blockTime",
    "proposerAddress",
  ]);
  const blockHeight =
    snapshot === null ? null : canonicalHeight(snapshot.blockHeight);
  if (
    snapshot === null ||
    blockHeight === null ||
    typeof snapshot.proposerAddress !== "string" ||
    snapshot.proposerAddress.length === 0 ||
    snapshot.proposerAddress.length > MAX_TEXT_LENGTH
  ) {
    throw terminal("FAILED");
  }
  return {
    ...snapshot,
    blockHeight,
  };
}

function identitySnapshot(identity) {
  const snapshot = dataFields(identity, ["owner"]);
  if (
    snapshot === null ||
    typeof snapshot.owner !== "string" ||
    !ADDRESS_PATTERN.test(snapshot.owner)
  ) {
    throw terminal("FAILED");
  }
  return snapshot;
}

export async function verifyTransition(input) {
  let snapshot;
  let message;
  let digest;
  let expectedReferenceId;
  let author;
  try {
    snapshot = verifyInputSnapshot(input);
    message = JSON.parse(
      canonicalBytes(snapshot.message).toString("utf8"),
    );
    digest = transitionDigest(message);
    expectedReferenceId = sessionKey(
      message.sessionDigest,
      message.kind,
    );
    author =
      message.kind === "acceptance"
        ? message.payee
        : message.payer;
  } catch (error) {
    if (isProtocolFailure(error)) {
      throw error;
    }
    throw terminal("FAILED");
  }

  try {
    assertByteEqualReferenceId(
      snapshot.referenceId,
      expectedReferenceId,
    );
  } catch {
    throw terminal("BINDING_MISMATCH");
  }

  if (
    Object.hasOwn(snapshot, "expectedDigest") &&
    snapshot.expectedDigest !== digest
  ) {
    throw terminal("BINDING_MISMATCH");
  }

  let searchResult;
  try {
    searchResult = await snapshot.methods.searchActions.call(
      snapshot.client,
      { asset_reference_id: expectedReferenceId },
    );
  } catch (error) {
    if (isRateLimited(error)) {
      throw terminal("RATE_BLOCKED");
    }
    throw terminal("FAILED");
  }

  let record;
  try {
    record = searchRecordSnapshot(
      singleSearchRecord(searchResult),
    );
  } catch (error) {
    if (isProtocolFailure(error)) {
      throw error;
    }
    throw terminal("FAILED");
  }
  if (record.assetReferenceId !== expectedReferenceId) {
    throw terminal("FAILED");
  }
  if (
    record.assetHash !== digest ||
    record.hashType !== "SHA-256"
  ) {
    throw terminal("BINDING_MISMATCH");
  }

  let crossPartyResult;
  try {
    crossPartyResult =
      await snapshot.methods.verifyCrossParty.call(
        snapshot.client,
        {
          blockHeight: record.blockHeight,
          ledgerId: record.ledgerId,
        },
      );
  } catch (error) {
    if (isRateLimited(error)) {
      throw terminal("RATE_BLOCKED");
    }
    throw terminal("ANCHOR_UNVERIFIED");
  }

  let crossParty;
  try {
    crossParty = crossPartySnapshot(crossPartyResult);
    assertCrossPartyVerification(crossParty, {
      anchoredHash: record.assetHash,
      assetReferenceId: record.assetReferenceId,
      blockHeight: record.blockHeight,
      ledgerId: record.ledgerId,
    });
  } catch (error) {
    if (isProtocolFailure(error)) {
      throw error;
    }
    if (
      isMcpVerification(error) &&
      safeErrorCode(error) === "MCP_CROSS_PARTY_BINDING_MISMATCH"
    ) {
      throw terminal("BINDING_MISMATCH");
    }
    if (isMcpVerification(error)) {
      throw terminal("ANCHOR_UNVERIFIED");
    }
    throw terminal("FAILED");
  }
  if (crossParty.onChain.anchoredHash !== digest) {
    throw terminal("BINDING_MISMATCH");
  }

  let block;
  try {
    block = blockSnapshot(
      await snapshot.methods.getBlock.call(snapshot.client, {
        height: record.blockHeight,
      }),
    );
  } catch (error) {
    if (isRateLimited(error)) {
      throw terminal("RATE_BLOCKED");
    }
    if (isProtocolFailure(error)) {
      if (error.terminalCode === "FAILED") {
        throw error;
      }
      throw terminal("ANCHOR_UNVERIFIED");
    }
    throw terminal("ANCHOR_UNVERIFIED");
  }
  if (block.blockHeight !== record.blockHeight) {
    throw terminal("BINDING_MISMATCH");
  }

  let blockTimeMs;
  try {
    blockTimeMs = parseBlockTime(block.blockTime);
  } catch {
    throw terminal("ANCHOR_UNVERIFIED");
  }

  let identity;
  try {
    identity = identitySnapshot(
      await snapshot.methods.resolveAgent.call(
        snapshot.client,
        author.agentId,
      ),
    );
  } catch (error) {
    if (isRateLimited(error)) {
      throw terminal("RATE_BLOCKED");
    }
    if (isProtocolFailure(error)) {
      throw error;
    }
    throw terminal("FAILED");
  }
  if (
    identity.owner.toLowerCase() !==
      author.address.toLowerCase()
  ) {
    throw terminal("FAILED");
  }

  return Object.freeze({
    ledgerId: record.ledgerId,
    blockHeight: record.blockHeight,
    anchoredHash: digest,
    assetReferenceId: record.assetReferenceId,
    blockTimeRaw: block.blockTime,
    blockTimeMs,
  });
}
