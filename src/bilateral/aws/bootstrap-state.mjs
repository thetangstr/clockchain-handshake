import { createHash } from "node:crypto";
import { types } from "node:util";

import { canonicalBytes } from "../canonical.mjs";
import {
  payerBootstrapClaimFingerprint,
  validatePayerBootstrapClaim,
} from "../local-mcp/payer-bootstrap-envelope.mjs";

export const AWS_BOOTSTRAP_STATE_SCHEMA =
  "clockchain.aws-bootstrap-state/v1";

const STATE_KEYS = Object.freeze([
  "claims",
  "paymentMoved",
  "releaseId",
  "repositorySha",
  "revision",
  "schema",
  "sessionId",
]);
const ENTRY_KEYS = Object.freeze([
  "authCapabilityDigest",
  "claim",
  "claimFingerprint",
  "createdAtMs",
  "expiresAtMs",
  "paymentMoved",
  "releaseId",
  "revision",
  "role",
  "sealedResponseBase64",
  "sealedResponseDigest",
  "sessionId",
  "status",
  "updatedAtMs",
]);
const REQUESTOR_CLAIM_KEYS = Object.freeze([
  "claimNonce",
  "paymentMoved",
  "repositorySha",
  "requestorPublicKey",
]);
const SHA40_PATTERN = /^[0-9a-f]{40}$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const UUID_V4_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const BASE64URL_32_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const STATUSES = new Set([
  "PENDING",
  "APPROVED",
  "SEALED",
  "CONSUMED",
  "REJECTED",
  "EXPIRED",
]);
const MAX_RESPONSE_BYTES = 262_144;

export class AwsBootstrapStateError extends Error {
  constructor() {
    super("AWS bootstrap state failed safely.");
    this.name = "AwsBootstrapStateError";
    this.code = "AWS_BOOTSTRAP_STATE_INVALID";
    this.category = "verification";
  }
}

function invalid() {
  throw new AwsBootstrapStateError();
}

function sanitize(error) {
  if (error instanceof AwsBootstrapStateError) {
    throw error;
  }
  invalid();
}

function dataObject(value, keys, ordered = false) {
  try {
    if (
      value === null ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      types.isProxy(value) ||
      ![Object.prototype, null].includes(
        Object.getPrototypeOf(value),
      )
    ) {
      invalid();
    }
    const ownKeys = Reflect.ownKeys(value);
    if (
      ownKeys.length !== keys.length ||
      (ordered
        ? keys.some(
          (key, index) => ownKeys[index] !== key)
        : ownKeys.some(
          (key) =>
            typeof key !== "string" ||
            !keys.includes(key)))
    ) {
      invalid();
    }
    const result = Object.create(null);
    for (const key of keys) {
      const descriptor =
        Object.getOwnPropertyDescriptor(value, key);
      if (
        descriptor?.enumerable !== true ||
        !Object.hasOwn(descriptor, "value")
      ) {
        invalid();
      }
      result[key] = descriptor.value;
    }
    return result;
  } catch (error) {
    sanitize(error);
  }
}

function timestamp(value) {
  if (
    typeof value !== "string" ||
    !/^(?:0|[1-9][0-9]*)$/.test(value) ||
    BigInt(value) > BigInt(Number.MAX_SAFE_INTEGER)
  ) {
    invalid();
  }
  return value;
}

function now(value) {
  if (
    !Number.isSafeInteger(value) ||
    value < 0
  ) {
    invalid();
  }
  return value;
}

function boundedText(value, maximum = 128) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximum ||
    value.trim() !== value ||
    !/^[ -~]+$/.test(value)
  ) {
    invalid();
  }
  return value;
}

export function validateRequestorBootstrapClaim(value) {
  try {
    const claim = dataObject(
      value,
      REQUESTOR_CLAIM_KEYS,
      true,
    );
    if (
      !UUID_V4_PATTERN.test(claim.claimNonce) ||
      claim.paymentMoved !== false ||
      !SHA40_PATTERN.test(claim.repositorySha) ||
      !BASE64URL_32_PATTERN.test(
        claim.requestorPublicKey,
      )
    ) {
      invalid();
    }
    const publicKey = Buffer.from(
      claim.requestorPublicKey,
      "base64url",
    );
    if (
      publicKey.length !== 32 ||
      publicKey.toString("base64url") !==
        claim.requestorPublicKey
    ) {
      invalid();
    }
    return Object.freeze({
      claimNonce: claim.claimNonce,
      paymentMoved: false,
      repositorySha: claim.repositorySha,
      requestorPublicKey:
        claim.requestorPublicKey,
    });
  } catch (error) {
    sanitize(error);
  }
}

export function requestorBootstrapClaimFingerprint(
  value,
) {
  try {
    return createHash("sha256")
      .update(
        canonicalBytes(
          validateRequestorBootstrapClaim(value),
        ),
      )
      .digest("hex");
  } catch (error) {
    sanitize(error);
  }
}

function claimFor(role, claim) {
  try {
    return role === "payer"
      ? validatePayerBootstrapClaim(claim)
      : role === "requestor"
        ? validateRequestorBootstrapClaim(claim)
        : invalid();
  } catch {
    invalid();
  }
}

function fingerprintFor(role, claim) {
  return role === "payer"
    ? payerBootstrapClaimFingerprint(claim)
    : requestorBootstrapClaimFingerprint(claim);
}

function entrySnapshot(value, context) {
  const entry = dataObject(value, ENTRY_KEYS, true);
  const claim = claimFor(entry.role, entry.claim);
  timestamp(entry.createdAtMs);
  timestamp(entry.expiresAtMs);
  timestamp(entry.revision);
  timestamp(entry.updatedAtMs);
  if (
    !SHA256_PATTERN.test(
      entry.authCapabilityDigest,
    ) ||
    entry.claimFingerprint !==
      fingerprintFor(entry.role, claim) ||
    entry.paymentMoved !== false ||
    entry.releaseId !== context.releaseId ||
    entry.sessionId !== context.sessionId ||
    !STATUSES.has(entry.status) ||
    Number(entry.expiresAtMs) <=
      Number(entry.createdAtMs) ||
    Number(entry.updatedAtMs) <
      Number(entry.createdAtMs)
  ) {
    invalid();
  }
  if (
    entry.role === "payer" &&
    (
      claim.releaseId !== context.releaseId ||
      claim.repositorySha !==
        context.repositorySha ||
      claim.sessionId !== context.sessionId
    )
  ) {
    invalid();
  }
  if (
    entry.role === "requestor" &&
    claim.repositorySha !== context.repositorySha
  ) {
    invalid();
  }
  const sealed =
    entry.status === "SEALED" ||
    entry.status === "CONSUMED";
  if (
    sealed !==
      (
        typeof entry.sealedResponseBase64 ===
          "string" &&
        typeof entry.sealedResponseDigest === "string"
      )
  ) {
    invalid();
  }
  if (sealed) {
    if (
      !SHA256_PATTERN.test(
        entry.sealedResponseDigest,
      ) ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
        entry.sealedResponseBase64,
      )
    ) {
      invalid();
    }
    const bytes = Buffer.from(
      entry.sealedResponseBase64,
      "base64",
    );
    if (
      bytes.length === 0 ||
      bytes.length > MAX_RESPONSE_BYTES ||
      bytes.toString("base64") !==
        entry.sealedResponseBase64 ||
      createHash("sha256")
        .update(bytes)
        .digest("hex") !==
        entry.sealedResponseDigest
    ) {
      invalid();
    }
  } else if (
    entry.sealedResponseBase64 !== null ||
    entry.sealedResponseDigest !== null
  ) {
    invalid();
  }
  return Object.freeze({
    ...entry,
    claim,
  });
}

function stateSnapshot(value) {
  const state = dataObject(value, STATE_KEYS, true);
  if (
    state.claims === null ||
    typeof state.claims !== "object" ||
    Array.isArray(state.claims) ||
    types.isProxy(state.claims) ||
    ![Object.prototype, null].includes(
      Object.getPrototypeOf(state.claims),
    ) ||
    state.paymentMoved !== false ||
    !boundedText(state.releaseId) ||
    !SHA40_PATTERN.test(state.repositorySha) ||
    !UUID_V4_PATTERN.test(state.sessionId) ||
    state.schema !== AWS_BOOTSTRAP_STATE_SCHEMA
  ) {
    invalid();
  }
  timestamp(state.revision);
  const claims = Object.create(null);
  const roles = new Set();
  let maximumEntryRevision = 0n;
  for (const key of Reflect.ownKeys(state.claims)) {
    if (
      typeof key !== "string" ||
      !SHA256_PATTERN.test(key)
    ) {
      invalid();
    }
    const descriptor =
      Object.getOwnPropertyDescriptor(
        state.claims,
        key,
      );
    if (
      descriptor?.enumerable !== true ||
      !Object.hasOwn(descriptor, "value")
    ) {
      invalid();
    }
    const entry = entrySnapshot(
      descriptor.value,
      state,
    );
    if (
      entry.claimFingerprint !== key ||
      roles.has(entry.role) ||
      BigInt(entry.revision) >
        BigInt(state.revision)
    ) {
      invalid();
    }
    roles.add(entry.role);
    maximumEntryRevision =
      BigInt(entry.revision) >
        maximumEntryRevision
        ? BigInt(entry.revision)
        : maximumEntryRevision;
    claims[key] = entry;
  }
  if (
    roles.size > 2 ||
    (
      roles.size === 0 &&
      state.revision !== "0"
    ) ||
    (
      roles.size > 0 &&
      maximumEntryRevision !==
        BigInt(state.revision)
    )
  ) {
    invalid();
  }
  return Object.freeze({
    claims: Object.freeze(claims),
    paymentMoved: false,
    releaseId: state.releaseId,
    repositorySha: state.repositorySha,
    revision: state.revision,
    schema: AWS_BOOTSTRAP_STATE_SCHEMA,
    sessionId: state.sessionId,
  });
}

export function validateBootstrapState(value) {
  try {
    return stateSnapshot(value);
  } catch (error) {
    sanitize(error);
  }
}

export function createBootstrapState(value) {
  try {
    const input = dataObject(value, [
      "paymentMoved",
      "releaseId",
      "repositorySha",
      "schema",
      "sessionId",
    ]);
    if (
      input.paymentMoved !== false ||
      !boundedText(input.releaseId) ||
      !SHA40_PATTERN.test(input.repositorySha) ||
      input.schema !== AWS_BOOTSTRAP_STATE_SCHEMA ||
      !UUID_V4_PATTERN.test(input.sessionId)
    ) {
      invalid();
    }
    return Object.freeze({
      claims: Object.freeze(
        Object.create(null),
      ),
      paymentMoved: false,
      releaseId: input.releaseId,
      repositorySha: input.repositorySha,
      revision: "0",
      schema: AWS_BOOTSTRAP_STATE_SCHEMA,
      sessionId: input.sessionId,
    });
  } catch (error) {
    sanitize(error);
  }
}

function expectedRevision(state, value) {
  timestamp(value);
  if (state.revision !== value) invalid();
}

function increment(value) {
  timestamp(value);
  if (Number(value) >= Number.MAX_SAFE_INTEGER) {
    invalid();
  }
  return String(Number(value) + 1);
}

function replaceEntry(state, fingerprint, entry) {
  const revision = increment(state.revision);
  const claims = Object.create(null);
  for (const [key, value] of Object.entries(
    state.claims,
  )) {
    claims[key] = value;
  }
  claims[fingerprint] = Object.freeze({
    ...entry,
    revision,
  });
  return stateSnapshot({
    claims,
    paymentMoved: false,
    releaseId: state.releaseId,
    repositorySha: state.repositorySha,
    revision,
    schema: AWS_BOOTSTRAP_STATE_SCHEMA,
    sessionId: state.sessionId,
  });
}

function submit({
  authCapabilityDigest,
  claim,
  expectedRevision: revision,
  expiresAtMs,
  nowMs,
  releaseId,
  role,
  sessionId,
  state: rawState,
}) {
  const state = stateSnapshot(rawState);
  expectedRevision(state, revision);
  now(nowMs);
  timestamp(expiresAtMs);
  if (
    !SHA256_PATTERN.test(authCapabilityDigest) ||
    Number(expiresAtMs) <= nowMs ||
    releaseId !== state.releaseId ||
    sessionId !== state.sessionId
  ) {
    invalid();
  }
  const canonicalClaim = claimFor(role, claim);
  const fingerprint = fingerprintFor(
    role,
    canonicalClaim,
  );
  const existing = state.claims[fingerprint];
  if (existing !== undefined) {
    if (
      existing.role !== role ||
      existing.authCapabilityDigest !==
        authCapabilityDigest ||
      existing.expiresAtMs !== expiresAtMs ||
      JSON.stringify(existing.claim) !==
        JSON.stringify(canonicalClaim)
    ) {
      invalid();
    }
    return state;
  }
  if (
    Object.values(state.claims).some(
      (entry) => entry.role === role,
    )
  ) {
    invalid();
  }
  return replaceEntry(state, fingerprint, {
    authCapabilityDigest,
    claim: canonicalClaim,
    claimFingerprint: fingerprint,
    createdAtMs: String(nowMs),
    expiresAtMs,
    paymentMoved: false,
    releaseId: state.releaseId,
    revision: state.revision,
    role,
    sealedResponseBase64: null,
    sealedResponseDigest: null,
    sessionId: state.sessionId,
    status: "PENDING",
    updatedAtMs: String(nowMs),
  });
}

export function submitPayerBootstrapClaim({
  authCapabilityDigest,
  claim,
  expectedRevision,
  expiresAtMs,
  nowMs,
  state,
} = {}) {
  try {
    return submit({
      authCapabilityDigest,
      claim,
      expectedRevision,
      expiresAtMs,
      nowMs,
      releaseId: claim?.releaseId,
      role: "payer",
      sessionId: claim?.sessionId,
      state,
    });
  } catch (error) {
    sanitize(error);
  }
}

export function submitRequestorBootstrapClaim({
  authCapabilityDigest,
  claim,
  expectedRevision,
  expiresAtMs,
  nowMs,
  releaseId,
  sessionId,
  state,
} = {}) {
  try {
    return submit({
      authCapabilityDigest,
      claim,
      expectedRevision,
      expiresAtMs,
      nowMs,
      releaseId,
      role: "requestor",
      sessionId,
      state,
    });
  } catch (error) {
    sanitize(error);
  }
}

function transition({
  claimFingerprint,
  expectedRevision: revision,
  nowMs,
  state: rawState,
  status,
}) {
  const state = stateSnapshot(rawState);
  expectedRevision(state, revision);
  now(nowMs);
  if (!SHA256_PATTERN.test(claimFingerprint)) {
    invalid();
  }
  const entry = state.claims[claimFingerprint];
  if (
    entry === undefined ||
    nowMs >= Number(entry.expiresAtMs) ||
    (
      status === "APPROVED" &&
      entry.status !== "PENDING"
    ) ||
    (
      status === "REJECTED" &&
      entry.status !== "PENDING"
    )
  ) {
    invalid();
  }
  return replaceEntry(state, claimFingerprint, {
    ...entry,
    status,
    updatedAtMs: String(nowMs),
  });
}

export function approveBootstrapClaimState(input) {
  try {
    return transition({
      ...input,
      status: "APPROVED",
    });
  } catch (error) {
    sanitize(error);
  }
}

export function rejectBootstrapClaim(input) {
  try {
    return transition({
      ...input,
      status: "REJECTED",
    });
  } catch (error) {
    sanitize(error);
  }
}

function responseSnapshot(value) {
  if (
    !Buffer.isBuffer(value) ||
    value.length === 0 ||
    value.length > MAX_RESPONSE_BYTES
  ) {
    invalid();
  }
  let parsed;
  try {
    parsed = JSON.parse(value.toString("utf8"));
  } catch {
    invalid();
  }
  if (
    !Buffer.from(
      JSON.stringify(parsed),
      "utf8",
    ).equals(value) ||
    parsed?.paymentMoved !== false
  ) {
    invalid();
  }
  return Buffer.from(value);
}

export function sealBootstrapClaim({
  claimFingerprint,
  expectedRevision: revision,
  nowMs,
  responseBytes,
  state: rawState,
} = {}) {
  try {
    const state = stateSnapshot(rawState);
    expectedRevision(state, revision);
    now(nowMs);
    if (!SHA256_PATTERN.test(claimFingerprint)) {
      invalid();
    }
    const entry = state.claims[claimFingerprint];
    const bytes = responseSnapshot(responseBytes);
    const digest = createHash("sha256")
      .update(bytes)
      .digest("hex");
    if (
      entry === undefined ||
      nowMs >= Number(entry.expiresAtMs)
    ) {
      invalid();
    }
    if (
      entry.status === "SEALED" ||
      entry.status === "CONSUMED"
    ) {
      if (
        entry.sealedResponseDigest !== digest ||
        !Buffer.from(
          entry.sealedResponseBase64,
          "base64",
        ).equals(bytes)
      ) {
        invalid();
      }
      return state;
    }
    if (entry.status !== "APPROVED") invalid();
    return replaceEntry(state, claimFingerprint, {
      ...entry,
      sealedResponseBase64:
        bytes.toString("base64"),
      sealedResponseDigest: digest,
      status: "SEALED",
      updatedAtMs: String(nowMs),
    });
  } catch (error) {
    sanitize(error);
  }
}

export function consumeBootstrapClaim({
  authCapabilityDigest,
  claimFingerprint,
  expectedRevision: revision,
  nowMs,
  state: rawState,
} = {}) {
  try {
    const state = stateSnapshot(rawState);
    expectedRevision(state, revision);
    now(nowMs);
    const entry = state.claims[claimFingerprint];
    if (
      entry === undefined ||
      entry.authCapabilityDigest !==
        authCapabilityDigest ||
      nowMs >= Number(entry.expiresAtMs)
    ) {
      invalid();
    }
    if (entry.status === "CONSUMED") return state;
    if (entry.status !== "SEALED") invalid();
    return replaceEntry(state, claimFingerprint, {
      ...entry,
      status: "CONSUMED",
      updatedAtMs: String(nowMs),
    });
  } catch (error) {
    sanitize(error);
  }
}

export function expireBootstrapClaim({
  claimFingerprint,
  expectedRevision: revision,
  nowMs,
  state: rawState,
} = {}) {
  try {
    const state = stateSnapshot(rawState);
    expectedRevision(state, revision);
    now(nowMs);
    const entry = state.claims[claimFingerprint];
    if (
      entry === undefined ||
      !["PENDING", "APPROVED"].includes(
        entry.status,
      ) ||
      nowMs < Number(entry.expiresAtMs)
    ) {
      invalid();
    }
    return replaceEntry(state, claimFingerprint, {
      ...entry,
      status: "EXPIRED",
      updatedAtMs: String(nowMs),
    });
  } catch (error) {
    sanitize(error);
  }
}

export function bootstrapStateClaim({
  authCapabilityDigest,
  claimFingerprint,
  nowMs,
  state: rawState,
} = {}) {
  try {
    const state = stateSnapshot(rawState);
    now(nowMs);
    if (
      !SHA256_PATTERN.test(
        authCapabilityDigest,
      ) ||
      !SHA256_PATTERN.test(claimFingerprint)
    ) {
      invalid();
    }
    const entry = state.claims[claimFingerprint];
    if (
      entry === undefined ||
      entry.authCapabilityDigest !==
        authCapabilityDigest ||
      (
        entry.status !== "EXPIRED" &&
        nowMs >= Number(entry.expiresAtMs)
      )
    ) {
      invalid();
    }
    return entry;
  } catch (error) {
    sanitize(error);
  }
}
