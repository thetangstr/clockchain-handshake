import {
  createHash,
  timingSafeEqual,
} from "node:crypto";

import {
  canonicalizeReceiptEventValue,
} from "../../canonical.mjs";
import {
  SENSITIVE_KEY,
  assertSecretFree,
} from "../../redact.mjs";
import {
  verifyDescriptorEnvelope,
} from "../descriptor.mjs";
import {
  parseCoordinationEnrollment,
} from "./enrollment.mjs";

export const MAX_RELAY_ARTIFACT_BYTES = 1_048_576;
export const MAX_RELAY_PACKAGE_BYTES = 3_145_728;
export const RELAY_PACKAGE_SCHEMA =
  "clockchain.bilateral-relay-package/v1";

export const ARTIFACT_POLICIES = Object.freeze({
  "coordination-enrollment": Object.freeze({
    maximum: 65_536,
  }),
  "coordination-receipt": Object.freeze({
    maximum: 65_536,
  }),
  "failure-summary": Object.freeze({
    maximum: 16_384,
  }),
  "identity-package": Object.freeze({
    maximum: 1_048_576,
    markerRequired: true,
  }),
  "invitation-public-bundle": Object.freeze({
    maximum: 16_384,
  }),
  "party-result-package": Object.freeze({
    maximum: 3_145_728,
    markerRequired: true,
  }),
  "preflight-aggregate-report": Object.freeze({
    maximum: 1_048_576,
    markerRequired: true,
  }),
  "preflight-participant-report": Object.freeze({
    maximum: 1_048_576,
    markerRequired: true,
  }),
  "preflight-plan": Object.freeze({
    maximum: 65_536,
  }),
  "preflight-public-key": Object.freeze({
    maximum: 65_536,
  }),
  "signed-descriptor": Object.freeze({
    maximum: 1_048_576,
  }),
  "token-commitment": Object.freeze({
    maximum: 65_536,
  }),
});

const INPUT_KEYS = Object.freeze([
  "artifactType",
  "bytes",
  "expectedDigest",
  "secretCanaries",
]);
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const PRIVATE_MATERIAL_PATTERN =
  /-----BEGIN (?:EC |OPENSSH |RSA )?PRIVATE KEY-----|(?:private.?key|secret|token|authorization|invite.?code|ciphertext)\s*["']?\s*[:=]\s*["']?[A-Za-z0-9+/_-]{16,}/i;
const ARCHIVE_PREFIXES = Object.freeze([
  Buffer.from([0x1f, 0x8b]),
  Buffer.from([0x50, 0x4b, 0x03, 0x04]),
  Buffer.from([0x50, 0x4b, 0x05, 0x06]),
  Buffer.from([0x50, 0x4b, 0x07, 0x08]),
]);
const MAX_CANARIES = 64;
const MAX_CANARY_BYTES = 8_192;

export class RelayArtifactError extends Error {
  constructor() {
    super("Relay artifact validation failed.");
    this.name = new.target.name;
    this.category = "verification";
    this.code = "RELAY_ARTIFACT_INVALID";
  }
}

function invalid() {
  throw new RelayArtifactError();
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object") {
    return false;
  }
  try {
    const prototype = Object.getPrototypeOf(value);
    return (
      prototype === Object.prototype || prototype === null
    );
  } catch {
    return false;
  }
}

function readExactData(value, keys) {
  if (!isPlainObject(value)) {
    invalid();
  }
  let ownKeys;
  try {
    ownKeys = Reflect.ownKeys(value);
  } catch {
    invalid();
  }
  if (
    ownKeys.length !== keys.length ||
    ownKeys.some(
      (key) =>
        typeof key !== "string" || !keys.includes(key),
    )
  ) {
    invalid();
  }
  const result = Object.create(null);
  for (const key of keys) {
    let descriptor;
    try {
      descriptor = Object.getOwnPropertyDescriptor(value, key);
    } catch {
      invalid();
    }
    if (
      descriptor?.enumerable !== true ||
      !Object.hasOwn(descriptor, "value")
    ) {
      invalid();
    }
    Object.defineProperty(result, key, {
      enumerable: true,
      value: descriptor.value,
    });
  }
  return Object.freeze(result);
}

function canonicalJsonBytes(value) {
  try {
    return Buffer.from(
      JSON.stringify(canonicalizeReceiptEventValue(value)),
      "utf8",
    );
  } catch {
    invalid();
  }
}

function parseCanonicalJson(bytes) {
  let parsed;
  try {
    const text = bytes.toString("utf8");
    if (Buffer.byteLength(text, "utf8") !== bytes.length) {
      invalid();
    }
    parsed = JSON.parse(text);
    if (!canonicalJsonBytes(parsed).equals(bytes)) {
      invalid();
    }
    return parsed;
  } catch (error) {
    if (error instanceof RelayArtifactError) {
      throw error;
    }
    invalid();
  }
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function normalizeCanaries(value) {
  if (
    !Array.isArray(value) ||
    value.length > MAX_CANARIES ||
    Reflect.ownKeys(value).length !== value.length + 1
  ) {
    invalid();
  }
  const result = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(
      value,
      String(index),
    );
    if (
      descriptor?.enumerable !== true ||
      !Object.hasOwn(descriptor, "value") ||
      typeof descriptor.value !== "string" ||
      descriptor.value.length === 0 ||
      Buffer.byteLength(descriptor.value, "utf8") >
        MAX_CANARY_BYTES
    ) {
      invalid();
    }
    result.push(descriptor.value);
  }
  return Object.freeze(result);
}

function assertDigest(expectedDigest, bytes) {
  if (
    typeof expectedDigest !== "string" ||
    !SHA256_PATTERN.test(expectedDigest)
  ) {
    invalid();
  }
  const actual = sha256(bytes);
  if (
    !timingSafeEqual(
      Buffer.from(expectedDigest, "ascii"),
      Buffer.from(actual, "ascii"),
    )
  ) {
    invalid();
  }
  return actual;
}

function assertNotArchive(bytes) {
  if (
    ARCHIVE_PREFIXES.some(
      (prefix) =>
        bytes.length >= prefix.length &&
        bytes.subarray(0, prefix.length).equals(prefix),
    ) ||
    (bytes.length >= 262 &&
      bytes.subarray(257, 262).toString("ascii") === "ustar")
  ) {
    invalid();
  }
}

function assertSafeBytes(bytes, parsed, canaries) {
  try {
    const text = bytes.toString("utf8");
    if (
      Buffer.byteLength(text, "utf8") !== bytes.length ||
      PRIVATE_MATERIAL_PATTERN.test(text)
    ) {
      invalid();
    }
    assertSecretFree(text, canaries);
    assertNoForbiddenKeys(parsed);
  } catch (error) {
    if (error instanceof RelayArtifactError) {
      throw error;
    }
    invalid();
  }
}

function assertNoForbiddenKeys(value) {
  const seen = new Set();
  let remaining = 4_096;
  function visit(entry, depth) {
    if (
      entry === null ||
      typeof entry !== "object" ||
      seen.has(entry)
    ) {
      return;
    }
    if (depth > 64 || remaining === 0) {
      invalid();
    }
    remaining -= 1;
    seen.add(entry);
    if (Array.isArray(entry)) {
      for (const item of entry) {
        visit(item, depth + 1);
      }
      return;
    }
    if (!isPlainObject(entry)) {
      invalid();
    }
    for (const key of Reflect.ownKeys(entry)) {
      const descriptor = Object.getOwnPropertyDescriptor(
        entry,
        key,
      );
      if (
        typeof key !== "string" ||
        descriptor?.enumerable !== true ||
        !Object.hasOwn(descriptor, "value") ||
        (SENSITIVE_KEY.test(key) &&
          !["tokenCommitments", "tokenSha256"].includes(
            key,
          ))
      ) {
        invalid();
      }
      visit(descriptor.value, depth + 1);
    }
  }
  visit(value, 1);
}

function validateSignedDescriptor(bytes, parsed, canaries) {
  assertSafeBytes(bytes, parsed, canaries);
  let publicKey;
  try {
    const operator = readExactData(parsed, [
      "descriptor",
      "operator",
    ]).operator;
    publicKey = readExactData(operator, [
      "algorithm",
      "keyId",
      "publicKey",
      "signature",
    ]).publicKey;
    verifyDescriptorEnvelope(parsed, {
      repositoryPublicKey: publicKey,
    });
  } catch {
    invalid();
  }
}

function validateCoordinationEnrollment(
  bytes,
  parsed,
  canaries,
) {
  assertSafeBytes(bytes, parsed, canaries);
  try {
    parseCoordinationEnrollment(bytes);
  } catch {
    invalid();
  }
}

export function validateRelayArtifact(input) {
  try {
    const data = readExactData(input, INPUT_KEYS);
    const policy = ARTIFACT_POLICIES[data.artifactType];
    if (
      policy === undefined ||
      !Buffer.isBuffer(data.bytes) ||
      data.bytes.length === 0 ||
      data.bytes.length > policy.maximum
    ) {
      invalid();
    }
    const bytes = Buffer.from(data.bytes);
    const canaries = normalizeCanaries(data.secretCanaries);
    assertNotArchive(bytes);
    const digest = assertDigest(
      data.expectedDigest,
      bytes,
    );
    const parsed = parseCanonicalJson(bytes);
    if (
      data.artifactType === "coordination-enrollment"
    ) {
      validateCoordinationEnrollment(
        bytes,
        parsed,
        canaries,
      );
    } else if (
      data.artifactType === "signed-descriptor"
    ) {
      validateSignedDescriptor(bytes, parsed, canaries);
    } else {
      // The allowlist reserves protocol artifact names and limits.
      // Publication remains disabled until a repository-owned exact
      // schema and trust validator is available for that type.
      invalid();
    }
    return Object.freeze({
      artifactType: data.artifactType,
      byteLength: String(bytes.length),
      digest,
    });
  } catch (error) {
    if (error instanceof RelayArtifactError) {
      throw error;
    }
    invalid();
  }
}
