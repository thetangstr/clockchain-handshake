import {
  createPrivateKey,
  sign,
  verify,
} from "node:crypto";

import {
  canonicalBytes,
} from "../canonical.mjs";
import {
  publicKeyPemFromRawBase64,
} from "../descriptor.mjs";

export const CAPABILITY_REGISTRATION_SCHEMA =
  "clockchain.bilateral-capability-registration/v1";
export const CAPABILITY_REGISTRATION_SIGNATURE_DOMAIN =
  "clockchain.bilateral-capability-registration-signature/v1\n";

const REGISTRATION_KEYS = Object.freeze([
  "capabilities",
  "operatorKeyId",
  "paymentMoved",
  "releaseId",
  "repositorySha",
  "schema",
  "sessionId",
  "signature",
]);
const BODY_KEYS = Object.freeze(
  REGISTRATION_KEYS.filter((key) => key !== "signature"),
);
const CREATE_KEYS = Object.freeze([
  "capabilities",
  "operatorKeyId",
  "paymentMoved",
  "privateKeyPem",
  "releaseId",
  "repositorySha",
  "sessionId",
]);
const CAPABILITIES_KEYS = Object.freeze(["payee", "payer"]);
const CAPABILITY_KEYS = Object.freeze([
  "capabilityDigest",
  "expiresAtMs",
]);
const SIGNATURE_KEYS = Object.freeze([
  "algorithm",
  "keyId",
  "value",
]);
const VERIFY_KEYS = Object.freeze([
  "expectedOperatorKeyId",
  "expectedOperatorPublicKey",
  "expectedRepositorySha",
  "nowMs",
]);
const VERIFY_KEYS_WITHOUT_NOW = Object.freeze(
  VERIFY_KEYS.filter((key) => key !== "nowMs"),
);
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const REPOSITORY_SHA_PATTERN = /^[0-9a-f]{40}$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const KEY_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,63}$/;
const BASE64_PATTERN =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export class CapabilityRegistrationError extends Error {
  constructor() {
    super("Capability registration validation failed.");
    this.name = new.target.name;
    this.category = "verification";
    this.code = "COORDINATION_CAPABILITY_REGISTRATION_INVALID";
  }
}

function invalid() {
  throw new CapabilityRegistrationError();
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object") return false;
  try {
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
  } catch {
    return false;
  }
}

function exact(value, keys) {
  if (!isPlainObject(value)) invalid();
  let ownKeys;
  try {
    ownKeys = Reflect.ownKeys(value);
  } catch {
    invalid();
  }
  if (
    ownKeys.length !== keys.length ||
    ownKeys.some((key) => typeof key !== "string" || !keys.includes(key))
  ) invalid();
  const result = Object.create(null);
  for (const key of keys) {
    let descriptor;
    try {
      descriptor = Object.getOwnPropertyDescriptor(value, key);
    } catch {
      invalid();
    }
    if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, "value")) invalid();
    result[key] = descriptor.value;
  }
  return result;
}

function assertText(value, pattern) {
  if (typeof value !== "string" || !pattern.test(value)) invalid();
  return value;
}

function assertReleaseId(value) {
  if (
    typeof value !== "string" || value.length === 0 || value.length > 256 ||
    !/^[ -~]+$/.test(value) || value.trim() !== value
  ) invalid();
  return value;
}

function assertExpiry(value, nowMs) {
  if (
    typeof value !== "string" || !DECIMAL_PATTERN.test(value) ||
    value.length > 16
  ) invalid();
  let expiry;
  try {
    expiry = BigInt(value);
  } catch {
    invalid();
  }
  if (expiry > BigInt(Number.MAX_SAFE_INTEGER)) invalid();
  if (
    nowMs !== null &&
    (expiry <= BigInt(nowMs) || expiry > BigInt(nowMs) + 3_600_000n)
  ) invalid();
  return value;
}

function registrationBody(value, nowMs) {
  const data = exact(value, BODY_KEYS);
  if (
    data.schema !== CAPABILITY_REGISTRATION_SCHEMA ||
    data.paymentMoved !== false
  ) invalid();
  const capabilities = exact(data.capabilities, CAPABILITIES_KEYS);
  const parsed = Object.create(null);
  for (const role of CAPABILITIES_KEYS) {
    const entry = exact(capabilities[role], CAPABILITY_KEYS);
    parsed[role] = Object.freeze({
      capabilityDigest: assertText(entry.capabilityDigest, SHA256_PATTERN),
      expiresAtMs: assertExpiry(entry.expiresAtMs, nowMs),
    });
  }
  if (parsed.payee.capabilityDigest === parsed.payer.capabilityDigest) invalid();
  return Object.freeze({
    capabilities: Object.freeze(parsed),
    operatorKeyId: assertText(data.operatorKeyId, KEY_ID_PATTERN),
    paymentMoved: false,
    releaseId: assertReleaseId(data.releaseId),
    repositorySha: assertText(data.repositorySha, REPOSITORY_SHA_PATTERN),
    schema: CAPABILITY_REGISTRATION_SCHEMA,
    sessionId: assertText(data.sessionId, UUID_PATTERN),
  });
}

export function capabilityRegistrationPreimage(value) {
  try {
    return Buffer.concat([
      Buffer.from(CAPABILITY_REGISTRATION_SIGNATURE_DOMAIN, "utf8"),
      canonicalBytes(value),
    ]);
  } catch {
    invalid();
  }
}

function checkedRegistration(value, nowMs) {
  const data = exact(value, REGISTRATION_KEYS);
  const body = registrationBody(Object.fromEntries(
    BODY_KEYS.map((key) => [key, data[key]]),
  ), nowMs);
  const signature = exact(data.signature, SIGNATURE_KEYS);
  if (
    signature.algorithm !== "ed25519" ||
    signature.keyId !== body.operatorKeyId ||
    typeof signature.value !== "string" ||
    !BASE64_PATTERN.test(signature.value)
  ) invalid();
  const bytes = Buffer.from(signature.value, "base64");
  if (bytes.length !== 64 || bytes.toString("base64") !== signature.value) invalid();
  return Object.freeze({ body, signature: Object.freeze({ algorithm: "ed25519", keyId: body.operatorKeyId, value: signature.value }) });
}

export function createCapabilityRegistration(value) {
  try {
    const data = exact(value, CREATE_KEYS);
    if (typeof data.privateKeyPem !== "string" || data.privateKeyPem.length === 0 || Buffer.byteLength(data.privateKeyPem, "utf8") > 1_024) invalid();
    const body = registrationBody({
      capabilities: data.capabilities,
      operatorKeyId: data.operatorKeyId,
      paymentMoved: data.paymentMoved,
      releaseId: data.releaseId,
      repositorySha: data.repositorySha,
      schema: CAPABILITY_REGISTRATION_SCHEMA,
      sessionId: data.sessionId,
    }, null);
    const privateKey = createPrivateKey(data.privateKeyPem);
    if (privateKey.asymmetricKeyType !== "ed25519") invalid();
    const signature = sign(null, capabilityRegistrationPreimage(body), privateKey);
    return Object.freeze({
      ...body,
      signature: Object.freeze({
        algorithm: "ed25519",
        keyId: body.operatorKeyId,
        value: signature.toString("base64"),
      }),
    });
  } catch (error) {
    if (error instanceof CapabilityRegistrationError) throw error;
    invalid();
  }
}

export function verifyCapabilityRegistration(value, options) {
  try {
    const expected = exact(
      options,
      Object.hasOwn(options, "nowMs")
        ? VERIFY_KEYS
        : VERIFY_KEYS_WITHOUT_NOW,
    );
    const nowMs = expected.nowMs ?? null;
    if (nowMs !== null && (!Number.isSafeInteger(nowMs) || nowMs < 0)) invalid();
    const registration = checkedRegistration(value, nowMs);
    if (
      registration.body.operatorKeyId !== assertText(expected.expectedOperatorKeyId, KEY_ID_PATTERN) ||
      registration.body.repositorySha !== assertText(expected.expectedRepositorySha, REPOSITORY_SHA_PATTERN) ||
      typeof expected.expectedOperatorPublicKey !== "string"
    ) invalid();
    const publicKey = publicKeyPemFromRawBase64(expected.expectedOperatorPublicKey);
    if (!verify(null, capabilityRegistrationPreimage(registration.body), publicKey, Buffer.from(registration.signature.value, "base64"))) invalid();
    return Object.freeze({ ...registration.body, signature: registration.signature });
  } catch (error) {
    if (error instanceof CapabilityRegistrationError) throw error;
    invalid();
  }
}
