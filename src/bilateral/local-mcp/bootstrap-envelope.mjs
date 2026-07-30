import {
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
} from "node:crypto";
import { types } from "node:util";

import { canonicalBytes } from "../canonical.mjs";

export const REQUESTOR_BOOTSTRAP_ENVELOPE_ALGORITHM =
  "X25519-HKDF-SHA256-AES-256-GCM";
export const REQUESTOR_BOOTSTRAP_ENVELOPE_SCHEMA =
  "clockchain.requestor-bootstrap-envelope/v1";

const CONTEXT_KEYS = Object.freeze([
  "claimNonce",
  "paymentMoved",
  "releaseId",
  "repositorySha",
  "sessionId",
]);
const ENVELOPE_KEYS = Object.freeze([
  "algorithm",
  "ciphertextBase64url",
  "ephemeralPublicKey",
  "ivBase64url",
  "paymentMoved",
  "schema",
  "tagBase64url",
]);
const PRIVATE_KEY_KEYS = Object.freeze(["format", "value"]);
const PRIVATE_KEY_FORMAT = "pkcs8-der-base64url";
const UUID_V4_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const LOWERCASE_SHA_PATTERN = /^[0-9a-f]{40}$/;
const PRINTABLE_ASCII_PATTERN = /^[ -~]+$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const PUBLIC_KEY_DER_PREFIX = Buffer.from("302a300506032b656e032100", "hex");
const PRIVATE_KEY_DER_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
const RAW_X25519_KEY_LENGTH = 32;
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const MIN_MANIFEST_BYTES = 1;
const MAX_MANIFEST_BYTES = 65_536;
const HKDF_INFO = Buffer.from("clockchain.requestor-bootstrap-envelope/v1", "utf8");

export class RequestorBootstrapEnvelopeError extends Error {
  constructor() {
    super("Requestor bootstrap envelope validation failed.");
    this.name = "RequestorBootstrapEnvelopeError";
    this.category = "verification";
    this.code = "REQUESTOR_BOOTSTRAP_ENVELOPE_INVALID";
  }
}

function invalid() {
  throw new RequestorBootstrapEnvelopeError();
}

function exactDataObject(value, keys) {
  try {
    if (
      value === null ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      types.isProxy(value)
    ) invalid();
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) invalid();
    const ownKeys = Reflect.ownKeys(value);
    if (
      ownKeys.length !== keys.length ||
      keys.some((key, index) => ownKeys[index] !== key)
    ) invalid();
    const result = Object.create(null);
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value")) invalid();
      result[key] = descriptor.value;
    }
    return result;
  } catch (error) {
    if (error instanceof RequestorBootstrapEnvelopeError) throw error;
    invalid();
  }
}

function printable(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 256 &&
    value.trim() === value &&
    PRINTABLE_ASCII_PATTERN.test(value)
  );
}

function contextSnapshot(value) {
  const result = exactDataObject(value, CONTEXT_KEYS);
  if (
    !UUID_V4_PATTERN.test(result.claimNonce) ||
    result.paymentMoved !== false ||
    !printable(result.releaseId) ||
    !LOWERCASE_SHA_PATTERN.test(result.repositorySha) ||
    !UUID_PATTERN.test(result.sessionId)
  ) invalid();
  return Object.freeze({
    claimNonce: result.claimNonce,
    paymentMoved: false,
    releaseId: result.releaseId,
    repositorySha: result.repositorySha,
    sessionId: result.sessionId,
  });
}

function exactBase64url(value, decodedLength = null) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    !BASE64URL_PATTERN.test(value) ||
    value.includes("=")
  ) invalid();
  let decoded;
  try {
    decoded = Buffer.from(value, "base64url");
  } catch {
    invalid();
  }
  if (decoded.length === 0 || (decodedLength !== null && decoded.length !== decodedLength)) invalid();
  if (decoded.toString("base64url") !== value) invalid();
  return decoded;
}

function publicKeyFromRawBase64url(value) {
  const raw = exactBase64url(value, RAW_X25519_KEY_LENGTH);
  try {
    return createPublicKey({
      key: Buffer.concat([PUBLIC_KEY_DER_PREFIX, raw]),
      format: "der",
      type: "spki",
    });
  } catch {
    invalid();
  }
}

function privateKeyFromExport(value) {
  const wrapped = exactDataObject(value, PRIVATE_KEY_KEYS);
  if (wrapped.format !== PRIVATE_KEY_FORMAT) invalid();
  const der = exactBase64url(wrapped.value, PRIVATE_KEY_DER_PREFIX.length + RAW_X25519_KEY_LENGTH);
  if (!der.subarray(0, PRIVATE_KEY_DER_PREFIX.length).equals(PRIVATE_KEY_DER_PREFIX)) invalid();
  try {
    const privateKey = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
    if (privateKey.asymmetricKeyType !== "x25519") invalid();
    return privateKey;
  } catch (error) {
    if (error instanceof RequestorBootstrapEnvelopeError) throw error;
    invalid();
  }
}

function rawPublicKey(publicKey) {
  try {
    const der = publicKey.export({ format: "der", type: "spki" });
    if (
      der.length !== PUBLIC_KEY_DER_PREFIX.length + RAW_X25519_KEY_LENGTH ||
      !der.subarray(0, PUBLIC_KEY_DER_PREFIX.length).equals(PUBLIC_KEY_DER_PREFIX)
    ) invalid();
    return der.subarray(PUBLIC_KEY_DER_PREFIX.length);
  } catch (error) {
    if (error instanceof RequestorBootstrapEnvelopeError) throw error;
    invalid();
  }
}

function keyExport(privateKey) {
  try {
    const der = privateKey.export({ format: "der", type: "pkcs8" });
    if (
      der.length !== PRIVATE_KEY_DER_PREFIX.length + RAW_X25519_KEY_LENGTH ||
      !der.subarray(0, PRIVATE_KEY_DER_PREFIX.length).equals(PRIVATE_KEY_DER_PREFIX)
    ) invalid();
    return Object.freeze({
      format: PRIVATE_KEY_FORMAT,
      value: der.toString("base64url"),
    });
  } catch (error) {
    if (error instanceof RequestorBootstrapEnvelopeError) throw error;
    invalid();
  }
}

function envelopeSnapshot(value) {
  const result = exactDataObject(value, ENVELOPE_KEYS);
  if (
    result.algorithm !== REQUESTOR_BOOTSTRAP_ENVELOPE_ALGORITHM ||
    result.paymentMoved !== false ||
    result.schema !== REQUESTOR_BOOTSTRAP_ENVELOPE_SCHEMA
  ) invalid();
  return Object.freeze({
    algorithm: result.algorithm,
    ciphertext: exactBase64url(result.ciphertextBase64url),
    ciphertextBase64url: result.ciphertextBase64url,
    ephemeralPublicKey: result.ephemeralPublicKey,
    ephemeralPublicKeyObject: publicKeyFromRawBase64url(result.ephemeralPublicKey),
    iv: exactBase64url(result.ivBase64url, IV_LENGTH),
    ivBase64url: result.ivBase64url,
    paymentMoved: false,
    schema: result.schema,
    tag: exactBase64url(result.tagBase64url, TAG_LENGTH),
    tagBase64url: result.tagBase64url,
  });
}

function manifestSnapshot(value) {
  if (!Buffer.isBuffer(value)) invalid();
  if (value.length < MIN_MANIFEST_BYTES || value.length > MAX_MANIFEST_BYTES) invalid();
  let parsed;
  try {
    parsed = JSON.parse(value.toString("utf8"));
  } catch {
    invalid();
  }
  try {
    if (!canonicalBytes(parsed).equals(value)) invalid();
  } catch {
    invalid();
  }
  return value;
}

function deriveAesKey({ context, privateKey, publicKey, ephemeralPublicKeyBytes }) {
  let sharedSecret;
  let aesKey;
  try {
    sharedSecret = diffieHellman({ privateKey, publicKey });
    aesKey = Buffer.from(hkdfSync(
      "sha256",
      sharedSecret,
      canonicalBytes(context),
      Buffer.concat([HKDF_INFO, ephemeralPublicKeyBytes]),
      32,
    ));
    return { aesKey, sharedSecret };
  } catch {
    if (sharedSecret) sharedSecret.fill(0);
    if (aesKey) aesKey.fill(0);
    invalid();
  }
}

export async function createRequestorBootstrapKey() {
  const { privateKey, publicKey } = generateKeyPairSync("x25519");
  return Object.freeze({
    privateKey: keyExport(privateKey),
    publicKey: rawPublicKey(publicKey).toString("base64url"),
  });
}

export async function sealRequestorBootstrapManifest({ context, manifestBytes, requestorPublicKey }) {
  const aad = contextSnapshot(context);
  const plaintext = manifestSnapshot(manifestBytes);
  const recipientPublicKey = publicKeyFromRawBase64url(requestorPublicKey);
  const ephemeral = generateKeyPairSync("x25519");
  const ephemeralPublicKeyBytes = rawPublicKey(ephemeral.publicKey);
  const iv = randomBytes(IV_LENGTH);
  const { aesKey, sharedSecret } = deriveAesKey({
    context: aad,
    privateKey: ephemeral.privateKey,
    publicKey: recipientPublicKey,
    ephemeralPublicKeyBytes,
  });
  try {
    const cipher = createCipheriv("aes-256-gcm", aesKey, iv);
    cipher.setAAD(canonicalBytes(aad));
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Object.freeze({
      algorithm: REQUESTOR_BOOTSTRAP_ENVELOPE_ALGORITHM,
      ciphertextBase64url: ciphertext.toString("base64url"),
      ephemeralPublicKey: ephemeralPublicKeyBytes.toString("base64url"),
      ivBase64url: iv.toString("base64url"),
      paymentMoved: false,
      schema: REQUESTOR_BOOTSTRAP_ENVELOPE_SCHEMA,
      tagBase64url: tag.toString("base64url"),
    });
  } catch {
    invalid();
  } finally {
    sharedSecret.fill(0);
    aesKey.fill(0);
  }
}

export async function openRequestorBootstrapEnvelope({ context, envelope, requestorPrivateKey }) {
  const aad = contextSnapshot(context);
  const sealed = envelopeSnapshot(envelope);
  const privateKey = privateKeyFromExport(requestorPrivateKey);
  const ephemeralPublicKeyBytes = exactBase64url(sealed.ephemeralPublicKey, RAW_X25519_KEY_LENGTH);
  const { aesKey, sharedSecret } = deriveAesKey({
    context: aad,
    privateKey,
    publicKey: sealed.ephemeralPublicKeyObject,
    ephemeralPublicKeyBytes,
  });
  try {
    const decipher = createDecipheriv("aes-256-gcm", aesKey, sealed.iv);
    decipher.setAAD(canonicalBytes(aad));
    decipher.setAuthTag(sealed.tag);
    const plaintext = Buffer.concat([
      decipher.update(sealed.ciphertext),
      decipher.final(),
    ]);
    return Buffer.from(manifestSnapshot(plaintext));
  } catch {
    invalid();
  } finally {
    sharedSecret.fill(0);
    aesKey.fill(0);
  }
}
