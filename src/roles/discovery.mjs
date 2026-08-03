import {
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from "node:crypto";
import { types } from "node:util";

import {
  canonicalBytes,
} from "../core/canonical.mjs";
import {
  MANDATE_MIN_WINDOW_MS,
} from "../core/deadline.mjs";
import {
  DESCRIPTOR_CHAIN_ID,
  KEY_ID_PATTERN,
  REGISTRY_ADDRESS,
  publicKeyPemFromRawBase64,
} from "../core/descriptor.mjs";
import {
  BILATERAL_PROTOCOL_ID,
} from "../core/mandate-construction.mjs";

// The signed discovery document is the ONLY handoff artifact between
// the operator and the requestor kit. It is Ed25519-signed over the
// canonical bytes of the document without the signature field; the kit
// verifies the signature against the operator public key committed in
// the repository at the pinned repositorySha.

export const DISCOVERY_SCHEMA = "handshake-discovery/v2";

const DOCUMENT_KEYS = Object.freeze([
  "chainId",
  "clockchainUrl",
  "expiresAtMs",
  "issuedAtMs",
  "kitManifestDigest",
  "kitRepoUrl",
  "operatorKeyId",
  "payerEndpoint",
  "paymentMoved",
  "protocolVersion",
  "registry",
  "relayUrl",
  "repositorySha",
  "schema",
  "sessionId",
  "subjectRun",
]);
const SIGNED_KEYS = Object.freeze([
  ...DOCUMENT_KEYS,
  "signature",
]);
const SIGNATURE_KEYS = Object.freeze([
  "algorithm",
  "keyId",
  "publicKey",
  "value",
]);

const SESSION_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA_PATTERN = /^[0-9a-f]{40}$/;
const DIGEST_PATTERN = /^[0-9a-f]{64}$/;
const DECIMAL_PATTERN = /^(0|[1-9][0-9]*)$/;
const BASE64_PATTERN =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const RAW_PUBLIC_KEY_BASE64_LENGTH = 44;
const SIGNATURE_BASE64_LENGTH = 88;

export class DiscoveryError extends Error {
  constructor(code = "DISCOVERY_INVALID") {
    super("Discovery document validation failed.");
    this.name = "DiscoveryError";
    this.category = "verification";
    this.code = code;
  }
}

function invalid(code = "DISCOVERY_INVALID") {
  throw new DiscoveryError(code);
}

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    !types.isProxy(value) &&
    (
      Object.getPrototypeOf(value) === Object.prototype ||
      Object.getPrototypeOf(value) === null
    )
  );
}

function snapshot(value, keys) {
  if (!isPlainObject(value)) invalid();
  const own = Object.keys(value);
  if (
    own.length !== keys.length ||
    !keys.every((key) => own.includes(key))
  ) {
    invalid();
  }
  const result = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(
      value,
      key,
    );
    if (
      descriptor === undefined ||
      descriptor.enumerable !== true ||
      !Object.hasOwn(descriptor, "value")
    ) {
      invalid();
    }
    result[key] = descriptor.value;
  }
  return result;
}

function isUrl(value, allowLoopbackHttp) {
  if (typeof value !== "string" || value.length > 256) {
    return false;
  }
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    return false;
  }
  if (parsed.protocol === "https:") return true;
  return (
    allowLoopbackHttp &&
    parsed.protocol === "http:" &&
    (
      parsed.hostname === "127.0.0.1" ||
      parsed.hostname === "localhost" ||
      parsed.hostname === "::1" ||
      parsed.hostname === "[::1]"
    )
  );
}

function decimal(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 16 ||
    !DECIMAL_PATTERN.test(value)
  ) {
    invalid();
  }
  return value;
}

function validateDocument(document) {
  const result = snapshot(document, DOCUMENT_KEYS);
  if (result.schema !== DISCOVERY_SCHEMA) invalid();
  if (
    typeof result.sessionId !== "string" ||
    !SESSION_ID_PATTERN.test(result.sessionId)
  ) {
    invalid();
  }
  if (
    !["rehearsal", "stakeholder"].includes(
      result.subjectRun,
    )
  ) {
    invalid();
  }
  if (result.protocolVersion !== BILATERAL_PROTOCOL_ID) {
    invalid();
  }
  if (!isUrl(result.relayUrl, true)) invalid();
  if (!isUrl(result.payerEndpoint, true)) invalid();
  if (
    typeof result.kitRepoUrl !== "string" ||
    result.kitRepoUrl.length > 256 ||
    !(
      result.kitRepoUrl.startsWith("https://") ||
      result.kitRepoUrl.startsWith("git@")
    )
  ) {
    invalid();
  }
  if (
    typeof result.repositorySha !== "string" ||
    !SHA_PATTERN.test(result.repositorySha)
  ) {
    invalid();
  }
  if (
    typeof result.kitManifestDigest !== "string" ||
    !DIGEST_PATTERN.test(result.kitManifestDigest)
  ) {
    invalid();
  }
  if (!isUrl(result.clockchainUrl, false)) invalid();
  if (result.registry !== REGISTRY_ADDRESS) invalid();
  if (
    decimal(result.chainId) !== DESCRIPTOR_CHAIN_ID
  ) {
    invalid();
  }
  const issuedAtMs = decimal(result.issuedAtMs);
  const expiresAtMs = decimal(result.expiresAtMs);
  if (
    BigInt(expiresAtMs) - BigInt(issuedAtMs) <
    BigInt(MANDATE_MIN_WINDOW_MS)
  ) {
    invalid("DISCOVERY_WINDOW");
  }
  if (result.paymentMoved !== false) invalid();
  if (
    typeof result.operatorKeyId !== "string" ||
    !KEY_ID_PATTERN.test(result.operatorKeyId)
  ) {
    invalid();
  }
  return result;
}

function validateSignatureBlock(block, operatorKeyId) {
  const result = snapshot(block, SIGNATURE_KEYS);
  if (
    result.algorithm !== "ed25519" ||
    result.keyId !== operatorKeyId ||
    typeof result.publicKey !== "string" ||
    result.publicKey.length !==
      RAW_PUBLIC_KEY_BASE64_LENGTH ||
    !BASE64_PATTERN.test(result.publicKey) ||
    typeof result.value !== "string" ||
    result.value.length !== SIGNATURE_BASE64_LENGTH ||
    !BASE64_PATTERN.test(result.value)
  ) {
    invalid("DISCOVERY_SIGNATURE_SHAPE");
  }
  return result;
}

export function buildDiscoveryDocument(document) {
  return Object.freeze(validateDocument(document));
}

export function signDiscoveryDocument({
  document,
  privateKeyPem,
}) {
  const snapshot = validateDocument(document);
  let privateKey;
  let publicKeyBase64;
  try {
    privateKey = createPrivateKey({
      key: privateKeyPem,
      format: "pem",
    });
    if (privateKey.asymmetricKeyType !== "ed25519") {
      invalid("DISCOVERY_KEY");
    }
    const der = createPublicKey(privateKey).export({
      format: "der",
      type: "spki",
    });
    publicKeyBase64 = Buffer.from(der)
      .subarray(der.length - 32)
      .toString("base64");
  } catch (error) {
    if (error instanceof DiscoveryError) throw error;
    invalid("DISCOVERY_KEY");
  }
  const value = sign(
    null,
    canonicalBytes(snapshot),
    privateKey,
  ).toString("base64");
  return Object.freeze({
    ...snapshot,
    signature: Object.freeze({
      algorithm: "ed25519",
      keyId: snapshot.operatorKeyId,
      publicKey: publicKeyBase64,
      value,
    }),
  });
}

export function verifyDiscoveryDocument({
  document,
  expectedPublicKey,
  nowMs,
}) {
  if (!Number.isSafeInteger(nowMs) || nowMs < 0) {
    invalid();
  }
  const signed = snapshot(document, SIGNED_KEYS);
  const unsignedInput = Object.create(null);
  for (const key of DOCUMENT_KEYS) {
    unsignedInput[key] = signed[key];
  }
  const unsigned = validateDocument(unsignedInput);
  const signature = validateSignatureBlock(
    signed.signature,
    unsigned.operatorKeyId,
  );
  if (
    expectedPublicKey !== undefined &&
    signature.publicKey !== expectedPublicKey
  ) {
    invalid("DISCOVERY_KEY_MISMATCH");
  }
  if (
    BigInt(nowMs) < BigInt(unsigned.issuedAtMs) ||
    BigInt(nowMs) >= BigInt(unsigned.expiresAtMs)
  ) {
    invalid("DISCOVERY_EXPIRED");
  }
  let valid;
  try {
    valid = verify(
      null,
      canonicalBytes(unsigned),
      publicKeyPemFromRawBase64(signature.publicKey),
      Buffer.from(signature.value, "base64"),
    );
  } catch {
    invalid("DISCOVERY_SIGNATURE");
  }
  if (!valid) {
    invalid("DISCOVERY_SIGNATURE");
  }
  return Object.freeze({
    ...unsigned,
    signature: Object.freeze(signature),
  });
}
