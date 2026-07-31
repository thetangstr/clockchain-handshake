#!/usr/bin/env node
import { createHash, createPrivateKey, createPublicKey, sign, verify, X509Certificate } from "node:crypto";
import { readFile } from "node:fs/promises";

import { canonicalBytes } from "../src/bilateral/canonical.mjs";

export const REQUESTOR_DISCOVERY_SCHEMA = "clockchain.requestor-discovery/v1";

const DISCOVERY_KEYS = Object.freeze([
  "certificateFingerprint",
  "certificateUrl",
  "expiresAtMs",
  "operatorKeyId",
  "publicUrl",
  "releaseId",
  "repositorySha",
  "sessionId",
  "signature",
]);
const UNSIGNED_DISCOVERY_KEYS = DISCOVERY_KEYS.slice(0, -1);
const SIGNATURE_KEYS = Object.freeze(["algorithm", "keyId", "value"]);
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const SHA40_PATTERN = /^[0-9a-f]{40}$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const KEY_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,63}$/;
const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

class RequestorDiscoveryError extends Error {
  constructor() {
    super("Requestor discovery failed safely.");
  }
}

function fail() {
  throw new RequestorDiscoveryError();
}

function exactObject(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) fail();
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.length !== keys.length || keys.some((key, index) => ownKeys[index] !== key)) fail();
  return value;
}

function httpsUrl(value, path = null) {
  if (typeof value !== "string") fail();
  let url;
  try {
    url = new URL(value);
  } catch {
    fail();
  }
  if (url.protocol !== "https:" || url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== "") fail();
  if (path !== null && url.pathname !== path) fail();
  return value;
}

function unsignedDiscovery(input) {
  const data = exactObject(input, UNSIGNED_DISCOVERY_KEYS);
  if (
    typeof data.certificateFingerprint !== "string" ||
    !SHA256_PATTERN.test(data.certificateFingerprint) ||
    !/^(?:0|[1-9][0-9]*)$/.test(data.expiresAtMs) ||
    BigInt(data.expiresAtMs) > BigInt(Number.MAX_SAFE_INTEGER) ||
    typeof data.operatorKeyId !== "string" ||
    !KEY_ID_PATTERN.test(data.operatorKeyId) ||
    typeof data.releaseId !== "string" ||
    data.releaseId.length === 0 ||
    data.releaseId.length > 128 ||
    typeof data.repositorySha !== "string" ||
    !SHA40_PATTERN.test(data.repositorySha) ||
    typeof data.sessionId !== "string" ||
    !UUID_PATTERN.test(data.sessionId)
  ) {
    fail();
  }
  httpsUrl(data.certificateUrl);
  httpsUrl(data.publicUrl, "/mcp");
  return Object.freeze({ ...data });
}

function ed25519PublicKeyFromRawBase64(value) {
  if (typeof value !== "string" || !BASE64_PATTERN.test(value)) fail();
  const raw = Buffer.from(value, "base64");
  if (raw.length !== 32 || raw.toString("base64") !== value) fail();
  return createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, raw]), format: "der", type: "spki" });
}

function signatureObject(value, keyId) {
  const signature = exactObject(value, SIGNATURE_KEYS);
  if (
    signature.algorithm !== "ed25519" ||
    signature.keyId !== keyId ||
    typeof signature.value !== "string" ||
    !BASE64_PATTERN.test(signature.value) ||
    Buffer.from(signature.value, "base64").length !== 64 ||
    Buffer.from(signature.value, "base64").toString("base64") !== signature.value
  ) {
    fail();
  }
  return signature;
}

export function createSignedRequestorDiscovery(input) {
  const { operatorPrivateKey, ...unsignedInput } = input;
  const unsigned = unsignedDiscovery(unsignedInput);
  if (!operatorPrivateKey || operatorPrivateKey.asymmetricKeyType !== "ed25519") fail();
  return Object.freeze({
    ...unsigned,
    signature: Object.freeze({
      algorithm: "ed25519",
      keyId: unsigned.operatorKeyId,
      value: sign(null, canonicalBytes(unsigned), operatorPrivateKey).toString("base64"),
    }),
  });
}

export function verifySignedRequestorDiscovery({ discovery, nowMs = Date.now(), operatorPublicKey, repositorySha } = {}) {
  const value = exactObject(discovery, DISCOVERY_KEYS);
  const { signature, ...unsignedRaw } = value;
  const unsigned = unsignedDiscovery(unsignedRaw);
  if (unsigned.repositorySha !== repositorySha || Number(unsigned.expiresAtMs) <= nowMs) fail();
  const verifiedSignature = signatureObject(signature, unsigned.operatorKeyId);
  const publicKey = typeof operatorPublicKey === "string" ? ed25519PublicKeyFromRawBase64(operatorPublicKey) : operatorPublicKey;
  if (!publicKey || publicKey.asymmetricKeyType !== "ed25519") fail();
  if (!verify(null, canonicalBytes(unsigned), publicKey, Buffer.from(verifiedSignature.value, "base64"))) fail();
  return Object.freeze({ ...unsigned, signature: Object.freeze({ ...verifiedSignature }) });
}

export async function publishRequestorDiscovery({
  bucket,
  certificateKey,
  certificatePath,
  certificateUrl,
  discoveryKey,
  expiresAtMs,
  operatorKeyId,
  operatorPrivateKeyPath,
  publicUrl,
  putObject,
  readTextFile = (path) => readFile(path, "utf8"),
  releaseId,
  repositorySha,
  sessionId,
} = {}) {
  if (typeof bucket !== "string" || bucket.length === 0 || typeof certificateKey !== "string" || typeof discoveryKey !== "string" || typeof putObject !== "function") fail();
  const certificatePem = await readTextFile(certificatePath);
  const certificateFingerprint = createHash("sha256").update(new X509Certificate(certificatePem).raw).digest("hex");
  const operatorPrivateKey = createPrivateKey(await readTextFile(operatorPrivateKeyPath));
  const discovery = createSignedRequestorDiscovery({
    certificateFingerprint,
    certificateUrl,
    expiresAtMs,
    operatorKeyId,
    operatorPrivateKey,
    publicUrl,
    releaseId,
    repositorySha,
    sessionId,
  });
  await putObject({ body: certificatePem, bucket, contentType: "application/x-pem-file", key: certificateKey });
  await putObject({ body: `${JSON.stringify(discovery)}\n`, bucket, contentType: "application/json", key: discoveryKey });
  return Object.freeze({ discovery, paymentMoved: false });
}
