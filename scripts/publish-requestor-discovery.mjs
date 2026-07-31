#!/usr/bin/env node
import { createHash, createPrivateKey, createPublicKey, sign, verify, X509Certificate } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { resolve } from "node:path";

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
const MAX_DISCOVERY_BYTES = 65_536;
const MAX_CERTIFICATE_BYTES = 65_536;
const MAX_OPERATOR_KEY_BYTES = 8192;

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

function rejectDuplicateJsonKeys(text) {
  if (typeof text !== "string" || text.length === 0 || Buffer.byteLength(text, "utf8") > MAX_DISCOVERY_BYTES) fail();
  let index = 0;
  const whitespace = () => {
    while (/[\t\n\r ]/.test(text[index] ?? "")) index += 1;
  };
  const parseString = () => {
    if (text[index] !== "\"") fail();
    index += 1;
    let value = "";
    while (index < text.length) {
      const char = text[index];
      if (char === "\"") {
        index += 1;
        return value;
      }
      if (char === "\\") {
        index += 1;
        const escaped = text[index];
        if (escaped === undefined) fail();
        if ("\"\\/".includes(escaped)) value += escaped;
        else if (escaped === "b") value += "\b";
        else if (escaped === "f") value += "\f";
        else if (escaped === "n") value += "\n";
        else if (escaped === "r") value += "\r";
        else if (escaped === "t") value += "\t";
        else if (escaped === "u") {
          const hex = text.slice(index + 1, index + 5);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail();
          value += String.fromCharCode(Number.parseInt(hex, 16));
          index += 4;
        } else fail();
      } else {
        if (char < " ") fail();
        value += char;
      }
      index += 1;
    }
    fail();
  };
  const parseNumber = () => {
    const start = index;
    if (text[index] === "-") index += 1;
    if (text[index] === "0") index += 1;
    else if (/[1-9]/.test(text[index] ?? "")) while (/[0-9]/.test(text[index] ?? "")) index += 1;
    else fail();
    if (text[index] === ".") {
      index += 1;
      if (!/[0-9]/.test(text[index] ?? "")) fail();
      while (/[0-9]/.test(text[index] ?? "")) index += 1;
    }
    if (text[index] === "e" || text[index] === "E") {
      index += 1;
      if (text[index] === "+" || text[index] === "-") index += 1;
      if (!/[0-9]/.test(text[index] ?? "")) fail();
      while (/[0-9]/.test(text[index] ?? "")) index += 1;
    }
    if (index === start) fail();
  };
  const parseLiteral = (literal) => {
    if (text.slice(index, index + literal.length) !== literal) fail();
    index += literal.length;
  };
  const parseArray = () => {
    index += 1;
    whitespace();
    if (text[index] === "]") {
      index += 1;
      return;
    }
    for (;;) {
      parseValue();
      whitespace();
      if (text[index] === "]") {
        index += 1;
        return;
      }
      if (text[index] !== ",") fail();
      index += 1;
      whitespace();
    }
  };
  const parseObject = () => {
    index += 1;
    const keys = new Set();
    whitespace();
    if (text[index] === "}") {
      index += 1;
      return;
    }
    for (;;) {
      const key = parseString();
      if (keys.has(key)) fail();
      keys.add(key);
      whitespace();
      if (text[index] !== ":") fail();
      index += 1;
      parseValue();
      whitespace();
      if (text[index] === "}") {
        index += 1;
        return;
      }
      if (text[index] !== ",") fail();
      index += 1;
      whitespace();
    }
  };
  function parseValue() {
    whitespace();
    const char = text[index];
    if (char === "{") return parseObject();
    if (char === "[") return parseArray();
    if (char === "\"") return parseString();
    if (char === "t") return parseLiteral("true");
    if (char === "f") return parseLiteral("false");
    if (char === "n") return parseLiteral("null");
    return parseNumber();
  }
  parseValue();
  whitespace();
  if (index !== text.length) fail();
}

export function parseRequestorDiscoveryWire(text) {
  if (typeof text !== "string" || !text.endsWith("\n") || text.slice(0, -1).includes("\n")) fail();
  const body = text.slice(0, -1);
  rejectDuplicateJsonKeys(body);
  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch {
    fail();
  }
  if (`${JSON.stringify(parsed)}\n` !== text) fail();
  return exactObject(parsed, DISCOVERY_KEYS);
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

export function validateRequestorDiscoveryCandidate({ discovery, nowMs = Date.now(), repositorySha } = {}) {
  const value = exactObject(discovery, DISCOVERY_KEYS);
  const { signature, ...unsignedRaw } = value;
  const unsigned = unsignedDiscovery(unsignedRaw);
  if (unsigned.repositorySha !== repositorySha || Number(unsigned.expiresAtMs) <= nowMs) fail();
  const candidateSignature = signatureObject(signature, unsigned.operatorKeyId);
  return Object.freeze({ ...unsigned, signature: Object.freeze({ ...candidateSignature }) });
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
  const candidate = validateRequestorDiscoveryCandidate({ discovery, nowMs, repositorySha });
  const { signature: verifiedSignature, ...unsigned } = candidate;
  const publicKey = typeof operatorPublicKey === "string" ? ed25519PublicKeyFromRawBase64(operatorPublicKey) : operatorPublicKey;
  if (!publicKey || publicKey.asymmetricKeyType !== "ed25519") fail();
  if (!verify(null, canonicalBytes(unsigned), publicKey, Buffer.from(verifiedSignature.value, "base64"))) fail();
  return Object.freeze({ ...unsigned, signature: Object.freeze({ ...verifiedSignature }) });
}

function safeObjectKey(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 1024 || value.startsWith("/") || /[\x00-\x1f\x7f]/.test(value)) fail();
  const parts = value.split("/");
  if (parts.some((part) => part.length === 0 || part === "." || part === "..")) fail();
  return value;
}

function sameFileIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function validatePinnedStats(stats, { allowedModes, maxSize, expectedUid = process.getuid?.() }) {
  if (
    !stats.isFile() ||
    stats.isSymbolicLink() ||
    stats.nlink !== 1 ||
    stats.size <= 0 ||
    stats.size > maxSize ||
    !allowedModes.has(stats.mode & 0o777) ||
    (expectedUid !== undefined && stats.uid !== expectedUid)
  ) {
    fail();
  }
}

async function readPinnedTextFile(path, options) {
  if (typeof path !== "string" || path.length === 0 || resolve(path) !== path) fail();
  const before = await lstat(path);
  validatePinnedStats(before, options);
  const handle = await open(path, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
  try {
    const opened = await handle.stat();
    validatePinnedStats(opened, options);
    if (!sameFileIdentity(before, opened)) fail();
    const text = await handle.readFile("utf8");
    const after = await lstat(path);
    validatePinnedStats(after, options);
    if (!sameFileIdentity(before, after) || after.size !== before.size) fail();
    return { stats: before, text };
  } finally {
    await handle.close();
  }
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
  releaseId,
  repositorySha,
  sessionId,
} = {}) {
  if (typeof bucket !== "string" || bucket.length === 0 || typeof putObject !== "function") fail();
  const safeCertificateKey = safeObjectKey(certificateKey);
  const safeDiscoveryKey = safeObjectKey(discoveryKey);
  if (safeCertificateKey === safeDiscoveryKey || certificatePath === operatorPrivateKeyPath) fail();
  const certificate = await readPinnedTextFile(certificatePath, {
    allowedModes: new Set([0o600, 0o644]),
    maxSize: MAX_CERTIFICATE_BYTES,
  });
  const operator = await readPinnedTextFile(operatorPrivateKeyPath, {
    allowedModes: new Set([0o600]),
    maxSize: MAX_OPERATOR_KEY_BYTES,
  });
  if (sameFileIdentity(certificate.stats, operator.stats)) fail();
  const certificatePem = certificate.text;
  const certificateFingerprint = createHash("sha256").update(new X509Certificate(certificatePem).raw).digest("hex");
  const operatorPrivateKey = createPrivateKey(operator.text);
  if (operatorPrivateKey.asymmetricKeyType !== "ed25519") fail();
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
  await putObject({ body: certificatePem, bucket, contentType: "application/x-pem-file", key: safeCertificateKey });
  await putObject({ body: `${JSON.stringify(discovery)}\n`, bucket, contentType: "application/json", key: safeDiscoveryKey });
  return Object.freeze({ discovery, paymentMoved: false });
}
