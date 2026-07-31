import {
  createHash,
  createPublicKey,
  verify,
  X509Certificate,
} from "node:crypto";
import { types } from "node:util";

import {
  canonicalizeReceiptEventValue,
} from "../../canonical.mjs";
import {
  createSealedEnvelopeKeyPair,
  openEnvelope,
  sealEnvelope,
} from "./sealed-envelope.mjs";

export const PAYER_BOOTSTRAP_CLAIM_SCHEMA =
  "clockchain.payer-bootstrap-claim/v1";
export const PAYER_BOOTSTRAP_PACKAGE_SCHEMA =
  "clockchain.payer-bootstrap-package/v1";
export const PAYER_BOOTSTRAP_RESPONSE_SCHEMA =
  "clockchain.payer-bootstrap-response/v1";

const CLAIM_KEYS = Object.freeze([
  "claimNonce",
  "mcpTlsCertificatePem",
  "mcpTlsFingerprint",
  "paymentMoved",
  "releaseId",
  "repositorySha",
  "role",
  "schema",
  "sessionId",
  "sshPublicKey",
  "sshPublicKeyFingerprint",
  "x25519PublicKey",
]);
const PACKAGE_KEYS = Object.freeze([
  "bootstrapBrokerCapability",
  "bootstrapBrokerUrl",
  "expiresAtMs",
  "launchManifestBase64url",
  "paymentMoved",
  "schema",
  "tunnelGrant",
]);
const RESPONSE_KEYS = Object.freeze([
  "claimFingerprint",
  "envelope",
  "expiresAtMs",
  "operatorKeyId",
  "paymentMoved",
  "schema",
  "signature",
]);
const SIGNATURE_KEYS = Object.freeze([
  "algorithm",
  "keyId",
  "value",
]);
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const SHA40_PATTERN = /^[0-9a-f]{40}$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const UUID_V4_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const KEY_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,63}$/;
const BASE64_PATTERN =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const ED25519_SPKI_PREFIX = Buffer.from(
  "302a300506032b6570032100",
  "hex",
);
const MAX_CERTIFICATE_BYTES = 65_536;
const MAX_MANIFEST_BYTES = 65_536;
const MAX_GRANT_BYTES = 65_536;
const MAX_PACKAGE_BYTES = 65_536;

export class PayerBootstrapEnvelopeError extends Error {
  constructor() {
    super("Payer bootstrap envelope validation failed.");
    this.name = "PayerBootstrapEnvelopeError";
    this.code = "PAYER_BOOTSTRAP_ENVELOPE_INVALID";
    this.category = "verification";
  }
}

function invalid() {
  throw new PayerBootstrapEnvelopeError();
}

function sanitize(error) {
  if (error instanceof PayerBootstrapEnvelopeError) throw error;
  invalid();
}

function exactObject(value, keys) {
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
      keys.some((key, index) => ownKeys[index] !== key)
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

function printable(value, maximum = 256) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= maximum &&
    value.trim() === value &&
    /^[ -~]+$/.test(value)
  );
}

function decimalTimestamp(value) {
  if (
    typeof value !== "string" ||
    !/^(?:0|[1-9][0-9]*)$/.test(value) ||
    BigInt(value) > BigInt(Number.MAX_SAFE_INTEGER)
  ) {
    invalid();
  }
  return value;
}

function exactBase64(value, decodedLength) {
  if (
    typeof value !== "string" ||
    !BASE64_PATTERN.test(value)
  ) {
    invalid();
  }
  const bytes = Buffer.from(value, "base64");
  if (
    bytes.length !== decodedLength ||
    bytes.toString("base64") !== value
  ) {
    invalid();
  }
  return bytes;
}

function exactBase64url(value, decodedLength) {
  if (
    typeof value !== "string" ||
    !BASE64URL_PATTERN.test(value) ||
    value.includes("=")
  ) {
    invalid();
  }
  const bytes = Buffer.from(value, "base64url");
  if (
    bytes.length !== decodedLength ||
    bytes.toString("base64url") !== value
  ) {
    invalid();
  }
  return bytes;
}

function readSshString(blob, offset) {
  if (offset + 4 > blob.length) invalid();
  const length = blob.readUInt32BE(offset);
  const start = offset + 4;
  const end = start + length;
  if (end > blob.length) invalid();
  return {
    bytes: blob.subarray(start, end),
    offset: end,
  };
}

function sshEd25519Blob(value) {
  if (
    typeof value !== "string" ||
    !value.startsWith("ssh-ed25519 ") ||
    value.includes("\n") ||
    value.includes("\r")
  ) {
    invalid();
  }
  const parts = value.split(" ");
  if (parts.length !== 2 || !BASE64_PATTERN.test(parts[1])) {
    invalid();
  }
  const blob = Buffer.from(parts[1], "base64");
  if (
    blob.length === 0 ||
    blob.toString("base64") !== parts[1]
  ) {
    invalid();
  }
  const algorithm = readSshString(blob, 0);
  const key = readSshString(blob, algorithm.offset);
  if (
    algorithm.bytes.toString("ascii") !== "ssh-ed25519" ||
    key.bytes.length !== 32 ||
    key.offset !== blob.length
  ) {
    invalid();
  }
  return blob;
}

export function sshEd25519Fingerprint(value) {
  try {
    return `SHA256:${createHash("sha256")
      .update(sshEd25519Blob(value))
      .digest("base64")
      .replace(/=+$/u, "")}`;
  } catch (error) {
    sanitize(error);
  }
}

function tlsFingerprint(certificatePem) {
  if (
    typeof certificatePem !== "string" ||
    certificatePem.length === 0 ||
    Buffer.byteLength(certificatePem, "utf8") >
      MAX_CERTIFICATE_BYTES
  ) {
    invalid();
  }
  try {
    return createHash("sha256")
      .update(new X509Certificate(certificatePem).raw)
      .digest("hex");
  } catch {
    invalid();
  }
}

function claimSnapshot(value) {
  const claim = exactObject(value, CLAIM_KEYS);
  if (
    !UUID_V4_PATTERN.test(claim.claimNonce) ||
    claim.mcpTlsFingerprint !==
      tlsFingerprint(claim.mcpTlsCertificatePem) ||
    claim.paymentMoved !== false ||
    !printable(claim.releaseId, 128) ||
    !SHA40_PATTERN.test(claim.repositorySha) ||
    claim.role !== "payer" ||
    claim.schema !== PAYER_BOOTSTRAP_CLAIM_SCHEMA ||
    !UUID_PATTERN.test(claim.sessionId) ||
    claim.sshPublicKeyFingerprint !==
      sshEd25519Fingerprint(claim.sshPublicKey)
  ) {
    invalid();
  }
  exactBase64url(claim.x25519PublicKey, 32);
  return Object.freeze({ ...claim });
}

export function validatePayerBootstrapClaim(value) {
  try {
    return claimSnapshot(value);
  } catch (error) {
    sanitize(error);
  }
}

function claimBytes(value) {
  return Buffer.from(
    JSON.stringify(claimSnapshot(value)),
    "utf8",
  );
}

export function payerBootstrapClaimFingerprint(value) {
  try {
    return createHash("sha256")
      .update(claimBytes(value))
      .digest("hex");
  } catch (error) {
    sanitize(error);
  }
}

function claimAadBytes(value) {
  return createHash("sha256")
    .update(claimBytes(value))
    .digest();
}

function canonicalJsonBytes(value, maximum) {
  if (
    !Buffer.isBuffer(value) ||
    value.length === 0 ||
    value.length > maximum
  ) {
    invalid();
  }
  let parsed;
  try {
    parsed = JSON.parse(value.toString("utf8"));
  } catch {
    invalid();
  }
  const stable = Buffer.from(
    JSON.stringify(
      canonicalizeReceiptEventValue(parsed),
    ),
    "utf8",
  );
  if (!stable.equals(value)) invalid();
  return {
    bytes: Buffer.from(value),
    value: JSON.parse(stable.toString("utf8")),
  };
}

function httpsUrl(value) {
  if (typeof value !== "string") invalid();
  let url;
  try {
    url = new URL(value);
  } catch {
    invalid();
  }
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== ""
  ) {
    invalid();
  }
  return value;
}

function packageSnapshot(value, nowMs) {
  const data = exactObject(value, PACKAGE_KEYS);
  if (
    !/^[0-9a-f]{64}$/.test(
      data.bootstrapBrokerCapability,
    ) ||
    data.paymentMoved !== false ||
    data.schema !== PAYER_BOOTSTRAP_PACKAGE_SCHEMA
  ) {
    invalid();
  }
  httpsUrl(data.bootstrapBrokerUrl);
  decimalTimestamp(data.expiresAtMs);
  if (Number(data.expiresAtMs) <= nowMs) invalid();
  if (
    typeof data.launchManifestBase64url !== "string" ||
    !BASE64URL_PATTERN.test(
      data.launchManifestBase64url,
    )
  ) {
    invalid();
  }
  const launchManifestBytes = Buffer.from(
    data.launchManifestBase64url,
    "base64url",
  );
  if (
    launchManifestBytes.toString("base64url") !==
    data.launchManifestBase64url
  ) {
    invalid();
  }
  const manifest = canonicalJsonBytes(
    launchManifestBytes,
    MAX_MANIFEST_BYTES,
  );
  const tunnel = canonicalJsonBytes(
    Buffer.from(JSON.stringify(data.tunnelGrant), "utf8"),
    MAX_GRANT_BYTES,
  );
  if (
    manifest.value?.paymentMoved !== false ||
    tunnel.value?.paymentMoved !== false
  ) {
    invalid();
  }
  return Object.freeze({
    bootstrapBrokerCapability:
      data.bootstrapBrokerCapability,
    bootstrapBrokerUrl: data.bootstrapBrokerUrl,
    expiresAtMs: data.expiresAtMs,
    launchManifestBytes: manifest.bytes,
    paymentMoved: false,
    tunnelGrantBytes: tunnel.bytes,
  });
}

function signatureSnapshot(value, keyId) {
  const signature = exactObject(value, SIGNATURE_KEYS);
  if (
    signature.algorithm !== "ed25519" ||
    signature.keyId !== keyId
  ) {
    invalid();
  }
  exactBase64(signature.value, 64);
  return Object.freeze({ ...signature });
}

function rawEd25519PublicKey(value) {
  const raw = exactBase64(value, 32);
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
    format: "der",
    type: "spki",
  });
}

function responseSigningBytes(unsigned) {
  return Buffer.from(JSON.stringify(unsigned), "utf8");
}

export function createPayerBootstrapKey() {
  try {
    return createSealedEnvelopeKeyPair();
  } catch (error) {
    sanitize(error);
  }
}

export function sealSignedPayerBootstrapPackage({
  bootstrapBrokerCapability,
  bootstrapBrokerUrl,
  claim,
  expiresAtMs,
  launchManifestBytes,
  operatorKeyId,
  signer,
  tunnelGrantBytes,
} = {}) {
  try {
    const boundClaim = claimSnapshot(claim);
    const manifest = canonicalJsonBytes(
      launchManifestBytes,
      MAX_MANIFEST_BYTES,
    );
    const tunnel = canonicalJsonBytes(
      tunnelGrantBytes,
      MAX_GRANT_BYTES,
    );
    decimalTimestamp(expiresAtMs);
    if (
      Number(expiresAtMs) <= Date.now() ||
      !printable(operatorKeyId, 64) ||
      !KEY_ID_PATTERN.test(operatorKeyId) ||
      typeof signer !== "function"
    ) {
      invalid();
    }
    const packageValue = {
      bootstrapBrokerCapability,
      bootstrapBrokerUrl,
      expiresAtMs,
      launchManifestBase64url:
        manifest.bytes.toString("base64url"),
      paymentMoved: false,
      schema: PAYER_BOOTSTRAP_PACKAGE_SCHEMA,
      tunnelGrant: tunnel.value,
    };
    packageSnapshot(packageValue, 0);
    const plaintextBytes = Buffer.from(
      JSON.stringify(packageValue),
      "utf8",
    );
    if (plaintextBytes.length > MAX_PACKAGE_BYTES) invalid();
    const envelope = sealEnvelope({
      aadBytes: claimAadBytes(boundClaim),
      plaintextBytes,
      recipientPublicKey:
        boundClaim.x25519PublicKey,
      schema: PAYER_BOOTSTRAP_PACKAGE_SCHEMA,
    });
    const unsigned = {
      claimFingerprint:
        payerBootstrapClaimFingerprint(boundClaim),
      envelope,
      expiresAtMs,
      operatorKeyId,
      paymentMoved: false,
      schema: PAYER_BOOTSTRAP_RESPONSE_SCHEMA,
    };
    const signatureValue = signer(
      responseSigningBytes(unsigned),
    );
    exactBase64(signatureValue, 64);
    return Object.freeze({
      ...unsigned,
      signature: Object.freeze({
        algorithm: "ed25519",
        keyId: operatorKeyId,
        value: signatureValue,
      }),
    });
  } catch (error) {
    sanitize(error);
  }
}

export function openSignedPayerBootstrapPackage({
  claim,
  consumeClaimNonce,
  expectedReleaseId,
  expectedRepositorySha,
  expectedSessionId,
  nowMs = Date.now(),
  operatorPublicKey,
  payerPrivateKey,
  response,
} = {}) {
  try {
    const boundClaim = claimSnapshot(claim);
    const data = exactObject(response, RESPONSE_KEYS);
    if (
      boundClaim.releaseId !== expectedReleaseId ||
      boundClaim.repositorySha !==
        expectedRepositorySha ||
      boundClaim.sessionId !== expectedSessionId ||
      data.claimFingerprint !==
        payerBootstrapClaimFingerprint(boundClaim) ||
      data.paymentMoved !== false ||
      data.schema !== PAYER_BOOTSTRAP_RESPONSE_SCHEMA ||
      !KEY_ID_PATTERN.test(data.operatorKeyId) ||
      typeof consumeClaimNonce !== "function"
    ) {
      invalid();
    }
    decimalTimestamp(data.expiresAtMs);
    if (Number(data.expiresAtMs) <= nowMs) invalid();
    const signature = signatureSnapshot(
      data.signature,
      data.operatorKeyId,
    );
    const unsigned = {
      claimFingerprint: data.claimFingerprint,
      envelope: data.envelope,
      expiresAtMs: data.expiresAtMs,
      operatorKeyId: data.operatorKeyId,
      paymentMoved: false,
      schema: data.schema,
    };
    const publicKey =
      typeof operatorPublicKey === "string"
        ? rawEd25519PublicKey(operatorPublicKey)
        : operatorPublicKey;
    if (
      publicKey?.asymmetricKeyType !== "ed25519" ||
      !verify(
        null,
        responseSigningBytes(unsigned),
        publicKey,
        Buffer.from(signature.value, "base64"),
      )
    ) {
      invalid();
    }
    const plaintextBytes = openEnvelope({
      aadBytes: claimAadBytes(boundClaim),
      envelope: data.envelope,
      expectedSchema: PAYER_BOOTSTRAP_PACKAGE_SCHEMA,
      recipientPrivateKey: payerPrivateKey,
    });
    if (plaintextBytes.length > MAX_PACKAGE_BYTES) invalid();
    let packageValue;
    try {
      packageValue = JSON.parse(
        plaintextBytes.toString("utf8"),
      );
    } catch {
      invalid();
    }
    if (
      !Buffer.from(
        JSON.stringify(packageValue),
        "utf8",
      ).equals(plaintextBytes)
    ) {
      invalid();
    }
    const opened = packageSnapshot(packageValue, nowMs);
    if (opened.expiresAtMs !== data.expiresAtMs) invalid();
    if (consumeClaimNonce(boundClaim.claimNonce) !== true) {
      invalid();
    }
    return opened;
  } catch (error) {
    sanitize(error);
  }
}
