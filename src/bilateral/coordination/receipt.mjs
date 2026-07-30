import {
  X509Certificate,
  constants as cryptoConstants,
  createHash,
  verify as verifySignature,
} from "node:crypto";

import {
  canonicalBytes,
} from "../canonical.mjs";
import {
  canonicalizeReceiptEventValue,
} from "../../canonical.mjs";

export const COORDINATION_RECEIPT_SCHEMA =
  "clockchain.bilateral-coordination-receipt/v1";
export const COORDINATION_RECEIPT_SIGNATURE_DOMAIN =
  "clockchain.bilateral-coordination-receipt-signature/v1\n";

const MAX_RECEIPT_BYTES = 65_536;
const MAX_CERTIFICATE_PEM_BYTES = 65_536;
const MAX_SIGNATURE_BYTES = 1_024;
const RECEIPT_KEYS = Object.freeze([
  "capabilityDigest",
  "certificateSha256",
  "enrollmentDigest",
  "paymentMoved",
  "releaseId",
  "repositorySha",
  "role",
  "schema",
  "sessionId",
  "signature",
  "signatureAlgorithm",
]);
const RECEIPT_UNSIGNED_KEYS = Object.freeze(
  RECEIPT_KEYS.filter((key) => key !== "signature"),
);
const CONTEXT_KEYS = Object.freeze([
  "capabilityDigest",
  "enrollmentDigest",
  "releaseId",
  "repositorySha",
  "role",
  "sessionId",
]);
const CREATE_KEYS = Object.freeze(["context", "signer"]);
const VERIFY_KEYS = Object.freeze([
  "bytes",
  "expected",
  "verifier",
]);
const CERTIFICATE_KEYS = Object.freeze([
  "tlsCertificatePem",
]);
const SIGNER_KEYS = Object.freeze([
  "certificateSha256",
  "sign",
  "signatureAlgorithm",
  "verify",
]);
const VERIFIER_KEYS = Object.freeze([
  "certificateSha256",
  "signatureAlgorithm",
  "verify",
]);
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const REPOSITORY_SHA_PATTERN = /^[0-9a-f]{40}$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PRINTABLE_ASCII_PATTERN = /^[ -~]+$/;
const BASE64_PATTERN =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const SIGNATURE_ALGORITHMS = new Set([
  "ecdsa-sha256",
  "ed25519",
  "rsa-pss-sha256",
]);

export class CoordinationReceiptError extends Error {
  constructor() {
    super("Coordination receipt validation failed.");
    this.name = new.target.name;
    this.category = "verification";
    this.code = "COORDINATION_RECEIPT_INVALID";
  }
}

function invalid() {
  throw new CoordinationReceiptError();
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

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function stableBytes(value) {
  try {
    return Buffer.from(
      JSON.stringify(canonicalizeReceiptEventValue(value)),
      "utf8",
    );
  } catch {
    invalid();
  }
}

function assertSha256(value) {
  if (
    typeof value !== "string" ||
    !SHA256_PATTERN.test(value)
  ) {
    invalid();
  }
  return value;
}

function assertReleaseId(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 256 ||
    !PRINTABLE_ASCII_PATTERN.test(value) ||
    value.trim() !== value
  ) {
    invalid();
  }
  return value;
}

function assertContext(value) {
  const data = readExactData(value, CONTEXT_KEYS);
  if (
    typeof data.repositorySha !== "string" ||
    !REPOSITORY_SHA_PATTERN.test(data.repositorySha) ||
    (data.role !== "payer" && data.role !== "payee") ||
    typeof data.sessionId !== "string" ||
    !UUID_PATTERN.test(data.sessionId)
  ) {
    invalid();
  }
  return Object.freeze({
    capabilityDigest: assertSha256(
      data.capabilityDigest,
    ),
    enrollmentDigest: assertSha256(
      data.enrollmentDigest,
    ),
    releaseId: assertReleaseId(data.releaseId),
    repositorySha: data.repositorySha,
    role: data.role,
    sessionId: data.sessionId,
  });
}

function assertSignatureAlgorithm(value) {
  if (!SIGNATURE_ALGORITHMS.has(value)) {
    invalid();
  }
  return value;
}

export function validateReceiptSigner(value) {
  const data = readExactData(value, SIGNER_KEYS);
  if (
    typeof data.sign !== "function" ||
    typeof data.verify !== "function"
  ) {
    invalid();
  }
  return Object.freeze({
    certificateSha256: assertSha256(
      data.certificateSha256,
    ),
    sign: data.sign,
    signatureAlgorithm: assertSignatureAlgorithm(
      data.signatureAlgorithm,
    ),
    verify: data.verify,
  });
}

function validateReceiptVerifier(value) {
  const data = readExactData(value, VERIFIER_KEYS);
  if (typeof data.verify !== "function") {
    invalid();
  }
  return Object.freeze({
    certificateSha256: assertSha256(
      data.certificateSha256,
    ),
    signatureAlgorithm: assertSignatureAlgorithm(
      data.signatureAlgorithm,
    ),
    verify: data.verify,
  });
}

function canonicalCertificatePem(certificate) {
  return [
    "-----BEGIN CERTIFICATE-----",
    ...certificate.raw
      .toString("base64")
      .match(/.{1,64}/g),
    "-----END CERTIFICATE-----",
    "",
  ].join("\n");
}

function certificateSignatureAlgorithm(publicKey) {
  if (publicKey.asymmetricKeyType === "ed25519") {
    return "ed25519";
  }
  if (publicKey.asymmetricKeyType === "ec") {
    return "ecdsa-sha256";
  }
  if (
    publicKey.asymmetricKeyType === "rsa" ||
    publicKey.asymmetricKeyType === "rsa-pss"
  ) {
    return "rsa-pss-sha256";
  }
  invalid();
}

function verificationOptions(publicKey, algorithm) {
  if (algorithm === "rsa-pss-sha256") {
    return {
      key: publicKey,
      padding: cryptoConstants.RSA_PKCS1_PSS_PADDING,
      saltLength: cryptoConstants.RSA_PSS_SALTLEN_DIGEST,
    };
  }
  return publicKey;
}

export function createReceiptVerifierFromCertificate(input) {
  try {
    const data = readExactData(input, CERTIFICATE_KEYS);
    if (
      typeof data.tlsCertificatePem !== "string" ||
      data.tlsCertificatePem.length === 0 ||
      Buffer.byteLength(data.tlsCertificatePem, "utf8") >
        MAX_CERTIFICATE_PEM_BYTES
    ) {
      invalid();
    }
    let certificate;
    try {
      certificate = new X509Certificate(
        data.tlsCertificatePem,
      );
    } catch {
      invalid();
    }
    if (
      canonicalCertificatePem(certificate) !==
      data.tlsCertificatePem
    ) {
      invalid();
    }
    const signatureAlgorithm =
      certificateSignatureAlgorithm(
        certificate.publicKey,
      );
    const algorithm =
      signatureAlgorithm === "ed25519"
        ? null
        : "sha256";
    const key = verificationOptions(
      certificate.publicKey,
      signatureAlgorithm,
    );
    return Object.freeze({
      certificateSha256: sha256(certificate.raw),
      signatureAlgorithm,
      verify(preimage, signature) {
        try {
          return verifySignature(
            algorithm,
            preimage,
            key,
            signature,
          );
        } catch {
          return false;
        }
      },
    });
  } catch (error) {
    if (error instanceof CoordinationReceiptError) {
      throw error;
    }
    invalid();
  }
}

function receiptUnsigned(context, signer) {
  return Object.freeze({
    capabilityDigest: context.capabilityDigest,
    certificateSha256: signer.certificateSha256,
    enrollmentDigest: context.enrollmentDigest,
    paymentMoved: false,
    releaseId: context.releaseId,
    repositorySha: context.repositorySha,
    role: context.role,
    schema: COORDINATION_RECEIPT_SCHEMA,
    sessionId: context.sessionId,
    signatureAlgorithm: signer.signatureAlgorithm,
  });
}

function receiptPreimage(unsigned) {
  return Buffer.concat([
    Buffer.from(
      COORDINATION_RECEIPT_SIGNATURE_DOMAIN,
      "ascii",
    ),
    Buffer.from(
      sha256(canonicalBytes(unsigned)),
      "ascii",
    ),
  ]);
}

function parseCanonicalReceipt(bytes) {
  if (
    !Buffer.isBuffer(bytes) ||
    bytes.length === 0 ||
    bytes.length > MAX_RECEIPT_BYTES
  ) {
    invalid();
  }
  let parsed;
  try {
    const text = bytes.toString("utf8");
    if (Buffer.byteLength(text, "utf8") !== bytes.length) {
      invalid();
    }
    parsed = JSON.parse(text);
    if (!stableBytes(parsed).equals(bytes)) {
      invalid();
    }
  } catch (error) {
    if (error instanceof CoordinationReceiptError) {
      throw error;
    }
    invalid();
  }
  return parsed;
}

function receiptFromParsed(value) {
  const data = readExactData(value, RECEIPT_KEYS);
  const context = assertContext({
    capabilityDigest: data.capabilityDigest,
    enrollmentDigest: data.enrollmentDigest,
    releaseId: data.releaseId,
    repositorySha: data.repositorySha,
    role: data.role,
    sessionId: data.sessionId,
  });
  if (
    data.schema !== COORDINATION_RECEIPT_SCHEMA ||
    data.paymentMoved !== false ||
    typeof data.signature !== "string" ||
    !BASE64_PATTERN.test(data.signature)
  ) {
    invalid();
  }
  const signatureAlgorithm = assertSignatureAlgorithm(
    data.signatureAlgorithm,
  );
  const certificateSha256 = assertSha256(
    data.certificateSha256,
  );
  const signature = Buffer.from(data.signature, "base64");
  if (
    signature.length === 0 ||
    signature.length > MAX_SIGNATURE_BYTES ||
    signature.toString("base64") !== data.signature
  ) {
    invalid();
  }
  const unsigned = receiptUnsigned(context, {
    certificateSha256,
    signatureAlgorithm,
  });
  return {
    receipt: Object.freeze({
      ...unsigned,
      signature: data.signature,
    }),
    signature,
    unsigned,
  };
}

async function verifyReceipt(bytes, expected, verifier) {
  const parsed = parseCanonicalReceipt(bytes);
  const {
    receipt,
    signature,
    unsigned,
  } = receiptFromParsed(parsed);
  if (
    receipt.capabilityDigest !==
      expected.capabilityDigest ||
    receipt.certificateSha256 !==
      verifier.certificateSha256 ||
    receipt.enrollmentDigest !==
      expected.enrollmentDigest ||
    receipt.releaseId !== expected.releaseId ||
    receipt.repositorySha !== expected.repositorySha ||
    receipt.role !== expected.role ||
    receipt.sessionId !== expected.sessionId ||
    receipt.signatureAlgorithm !==
      verifier.signatureAlgorithm
  ) {
    invalid();
  }
  let verified;
  try {
    verified = await verifier.verify(
      receiptPreimage(unsigned),
      Buffer.from(signature),
    );
  } catch {
    invalid();
  }
  if (verified !== true) {
    invalid();
  }
  return receipt;
}

export async function verifyCoordinationReceipt(input) {
  try {
    const data = readExactData(input, VERIFY_KEYS);
    const expected = assertContext(data.expected);
    const verifier = isPlainObject(data.verifier) &&
      Reflect.ownKeys(data.verifier).includes("sign")
      ? validateReceiptSigner(data.verifier)
      : validateReceiptVerifier(data.verifier);
    if (!Buffer.isBuffer(data.bytes)) {
      invalid();
    }
    return await verifyReceipt(
      Buffer.from(data.bytes),
      expected,
      verifier,
    );
  } catch (error) {
    if (error instanceof CoordinationReceiptError) {
      throw error;
    }
    invalid();
  }
}

export async function createCoordinationReceipt(input) {
  try {
    const data = readExactData(input, CREATE_KEYS);
    const context = assertContext(data.context);
    const signer = validateReceiptSigner(data.signer);
    const unsigned = receiptUnsigned(context, signer);
    const preimage = receiptPreimage(unsigned);
    let signature;
    try {
      signature = await signer.sign(
        Buffer.from(preimage),
      );
    } catch {
      invalid();
    }
    if (
      !Buffer.isBuffer(signature) ||
      signature.length === 0 ||
      signature.length > MAX_SIGNATURE_BYTES
    ) {
      invalid();
    }
    const bytes = stableBytes({
      ...unsigned,
      signature: signature.toString("base64"),
    });
    await verifyReceipt(bytes, context, signer);
    return bytes;
  } catch (error) {
    if (error instanceof CoordinationReceiptError) {
      throw error;
    }
    invalid();
  }
}
