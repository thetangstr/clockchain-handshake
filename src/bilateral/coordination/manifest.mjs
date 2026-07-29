import {
  constants as fsConstants,
} from "node:fs";
import {
  lstat,
  open,
  unlink,
} from "node:fs/promises";
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes as secureRandomBytes,
  sign as signBytes,
  timingSafeEqual,
  verify as verifyBytes,
} from "node:crypto";
import {
  isIP,
} from "node:net";
import {
  dirname,
  resolve,
} from "node:path";
import {
  types as utilTypes,
} from "node:util";

import {
  canonicalizeReceiptEventValue,
} from "../../canonical.mjs";
import {
  BILATERAL_PROTOCOL,
  KEY_ID_PATTERN,
} from "../descriptor.mjs";
import {
  canonicalBytes,
} from "../canonical.mjs";
import {
  parseCoordinationEnrollment,
  verifyCoordinationEnrollment,
} from "./enrollment.mjs";
import {
  createReceiptVerifierFromCertificate,
  verifyCoordinationReceipt,
} from "./receipt.mjs";

export const LAUNCH_MANIFEST_SCHEMA =
  "clockchain.bilateral-launch-manifest/v1";
export const ACTIVE_LAUNCH_STATE_SCHEMA =
  "clockchain.bilateral-active-launch-state/v1";
export const ACTIVE_LAUNCH_STATE_SIGNATURE_DOMAIN =
  "clockchain.bilateral-active-launch-state-signature/v1\n";
export const UNUSED_CAPABILITY_LIFETIME_MS = 3_600_000;

const MAX_MANIFEST_BYTES = 131_072;
const CREATE_COMMON_KEYS = Object.freeze([
  "expectedTlsFingerprint",
  "nowMs",
  "operatorKeyId",
  "randomBytes",
  "relayUrl",
  "releaseId",
  "repositorySha",
  "role",
  "sessionId",
  "tlsCertificatePem",
]);
const CREATE_COMMON_KEYS_WITHOUT_RANDOM = Object.freeze(
  CREATE_COMMON_KEYS.filter((key) => key !== "randomBytes"),
);
const MANIFEST_COMMON_KEYS = Object.freeze([
  "bootstrapCapability",
  "expectedTlsFingerprint",
  "expiresAtMs",
  "issuedAtMs",
  "operatorKeyId",
  "protocol",
  "relayUrl",
  "releaseId",
  "repositorySha",
  "role",
  "schema",
  "sessionId",
  "tlsCertificatePem",
]);
const ACTIVE_STATE_COMMON_KEYS = Object.freeze([
  "capabilityDigest",
  "enrollmentBase64",
  "enrollmentDigest",
  "expectedTlsFingerprint",
  "expiresAtMs",
  "issuedAtMs",
  "operatorKeyId",
  "paymentMoved",
  "protocol",
  "receiptBase64",
  "relayUrl",
  "releaseId",
  "repositorySha",
  "role",
  "schema",
  "sessionId",
  "signature",
  "tlsCertificatePem",
]);
const CREATE_ACTIVE_STATE_KEYS = Object.freeze([
  "coordinationIdentity",
  "enrollment",
  "manifest",
  "receiptBytes",
]);
const COORDINATION_IDENTITY_KEYS = Object.freeze([
  "keyId",
  "privateKeyPem",
  "publicKey",
]);
const DEPENDENCY_KEYS = Object.freeze(["fileSystem"]);
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const CAPABILITY_PATTERN = /^[0-9a-f]{64}$/;
const REPOSITORY_SHA_PATTERN = /^[0-9a-f]{40}$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const PRINTABLE_ASCII_PATTERN = /^[ -~]+$/;
const BASE64_PATTERN =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const RELAY_URL_PATTERN =
  /^https:\/\/(\[[0-9a-fA-F:.]+\]|[0-9.]+):([0-9]{1,5})$/;
const ED25519_SPKI_PREFIX = Buffer.from(
  "302a300506032b6570032100",
  "hex",
);
const DEFAULT_FILE_SYSTEM = Object.freeze({
  lstat,
  open,
});
const ROLE_MCP_FIELD = Object.freeze({
  payee: "payerMcpIntakeCapability",
  payer: "payerMcpIntakeCapabilityDigest",
});

export class LaunchManifestError extends Error {
  constructor() {
    super("Launch manifest processing failed safely.");
    this.name = new.target.name;
    this.category = "verification";
    this.code = "LAUNCH_MANIFEST_INVALID";
  }
}

function invalid() {
  throw new LaunchManifestError();
}

function isPlainObject(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    utilTypes.isProxy(value)
  ) {
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

function isProxy(value) {
  try {
    return utilTypes.isProxy(value);
  } catch {
    return true;
  }
}

function readDataRole(value) {
  if (!isPlainObject(value)) {
    invalid();
  }
  let descriptor;
  try {
    descriptor = Object.getOwnPropertyDescriptor(
      value,
      "role",
    );
  } catch {
    invalid();
  }
  if (
    descriptor?.enumerable !== true ||
    !Object.hasOwn(descriptor, "value") ||
    (descriptor.value !== "payer" &&
      descriptor.value !== "payee")
  ) {
    invalid();
  }
  return descriptor.value;
}

function manifestKeysForRole(role) {
  return Object.freeze([
    ...MANIFEST_COMMON_KEYS,
    ROLE_MCP_FIELD[role],
  ]);
}

function createKeysForRole(role, hasRandomBytes) {
  const common = hasRandomBytes
    ? CREATE_COMMON_KEYS
    : CREATE_COMMON_KEYS_WITHOUT_RANDOM;
  return Object.freeze([...common, ROLE_MCP_FIELD[role]]);
}

function activeStateKeysForRole(role) {
  return role === "payer"
    ? Object.freeze([
        ...ACTIVE_STATE_COMMON_KEYS,
        "payerMcpIntakeCapabilityDigest",
      ])
    : ACTIVE_STATE_COMMON_KEYS;
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

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function containsCapabilityEncoding(bytes, capability) {
  const text = bytes.toString("utf8");
  return (
    text
      .toLowerCase()
      .includes(capability.toString("hex")) ||
    text.includes(capability.toString("base64")) ||
    text.includes(capability.toString("base64url"))
  );
}

function assertCapabilityIsolated(bytes, capability) {
  if (containsCapabilityEncoding(bytes, capability)) {
    invalid();
  }
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

function assertRelayUrl(value) {
  if (typeof value !== "string") {
    invalid();
  }
  const match = RELAY_URL_PATTERN.exec(value);
  if (match === null) {
    invalid();
  }
  const host = match[1].startsWith("[")
    ? match[1].slice(1, -1)
    : match[1];
  const port = Number(match[2]);
  if (
    isIP(host) === 0 ||
    port < 1 ||
    port > 65_535
  ) {
    invalid();
  }
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    invalid();
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.pathname !== "/" ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    parsed.origin !== value ||
    host === "0.0.0.0" ||
    host === "::"
  ) {
    invalid();
  }
  return value;
}

function assertCertificateAndFingerprint(
  tlsCertificatePem,
  expectedTlsFingerprint,
) {
  if (
    typeof expectedTlsFingerprint !== "string" ||
    !SHA256_PATTERN.test(expectedTlsFingerprint)
  ) {
    invalid();
  }
  let verifier;
  try {
    verifier = createReceiptVerifierFromCertificate({
      tlsCertificatePem,
    });
  } catch {
    invalid();
  }
  if (
    !timingSafeEqual(
      Buffer.from(
        verifier.certificateSha256,
        "hex",
      ),
      Buffer.from(expectedTlsFingerprint, "hex"),
    )
  ) {
    invalid();
  }
  return tlsCertificatePem;
}

function assertDecimalMs(value) {
  if (
    typeof value !== "string" ||
    !DECIMAL_PATTERN.test(value)
  ) {
    invalid();
  }
  const number = Number(value);
  if (
    !Number.isSafeInteger(number) ||
    number < 0 ||
    String(number) !== value
  ) {
    invalid();
  }
  return number;
}

export function validateLaunchManifest(value) {
  try {
    const role = readDataRole(value);
    const data = readExactData(
      value,
      manifestKeysForRole(role),
    );
    const issuedAtMs = assertDecimalMs(data.issuedAtMs);
    const expiresAtMs = assertDecimalMs(data.expiresAtMs);
    if (
      data.schema !== LAUNCH_MANIFEST_SCHEMA ||
      data.protocol !== BILATERAL_PROTOCOL ||
      typeof data.repositorySha !== "string" ||
      !REPOSITORY_SHA_PATTERN.test(data.repositorySha) ||
      typeof data.operatorKeyId !== "string" ||
      !KEY_ID_PATTERN.test(data.operatorKeyId) ||
      typeof data.sessionId !== "string" ||
      !UUID_PATTERN.test(data.sessionId) ||
      typeof data.bootstrapCapability !== "string" ||
      !CAPABILITY_PATTERN.test(
        data.bootstrapCapability,
      ) ||
      expiresAtMs - issuedAtMs !==
        UNUSED_CAPABILITY_LIFETIME_MS
    ) {
      invalid();
    }
    if (
      data.role === "payee" &&
      (typeof data.payerMcpIntakeCapability !==
        "string" ||
        !CAPABILITY_PATTERN.test(
          data.payerMcpIntakeCapability,
        ) ||
        data.payerMcpIntakeCapability ===
          data.bootstrapCapability)
    ) {
      invalid();
    }
    if (
      data.role === "payer" &&
      (typeof data.payerMcpIntakeCapabilityDigest !==
        "string" ||
        !SHA256_PATTERN.test(
          data.payerMcpIntakeCapabilityDigest,
        ) ||
        data.payerMcpIntakeCapabilityDigest ===
          sha256(
            Buffer.from(
              data.bootstrapCapability,
              "hex",
            ),
          ))
    ) {
      invalid();
    }
    assertCertificateAndFingerprint(
      data.tlsCertificatePem,
      data.expectedTlsFingerprint,
    );
    const publicProjection = Object.freeze({
      expectedTlsFingerprint:
        data.expectedTlsFingerprint,
      expiresAtMs: data.expiresAtMs,
      issuedAtMs: data.issuedAtMs,
      operatorKeyId: data.operatorKeyId,
      protocol: data.protocol,
      relayUrl: assertRelayUrl(data.relayUrl),
      releaseId: assertReleaseId(data.releaseId),
      repositorySha: data.repositorySha,
      role: data.role,
      schema: data.schema,
      sessionId: data.sessionId,
      tlsCertificatePem: data.tlsCertificatePem,
    });
    const capability = Buffer.from(
      data.bootstrapCapability,
      "hex",
    );
    assertCapabilityIsolated(
      stableBytes(publicProjection),
      capability,
    );
    return Object.freeze({
      bootstrapCapability: data.bootstrapCapability,
      ...(data.role === "payee"
        ? {
            payerMcpIntakeCapability:
              data.payerMcpIntakeCapability,
          }
        : {
            payerMcpIntakeCapabilityDigest:
              data.payerMcpIntakeCapabilityDigest,
          }),
      ...publicProjection,
    });
  } catch (error) {
    if (error instanceof LaunchManifestError) {
      throw error;
    }
    invalid();
  }
}

export function createLaunchManifest(input) {
  try {
    if (!isPlainObject(input)) {
      invalid();
    }
    const role = readDataRole(input);
    const ownKeys = Reflect.ownKeys(input);
    const keys = createKeysForRole(
      role,
      ownKeys.includes("randomBytes"),
    );
    const data = readExactData(input, keys);
    if (
      !Number.isSafeInteger(data.nowMs) ||
      data.nowMs < 0 ||
      data.nowMs >
        Number.MAX_SAFE_INTEGER -
          UNUSED_CAPABILITY_LIFETIME_MS
    ) {
      invalid();
    }
    const randomBytes =
      data.randomBytes ?? secureRandomBytes;
    if (
      typeof randomBytes !== "function" ||
      isProxy(randomBytes)
    ) {
      invalid();
    }
    let capability;
    try {
      capability = randomBytes(32);
    } catch {
      invalid();
    }
    if (
      !Buffer.isBuffer(capability) ||
      capability.length !== 32
    ) {
      invalid();
    }
    if (
      data.role === "payee" &&
      (typeof data.payerMcpIntakeCapability !==
        "string" ||
        !CAPABILITY_PATTERN.test(
          data.payerMcpIntakeCapability,
        ) ||
        data.payerMcpIntakeCapability ===
          capability.toString("hex"))
    ) {
      invalid();
    }
    if (
      data.role === "payer" &&
      (typeof data.payerMcpIntakeCapabilityDigest !==
        "string" ||
        !SHA256_PATTERN.test(
          data.payerMcpIntakeCapabilityDigest,
        ) ||
        data.payerMcpIntakeCapabilityDigest ===
          sha256(capability))
    ) {
      invalid();
    }
    const manifest = validateLaunchManifest({
      bootstrapCapability:
        capability.toString("hex"),
      expectedTlsFingerprint:
        data.expectedTlsFingerprint,
      expiresAtMs: String(
        data.nowMs + UNUSED_CAPABILITY_LIFETIME_MS,
      ),
      issuedAtMs: String(data.nowMs),
      operatorKeyId: data.operatorKeyId,
      ...(data.role === "payee"
        ? {
            payerMcpIntakeCapability:
              data.payerMcpIntakeCapability,
          }
        : {
            payerMcpIntakeCapabilityDigest:
              data.payerMcpIntakeCapabilityDigest,
          }),
      protocol: BILATERAL_PROTOCOL,
      relayUrl: data.relayUrl,
      releaseId: data.releaseId,
      repositorySha: data.repositorySha,
      role: data.role,
      schema: LAUNCH_MANIFEST_SCHEMA,
      sessionId: data.sessionId,
      tlsCertificatePem: data.tlsCertificatePem,
    });
    return Object.freeze({
      capabilityDigest: sha256(capability),
      manifest,
    });
  } catch (error) {
    if (error instanceof LaunchManifestError) {
      throw error;
    }
    invalid();
  }
}

function activeStateSignaturePreimage(unsignedState) {
  return Buffer.concat([
    Buffer.from(
      ACTIVE_LAUNCH_STATE_SIGNATURE_DOMAIN,
      "ascii",
    ),
    Buffer.from(
      sha256(stableBytes(unsignedState)),
      "ascii",
    ),
  ]);
}

function enrolledCoordinationPublicKey(enrollment) {
  try {
    return createPublicKey({
      key: Buffer.concat([
        ED25519_SPKI_PREFIX,
        Buffer.from(
          enrollment.coordinationKey.publicKey,
          "base64",
        ),
      ]),
      format: "der",
      type: "spki",
    });
  } catch {
    invalid();
  }
}

function validateCoordinationIdentity(
  value,
  enrollment,
) {
  const data = readExactData(
    value,
    COORDINATION_IDENTITY_KEYS,
  );
  if (
    typeof data.keyId !== "string" ||
    !KEY_ID_PATTERN.test(data.keyId) ||
    typeof data.privateKeyPem !== "string" ||
    data.privateKeyPem.length === 0 ||
    Buffer.byteLength(data.privateKeyPem, "utf8") >
      1_024 ||
    typeof data.publicKey !== "string" ||
    !BASE64_PATTERN.test(data.publicKey)
  ) {
    invalid();
  }
  let privateKey;
  let derived;
  try {
    privateKey = createPrivateKey(data.privateKeyPem);
    if (
      privateKey.asymmetricKeyType !== "ed25519" ||
      privateKey.export({
        format: "pem",
        type: "pkcs8",
      }) !== data.privateKeyPem
    ) {
      invalid();
    }
    const der = createPublicKey(privateKey).export({
      format: "der",
      type: "spki",
    });
    if (
      der.length !== ED25519_SPKI_PREFIX.length + 32 ||
      !der
        .subarray(0, ED25519_SPKI_PREFIX.length)
        .equals(ED25519_SPKI_PREFIX)
    ) {
      invalid();
    }
    derived = der.subarray(ED25519_SPKI_PREFIX.length);
  } catch (error) {
    if (error instanceof LaunchManifestError) {
      throw error;
    }
    invalid();
  }
  const supplied = Buffer.from(data.publicKey, "base64");
  if (
    supplied.length !== 32 ||
    supplied.toString("base64") !== data.publicKey ||
    !timingSafeEqual(supplied, derived) ||
    data.keyId !== enrollment.coordinationKey.keyId ||
    data.publicKey !==
      enrollment.coordinationKey.publicKey
  ) {
    invalid();
  }
  return privateKey;
}

function assertActiveStateStructure(value) {
  const role = readDataRole(value);
  const data = readExactData(
    value,
    activeStateKeysForRole(role),
  );
  const issuedAtMs = assertDecimalMs(data.issuedAtMs);
  const expiresAtMs = assertDecimalMs(data.expiresAtMs);
  if (
    data.schema !== ACTIVE_LAUNCH_STATE_SCHEMA ||
    data.protocol !== BILATERAL_PROTOCOL ||
    data.paymentMoved !== false ||
    typeof data.capabilityDigest !== "string" ||
    !SHA256_PATTERN.test(data.capabilityDigest) ||
    typeof data.enrollmentBase64 !== "string" ||
    !BASE64_PATTERN.test(data.enrollmentBase64) ||
    typeof data.enrollmentDigest !== "string" ||
    !SHA256_PATTERN.test(data.enrollmentDigest) ||
    typeof data.repositorySha !== "string" ||
    !REPOSITORY_SHA_PATTERN.test(data.repositorySha) ||
    typeof data.operatorKeyId !== "string" ||
    !KEY_ID_PATTERN.test(data.operatorKeyId) ||
    typeof data.sessionId !== "string" ||
    !UUID_PATTERN.test(data.sessionId) ||
    expiresAtMs - issuedAtMs !==
      UNUSED_CAPABILITY_LIFETIME_MS ||
    typeof data.receiptBase64 !== "string" ||
    !BASE64_PATTERN.test(data.receiptBase64) ||
    typeof data.signature !== "string" ||
    !BASE64_PATTERN.test(data.signature)
  ) {
    invalid();
  }
  if (
    data.role === "payer" &&
    (typeof data.payerMcpIntakeCapabilityDigest !==
      "string" ||
      !SHA256_PATTERN.test(
        data.payerMcpIntakeCapabilityDigest,
      ))
  ) {
    invalid();
  }
  const enrollmentBytes = Buffer.from(
    data.enrollmentBase64,
    "base64",
  );
  const receiptBytes = Buffer.from(
    data.receiptBase64,
    "base64",
  );
  const signature = Buffer.from(
    data.signature,
    "base64",
  );
  if (
    enrollmentBytes.length === 0 ||
    enrollmentBytes.length > 65_536 ||
    enrollmentBytes.toString("base64") !==
      data.enrollmentBase64 ||
    receiptBytes.length === 0 ||
    receiptBytes.length > 65_536 ||
    receiptBytes.toString("base64") !==
      data.receiptBase64 ||
    signature.length !== 64 ||
    signature.toString("base64") !== data.signature
  ) {
    invalid();
  }
  const enrollment = parseCoordinationEnrollment(
    enrollmentBytes,
  );
  if (
    sha256(enrollmentBytes) !== data.enrollmentDigest ||
    enrollment.capabilityDigest !==
      data.capabilityDigest ||
    enrollment.coordinationKey.keyId !==
      `${data.role}-coordination` ||
    enrollment.paymentMoved !== false ||
    enrollment.preflightKey.keyId !==
      `${data.role}-preflight` ||
    enrollment.releaseId !== data.releaseId ||
    enrollment.repositorySha !==
      data.repositorySha ||
    enrollment.role !== data.role ||
    enrollment.sessionId !== data.sessionId
  ) {
    invalid();
  }
  assertCertificateAndFingerprint(
    data.tlsCertificatePem,
    data.expectedTlsFingerprint,
  );
  const unsignedState = Object.freeze({
    capabilityDigest: data.capabilityDigest,
    enrollmentBase64: data.enrollmentBase64,
    enrollmentDigest: data.enrollmentDigest,
    expectedTlsFingerprint:
      data.expectedTlsFingerprint,
    expiresAtMs: data.expiresAtMs,
    issuedAtMs: data.issuedAtMs,
    operatorKeyId: data.operatorKeyId,
    ...(data.role === "payer"
      ? {
          payerMcpIntakeCapabilityDigest:
            data.payerMcpIntakeCapabilityDigest,
        }
      : {}),
    paymentMoved: false,
    protocol: data.protocol,
    receiptBase64: data.receiptBase64,
    relayUrl: assertRelayUrl(data.relayUrl),
    releaseId: assertReleaseId(data.releaseId),
    repositorySha: data.repositorySha,
    role: data.role,
    schema: data.schema,
    sessionId: data.sessionId,
    tlsCertificatePem: data.tlsCertificatePem,
  });
  let signatureValid;
  try {
    signatureValid = verifyBytes(
      null,
      activeStateSignaturePreimage(unsignedState),
      enrolledCoordinationPublicKey(enrollment),
      signature,
    );
  } catch {
    invalid();
  }
  if (signatureValid !== true) {
    invalid();
  }
  return Object.freeze({
    state: Object.freeze({
      ...unsignedState,
      signature: data.signature,
    }),
    enrollment,
    receiptBytes,
  });
}

export async function validateActiveLaunchState(value) {
  try {
    const { receiptBytes, state } =
      assertActiveStateStructure(value);
    const verifier =
      createReceiptVerifierFromCertificate({
        tlsCertificatePem:
          state.tlsCertificatePem,
      });
    const receipt = await verifyCoordinationReceipt({
      bytes: receiptBytes,
      expected: {
        capabilityDigest: state.capabilityDigest,
        enrollmentDigest: state.enrollmentDigest,
        releaseId: state.releaseId,
        repositorySha: state.repositorySha,
        role: state.role,
        sessionId: state.sessionId,
      },
      verifier,
    });
    if (
      receipt.paymentMoved !== false ||
      receipt.certificateSha256 !==
        state.expectedTlsFingerprint
    ) {
      invalid();
    }
    return state;
  } catch (error) {
    if (error instanceof LaunchManifestError) {
      throw error;
    }
    invalid();
  }
}

export async function createActiveLaunchState(input) {
  try {
    const data = readExactData(
      input,
      CREATE_ACTIVE_STATE_KEYS,
    );
    const manifest = validateLaunchManifest(
      data.manifest,
    );
    if (!Buffer.isBuffer(data.receiptBytes)) {
      invalid();
    }
    const enrollment =
      verifyCoordinationEnrollment(data.enrollment);
    const privateKey = validateCoordinationIdentity(
      data.coordinationIdentity,
      enrollment,
    );
    const enrollmentBytes =
      canonicalBytes(enrollment);
    const capabilityDigest = sha256(
      Buffer.from(
        manifest.bootstrapCapability,
        "hex",
      ),
    );
    if (
      enrollment.capabilityDigest !==
        capabilityDigest ||
      enrollment.paymentMoved !== false ||
      enrollment.releaseId !== manifest.releaseId ||
      enrollment.repositorySha !==
        manifest.repositorySha ||
      enrollment.role !== manifest.role ||
      enrollment.sessionId !== manifest.sessionId
    ) {
      invalid();
    }
    const unsignedState = Object.freeze({
      capabilityDigest,
      enrollmentBase64:
        enrollmentBytes.toString("base64"),
      enrollmentDigest: sha256(enrollmentBytes),
      expectedTlsFingerprint:
        manifest.expectedTlsFingerprint,
      expiresAtMs: manifest.expiresAtMs,
      issuedAtMs: manifest.issuedAtMs,
      operatorKeyId: manifest.operatorKeyId,
      ...(manifest.role === "payer"
        ? {
            payerMcpIntakeCapabilityDigest:
              manifest.payerMcpIntakeCapabilityDigest,
          }
        : {}),
      paymentMoved: false,
      protocol: manifest.protocol,
      receiptBase64: Buffer.from(
        data.receiptBytes,
      ).toString("base64"),
      relayUrl: manifest.relayUrl,
      releaseId: manifest.releaseId,
      repositorySha: manifest.repositorySha,
      role: manifest.role,
      schema: ACTIVE_LAUNCH_STATE_SCHEMA,
      sessionId: manifest.sessionId,
      tlsCertificatePem:
        manifest.tlsCertificatePem,
    });
    const capability = Buffer.from(
      manifest.bootstrapCapability,
      "hex",
    );
    assertCapabilityIsolated(
      stableBytes(unsignedState),
      capability,
    );
    if (manifest.role === "payee") {
      assertCapabilityIsolated(
        stableBytes(unsignedState),
        Buffer.from(
          manifest.payerMcpIntakeCapability,
          "hex",
        ),
      );
    }
    let signature;
    try {
      signature = signBytes(
        null,
        activeStateSignaturePreimage(unsignedState),
        privateKey,
      );
    } catch {
      invalid();
    }
    if (
      !Buffer.isBuffer(signature) ||
      signature.length !== 64
    ) {
      invalid();
    }
    const state = Object.freeze({
      ...unsignedState,
      signature: signature.toString("base64"),
    });
    assertCapabilityIsolated(
      stableBytes(state),
      capability,
    );
    return await validateActiveLaunchState(state);
  } catch (error) {
    if (error instanceof LaunchManifestError) {
      throw error;
    }
    invalid();
  }
}

function readFileSystem(dependencies) {
  if (dependencies === undefined) {
    return DEFAULT_FILE_SYSTEM;
  }
  const data = readExactData(
    dependencies,
    DEPENDENCY_KEYS,
  );
  const fileSystem = data.fileSystem;
  if (!isPlainObject(fileSystem)) {
    invalid();
  }
  const methods = Object.create(null);
  for (const method of ["lstat", "open"]) {
    const descriptor =
      Object.getOwnPropertyDescriptor(
        fileSystem,
        method,
      );
    if (
      descriptor?.enumerable !== true ||
      !Object.hasOwn(descriptor, "value") ||
      typeof descriptor.value !== "function"
    ) {
      invalid();
    }
    methods[method] = descriptor.value;
  }
  const unlinkDescriptor =
    Object.getOwnPropertyDescriptor(
      fileSystem,
      "unlink",
    );
  if (unlinkDescriptor !== undefined) {
    if (
      unlinkDescriptor.enumerable !== true ||
      !Object.hasOwn(unlinkDescriptor, "value") ||
      typeof unlinkDescriptor.value !== "function"
    ) {
      invalid();
    }
    methods.unlink = unlinkDescriptor.value;
  } else {
    methods.unlink = unlink;
  }
  return Object.freeze(methods);
}

function normalizePath(path) {
  if (
    typeof path !== "string" ||
    path.length === 0 ||
    path.includes("\0")
  ) {
    invalid();
  }
  return resolve(path);
}

function sameIdentity(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.nlink === right.nlink &&
    left.uid === right.uid &&
    left.gid === right.gid &&
    left.rdev === right.rdev &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs
  );
}

function sameNode(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.nlink === right.nlink &&
    left.uid === right.uid &&
    left.gid === right.gid &&
    left.rdev === right.rdev
  );
}

function sameDirectoryNode(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.uid === right.uid &&
    left.gid === right.gid &&
    left.rdev === right.rdev
  );
}

function validPrivateDirectory(metadata) {
  return (
    metadata.isDirectory() &&
    !metadata.isSymbolicLink() &&
    metadata.uid === process.getuid() &&
    (metadata.mode & 0o777) === 0o700
  );
}

function validPrivateRegular(metadata, maximum) {
  return (
    metadata.isFile() &&
    !metadata.isSymbolicLink() &&
    metadata.nlink === 1 &&
    metadata.uid === process.getuid() &&
    (metadata.mode & 0o777) === 0o600 &&
    metadata.size > 0 &&
    metadata.size <= maximum
  );
}

async function closeHandle(handle) {
  if (handle !== undefined) {
    await handle.close();
  }
}

async function openPinnedParent(
  path,
  fileSystem,
) {
  const parentPath = dirname(path);
  const before = await fileSystem.lstat(parentPath);
  if (!validPrivateDirectory(before)) {
    invalid();
  }
  let handle;
  try {
    handle = await fileSystem.open(
      parentPath,
      fsConstants.O_RDONLY |
        (fsConstants.O_DIRECTORY ?? 0) |
        (fsConstants.O_NOFOLLOW ?? 0) |
        fsConstants.O_NONBLOCK,
    );
    const opened = await handle.stat();
    if (
      !validPrivateDirectory(opened) ||
      !sameIdentity(before, opened)
    ) {
      invalid();
    }
    return Object.freeze({
      before,
      handle,
      parentPath,
    });
  } catch (error) {
    try {
      await closeHandle(handle);
    } catch {
      invalid();
    }
    throw error;
  }
}

async function assertUnchangedParent(
  parent,
  fileSystem,
  { allowDirectoryMutation = false } = {},
) {
  const opened = await parent.handle.stat();
  const pathname = await fileSystem.lstat(
    parent.parentPath,
  );
  if (
    !validPrivateDirectory(opened) ||
    !validPrivateDirectory(pathname) ||
    !sameIdentity(opened, pathname) ||
    (allowDirectoryMutation
      ? !sameDirectoryNode(parent.before, opened)
      : !sameIdentity(parent.before, opened))
  ) {
    invalid();
  }
}

export async function readLaunchManifest(
  path,
  dependencies,
) {
  let handle;
  let parent;
  let failure;
  let manifest;
  try {
    const fileSystem = readFileSystem(dependencies);
    const normalizedPath = normalizePath(path);
    parent = await openPinnedParent(
      normalizedPath,
      fileSystem,
    );
    const before =
      await fileSystem.lstat(normalizedPath);
    if (
      !validPrivateRegular(
        before,
        MAX_MANIFEST_BYTES,
      )
    ) {
      invalid();
    }
    handle = await fileSystem.open(
      normalizedPath,
      fsConstants.O_RDONLY |
        (fsConstants.O_NOFOLLOW ?? 0) |
        fsConstants.O_NONBLOCK,
    );
    const opened = await handle.stat();
    if (!sameIdentity(before, opened)) {
      invalid();
    }
    const output = Buffer.alloc(MAX_MANIFEST_BYTES + 1);
    let offset = 0;
    for (;;) {
      const { bytesRead } = await handle.read(
        output,
        offset,
        output.length - offset,
        offset,
      );
      offset += bytesRead;
      if (
        bytesRead === 0 ||
        offset === output.length
      ) {
        break;
      }
    }
    const after = await handle.stat();
    const pathnameAfter =
      await fileSystem.lstat(normalizedPath);
    if (
      offset !== before.size ||
      offset === 0 ||
      offset > MAX_MANIFEST_BYTES ||
      !sameIdentity(before, after) ||
      !sameIdentity(before, pathnameAfter)
    ) {
      invalid();
    }
    await assertUnchangedParent(
      parent,
      fileSystem,
    );
    const bytes = Buffer.from(output.subarray(0, offset));
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
      if (error instanceof LaunchManifestError) {
        throw error;
      }
      invalid();
    }
    manifest = validateLaunchManifest(parsed);
  } catch (error) {
    failure =
      error instanceof LaunchManifestError
        ? error
        : new LaunchManifestError();
  }
  try {
    await closeHandle(handle);
    handle = undefined;
  } catch (error) {
    failure ??=
      error instanceof LaunchManifestError
        ? error
        : new LaunchManifestError();
  }
  try {
    await closeHandle(parent?.handle);
    parent = undefined;
  } catch (error) {
    failure ??=
      error instanceof LaunchManifestError
        ? error
        : new LaunchManifestError();
  }
  if (failure !== undefined) {
    throw failure;
  }
  return manifest;
}

export async function writeLaunchManifest(
  path,
  value,
  dependencies,
) {
  let fileHandle;
  let parent;
  let createdPath;
  let createdIdentity;
  let fileSystem;
  let failure;
  let publicRegistration;
  try {
    fileSystem = readFileSystem(dependencies);
    const normalizedPath = normalizePath(path);
    const manifest = validateLaunchManifest(value);
    const bytes = stableBytes(manifest);
    if (
      bytes.length === 0 ||
      bytes.length > MAX_MANIFEST_BYTES
    ) {
      invalid();
    }
    parent = await openPinnedParent(
      normalizedPath,
      fileSystem,
    );
    try {
      await fileSystem.lstat(normalizedPath);
      invalid();
    } catch (error) {
      if (error instanceof LaunchManifestError) {
        throw error;
      }
      if (error?.code !== "ENOENT") {
        invalid();
      }
    }
    fileHandle = await fileSystem.open(
      normalizedPath,
      fsConstants.O_RDWR |
        fsConstants.O_CREAT |
        fsConstants.O_EXCL |
        (fsConstants.O_NOFOLLOW ?? 0) |
        fsConstants.O_NONBLOCK,
      0o600,
    );
    createdPath = normalizedPath;
    createdIdentity = await fileHandle.stat();
    if (
      !createdIdentity.isFile() ||
      createdIdentity.isSymbolicLink() ||
      createdIdentity.nlink !== 1 ||
      createdIdentity.uid !== process.getuid() ||
      (createdIdentity.mode & 0o777) !== 0o600 ||
      createdIdentity.size !== 0
    ) {
      invalid();
    }
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesWritten } = await fileHandle.write(
        bytes,
        offset,
        bytes.length - offset,
        offset,
      );
      if (bytesWritten <= 0) {
        invalid();
      }
      offset += bytesWritten;
    }
    await fileHandle.sync();
    const persisted = Buffer.alloc(bytes.length + 1);
    let readOffset = 0;
    for (;;) {
      const { bytesRead } = await fileHandle.read(
        persisted,
        readOffset,
        persisted.length - readOffset,
        readOffset,
      );
      readOffset += bytesRead;
      if (
        bytesRead === 0 ||
        readOffset === persisted.length
      ) {
        break;
      }
    }
    if (
      readOffset !== bytes.length ||
      !persisted
        .subarray(0, readOffset)
        .equals(bytes)
    ) {
      invalid();
    }
    const opened = await fileHandle.stat();
    const pathname =
      await fileSystem.lstat(normalizedPath);
    if (
      !validPrivateRegular(
        opened,
        MAX_MANIFEST_BYTES,
      ) ||
      opened.size !== bytes.length ||
      !sameIdentity(opened, pathname)
    ) {
      invalid();
    }
    await parent.handle.sync();
    await assertUnchangedParent(
      parent,
      fileSystem,
      { allowDirectoryMutation: true },
    );
    publicRegistration = Object.freeze({
      capabilityDigest: sha256(
        Buffer.from(
          manifest.bootstrapCapability,
          "hex",
        ),
      ),
      expiresAtMs: manifest.expiresAtMs,
      releaseId: manifest.releaseId,
      role: manifest.role,
      sessionId: manifest.sessionId,
    });
  } catch (error) {
    failure =
      error instanceof LaunchManifestError
        ? error
        : new LaunchManifestError();
  }
  for (const handle of [
    fileHandle,
    parent?.handle,
  ]) {
    try {
      await closeHandle(handle);
    } catch (error) {
      failure ??=
        error instanceof LaunchManifestError
          ? error
          : new LaunchManifestError();
    }
  }
  if (failure !== undefined) {
    if (createdPath !== undefined) {
      try {
        const pathname = await (
          fileSystem?.lstat ?? lstat
        )(createdPath);
        if (
          createdIdentity !== undefined &&
          sameNode(createdIdentity, pathname)
        ) {
          await (fileSystem?.unlink ?? unlink)(
            createdPath,
          );
        }
      } catch {
        // The fixed public error is retained. The caller can inspect
        // the private directory before retrying an exclusive write.
      }
    }
    throw failure;
  }
  return publicRegistration;
}
