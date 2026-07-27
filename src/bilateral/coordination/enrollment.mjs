import {
  createHash,
  createPublicKey,
  verify,
} from "node:crypto";

import {
  canonicalBytes,
} from "../canonical.mjs";
import {
  KEY_ID_PATTERN,
} from "../descriptor.mjs";
import {
  canonicalizeReceiptEventValue,
} from "../../canonical.mjs";
import {
  assertSecretFree,
} from "../../redact.mjs";

export const COORDINATION_ENROLLMENT_SCHEMA =
  "clockchain.bilateral-coordination-enrollment/v1";
export const COORDINATION_ENROLLMENT_SET_SCHEMA =
  "clockchain.bilateral-coordination-enrollment-set/v1";
export const COORDINATION_ENROLLMENT_SIGNATURE_DOMAIN =
  "clockchain.bilateral-coordination-enrollment-signature/v1\n";
export const INVITATION_PROOF_DOMAIN =
  "clockchain.bilateral-invitation-proof/v1\n";
export const MAX_COORDINATION_ENROLLMENT_BYTES = 65_536;
export const MAX_COORDINATION_ENROLLMENT_SET_BYTES =
  524_288;

const ENROLLMENT_KEYS = Object.freeze([
  "capabilityDigest",
  "coordinationKey",
  "invitations",
  "paymentMoved",
  "preflightKey",
  "releaseId",
  "repositorySha",
  "role",
  "schema",
  "sessionId",
  "signature",
]);
const ENROLLMENT_SET_KEYS = Object.freeze([
  "enrollments",
  "paymentMoved",
  "releaseId",
  "repositorySha",
  "schema",
  "sessionId",
]);
const ENROLLMENTS_KEYS = Object.freeze([
  "payee",
  "payer",
]);
const ENROLLMENT_SET_ENTRY_KEYS = Object.freeze([
  "enrollmentBase64",
  "enrollmentDigest",
  "receiptBase64",
]);
const UNSIGNED_ENROLLMENT_KEYS = Object.freeze(
  ENROLLMENT_KEYS.filter((key) => key !== "signature"),
);
const KEY_KEYS = Object.freeze([
  "algorithm",
  "keyId",
  "publicKey",
]);
const INVITATIONS_KEYS = Object.freeze([
  "rehearsal",
  "stakeholder",
]);
const INVITATION_KEYS = Object.freeze([
  "address",
  "algorithm",
  "signature",
]);
const INVITATION_PROOF_KEYS = Object.freeze([
  "address",
  "capabilityDigest",
  "releaseId",
  "repositorySha",
  "role",
  "run",
  "sessionId",
]);
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const REPOSITORY_SHA_PATTERN = /^[0-9a-f]{40}$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const EIP191_SIGNATURE_PATTERN = /^0x[0-9a-f]{130}$/;
const BASE64_PATTERN =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const PRINTABLE_ASCII_PATTERN = /^[ -~]+$/;
const ED25519_SPKI_PREFIX = Buffer.from(
  "302a300506032b6570032100",
  "hex",
);

export class CoordinationEnrollmentError extends Error {
  constructor() {
    super("Coordination enrollment validation failed.");
    this.name = new.target.name;
    this.category = "verification";
    this.code = "COORDINATION_ENROLLMENT_INVALID";
  }
}

function invalid() {
  throw new CoordinationEnrollmentError();
}

function guarded(operation) {
  try {
    return operation();
  } catch (error) {
    if (error instanceof CoordinationEnrollmentError) {
      throw error;
    }
    invalid();
  }
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object") {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return (
    prototype === Object.prototype || prototype === null
  );
}

function readExactData(value, keys) {
  if (!isPlainObject(value)) {
    invalid();
  }
  const ownKeys = Reflect.ownKeys(value);
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
    const descriptor = Object.getOwnPropertyDescriptor(
      value,
      key,
    );
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
  return result;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function stableBytes(value) {
  return Buffer.from(
    JSON.stringify(canonicalizeReceiptEventValue(value)),
    "utf8",
  );
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

function assertRepositorySha(value) {
  if (
    typeof value !== "string" ||
    !REPOSITORY_SHA_PATTERN.test(value)
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

function assertRole(value) {
  if (value !== "payer" && value !== "payee") {
    invalid();
  }
  return value;
}

function assertSessionId(value) {
  if (
    typeof value !== "string" ||
    !UUID_PATTERN.test(value)
  ) {
    invalid();
  }
  return value;
}

function publicKey(value) {
  const data = readExactData(value, KEY_KEYS);
  if (
    data.algorithm !== "ed25519" ||
    typeof data.keyId !== "string" ||
    !KEY_ID_PATTERN.test(data.keyId) ||
    typeof data.publicKey !== "string" ||
    data.publicKey.length !== 44 ||
    !BASE64_PATTERN.test(data.publicKey)
  ) {
    invalid();
  }
  const raw = Buffer.from(data.publicKey, "base64");
  if (
    raw.length !== 32 ||
    raw.toString("base64") !== data.publicKey
  ) {
    invalid();
  }
  return Object.freeze({
    algorithm: data.algorithm,
    keyId: data.keyId,
    publicKey: data.publicKey,
  });
}

function invitation(value) {
  const data = readExactData(value, INVITATION_KEYS);
  if (
    typeof data.address !== "string" ||
    !ADDRESS_PATTERN.test(data.address) ||
    data.algorithm !== "eip191" ||
    typeof data.signature !== "string" ||
    !EIP191_SIGNATURE_PATTERN.test(data.signature)
  ) {
    invalid();
  }
  return Object.freeze({
    address: data.address,
    algorithm: data.algorithm,
    signature: data.signature,
  });
}

function invitations(value) {
  const data = readExactData(value, INVITATIONS_KEYS);
  const rehearsal = invitation(data.rehearsal);
  const stakeholder = invitation(data.stakeholder);
  if (rehearsal.address === stakeholder.address) {
    invalid();
  }
  return Object.freeze({
    rehearsal,
    stakeholder,
  });
}

function unsignedEnrollment(value) {
  const data = readExactData(
    value,
    UNSIGNED_ENROLLMENT_KEYS,
  );
  const coordinationKey = publicKey(
    data.coordinationKey,
  );
  const preflightKey = publicKey(data.preflightKey);
  if (
    coordinationKey.keyId === preflightKey.keyId ||
    coordinationKey.publicKey === preflightKey.publicKey
  ) {
    invalid();
  }
  const snapshot = Object.freeze({
    capabilityDigest: assertSha256(
      data.capabilityDigest,
    ),
    coordinationKey,
    invitations: invitations(data.invitations),
    paymentMoved:
      data.paymentMoved === false
        ? false
        : invalid(),
    preflightKey,
    releaseId: assertReleaseId(data.releaseId),
    repositorySha: assertRepositorySha(
      data.repositorySha,
    ),
    role: assertRole(data.role),
    schema:
      data.schema === COORDINATION_ENROLLMENT_SCHEMA
        ? data.schema
        : invalid(),
    sessionId: assertSessionId(data.sessionId),
  });
  assertSecretFree(snapshot);
  return snapshot;
}

function signatureBytes(value) {
  if (
    typeof value !== "string" ||
    value.length !== 88 ||
    !BASE64_PATTERN.test(value)
  ) {
    invalid();
  }
  const bytes = Buffer.from(value, "base64");
  if (
    bytes.length !== 64 ||
    bytes.toString("base64") !== value
  ) {
    invalid();
  }
  return bytes;
}

function canonicalBase64Bytes(value, maximum) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    !BASE64_PATTERN.test(value)
  ) {
    invalid();
  }
  const bytes = Buffer.from(value, "base64");
  if (
    bytes.length === 0 ||
    bytes.length > maximum ||
    bytes.toString("base64") !== value
  ) {
    invalid();
  }
  return bytes;
}

function publicKeyObject(rawBase64) {
  const raw = Buffer.from(rawBase64, "base64");
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
    format: "der",
    type: "spki",
  });
}

export function invitationProofPreimage(input) {
  return guarded(() => {
    const data = readExactData(
      input,
      INVITATION_PROOF_KEYS,
    );
    const challenge = Object.freeze({
      address:
        typeof data.address === "string" &&
        ADDRESS_PATTERN.test(data.address)
          ? data.address
          : invalid(),
      capabilityDigest: assertSha256(
        data.capabilityDigest,
      ),
      releaseId: assertReleaseId(data.releaseId),
      repositorySha: assertRepositorySha(
        data.repositorySha,
      ),
      role: assertRole(data.role),
      run:
        data.run === "rehearsal" ||
        data.run === "stakeholder"
          ? data.run
          : invalid(),
      sessionId: assertSessionId(data.sessionId),
    });
    return Buffer.concat([
      Buffer.from(INVITATION_PROOF_DOMAIN, "ascii"),
      Buffer.from(
        sha256(canonicalBytes(challenge)),
        "ascii",
      ),
    ]);
  });
}

export function coordinationEnrollmentSignaturePreimage(
  enrollment,
) {
  return guarded(() => {
    const unsigned = unsignedEnrollment(enrollment);
    return Buffer.concat([
      Buffer.from(
        COORDINATION_ENROLLMENT_SIGNATURE_DOMAIN,
        "ascii",
      ),
      Buffer.from(
        sha256(canonicalBytes(unsigned)),
        "ascii",
      ),
    ]);
  });
}

export function verifyCoordinationEnrollment(enrollment) {
  return guarded(() => {
    const data = readExactData(enrollment, ENROLLMENT_KEYS);
    const unsigned = unsignedEnrollment({
      capabilityDigest: data.capabilityDigest,
      coordinationKey: data.coordinationKey,
      invitations: data.invitations,
      paymentMoved: data.paymentMoved,
      preflightKey: data.preflightKey,
      releaseId: data.releaseId,
      repositorySha: data.repositorySha,
      role: data.role,
      schema: data.schema,
      sessionId: data.sessionId,
    });
    const signature = signatureBytes(data.signature);
    const valid = verify(
      null,
      coordinationEnrollmentSignaturePreimage(unsigned),
      publicKeyObject(unsigned.coordinationKey.publicKey),
      signature,
    );
    if (!valid) {
      invalid();
    }
    const snapshot = Object.freeze({
      ...unsigned,
      signature: data.signature,
    });
    if (
      canonicalBytes(snapshot).length >
      MAX_COORDINATION_ENROLLMENT_BYTES
    ) {
      invalid();
    }
    return snapshot;
  });
}

export function parseCoordinationEnrollment(bytes) {
  return guarded(() => {
    if (
      !Buffer.isBuffer(bytes) ||
      bytes.length === 0 ||
      bytes.length > MAX_COORDINATION_ENROLLMENT_BYTES
    ) {
      invalid();
    }
    const copy = Buffer.from(bytes);
    const text = copy.toString("utf8");
    if (Buffer.byteLength(text, "utf8") !== copy.length) {
      invalid();
    }
    const verified = verifyCoordinationEnrollment(
      JSON.parse(text),
    );
    if (!canonicalBytes(verified).equals(copy)) {
      invalid();
    }
    return verified;
  });
}

function enrollmentSetEntry(
  value,
  role,
  {
    releaseId,
    repositorySha,
    sessionId,
  },
) {
  const data = readExactData(
    value,
    ENROLLMENT_SET_ENTRY_KEYS,
  );
  const enrollmentBytes = canonicalBase64Bytes(
    data.enrollmentBase64,
    MAX_COORDINATION_ENROLLMENT_BYTES,
  );
  canonicalBase64Bytes(data.receiptBase64, 65_536);
  const enrollmentDigest = assertSha256(
    data.enrollmentDigest,
  );
  const enrollment =
    parseCoordinationEnrollment(enrollmentBytes);
  if (
    sha256(enrollmentBytes) !== enrollmentDigest ||
    enrollment.paymentMoved !== false ||
    enrollment.releaseId !== releaseId ||
    enrollment.repositorySha !== repositorySha ||
    enrollment.role !== role ||
    enrollment.sessionId !== sessionId
  ) {
    invalid();
  }
  return Object.freeze({
    entry: Object.freeze({
      enrollmentBase64: data.enrollmentBase64,
      enrollmentDigest,
      receiptBase64: data.receiptBase64,
    }),
    enrollment,
  });
}

function verifyEnrollmentSet(value) {
  const data = readExactData(
    value,
    ENROLLMENT_SET_KEYS,
  );
  const releaseId = assertReleaseId(data.releaseId);
  const repositorySha = assertRepositorySha(
    data.repositorySha,
  );
  const sessionId = assertSessionId(data.sessionId);
  if (
    data.schema !==
      COORDINATION_ENROLLMENT_SET_SCHEMA ||
    data.paymentMoved !== false
  ) {
    invalid();
  }
  const enrollmentsData = readExactData(
    data.enrollments,
    ENROLLMENTS_KEYS,
  );
  const payee = enrollmentSetEntry(
    enrollmentsData.payee,
    "payee",
    { releaseId, repositorySha, sessionId },
  );
  const payer = enrollmentSetEntry(
    enrollmentsData.payer,
    "payer",
    { releaseId, repositorySha, sessionId },
  );
  const keyIds = [
    payee.enrollment.coordinationKey.keyId,
    payee.enrollment.preflightKey.keyId,
    payer.enrollment.coordinationKey.keyId,
    payer.enrollment.preflightKey.keyId,
  ];
  const publicKeys = [
    payee.enrollment.coordinationKey.publicKey,
    payee.enrollment.preflightKey.publicKey,
    payer.enrollment.coordinationKey.publicKey,
    payer.enrollment.preflightKey.publicKey,
  ];
  const addresses = [
    payee.enrollment.invitations.rehearsal.address,
    payee.enrollment.invitations.stakeholder.address,
    payer.enrollment.invitations.rehearsal.address,
    payer.enrollment.invitations.stakeholder.address,
  ];
  if (
    new Set(keyIds).size !== keyIds.length ||
    new Set(publicKeys).size !== publicKeys.length ||
    new Set(addresses).size !== addresses.length
  ) {
    invalid();
  }
  const snapshot = Object.freeze({
    enrollments: Object.freeze({
      payee: payee.entry,
      payer: payer.entry,
    }),
    paymentMoved: false,
    releaseId,
    repositorySha,
    schema: COORDINATION_ENROLLMENT_SET_SCHEMA,
    sessionId,
  });
  assertSecretFree(snapshot);
  return snapshot;
}

export function parseCoordinationEnrollmentSet(bytes) {
  return guarded(() => {
    if (
      !Buffer.isBuffer(bytes) ||
      bytes.length === 0 ||
      bytes.length >
        MAX_COORDINATION_ENROLLMENT_SET_BYTES
    ) {
      invalid();
    }
    const copy = Buffer.from(bytes);
    const text = copy.toString("utf8");
    if (!Buffer.from(text, "utf8").equals(copy)) {
      invalid();
    }
    const verified = verifyEnrollmentSet(
      JSON.parse(text),
    );
    if (!stableBytes(verified).equals(copy)) {
      invalid();
    }
    return verified;
  });
}
