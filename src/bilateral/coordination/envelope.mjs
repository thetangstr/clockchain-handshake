import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  timingSafeEqual,
  verify,
} from "node:crypto";

import {
  MAX_CANONICAL_STRING_LENGTH,
  canonicalBytes,
} from "../canonical.mjs";

export const COORDINATION_ENVELOPE_SCHEMA =
  "clockchain.bilateral-coordination-event/v1";
export const COORDINATION_SIGNATURE_DOMAIN =
  "clockchain.bilateral-coordination-signature/v1\n";
export const MAX_COORDINATION_ENVELOPE_BYTES = 65_536;

const ENVELOPE_KEYS = Object.freeze([
  "artifactDigest",
  "eventDigest",
  "kind",
  "paymentMoved",
  "previousEventDigest",
  "releaseId",
  "repositorySha",
  "role",
  "schema",
  "sequence",
  "sessionId",
  "signature",
  "subjectRun",
]);
const SIGNATURE_KEYS = Object.freeze([
  "algorithm",
  "keyId",
  "publicKey",
  "value",
]);
const CREATE_KEYS = Object.freeze([
  "artifactDigest",
  "kind",
  "paymentMoved",
  "previousEventDigest",
  "privateKeyPem",
  "publicKey",
  "publicKeyId",
  "releaseId",
  "repositorySha",
  "role",
  "schema",
  "sequence",
  "sessionId",
  "subjectRun",
]);
const EXPECTED_KEYS = Object.freeze([
  "expectedPublicKey",
  "expectedReleaseId",
  "expectedRepositorySha",
  "expectedRole",
  "expectedSessionId",
]);
const EXPECTED_KEYS_WITH_SUBJECT_RUN = Object.freeze([
  ...EXPECTED_KEYS,
  "expectedSubjectRun",
]);
const ROLES = Object.freeze(["operator", "payer", "payee"]);
const SUBJECT_RUNS = Object.freeze([
  "release",
  "rehearsal",
  "stakeholder",
]);

const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const REPOSITORY_SHA_PATTERN = /^[0-9a-f]{40}$/;
const SEQUENCE_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const KIND_PATTERN =
  /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const KEY_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,63}$/;
const PRINTABLE_ASCII_PATTERN = /^[ -~]+$/;
const BASE64_PATTERN =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const SIGNATURE_BASE64_LENGTH = 88;
const RAW_PUBLIC_KEY_BASE64_LENGTH = 44;
const MAX_KIND_LENGTH = 64;
const MAX_SNAPSHOT_DEPTH = 4;
const MAX_SNAPSHOT_OBJECTS = 4;
const MAX_SNAPSHOT_PROPERTIES = 64;
const MAX_SNAPSHOT_KEY_LENGTH = MAX_CANONICAL_STRING_LENGTH;
const MAX_PRIVATE_KEY_PEM_BYTES = 1_024;
const ED25519_SPKI_PREFIX = Buffer.from(
  "302a300506032b6570032100",
  "hex",
);

export class CoordinationEnvelopeError extends Error {
  constructor() {
    super("Coordination envelope validation failed.");
    this.name = new.target.name;
    this.category = "verification";
    this.code = "COORDINATION_ENVELOPE_INVALID";
  }
}

function invalid() {
  throw new CoordinationEnvelopeError();
}

class SnapshotFailure extends Error {}

function snapshotFailure() {
  throw new SnapshotFailure();
}

function snapshotValue(value, state, depth) {
  if (
    value === null ||
    value === undefined ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    typeof value === "number" ||
    typeof value === "bigint"
  ) {
    return value;
  }
  if (
    typeof value !== "object" ||
    depth > MAX_SNAPSHOT_DEPTH ||
    state.remainingObjects === 0 ||
    state.ancestors.has(value) ||
    Array.isArray(value)
  ) {
    snapshotFailure();
  }

  state.remainingObjects -= 1;
  state.ancestors.add(value);
  try {
    const prototype = Object.getPrototypeOf(value);
    if (
      prototype !== Object.prototype &&
      prototype !== null
    ) {
      snapshotFailure();
    }
    const keys = Reflect.ownKeys(value);
    if (keys.length > state.remainingProperties) {
      snapshotFailure();
    }
    state.remainingProperties -= keys.length;
    const snapshot = Object.create(null);
    for (const key of keys) {
      const property = Object.getOwnPropertyDescriptor(value, key);
      if (
        typeof key !== "string" ||
        key.length > MAX_SNAPSHOT_KEY_LENGTH ||
        property?.enumerable !== true ||
        !Object.hasOwn(property, "value")
      ) {
        snapshotFailure();
      }
      const propertyValue = snapshotValue(
        property.value,
        state,
        depth + 1,
      );
      Object.defineProperty(snapshot, key, {
        configurable: true,
        enumerable: true,
        value: propertyValue,
        writable: true,
      });
    }
    return Object.freeze(snapshot);
  } catch (error) {
    if (error instanceof SnapshotFailure) {
      throw error;
    }
    snapshotFailure();
  } finally {
    state.ancestors.delete(value);
  }
}

function snapshot(value) {
  try {
    return snapshotValue(
      value,
      {
        ancestors: new Set(),
        remainingObjects: MAX_SNAPSHOT_OBJECTS,
        remainingProperties: MAX_SNAPSHOT_PROPERTIES,
      },
      1,
    );
  } catch {
    invalid();
  }
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object") {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasExactKeys(value, expectedKeys) {
  if (!isPlainObject(value)) {
    return false;
  }
  const keys = Reflect.ownKeys(value);
  return (
    keys.length === expectedKeys.length &&
    keys.every(
      (key) =>
        typeof key === "string" &&
        expectedKeys.includes(key),
    )
  );
}

function assertExactKeys(value, expectedKeys) {
  if (!hasExactKeys(value, expectedKeys)) {
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
}

function assertNullableSha256(value) {
  if (value !== null) {
    assertSha256(value);
  }
}

function assertRole(value) {
  if (!ROLES.includes(value)) {
    invalid();
  }
}

function assertSubjectRun(value) {
  if (!SUBJECT_RUNS.includes(value)) {
    invalid();
  }
}

function assertReleaseId(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > MAX_CANONICAL_STRING_LENGTH ||
    !PRINTABLE_ASCII_PATTERN.test(value) ||
    value.trim() !== value
  ) {
    invalid();
  }
}

function assertBodyFields(event) {
  assertNullableSha256(event.artifactDigest);
  if (
    typeof event.kind !== "string" ||
    event.kind.length > MAX_KIND_LENGTH ||
    !KIND_PATTERN.test(event.kind) ||
    event.paymentMoved !== false
  ) {
    invalid();
  }
  assertNullableSha256(event.previousEventDigest);
  assertReleaseId(event.releaseId);
  if (
    typeof event.repositorySha !== "string" ||
    !REPOSITORY_SHA_PATTERN.test(event.repositorySha)
  ) {
    invalid();
  }
  assertRole(event.role);
  if (
    event.schema !== COORDINATION_ENVELOPE_SCHEMA ||
    typeof event.sequence !== "string" ||
    event.sequence.length > MAX_CANONICAL_STRING_LENGTH ||
    !SEQUENCE_PATTERN.test(event.sequence) ||
    typeof event.sessionId !== "string" ||
    !UUID_PATTERN.test(event.sessionId)
  ) {
    invalid();
  }
  assertSubjectRun(event.subjectRun);
}

function decodeCanonicalBase64(
  value,
  encodedLength,
  decodedLength,
) {
  if (
    typeof value !== "string" ||
    value.length !== encodedLength ||
    !BASE64_PATTERN.test(value)
  ) {
    invalid();
  }
  let bytes;
  try {
    bytes = Buffer.from(value, "base64");
  } catch {
    invalid();
  }
  if (
    bytes.length !== decodedLength ||
    bytes.toString("base64") !== value
  ) {
    invalid();
  }
  return bytes;
}

function decodePublicKey(value) {
  const raw = decodeCanonicalBase64(
    value,
    RAW_PUBLIC_KEY_BASE64_LENGTH,
    32,
  );
  try {
    const key = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
      format: "der",
      type: "spki",
    });
    if (key.asymmetricKeyType !== "ed25519") {
      invalid();
    }
    return { key, raw };
  } catch {
    invalid();
  }
}

function decodeSignature(value) {
  return decodeCanonicalBase64(
    value,
    SIGNATURE_BASE64_LENGTH,
    64,
  );
}

function assertSignatureFields(signature) {
  assertExactKeys(signature, SIGNATURE_KEYS);
  if (
    signature.algorithm !== "ed25519" ||
    typeof signature.keyId !== "string" ||
    !KEY_ID_PATTERN.test(signature.keyId)
  ) {
    invalid();
  }
  decodePublicKey(signature.publicKey);
  decodeSignature(signature.value);
}

function assertEnvelopeFields(envelope) {
  assertExactKeys(envelope, ENVELOPE_KEYS);
  assertBodyFields(envelope);
  assertSha256(envelope.eventDigest);
  assertSignatureFields(envelope.signature);
}

function eventBody(event) {
  return Object.freeze({
    artifactDigest: event.artifactDigest,
    kind: event.kind,
    paymentMoved: event.paymentMoved,
    previousEventDigest: event.previousEventDigest,
    releaseId: event.releaseId,
    repositorySha: event.repositorySha,
    role: event.role,
    schema: event.schema,
    sequence: event.sequence,
    sessionId: event.sessionId,
    subjectRun: event.subjectRun,
  });
}

function digestBody(body) {
  return createHash("sha256")
    .update(canonicalBytes(body))
    .digest("hex");
}

function canonicalSignature(signature) {
  return Object.freeze({
    algorithm: signature.algorithm,
    keyId: signature.keyId,
    publicKey: signature.publicKey,
    value: signature.value,
  });
}

function canonicalEnvelope(envelope) {
  return Object.freeze({
    artifactDigest: envelope.artifactDigest,
    eventDigest: envelope.eventDigest,
    kind: envelope.kind,
    paymentMoved: envelope.paymentMoved,
    previousEventDigest: envelope.previousEventDigest,
    releaseId: envelope.releaseId,
    repositorySha: envelope.repositorySha,
    role: envelope.role,
    schema: envelope.schema,
    sequence: envelope.sequence,
    sessionId: envelope.sessionId,
    signature: canonicalSignature(envelope.signature),
    subjectRun: envelope.subjectRun,
  });
}

function assertEnvelopeSize(envelope) {
  if (
    canonicalBytes(envelope).length >
    MAX_COORDINATION_ENVELOPE_BYTES
  ) {
    invalid();
  }
}

function privateEd25519Key(privateKeyPem) {
  if (
    typeof privateKeyPem !== "string" ||
    privateKeyPem.length === 0 ||
    Buffer.byteLength(privateKeyPem, "utf8") >
      MAX_PRIVATE_KEY_PEM_BYTES
  ) {
    invalid();
  }
  try {
    const key = createPrivateKey(privateKeyPem);
    if (
      key.asymmetricKeyType !== "ed25519" ||
      key.export({
        format: "pem",
        type: "pkcs8",
      }) !== privateKeyPem
    ) {
      invalid();
    }
    return key;
  } catch {
    invalid();
  }
}

function rawPublicKeyFromPrivateKey(privateKey) {
  try {
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
    return der.subarray(ED25519_SPKI_PREFIX.length);
  } catch {
    invalid();
  }
}

function signatureBytes(digest, privateKey) {
  try {
    return sign(
      null,
      signaturePreimageValue(digest),
      privateKey,
    ).toString("base64");
  } catch {
    invalid();
  }
}

function signaturePreimageValue(digest) {
  assertSha256(digest);
  return Buffer.concat([
    Buffer.from(COORDINATION_SIGNATURE_DOMAIN, "ascii"),
    Buffer.from(digest, "ascii"),
  ]);
}

function validateCreateInput(input) {
  assertExactKeys(input, CREATE_KEYS);
  assertBodyFields({
    artifactDigest: input.artifactDigest,
    kind: input.kind,
    paymentMoved: input.paymentMoved,
    previousEventDigest: input.previousEventDigest,
    releaseId: input.releaseId,
    repositorySha: input.repositorySha,
    role: input.role,
    schema: input.schema,
    sequence: input.sequence,
    sessionId: input.sessionId,
    subjectRun: input.subjectRun,
  });
  if (
    typeof input.publicKeyId !== "string" ||
    !KEY_ID_PATTERN.test(input.publicKeyId)
  ) {
    invalid();
  }
  decodePublicKey(input.publicKey);
}

function expectedKeys(expected) {
  if (
    isPlainObject(expected) &&
    Object.hasOwn(expected, "expectedSubjectRun")
  ) {
    return EXPECTED_KEYS_WITH_SUBJECT_RUN;
  }
  return EXPECTED_KEYS;
}

function validateExpected(expected) {
  assertExactKeys(expected, expectedKeys(expected));
  decodePublicKey(expected.expectedPublicKey);
  assertReleaseId(expected.expectedReleaseId);
  if (
    typeof expected.expectedRepositorySha !== "string" ||
    !REPOSITORY_SHA_PATTERN.test(
      expected.expectedRepositorySha,
    ) ||
    typeof expected.expectedSessionId !== "string" ||
    !UUID_PATTERN.test(expected.expectedSessionId)
  ) {
    invalid();
  }
  assertRole(expected.expectedRole);
  if (Object.hasOwn(expected, "expectedSubjectRun")) {
    assertSubjectRun(expected.expectedSubjectRun);
  }
}

function assertExpectedContext(envelope, expected) {
  if (
    envelope.signature.publicKey !==
      expected.expectedPublicKey ||
    envelope.releaseId !== expected.expectedReleaseId ||
    envelope.repositorySha !==
      expected.expectedRepositorySha ||
    envelope.role !== expected.expectedRole ||
    envelope.sessionId !== expected.expectedSessionId ||
    (Object.hasOwn(expected, "expectedSubjectRun") &&
      envelope.subjectRun !== expected.expectedSubjectRun)
  ) {
    invalid();
  }
}

function guarded(action) {
  try {
    return action();
  } catch {
    invalid();
  }
}

export function eventDigest(envelope) {
  return guarded(() => {
    const envelopeSnapshot = snapshot(envelope);
    assertEnvelopeFields(envelopeSnapshot);
    return digestBody(eventBody(envelopeSnapshot));
  });
}

export function signaturePreimage(digest) {
  return guarded(() => signaturePreimageValue(digest));
}

export function createCoordinationEnvelope(input) {
  return guarded(() => {
    const inputSnapshot = snapshot(input);
    validateCreateInput(inputSnapshot);

    const privateKey = privateEd25519Key(
      inputSnapshot.privateKeyPem,
    );
    const suppliedPublicKey = decodePublicKey(
      inputSnapshot.publicKey,
    ).raw;
    const derivedPublicKey =
      rawPublicKeyFromPrivateKey(privateKey);
    if (
      suppliedPublicKey.length !== derivedPublicKey.length ||
      !timingSafeEqual(suppliedPublicKey, derivedPublicKey)
    ) {
      invalid();
    }

    const body = eventBody({
      artifactDigest: inputSnapshot.artifactDigest,
      kind: inputSnapshot.kind,
      paymentMoved: inputSnapshot.paymentMoved,
      previousEventDigest: inputSnapshot.previousEventDigest,
      releaseId: inputSnapshot.releaseId,
      repositorySha: inputSnapshot.repositorySha,
      role: inputSnapshot.role,
      schema: inputSnapshot.schema,
      sequence: inputSnapshot.sequence,
      sessionId: inputSnapshot.sessionId,
      subjectRun: inputSnapshot.subjectRun,
    });
    const digest = digestBody(body);
    const envelope = canonicalEnvelope({
      ...body,
      eventDigest: digest,
      signature: {
        algorithm: "ed25519",
        keyId: inputSnapshot.publicKeyId,
        publicKey: inputSnapshot.publicKey,
        value: signatureBytes(digest, privateKey),
      },
    });
    assertEnvelopeSize(envelope);
    return envelope;
  });
}

export function verifyCoordinationEnvelope(envelope, expected) {
  return guarded(() => {
    const envelopeSnapshot = snapshot(envelope);
    const expectedSnapshot = snapshot(expected);
    assertEnvelopeFields(envelopeSnapshot);
    validateExpected(expectedSnapshot);

    const canonical = canonicalEnvelope(envelopeSnapshot);
    assertEnvelopeSize(canonical);
    const digest = digestBody(eventBody(canonical));
    if (canonical.eventDigest !== digest) {
      invalid();
    }
    assertExpectedContext(canonical, expectedSnapshot);

    const signature = decodeSignature(
      canonical.signature.value,
    );
    const publicKey = decodePublicKey(
      canonical.signature.publicKey,
    ).key;
    let valid;
    try {
      valid = verify(
        null,
        signaturePreimageValue(digest),
        publicKey,
        signature,
      );
    } catch {
      invalid();
    }
    if (!valid) {
      invalid();
    }
    return canonical;
  });
}
