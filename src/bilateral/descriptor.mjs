import {
  createPrivateKey,
  createPublicKey,
  sign,
  timingSafeEqual,
  verify,
} from "node:crypto";

import {
  MAX_CANONICAL_STRING_LENGTH,
  canonicalBytes,
  digestHex,
} from "./canonical.mjs";

export const DESCRIPTOR_SCHEMA =
  "clockchain.bilateral-session-descriptor/v2";
export const BILATERAL_PROTOCOL =
  "clockchain.bilateral-authorization/v1";
export const PROTOCOL_VERSION = "1";
export const DESCRIPTOR_NAMESPACE = "cbv1";
export const DESCRIPTOR_CHAIN_ID = "11155111";
export const DESCRIPTOR_EXPIRY_SECONDS = "600";
export const DESCRIPTOR_SETTLEMENT = "not-executed";
export const REGISTRY_ADDRESS =
  "0x8004a818bfb912233c491871b3d84c89a494bd9e";
export const MAX_AMOUNT_OPTIONS = 8;
export const OPERATOR_KEY_ALGORITHM = "ed25519";

export const DESCRIPTOR_KEYS = Object.freeze([
  "amountOptions",
  "chainId",
  "expirySeconds",
  "mandateDigest",
  "namespace",
  "payee",
  "payer",
  "paymentMoved",
  "promptSha256",
  "protocol",
  "protocolVersion",
  "registry",
  "repositorySha",
  "requestDigest",
  "schema",
  "sessionId",
  "settlement",
]);
export const PARTY_KEYS = Object.freeze([
  "address",
  "agentId",
  "displayName",
  "role",
]);
export const AMOUNT_OPTION_KEYS = Object.freeze([
  "currency",
  "value",
]);
export const ENVELOPE_KEYS = Object.freeze([
  "descriptor",
  "operator",
]);
export const OPERATOR_KEYS = Object.freeze([
  "algorithm",
  "keyId",
  "publicKey",
  "signature",
]);

export const KEY_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,63}$/;

const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const AGENT_ID_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const HASH_PATTERN = /^[0-9a-f]{64}$/;
const REPOSITORY_SHA_PATTERN = /^[0-9a-f]{40}$/;
const SESSION_ID_PATTERN = /^[0-9a-f]{32}$/;
const DISPLAY_NAME_PATTERN = /^[ -~]{1,64}$/;
const CURRENCY_PATTERN = /^[A-Z]{3}$/;
const DECIMAL_PATTERN =
  /^(?:[1-9][0-9]*|(?:0|[1-9][0-9]*)\.[0-9]*[1-9])$/;
const ARRAY_INDEX_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const BASE64_PATTERN =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const ED25519_SPKI_PREFIX = Buffer.from(
  "302a300506032b6570032100",
  "hex",
);
const MAX_DECIMAL_LENGTH = MAX_CANONICAL_STRING_LENGTH;
const PAYER_REFERENCE_PREFIX =
  `eip155:${DESCRIPTOR_CHAIN_ID}:${REGISTRY_ADDRESS}:`;
const MAX_PAYER_AGENT_ID_LENGTH =
  MAX_CANONICAL_STRING_LENGTH - PAYER_REFERENCE_PREFIX.length;
const SIGNATURE_BASE64_LENGTH = 88;
const RAW_PUBLIC_KEY_BASE64_LENGTH = 44;
const MAX_SNAPSHOT_DEPTH = 32;
const MAX_SNAPSHOT_OBJECTS = 256;

export class DescriptorError extends Error {
  constructor(
    message = "Bilateral descriptor processing failed.",
    code = "DESCRIPTOR_ERROR",
  ) {
    super(message);
    this.name = new.target.name;
    this.category = "verification";
    this.code = code;
  }
}

export class DescriptorValidationError extends DescriptorError {
  constructor(
    code = "DESCRIPTOR_INVALID",
    message = "Bilateral descriptor validation failed.",
  ) {
    super(message, code);
  }
}

export class DescriptorSignatureError extends DescriptorError {
  constructor(
    code = "DESCRIPTOR_SIGNATURE",
    message = "Bilateral descriptor signature verification failed.",
  ) {
    super(message, code);
  }
}

export class OperatorKeyMismatchError extends DescriptorError {
  constructor() {
    super(
      "The descriptor operator key does not match the repository key.",
      "OPERATOR_KEY_MISMATCH",
    );
  }
}

function invalid(code) {
  throw new DescriptorValidationError(code);
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
    state.ancestors.has(value)
  ) {
    snapshotFailure();
  }

  state.remainingObjects -= 1;
  state.ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const keys = Reflect.ownKeys(value);
      const lengthProperty =
        Object.getOwnPropertyDescriptor(value, "length");
      const length = lengthProperty?.value;
      if (
        !lengthProperty ||
        lengthProperty.enumerable ||
        !Object.hasOwn(lengthProperty, "value") ||
        !Number.isSafeInteger(length) ||
        length < 0 ||
        keys.length !== length + 1 ||
        keys.some(
          (key) =>
            key !== "length" &&
            (typeof key !== "string" ||
              !ARRAY_INDEX_PATTERN.test(key) ||
              Number(key) >= length),
        )
      ) {
        snapshotFailure();
      }
      const snapshot = new Array(length);
      for (let index = 0; index < length; index += 1) {
        const property = Object.getOwnPropertyDescriptor(
          value,
          String(index),
        );
        if (
          property?.enumerable !== true ||
          !Object.hasOwn(property, "value")
        ) {
          snapshotFailure();
        }
        snapshot[index] = snapshotValue(
          property.value,
          state,
          depth + 1,
        );
      }
      return Object.freeze(snapshot);
    }

    const prototype = Object.getPrototypeOf(value);
    if (
      prototype !== Object.prototype &&
      prototype !== null
    ) {
      snapshotFailure();
    }
    const keys = Reflect.ownKeys(value);
    const snapshot =
      prototype === null ? Object.create(null) : {};
    for (const key of keys) {
      const property = Object.getOwnPropertyDescriptor(value, key);
      if (
        typeof key !== "string" ||
        property?.enumerable !== true ||
        !Object.hasOwn(property, "value")
      ) {
        snapshotFailure();
      }
      snapshot[key] = snapshotValue(
        property.value,
        state,
        depth + 1,
      );
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

function materializeSnapshot(value) {
  try {
    return snapshotValue(
      value,
      {
        ancestors: new Set(),
        remainingObjects: MAX_SNAPSHOT_OBJECTS,
      },
      1,
    );
  } catch {
    invalid("DESCRIPTOR_SNAPSHOT");
  }
}

function isPlainSnapshotObject(value) {
  if (value === null || typeof value !== "object") {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasExactEnumerableDataKeys(value, expectedKeys) {
  if (!isPlainSnapshotObject(value)) {
    return false;
  }
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== expectedKeys.length ||
    keys.some(
      (key) =>
        typeof key !== "string" ||
        !expectedKeys.includes(key),
    )
  ) {
    return false;
  }
  return keys.every((key) => {
    const property = Object.getOwnPropertyDescriptor(value, key);
    return (
      property?.enumerable === true &&
      Object.hasOwn(property, "value")
    );
  });
}

function validateParty(party, expectedRole) {
  if (!hasExactEnumerableDataKeys(party, PARTY_KEYS)) {
    invalid("DESCRIPTOR_PARTY");
  }
  const maxAgentIdLength =
    expectedRole === "payer"
      ? MAX_PAYER_AGENT_ID_LENGTH
      : MAX_DECIMAL_LENGTH;
  if (
    typeof party.address !== "string" ||
    !ADDRESS_PATTERN.test(party.address) ||
    typeof party.agentId !== "string" ||
    party.agentId.length > maxAgentIdLength ||
    !AGENT_ID_PATTERN.test(party.agentId) ||
    typeof party.displayName !== "string" ||
    !DISPLAY_NAME_PATTERN.test(party.displayName) ||
    party.displayName.trim() !== party.displayName ||
    party.role !== expectedRole
  ) {
    invalid("DESCRIPTOR_PARTY");
  }
}

function compareAmountOptions(left, right) {
  if (left.currency !== right.currency) {
    return left.currency < right.currency ? -1 : 1;
  }
  if (left.value === right.value) {
    return 0;
  }
  return left.value < right.value ? -1 : 1;
}

function isDenseIndexOnlyDataArray(value) {
  if (!Array.isArray(value)) {
    return false;
  }
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== value.length + 1 ||
    keys.some(
      (key) =>
        key !== "length" &&
        (typeof key !== "string" ||
          !ARRAY_INDEX_PATTERN.test(key) ||
          Number(key) >= value.length),
    )
  ) {
    return false;
  }
  for (let index = 0; index < value.length; index += 1) {
    const property = Object.getOwnPropertyDescriptor(
      value,
      String(index),
    );
    if (
      property?.enumerable !== true ||
      !Object.hasOwn(property, "value")
    ) {
      return false;
    }
  }
  return true;
}

function validateAmountOptions(amountOptions) {
  if (
    !isDenseIndexOnlyDataArray(amountOptions) ||
    amountOptions.length === 0 ||
    amountOptions.length > MAX_AMOUNT_OPTIONS
  ) {
    invalid("DESCRIPTOR_AMOUNT_OPTIONS");
  }

  for (let index = 0; index < amountOptions.length; index += 1) {
    const option = amountOptions[index];
    if (
      !hasExactEnumerableDataKeys(option, AMOUNT_OPTION_KEYS) ||
      typeof option.currency !== "string" ||
      !CURRENCY_PATTERN.test(option.currency) ||
      typeof option.value !== "string" ||
      option.value.length === 0 ||
      option.value.length > MAX_DECIMAL_LENGTH ||
      !DECIMAL_PATTERN.test(option.value)
    ) {
      invalid("DESCRIPTOR_AMOUNT_OPTIONS");
    }
    if (
      index > 0 &&
      compareAmountOptions(amountOptions[index - 1], option) >= 0
    ) {
      invalid("DESCRIPTOR_AMOUNT_OPTIONS");
    }
  }
}

function validateDescriptorSnapshot(descriptor) {
  if (!hasExactEnumerableDataKeys(descriptor, DESCRIPTOR_KEYS)) {
    invalid("DESCRIPTOR_SHAPE");
  }

  if (
    descriptor.chainId !== DESCRIPTOR_CHAIN_ID ||
    descriptor.expirySeconds !== DESCRIPTOR_EXPIRY_SECONDS ||
    descriptor.namespace !== DESCRIPTOR_NAMESPACE ||
    typeof descriptor.mandateDigest !== "string" ||
    !HASH_PATTERN.test(descriptor.mandateDigest) ||
    descriptor.paymentMoved !== false ||
    descriptor.protocol !== BILATERAL_PROTOCOL ||
    descriptor.protocolVersion !== PROTOCOL_VERSION ||
    descriptor.registry !== REGISTRY_ADDRESS ||
    descriptor.schema !== DESCRIPTOR_SCHEMA ||
    descriptor.settlement !== DESCRIPTOR_SETTLEMENT ||
    typeof descriptor.repositorySha !== "string" ||
    !REPOSITORY_SHA_PATTERN.test(descriptor.repositorySha) ||
    typeof descriptor.requestDigest !== "string" ||
    !HASH_PATTERN.test(descriptor.requestDigest) ||
    typeof descriptor.promptSha256 !== "string" ||
    !HASH_PATTERN.test(descriptor.promptSha256) ||
    typeof descriptor.sessionId !== "string" ||
    !SESSION_ID_PATTERN.test(descriptor.sessionId)
  ) {
    invalid("DESCRIPTOR_FIELD");
  }

  validateParty(descriptor.payer, "payer");
  validateParty(descriptor.payee, "payee");
  if (
    descriptor.payer.address === descriptor.payee.address ||
    descriptor.payer.agentId === descriptor.payee.agentId
  ) {
    invalid("DESCRIPTOR_PARTY");
  }
  validateAmountOptions(descriptor.amountOptions);
}

function validatedDescriptorSnapshot(descriptor) {
  const snapshot = materializeSnapshot(descriptor);
  validateDescriptorSnapshot(snapshot);
  return snapshot;
}

export function validateDescriptor(descriptor) {
  validatedDescriptorSnapshot(descriptor);
}

export function dSession(descriptor) {
  return digestHex(validatedDescriptorSnapshot(descriptor));
}

function privateEd25519Key(privateKeyPem) {
  try {
    if (
      typeof privateKeyPem !== "string" ||
      privateKeyPem.length === 0
    ) {
      throw new Error();
    }
    const key = createPrivateKey(privateKeyPem);
    if (key.asymmetricKeyType !== "ed25519") {
      throw new Error();
    }
    return key;
  } catch {
    throw new DescriptorSignatureError("OPERATOR_PRIVATE_KEY");
  }
}

function publicEd25519Key(publicKeyPem) {
  try {
    if (
      typeof publicKeyPem !== "string" ||
      publicKeyPem.length === 0
    ) {
      throw new Error();
    }
    const key = createPublicKey(publicKeyPem);
    if (key.asymmetricKeyType !== "ed25519") {
      throw new Error();
    }
    const canonicalPublicKeyPem = key.export({
      format: "pem",
      type: "spki",
    });
    if (canonicalPublicKeyPem !== publicKeyPem) {
      throw new Error();
    }
    return key;
  } catch {
    throw new DescriptorSignatureError("OPERATOR_PUBLIC_KEY");
  }
}

function decodeSignature(signature) {
  if (
    typeof signature !== "string" ||
    signature.length !== SIGNATURE_BASE64_LENGTH
  ) {
    throw new DescriptorSignatureError("DESCRIPTOR_SIGNATURE_ENCODING");
  }

  let bytes;
  if (BASE64_PATTERN.test(signature)) {
    bytes = Buffer.from(signature, "base64");
    if (bytes.toString("base64") !== signature) {
      throw new DescriptorSignatureError(
        "DESCRIPTOR_SIGNATURE_ENCODING",
      );
    }
  } else {
    throw new DescriptorSignatureError(
      "DESCRIPTOR_SIGNATURE_ENCODING",
    );
  }
  if (bytes.length !== 64) {
    throw new DescriptorSignatureError(
      "DESCRIPTOR_SIGNATURE_ENCODING",
    );
  }
  return bytes;
}

function signDescriptorSnapshot(descriptor, key) {
  try {
    return sign(null, canonicalBytes(descriptor), key).toString(
      "base64",
    );
  } catch {
    throw new DescriptorSignatureError("DESCRIPTOR_SIGNING");
  }
}

export function signDescriptor(descriptor, privateKeyPem) {
  const snapshot = validatedDescriptorSnapshot(descriptor);
  return signDescriptorSnapshot(
    snapshot,
    privateEd25519Key(privateKeyPem),
  );
}

function verifyDescriptorSnapshotSignature(
  descriptor,
  signature,
  publicKeyPem,
) {
  const signatureBytes = decodeSignature(signature);
  const key = publicEd25519Key(publicKeyPem);
  let valid;
  try {
    valid = verify(
      null,
      canonicalBytes(descriptor),
      key,
      signatureBytes,
    );
  } catch {
    throw new DescriptorSignatureError();
  }
  if (!valid) {
    throw new DescriptorSignatureError();
  }
}

export function verifyDescriptorSignature(
  descriptor,
  signature,
  publicKeyPem,
) {
  verifyDescriptorSnapshotSignature(
    validatedDescriptorSnapshot(descriptor),
    signature,
    publicKeyPem,
  );
}

function decodeRawPublicKey(rawPublicKeyBase64) {
  if (
    typeof rawPublicKeyBase64 !== "string" ||
    rawPublicKeyBase64.length !== RAW_PUBLIC_KEY_BASE64_LENGTH ||
    !BASE64_PATTERN.test(rawPublicKeyBase64)
  ) {
    throw new DescriptorError(
      "The operator public key encoding is invalid.",
      "OPERATOR_PUBLIC_KEY",
    );
  }
  const raw = Buffer.from(rawPublicKeyBase64, "base64");
  if (
    raw.length !== 32 ||
    raw.toString("base64") !== rawPublicKeyBase64
  ) {
    throw new DescriptorError(
      "The operator public key encoding is invalid.",
      "OPERATOR_PUBLIC_KEY",
    );
  }
  return raw;
}

export function publicKeyPemFromRawBase64(rawPublicKeyBase64) {
  const raw = decodeRawPublicKey(rawPublicKeyBase64);
  try {
    return createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
      format: "der",
      type: "spki",
    }).export({ format: "pem", type: "spki" });
  } catch {
    throw new DescriptorError(
      "The operator public key encoding is invalid.",
      "OPERATOR_PUBLIC_KEY",
    );
  }
}

export function rawPublicKeyBase64FromPem(publicKeyPem) {
  let key;
  try {
    key = publicEd25519Key(publicKeyPem);
  } catch {
    throw new DescriptorError(
      "The operator public key is invalid.",
      "OPERATOR_PUBLIC_KEY",
    );
  }
  const der = key.export({ format: "der", type: "spki" });
  if (
    der.length !== ED25519_SPKI_PREFIX.length + 32 ||
    !der.subarray(0, ED25519_SPKI_PREFIX.length).equals(
      ED25519_SPKI_PREFIX,
    )
  ) {
    throw new DescriptorError(
      "The operator public key is invalid.",
      "OPERATOR_PUBLIC_KEY",
    );
  }
  return der.subarray(ED25519_SPKI_PREFIX.length).toString("base64");
}

function validateKeyId(keyId) {
  if (
    typeof keyId !== "string" ||
    !KEY_ID_PATTERN.test(keyId)
  ) {
    invalid("OPERATOR_KEY_ID");
  }
}

export function operatorPublicKeyPath(keyId) {
  validateKeyId(keyId);
  return `docs/operator-keys/${keyId}.pub`;
}

export function createSignedEnvelope(
  descriptor,
  { keyId, privateKeyPem } = {},
) {
  validateKeyId(keyId);
  const descriptorSnapshot =
    validatedDescriptorSnapshot(descriptor);
  const privateKey = privateEd25519Key(privateKeyPem);
  let publicKeyPem;
  try {
    publicKeyPem = createPublicKey(privateKey).export({
      format: "pem",
      type: "spki",
    });
  } catch {
    throw new DescriptorSignatureError("OPERATOR_PRIVATE_KEY");
  }
  const operator = Object.freeze({
      algorithm: OPERATOR_KEY_ALGORITHM,
      keyId,
      publicKey: rawPublicKeyBase64FromPem(publicKeyPem),
      signature: signDescriptorSnapshot(
        descriptorSnapshot,
        privateKey,
      ),
  });
  return Object.freeze({
    descriptor: descriptorSnapshot,
    operator,
  });
}

function validateEnvelopeSnapshot(envelope) {
  if (!hasExactEnumerableDataKeys(envelope, ENVELOPE_KEYS)) {
    invalid("DESCRIPTOR_ENVELOPE");
  }
  if (
    !hasExactEnumerableDataKeys(envelope.operator, OPERATOR_KEYS) ||
    envelope.operator.algorithm !== OPERATOR_KEY_ALGORITHM
  ) {
    invalid("DESCRIPTOR_OPERATOR");
  }
  validateKeyId(envelope.operator.keyId);
  validateDescriptorSnapshot(envelope.descriptor);
}

export function verifyDescriptorEnvelope(
  envelope,
  { repositoryPublicKey } = {},
) {
  const envelopeSnapshot = materializeSnapshot(envelope);
  validateEnvelopeSnapshot(envelopeSnapshot);
  const repositoryRaw = decodeRawPublicKey(repositoryPublicKey);
  const shippedRaw = decodeRawPublicKey(
    envelopeSnapshot.operator.publicKey,
  );
  if (
    repositoryRaw.length !== shippedRaw.length ||
    !timingSafeEqual(repositoryRaw, shippedRaw)
  ) {
    throw new OperatorKeyMismatchError();
  }
  verifyDescriptorSnapshotSignature(
    envelopeSnapshot.descriptor,
    envelopeSnapshot.operator.signature,
    publicKeyPemFromRawBase64(repositoryPublicKey),
  );
  return Object.freeze({
    dSession: digestHex(envelopeSnapshot.descriptor),
  });
}
