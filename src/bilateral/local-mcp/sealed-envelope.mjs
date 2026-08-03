import {
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes as secureRandomBytes,
} from "node:crypto";
import { types } from "node:util";

export const SEALED_ENVELOPE_ALGORITHM =
  "X25519-HKDF-SHA256-AES-256-GCM";

const ENVELOPE_KEYS = Object.freeze([
  "algorithm",
  "ciphertextBase64url",
  "ephemeralPublicKey",
  "ivBase64url",
  "paymentMoved",
  "schema",
  "tagBase64url",
]);
const PRIVATE_KEY_KEYS = Object.freeze([
  "format",
  "value",
]);
const SEAL_INPUT_KEYS = Object.freeze([
  "aadBytes",
  "plaintextBytes",
  "recipientPublicKey",
  "schema",
]);
const OPEN_INPUT_KEYS = Object.freeze([
  "aadBytes",
  "envelope",
  "expectedSchema",
  "recipientPrivateKey",
]);
const SEAL_DEPENDENCY_KEYS = Object.freeze([
  "generateKeyPair",
  "observeDerivedSecrets",
  "randomBytes",
]);
const OPEN_DEPENDENCY_KEYS = Object.freeze([
  "observeDerivedSecrets",
]);
const PRIVATE_KEY_FORMAT = "pkcs8-der-base64url";
const PUBLIC_KEY_DER_PREFIX = Buffer.from(
  "302a300506032b656e032100",
  "hex",
);
const PRIVATE_KEY_DER_PREFIX = Buffer.from(
  "302e020100300506032b656e04220420",
  "hex",
);
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const PRINTABLE_ASCII_PATTERN = /^[ -~]+$/;
const RAW_X25519_KEY_LENGTH = 32;
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const MAX_AAD_BYTES = 131_072;
const MAX_PLAINTEXT_BYTES = 65_536;
const HKDF_SEPARATOR = Buffer.from([0]);

export class SealedEnvelopeError extends Error {
  constructor() {
    super("Sealed envelope validation failed safely.");
    this.name = "SealedEnvelopeError";
    this.code = "SEALED_ENVELOPE_INVALID";
    this.category = "verification";
  }
}

function invalid() {
  throw new SealedEnvelopeError();
}

function sanitize(error) {
  if (error instanceof SealedEnvelopeError) throw error;
  invalid();
}

function exactDataObject(value, keys) {
  try {
    if (
      value === null ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      types.isProxy(value)
    ) {
      invalid();
    }
    const prototype = Object.getPrototypeOf(value);
    if (
      prototype !== Object.prototype &&
      prototype !== null
    ) {
      invalid();
    }
    const ownKeys = Reflect.ownKeys(value);
    if (
      ownKeys.length !== keys.length ||
      ownKeys.some(
        (key) =>
          typeof key !== "string" ||
          !keys.includes(key),
      )
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

function dependencies(value, allowedKeys) {
  if (value === undefined) value = {};
  try {
    if (
      value === null ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      types.isProxy(value)
    ) {
      invalid();
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype) invalid();
    const ownKeys = Reflect.ownKeys(value);
    if (
      ownKeys.some(
        (key) =>
          typeof key !== "string" ||
          !allowedKeys.includes(key),
      )
    ) {
      invalid();
    }
    const result = Object.create(null);
    for (const key of ownKeys) {
      const descriptor =
        Object.getOwnPropertyDescriptor(value, key);
      if (
        descriptor?.enumerable !== true ||
        !Object.hasOwn(descriptor, "value") ||
        typeof descriptor.value !== "function" ||
        types.isProxy(descriptor.value)
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

function schema(value) {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 256 ||
    value.trim() !== value ||
    !PRINTABLE_ASCII_PATTERN.test(value) ||
    !value.startsWith("clockchain.") ||
    !value.endsWith("/v1")
  ) {
    invalid();
  }
  return value;
}

function bytes(value, maximum) {
  if (
    !Buffer.isBuffer(value) ||
    value.length < 1 ||
    value.length > maximum
  ) {
    invalid();
  }
  return Buffer.from(value);
}

function maxBase64urlLength(decodedLength) {
  const remainder = decodedLength % 3;
  return (
    Math.floor(decodedLength / 3) * 4 +
    (remainder === 0 ? 0 : remainder + 1)
  );
}

function exactBase64url(
  value,
  {
    decodedLength = null,
    maxDecodedLength = null,
  } = {},
) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    !BASE64URL_PATTERN.test(value) ||
    value.includes("=") ||
    (decodedLength !== null &&
      value.length !==
        maxBase64urlLength(decodedLength)) ||
    (maxDecodedLength !== null &&
      value.length >
        maxBase64urlLength(maxDecodedLength))
  ) {
    invalid();
  }
  let decoded;
  try {
    decoded = Buffer.from(value, "base64url");
  } catch {
    invalid();
  }
  if (
    decoded.length === 0 ||
    (decodedLength !== null &&
      decoded.length !== decodedLength) ||
    (maxDecodedLength !== null &&
      decoded.length > maxDecodedLength) ||
    decoded.toString("base64url") !== value
  ) {
    invalid();
  }
  return decoded;
}

function publicKeyFromRawBase64url(value) {
  const raw = exactBase64url(value, {
    decodedLength: RAW_X25519_KEY_LENGTH,
  });
  try {
    const publicKey = createPublicKey({
      key: Buffer.concat([
        PUBLIC_KEY_DER_PREFIX,
        raw,
      ]),
      format: "der",
      type: "spki",
    });
    if (publicKey.asymmetricKeyType !== "x25519") {
      invalid();
    }
    return publicKey;
  } catch (error) {
    sanitize(error);
  }
}

function privateKeyFromExport(value) {
  const wrapped = exactDataObject(
    value,
    PRIVATE_KEY_KEYS,
  );
  if (wrapped.format !== PRIVATE_KEY_FORMAT) {
    invalid();
  }
  const der = exactBase64url(wrapped.value, {
    decodedLength:
      PRIVATE_KEY_DER_PREFIX.length +
      RAW_X25519_KEY_LENGTH,
  });
  try {
    if (
      !der
        .subarray(0, PRIVATE_KEY_DER_PREFIX.length)
        .equals(PRIVATE_KEY_DER_PREFIX)
    ) {
      invalid();
    }
    const privateKey = createPrivateKey({
      key: der,
      format: "der",
      type: "pkcs8",
    });
    if (privateKey.asymmetricKeyType !== "x25519") {
      invalid();
    }
    return privateKey;
  } catch (error) {
    sanitize(error);
  } finally {
    der.fill(0);
  }
}

function rawPublicKey(value) {
  let der;
  try {
    if (value?.asymmetricKeyType !== "x25519") {
      invalid();
    }
    der = value.export({
      format: "der",
      type: "spki",
    });
    if (
      der.length !==
        PUBLIC_KEY_DER_PREFIX.length +
          RAW_X25519_KEY_LENGTH ||
      !der
        .subarray(0, PUBLIC_KEY_DER_PREFIX.length)
        .equals(PUBLIC_KEY_DER_PREFIX)
    ) {
      invalid();
    }
    return Buffer.from(
      der.subarray(PUBLIC_KEY_DER_PREFIX.length),
    );
  } catch (error) {
    sanitize(error);
  }
}

function privateKeyExport(value) {
  let der;
  try {
    if (value?.asymmetricKeyType !== "x25519") {
      invalid();
    }
    der = value.export({
      format: "der",
      type: "pkcs8",
    });
    if (
      der.length !==
        PRIVATE_KEY_DER_PREFIX.length +
          RAW_X25519_KEY_LENGTH ||
      !der
        .subarray(0, PRIVATE_KEY_DER_PREFIX.length)
        .equals(PRIVATE_KEY_DER_PREFIX)
    ) {
      invalid();
    }
    return Object.freeze({
      format: PRIVATE_KEY_FORMAT,
      value: der.toString("base64url"),
    });
  } catch (error) {
    sanitize(error);
  } finally {
    der?.fill(0);
  }
}

function keyPair(generator) {
  let pair;
  try {
    pair = generator("x25519");
  } catch {
    invalid();
  }
  if (
    pair === null ||
    typeof pair !== "object" ||
    pair.privateKey?.asymmetricKeyType !== "x25519" ||
    pair.publicKey?.asymmetricKeyType !== "x25519"
  ) {
    invalid();
  }
  const actualPublic = createPublicKey(pair.privateKey);
  if (
    !rawPublicKey(actualPublic).equals(
      rawPublicKey(pair.publicKey),
    )
  ) {
    invalid();
  }
  return Object.freeze({
    privateKey: pair.privateKey,
    publicKey: pair.publicKey,
  });
}

function envelopeSnapshot(value, expectedSchema) {
  const result = exactDataObject(
    value,
    ENVELOPE_KEYS,
  );
  if (
    result.algorithm !== SEALED_ENVELOPE_ALGORITHM ||
    result.paymentMoved !== false ||
    result.schema !== expectedSchema
  ) {
    invalid();
  }
  return Object.freeze({
    ciphertext: exactBase64url(
      result.ciphertextBase64url,
      { maxDecodedLength: MAX_PLAINTEXT_BYTES },
    ),
    ephemeralPublicKey:
      result.ephemeralPublicKey,
    ephemeralPublicKeyObject:
      publicKeyFromRawBase64url(
        result.ephemeralPublicKey,
      ),
    iv: exactBase64url(result.ivBase64url, {
      decodedLength: IV_LENGTH,
    }),
    tag: exactBase64url(result.tagBase64url, {
      decodedLength: TAG_LENGTH,
    }),
  });
}

function deriveAesKey({
  aadBytes,
  ephemeralPublicKeyBytes,
  privateKey,
  publicKey,
  schemaValue,
}) {
  let sharedSecret;
  let aesKey;
  try {
    sharedSecret = diffieHellman({
      privateKey,
      publicKey,
    });
    aesKey = Buffer.from(
      hkdfSync(
        "sha256",
        sharedSecret,
        aadBytes,
        Buffer.concat([
          Buffer.from(schemaValue, "utf8"),
          HKDF_SEPARATOR,
          aadBytes,
          HKDF_SEPARATOR,
          ephemeralPublicKeyBytes,
        ]),
        32,
      ),
    );
    return { aesKey, sharedSecret };
  } catch {
    sharedSecret?.fill(0);
    aesKey?.fill(0);
    invalid();
  }
}

function observeSecrets(observer, secrets) {
  if (observer !== undefined) {
    observer({
      aesKey: secrets.aesKey,
      sharedSecret: secrets.sharedSecret,
    });
  }
}

export function createSealedEnvelopeKeyPair() {
  try {
    const pair = keyPair(generateKeyPairSync);
    return Object.freeze({
      privateKey: privateKeyExport(pair.privateKey),
      publicKey: rawPublicKey(
        pair.publicKey,
      ).toString("base64url"),
    });
  } catch (error) {
    sanitize(error);
  }
}

export function sealEnvelope(input, dependencyInput) {
  let secrets;
  try {
    const data = exactDataObject(
      input,
      SEAL_INPUT_KEYS,
    );
    const dependencyData = dependencies(
      dependencyInput,
      SEAL_DEPENDENCY_KEYS,
    );
    const schemaValue = schema(data.schema);
    const aadBytes = bytes(
      data.aadBytes,
      MAX_AAD_BYTES,
    );
    const plaintextBytes = bytes(
      data.plaintextBytes,
      MAX_PLAINTEXT_BYTES,
    );
    const recipientPublicKey =
      publicKeyFromRawBase64url(
        data.recipientPublicKey,
      );
    const pair = keyPair(
      dependencyData.generateKeyPair ??
        generateKeyPairSync,
    );
    const ephemeralPublicKeyBytes =
      rawPublicKey(pair.publicKey);
    const random =
      dependencyData.randomBytes ??
      secureRandomBytes;
    const iv = random(IV_LENGTH);
    if (
      !Buffer.isBuffer(iv) ||
      iv.length !== IV_LENGTH
    ) {
      invalid();
    }
    secrets = deriveAesKey({
      aadBytes,
      ephemeralPublicKeyBytes,
      privateKey: pair.privateKey,
      publicKey: recipientPublicKey,
      schemaValue,
    });
    observeSecrets(
      dependencyData.observeDerivedSecrets,
      secrets,
    );
    const cipher = createCipheriv(
      "aes-256-gcm",
      secrets.aesKey,
      iv,
    );
    cipher.setAAD(aadBytes);
    const ciphertext = Buffer.concat([
      cipher.update(plaintextBytes),
      cipher.final(),
    ]);
    const tag = cipher.getAuthTag();
    return Object.freeze({
      algorithm: SEALED_ENVELOPE_ALGORITHM,
      ciphertextBase64url:
        ciphertext.toString("base64url"),
      ephemeralPublicKey:
        ephemeralPublicKeyBytes.toString(
          "base64url",
        ),
      ivBase64url: iv.toString("base64url"),
      paymentMoved: false,
      schema: schemaValue,
      tagBase64url: tag.toString("base64url"),
    });
  } catch (error) {
    sanitize(error);
  } finally {
    secrets?.sharedSecret.fill(0);
    secrets?.aesKey.fill(0);
  }
}

export function openEnvelope(input, dependencyInput) {
  let secrets;
  try {
    const data = exactDataObject(
      input,
      OPEN_INPUT_KEYS,
    );
    const dependencyData = dependencies(
      dependencyInput,
      OPEN_DEPENDENCY_KEYS,
    );
    const schemaValue = schema(
      data.expectedSchema,
    );
    const aadBytes = bytes(
      data.aadBytes,
      MAX_AAD_BYTES,
    );
    const sealed = envelopeSnapshot(
      data.envelope,
      schemaValue,
    );
    const recipientPrivateKey =
      privateKeyFromExport(
        data.recipientPrivateKey,
      );
    const ephemeralPublicKeyBytes =
      exactBase64url(
        sealed.ephemeralPublicKey,
        { decodedLength: RAW_X25519_KEY_LENGTH },
      );
    secrets = deriveAesKey({
      aadBytes,
      ephemeralPublicKeyBytes,
      privateKey: recipientPrivateKey,
      publicKey:
        sealed.ephemeralPublicKeyObject,
      schemaValue,
    });
    observeSecrets(
      dependencyData.observeDerivedSecrets,
      secrets,
    );
    const decipher = createDecipheriv(
      "aes-256-gcm",
      secrets.aesKey,
      sealed.iv,
    );
    decipher.setAAD(aadBytes);
    decipher.setAuthTag(sealed.tag);
    const plaintext = Buffer.concat([
      decipher.update(sealed.ciphertext),
      decipher.final(),
    ]);
    if (
      plaintext.length < 1 ||
      plaintext.length > MAX_PLAINTEXT_BYTES
    ) {
      invalid();
    }
    return plaintext;
  } catch (error) {
    sanitize(error);
  } finally {
    secrets?.sharedSecret.fill(0);
    secrets?.aesKey.fill(0);
  }
}
