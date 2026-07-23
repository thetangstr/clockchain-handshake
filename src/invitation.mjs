import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scrypt as scryptCallback,
} from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { open } from "node:fs/promises";
import { promisify } from "node:util";

import { INVITATION_SCHEMA } from "./constants.mjs";

const scrypt = promisify(scryptCallback);

const INVITATION_VERSION = 1;
const MAX_DISPLAY_NAME_LENGTH = 128;
const MAX_CODE_BYTES = 1_024;
const MAX_CIPHERTEXT_BYTES = 4_096;
const MAX_SECRET_FILE_BYTES = 16_384;
const SECRET_FILE_OPEN_FLAGS =
  fsConstants.O_RDONLY |
  (fsConstants.O_NOFOLLOW ?? 0) |
  (fsConstants.O_NONBLOCK ?? 0);
const KDF = Object.freeze({
  name: "scrypt",
  N: 16_384,
  r: 8,
  p: 1,
  keyLength: 32,
});
const CIPHER = Object.freeze({
  name: "aes-256-gcm",
  ivLength: 12,
  tagLength: 16,
});
const ENCODING = "hex";
const BUNDLE_KEYS = Object.freeze([
  "schema",
  "version",
  "address",
  "displayName",
  "crypto",
]);
const CRYPTO_KEYS = Object.freeze([
  "kdf",
  "cipher",
  "encoding",
  "salt",
  "iv",
  "ciphertext",
  "tag",
]);
const KDF_KEYS = Object.freeze(["name", "N", "r", "p", "keyLength"]);
const CIPHER_KEYS = Object.freeze([
  "name",
  "ivLength",
  "tagLength",
]);
const PAYLOAD_KEYS = Object.freeze(["privateKey", "address", "displayName"]);
const SECRET_FILE_KEYS = Object.freeze(["bundle", "code"]);

class SecretInvitationFileError extends Error {
  constructor(message) {
    super(message);
    this.name = "SecretInvitationFileError";
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
    expectedKeys.every((key) => keys.includes(key))
  );
}

function isAddress(value) {
  return typeof value === "string" && /^0x[0-9a-fA-F]{40}$/.test(value);
}

function isPrivateKey(value) {
  return typeof value === "string" && /^0x[0-9a-fA-F]{64}$/.test(value);
}

function isDisplayName(value) {
  return (
    typeof value === "string" &&
    value.trim().length > 0 &&
    value.length <= MAX_DISPLAY_NAME_LENGTH
  );
}

function isCanonicalHex(value, byteLength) {
  return (
    typeof value === "string" &&
    value.length === byteLength * 2 &&
    /^[0-9a-f]+$/.test(value)
  );
}

function isCanonicalCiphertext(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= MAX_CIPHERTEXT_BYTES * 2 &&
    value.length % 2 === 0 &&
    /^[0-9a-f]+$/.test(value)
  );
}

function validateCode(code) {
  if (typeof code !== "string" || code.trim().length === 0) {
    throw new Error("Invitation code is invalid.");
  }

  if (Buffer.byteLength(code, "utf8") > MAX_CODE_BYTES) {
    throw new Error("Invitation code is too large.");
  }
}

function validatePayload(payload) {
  if (
    !hasExactKeys(payload, PAYLOAD_KEYS) ||
    !isPrivateKey(payload.privateKey) ||
    !isAddress(payload.address) ||
    !isDisplayName(payload.displayName)
  ) {
    throw new Error("Invitation payload is invalid.");
  }

  return {
    privateKey: payload.privateKey,
    address: payload.address,
    displayName: payload.displayName,
  };
}

function hasSupportedKdf(kdf) {
  return (
    hasExactKeys(kdf, KDF_KEYS) &&
    kdf.name === KDF.name &&
    kdf.N === KDF.N &&
    kdf.r === KDF.r &&
    kdf.p === KDF.p &&
    kdf.keyLength === KDF.keyLength
  );
}

function hasSupportedCipher(cipher) {
  return (
    hasExactKeys(cipher, CIPHER_KEYS) &&
    cipher.name === CIPHER.name &&
    cipher.ivLength === CIPHER.ivLength &&
    cipher.tagLength === CIPHER.tagLength
  );
}

function validateBundle(bundle) {
  const crypto = bundle?.crypto;

  if (
    !hasExactKeys(bundle, BUNDLE_KEYS) ||
    bundle.schema !== INVITATION_SCHEMA ||
    bundle.version !== INVITATION_VERSION ||
    !isAddress(bundle.address) ||
    !isDisplayName(bundle.displayName) ||
    !hasExactKeys(crypto, CRYPTO_KEYS) ||
    !hasSupportedKdf(crypto.kdf) ||
    !hasSupportedCipher(crypto.cipher) ||
    crypto.encoding !== ENCODING ||
    !isCanonicalHex(crypto.salt, 32) ||
    !isCanonicalHex(crypto.iv, CIPHER.ivLength) ||
    !isCanonicalCiphertext(crypto.ciphertext) ||
    !isCanonicalHex(crypto.tag, CIPHER.tagLength)
  ) {
    throw new Error("Invitation bundle is invalid or unsupported.");
  }

  return bundle;
}

function createPublicHeader(bundle) {
  return {
    schema: bundle.schema,
    version: bundle.version,
    address: bundle.address,
    displayName: bundle.displayName,
    crypto: {
      kdf: {
        name: bundle.crypto.kdf.name,
        N: bundle.crypto.kdf.N,
        r: bundle.crypto.kdf.r,
        p: bundle.crypto.kdf.p,
        keyLength: bundle.crypto.kdf.keyLength,
      },
      cipher: {
        name: bundle.crypto.cipher.name,
        ivLength: bundle.crypto.cipher.ivLength,
        tagLength: bundle.crypto.cipher.tagLength,
      },
      encoding: bundle.crypto.encoding,
      salt: bundle.crypto.salt,
      iv: bundle.crypto.iv,
    },
  };
}

function encodeAad(bundle) {
  return Buffer.from(JSON.stringify(createPublicHeader(bundle)), "utf8");
}

async function deriveKey(code, salt) {
  return scrypt(code, salt, KDF.keyLength, {
    N: KDF.N,
    r: KDF.r,
    p: KDF.p,
  });
}

export async function encryptInvitation(payload, code) {
  validateCode(code);
  const validatedPayload = validatePayload(payload);
  const salt = randomBytes(32);
  const iv = randomBytes(CIPHER.ivLength);
  const bundle = {
    schema: INVITATION_SCHEMA,
    version: INVITATION_VERSION,
    address: validatedPayload.address,
    displayName: validatedPayload.displayName,
    crypto: {
      kdf: { ...KDF },
      cipher: { ...CIPHER },
      encoding: ENCODING,
      salt: salt.toString(ENCODING),
      iv: iv.toString(ENCODING),
      ciphertext: "",
      tag: "",
    },
  };
  const plaintext = Buffer.from(JSON.stringify(validatedPayload), "utf8");
  let key;

  try {
    key = await deriveKey(code, salt);
    const cipher = createCipheriv(CIPHER.name, key, iv, {
      authTagLength: CIPHER.tagLength,
    });
    cipher.setAAD(encodeAad(bundle));
    const ciphertext = Buffer.concat([
      cipher.update(plaintext),
      cipher.final(),
    ]);

    bundle.crypto.ciphertext = ciphertext.toString(ENCODING);
    bundle.crypto.tag = cipher.getAuthTag().toString(ENCODING);
    return bundle;
  } finally {
    key?.fill(0);
    plaintext.fill(0);
  }
}

export async function decryptInvitation(bundle, code) {
  validateCode(code);
  const validatedBundle = validateBundle(bundle);
  const salt = Buffer.from(validatedBundle.crypto.salt, ENCODING);
  const iv = Buffer.from(validatedBundle.crypto.iv, ENCODING);
  const ciphertext = Buffer.from(
    validatedBundle.crypto.ciphertext,
    ENCODING,
  );
  const tag = Buffer.from(validatedBundle.crypto.tag, ENCODING);
  let key;
  let plaintext;

  try {
    key = await deriveKey(code, salt);

    try {
      const decipher = createDecipheriv(CIPHER.name, key, iv, {
        authTagLength: CIPHER.tagLength,
      });
      decipher.setAAD(encodeAad(validatedBundle));
      decipher.setAuthTag(tag);
      plaintext = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final(),
      ]);
    } catch {
      throw new Error("Invitation authentication failed.");
    }

    let payload;

    try {
      payload = validatePayload(JSON.parse(plaintext.toString("utf8")));
    } catch {
      throw new Error("Decrypted invitation payload is invalid.");
    }

    if (
      payload.address !== validatedBundle.address ||
      payload.displayName !== validatedBundle.displayName
    ) {
      throw new Error(
        "Decrypted invitation payload does not match its public header.",
      );
    }

    return payload;
  } finally {
    key?.fill(0);
    plaintext?.fill(0);
  }
}

function sameFile(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.mode === right.mode
  );
}

function safeFileError(error) {
  if (error instanceof SecretInvitationFileError) {
    return error;
  }

  if (error?.code === "ELOOP") {
    return new SecretInvitationFileError(
      "Secret invitation must be a regular file.",
    );
  }

  return new SecretInvitationFileError(
    "Unable to read secret invitation file.",
  );
}

export async function readSecretInvitation(path) {
  let fileHandle;
  let failure;
  let result;

  try {
    fileHandle = await open(path, SECRET_FILE_OPEN_FLAGS);
    const fileMetadata = await fileHandle.stat();

    if (!fileMetadata.isFile()) {
      throw new SecretInvitationFileError(
        "Secret invitation must be a regular file.",
      );
    }

    if (
      process.platform !== "win32" &&
      (fileMetadata.mode & 0o077) !== 0
    ) {
      throw new SecretInvitationFileError(
        "Secret invitation file permissions must deny group and world access.",
      );
    }

    if (fileMetadata.size > MAX_SECRET_FILE_BYTES) {
      throw new SecretInvitationFileError(
        "Secret invitation file is too large.",
      );
    }

    const serialized = await fileHandle.readFile("utf8");
    const finalMetadata = await fileHandle.stat();

    if (
      !finalMetadata.isFile() ||
      !sameFile(fileMetadata, finalMetadata)
    ) {
      throw new SecretInvitationFileError(
        "Secret invitation file changed while it was being read.",
      );
    }

    if (Buffer.byteLength(serialized, "utf8") > MAX_SECRET_FILE_BYTES) {
      throw new SecretInvitationFileError(
        "Secret invitation file is too large.",
      );
    }

    let invitation;

    try {
      invitation = JSON.parse(serialized);
    } catch {
      throw new SecretInvitationFileError(
        "Secret invitation file is invalid.",
      );
    }

    if (!hasExactKeys(invitation, SECRET_FILE_KEYS)) {
      throw new SecretInvitationFileError(
        "Secret invitation file is invalid.",
      );
    }

    try {
      validateBundle(invitation.bundle);
      validateCode(invitation.code);
    } catch {
      throw new SecretInvitationFileError(
        "Secret invitation file is invalid.",
      );
    }

    result = {
      bundle: invitation.bundle,
      code: invitation.code,
    };
  } catch (error) {
    failure = safeFileError(error);
  } finally {
    if (fileHandle !== undefined) {
      try {
        await fileHandle.close();
      } catch {
        failure ??= new SecretInvitationFileError(
          "Unable to close secret invitation file.",
        );
      }
    }
  }

  if (failure !== undefined) {
    throw failure;
  }

  return result;
}
