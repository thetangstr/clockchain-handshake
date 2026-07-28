import {
  createDecipheriv,
  createHash,
  scrypt as scryptCallback,
} from "node:crypto";
import { execFile as execFileCallback } from "node:child_process";
import { constants as fsConstants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { promisify } from "node:util";

import { keccak256 } from "viem";
import { privateKeyToAccount } from "viem/accounts";

const execFileAsync = promisify(execFileCallback);
const scryptAsync = promisify(scryptCallback);

export const FUNDING_KEYCHAIN_SERVICE =
  "com.clockchain.handshake.sepolia-funding";
export const FUNDING_KEYCHAIN_ACCOUNT = "riyadh-v3";

const SEPOLIA_CHAIN_ID = 11155111;
const MAX_KEYSTORE_BYTES = 65_536;
const MAX_METADATA_BYTES = 4_096;
const READ_FLAGS =
  fsConstants.O_RDONLY |
  (fsConstants.O_NOFOLLOW ?? 0) |
  (fsConstants.O_NONBLOCK ?? 0);
const PUBLIC_METADATA_KEYS = Object.freeze([
  "schemaVersion",
  "chainId",
  "fundingAddress",
  "keystoreSha256",
  "createdAt",
]);
const KEYSTORE_KEYS = Object.freeze(["version", "id", "address", "crypto"]);
const CRYPTO_KEYS = Object.freeze([
  "ciphertext",
  "cipherparams",
  "cipher",
  "kdf",
  "kdfparams",
  "mac",
]);
const CIPHERPARAM_KEYS = Object.freeze(["iv"]);
const SCRYPT_KEYS = Object.freeze(["dklen", "salt", "n", "r", "p"]);
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/u;
const ADDRESS_NO_PREFIX_PATTERN = /^[0-9a-f]{40}$/u;
const HEX_32_PATTERN = /^[0-9a-f]{64}$/u;
const ISO_DATE_PATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

class FundingKeystoreError extends Error {
  constructor() {
    super("Bilateral funding failed safely.");
    this.name = "FundingKeystoreError";
    this.code = "BILATERAL_FUNDING_KEYSTORE_INVALID";
  }
}

function fail() {
  throw new FundingKeystoreError();
}

function sanitize(operation) {
  try {
    return operation();
  } catch (error) {
    if (error instanceof FundingKeystoreError) throw error;
    fail();
  }
}

async function sanitizeAsync(operation) {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof FundingKeystoreError) throw error;
    fail();
  }
}

function hasPrivateFileMetadata(metadata, maximum) {
  return (
    metadata?.isFile?.() === true &&
    metadata?.isSymbolicLink?.() === false &&
    metadata.nlink === 1 &&
    (metadata.mode & 0o777) === 0o600 &&
    Number.isSafeInteger(metadata.size) &&
    metadata.size >= 0 &&
    metadata.size <= maximum
  );
}

function sameFile(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

async function readPinnedFile(path, maximum, fileSystem) {
  const before = await sanitizeAsync(() => fileSystem.lstat(path));
  if (!hasPrivateFileMetadata(before, maximum)) fail();

  let handle;
  try {
    handle = await fileSystem.open(path, READ_FLAGS);
    const opened = await handle.stat();
    if (!hasPrivateFileMetadata(opened, maximum) || !sameFile(before, opened)) {
      fail();
    }

    const buffer = Buffer.alloc(before.size);
    const { bytesRead } = await handle.read(buffer, 0, before.size, 0);
    const after = await fileSystem.lstat(path);
    if (
      bytesRead !== before.size ||
      !sameFile(before, after) ||
      !sameFile(before, opened) ||
      !hasPrivateFileMetadata(after, maximum)
    ) {
      fail();
    }
    return buffer.subarray(0, bytesRead);
  } catch (error) {
    if (error instanceof FundingKeystoreError) throw error;
    fail();
  } finally {
    if (handle) await handle.close().catch(() => {});
  }
}

function parseJson(bytes) {
  return sanitize(() => JSON.parse(bytes.toString("utf8")));
}

function snapshotObject(value, keys) {
  if (value === null || typeof value !== "object") fail();
  const prototype = sanitize(() => Object.getPrototypeOf(value));
  if (prototype !== Object.prototype && prototype !== null) fail();
  const ownKeys = sanitize(() => Reflect.ownKeys(value));
  if (
    ownKeys.length !== keys.length ||
    !keys.every((key) => ownKeys.includes(key))
  ) {
    fail();
  }
  const snapshot = {};
  for (const key of keys) {
    const descriptor = sanitize(() =>
      Object.getOwnPropertyDescriptor(value, key),
    );
    if (
      !descriptor ||
      !descriptor.enumerable ||
      !Object.hasOwn(descriptor, "value")
    ) {
      fail();
    }
    snapshot[key] = descriptor.value;
  }
  return snapshot;
}

function isHex(value, bytes) {
  return (
    typeof value === "string" &&
    value.length === bytes * 2 &&
    /^[0-9a-f]+$/u.test(value)
  );
}

function validateMetadata(value) {
  const metadata = snapshotObject(value, PUBLIC_METADATA_KEYS);
  if (
    metadata.schemaVersion !== 1 ||
    metadata.chainId !== SEPOLIA_CHAIN_ID ||
    !ADDRESS_PATTERN.test(metadata.fundingAddress) ||
    metadata.fundingAddress === ZERO_ADDRESS ||
    !HEX_32_PATTERN.test(metadata.keystoreSha256) ||
    typeof metadata.createdAt !== "string" ||
    !ISO_DATE_PATTERN.test(metadata.createdAt) ||
    Number.isNaN(Date.parse(metadata.createdAt))
  ) {
    fail();
  }
  return Object.freeze({
    schemaVersion: 1,
    chainId: SEPOLIA_CHAIN_ID,
    fundingAddress: metadata.fundingAddress,
    keystoreSha256: metadata.keystoreSha256,
    createdAt: metadata.createdAt,
  });
}

function validateKeystore(value) {
  const keystore = snapshotObject(value, KEYSTORE_KEYS);
  const crypto = snapshotObject(keystore.crypto, CRYPTO_KEYS);
  const cipherparams = snapshotObject(crypto.cipherparams, CIPHERPARAM_KEYS);
  const kdfparams = snapshotObject(crypto.kdfparams, SCRYPT_KEYS);
  if (
    keystore.version !== 3 ||
    typeof keystore.id !== "string" ||
    keystore.id.length === 0 ||
    !ADDRESS_NO_PREFIX_PATTERN.test(keystore.address) ||
    crypto.cipher !== "aes-128-ctr" ||
    crypto.kdf !== "scrypt" ||
    !isHex(crypto.ciphertext, 32) ||
    !isHex(cipherparams.iv, 16) ||
    !HEX_32_PATTERN.test(crypto.mac) ||
    kdfparams.dklen !== 32 ||
    !isHex(kdfparams.salt, 32) ||
    !Number.isInteger(kdfparams.n) ||
    kdfparams.n < 2 ||
    (kdfparams.n & (kdfparams.n - 1)) !== 0 ||
    kdfparams.n > 262_144 ||
    kdfparams.r !== 8 ||
    kdfparams.p !== 1
  ) {
    fail();
  }
  return Object.freeze({
    version: 3,
    id: keystore.id,
    address: keystore.address,
    crypto: Object.freeze({
      ciphertext: crypto.ciphertext,
      cipherparams: Object.freeze({ iv: cipherparams.iv }),
      cipher: "aes-128-ctr",
      kdf: "scrypt",
      kdfparams: Object.freeze({
        dklen: 32,
        salt: kdfparams.salt,
        n: kdfparams.n,
        r: 8,
        p: 1,
      }),
      mac: crypto.mac,
    }),
  });
}

async function defaultReadKeychainPassword(service, account, dependencies) {
  const execFile = dependencies.execFile ?? execFileAsync;
  const result = await sanitizeAsync(() =>
    execFile(
      "/usr/bin/security",
      ["find-generic-password", "-s", service, "-a", account, "-w"],
      { encoding: "utf8", maxBuffer: 4096 },
    ),
  );
  return result.stdout;
}

async function readPassword(dependencies) {
  const reader =
    dependencies.readKeychainPassword ??
    ((service, account) =>
      defaultReadKeychainPassword(service, account, dependencies));
  const password = await sanitizeAsync(() =>
    reader(FUNDING_KEYCHAIN_SERVICE, FUNDING_KEYCHAIN_ACCOUNT),
  );
  if (
    typeof password !== "string" ||
    password.trim().length === 0 ||
    Buffer.byteLength(password, "utf8") > 4096
  ) {
    fail();
  }
  return password.replace(/\r?\n$/u, "");
}

async function deriveKey(password, params, dependencies) {
  const derive = dependencies.scrypt ?? scryptAsync;
  return Buffer.from(
    await sanitizeAsync(() =>
      derive(password, Buffer.from(params.salt, "hex"), params.dklen, {
        N: params.n,
        r: params.r,
        p: params.p,
        maxmem: 512 * 1024 * 1024,
      }),
    ),
  );
}

function decryptPrivateKey(keystore, key) {
  return sanitize(() => {
    const ciphertext = Buffer.from(keystore.crypto.ciphertext, "hex");
    const expectedMac = keccak256(
      Buffer.concat([key.subarray(16, 32), ciphertext]),
    ).slice(2);
    if (expectedMac !== keystore.crypto.mac) fail();
    const decipher = createDecipheriv(
      "aes-128-ctr",
      key.subarray(0, 16),
      Buffer.from(keystore.crypto.cipherparams.iv, "hex"),
    );
    return `0x${Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]).toString("hex")}`;
  });
}

function validateAccount(privateKey, expectedAddress) {
  return sanitize(() => {
    if (!/^0x[0-9a-f]{64}$/u.test(privateKey)) fail();
    const account = privateKeyToAccount(privateKey);
    if (account.address.toLowerCase() !== expectedAddress) fail();
    return account;
  });
}

export async function openFundingWallet({
  keystorePath,
  metadataPath = `${keystorePath.slice(0, -5)}.public.json`,
  dependencies = {},
}) {
  if (
    typeof keystorePath !== "string" ||
    keystorePath.length === 0 ||
    typeof metadataPath !== "string" ||
    metadataPath.length === 0 ||
    dependencies === null ||
    typeof dependencies !== "object"
  ) {
    fail();
  }
  const fileSystem = dependencies.fs ?? Object.freeze({ lstat, open });
  if (
    typeof fileSystem.lstat !== "function" ||
    typeof fileSystem.open !== "function"
  ) {
    fail();
  }

  const [keystoreBytes, metadataBytes] = await Promise.all([
    readPinnedFile(keystorePath, MAX_KEYSTORE_BYTES, fileSystem),
    readPinnedFile(metadataPath, MAX_METADATA_BYTES, fileSystem),
  ]);
  const metadata = validateMetadata(parseJson(metadataBytes));
  const keystoreSha256 = createHash("sha256").update(keystoreBytes).digest("hex");
  if (keystoreSha256 !== metadata.keystoreSha256) fail();
  const keystore = validateKeystore(parseJson(keystoreBytes));
  if (`0x${keystore.address}` !== metadata.fundingAddress) fail();

  const password = await readPassword(dependencies);
  const key = await deriveKey(password, keystore.crypto.kdfparams, dependencies);
  if (key.length !== 32) fail();
  const privateKey = decryptPrivateKey(keystore, key);
  const account = validateAccount(privateKey, metadata.fundingAddress);

  return Object.freeze({ account, metadata });
}
