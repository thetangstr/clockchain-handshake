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

export const FUNDING_PASSWORD_FILE_ENV =
  "CLOCKCHAIN_FUNDING_PASSWORD_FILE";
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
const OPTION_KEYS = Object.freeze([
  "keystorePath",
  "metadataPath",
  "dependencies",
]);
const DEPENDENCY_KEYS = Object.freeze([
  "readKeychainPassword",
  "execFile",
  "fs",
  "scrypt",
  "stdout",
  "stderr",
]);
const FILE_SYSTEM_KEYS = Object.freeze(["lstat", "open"]);
const EXEC_FILE_RESULT_KEYS = Object.freeze(["stdout", "stderr"]);
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

function snapshotAllowedObject(value, allowedKeys, requiredKeys = []) {
  if (value === null || typeof value !== "object") fail();
  const prototype = sanitize(() => Object.getPrototypeOf(value));
  if (prototype !== Object.prototype && prototype !== null) fail();
  const ownKeys = sanitize(() => Reflect.ownKeys(value));
  if (
    ownKeys.some(
      (key) => typeof key !== "string" || !allowedKeys.includes(key),
    ) ||
    requiredKeys.some((key) => !ownKeys.includes(key))
  ) {
    fail();
  }
  const snapshot = {};
  for (const key of ownKeys) {
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
  return Object.freeze(snapshot);
}

function snapshotOptions(options) {
  const snapshot = snapshotAllowedObject(options, OPTION_KEYS, ["keystorePath"]);
  if (
    typeof snapshot.keystorePath !== "string" ||
    snapshot.keystorePath.length === 0 ||
    (Object.hasOwn(snapshot, "metadataPath") &&
      (typeof snapshot.metadataPath !== "string" ||
        snapshot.metadataPath.length === 0)) ||
    (Object.hasOwn(snapshot, "dependencies") &&
      (snapshot.dependencies === null ||
        typeof snapshot.dependencies !== "object"))
  ) {
    fail();
  }
  return Object.freeze({
    keystorePath: snapshot.keystorePath,
    metadataPath: Object.hasOwn(snapshot, "metadataPath")
      ? snapshot.metadataPath
      : `${snapshot.keystorePath.slice(0, -5)}.public.json`,
    dependencies: Object.hasOwn(snapshot, "dependencies")
      ? snapshotDependencyBag(snapshot.dependencies)
      : Object.freeze({}),
  });
}

function snapshotDependencyBag(dependencies) {
  const snapshot = snapshotAllowedObject(dependencies, DEPENDENCY_KEYS);
  if (
    (Object.hasOwn(snapshot, "readKeychainPassword") &&
      typeof snapshot.readKeychainPassword !== "function") ||
    (Object.hasOwn(snapshot, "execFile") &&
      typeof snapshot.execFile !== "function") ||
    (Object.hasOwn(snapshot, "scrypt") &&
      typeof snapshot.scrypt !== "function")
  ) {
    fail();
  }
  return snapshot;
}

function snapshotFileSystem(fileSystem) {
  const snapshot = snapshotAllowedObject(
    fileSystem,
    FILE_SYSTEM_KEYS,
    FILE_SYSTEM_KEYS,
  );
  if (
    typeof snapshot.lstat !== "function" ||
    typeof snapshot.open !== "function"
  ) {
    fail();
  }
  return snapshot;
}

function snapshotExecFileResult(value) {
  const snapshot = snapshotAllowedObject(value, EXEC_FILE_RESULT_KEYS);
  if (
    (Object.hasOwn(snapshot, "stdout") && typeof snapshot.stdout !== "string") ||
    (Object.hasOwn(snapshot, "stderr") && typeof snapshot.stderr !== "string")
  ) {
    fail();
  }
  return Object.freeze({
    stdout: snapshot.stdout ?? "",
    stderr: snapshot.stderr ?? "",
  });
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
  return snapshotExecFileResult(result).stdout;
}

async function readPassword(dependencies) {
  // Portable secret path: when CLOCKCHAIN_FUNDING_PASSWORD_FILE names a
  // private password file, read it instead of the macOS keychain so the
  // funding flow runs on any operating system. Explicit configuration fails
  // closed; there is no silent fallback to the keychain.
  const passwordFile = process.env[FUNDING_PASSWORD_FILE_ENV];
  if (passwordFile !== undefined) {
    if (typeof passwordFile !== "string" || passwordFile.length === 0) fail();
    const fileSystem = Object.hasOwn(dependencies, "fs")
      ? snapshotFileSystem(dependencies.fs)
      : Object.freeze({ lstat, open });
    const bytes = await sanitizeAsync(() =>
      readPinnedFile(passwordFile, 4097, fileSystem),
    );
    const password = bytes.toString("utf8").replace(/\r?\n$/u, "");
    if (password.trim().length === 0) fail();
    return password;
  }
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

export async function openFundingWallet(options) {
  return sanitizeAsync(async () => {
    const { keystorePath, metadataPath, dependencies } =
      snapshotOptions(options);
    const fileSystem = Object.hasOwn(dependencies, "fs")
      ? snapshotFileSystem(dependencies.fs)
      : Object.freeze({ lstat, open });

    const [keystoreBytes, metadataBytes] = await Promise.all([
      readPinnedFile(keystorePath, MAX_KEYSTORE_BYTES, fileSystem),
      readPinnedFile(metadataPath, MAX_METADATA_BYTES, fileSystem),
    ]);
    const metadata = validateMetadata(parseJson(metadataBytes));
    const keystoreSha256 = createHash("sha256")
      .update(keystoreBytes)
      .digest("hex");
    if (keystoreSha256 !== metadata.keystoreSha256) fail();
    const keystore = validateKeystore(parseJson(keystoreBytes));
    if (`0x${keystore.address}` !== metadata.fundingAddress) fail();

    const password = await readPassword(dependencies);
    const key = await deriveKey(
      password,
      keystore.crypto.kdfparams,
      dependencies,
    );
    if (key.length !== 32) fail();
    const privateKey = decryptPrivateKey(keystore, key);
    const account = validateAccount(privateKey, metadata.fundingAddress);

    return Object.freeze({ account, metadata });
  });
}
