#!/usr/bin/env node

import {
  GetSecretValueCommand,
  SecretsManagerClient,
} from "@aws-sdk/client-secrets-manager";
import {
  createHash,
} from "node:crypto";
import {
  chmod,
  mkdtemp,
  rm,
  rmdir,
} from "node:fs/promises";
import {
  tmpdir,
} from "node:os";
import {
  basename,
  isAbsolute,
  join,
} from "node:path";
import { types } from "node:util";

import {
  runAwsFundingTask,
} from "../../../scripts/run-aws-funding-task.mjs";
import {
  installPrivateFile,
  parseRuntimeInput,
  readSecretString,
} from "./runtime-input.mjs";

const FUNDING_INPUT_KEYS = Object.freeze([
  "actionAtMs",
  "actionId",
  "createdAt",
  "expectedTreasuryAddress",
  "fundingRecordPath",
  "journalDirectory",
  "keystoreSecretArn",
  "passwordSecretArn",
  "releaseIdentity",
  "repositorySha",
  "resultPath",
  "rpcSecretArn",
]);
const RELEASE_IDENTITY_KEYS = Object.freeze([
  "releaseId",
  "sessionId",
]);
const KEYSTORE_KEYS = Object.freeze([
  "version",
  "id",
  "address",
  "crypto",
]);
const CRYPTO_KEYS = Object.freeze([
  "ciphertext",
  "cipherparams",
  "cipher",
  "kdf",
  "kdfparams",
  "mac",
]);
const CIPHERPARAM_KEYS = Object.freeze(["iv"]);
const SCRYPT_KEYS = Object.freeze([
  "dklen",
  "salt",
  "n",
  "r",
  "p",
]);
const ADDRESS = /^0x[0-9a-f]{40}$/;
const CONTROL = /[\u0000-\u001f\u007f]/;
const HEX40 = /^[0-9a-f]{40}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const ISO_INSTANT =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const SECRET_ARN =
  /^arn:aws(?:-[a-z]+)?:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]{1,512}$/;
const SHA40 = /^[0-9a-f]{40}$/;
const RESERVED_DNS_SUFFIXES = Object.freeze([
  "invalid",
  "test",
  "example",
  "localhost",
  "local",
]);
const ZERO_ADDRESS =
  "0x0000000000000000000000000000000000000000";
const RELEASE = /^release-[0-9a-f]{16}$/;
const SESSION =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const UUID = SESSION;

class AwsFundingEntrypointError extends Error {
  constructor() {
    super("AWS funding entrypoint failed safely.");
    this.name = "AwsFundingEntrypointError";
  }
}

function fail() {
  throw new AwsFundingEntrypointError();
}

function plain(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    !types.isProxy(value) &&
    Object.getPrototypeOf(value) ===
      Object.prototype
  );
}

function exact(value, keys) {
  if (!plain(value)) fail();
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== keys.length ||
    keys.some((key, index) =>
      ownKeys[index] !== key)
  ) {
    fail();
  }
  for (const key of keys) {
    const descriptor =
      Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor?.enumerable !== true ||
      !Object.hasOwn(descriptor, "value")
    ) {
      fail();
    }
  }
  return value;
}

function absolutePath(value) {
  if (
    typeof value !== "string" ||
    !isAbsolute(value) ||
    CONTROL.test(value)
  ) {
    fail();
  }
  return value;
}

async function defaultCreateTempDir(prefix) {
  const path = await mkdtemp(prefix);
  try {
    await chmod(path, 0o700);
  } catch (error) {
    await rmdir(path).catch(() => {});
    throw error;
  }
  return path;
}

function validateScratchDir(path) {
  absolutePath(path);
  if (
    !basename(path).startsWith(
      "clockchain-funding-",
    )
  ) {
    fail();
  }
  return path;
}

function validateFundingInput(value) {
  const funding = exact(
    value,
    FUNDING_INPUT_KEYS,
  );
  const releaseIdentity = exact(
    funding.releaseIdentity,
    RELEASE_IDENTITY_KEYS,
  );
  if (
    !Number.isSafeInteger(funding.actionAtMs) ||
    funding.actionAtMs < 0 ||
    !UUID.test(funding.actionId) ||
    !ISO_INSTANT.test(funding.createdAt) ||
    Number.isNaN(
      Date.parse(funding.createdAt),
    ) ||
    new Date(funding.createdAt).toISOString() !==
      funding.createdAt ||
    !ADDRESS.test(
      funding.expectedTreasuryAddress,
    ) ||
    funding.expectedTreasuryAddress ===
      ZERO_ADDRESS ||
    !SHA40.test(funding.repositorySha) ||
    !RELEASE.test(releaseIdentity.releaseId) ||
    !SESSION.test(releaseIdentity.sessionId) ||
    !SECRET_ARN.test(
      funding.keystoreSecretArn,
    ) ||
    !SECRET_ARN.test(
      funding.passwordSecretArn,
    ) ||
    !SECRET_ARN.test(funding.rpcSecretArn)
  ) {
    fail();
  }
  absolutePath(funding.fundingRecordPath);
  absolutePath(funding.journalDirectory);
  absolutePath(funding.resultPath);
  if (
    funding.resultPath !==
    `/var/lib/clockchain/funding-result/releases/${releaseIdentity.releaseId}/actions/${funding.actionId}/funding-result.json`
  ) {
    fail();
  }
  return Object.freeze({
    ...funding,
    releaseIdentity,
  });
}

function privateIpv4(hostname) {
  const parts = hostname.split(".");
  if (
    parts.length !== 4 ||
    parts.some(
      (part) =>
        !/^(?:0|[1-9][0-9]{0,2})$/.test(part),
    )
  ) {
    return false;
  }
  const octets = parts.map(Number);
  if (octets.some((octet) => octet > 255)) {
    return false;
  }
  return (
    octets[0] === 0 ||
    octets[0] === 10 ||
    octets[0] === 127 ||
    (octets[0] === 169 && octets[1] === 254) ||
    (octets[0] === 172 &&
      octets[1] >= 16 &&
      octets[1] <= 31) ||
    (octets[0] === 192 && octets[1] === 168)
  );
}

function reservedIpv6(hostname) {
  const host = hostname
    .toLowerCase()
    .replace(/^\[/, "")
    .replace(/\]$/, "");
  return (
    host === "::" ||
    host === "::1" ||
    /^f[cd][0-9a-f]{0,2}:/u.test(host) ||
    /^fe[89ab][0-9a-f]?:/u.test(host)
  );
}

function reservedHostname(hostname) {
  const host = hostname.toLowerCase();
  return (
    RESERVED_DNS_SUFFIXES.some(
      (suffix) =>
        host === suffix ||
        host.endsWith(`.${suffix}`),
    ) ||
    privateIpv4(host) ||
    (host.startsWith("[") &&
      host.endsWith("]") &&
      reservedIpv6(host))
  );
}

function validRpcUrl(value) {
  try {
    const url = new URL(value);
    return (
      url.href === value &&
      url.protocol === "https:" &&
      url.username === "" &&
      url.password === "" &&
      url.search === "" &&
      url.hash === "" &&
      !reservedHostname(url.hostname)
    );
  } catch {
    return false;
  }
}

function exactKeystoreAddress(value) {
  try {
    if (
      typeof value !== "string" ||
      value.length === 0 ||
      Buffer.byteLength(value, "utf8") > 65_536
    ) {
      return null;
    }
    const parsed = JSON.parse(value);
    const keystore = exact(parsed, KEYSTORE_KEYS);
    const crypto = exact(
      keystore.crypto,
      CRYPTO_KEYS,
    );
    const cipherparams = exact(
      crypto.cipherparams,
      CIPHERPARAM_KEYS,
    );
    const kdfparams = exact(
      crypto.kdfparams,
      SCRYPT_KEYS,
    );
    if (
      JSON.stringify(parsed) !== value ||
      keystore.version !== 3 ||
      typeof keystore.id !== "string" ||
      keystore.id.length === 0 ||
      CONTROL.test(keystore.id) ||
      !HEX40.test(keystore.address) ||
      `0x${keystore.address}` === ZERO_ADDRESS ||
      crypto.cipher !== "aes-128-ctr" ||
      crypto.kdf !== "scrypt" ||
      typeof crypto.ciphertext !== "string" ||
      !HEX64.test(crypto.ciphertext) ||
      typeof cipherparams.iv !== "string" ||
      !/^[0-9a-f]{32}$/.test(
        cipherparams.iv,
      ) ||
      typeof crypto.mac !== "string" ||
      !HEX64.test(crypto.mac) ||
      kdfparams.dklen !== 32 ||
      typeof kdfparams.salt !== "string" ||
      !HEX64.test(kdfparams.salt) ||
      !Number.isInteger(kdfparams.n) ||
      kdfparams.n < 2 ||
      (kdfparams.n & (kdfparams.n - 1)) !==
        0 ||
      kdfparams.n > 262_144 ||
      kdfparams.r !== 8 ||
      kdfparams.p !== 1
    ) {
      return null;
    }
    return keystore.address;
  } catch {
    return null;
  }
}

function keystoreMetadata({
  createdAt,
  expectedTreasuryAddress,
  keystore,
}) {
  const address = exactKeystoreAddress(keystore);
  if (
    address === null ||
    `0x${address}` !== expectedTreasuryAddress
  ) {
    fail();
  }
  return JSON.stringify({
    schemaVersion: 1,
    chainId: 11155111,
    fundingAddress: expectedTreasuryAddress,
    keystoreSha256: createHash("sha256")
      .update(keystore)
      .digest("hex"),
    createdAt,
  });
}

export async function main({
  client = new SecretsManagerClient({}),
  createTempDir = defaultCreateTempDir,
  env = process.env,
  removeDir = rmdir,
  removeFile = (path) => rm(path, { force: true }),
  run = runAwsFundingTask,
} = {}) {
  let failure;
  let keystorePath;
  let metadataPath;
  let result;
  let rpcUrlFile;
  let scratchDir;
  try {
    const input = exact(parseRuntimeInput(env), [
      "funding",
      "paymentMoved",
      "schema",
    ]);
    const funding = validateFundingInput(
      input.funding,
    );
    if (
      typeof createTempDir !== "function" ||
      typeof removeDir !== "function" ||
      typeof removeFile !== "function" ||
      typeof run !== "function"
    ) {
      fail();
    }
    const keystore = await readSecretString({
      client,
      commandFactory: (value) =>
        new GetSecretValueCommand(value),
      secretArn: funding.keystoreSecretArn,
      validate: (value) =>
        exactKeystoreAddress(value) ===
        funding.expectedTreasuryAddress.slice(2),
    });
    const rpcUrl = await readSecretString({
      client,
      commandFactory: (value) =>
        new GetSecretValueCommand(value),
      secretArn: funding.rpcSecretArn,
      validate: validRpcUrl,
    });
    const metadata = keystoreMetadata({
      createdAt: funding.createdAt,
      expectedTreasuryAddress:
        funding.expectedTreasuryAddress,
      keystore,
    });
    scratchDir = validateScratchDir(
      await createTempDir(
        join(tmpdir(), "clockchain-funding-"),
      ),
    );
    keystorePath = join(
      scratchDir,
      "treasury-keystore.json",
    );
    metadataPath = join(
      scratchDir,
      "treasury-keystore.public.json",
    );
    rpcUrlFile = join(
      scratchDir,
      "sepolia-rpc-url",
    );
    await installPrivateFile({
      path: keystorePath,
      value: keystore,
    });
    await installPrivateFile({
      path: metadataPath,
      value: metadata,
    });
    await installPrivateFile({
      path: rpcUrlFile,
      value: `${rpcUrl}\n`,
    });
    result = await run(
      {
        actionAtMs: funding.actionAtMs,
        actionId: funding.actionId,
        expectedTreasuryAddress:
          funding.expectedTreasuryAddress,
        fundingRecordPath:
          funding.fundingRecordPath,
        journalDirectory:
          funding.journalDirectory,
        keystorePath,
        releaseId:
          funding.releaseIdentity.releaseId,
        repositorySha: funding.repositorySha,
        resultPath: funding.resultPath,
        rpcUrlFile,
        secretId: funding.passwordSecretArn,
        sessionId:
          funding.releaseIdentity.sessionId,
      },
      {
        readSecret: (secretArn) =>
          readSecretString({
            client,
            commandFactory: (value) =>
              new GetSecretValueCommand(value),
            secretArn,
            validate: (value) =>
              typeof value === "string" &&
              value.trim().length > 0 &&
              !value.includes("\0"),
          }),
      },
    );
  } catch (error) {
    failure = error;
  } finally {
    if (scratchDir !== undefined) {
      for (const path of [
        keystorePath,
        metadataPath,
        rpcUrlFile,
      ]) {
        if (path !== undefined) {
          try {
            await removeFile(path);
          } catch (error) {
            failure ??= error;
          }
        }
      }
      try {
        await removeDir(scratchDir);
      } catch (error) {
        failure ??= error;
      }
    }
  }
  if (failure !== undefined) {
    fail();
  }
  return result;
}

if (
  process.argv[1] !== undefined &&
  import.meta.url ===
    new URL(`file://${process.argv[1]}`).href
) {
  main().catch(() => {
    process.stderr.write(
      "AWS_FUNDING_ENTRYPOINT_FAILED\n",
    );
    process.exitCode = 1;
  });
}
