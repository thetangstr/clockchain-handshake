#!/usr/bin/env node

import {
  GetSecretValueCommand,
  SecretsManagerClient,
} from "@aws-sdk/client-secrets-manager";
import {
  createHash,
  createPrivateKey,
  X509Certificate,
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
  isIP,
} from "node:net";
import {
  basename,
  isAbsolute,
  join,
  normalize,
} from "node:path";
import { types } from "node:util";

import {
  main as coordinatorMain,
} from "../../../bin/handshake-coordinator.mjs";
import {
  installPrivateFile,
  parseRuntimeInput,
  readSecretString,
} from "./runtime-input.mjs";
import {
  validatePublicAddress,
} from "../../../src/bilateral/network-endpoint.mjs";

const COORDINATOR_INPUT_KEYS = Object.freeze([
  "clockchainTokenSecretArn",
  "operatorKeyId",
  "operatorKeySecretArn",
  "releaseIdentity",
  "releaseRoot",
  "relayUrl",
  "repositorySha",
  "rpcSecretArn",
  "tlsCertificatePem",
  "tlsFingerprint",
]);
const RELEASE_IDENTITY_KEYS = Object.freeze([
  "releaseId",
  "sessionId",
]);
const OPERATOR_ROOT =
  "/var/lib/clockchain/operator";
const CONTROL = /[\u0000-\u001f\u007f]/;
const FINGERPRINT = /^[0-9a-f]{64}$/;
const OPERATOR_KEY_ID =
  /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
const RELEASE = /^release-[0-9a-f]{16}$/;
const SECRET_ARN =
  /^arn:aws(?:-[a-z]+)?:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]{1,512}$/;
const SESSION =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA40 = /^[0-9a-f]{40}$/;
const TOKEN = /^[\x20-\x7e]{1,4096}$/;
const RESERVED_DNS_SUFFIXES = Object.freeze([
  "invalid",
  "test",
  "example",
  "localhost",
  "local",
]);

class AwsCoordinatorEntrypointError extends Error {
  constructor() {
    super(
      "AWS coordinator entrypoint failed safely.",
    );
    this.name = "AwsCoordinatorEntrypointError";
  }
}

function fail() {
  throw new AwsCoordinatorEntrypointError();
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

function expectedReleaseId(sessionId) {
  return `release-${createHash("sha256").update(sessionId, "utf8").digest("hex").slice(0, 16)}`;
}

function exactReleaseRoot(releaseId) {
  return `${OPERATOR_ROOT}/releases/${releaseId}`;
}

function normalizedAbsolute(value) {
  if (
    typeof value !== "string" ||
    !isAbsolute(value) ||
    CONTROL.test(value) ||
    normalize(value) !== value
  ) {
    fail();
  }
  return value;
}

function validateReleaseRoot(value, releaseId) {
  const path = normalizedAbsolute(value);
  if (path !== exactReleaseRoot(releaseId)) {
    fail();
  }
  return path;
}

function validateTlsCertificatePem(value, fingerprint) {
  try {
    if (
      typeof value !== "string" ||
      value.length === 0 ||
      /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value) ||
      Buffer.byteLength(value, "utf8") >
        65_536
    ) {
      fail();
    }
    const certificate = new X509Certificate(value);
    if (
      certificate.toString() !== value ||
      createHash("sha256")
        .update(certificate.raw)
        .digest("hex") !== fingerprint
    ) {
      fail();
    }
    return value;
  } catch (error) {
    if (
      error instanceof
      AwsCoordinatorEntrypointError
    ) {
      throw error;
    }
    fail();
  }
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
  if (
    typeof path !== "string" ||
    !isAbsolute(path) ||
    CONTROL.test(path) ||
    !basename(path).startsWith(
      "clockchain-coordinator-",
    )
  ) {
    fail();
  }
  return path;
}

function publicIpLiteral(hostname) {
  const host = hostname
    .toLowerCase()
    .replace(/^\[/, "")
    .replace(/\]$/, "");
  if (isIP(host) === 0) {
    return null;
  }
  try {
    validatePublicAddress(host);
    return true;
  } catch {
    return false;
  }
}

function reservedHostname(hostname) {
  const host = hostname.toLowerCase();
  const publicIp = publicIpLiteral(host);
  return (
    RESERVED_DNS_SUFFIXES.some(
      (suffix) =>
        host === suffix ||
        host.endsWith(`.${suffix}`),
    ) ||
    publicIp === false
  );
}

function validRelayUrl(value) {
  try {
    const url = new URL(value);
    return (
      value === `https://${url.host}` &&
      url.protocol === "https:" &&
      url.port !== "" &&
      url.username === "" &&
      url.password === "" &&
      url.pathname === "/" &&
      url.search === "" &&
      url.hash === "" &&
      !reservedHostname(url.hostname)
    );
  } catch {
    return false;
  }
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

function validateReleaseIdentity(value) {
  const releaseIdentity = exact(
    value,
    RELEASE_IDENTITY_KEYS,
  );
  if (
    !RELEASE.test(releaseIdentity.releaseId) ||
    !SESSION.test(releaseIdentity.sessionId) ||
    releaseIdentity.releaseId !==
      expectedReleaseId(
        releaseIdentity.sessionId,
      )
  ) {
    fail();
  }
  return Object.freeze({
    releaseId: releaseIdentity.releaseId,
    sessionId: releaseIdentity.sessionId,
  });
}

function validateCoordinatorInput(value) {
  const coordinator = exact(
    value,
    COORDINATOR_INPUT_KEYS,
  );
  const releaseIdentity =
    validateReleaseIdentity(
      coordinator.releaseIdentity,
    );
  if (
    !SECRET_ARN.test(
      coordinator.clockchainTokenSecretArn,
    ) ||
    !OPERATOR_KEY_ID.test(
      coordinator.operatorKeyId,
    ) ||
    !SECRET_ARN.test(
      coordinator.operatorKeySecretArn,
    ) ||
    !validRelayUrl(coordinator.relayUrl) ||
    !SHA40.test(coordinator.repositorySha) ||
    !SECRET_ARN.test(
      coordinator.rpcSecretArn,
    ) ||
    !FINGERPRINT.test(
      coordinator.tlsFingerprint,
    )
  ) {
    fail();
  }
  return Object.freeze({
    clockchainTokenSecretArn:
      coordinator.clockchainTokenSecretArn,
    operatorKeyId: coordinator.operatorKeyId,
    operatorKeySecretArn:
      coordinator.operatorKeySecretArn,
    releaseIdentity,
    releaseRoot: validateReleaseRoot(
      coordinator.releaseRoot,
      releaseIdentity.releaseId,
    ),
    relayUrl: coordinator.relayUrl,
    repositorySha: coordinator.repositorySha,
    rpcSecretArn: coordinator.rpcSecretArn,
    tlsCertificatePem: validateTlsCertificatePem(
      coordinator.tlsCertificatePem,
      coordinator.tlsFingerprint,
    ),
    tlsFingerprint: coordinator.tlsFingerprint,
  });
}

function validClockchainToken(value) {
  return (
    TOKEN.test(value) &&
    value.trim().length > 0
  );
}

function validOperatorPrivateKey(value) {
  try {
    if (
      typeof value !== "string" ||
      value.length === 0 ||
      Buffer.byteLength(value, "utf8") >
        65_536
    ) {
      return false;
    }
    const key = createPrivateKey(value);
    return (
      key.asymmetricKeyType === "ed25519" &&
      key.export({
        format: "pem",
        type: "pkcs8",
      }) === value
    );
  } catch {
    return false;
  }
}

export async function main({
  client = new SecretsManagerClient({}),
  createTempDir = defaultCreateTempDir,
  env = process.env,
  removeDir = rmdir,
  removeFile = (path) => rm(path, { force: true }),
  run = coordinatorMain,
} = {}) {
  let failure;
  let operatorKeyPath;
  let result;
  let rpcUrlFile;
  let scratchDir;
  let tlsCertificatePath;
  let tokenPath;
  try {
    const input = exact(parseRuntimeInput(env), [
      "coordinator",
      "paymentMoved",
      "schema",
    ]);
    const coordinator =
      validateCoordinatorInput(
        input.coordinator,
      );
    if (
      client === null ||
      typeof client !== "object" ||
      typeof client.send !== "function" ||
      typeof createTempDir !== "function" ||
      typeof removeDir !== "function" ||
      typeof removeFile !== "function" ||
      typeof run !== "function"
    ) {
      fail();
    }
    const clockchainToken =
      await readSecretString({
        client,
        commandFactory: (value) =>
          new GetSecretValueCommand(value),
        secretArn:
          coordinator.clockchainTokenSecretArn,
        validate: validClockchainToken,
      });
    const operatorPrivateKey =
      await readSecretString({
        client,
        commandFactory: (value) =>
          new GetSecretValueCommand(value),
        secretArn:
          coordinator.operatorKeySecretArn,
        validate: validOperatorPrivateKey,
      });
    const rpcUrl = await readSecretString({
      client,
      commandFactory: (value) =>
        new GetSecretValueCommand(value),
      secretArn: coordinator.rpcSecretArn,
      validate: validRpcUrl,
    });
    scratchDir = validateScratchDir(
      await createTempDir(
        join(tmpdir(), "clockchain-coordinator-"),
      ),
    );
    tokenPath = join(
      scratchDir,
      "clockchain-token",
    );
    operatorKeyPath = join(
      scratchDir,
      "operator-private-key.pem",
    );
    rpcUrlFile = join(
      scratchDir,
      "sepolia-rpc-url",
    );
    tlsCertificatePath = join(
      scratchDir,
      "relay-public-certificate.pem",
    );
    await installPrivateFile({
      path: tokenPath,
      value: clockchainToken,
    });
    await installPrivateFile({
      path: operatorKeyPath,
      value: operatorPrivateKey,
    });
    await installPrivateFile({
      path: rpcUrlFile,
      value: `${rpcUrl}\n`,
    });
    await installPrivateFile({
      path: tlsCertificatePath,
      value: coordinator.tlsCertificatePem,
    });
    const argv = [
      "--clockchain-token-file",
      tokenPath,
      "--operator-key-id",
      coordinator.operatorKeyId,
      "--operator-private-key",
      operatorKeyPath,
      "--release-root",
      coordinator.releaseRoot,
      "--relay-url",
      coordinator.relayUrl,
      "--repository-sha",
      coordinator.repositorySha,
      "--rpc-url-file",
      rpcUrlFile,
      "--tls-certificate",
      tlsCertificatePath,
      "--tls-fingerprint",
      coordinator.tlsFingerprint,
    ];
    result = await run(argv, {
      releaseIdentity:
        coordinator.releaseIdentity,
    });
    if (result !== 0) {
      fail();
    }
  } catch (error) {
    failure = error;
  } finally {
    if (scratchDir !== undefined) {
      for (const path of [
        tokenPath,
        operatorKeyPath,
        rpcUrlFile,
        tlsCertificatePath,
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
      "AWS_COORDINATOR_ENTRYPOINT_FAILED\n",
    );
    process.exitCode = 1;
  });
}
