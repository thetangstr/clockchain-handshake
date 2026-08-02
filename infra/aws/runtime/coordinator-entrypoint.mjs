#!/usr/bin/env node

import {
  GetSecretValueCommand,
  SecretsManagerClient,
} from "@aws-sdk/client-secrets-manager";
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  X509Certificate,
} from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  rm,
  rmdir,
} from "node:fs/promises";
import {
  isIP,
} from "node:net";
import {
  basename,
  isAbsolute,
  join,
  normalize,
} from "node:path";
import {
  setTimeout as delay,
} from "node:timers/promises";
import { types } from "node:util";

import {
  main as coordinatorMain,
} from "../../../bin/handshake-coordinator.mjs";
import {
  readApprovedPayerPublicProjection,
} from "../../../src/bilateral/aws/approved-payer-public.mjs";
import {
  createAwsPublicStager,
} from "../../../src/bilateral/aws/public-staging.mjs";
import {
  readTunnelHealthProjection,
} from "../../../src/bilateral/aws/tunnel-health.mjs";
import {
  buildUnavailablePublicMonitorSnapshot,
} from "../../../src/bilateral/coordination/public-monitor.mjs";
import {
  installPrivateFile,
  parseRuntimeInput,
  readSecretString,
} from "./runtime-input.mjs";
import {
  sshEd25519Fingerprint,
} from "../../../scripts/publish-payer-bootstrap-discovery.mjs";
import {
  validatePublicAddress,
} from "../../../src/bilateral/network-endpoint.mjs";

const COORDINATOR_INPUT_KEYS = Object.freeze([
  "clockchainTokenSecretArn",
  "operatorKeyId",
  "operatorKeySecretArn",
  "provenance",
  "publicStaging",
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
const PUBLIC_STAGING_KEYS = Object.freeze([
  "approvedPayerPublicPath",
  "bootstrapPayerClaimUrl",
  "imageDigest",
  "paths",
  "publicBaseUrl",
  "publicMcpHostname",
  "publicMcpUrl",
  "tunnelHealthPath",
  "tunnelHostKeyFingerprint",
  "tunnelHostPublicKey",
]);
const PUBLIC_STAGING_PATH_KEYS = Object.freeze([
  "certificate",
  "gate",
  "input",
  "payer",
  "requestor",
]);
const OPERATOR_ROOT =
  "/var/lib/clockchain/operator";
const PUBLIC_ROOT =
  "/var/lib/clockchain/public";
const SCRATCH_ROOT = "/dev/shm";
const CONTROL = /[\u0000-\u001f\u007f]/;
const FINGERPRINT = /^[0-9a-f]{64}$/;
const IMAGE =
  /^[0-9]{12}\.dkr\.ecr\.[a-z]{2}-[a-z]+-[1-9]\.amazonaws\.com\/[a-z0-9][a-z0-9._/-]{0,254}@sha256:[0-9a-f]{64}$/;
const IMAGE_DIGEST = /^sha256:[0-9a-f]{64}$/;
const HOST =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const OPERATOR_KEY_ID =
  /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
const RELEASE = /^release-[0-9a-f]{16}$/;
const SECRET_ARN =
  /^arn:aws(?:-[a-z]+)?:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]{1,512}$/;
const SESSION =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA40 = /^[0-9a-f]{40}$/;
const SHA64 = /^[0-9a-f]{64}$/;
const RAW_ED25519_PUBLIC_KEY =
  /^[A-Za-z0-9+/]{43}=$/;
const TOKEN = /^[\x20-\x7e]{1,4096}$/;
const SSH_SHA256_FINGERPRINT =
  /^SHA256:[A-Za-z0-9+/]{43}$/;
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

async function defaultCreatePublicReleaseRoot(path) {
  const created = await mkdir(path, {
    mode: 0o700,
    recursive: true,
  });
  let stats = await lstat(path);
  if (
    !stats.isDirectory() ||
    stats.isSymbolicLink()
  ) {
    fail();
  }
  if ((stats.mode & 0o777) !== 0o700) {
    if (created === undefined) fail();
    await chmod(path, 0o700);
    stats = await lstat(path);
    if (
      !stats.isDirectory() ||
      stats.isSymbolicLink() ||
      (stats.mode & 0o777) !== 0o700
    ) {
      fail();
    }
  }
}

function defaultSleeper(ms, { signal } = {}) {
  return delay(ms, undefined, { signal });
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

function validPublicUrl(value, expectedPath) {
  try {
    const url = new URL(value);
    return (
      url.href === value &&
      url.protocol === "https:" &&
      url.username === "" &&
      url.password === "" &&
      url.pathname === expectedPath &&
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

function exactPath(value, expected) {
  const path = normalizedAbsolute(value);
  if (path !== expected) fail();
  return path;
}

function validatePublicStaging(value, scope) {
  const input = exact(value, PUBLIC_STAGING_KEYS);
  const paths = exact(
    input.paths,
    PUBLIC_STAGING_PATH_KEYS,
  );
  let bootstrapUrl;
  let baseUrl;
  let mcpUrl;
  try {
    bootstrapUrl = new URL(
      input.bootstrapPayerClaimUrl,
    );
    baseUrl = new URL(input.publicBaseUrl);
    mcpUrl = new URL(input.publicMcpUrl);
  } catch {
    fail();
  }
  const publicRoot =
    `${PUBLIC_ROOT}/releases/${scope.releaseId}`;
  if (
    !validPublicUrl(
      input.bootstrapPayerClaimUrl,
      "/v1/payer-claims",
    ) ||
    bootstrapUrl.port !== "" ||
    !IMAGE.test(input.imageDigest) ||
    !validPublicUrl(input.publicBaseUrl, "/") ||
    baseUrl.port !== "" ||
    !validPublicUrl(input.publicMcpUrl, "/mcp") ||
    mcpUrl.port !== "9443" ||
    input.publicMcpHostname !== mcpUrl.hostname ||
    !HOST.test(input.publicMcpHostname) ||
    reservedHostname(input.publicMcpHostname) ||
    !SSH_SHA256_FINGERPRINT.test(
      input.tunnelHostKeyFingerprint,
    ) ||
    sshEd25519Fingerprint(
      input.tunnelHostPublicKey,
    ) !== input.tunnelHostKeyFingerprint
  ) {
    fail();
  }
  const checkedPaths = Object.freeze({
    certificate: exactPath(
      paths.certificate,
      `${publicRoot}/payer-mcp.crt`,
    ),
    gate: exactPath(
      paths.gate,
      `${publicRoot}/publication-gate.json`,
    ),
    input: exactPath(
      paths.input,
      `${publicRoot}/publisher-input.json`,
    ),
    payer: exactPath(
      paths.payer,
      `${publicRoot}/payer.json`,
    ),
    requestor: exactPath(
      paths.requestor,
      `${publicRoot}/requestor.json`,
    ),
  });
  if (
    new Set(Object.values(checkedPaths)).size !==
    PUBLIC_STAGING_PATH_KEYS.length
  ) {
    fail();
  }
  return Object.freeze({
    approvedPayerPublicPath: exactPath(
      input.approvedPayerPublicPath,
      `/var/lib/clockchain/approved-payer/releases/${scope.releaseId}/approved-payer.json`,
    ),
    bootstrapPayerClaimUrl: bootstrapUrl.href,
    imageDigest: input.imageDigest,
    paths: checkedPaths,
    publicBaseUrl: baseUrl.href,
    publicMcpHostname: input.publicMcpHostname,
    publicMcpUrl: mcpUrl.href,
    releaseRoot: publicRoot,
    tunnelHealthPath: exactPath(
      input.tunnelHealthPath,
      `/var/lib/clockchain/tunnel-health/releases/${scope.releaseId}/tunnel-health.json`,
    ),
    tunnelHostKeyFingerprint:
      input.tunnelHostKeyFingerprint,
    tunnelHostPublicKey:
      input.tunnelHostPublicKey,
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
  const publicStaging = validatePublicStaging(
    coordinator.publicStaging,
    releaseIdentity,
  );
  const provenance = exact(
    coordinator.provenance,
    [
      "imageDigest",
      "operatorPublicKey",
      "repositorySha",
      "sourceTreeSha256",
    ],
  );
  if (
    !IMAGE_DIGEST.test(provenance.imageDigest) ||
    provenance.imageDigest !==
      publicStaging.imageDigest.split("@")[1] ||
    !RAW_ED25519_PUBLIC_KEY.test(
      provenance.operatorPublicKey,
    ) ||
    Buffer.from(
      provenance.operatorPublicKey,
      "base64",
    ).length !== 32 ||
    Buffer.from(
      provenance.operatorPublicKey,
      "base64",
    ).toString("base64") !==
      provenance.operatorPublicKey ||
    provenance.repositorySha !==
      coordinator.repositorySha ||
    !SHA64.test(provenance.sourceTreeSha256)
  ) {
    fail();
  }
  return Object.freeze({
    clockchainTokenSecretArn:
      coordinator.clockchainTokenSecretArn,
    operatorKeyId: coordinator.operatorKeyId,
    operatorKeySecretArn:
      coordinator.operatorKeySecretArn,
    provenance: Object.freeze({
      imageDigest: provenance.imageDigest,
      operatorPublicKey:
        provenance.operatorPublicKey,
      repositorySha: provenance.repositorySha,
      sourceTreeSha256:
        provenance.sourceTreeSha256,
    }),
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
    publicStaging,
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

function publicStagerConfig(coordinator, operatorPrivateKey) {
  const staging = coordinator.publicStaging;
  return Object.freeze({
    imageDigest: staging.imageDigest,
    operatorKeyId: coordinator.operatorKeyId,
    operatorPrivateKey,
    paths: staging.paths,
    payerClaimUrl: staging.bootstrapPayerClaimUrl,
    publicBaseUrl: staging.publicBaseUrl,
    publicMcpHostname: staging.publicMcpHostname,
    publicMcpUrl: staging.publicMcpUrl,
    releaseId: coordinator.releaseIdentity.releaseId,
    repositorySha: coordinator.repositorySha,
    sessionId: coordinator.releaseIdentity.sessionId,
    tunnelHost: staging.publicMcpHostname,
    tunnelHostPublicKey:
      staging.tunnelHostPublicKey,
    tunnelHostKeyFingerprint:
      staging.tunnelHostKeyFingerprint,
  });
}

function initialPublicSnapshot(coordinator, nowMs) {
  if (!Number.isSafeInteger(nowMs + 600_000)) {
    fail();
  }
  return buildUnavailablePublicMonitorSnapshot({
    publishedAtMs: nowMs,
    runId: `run-${coordinator.releaseIdentity.releaseId.slice("release-".length)}`,
    staleAfterMs: 60_000,
  });
}

function validateReadyEvidence({
  approvedPayer,
  coordinator,
  nowMs,
  tunnelHealth,
}) {
  if (
    approvedPayer === null ||
    tunnelHealth === null ||
    approvedPayer.paymentMoved !== false ||
    tunnelHealth.paymentMoved !== false ||
    approvedPayer.releaseId !== coordinator.releaseIdentity.releaseId ||
    tunnelHealth.releaseId !== coordinator.releaseIdentity.releaseId ||
    approvedPayer.repositorySha !== coordinator.repositorySha ||
    tunnelHealth.repositorySha !== coordinator.repositorySha ||
    approvedPayer.sessionId !== coordinator.releaseIdentity.sessionId ||
    tunnelHealth.sessionId !== coordinator.releaseIdentity.sessionId ||
    approvedPayer.status !== "APPROVED" ||
    tunnelHealth.status !== "READY" ||
    tunnelHealth.claimFingerprint !== approvedPayer.claimFingerprint ||
    tunnelHealth.mcpTlsFingerprint !== approvedPayer.certificateFingerprint ||
    BigInt(approvedPayer.expiresAtMs) <= BigInt(nowMs) ||
    BigInt(tunnelHealth.expiresAtMs) <= BigInt(nowMs)
  ) {
    fail();
  }
}

async function pollPayerReadiness({
  approvedPayerReader,
  coordinator,
  now,
  publicStager,
  signal,
  sleeper,
  tunnelHealthReader,
}) {
  const start = now();
  if (!Number.isSafeInteger(start) || start < 0) {
    fail();
  }
  for (let attempt = 0; attempt < 601; attempt += 1) {
    if (signal.aborted) return false;
    const approvedPayer = await approvedPayerReader(
      coordinator.publicStaging.approvedPayerPublicPath,
    );
    const tunnelHealth = await tunnelHealthReader(
      coordinator.publicStaging.tunnelHealthPath,
    );
    if (approvedPayer !== null || tunnelHealth !== null) {
      if (approvedPayer === null || tunnelHealth === null) {
        fail();
      }
      const nowMs = now();
      validateReadyEvidence({
        approvedPayer,
        coordinator,
        nowMs,
        tunnelHealth,
      });
      await publicStager.stagePayerReady({
        approvedPayer,
        nowMs,
        tunnelHealth,
      });
      return true;
    }
    if (now() - start >= 600_000) break;
    await sleeper(1000, { signal });
  }
  fail();
}

export async function main({
  approvedPayerReader = readApprovedPayerPublicProjection,
  client = new SecretsManagerClient({}),
  createPublicReleaseRoot = defaultCreatePublicReleaseRoot,
  createTempDir = defaultCreateTempDir,
  env = process.env,
  now = Date.now,
  publicStagerFactory = createAwsPublicStager,
  removeDir = rmdir,
  removeFile = (path) => rm(path, { force: true }),
  run = coordinatorMain,
  scratchRoot = SCRATCH_ROOT,
  sleeper = defaultSleeper,
  tunnelHealthReader = readTunnelHealthProjection,
} = {}) {
  let failure;
  let operatorKeyPath;
  let pollPromise;
  let result;
  let rpcUrlFile;
  let scratchDir;
  let tlsCertificatePath;
  let tokenPath;
  let pollAbort;
  let publicStager;
  let runAbort;
  let runPromise;
  let stageStarted = false;
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
      typeof approvedPayerReader !== "function" ||
      typeof createPublicReleaseRoot !== "function" ||
      typeof createTempDir !== "function" ||
      typeof now !== "function" ||
      typeof publicStagerFactory !== "function" ||
      typeof removeDir !== "function" ||
      typeof removeFile !== "function" ||
      typeof run !== "function" ||
      typeof scratchRoot !== "string" ||
      !isAbsolute(scratchRoot) ||
      CONTROL.test(scratchRoot) ||
      normalize(scratchRoot) !== scratchRoot ||
      typeof sleeper !== "function" ||
      typeof tunnelHealthReader !== "function"
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
    const operatorPrivateKeyObject =
      createPrivateKey(operatorPrivateKey);
    const operatorPublicKey = createPublicKey(
      operatorPrivateKeyObject,
    )
      .export({ format: "der", type: "spki" })
      .subarray(-32)
      .toString("base64");
    if (
      operatorPublicKey !==
      coordinator.provenance.operatorPublicKey
    ) {
      fail();
    }
    const taskProvenance = Object.freeze({
      imageDigest:
        coordinator.provenance.imageDigest,
      operatorPublicKey,
      repositorySha:
        coordinator.provenance.repositorySha,
      sourceTreeSha256:
        coordinator.provenance.sourceTreeSha256,
    });
    const provenanceProvider = Object.freeze({
      async assertRepository(value) {
        if (
          value?.repositorySha !==
          taskProvenance.repositorySha
        ) {
          throw new Error();
        }
        return taskProvenance;
      },
      async verify(value) {
        if (
          value?.operatorKeyId !==
            coordinator.operatorKeyId ||
          value?.repositorySha !==
            taskProvenance.repositorySha
        ) {
          throw new Error();
        }
        return taskProvenance;
      },
    });
    await createPublicReleaseRoot(
      coordinator.publicStaging.releaseRoot,
    );
    publicStager = publicStagerFactory(
      publicStagerConfig(
        coordinator,
        operatorPrivateKeyObject,
      ),
    );
    if (
      publicStager === null ||
      typeof publicStager !== "object" ||
      typeof publicStager.close !== "function" ||
      typeof publicStager.stagePayerReady !== "function" ||
      typeof publicStager.stageStart !== "function" ||
      typeof publicStager.stageTerminalFailure !== "function"
    ) {
      fail();
    }
    const currentNow = now();
    if (
      !Number.isSafeInteger(currentNow) ||
      currentNow < 0 ||
      !Number.isSafeInteger(currentNow + 600_000)
    ) {
      fail();
    }
    await publicStager.stageStart({
      expiresAtMs: String(currentNow + 600_000),
      nowMs: currentNow,
      snapshot: initialPublicSnapshot(
        coordinator,
        currentNow,
      ),
    });
    stageStarted = true;
    scratchDir = validateScratchDir(
      await createTempDir(
        join(scratchRoot, "clockchain-coordinator-"),
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
    pollAbort = new AbortController();
    pollPromise = pollPayerReadiness({
      approvedPayerReader,
      coordinator,
      now,
      publicStager,
      signal: pollAbort.signal,
      sleeper,
      tunnelHealthReader,
    });
    runAbort = new AbortController();
    runPromise = Promise.resolve(
      run(argv, {
        abortSignal: runAbort.signal,
        provenanceProvider,
        releaseIdentity:
          coordinator.releaseIdentity,
        publicStager,
      }),
    );
    const first = await Promise.race([
      runPromise.then((value) => ({
        type: "run",
        value,
      })),
      pollPromise.then((value) => ({
        type: "poll",
        value,
      })),
    ]);
    if (first.type === "run") {
      result = first.value;
      if (result !== 0) {
        fail();
      }
      await pollPromise;
    } else {
      result = await runPromise;
    }
    if (result !== 0) {
      fail();
    }
  } catch (error) {
    runAbort?.abort();
    if (runPromise !== undefined) {
      try {
        await runPromise;
      } catch {}
    }
    pollAbort?.abort();
    if (pollPromise !== undefined) {
      try {
        await pollPromise;
      } catch {}
    }
    failure = error;
  } finally {
    pollAbort?.abort();
    if (
      failure !== undefined &&
      publicStager !== undefined &&
      stageStarted
    ) {
      try {
        await publicStager.stageTerminalFailure({
          nowMs: now(),
        });
      } catch {}
    }
    if (publicStager !== undefined) {
      try {
        await publicStager.close();
      } catch (error) {
        failure ??= error;
      }
    }
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
