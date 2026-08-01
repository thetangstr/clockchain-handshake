import {
  createHash,
  X509Certificate,
} from "node:crypto";
import {
  isIP,
} from "node:net";
import {
  isAbsolute,
  resolve,
} from "node:path";
import { types } from "node:util";

import {
  validatePublicAddress,
} from "../../../src/bilateral/network-endpoint.mjs";

const SCHEMA =
  "clockchain.aws-runtime-input/v1";
const COORDINATOR_KEYS = Object.freeze([
  "clockchainTokenSecretArn",
  "operatorKeyId",
  "operatorKeySecretArn",
  "paymentMoved",
  "publicStaging",
  "releaseId",
  "releaseRoot",
  "relayUrl",
  "repositorySha",
  "rpcSecretArn",
  "sessionId",
  "tlsCertificatePem",
  "tlsFingerprint",
]);
const FUNDING_KEYS = Object.freeze([
  "actionAtMs",
  "actionId",
  "createdAt",
  "expectedTreasuryAddress",
  "fundingRecordPath",
  "journalDirectory",
  "keystoreSecretArn",
  "passwordSecretArn",
  "paymentMoved",
  "releaseId",
  "resultPath",
  "repositorySha",
  "rpcSecretArn",
  "sessionId",
]);
const VERIFIER_KEYS = Object.freeze([
  "actionAtMs",
  "attemptId",
  "attemptRoot",
  "clockchainTokenSecretArn",
  "descriptorPath",
  "evidenceDigest",
  "expectedRevision",
  "mandateDigest",
  "payerMandatePath",
  "payeeResultsPath",
  "payerResultsPath",
  "paymentMoved",
  "paymentRequestPath",
  "publicationPath",
  "releaseId",
  "repositorySha",
  "requestDigest",
  "rpcSecretArn",
  "sessionDigest",
  "sessionId",
]);
const ADDRESS = /^0x[0-9a-f]{40}$/;
const ATTEMPT_ID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const CONTROL = /[\u0000-\u001f\u007f]/;
const RELEASE =
  /^release-[0-9a-f]{16}$/;
const OPERATOR_KEY_ID =
  /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
const SECRET_ARN =
  /^arn:aws(?:-[a-z]+)?:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]{1,512}$/;
const SESSION =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA40 = /^[0-9a-f]{40}$/;
const SHA64 = /^[0-9a-f]{64}$/;
const IMAGE =
  /^[0-9]{12}\.dkr\.ecr\.[a-z]{2}-[a-z]+-[1-9]\.amazonaws\.com\/[a-z0-9][a-z0-9._/-]{0,254}@sha256:[0-9a-f]{64}$/;
const ISO_INSTANT =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const ZERO_ADDRESS =
  "0x0000000000000000000000000000000000000000";
const RESERVED_DNS_SUFFIXES = Object.freeze([
  "invalid",
  "test",
  "example",
  "localhost",
  "local",
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
const SSH_ED25519_PUBLIC_KEY =
  /^ssh-ed25519 ([A-Za-z0-9+/]+={0,2})$/;
const SSH_SHA256_FINGERPRINT =
  /^SHA256:[A-Za-z0-9+/]{43}$/;

export class AwsOperatorTaskInputError extends Error {
  constructor() {
    super("AWS operator task input failed safely.");
    this.name = "AwsOperatorTaskInputError";
    this.code =
      "AWS_OPERATOR_TASK_INPUT_INVALID";
    this.category = "configuration";
  }
}

function fail() {
  throw new AwsOperatorTaskInputError();
}

function exact(value, keys) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    types.isProxy(value) ||
    Object.getPrototypeOf(value) !==
      Object.prototype
  ) {
    fail();
  }
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== keys.length ||
    keys.some((key, index) =>
      ownKeys[index] !== key)
  ) {
    fail();
  }
  const snapshot = {};
  for (const key of keys) {
    const descriptor =
      Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor?.enumerable !== true ||
      !Object.hasOwn(descriptor, "value")
    ) {
      fail();
    }
    snapshot[key] = descriptor.value;
  }
  return Object.freeze(snapshot);
}

function expectedReleaseId(sessionId) {
  return `release-${createHash("sha256")
    .update(sessionId, "utf8")
    .digest("hex")
    .slice(0, 16)}`;
}

function stringMatching(value, pattern) {
  if (
    typeof value !== "string" ||
    !pattern.test(value)
  ) {
    fail();
  }
  return value;
}

function validateScope(value) {
  const releaseId = stringMatching(
    value.releaseId,
    RELEASE,
  );
  const repositorySha = stringMatching(
    value.repositorySha,
    SHA40,
  );
  const sessionId = stringMatching(
    value.sessionId,
    SESSION,
  );
  if (
    value.paymentMoved !== false ||
    releaseId !== expectedReleaseId(sessionId)
  ) {
    fail();
  }
  return Object.freeze({
    releaseId,
    repositorySha,
    sessionId,
  });
}

function path(value) {
  if (
    typeof value !== "string" ||
    !isAbsolute(value) ||
    CONTROL.test(value) ||
    resolve(value) !== value
  ) {
    fail();
  }
  return value;
}

function pathUnder(value, root) {
  const next = path(value);
  if (!next.startsWith(`${root}/`)) {
    fail();
  }
  return next;
}

function exactPath(value, expected) {
  const next = path(value);
  if (next !== expected) fail();
  return next;
}

function instant(value) {
  const next = stringMatching(
    value,
    ISO_INSTANT,
  );
  if (
    Number.isNaN(Date.parse(next)) ||
    new Date(next).toISOString() !== next
  ) {
    fail();
  }
  return next;
}

function secretArn(value) {
  return stringMatching(value, SECRET_ARN);
}

function operatorKeyId(value) {
  return stringMatching(value, OPERATOR_KEY_ID);
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

function relayUrl(value) {
  try {
    if (
      typeof value !== "string" ||
      CONTROL.test(value)
    ) {
      fail();
    }
    const url = new URL(value);
    if (
      url.origin !== value ||
      url.protocol !== "https:" ||
      url.port === "" ||
      url.username !== "" ||
      url.password !== "" ||
      url.pathname !== "/" ||
      url.search !== "" ||
      url.hash !== "" ||
      reservedHostname(url.hostname)
    ) {
      fail();
    }
    return value;
  } catch (error) {
    if (
      error instanceof
      AwsOperatorTaskInputError
    ) {
      throw error;
    }
    fail();
  }
}

function sha64(value) {
  return stringMatching(value, SHA64);
}

function validHostname(value) {
  return (
    typeof value === "string" &&
    /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(value) &&
    !reservedHostname(value)
  );
}

function httpsUrl(value, expectedPath) {
  try {
    if (
      typeof value !== "string" ||
      CONTROL.test(value)
    ) {
      fail();
    }
    const url = new URL(value);
    if (
      url.href !== value ||
      url.protocol !== "https:" ||
      url.username !== "" ||
      url.password !== "" ||
      url.pathname !== expectedPath ||
      url.search !== "" ||
      url.hash !== "" ||
      !validHostname(url.hostname)
    ) {
      fail();
    }
    return url;
  } catch (error) {
    if (error instanceof AwsOperatorTaskInputError) {
      throw error;
    }
    fail();
  }
}

function validTunnelHostKey(publicKey, fingerprint) {
  if (
    typeof publicKey !== "string" ||
    typeof fingerprint !== "string" ||
    !SSH_SHA256_FINGERPRINT.test(fingerprint)
  ) {
    return false;
  }
  const match =
    SSH_ED25519_PUBLIC_KEY.exec(publicKey);
  if (match === null) return false;
  const blob = Buffer.from(match[1], "base64");
  if (blob.toString("base64") !== match[1]) {
    return false;
  }
  let offset = 0;
  const readString = () => {
    if (offset + 4 > blob.length) return null;
    const length = blob.readUInt32BE(offset);
    offset += 4;
    if (offset + length > blob.length) {
      return null;
    }
    const value = blob.subarray(
      offset,
      offset + length,
    );
    offset += length;
    return value;
  };
  const algorithm = readString();
  const key = readString();
  return (
    algorithm?.toString("ascii") ===
      "ssh-ed25519" &&
    key?.length === 32 &&
    offset === blob.length &&
    `SHA256:${createHash("sha256")
      .update(blob)
      .digest("base64")
      .replace(/=+$/u, "")}` === fingerprint
  );
}

function publicStaging(value, scope) {
  const input = exact(
    value,
    PUBLIC_STAGING_KEYS,
  );
  const paths = exact(
    input.paths,
    PUBLIC_STAGING_PATH_KEYS,
  );
  const publicRoot =
    `/var/lib/clockchain/public/releases/${scope.releaseId}`;
  const bootstrapPayerClaimUrl = httpsUrl(
    input.bootstrapPayerClaimUrl,
    "/v1/payer-claims",
  );
  const publicBaseUrl = httpsUrl(
    input.publicBaseUrl,
    "/",
  );
  const publicMcpUrl = httpsUrl(
    input.publicMcpUrl,
    "/mcp",
  );
  if (
    bootstrapPayerClaimUrl.port !== "" ||
    publicMcpUrl.port !== "9443" ||
    input.publicMcpHostname !==
      publicMcpUrl.hostname ||
    !validHostname(input.publicMcpHostname) ||
    !IMAGE.test(input.imageDigest) ||
    !validTunnelHostKey(
      input.tunnelHostPublicKey,
      input.tunnelHostKeyFingerprint,
    )
  ) {
    fail();
  }
  return Object.freeze({
    approvedPayerPublicPath: exactPath(
      input.approvedPayerPublicPath,
      `/var/lib/clockchain/approved-payer/releases/${scope.releaseId}/approved-payer.json`,
    ),
    bootstrapPayerClaimUrl:
      bootstrapPayerClaimUrl.href,
    imageDigest: input.imageDigest,
    paths: Object.freeze({
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
    }),
    publicBaseUrl: publicBaseUrl.href,
    publicMcpHostname:
      input.publicMcpHostname,
    publicMcpUrl: publicMcpUrl.href,
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

function certificatePem(value, fingerprint) {
  try {
    if (
      typeof value !== "string" ||
      value.length === 0 ||
      /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value) ||
      Buffer.byteLength(value, "utf8") > 65_536
    ) {
      fail();
    }
    const certificate = new X509Certificate(value);
    if (
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
      AwsOperatorTaskInputError
    ) {
      throw error;
    }
    fail();
  }
}

function topLevel(key, value) {
  if (key === "verifier") {
    return Object.freeze({
      paymentMoved: false,
      schema: SCHEMA,
      verifier: Object.freeze(value),
    });
  }
  return Object.freeze({
    [key]: Object.freeze(value),
    paymentMoved: false,
    schema: SCHEMA,
  });
}

export function buildCoordinatorRuntimeInput(
  value,
) {
  try {
    const input = exact(value, COORDINATOR_KEYS);
    const scope = validateScope(input);
    const operatorRoot =
      `/var/lib/clockchain/operator/releases/${scope.releaseId}`;
    const releaseRoot = exactPath(
      input.releaseRoot,
      operatorRoot,
    );
    return topLevel("coordinator", {
      clockchainTokenSecretArn: secretArn(
        input.clockchainTokenSecretArn,
      ),
      operatorKeyId: operatorKeyId(
        input.operatorKeyId,
      ),
      operatorKeySecretArn: secretArn(
        input.operatorKeySecretArn,
      ),
      publicStaging: publicStaging(
        input.publicStaging,
        scope,
      ),
      releaseIdentity: Object.freeze({
        releaseId: scope.releaseId,
        sessionId: scope.sessionId,
      }),
      releaseRoot,
      relayUrl: relayUrl(input.relayUrl),
      repositorySha: scope.repositorySha,
      rpcSecretArn: secretArn(
        input.rpcSecretArn,
      ),
      tlsCertificatePem: certificatePem(
        input.tlsCertificatePem,
        input.tlsFingerprint,
      ),
      tlsFingerprint: sha64(
        input.tlsFingerprint,
      ),
    });
  } catch (error) {
    if (
      error instanceof
      AwsOperatorTaskInputError
    ) {
      throw error;
    }
    fail();
  }
}

export function buildFundingRuntimeInput(value) {
  try {
    const input = exact(value, FUNDING_KEYS);
    const scope = validateScope(input);
    const actionId = stringMatching(
      input.actionId,
      ATTEMPT_ID,
    );
    if (
      !Number.isSafeInteger(input.actionAtMs) ||
      input.actionAtMs < 0
    ) {
      fail();
    }
    const fundingRecordPath = pathUnder(
      input.fundingRecordPath,
      `/var/lib/clockchain/funding-record/releases/${scope.releaseId}`,
    );
    const journalDirectory = pathUnder(
      input.journalDirectory,
      `/var/lib/clockchain/funding-journal/releases/${scope.releaseId}`,
    );
    const resultPath = exactPath(
      input.resultPath,
      `/var/lib/clockchain/funding-result/releases/${scope.releaseId}/actions/${actionId}/funding-result.json`,
    );
    const expectedTreasuryAddress =
      stringMatching(
        input.expectedTreasuryAddress,
        ADDRESS,
      );
    if (expectedTreasuryAddress === ZERO_ADDRESS) {
      fail();
    }
    return topLevel("funding", {
      actionAtMs: input.actionAtMs,
      actionId,
      createdAt: instant(input.createdAt),
      expectedTreasuryAddress:
        expectedTreasuryAddress,
      fundingRecordPath,
      journalDirectory,
      keystoreSecretArn: secretArn(
        input.keystoreSecretArn,
      ),
      passwordSecretArn: secretArn(
        input.passwordSecretArn,
      ),
      releaseIdentity: Object.freeze({
        releaseId: scope.releaseId,
        sessionId: scope.sessionId,
      }),
      repositorySha: scope.repositorySha,
      rpcSecretArn: secretArn(
        input.rpcSecretArn,
      ),
      resultPath,
    });
  } catch (error) {
    if (
      error instanceof
      AwsOperatorTaskInputError
    ) {
      throw error;
    }
    fail();
  }
}

export function buildVerifierRuntimeInput(value) {
  try {
    const input = exact(value, VERIFIER_KEYS);
    const scope = validateScope(input);
    const attemptId = stringMatching(
      input.attemptId,
      ATTEMPT_ID,
    );
    if (
      !Number.isSafeInteger(
        input.actionAtMs,
      ) ||
      input.actionAtMs < 0 ||
      !Number.isSafeInteger(
        input.expectedRevision,
      ) ||
      input.expectedRevision < 0
    ) {
      fail();
    }
    const evidenceRoot =
      `/var/lib/clockchain/evidence/releases/${scope.releaseId}/stakeholder`;
    const verifierOutputRoot =
      `/var/lib/clockchain/verifier-output/releases/${scope.releaseId}`;
    const attemptRoot = exactPath(
      input.attemptRoot,
      `${verifierOutputRoot}/attempts/${attemptId}`,
    );
    const descriptorPath = exactPath(
      input.descriptorPath,
      `${evidenceRoot}/descriptor.json`,
    );
    const payerMandatePath = exactPath(
      input.payerMandatePath,
      `${evidenceRoot}/payer-mandate.json`,
    );
    const payeeResultsPath = exactPath(
      input.payeeResultsPath,
      `${evidenceRoot}/payee-results`,
    );
    const payerResultsPath = exactPath(
      input.payerResultsPath,
      `${evidenceRoot}/payer-results`,
    );
    const paymentRequestPath = exactPath(
      input.paymentRequestPath,
      `${evidenceRoot}/payment-request.json`,
    );
    const publicationPath = exactPath(
      input.publicationPath,
      `${verifierOutputRoot}/stakeholder-publication.json`,
    );
    const digests = [
      sha64(input.evidenceDigest),
      sha64(input.mandateDigest),
      sha64(input.requestDigest),
      sha64(input.sessionDigest),
    ];
    if (
      new Set([
        descriptorPath,
        payerMandatePath,
        payeeResultsPath,
        payerResultsPath,
        paymentRequestPath,
        publicationPath,
      ]).size !== 6
    ) {
      fail();
    }
    return topLevel("verifier", {
      actionAtMs: input.actionAtMs,
      attemptId,
      attemptRoot,
      clockchainTokenSecretArn: secretArn(
        input.clockchainTokenSecretArn,
      ),
      descriptorPath,
      evidenceDigest: digests[0],
      expectedRevision:
        input.expectedRevision,
      mandateDigest: digests[1],
      payerMandatePath,
      payeeResultsPath,
      payerResultsPath,
      paymentRequestPath,
      publicationPath,
      repositorySha: scope.repositorySha,
      requestDigest: digests[2],
      rpcSecretArn: secretArn(
        input.rpcSecretArn,
      ),
      sessionDigest: digests[3],
    });
  } catch (error) {
    if (
      error instanceof
      AwsOperatorTaskInputError
    ) {
      throw error;
    }
    fail();
  }
}
