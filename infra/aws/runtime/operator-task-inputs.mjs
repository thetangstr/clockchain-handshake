import {
  createHash,
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
  "releaseId",
  "releaseRoot",
  "relayUrl",
  "repositorySha",
  "rpcSecretArn",
  "sessionId",
  "tlsCertificatePath",
  "tlsFingerprint",
]);
const FUNDING_KEYS = Object.freeze([
  "createdAt",
  "expectedTreasuryAddress",
  "fundingRecordPath",
  "journalDirectory",
  "keystoreSecretArn",
  "passwordSecretArn",
  "paymentMoved",
  "releaseId",
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
      tlsCertificatePath: pathUnder(
        input.tlsCertificatePath,
        operatorRoot,
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
    const fundingRecordPath = pathUnder(
      input.fundingRecordPath,
      `/var/lib/clockchain/funding-record/releases/${scope.releaseId}`,
    );
    const journalDirectory = pathUnder(
      input.journalDirectory,
      `/var/lib/clockchain/funding-journal/releases/${scope.releaseId}`,
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
      repositorySha: scope.repositorySha,
      rpcSecretArn: secretArn(
        input.rpcSecretArn,
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
