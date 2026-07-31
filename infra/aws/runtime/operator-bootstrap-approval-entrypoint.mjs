#!/usr/bin/env node

import {
  createPrivateKey,
} from "node:crypto";
import {
  types,
} from "node:util";
import {
  GetSecretValueCommand,
} from "@aws-sdk/client-secrets-manager";

import {
  createAwsRuntimeClients,
} from "./aws-clients.mjs";
import {
  createAwsOperatorBootstrapAdapter,
} from "./operator-bootstrap-adapter.mjs";
import {
  parseRuntimeInput,
  readSecretString,
} from "./runtime-input.mjs";

function validateEd25519PrivateKeyPem(value) {
  try {
    return (
      createPrivateKey(value).asymmetricKeyType ===
      "ed25519"
    );
  } catch {
    return false;
  }
}

function validateCapability(value) {
  return /^[0-9a-f]{64}$/.test(value);
}

const BOOTSTRAP_APPROVAL_KEYS = Object.freeze([
  "claimFingerprint",
  "operatorKeySecretArn",
  "bootstrapBrokerCapabilitySecretArn",
  "bootstrapBrokerUrl",
  "bootstrapStatePath",
  "expectedRevision",
  "operatorKeyId",
  "paymentMoved",
  "payeeLaunchManifestPath",
  "payerLaunchManifestPath",
  "publicMcpHostname",
  "releaseId",
  "repositorySha",
  "role",
  "sessionId",
  "tunnelGrantPath",
]);

function exact(value, keys) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    types.isProxy(value) ||
    Object.getPrototypeOf(value) !==
      Object.prototype ||
    Reflect.ownKeys(value).length !==
      keys.length ||
    keys.some(
      (key, index) =>
        Reflect.ownKeys(value)[index] !== key,
    )
  ) {
    throw new Error(
      "AWS operator bootstrap approval entrypoint failed safely.",
    );
  }
  for (const key of keys) {
    const descriptor =
      Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor?.enumerable !== true ||
      !Object.hasOwn(descriptor, "value")
    ) {
      throw new Error(
        "AWS operator bootstrap approval entrypoint failed safely.",
      );
    }
  }
  return value;
}

export async function main({
  createClients = createAwsRuntimeClients,
  env = process.env,
  nowMs = () => Date.now(),
} = {}) {
  const input =
    exact(
      parseRuntimeInput(env).bootstrapApproval,
      BOOTSTRAP_APPROVAL_KEYS,
    );
  const clients = await createClients();
  const operatorPrivateKeyPem =
    await readSecretString({
      client: clients.secrets,
      commandFactory: (request) =>
        new GetSecretValueCommand(request),
      secretArn: input.operatorKeySecretArn,
      validate: validateEd25519PrivateKeyPem,
    });
  const bootstrapBrokerCapability =
    await readSecretString({
      client: clients.secrets,
      commandFactory: (request) =>
        new GetSecretValueCommand(request),
      secretArn:
        input.bootstrapBrokerCapabilitySecretArn,
      validate: validateCapability,
    });
  const adapter =
    createAwsOperatorBootstrapAdapter({
      bootstrapBrokerCapability,
      bootstrapBrokerUrl:
        input.bootstrapBrokerUrl,
      bootstrapStatePath:
        input.bootstrapStatePath,
      nowMs,
      operatorKeyId: input.operatorKeyId,
      operatorPrivateKeyPem,
      payeeLaunchManifestPath:
        input.payeeLaunchManifestPath,
      payerLaunchManifestPath:
        input.payerLaunchManifestPath,
      publicMcpHostname:
        input.publicMcpHostname,
      releaseId: input.releaseId,
      repositorySha: input.repositorySha,
      sessionId: input.sessionId,
      tunnelGrantPath:
        input.tunnelGrantPath,
    });
  return adapter.approveAndSeal({
    claimFingerprint:
      input.claimFingerprint,
    expectedRevision:
      input.expectedRevision,
    paymentMoved: false,
    releaseId: input.releaseId,
    repositorySha: input.repositorySha,
    role: input.role,
    sessionId: input.sessionId,
  });
}

if (
  process.argv[1] !== undefined &&
  import.meta.url ===
    new URL(`file://${process.argv[1]}`).href
) {
  main().catch(() => {
    process.stderr.write(
      "AWS_OPERATOR_BOOTSTRAP_APPROVAL_ENTRYPOINT_FAILED\n",
    );
    process.exitCode = 1;
  });
}
