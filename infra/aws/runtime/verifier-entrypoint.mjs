#!/usr/bin/env node

import {
  GetSecretValueCommand,
  SecretsManagerClient,
} from "@aws-sdk/client-secrets-manager";
import {
  rm,
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
  runAwsVerifierTask,
} from "../../../scripts/run-aws-verifier-task.mjs";
import {
  installPrivateFile,
  parseRuntimeInput,
  readSecretString,
} from "./runtime-input.mjs";

const VERIFIER_INPUT_KEYS = Object.freeze([
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
  "paymentRequestPath",
  "publicationPath",
  "repositorySha",
  "requestDigest",
  "rpcSecretArn",
  "sessionDigest",
]);
const ATTEMPT_ID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const CONTROL = /[\u0000-\u001f\u007f]/;
const SHA40 = /^[0-9a-f]{40}$/;
const SHA64 = /^[0-9a-f]{64}$/;
const TASK_ARN =
  /^arn:aws(?:-[a-z]+)?:ecs:[a-z0-9-]+:[0-9]{12}:task\/(?:[A-Za-z0-9_-]{1,255}\/)?[0-9a-f]{32}$/;

class AwsVerifierEntrypointError extends Error {
  constructor() {
    super("AWS verifier entrypoint failed safely.");
    this.name = "AwsVerifierEntrypointError";
  }
}

function fail() {
  throw new AwsVerifierEntrypointError();
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

function validateVerifierInput(value) {
  const verifier = exact(
    value,
    VERIFIER_INPUT_KEYS,
  );
  if (
    !Number.isSafeInteger(
      verifier.actionAtMs,
    ) ||
    verifier.actionAtMs < 0 ||
    !ATTEMPT_ID.test(verifier.attemptId) ||
    !Number.isSafeInteger(
      verifier.expectedRevision,
    ) ||
    verifier.expectedRevision < 0 ||
    !SHA40.test(verifier.repositorySha) ||
    !SHA64.test(verifier.evidenceDigest) ||
    !SHA64.test(verifier.mandateDigest) ||
    !SHA64.test(verifier.requestDigest) ||
    !SHA64.test(verifier.sessionDigest) ||
    typeof verifier
      .clockchainTokenSecretArn !== "string" ||
    typeof verifier.rpcSecretArn !== "string"
  ) {
    fail();
  }
  for (const key of [
    "attemptRoot",
    "descriptorPath",
    "payerMandatePath",
    "payeeResultsPath",
    "payerResultsPath",
    "paymentRequestPath",
    "publicationPath",
  ]) {
    absolutePath(verifier[key]);
  }
  if (
    basename(verifier.attemptRoot) !==
      verifier.attemptId ||
    verifier.publicationPath.startsWith(
      `${verifier.attemptRoot}/`,
    )
  ) {
    fail();
  }
  return verifier;
}

function metadataTaskUrl(env) {
  const raw = env?.ECS_CONTAINER_METADATA_URI_V4;
  if (typeof raw !== "string") fail();
  let url;
  try {
    url = new URL(raw);
  } catch {
    fail();
  }
  if (
    url.protocol !== "http:" ||
    url.hostname !== "169.254.170.2" ||
    url.port !== "" ||
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== "" ||
    url.pathname.length === 0 ||
    url.pathname.length > 256 ||
    url.pathname.includes("//") ||
    raw.endsWith("/")
  ) {
    fail();
  }
  return `${raw}/task`;
}

async function readTaskArn(env, fetcher) {
  try {
    if (typeof fetcher !== "function") fail();
    const response = await fetcher(
      metadataTaskUrl(env),
    );
    if (
      response?.ok !== true ||
      typeof response.json !== "function"
    ) {
      fail();
    }
    const value = exact(
      await response.json(),
      ["TaskARN"],
    );
    if (!TASK_ARN.test(value.TaskARN)) {
      fail();
    }
    return value.TaskARN;
  } catch (error) {
    if (
      error instanceof AwsVerifierEntrypointError
    ) {
      throw error;
    }
    fail();
  }
}

function validClockchainToken(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    !CONTROL.test(value)
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
      url.hash === ""
    );
  } catch {
    return false;
  }
}

export async function main({
  client = new SecretsManagerClient({}),
  env = process.env,
  fetch = globalThis.fetch,
  run = runAwsVerifierTask,
  tempDir = tmpdir(),
} = {}) {
  let tokenPath;
  try {
    const input = exact(parseRuntimeInput(env), [
      "paymentMoved",
      "schema",
      "verifier",
    ]);
    const verifier = validateVerifierInput(
      input.verifier,
    );
    if (typeof run !== "function") fail();
    absolutePath(tempDir);
    const taskArn = await readTaskArn(env, fetch);
    const clockchainToken =
      await readSecretString({
        client,
        commandFactory: (value) =>
          new GetSecretValueCommand(value),
        secretArn:
          verifier.clockchainTokenSecretArn,
        validate: validClockchainToken,
      });
    const rpcUrl = await readSecretString({
      client,
      commandFactory: (value) =>
        new GetSecretValueCommand(value),
      secretArn: verifier.rpcSecretArn,
      validate: validRpcUrl,
    });
    const nextTokenPath = join(
      tempDir,
      "clockchain-token",
    );
    await installPrivateFile({
      path: nextTokenPath,
      value: clockchainToken,
    });
    tokenPath = nextTokenPath;
    return await run({
      actionAtMs: verifier.actionAtMs,
      attemptId: verifier.attemptId,
      attemptRoot: verifier.attemptRoot,
      clockchainTokenFile: nextTokenPath,
      descriptorPath: verifier.descriptorPath,
      evidenceDigest: verifier.evidenceDigest,
      expectedRevision:
        verifier.expectedRevision,
      mandateDigest: verifier.mandateDigest,
      payerMandatePath:
        verifier.payerMandatePath,
      payeeResultsPath:
        verifier.payeeResultsPath,
      payerResultsPath:
        verifier.payerResultsPath,
      paymentRequestPath:
        verifier.paymentRequestPath,
      publicationPath:
        verifier.publicationPath,
      repositorySha: verifier.repositorySha,
      requestDigest: verifier.requestDigest,
      rpcUrl,
      sessionDigest: verifier.sessionDigest,
      taskArn,
    });
  } catch (error) {
    if (
      error instanceof AwsVerifierEntrypointError
    ) {
      throw error;
    }
    fail();
  } finally {
    if (tokenPath !== undefined) {
      await rm(tokenPath, {
        force: true,
      }).catch(() => {});
    }
  }
}

if (
  process.argv[1] !== undefined &&
  import.meta.url ===
    new URL(`file://${process.argv[1]}`).href
) {
  main().catch(() => {
    process.stderr.write(
      "AWS_VERIFIER_ENTRYPOINT_FAILED\n",
    );
    process.exitCode = 1;
  });
}
