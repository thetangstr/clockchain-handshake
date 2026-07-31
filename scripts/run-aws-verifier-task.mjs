#!/usr/bin/env node

import {
  constants,
} from "node:fs";
import {
  open,
  readFile,
  readdir,
} from "node:fs/promises";
import {
  basename,
  isAbsolute,
} from "node:path";
import { types } from "node:util";

import {
  main as verifierMain,
} from "./verify-bilateral-results.mjs";
import {
  validatePublishedBilateralVerdict,
} from "../src/bilateral/verdict.mjs";

const INPUT_KEYS = Object.freeze([
  "actionAtMs",
  "attemptId",
  "attemptRoot",
  "clockchainTokenFile",
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
  "rpcUrl",
  "sessionDigest",
  "taskArn",
]);
const OUTPUT_FILES = Object.freeze([
  ".bilateral-verdict.complete.json",
  "BILATERAL-VERDICT.md",
  "bilateral-verdict.json",
]);
const ATTEMPT_ID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA40 = /^[0-9a-f]{40}$/;
const SHA64 = /^[0-9a-f]{64}$/;
const TASK_ARN =
  /^arn:aws(?:-[a-z]+)?:ecs:[a-z0-9-]+:[0-9]{12}:task\/(?:[A-Za-z0-9_-]{1,255}\/)?[0-9a-f]{32}$/;

export class AwsVerifierTaskError extends Error {
  constructor() {
    super("AWS verifier task failed safely.");
    this.name = "AwsVerifierTaskError";
    this.code = "AWS_VERIFIER_TASK_FAILED";
    this.category = "verification";
  }
}

function fail() {
  throw new AwsVerifierTaskError();
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
    value.includes("\0") ||
    value.includes("\n") ||
    value.includes("\r")
  ) {
    fail();
  }
  return value;
}

function validateInput(value) {
  const input = exact(value, INPUT_KEYS);
  if (
    !Number.isSafeInteger(input.actionAtMs) ||
    input.actionAtMs < 0 ||
    !ATTEMPT_ID.test(input.attemptId) ||
    !Number.isSafeInteger(
      input.expectedRevision,
    ) ||
    input.expectedRevision < 0 ||
    !SHA40.test(input.repositorySha) ||
    !SHA64.test(input.evidenceDigest) ||
    !SHA64.test(input.mandateDigest) ||
    !SHA64.test(input.requestDigest) ||
    !SHA64.test(input.sessionDigest) ||
    !TASK_ARN.test(input.taskArn)
  ) {
    fail();
  }
  for (const key of [
    "attemptRoot",
    "clockchainTokenFile",
    "descriptorPath",
    "payerMandatePath",
    "payeeResultsPath",
    "payerResultsPath",
    "paymentRequestPath",
    "publicationPath",
  ]) {
    absolutePath(input[key]);
  }
  if (
    basename(input.attemptRoot) !==
      input.attemptId ||
    input.publicationPath.startsWith(
      `${input.attemptRoot}/`,
    )
  ) {
    fail();
  }
  let rpc;
  try {
    rpc = new URL(input.rpcUrl);
  } catch {
    fail();
  }
  if (
    rpc.protocol !== "https:" ||
    rpc.username !== "" ||
    rpc.password !== "" ||
    rpc.hash !== ""
  ) {
    fail();
  }
  return input;
}

function validateVerdict(value, repositorySha) {
  if (
    !plain(value) ||
    value.paymentMoved !== false ||
    value.repositorySha !== repositorySha ||
    !Array.isArray(value.transitions) ||
    value.transitions.length !== 3 ||
    value.transitions.some(
      (transition) => !plain(transition),
    )
  ) {
    fail();
  }
  const anchors = value.transitions.map(
    ({ kind }) => kind,
  );
  if (
    anchors.some(
      (kind, index) =>
        kind !== [
          "PROPOSED",
          "ACCEPTED",
          "ACKNOWLEDGED",
        ][index],
    )
  ) {
    fail();
  }
  return Object.freeze(anchors);
}

async function defaultReadVerdict(root) {
  const bytes = await readFile(
    `${root}/bilateral-verdict.json`,
  );
  if (bytes.length > 1024 * 1024) fail();
  return JSON.parse(bytes.toString("utf8"));
}

async function defaultWritePublication(
  publication,
  path,
) {
  const handle = await open(
    path,
    constants.O_WRONLY |
      constants.O_CREAT |
      constants.O_EXCL |
      (constants.O_NOFOLLOW ?? 0),
    0o600,
  );
  try {
    await handle.writeFile(
      `${JSON.stringify(publication)}\n`,
    );
    await handle.sync();
  } finally {
    await handle.close();
  }
}

export async function runAwsVerifierTask(
  value,
  dependencies = {},
) {
  try {
    const input = validateInput(value);
    const run =
      dependencies.verifierMain ??
      verifierMain;
    const listOutputFiles =
      dependencies.listOutputFiles ??
      readdir;
    const readVerdict =
      dependencies.readVerdict ??
      defaultReadVerdict;
    const validatePublication =
      dependencies.validatePublication ??
      validatePublishedBilateralVerdict;
    const writePublication =
      dependencies.writePublication ??
      (
        (publication) =>
          defaultWritePublication(
            publication,
            input.publicationPath,
          )
      );
    const nowMs =
      dependencies.nowMs ?? Date.now;
    const stdout =
      dependencies.verifierStdout ??
      process.stdout;
    const stderr =
      dependencies.verifierStderr ??
      process.stderr;
    if (
      typeof run !== "function" ||
      typeof listOutputFiles !== "function" ||
      typeof readVerdict !== "function" ||
      typeof validatePublication !==
        "function" ||
      typeof writePublication !== "function" ||
      typeof nowMs !== "function" ||
      typeof stdout?.write !== "function" ||
      typeof stderr?.write !== "function"
    ) {
      fail();
    }
    let taskResult = null;
    const beforeAuthorizationOutput =
      async ({ output }) => {
        if (output !== input.attemptRoot) {
          fail();
        }
        const files = await listOutputFiles(
          input.attemptRoot,
        );
        if (
          !Array.isArray(files) ||
          files.length !== OUTPUT_FILES.length ||
          [...files].sort().some(
            (name, index) =>
              name !== OUTPUT_FILES[index],
          )
        ) {
          fail();
        }
        const validated =
          await validatePublication({
            mandateDigest:
              input.mandateDigest,
            outputDirectory:
              input.attemptRoot,
            repositorySha:
              input.repositorySha,
            requestDigest:
              input.requestDigest,
            sessionDigest:
              input.sessionDigest,
          });
        if (
          !plain(validated) ||
          validated.status !==
            "VERIFICATION_PASSED" ||
          !SHA64.test(
            validated.publicationDigest,
          )
        ) {
          fail();
        }
        const anchors = validateVerdict(
          await readVerdict(
            input.attemptRoot,
          ),
          input.repositorySha,
        );
        const writtenAtMs = nowMs();
        if (
          !Number.isSafeInteger(
            writtenAtMs,
          ) ||
          writtenAtMs < input.actionAtMs
        ) {
          fail();
        }
        const publication = Object.freeze({
          attemptId: input.attemptId,
          evidenceDigest:
            input.evidenceDigest,
          paymentMoved: false,
          publicationDigest:
            validated.publicationDigest,
          repositorySha:
            input.repositorySha,
          revision:
            input.expectedRevision,
          schema:
            "clockchain.aws-verifier-task-publication/v1",
          status: "VERIFICATION_PASSED",
          taskArn: input.taskArn,
          writtenAtMs: String(writtenAtMs),
        });
        await writePublication(publication);
        taskResult = Object.freeze({
          anchors,
          paymentMoved: false,
          publicationDigest:
            publication.publicationDigest,
          verifier: Object.freeze({
            status: "VERIFIED",
          }),
        });
      };
    const exitCode = await run(
      [
        "--clockchain-token-file",
        input.clockchainTokenFile,
        "--descriptor",
        input.descriptorPath,
        "--output",
        input.attemptRoot,
        "--payer-mandate",
        input.payerMandatePath,
        "--payee-results",
        input.payeeResultsPath,
        "--payer-results",
        input.payerResultsPath,
        "--payment-request",
        input.paymentRequestPath,
        "--rpc-url",
        input.rpcUrl,
      ],
      {
        beforeAuthorizationOutput,
        ...(typeof dependencies
          .buildVerifierInput === "function"
          ? {
              buildVerifierInput:
                dependencies
                  .buildVerifierInput,
            }
          : {}),
        stderr,
        stdout,
      },
    );
    if (
      exitCode !== 0 ||
      taskResult === null
    ) {
      fail();
    }
    return taskResult;
  } catch (error) {
    if (error instanceof AwsVerifierTaskError) {
      throw error;
    }
    fail();
  }
}
