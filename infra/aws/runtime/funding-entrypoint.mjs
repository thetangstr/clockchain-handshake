#!/usr/bin/env node

import {
  GetSecretValueCommand,
  SecretsManagerClient,
} from "@aws-sdk/client-secrets-manager";

import {
  runAwsFundingTask,
} from "../../../scripts/run-aws-funding-task.mjs";
import {
  parseRuntimeInput,
  readSecretString,
} from "./runtime-input.mjs";

export async function main({
  client = new SecretsManagerClient({}),
  env = process.env,
  run = runAwsFundingTask,
} = {}) {
  const input = parseRuntimeInput(env);
  if (
    input.funding === null ||
    typeof input.funding !== "object" ||
    Array.isArray(input.funding) ||
    typeof run !== "function"
  ) {
    throw new Error(
      "AWS funding entrypoint failed safely.",
    );
  }
  await run(input.funding, {
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
  });
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
