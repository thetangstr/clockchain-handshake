#!/usr/bin/env node

import {
  runAwsVerifierTask,
} from "../../../scripts/run-aws-verifier-task.mjs";
import {
  parseRuntimeInput,
} from "./runtime-input.mjs";

export async function main({
  env = process.env,
  run = runAwsVerifierTask,
} = {}) {
  const input = parseRuntimeInput(env);
  if (
    input.verifier === null ||
    typeof input.verifier !== "object" ||
    Array.isArray(input.verifier) ||
    typeof run !== "function"
  ) {
    throw new Error(
      "AWS verifier entrypoint failed safely.",
    );
  }
  await run(input.verifier);
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
