#!/usr/bin/env node

import {
  createAwsRuntimeClients,
} from "./aws-clients.mjs";
import {
  parseRuntimeInput,
} from "./runtime-input.mjs";

export async function main({
  createClients = createAwsRuntimeClients,
  env = process.env,
  run,
} = {}) {
  const input = parseRuntimeInput(env);
  if (
    typeof createClients !== "function" ||
    typeof run !== "function"
  ) {
    throw new Error(
      "AWS operator worker entrypoint failed safely.",
    );
  }
  const clients = await createClients();
  await run({
    clients,
    input,
  });
}

if (
  process.argv[1] !== undefined &&
  import.meta.url ===
    new URL(`file://${process.argv[1]}`).href
) {
  main().catch(() => {
    process.stderr.write(
      "AWS_OPERATOR_WORKER_ENTRYPOINT_FAILED\n",
    );
    process.exitCode = 1;
  });
}
