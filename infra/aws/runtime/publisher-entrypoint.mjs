#!/usr/bin/env node

import {
  createAwsRuntimeClients,
} from "./aws-clients.mjs";
import {
  parseRuntimeInput,
} from "./runtime-input.mjs";
import {
  runAwsPublisherLoop,
} from "./publisher-runtime.mjs";

export async function main({
  createClients = createAwsRuntimeClients,
  env = process.env,
  run = runAwsPublisherLoop,
  signal,
} = {}) {
  const input = parseRuntimeInput(env);
  if (
    typeof createClients !== "function" ||
    typeof run !== "function" ||
    input.publisher === null ||
    typeof input.publisher !== "object" ||
    Array.isArray(input.publisher)
  ) {
    throw new Error(
      "AWS publisher entrypoint failed safely.",
    );
  }
  const clients = await createClients();
  await run(input.publisher, {
    s3: clients.s3,
    signal,
    writeRecord: async (record) => {
      process.stdout.write(
        `${JSON.stringify(record)}\n`,
      );
    },
  });
}

if (
  process.argv[1] !== undefined &&
  import.meta.url ===
    new URL(`file://${process.argv[1]}`).href
) {
  const controller = new AbortController();
  const stop = () => controller.abort();
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
  main({
    signal: controller.signal,
  }).catch(() => {
    process.stderr.write(
      "AWS_PUBLISHER_ENTRYPOINT_FAILED\n",
    );
    process.exitCode = 1;
  });
}
