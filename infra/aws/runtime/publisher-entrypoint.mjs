#!/usr/bin/env node

import {
  createAwsRuntimeClients,
} from "./aws-clients.mjs";

async function main() {
  await createAwsRuntimeClients();
  throw new Error(
    "Publisher wiring is supplied by the deployed task definition.",
  );
}

main().catch(() => {
  process.stderr.write(
    "AWS_PUBLISHER_ENTRYPOINT_FAILED\n",
  );
  process.exitCode = 1;
});
