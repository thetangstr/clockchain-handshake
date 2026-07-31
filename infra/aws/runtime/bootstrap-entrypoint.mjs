#!/usr/bin/env node

import {
  main as bootstrapMain,
} from "../../../scripts/run-aws-bootstrap-service.mjs";

export async function main() {
  await bootstrapMain();
}

if (
  process.argv[1] !== undefined &&
  import.meta.url ===
    new URL(
      `file://${process.argv[1]}`,
    ).href
) {
  main().catch(() => {
    process.stderr.write(
      "AWS_BOOTSTRAP_ENTRYPOINT_FAILED\n",
    );
    process.exitCode = 1;
  });
}
