#!/usr/bin/env node

import {
  main as coordinatorMain,
} from "../../../bin/handshake-coordinator.mjs";
import {
  parseRuntimeInput,
} from "./runtime-input.mjs";

export async function main({
  env = process.env,
  run = coordinatorMain,
} = {}) {
  const input = parseRuntimeInput(env);
  if (
    !Array.isArray(input.argv) ||
    input.argv.some(
      (value) =>
        typeof value !== "string" ||
        value.includes("\0"),
    ) ||
    typeof run !== "function"
  ) {
    throw new Error(
      "AWS coordinator entrypoint failed safely.",
    );
  }
  const exitCode = await run(input.argv);
  if (exitCode !== 0) {
    throw new Error(
      "AWS coordinator entrypoint failed safely.",
    );
  }
}

if (
  process.argv[1] !== undefined &&
  import.meta.url ===
    new URL(`file://${process.argv[1]}`).href
) {
  main().catch(() => {
    process.stderr.write(
      "AWS_COORDINATOR_ENTRYPOINT_FAILED\n",
    );
    process.exitCode = 1;
  });
}
