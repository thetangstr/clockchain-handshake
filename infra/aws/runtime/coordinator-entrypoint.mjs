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
  const coordinator =
    input.coordinator;
  if (
    coordinator === null ||
    typeof coordinator !== "object" ||
    Array.isArray(coordinator) ||
    !Array.isArray(coordinator.argv) ||
    coordinator.argv.some(
      (value) =>
        typeof value !== "string" ||
        value.includes("\0"),
    ) ||
    coordinator.releaseIdentity ===
      null ||
    typeof coordinator
      .releaseIdentity !== "object" ||
    Array.isArray(
      coordinator.releaseIdentity,
    ) ||
    !/^release-[0-9a-f]{16}$/.test(
      coordinator.releaseIdentity
        .releaseId,
    ) ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
      coordinator.releaseIdentity
        .sessionId,
    ) ||
    typeof run !== "function"
  ) {
    throw new Error(
      "AWS coordinator entrypoint failed safely.",
    );
  }
  const exitCode = await run(
    coordinator.argv,
    {
      releaseIdentity:
        coordinator.releaseIdentity,
    },
  );
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
