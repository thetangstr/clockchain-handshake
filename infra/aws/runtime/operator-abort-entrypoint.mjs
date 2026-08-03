#!/usr/bin/env node

import {
  types,
} from "node:util";

import {
  createAwsOperatorAbortAdapter,
} from "./operator-abort-adapter.mjs";
import {
  parseRuntimeInput,
} from "./runtime-input.mjs";

const ABORT_KEYS = Object.freeze([
  "abortMarkerPath",
  "actionId",
  "expectedRevision",
  "paymentMoved",
  "releaseId",
  "repositorySha",
  "sessionId",
  "tunnelGrantPath",
]);

function exact(value, keys) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    types.isProxy(value) ||
    Object.getPrototypeOf(value) !==
      Object.prototype ||
    Reflect.ownKeys(value).length !==
      keys.length ||
    keys.some(
      (key, index) =>
        Reflect.ownKeys(value)[index] !== key,
    )
  ) {
    throw new Error(
      "AWS operator abort entrypoint failed safely.",
    );
  }
  for (const key of keys) {
    const descriptor =
      Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor?.enumerable !== true ||
      !Object.hasOwn(descriptor, "value")
    ) {
      throw new Error(
        "AWS operator abort entrypoint failed safely.",
      );
    }
  }
  return value;
}

export async function main({
  env = process.env,
  nowMs = () => Date.now(),
} = {}) {
  const input = exact(
    parseRuntimeInput(env).abort,
    ABORT_KEYS,
  );
  const adapter = createAwsOperatorAbortAdapter({
    abortMarkerPath: input.abortMarkerPath,
    nowMs,
    paymentMoved: false,
    releaseId: input.releaseId,
    repositorySha: input.repositorySha,
    sessionId: input.sessionId,
    tunnelGrantPath: input.tunnelGrantPath,
  });
  return adapter.abort({
    actionId: input.actionId,
    expectedRevision: input.expectedRevision,
    paymentMoved: false,
    releaseId: input.releaseId,
    repositorySha: input.repositorySha,
    sessionId: input.sessionId,
  });
}

if (
  process.argv[1] !== undefined &&
  import.meta.url ===
    new URL(`file://${process.argv[1]}`).href
) {
  main().catch(() => {
    process.stderr.write(
      "AWS_OPERATOR_ABORT_ENTRYPOINT_FAILED\n",
    );
    process.exitCode = 1;
  });
}
