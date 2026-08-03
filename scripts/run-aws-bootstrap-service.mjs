#!/usr/bin/env node

import { pathToFileURL } from "node:url";

import {
  createAwsBootstrapService,
  createAwsBootstrapStateFileStore,
} from "../src/bilateral/aws/bootstrap-service.mjs";
import {
  createBootstrapState,
} from "../src/bilateral/aws/bootstrap-state.mjs";

function fail() {
  throw new Error(
    "AWS bootstrap service adapter failed safely.",
  );
}

function required(env, key) {
  const value = env?.[key];
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.trim() !== value
  ) {
    fail();
  }
  return value;
}

function decimal(env, key, minimum, maximum) {
  const value = required(env, key);
  if (
    !/^(?:0|[1-9][0-9]*)$/.test(value) ||
    BigInt(value) > BigInt(Number.MAX_SAFE_INTEGER)
  ) {
    fail();
  }
  const number = Number(value);
  if (number < minimum || number > maximum) fail();
  return number;
}

export async function createAwsBootstrapServiceFromEnvironment({
  createService = createAwsBootstrapService,
  createStore = createAwsBootstrapStateFileStore,
  env = process.env,
} = {}) {
  try {
    if (
      typeof createService !== "function" ||
      typeof createStore !== "function"
    ) {
      fail();
    }
    const initialState = createBootstrapState({
      paymentMoved: false,
      releaseId: required(
        env,
        "BILATERAL_RELEASE_ID",
      ),
      repositorySha: required(
        env,
        "BILATERAL_REPOSITORY_SHA",
      ),
      schema: "clockchain.aws-bootstrap-state/v1",
      sessionId: required(
        env,
        "BILATERAL_SESSION_ID",
      ),
    });
    const store = await createStore({
      initialState,
      statePath: required(
        env,
        "AWS_BOOTSTRAP_STATE_PATH",
      ),
    });
    return createService({
      brokerCapabilityDigest: required(
        env,
        "AWS_BOOTSTRAP_BROKER_CAPABILITY_DIGEST",
      ),
      claimExpiresAfterMs: decimal(
        env,
        "AWS_BOOTSTRAP_CLAIM_EXPIRES_AFTER_MS",
        1_000,
        1_800_000,
      ),
      host: required(
        env,
        "AWS_BOOTSTRAP_BIND_HOST",
      ),
      port: decimal(
        env,
        "AWS_BOOTSTRAP_PORT",
        1,
        65_535,
      ),
      store,
    });
  } catch {
    fail();
  }
}

export async function main() {
  const service =
    await createAwsBootstrapServiceFromEnvironment();
  await service.start();
  process.stdout.write(
    `${JSON.stringify({
      paymentMoved: false,
      status: "READY",
    })}\n`,
  );
  let stopping = false;
  const stop = async () => {
    if (stopping) return;
    stopping = true;
    await service.stop();
  };
  process.once("SIGINT", () => {
    void stop();
  });
  process.once("SIGTERM", () => {
    void stop();
  });
}

if (
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  main().catch(() => {
    process.stderr.write(
      "AWS_BOOTSTRAP_SERVICE_FAILED\n",
    );
    process.exitCode = 1;
  });
}
