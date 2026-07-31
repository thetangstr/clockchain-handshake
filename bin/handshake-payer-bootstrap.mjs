#!/usr/bin/env node
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

import {
  createProductionPayerBootstrapDependencies,
  runPayerBootstrap,
} from "../src/bilateral/local-mcp/payer-bootstrap-production.mjs";

export const PAYER_BOOTSTRAP_CLI_FLAGS =
  Object.freeze([
    "--discovery-url",
    "--state",
  ]);

const FAILURE_LINE =
  '{"paymentMoved":false,"status":"PAYER_BOOTSTRAP_FAILED"}\n';

function fail() {
  throw new Error(
    "Payer bootstrap CLI failed safely.",
  );
}

function parseArguments(arguments_) {
  if (
    !Array.isArray(arguments_) ||
    arguments_.length !==
      PAYER_BOOTSTRAP_CLI_FLAGS.length * 2
  ) {
    fail();
  }
  const values = Object.create(null);
  for (
    let index = 0;
    index < arguments_.length;
    index += 2
  ) {
    const flag = arguments_[index];
    const value = arguments_[index + 1];
    if (
      !PAYER_BOOTSTRAP_CLI_FLAGS.includes(flag) ||
      typeof value !== "string" ||
      value.length === 0 ||
      Object.hasOwn(values, flag)
    ) {
      fail();
    }
    values[flag] = value;
  }
  let discovery;
  try {
    discovery = new URL(
      values["--discovery-url"],
    );
  } catch {
    fail();
  }
  if (
    discovery.protocol !== "https:" ||
    discovery.username !== "" ||
    discovery.password !== "" ||
    discovery.search !== "" ||
    discovery.hash !== ""
  ) {
    fail();
  }
  const stateRoot = values["--state"];
  if (
    resolve(stateRoot) !== stateRoot ||
    stateRoot === "/"
  ) {
    fail();
  }
  return Object.freeze({
    discoveryUrl: discovery.href,
    stateRoot,
  });
}

export async function main(
  arguments_ = process.argv.slice(2),
  dependencyOverrides = {},
) {
  try {
    const input = parseArguments(arguments_);
    if (
      dependencyOverrides === null ||
      typeof dependencyOverrides !== "object" ||
      Array.isArray(dependencyOverrides) ||
      Object.keys(dependencyOverrides).some(
        (key) =>
          ![
            "createProductionDependencies",
            "runBootstrap",
          ].includes(key),
      )
    ) {
      fail();
    }
    const createDependencies =
      dependencyOverrides.createProductionDependencies ??
      createProductionPayerBootstrapDependencies;
    const run =
      dependencyOverrides.runBootstrap ??
      runPayerBootstrap;
    if (
      typeof createDependencies !== "function" ||
      typeof run !== "function"
    ) {
      fail();
    }
    const dependencies =
      await createDependencies(input);
    return await run(input, dependencies);
  } catch (error) {
    if (
      error?.message ===
      "Payer bootstrap CLI failed safely."
    ) {
      throw error;
    }
    fail();
  }
}

if (
  import.meta.url ===
  pathToFileURL(process.argv[1] ?? "").href
) {
  main().catch(() => {
    process.stdout.write(FAILURE_LINE);
    process.exitCode = 1;
  });
}
