#!/usr/bin/env node

import { isAbsolute } from "node:path";
import { pathToFileURL } from "node:url";

import { readHybridOperatorConfig } from "../src/bilateral/local-demo/operator-config.mjs";
import { createProductionHybridOperatorDependencies } from "../src/bilateral/local-demo/operator-production.mjs";
import { runHybridLocalOperator } from "../src/bilateral/local-demo/operator-runtime.mjs";

const FAILURE_LINE =
  '{"paymentMoved":false,"status":"HYBRID_OPERATOR_FAILED"}\n';
const DEPENDENCY_KEYS = Object.freeze([
  "createProductionDependencies",
  "readConfig",
  "runOperator",
  "runRuntime",
  "stdout",
]);

function fail() {
  throw new Error("Hybrid local operator CLI failed safely.");
}

function parseArguments(argv) {
  if (
    !Array.isArray(argv) ||
    argv.length !== 4 ||
    argv[0] !== "--config" ||
    argv[2] !== "--state" ||
    typeof argv[1] !== "string" ||
    argv[1].length === 0 ||
    argv[1].startsWith("--") ||
    argv[1].includes("\0") ||
    typeof argv[3] !== "string" ||
    !isAbsolute(argv[3]) ||
    argv[3] === "/" ||
    argv[3].includes("\0")
  ) {
    fail();
  }
  return Object.freeze({
    configPath: argv[1],
    stateRoot: argv[3],
  });
}

function activeDependencies(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Reflect.ownKeys(value).some((key) => !DEPENDENCY_KEYS.includes(key))
  ) {
    fail();
  }
  const createProductionDependencies = value.createProductionDependencies ??
    createProductionHybridOperatorDependencies;
  const runRuntime = value.runRuntime ?? runHybridLocalOperator;
  if (
    typeof createProductionDependencies !== "function" ||
    typeof runRuntime !== "function"
  ) {
    fail();
  }
  const dependencies = Object.freeze({
    readConfig: value.readConfig ?? readHybridOperatorConfig,
    runOperator: value.runOperator ?? ((input) =>
      runRuntime(input, createProductionDependencies())),
    stdout: value.stdout ?? process.stdout,
  });
  if (
    typeof dependencies.readConfig !== "function" ||
    typeof dependencies.runOperator !== "function" ||
    typeof dependencies.stdout?.write !== "function"
  ) {
    fail();
  }
  return dependencies;
}

export async function main(
  argv = process.argv.slice(2),
  dependencyInput = {},
) {
  let stdout = process.stdout;
  try {
    const dependencies = activeDependencies(dependencyInput);
    stdout = dependencies.stdout;
    const { configPath, stateRoot } = parseArguments(argv);
    const config = await dependencies.readConfig(configPath, stateRoot);
    const result = await dependencies.runOperator({ config, stateRoot });
    if (
      result?.paymentMoved !== false ||
      result.status !== "VERIFICATION_PASSED"
    ) {
      fail();
    }
    return 0;
  } catch {
    try {
      stdout.write(FAILURE_LINE);
    } catch {
      // The CLI has no safe secondary stream when its configured output fails.
    }
    return 1;
  }
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  process.exitCode = await main();
}
