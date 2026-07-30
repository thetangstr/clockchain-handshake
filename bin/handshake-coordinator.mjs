#!/usr/bin/env node
import {
  parseCoordinatorArguments,
  readCoordinatorRuntimeConfig,
  runCoordinatorUntilComplete,
} from "../src/bilateral/coordination/coordinator-runtime.mjs";

export async function main(argv = process.argv.slice(2), dependencies = {}) {
  try {
    const values = parseCoordinatorArguments(argv);
    const config = await readCoordinatorRuntimeConfig(values, dependencies);
    try {
      const result = await runCoordinatorUntilComplete(config, dependencies);
      return result.state === "COMPLETE" ? 0 : 1;
    } finally {
      await config.releaseRoot.handle.close();
    }
  } catch {
    return 1;
  }
}

if (import.meta.url === `file://${process.argv[1]}`) process.exitCode = await main();
