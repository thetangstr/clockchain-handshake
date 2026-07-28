#!/usr/bin/env node

import { pathToFileURL } from "node:url";

import {
  runPayerRole,
  runRoleCli,
} from "../src/bilateral/roles.mjs";

export async function main(
  arguments_ = process.argv.slice(2),
  dependencies = {},
) {
  return runRoleCli("payer", arguments_, {
    ...dependencies,
    runRole: dependencies.runRole ?? runPayerRole,
  });
}

if (
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  process.exitCode = await main();
}
