#!/usr/bin/env node

import { pathToFileURL } from "node:url";

import {
  runPayeeRole,
  runRoleCli,
} from "../src/bilateral/roles.mjs";

export async function main(
  arguments_ = process.argv.slice(2),
  dependencies = {},
) {
  return runRoleCli("payee", arguments_, {
    ...dependencies,
    runRole: dependencies.runRole ?? runPayeeRole,
  });
}

if (
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  process.exitCode = await main();
}
