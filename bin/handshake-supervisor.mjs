#!/usr/bin/env node
import { runSupervisor } from "../src/bilateral/coordination/supervisor.mjs";
import { createProductionSupervisorDependencies } from "../src/bilateral/coordination/supervisor-runtime.mjs";

export async function main(arguments_ = process.argv.slice(2), dependencies = {}) {
  if (arguments_.length !== 4 || arguments_[0] !== "--launch-manifest" || arguments_[2] !== "--state") throw new Error("Supervisor startup failed safely.");
  const active = Object.keys(dependencies).length === 0 ? await createProductionSupervisorDependencies({ launchManifestPath: arguments_[1], stateRoot: arguments_[3] }) : dependencies;
  return runSupervisor({ launchManifestPath: arguments_[1], stateRoot: arguments_[3], dependencies: active });
}

if (import.meta.url === `file://${process.argv[1]}`) main().catch(() => { process.exitCode = 1; });
