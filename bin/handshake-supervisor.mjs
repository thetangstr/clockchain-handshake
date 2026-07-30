#!/usr/bin/env node
import { runSupervisor } from "../src/bilateral/coordination/supervisor.mjs";
import { createProductionSupervisorDependencies as defaultCreateProductionSupervisorDependencies, createSupervisorStatusLine } from "../src/bilateral/coordination/supervisor-runtime.mjs";

const BASE_OPTIONS = Object.freeze(["--launch-manifest", "--state"]);
const PAYER_MCP_OPTIONS = Object.freeze(["--payer-mcp-host", "--payer-mcp-port", "--payer-mcp-tls-certificate", "--payer-mcp-tls-private-key"]);
const PAYER_MCP_PUBLIC_OPTION = "--payer-mcp-public-url";

function fail() {
  throw new Error("Supervisor startup failed safely.");
}

function parsePort(value) {
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]{0,4})$/.test(value)) fail();
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) fail();
  return port;
}

function parseArguments(arguments_) {
  if (!Array.isArray(arguments_) || ![4, 12, 14].includes(arguments_.length)) fail();
  const values = Object.create(null);
  for (let index = 0; index < arguments_.length; index += 2) {
    const key = arguments_[index];
    const value = arguments_[index + 1];
    if (![...BASE_OPTIONS, ...PAYER_MCP_OPTIONS, PAYER_MCP_PUBLIC_OPTION].includes(key) || typeof value !== "string" || value.length === 0 || Object.hasOwn(values, key)) fail();
    values[key] = value;
  }
  if (!BASE_OPTIONS.every((key) => Object.hasOwn(values, key))) fail();
  const suppliedMcp = PAYER_MCP_OPTIONS.filter((key) => Object.hasOwn(values, key));
  if (suppliedMcp.length !== 0 && suppliedMcp.length !== PAYER_MCP_OPTIONS.length) fail();
  if (Object.hasOwn(values, PAYER_MCP_PUBLIC_OPTION) && suppliedMcp.length !== PAYER_MCP_OPTIONS.length) fail();
  return Object.freeze({
    launchManifestPath: values["--launch-manifest"],
    payerMcpServerOptions: suppliedMcp.length === 0 ? undefined : Object.freeze({
      host: values["--payer-mcp-host"],
      port: parsePort(values["--payer-mcp-port"]),
      ...(Object.hasOwn(values, PAYER_MCP_PUBLIC_OPTION) ? { publicUrl: values[PAYER_MCP_PUBLIC_OPTION] } : {}),
      tlsCertificatePath: values["--payer-mcp-tls-certificate"],
      tlsPrivateKeyPath: values["--payer-mcp-tls-private-key"],
    }),
    stateRoot: values["--state"],
  });
}

export async function main(arguments_ = process.argv.slice(2), dependencies = {}) {
  const parsed = parseArguments(arguments_);
  const productionFactory = dependencies.createProductionSupervisorDependencies ?? defaultCreateProductionSupervisorDependencies;
  const active = Object.keys(dependencies).length === 0 || dependencies.createProductionSupervisorDependencies
    ? await productionFactory(parsed)
    : dependencies;
  const supervisor = active.runSupervisor ?? runSupervisor;
  return supervisor({ launchManifestPath: parsed.launchManifestPath, stateRoot: parsed.stateRoot, dependencies: active });
}

if (import.meta.url === `file://${process.argv[1]}`) main().catch(() => {
  process.stdout.write(createSupervisorStatusLine({
    code: "COORDINATION_SUPERVISOR_FAILED",
    paymentMoved: false,
  }));
  process.exitCode = 1;
});
