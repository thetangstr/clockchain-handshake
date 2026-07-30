#!/usr/bin/env node
import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { readLaunchManifest } from "../src/bilateral/coordination/manifest.mjs";
import { createProductionSupervisorDependencies } from "../src/bilateral/coordination/supervisor-runtime.mjs";
import { runSupervisor } from "../src/bilateral/coordination/supervisor.mjs";
import { requestPaymentThroughPayerMcp } from "../src/bilateral/local-mcp/client.mjs";

export const REQUEST_PAYMENT_CLI_FLAGS = Object.freeze([
  "--launch-manifest",
  "--intake-request-id",
  "--mcp-url",
  "--state",
  "--tls-certificate",
  "--tls-fingerprint",
]);
const execFileAsync = promisify(execFile);
const FAILURE_LINE = '{"code":"REQUEST_PAYMENT_FAILED","paymentMoved":false}\n';
const HANDSHAKE_REQUIRED_LINE = '{"paymentMoved":false,"status":"HANDSHAKE_REQUIRED"}\n';
const SHA_PATTERN = /^[0-9a-f]{40}$/;
const REQUEST_PAYMENT_REPOSITORY_ROOT = resolve(fileURLToPath(new URL("../", import.meta.url)));
const GIT_ENV = Object.freeze(Object.assign(Object.create(null), {
  GIT_ATTR_NOSYSTEM: "1",
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_SYSTEM: "/dev/null",
  GIT_NO_REPLACE_OBJECTS: "1",
  GIT_OPTIONAL_LOCKS: "0",
  GIT_TERMINAL_PROMPT: "0",
  LANG: "C",
  LC_ALL: "C",
  PATH: "/usr/bin:/bin",
}));
const GIT_PREFIX = Object.freeze(["--no-pager", "--no-replace-objects", "-c", "core.attributesFile=/dev/null", "-c", "core.excludesFile=/dev/null", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.untrackedCache=false", "-C"]);

function fail() {
  throw new Error("Request payment startup failed safely.");
}

function sanitize(error) {
  if (error?.message === "Request payment startup failed safely.") throw error;
  fail();
}

function parseArguments(arguments_) {
  if (!Array.isArray(arguments_) || arguments_.length !== REQUEST_PAYMENT_CLI_FLAGS.length * 2) fail();
  const parsed = Object.create(null);
  for (let index = 0; index < arguments_.length; index += 2) {
    const flag = arguments_[index];
    const value = arguments_[index + 1];
    if (!REQUEST_PAYMENT_CLI_FLAGS.includes(flag) || typeof value !== "string" || Object.hasOwn(parsed, flag)) fail();
    parsed[flag] = value;
  }
  if (REQUEST_PAYMENT_CLI_FLAGS.some((flag) => !Object.hasOwn(parsed, flag))) fail();
  const launchManifestPath = absolutePrivatePath(parsed["--launch-manifest"]);
  const stateRoot = absolutePrivatePath(parsed["--state"]);
  const tlsCertificatePath = absolutePrivatePath(parsed["--tls-certificate"]);
  if (stateRoot === launchManifestPath || stateRoot === tlsCertificatePath || stateRoot === "/") fail();
  return Object.freeze({
    intakeRequestId: parsed["--intake-request-id"],
    launchManifestPath,
    mcpUrl: parsed["--mcp-url"],
    stateRoot,
    tlsCertificatePath,
    tlsFingerprint: parsed["--tls-fingerprint"],
  });
}

function absolutePrivatePath(value) {
  if (typeof value !== "string" || value.length === 0 || resolve(value) !== value || value === "/") fail();
  return value;
}

async function inspectRepository(repositoryRoot = REQUEST_PAYMENT_REPOSITORY_ROOT) {
  const cwd = resolve(repositoryRoot);
  const git = (arguments_) => execFileAsync("/usr/bin/git", arguments_, {
    cwd,
    encoding: "utf8",
    env: GIT_ENV,
    maxBuffer: 8192,
  });
  const run = (arguments_) => git([...GIT_PREFIX, cwd, ...arguments_]);
  const { stdout: head } = await run(["rev-parse", "--verify", "HEAD^{commit}"]);
  const { stdout: status } = await run(["status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none"]);
  let detached = false;
  try {
    await run(["symbolic-ref", "-q", "HEAD"]);
  } catch (error) {
    detached = error?.code === 1;
  }
  const normalizedHead = head.trim();
  if (!SHA_PATTERN.test(normalizedHead)) fail();
  return Object.freeze({ clean: status === "", detached, head: normalizedHead });
}

function validateRepositoryProof(value) {
  if (!value || value.clean !== true || value.detached !== true || typeof value.head !== "string" || !SHA_PATTERN.test(value.head)) fail();
  return value.head;
}

export async function main(arguments_ = process.argv.slice(2), dependencies = {}) {
  try {
    const parsed = parseArguments(arguments_);
    const inspect = dependencies.inspectRepository ?? inspectRepository;
    if (typeof inspect !== "function") fail();
    const verifiedHead = validateRepositoryProof(await inspect(REQUEST_PAYMENT_REPOSITORY_ROOT));
    const reader = dependencies.readLaunchManifest ?? readLaunchManifest;
    const manifest = await reader(parsed.launchManifestPath);
    if (
      manifest?.role !== "payee" ||
      typeof manifest.payerMcpIntakeCapability !== "string" ||
      manifest.repositorySha !== verifiedHead
    ) {
      fail();
    }
    const readTextFile = dependencies.readTextFile ?? ((path) => readFile(path, "utf8"));
    const tlsCertificatePem = await readTextFile(parsed.tlsCertificatePath);
    const requestPayment = dependencies.requestPayment ?? requestPaymentThroughPayerMcp;
    const intakeResult = await requestPayment({
      capability: manifest.payerMcpIntakeCapability,
      intakeRequestId: parsed.intakeRequestId,
      mcpUrl: parsed.mcpUrl,
      repositorySha: manifest.repositorySha,
      stateRoot: parsed.stateRoot,
      tlsCertificatePem,
      tlsFingerprint: parsed.tlsFingerprint,
    });
    if (intakeResult?.status !== "HANDSHAKE_REQUIRED" || intakeResult.paymentMoved !== false) fail();
    const writeStatus = dependencies.writeStatus ?? (() => process.stdout.write(HANDSHAKE_REQUIRED_LINE));
    writeStatus(Object.freeze({ paymentMoved: false, status: "HANDSHAKE_REQUIRED" }));
    const supervisor = dependencies.runSupervisor ?? (async (input) => runSupervisor({
      launchManifestPath: input.launchManifestPath,
      stateRoot: input.stateRoot,
      dependencies: await (dependencies.createSupervisorDependencies ?? createProductionSupervisorDependencies)({
        launchManifestPath: input.launchManifestPath,
        stateRoot: input.stateRoot,
      }),
    }));
    return await supervisor({
      launchManifestPath: parsed.launchManifestPath,
      stateRoot: parsed.stateRoot,
    });
  } catch (error) {
    sanitize(error);
  }
  fail();
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(() => {
    process.stdout.write(FAILURE_LINE);
    process.exitCode = 1;
  });
}
