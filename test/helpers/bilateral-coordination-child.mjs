#!/usr/bin/env node
// Test-only process driver. It imports production parsers/builders while
// injecting the localhost fake only through explicit test configuration.
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, readFile, writeFile } from "node:fs/promises";
import { Agent, request as httpsRequest } from "node:https";
import process from "node:process";

import { buildDefaultRoleInput, runBillyRole, runIrisRole } from "../../src/bilateral/roles.mjs";
import { main as proposeMain } from "../../bin/handshake-propose.mjs";
import { main as acceptMain } from "../../bin/handshake-accept.mjs";
import { buildDefaultVerifierInput, main as verifierMain } from "../../scripts/verify-bilateral-results.mjs";
import { createFakeBilateralClockchainHttpClient } from "./fake-bilateral-clockchain-service.mjs";

const SCHEMA = "clockchain.bilateral-coordination-process-child/v1";
const MODES = new Set(["coordinator", "payer", "payee", "verifier"]);
const CHILD_DEADLINE_MS = 20_000;
const STOP_GRACE_MS = 1_000;
const BARRIER_DEADLINE_MS = 5_000;

function fail() {
  throw new Error("process child rejected its configuration");
}

function exact(value, keys) {
  return value !== null
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).length === keys.length
    && keys.every((key) => Object.hasOwn(value, key));
}

function canonicalJson(value) {
  if (value === null || ["string", "boolean", "number"].includes(typeof value)) {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype) {
    return `{${Object.keys(value).sort().map(
      (key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`,
    ).join(",")}}`;
  }
  fail();
}

function identity(owners) {
  return Object.freeze({
    async getChainId() {
      return 11155111;
    },
    async readContract({ args }) {
      const owner = owners[String(args[0])];
      if (typeof owner !== "string") throw new Error("unknown agent");
      return owner;
    },
  });
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function absolute(path) {
  return typeof path === "string" && path.startsWith("/") && path.length < 4096;
}

function parse(argv) {
  if (!Array.isArray(argv) || argv.length !== 3 || !MODES.has(argv[0]) || argv[1] !== "--configuration" || !absolute(argv[2])) fail();
  return { mode: argv[0], path: argv[2] };
}

async function config(path) {
  const info = await lstat(path);
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || (info.mode & 0o777) !== 0o600 || info.size < 2 || info.size > 65536) fail();
  const handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = await handle.stat();
    if (opened.dev !== info.dev || opened.ino !== info.ino) fail();
    const bytes = Buffer.alloc(info.size);
    const { bytesRead } = await handle.read(bytes, 0, bytes.length, 0);
    if (bytesRead !== bytes.length) fail();
    const value = JSON.parse(bytes.toString("utf8"));
    if (canonicalJson(value) !== bytes.toString("utf8")) fail();
    return value;
  } finally { await handle.close(); }
}

function validFake(value) {
  return exact(value, ["host", "paymentMoved", "pid", "port", "schema"])
    && value.schema === "clockchain.fake-bilateral-clockchain-listen/v1"
    && value.host === "127.0.0.1"
    && value.paymentMoved === false
    && Number.isInteger(value.pid)
    && Number.isInteger(value.port);
}

function roleDependencies(value, role) {
  if (!exact(value, ["arguments", "fake", "owners", "schema"])
    || value.schema !== SCHEMA
    || !Array.isArray(value.arguments)
    || !validFake(value.fake)
    || !exact(value.owners, ["8677", "8678"])) fail();
  const buildRoleInput = (values, requestedRole) => buildDefaultRoleInput(
    values,
    requestedRole,
    {
      createClockchainClient: () => createFakeBilateralClockchainHttpClient(value.fake),
      createIdentityClient: () => identity(value.owners),
    },
  );
  const runner = role === "payer" ? runBillyRole : runIrisRole;
  let elapsed = 0;
  return {
    buildRoleInput,
    runRole: async (input) => runner({
      ...input,
      jitter: () => 0,
      monotonicNow: () => elapsed,
      now: () => 1_784_923_200_000,
      sleeper: async () => {
        elapsed += 1;
        await new Promise((resolve) => setImmediate(resolve));
      },
    }),
  };
}
async function runRole(value, role) {
  const dependencies = roleDependencies(value, role);
  const result = role === "payer"
    ? await proposeMain(value.arguments, dependencies)
    : await acceptMain(value.arguments, dependencies);
  if (result !== 0) fail();
}

async function runVerifier(value) {
  if (!exact(value, ["arguments", "fake", "owners", "schema"])
    || value.schema !== SCHEMA
    || !Array.isArray(value.arguments)
    || !validFake(value.fake)
    || !exact(value.owners, ["8677", "8678"])) fail();
  const result = await verifierMain(value.arguments, {
    buildVerifierInput: (values) => buildDefaultVerifierInput(values, {
      createClockchainClient: () => createFakeBilateralClockchainHttpClient(value.fake),
      createIdentityClient: () => identity(value.owners),
    }),
  });
  if (result !== 0) fail();
}

async function tlsProbe(relay) {
  const ca = await readFile(relay.ca);
  const agent = new Agent({ ca, keepAlive: false, maxCachedSessions: 0 });
  try {
    await new Promise((resolve, reject) => {
      const request = httpsRequest({ agent, ca, host: "127.0.0.1", method: "GET", path: "/v1/bootstrap", port: relay.port, rejectUnauthorized: true, servername: "localhost", headers: { host: `127.0.0.1:${relay.port}` } }, (response) => {
        const certificate = response.socket.getPeerCertificate(true);
        const fingerprint = certificate.raw && createHash("sha256").update(certificate.raw).digest("hex");
        response.resume();
        response.once("end", () => response.statusCode === 400 && fingerprint === relay.fingerprint ? resolve() : reject(new Error("relay probe failed")));
      });
      request.once("error", reject);
      request.end();
    });
  } finally { agent.destroy(); }
}

function childExited(child) {
  return child.exitCode !== null || child.signalCode !== null;
}

async function terminate(child) {
  if (childExited(child)) return;
  child.kill("SIGTERM");
  await Promise.race([
    new Promise((resolve) => child.once("close", resolve)),
    sleep(STOP_GRACE_MS),
  ]);
  if (!childExited(child)) {
    child.kill("SIGKILL");
    await new Promise((resolve) => child.once("close", resolve));
  }
}

async function waitForChild(child) {
  if (childExited(child)) return { code: child.exitCode, signal: child.signalCode };
  return new Promise((resolve, reject) => {
    const timer = setTimeout(async () => {
      try { await terminate(child); reject(new Error("child deadline expired")); } catch (error) { reject(error); }
    }, CHILD_DEADLINE_MS);
    child.once("error", (error) => { clearTimeout(timer); reject(error); });
    child.once("close", (code, signal) => { clearTimeout(timer); resolve({ code, signal }); });
  });
}
async function start(configuration) {
  const stdout = await open(configuration.logs.stdout, "wx", 0o600);
  const stderr = await open(configuration.logs.stderr, "wx", 0o600);
  try {
    return spawn(process.execPath, [
      process.argv[1],
      configuration.mode,
      "--configuration",
      configuration.path,
    ], { stdio: ["ignore", stdout, stderr] });
  } finally {
    await stdout.close();
    await stderr.close();
  }
}

async function writeExclusive(path, value) {
  await writeFile(path, canonicalJson(value), {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });
}

async function readRelease(path) {
  const info = await lstat(path);
  if (!info.isFile()
    || info.isSymbolicLink()
    || info.nlink !== 1
    || (info.mode & 0o777) !== 0o600
    || info.size > 256) fail();
  const text = await readFile(path, "utf8");
  const value = JSON.parse(text);
  if (!exact(value, ["release"]) || value.release !== true || canonicalJson(value) !== text) fail();
}

async function waitForRelease(path) {
  const deadline = Date.now() + BARRIER_DEADLINE_MS;
  while (Date.now() < deadline) {
    try {
      await readRelease(path);
      return;
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    await sleep(20);
  }
  fail();
}

async function runCoordinator(value) {
  if (!exact(value, ["barrier", "children", "fake", "relay", "report", "schema"])
    || value.schema !== SCHEMA
    || !exact(value.children, ["payer", "payee", "verifier"])
    || !validFake(value.fake)
    || !exact(value.relay, ["ca", "fingerprint", "port"])
    || !absolute(value.relay.ca)
    || !/^[0-9a-f]{64}$/.test(value.relay.fingerprint)
    || !Number.isInteger(value.relay.port)
    || !absolute(value.report)) fail();
  if (value.barrier !== null && (!exact(value.barrier, ["ready", "release"]) || !absolute(value.barrier.ready) || !absolute(value.barrier.release))) fail();
  for (const child of Object.values(value.children)) {
    if (!exact(child, ["logs", "mode", "path"])
      || !exact(child.logs, ["stderr", "stdout"])
      || !absolute(child.path)
      || !absolute(child.logs.stdout)
      || !absolute(child.logs.stderr)) fail();
  }
  const active = new Set();
  try {
    await tlsProbe(value.relay);
    const payee = await start(value.children.payee);
    active.add(payee);
    const payer = await start(value.children.payer);
    active.add(payer);
    const [payeeExit, payerExit] = await Promise.all([waitForChild(payee), waitForChild(payer)]);
    active.delete(payee);
    active.delete(payer);
    if (payeeExit.code !== 0 || payerExit.code !== 0 || payeeExit.signal !== null || payerExit.signal !== null) fail();
    const beforeVerifier = (await createFakeBilateralClockchainHttpClient(value.fake).snapshot()).readCounters;
    if (value.barrier !== null) {
      await writeExclusive(value.barrier.ready, { schema: SCHEMA, stage: "roles-complete" });
      await waitForRelease(value.barrier.release);
    }
    await tlsProbe(value.relay);
    const verifier = await start(value.children.verifier);
    active.add(verifier);
    const verifierExit = await waitForChild(verifier);
    active.delete(verifier);
    if (verifierExit.code !== 0 || verifierExit.signal !== null) fail();
    const afterVerifier = (await createFakeBilateralClockchainHttpClient(value.fake).snapshot()).readCounters;
    await writeExclusive(value.report, {
      coordinatorPid: process.pid,
      payer: { code: payerExit.code, pid: payer.pid },
      payee: { code: payeeExit.code, pid: payee.pid },
      paymentMoved: false,
      readCountersAfterVerifier: afterVerifier,
      readCountersBeforeVerifier: beforeVerifier,
      schema: SCHEMA,
      verifier: { code: verifierExit.code, pid: verifier.pid },
    });
  } finally {
    await Promise.all([...active].map((child) => terminate(child).catch(() => {})));
  }
}

export async function main(argv = process.argv.slice(2)) {
  const parsed = parse(argv);
  const value = await config(parsed.path);
  if (parsed.mode === "coordinator") await runCoordinator(value);
  else if (parsed.mode === "verifier") await runVerifier(value);
  else await runRole(value, parsed.mode);
  return 0;
}

if (import.meta.url === new URL(process.argv[1], "file:").href) {
  try {
    process.exitCode = await main();
  } catch {
    process.stderr.write("PROCESS_CHILD_FAILED\n");
    process.exitCode = 1;
  }
}
