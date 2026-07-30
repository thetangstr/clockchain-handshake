#!/usr/bin/env node
import { spawn } from "node:child_process";
import { createConnection } from "node:net";
import { pathToFileURL } from "node:url";
import { buildPublicMonitorSnapshot } from "../src/bilateral/coordination/public-monitor.mjs";

const DEFAULT_BUCKET = "clockchain-handshake-monitor-570035913370-us-west-2";

function fail() {
  throw new Error("Public monitor arguments failed safely.");
}

function integer(value, minimum, maximum) {
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]*)$/.test(value)) fail();
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) fail();
  return parsed;
}

export function parsePublicMonitorArguments(argv) {
  const allowed = new Set([
    "--bucket",
    "--console-url",
    "--interval-ms",
    "--payer-mcp-host",
    "--payer-mcp-port",
    "--region",
  ]);
  const values = Object.create(null);
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (
      !allowed.has(flag) ||
      Object.hasOwn(values, flag) ||
      typeof value !== "string" ||
      value.length === 0 ||
      value.includes("\0")
    ) fail();
    values[flag] = value;
  }
  const consoleUrl =
    values["--console-url"] ??
    "http://127.0.0.1:8787/v1/console/session";
  let parsedConsole;
  try {
    parsedConsole = new URL(consoleUrl);
  } catch {
    fail();
  }
  if (
    parsedConsole.protocol !== "http:" ||
    !["127.0.0.1", "::1", "localhost"].includes(parsedConsole.hostname) ||
    parsedConsole.pathname !== "/v1/console/session" ||
    parsedConsole.search !== "" ||
    parsedConsole.hash !== ""
  ) fail();
  const bucket = values["--bucket"] ?? DEFAULT_BUCKET;
  const region = values["--region"] ?? "us-west-2";
  const payerMcpHost = values["--payer-mcp-host"] ?? "127.0.0.1";
  if (
    !/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(bucket) ||
    !/^[a-z]{2}-[a-z]+-[1-9]$/.test(region) ||
    !["127.0.0.1", "::1", "localhost"].includes(payerMcpHost)
  ) fail();
  return Object.freeze({
    bucket,
    consoleUrl,
    intervalMs: integer(values["--interval-ms"] ?? "2000", 1_000, 10_000),
    payerMcpHost,
    payerMcpPort: integer(values["--payer-mcp-port"] ?? "9443", 1, 65_535),
    region,
  });
}

function probeTcp({ host, port }) {
  return new Promise((resolve) => {
    const socket = createConnection({ host, port });
    const finish = (ready) => {
      socket.destroy();
      resolve(ready);
    };
    socket.setTimeout(750, () => finish(false));
    socket.once("connect", () => finish(true));
    socket.once("error", () => finish(false));
  });
}

function uploadSnapshot(snapshot, options) {
  return new Promise((resolve, reject) => {
    const child = spawn(
      "aws",
      [
        "s3",
        "cp",
        "-",
        `s3://${options.bucket}/latest.json`,
        "--region",
        options.region,
        "--content-type",
        "application/json",
        "--cache-control",
        "no-store,max-age=0",
        "--only-show-errors",
      ],
      { stdio: ["pipe", "ignore", "pipe"] },
    );
    let error = "";
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk) => {
      if (error.length < 4_096) error += chunk;
    });
    child.once("error", reject);
    child.once("exit", (code) => {
      if (code === 0) resolve();
      else reject(new Error(`Public monitor upload failed: ${error.trim()}`));
    });
    child.stdin.end(`${JSON.stringify(snapshot)}\n`);
  });
}

async function publishOnce(options) {
  const response = await fetch(options.consoleUrl, {
    cache: "no-store",
    signal: AbortSignal.timeout(1_500),
  });
  if (!response.ok) throw new Error(`Console returned ${response.status}.`);
  const projection = await response.json();
  const payerMcpReady = await probeTcp({
    host: options.payerMcpHost,
    port: options.payerMcpPort,
  });
  const snapshot = buildPublicMonitorSnapshot(projection, {
    observedAt: new Date().toISOString(),
    payerMcpReady,
  });
  await uploadSnapshot(snapshot, options);
  process.stdout.write(`PUBLIC_MONITOR_UPDATED ${snapshot.observedAt} ${snapshot.status}\n`);
}

async function main() {
  const options = parsePublicMonitorArguments(process.argv.slice(2));
  let stopped = false;
  process.once("SIGINT", () => { stopped = true; });
  process.once("SIGTERM", () => { stopped = true; });
  while (!stopped) {
    try {
      await publishOnce(options);
    } catch (error) {
      process.stderr.write(`PUBLIC_MONITOR_WAITING ${error instanceof Error ? error.message : "Unknown failure."}\n`);
    }
    if (!stopped) {
      await new Promise((resolve) => setTimeout(resolve, options.intervalMs));
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
