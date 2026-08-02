#!/usr/bin/env node
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createConnection } from "node:net";
import { pathToFileURL } from "node:url";
import {
  appendPublicRunIndex,
  createImmutableRunSummary,
  observeImmutableRunSummary,
} from "../src/bilateral/aws/public-history.mjs";
import {
  buildPublicMonitorSnapshot,
  buildUnavailablePublicMonitorSnapshot,
} from "../src/bilateral/coordination/public-monitor.mjs";

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

function publicObjectUrl({ bucket, key, region }) {
  return `https://${bucket}.s3.${region}.amazonaws.com/${key}`;
}

function objectKey(value) {
  if (
    typeof value !== "string" ||
    value.length > 256 ||
    value.includes("..") ||
    value.includes("//") ||
    !/^(?:latest\.json|runs\/(?:index|run-[0-9a-f]{16})\.json)$/.test(value)
  ) {
    throw new Error("Public monitor object key failed safely.");
  }
  return value;
}

function jsonBody(value) {
  return `${JSON.stringify(value)}\n`;
}

function putObject(entry, options) {
  return new Promise((resolve, reject) => {
    const key = objectKey(entry.key);
    const child = spawn(
      "aws",
      [
        "s3",
        "cp",
        "-",
        `s3://${options.bucket}/${key}`,
        "--region",
        options.region,
        "--content-type",
        entry.contentType ?? "application/json",
        "--cache-control",
        entry.cacheControl ?? "no-store,max-age=0",
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
      if (code === 0) resolve({ status: "CREATED" });
      else reject(new Error(`Public monitor upload failed: ${error.trim()}`));
    });
    child.stdin.end(entry.body);
  });
}

function readObject(key, options) {
  return new Promise((resolve, reject) => {
    const child = spawn(
      "aws",
      [
        "s3",
        "cp",
        `s3://${options.bucket}/${objectKey(key)}`,
        "-",
        "--region",
        options.region,
        "--only-show-errors",
      ],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
    let body = "";
    let error = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      if (body.length < 1_000_000) body += chunk;
    });
    child.stderr.on("data", (chunk) => {
      if (error.length < 4_096) error += chunk;
    });
    child.once("error", reject);
    child.once("exit", (code) => {
      if (code === 0) resolve(body);
      else if (/not exist|NoSuchKey|404/i.test(error)) resolve(null);
      else reject(new Error(`Public monitor read failed: ${error.trim()}`));
    });
  });
}

async function readRunIndex(options, dependencies) {
  const read = dependencies.readObject ?? readObject;
  const body = await read("runs/index.json", options);
  if (body === null || body === undefined || body === "") return null;
  return JSON.parse(body);
}

function objectWriter(options, dependencies) {
  if (typeof dependencies.putObject === "function") {
    return dependencies.putObject;
  }
  if (typeof dependencies.uploadSnapshot === "function") {
    return null;
  }
  return (entry) => putObject(entry, options);
}

async function publishLatest(snapshot, options, dependencies) {
  const write = objectWriter(options, dependencies);
  if (write) {
    await write({
      body: jsonBody(snapshot),
      cacheControl: "no-store,max-age=0",
      contentType: "application/json",
      key: "latest.json",
    });
    return;
  }
  await (dependencies.uploadSnapshot ?? uploadSnapshot)(snapshot, options);
}

async function publishImmutableHistory(snapshot, options, dependencies, completedAtMs) {
  const write = objectWriter(options, dependencies);
  if (
    !write ||
    snapshot.runStatus !== "VERIFIED" ||
    snapshot.verifier?.status !== "VERIFIED"
  ) {
    return;
  }
  const summaryKey = `runs/${snapshot.runId}.json`;
  const toUrl = dependencies.publicObjectUrl ?? publicObjectUrl;
  const summary = createImmutableRunSummary({
    completedAtMs,
    projection: snapshot,
    secretCanaries: [],
    summaryUrl: toUrl({
      bucket: options.bucket,
      key: summaryKey,
      region: options.region,
    }),
    verifierPublicationValidated: true,
  });
  const summaryBody = jsonBody(summary);
  try {
    await write({
      body: summaryBody,
      cacheControl: "public,max-age=31536000,immutable",
      contentType: "application/json",
      ifNoneMatch: "*",
      key: summaryKey,
    });
  } catch (error) {
    if (error?.code !== "OBJECT_EXISTS") throw error;
    const read = dependencies.readObject ?? readObject;
    const existing = await read(summaryKey, options);
    if (existing !== summaryBody) throw error;
  }
  observeImmutableRunSummary(summary);
  const existingIndex = typeof dependencies.readRunIndex === "function"
    ? await dependencies.readRunIndex()
    : await readRunIndex(options, dependencies);
  const index = appendPublicRunIndex({
    index: existingIndex,
    summary,
    updatedAtMs: completedAtMs,
  });
  await write({
    body: jsonBody(index),
    cacheControl: "no-store,max-age=0",
    contentType: "application/json",
    key: "runs/index.json",
  });
}

export async function publishOnce(options, dependencies = {}) {
  const probe = dependencies.probeTcp ?? probeTcp;
  const fetchConsole = dependencies.fetch ?? fetch;
  const now = dependencies.now ?? Date.now;
  const payerMcpReady = await probe({
    host: options.payerMcpHost,
    port: options.payerMcpPort,
  });
  const waitingRunId =
    `run-${createHash("sha256")
      .update(options.bucket)
      .digest("hex")
      .slice(0, 16)}`;
  let snapshot;
  try {
    const response = await fetchConsole(options.consoleUrl, {
      cache: "no-store",
      signal: AbortSignal.timeout(1_500),
    });
    if (!response.ok) throw new Error(`Console returned ${response.status}.`);
    const projection = await response.json();
    const publishedAtMs = now();
    const runId =
      `run-${createHash("sha256")
        .update(
          `${projection.session?.releaseId ?? ""}:` +
          `${projection.session?.sessionId ?? ""}`,
        )
        .digest("hex")
        .slice(0, 16)}`;
    snapshot = buildPublicMonitorSnapshot(projection, {
      anchorExplorerUrls:
        projection.anchors.map(
          ({ block, verified }) =>
            verified
              ? `https://sepolia.etherscan.io/block/${block}`
              : null,
        ),
      nowMs: publishedAtMs,
      payerMcpReady,
      publishedAtMs,
      runId,
      sourceObservedAtMs:
        projection.deadline?.nowMs,
      staleAfterMs: 10_000,
      verifierPublicationValidated:
        projection.verifier?.status ===
          "VERIFICATION_PASSED",
    });
  } catch {
    const publishedAtMs = now();
    snapshot = buildUnavailablePublicMonitorSnapshot({
      publishedAtMs,
      runId: waitingRunId,
      staleAfterMs: 10_000,
    });
  }
  await publishLatest(snapshot, options, dependencies);
  await publishImmutableHistory(snapshot, options, dependencies, now());
  process.stdout.write(
    `PUBLIC_MONITOR_UPDATED ${snapshot.publishedAtMs} ${snapshot.runStatus}\n`,
  );
  return snapshot;
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
