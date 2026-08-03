#!/usr/bin/env node

import { execFile } from "node:child_process";
import { mkdir } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { parseArgs } from "node:util";
import { pathToFileURL } from "node:url";

import { createLocalPublicMonitorPublisher } from "../src/bilateral/local-demo/public-monitor-publisher.mjs";

const HEARTBEAT_SCHEMA = "clockchain.local-public-monitor-heartbeat/v1";
const MAX_CANARIES = 32;

export class PublicMonitorCliError extends Error {
  constructor() {
    super("Public monitor CLI failed safely.");
    this.name = "PublicMonitorCliError";
    this.code = "PUBLIC_MONITOR_CLI_INVALID";
    this.category = "configuration";
  }
}

function fail() {
  throw new PublicMonitorCliError();
}

function absolutePath(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.includes("\0") ||
    !isAbsolute(value)
  ) {
    fail();
  }
  return value;
}

function bucketPrefix(value) {
  if (
    typeof value !== "string" ||
    !/^s3:\/\/[a-z0-9][a-z0-9.-]{1,61}[a-z0-9](\/[A-Za-z0-9._\/-]+)?$/.test(value) ||
    value.endsWith("/")
  ) {
    fail();
  }
  return value;
}

function publicBaseUrl(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    fail();
  }
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== ""
  ) {
    fail();
  }
  return value.replace(/\/$/, "");
}

function milliseconds(value, minimum) {
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]*)$/.test(value)) fail();
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum) fail();
  return parsed;
}

function parseArguments(argv) {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      options: {
        "bucket-prefix": { type: "string" },
        "canary": { type: "string", multiple: true },
        "console-state": { type: "string" },
        "grace-ms": { type: "string" },
        "max-ms": { type: "string" },
        "poll-ms": { type: "string" },
        "public-base-url": { type: "string" },
        "stage-root": { type: "string" },
      },
      strict: true,
    });
  } catch {
    fail();
  }
  const values = parsed.values;
  const canaries = values["canary"];
  if (
    parsed.positionals.length !== 0 ||
    !Array.isArray(canaries) ||
    canaries.length < 1 ||
    canaries.length > MAX_CANARIES ||
    canaries.some((entry) => typeof entry !== "string" || entry.length === 0)
  ) {
    fail();
  }
  const pollMs = values["poll-ms"] === undefined ? 15_000 : milliseconds(values["poll-ms"], 1_000);
  return Object.freeze({
    bucketPrefix: bucketPrefix(values["bucket-prefix"]),
    canaries: Object.freeze([...canaries]),
    consoleStatePath: absolutePath(values["console-state"]),
    graceMs: values["grace-ms"] === undefined ? 1_800_000 : milliseconds(values["grace-ms"], 0),
    maxMs: values["max-ms"] === undefined ? 7_200_000 : milliseconds(values["max-ms"], pollMs),
    pollMs,
    publicBaseUrl: publicBaseUrl(values["public-base-url"]),
    stageRoot: absolutePath(values["stage-root"]),
  });
}

function execFilePromise(command, args) {
  return new Promise((resolvePromise, reject) => {
    execFile(command, args, { maxBuffer: 4 * 1024 * 1024 }, (error, stdout, stderr) => {
      if (error) {
        reject(error);
        return;
      }
      resolvePromise({ stdout, stderr });
    });
  });
}

function createS3Transport({ exec = execFilePromise, sleeper = (ms) => new Promise((resolve) => setTimeout(resolve, ms)) } = {}) {
  return async (localPath, s3Uri) => {
    let lastError = null;
    for (let attempt = 0; attempt < 3; attempt += 1) {
      try {
        await exec("aws", [
          "s3", "cp", localPath, s3Uri,
          "--cache-control", "no-cache",
          "--content-type", "application/json",
        ]);
        return;
      } catch (error) {
        lastError = error;
        await sleeper(1_000 * (attempt + 1));
      }
    }
    throw lastError;
  };
}

export async function main(argv = process.argv.slice(2), dependencies = {}) {
  const options = parseArguments(argv);
  const now = dependencies.now ?? Date.now;
  const sleeper = dependencies.sleeper ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
  const stdout = dependencies.stdout ?? process.stdout;
  const transport = dependencies.transport ?? createS3Transport({ sleeper });
  const createPublisher = dependencies.createPublisher ?? createLocalPublicMonitorPublisher;
  if (
    typeof now !== "function" ||
    typeof sleeper !== "function" ||
    typeof transport !== "function" ||
    typeof createPublisher !== "function" ||
    typeof stdout?.write !== "function"
  ) {
    fail();
  }
  await mkdir(join(options.stageRoot, "runs"), { mode: 0o700, recursive: true });
  const publisher = createPublisher({
    bucketPrefix: options.bucketPrefix,
    consoleStatePath: options.consoleStatePath,
    now,
    pollMs: options.pollMs,
    publicBaseUrl: options.publicBaseUrl,
    secretCanaries: options.canaries,
    sleeper,
    stageRoot: options.stageRoot,
    transport,
  });
  if (typeof publisher?.run !== "function") fail();
  const heartbeat = (result) => {
    const line = JSON.stringify({
      historyWritten: result.historyWritten === true,
      paymentMoved: false,
      published: result.published === true,
      ...(result.published === false ? { reason: result.reason } : {}),
      ...(result.runId === undefined ? {} : { runId: result.runId }),
      ...(result.runStatus === undefined ? {} : { runStatus: result.runStatus }),
      schema: HEARTBEAT_SCHEMA,
    });
    if (options.canaries.some((canary) => line.includes(canary)) || line.includes("AUTHORIZED")) fail();
    stdout.write(`${line}\n`);
  };
  const instrumented = {
    async run(bounds) {
      const started = now();
      let terminalAt = null;
      for (;;) {
        const result = await publisher.publishOnce();
        heartbeat(result);
        const current = now();
        if (result.published && result.runStatus === "VERIFIED" && terminalAt === null) terminalAt = current;
        if (terminalAt !== null && current - terminalAt >= bounds.graceMs) {
          return Object.freeze({ exitCode: 0 });
        }
        if (current - started >= bounds.maxMs) {
          return Object.freeze({ exitCode: 1 });
        }
        await sleeper(options.pollMs);
      }
    },
  };
  const result = await instrumented.run({ graceMs: options.graceMs, maxMs: options.maxMs });
  if (result.exitCode !== 0 && result.exitCode !== 1) fail();
  return result.exitCode;
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  main().then(
    (code) => {
      process.exitCode = code;
    },
    () => {
      process.stderr.write("PUBLIC_MONITOR_FAILED\n");
      process.exitCode = 1;
    },
  );
}
