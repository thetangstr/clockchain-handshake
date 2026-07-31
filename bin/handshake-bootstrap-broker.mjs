#!/usr/bin/env node
import {
  approveBootstrapClaim,
  createBootstrapBroker,
} from "../src/bilateral/local-mcp/bootstrap-broker.mjs";

const SERVE_FLAGS = Object.freeze([
  "--capability-file",
  "--host",
  "--manifest",
  "--operator-key-id",
  "--operator-private-key",
  "--port",
  "--repository-sha",
  "--state",
]);
const APPROVE_FLAGS = Object.freeze([
  "--claim-fingerprint",
  "--state",
]);

function usage() {
  return [
    "Usage:",
    "  npm run bilateral:bootstrap-broker -- serve --capability-file <path> --host <127.0.0.1> --manifest <path> --operator-key-id <key-id> --operator-private-key <path> --port <port> --repository-sha <sha> --state <path>",
    "  npm run bilateral:bootstrap-broker -- approve --state <path> --claim-fingerprint <sha256>",
  ].join("\n");
}

function fail() {
  console.error(usage());
  process.exitCode = 1;
}

function parseExact(argv, flags) {
  if (argv.length !== flags.length * 2) {
    throw new Error("invalid arguments");
  }
  const values = Object.create(null);
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!flags.includes(flag) || values[flag] !== undefined || value === undefined) {
      throw new Error("invalid arguments");
    }
    values[flag] = value;
  }
  for (const flag of flags) {
    if (values[flag] === undefined) throw new Error("invalid arguments");
  }
  return values;
}

async function main() {
  const [mode, ...rest] = process.argv.slice(2);
  if (mode === "serve") {
    const values = parseExact(rest, SERVE_FLAGS);
    const port = Number(values["--port"]);
    if (!Number.isInteger(port)) throw new Error("invalid port");
    const broker = createBootstrapBroker({
      capabilityFile: values["--capability-file"],
      host: values["--host"],
      manifestPath: values["--manifest"],
      operatorKeyId: values["--operator-key-id"],
      operatorPrivateKeyPath: values["--operator-private-key"],
      port,
      repositorySha: values["--repository-sha"],
      stateRoot: values["--state"],
    });
    const listening = await broker.start();
    console.log(JSON.stringify({
      host: listening.host,
      paymentMoved: false,
      port: listening.port,
      status: "BOOTSTRAP_BROKER_READY",
      url: listening.url,
    }));
    process.once("SIGINT", async () => {
      await broker.stop();
      process.exit(0);
    });
    process.once("SIGTERM", async () => {
      await broker.stop();
      process.exit(0);
    });
    return;
  }
  if (mode === "approve") {
    const values = parseExact(rest, APPROVE_FLAGS);
    const result = await approveBootstrapClaim({
      claimFingerprint: values["--claim-fingerprint"],
      stateRoot: values["--state"],
    });
    console.log(JSON.stringify(result));
    return;
  }
  fail();
}

main().catch(() => {
  fail();
});
