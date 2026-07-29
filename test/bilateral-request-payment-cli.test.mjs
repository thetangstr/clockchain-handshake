import assert from "node:assert/strict";
import { chmod, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";

import { main, REQUEST_PAYMENT_CLI_FLAGS } from "../bin/handshake-request-payment.mjs";

const CAPABILITY = "ab".repeat(32);
const REPOSITORY_SHA = "abcdef0123456789abcdef0123456789abcdef01";
const INTAKE_REQUEST_ID = "00000000-0000-4000-8000-000000000000";

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "request-payment-cli-"));
  await chmod(root, 0o700);
  const manifestPath = join(root, "manifest.json");
  const certificatePath = join(root, "cert.pem");
  const stateRoot = join(root, "state");
  await chmod(root, 0o700);
  await writeFile(certificatePath, "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n", { mode: 0o600 });
  return {
    args: [
      "--launch-manifest", manifestPath,
      "--intake-request-id", INTAKE_REQUEST_ID,
      "--mcp-url", "https://127.0.0.1:443/mcp",
      "--state", stateRoot,
      "--tls-certificate", certificatePath,
      "--tls-fingerprint", "a".repeat(64),
    ],
    certificatePath,
    manifestPath,
    root,
    stateRoot,
  };
}

test("Requestor CLI exposes exactly six options, validates clean immutable state, calls MCP, then starts supervisor once", async () => {
  const fx = await fixture();
  const calls = [];
  const result = await main(fx.args, {
    async readLaunchManifest(path) {
      calls.push(["readLaunchManifest", path]);
      assert.equal(path, fx.manifestPath);
      return {
        payerMcpIntakeCapability: CAPABILITY,
        repositorySha: REPOSITORY_SHA,
        role: "payee",
      };
    },
    async readTextFile(path) {
      calls.push(["readTextFile", path]);
      assert.equal(path, fx.certificatePath);
      return readFile(path, "utf8");
    },
    async verifyRepositoryState(repositorySha) {
      calls.push(["verifyRepositoryState", repositorySha]);
      assert.equal(repositorySha, REPOSITORY_SHA);
      return true;
    },
    async requestPayment(input) {
      calls.push(["requestPayment", input.capability, input.stateRoot]);
      assert.equal(input.capability, CAPABILITY);
      assert.equal(input.stateRoot, fx.stateRoot);
      return { paymentMoved: false, status: "HANDSHAKE_REQUIRED" };
    },
    async runSupervisor(input) {
      calls.push(["runSupervisor", input.launchManifestPath, input.stateRoot]);
      assert.equal(input.launchManifestPath, fx.manifestPath);
      assert.equal(input.stateRoot, fx.stateRoot);
      return { paymentMoved: false, supervisor: "started" };
    },
    writeStatus(value) {
      calls.push(["writeStatus", value]);
      assert.deepEqual(value, { paymentMoved: false, status: "HANDSHAKE_REQUIRED" });
      assert.equal(JSON.stringify(value).includes(CAPABILITY), false);
    },
  });
  assert.deepEqual(result, { paymentMoved: false, supervisor: "started" });
  assert.deepEqual(REQUEST_PAYMENT_CLI_FLAGS, [
    "--launch-manifest",
    "--intake-request-id",
    "--mcp-url",
    "--state",
    "--tls-certificate",
    "--tls-fingerprint",
  ]);
  assert.deepEqual(calls.map((entry) => entry[0]), [
    "readLaunchManifest",
    "verifyRepositoryState",
    "readTextFile",
    "requestPayment",
    "writeStatus",
    "runSupervisor",
  ]);
});

test("Requestor CLI rejects bad arguments, wrong role, dirty SHA, and any prior failure without supervisor start", async () => {
  const fx = await fixture();
  for (const args of [
    fx.args.slice(0, -2),
    [...fx.args, "--unknown", "x"],
    [...fx.args, "--state", fx.stateRoot],
    fx.args.map((value) => value === fx.manifestPath ? "relative.json" : value),
  ]) {
    await assert.rejects(main(args, {}), /Request payment startup failed safely/);
  }

  const failures = [
    { manifest: { payerMcpIntakeCapability: CAPABILITY, repositorySha: REPOSITORY_SHA, role: "payer" } },
    { manifest: { payerMcpIntakeCapability: CAPABILITY, repositorySha: REPOSITORY_SHA, role: "payee" }, repositoryOk: false },
    { manifest: { payerMcpIntakeCapability: CAPABILITY, repositorySha: REPOSITORY_SHA, role: "payee" }, requestFails: true },
  ];
  for (const failure of failures) {
    let supervisorCalls = 0;
    await assert.rejects(
      main(fx.args, {
        async readLaunchManifest() {
          return failure.manifest;
        },
        async readTextFile() {
          return "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n";
        },
        async verifyRepositoryState() {
          return failure.repositoryOk !== false;
        },
        async requestPayment() {
          if (failure.requestFails) throw new Error("boom");
          return { paymentMoved: false, status: "HANDSHAKE_REQUIRED" };
        },
        async runSupervisor() {
          supervisorCalls += 1;
        },
      }),
      /Request payment startup failed safely/,
    );
    assert.equal(supervisorCalls, 0);
  }

  assert.equal(resolve(fx.manifestPath), fx.manifestPath);
});
