import assert from "node:assert/strict";
import { execFile, execFileSync } from "node:child_process";
import { chmod, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { promisify } from "node:util";

import { main, REQUEST_PAYMENT_CLI_FLAGS } from "../bin/handshake-request-payment.mjs";

const CAPABILITY = "ab".repeat(32);
const REPOSITORY_SHA = "abcdef0123456789abcdef0123456789abcdef01";
const INTAKE_REQUEST_ID = "00000000-0000-4000-8000-000000000000";
const execFileAsync = promisify(execFile);
const REPOSITORY_ROOT = resolve(fileURLToPath(new URL("../", import.meta.url)));

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
    async inspectRepository() {
      calls.push(["inspectRepository"]);
      return { clean: true, detached: true, head: REPOSITORY_SHA };
    },
    async readTextFile(path) {
      calls.push(["readTextFile", path]);
      assert.equal(path, fx.certificatePath);
      return readFile(path, "utf8");
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
    "inspectRepository",
    "readLaunchManifest",
    "readTextFile",
    "requestPayment",
    "writeStatus",
    "runSupervisor",
  ]);
});

test("Requestor CLI default success path emits fixed secret-free HANDSHAKE_REQUIRED line and starts supervisor", async () => {
  const fx = await fixture();
  const writes = [];
  const originalWrite = process.stdout.write;
  process.stdout.write = function patchedWrite(chunk, ...rest) {
    writes.push(String(chunk));
    return true;
  };
  try {
    const result = await main(fx.args, {
      async inspectRepository() {
        return { clean: true, detached: true, head: REPOSITORY_SHA };
      },
      async readLaunchManifest() {
        return {
          payerMcpIntakeCapability: CAPABILITY,
          repositorySha: REPOSITORY_SHA,
          role: "payee",
        };
      },
      async readTextFile() {
        return "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n";
      },
      async requestPayment() {
        return { paymentMoved: false, status: "HANDSHAKE_REQUIRED" };
      },
      async runSupervisor() {
        return { paymentMoved: false, supervisor: "started" };
      },
    });
    assert.deepEqual(result, { paymentMoved: false, supervisor: "started" });
  } finally {
    process.stdout.write = originalWrite;
  }
  assert.deepEqual(writes, ['{"paymentMoved":false,"status":"HANDSHAKE_REQUIRED"}\n']);
  assert.equal(writes.join("").includes(CAPABILITY), false);
});

test("spawned Requestor CLI failure emits exact secret-free REQUEST_PAYMENT_FAILED line and no stack", async () => {
  await assert.rejects(
    execFileAsync(process.execPath, ["bin/handshake-request-payment.mjs"], {
      cwd: process.cwd(),
      encoding: "utf8",
    }),
    (error) => {
      assert.equal(error.code, 1);
      assert.equal(error.stdout, '{"code":"REQUEST_PAYMENT_FAILED","paymentMoved":false}\n');
      assert.equal(error.stderr, "");
      assert.equal(error.stdout.includes(CAPABILITY), false);
      assert.equal(error.stdout.includes("Error:"), false);
      return true;
    },
  );
});

test("Requestor CLI verifies clean detached HEAD before reading manifest, TLS, or capability", async () => {
  const fx = await fixture();
  const calls = [];
  await assert.rejects(
    main(fx.args, {
      async readLaunchManifest() {
        calls.push("readLaunchManifest");
        throw new Error("manifest read must be after repository proof");
      },
      async readTextFile() {
        calls.push("readTextFile");
        throw new Error("TLS read must be after repository proof");
      },
      async inspectRepository() {
        calls.push("inspectRepository");
        return { clean: false, detached: true, head: REPOSITORY_SHA };
      },
      async runSupervisor() {
        calls.push("runSupervisor");
      },
    }),
    /Request payment startup failed safely/,
  );
  assert.deepEqual(calls, ["inspectRepository"]);
});

test("Requestor CLI verifies the module repository root before private reads even when cwd is a separate clean checkout", async (t) => {
  const fx = await fixture();
  const otherRoot = await mkdtemp(join(tmpdir(), "request-payment-clean-cwd-"));
  t.after(() => execFileSync("/bin/rm", ["-rf", otherRoot]));
  execFileSync("/usr/bin/git", ["init"], { cwd: otherRoot, stdio: "ignore" });
  execFileSync("/usr/bin/git", ["config", "user.email", "fixture@example.invalid"], { cwd: otherRoot });
  execFileSync("/usr/bin/git", ["config", "user.name", "fixture"], { cwd: otherRoot });
  await writeFile(join(otherRoot, "README.md"), "clean other repo\n");
  execFileSync("/usr/bin/git", ["add", "."], { cwd: otherRoot });
  execFileSync("/usr/bin/git", ["commit", "-m", "other repo"], { cwd: otherRoot, stdio: "ignore" });
  const otherHead = execFileSync("/usr/bin/git", ["rev-parse", "HEAD"], { cwd: otherRoot, encoding: "utf8" }).trim();
  execFileSync("/usr/bin/git", ["checkout", "--detach", otherHead], { cwd: otherRoot, stdio: "ignore" });

  const originalCwd = process.cwd();
  process.chdir(otherRoot);
  try {
    const calls = [];
    await assert.rejects(
      main(fx.args, {
        async readLaunchManifest() {
          calls.push("readLaunchManifest");
          return {
            payerMcpIntakeCapability: CAPABILITY,
            repositorySha: otherHead,
            role: "payee",
          };
        },
        async readTextFile() {
          calls.push("readTextFile");
          return "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n";
        },
        async requestPayment() {
          calls.push("requestPayment");
          return { paymentMoved: false, status: "HANDSHAKE_REQUIRED" };
        },
        async runSupervisor() {
          calls.push("runSupervisor");
        },
      }),
      /Request payment startup failed safely/,
    );
    assert.equal(calls.includes("readTextFile"), false);
    assert.equal(calls.includes("requestPayment"), false);
    assert.equal(calls.includes("runSupervisor"), false);
  } finally {
    process.chdir(originalCwd);
  }
  assert.equal(REPOSITORY_ROOT.endsWith("riyadh-v3"), true);
});

test("Requestor CLI binds manifest repositorySha to verified clean detached HEAD before private capability use", async () => {
  const fx = await fixture();
  const calls = [];
  await assert.rejects(
    main(fx.args, {
      async inspectRepository() {
        calls.push("inspectRepository");
        return { clean: true, detached: true, head: REPOSITORY_SHA };
      },
      async readLaunchManifest() {
        calls.push("readLaunchManifest");
        return {
          payerMcpIntakeCapability: CAPABILITY,
          repositorySha: "b".repeat(40),
          role: "payee",
        };
      },
      async readTextFile() {
        calls.push("readTextFile");
        return "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n";
      },
      async requestPayment() {
        calls.push("requestPayment");
        return { paymentMoved: false, status: "HANDSHAKE_REQUIRED" };
      },
      async runSupervisor() {
        calls.push("runSupervisor");
      },
    }),
    /Request payment startup failed safely/,
  );
  assert.deepEqual(calls, ["inspectRepository", "readLaunchManifest"]);
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
    { manifest: { payerMcpIntakeCapability: CAPABILITY, repositorySha: REPOSITORY_SHA, role: "payee" }, requestFails: true },
  ];
  for (const failure of failures) {
    let supervisorCalls = 0;
    await assert.rejects(
      main(fx.args, {
        async readLaunchManifest() {
          return failure.manifest;
        },
        async inspectRepository() {
          return { clean: true, detached: true, head: REPOSITORY_SHA };
        },
        async readTextFile() {
          return "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n";
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
