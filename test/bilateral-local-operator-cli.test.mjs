import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { main } from "../bin/handshake-local-operator.mjs";

test("accepts only the exact config and fresh-state flags and invokes the runtime once", async () => {
  const calls = [];
  const stdout = { write(value) { calls.push(["stdout", value]); } };
  const config = Object.freeze({ paymentMoved: false });
  const code = await main([
    "--config", ".context/hybrid-demo/operator.json",
    "--state", "/private/new-hybrid-state",
  ], {
    async readConfig(configPath, stateRoot) {
      calls.push(["read", configPath, stateRoot]);
      return config;
    },
    async runOperator(input) {
      calls.push(["run", input]);
      return Object.freeze({ paymentMoved: false, status: "VERIFICATION_PASSED" });
    },
    stdout,
  });

  assert.equal(code, 0);
  assert.deepEqual(calls, [
    ["read", ".context/hybrid-demo/operator.json", "/private/new-hybrid-state"],
    ["run", { config, stateRoot: "/private/new-hybrid-state" }],
  ]);
});

test("the default CLI path composes the runtime with production dependencies", async () => {
  const calls = [];
  const config = Object.freeze({ paymentMoved: false });
  const productionDependencies = Object.freeze({ marker: "production" });
  const code = await main([
    "--config", ".context/hybrid-demo/operator.json",
    "--state", "/private/new-hybrid-state",
  ], {
    createProductionDependencies() {
      calls.push(["create-production"]);
      return productionDependencies;
    },
    async readConfig(configPath, stateRoot) {
      calls.push(["read", configPath, stateRoot]);
      return config;
    },
    async runRuntime(input, dependencies) {
      calls.push(["runtime", input, dependencies]);
      return Object.freeze({ paymentMoved: false, status: "VERIFICATION_PASSED" });
    },
    stdout: { write(value) { calls.push(["stdout", value]); } },
  });

  assert.equal(code, 0);
  assert.deepEqual(calls, [
    ["read", ".context/hybrid-demo/operator.json", "/private/new-hybrid-state"],
    ["create-production"],
    ["runtime", { config, stateRoot: "/private/new-hybrid-state" }, productionDependencies],
  ]);
});

test("fails with one fixed non-authorizing line before dependencies on malformed CLI input", async (t) => {
  for (const argv of [
    [],
    ["--config", "config.json"],
    ["--state", "/private/state", "--config", "config.json"],
    ["--config", "config.json", "--config", "other.json"],
    ["--config", "config.json", "--state", "state"],
    ["--config", "config.json", "--state", "/private/state", "--extra", "x"],
  ]) {
    await t.test(argv.join(" ") || "empty", async () => {
      const output = [];
      let dependenciesCalled = false;
      const code = await main(argv, {
        async readConfig() { dependenciesCalled = true; },
        async runOperator() { dependenciesCalled = true; },
        stdout: { write(value) { output.push(value); } },
      });
      assert.equal(code, 1);
      assert.equal(dependenciesCalled, false);
      assert.deepEqual(output, [
        '{"paymentMoved":false,"status":"HYBRID_OPERATOR_FAILED"}\n',
      ]);
      assert.doesNotMatch(output[0], /AUTHORIZED|config\.json|\/private\/state/);
    });
  }
});

test("fails safely when config or runtime rejects without serializing its message", async (t) => {
  for (const failAt of ["config", "runtime"]) {
    await t.test(failAt, async () => {
      const output = [];
      const code = await main([
        "--config", ".context/hybrid-demo/operator.json",
        "--state", "/private/new-hybrid-state",
      ], {
        async readConfig() {
          if (failAt === "config") throw new Error("private config failure");
          return Object.freeze({ paymentMoved: false });
        },
        async runOperator() {
          if (failAt === "runtime") throw new Error("private runtime failure");
        },
        stdout: { write(value) { output.push(value); } },
      });
      assert.equal(code, 1);
      assert.deepEqual(output, [
        '{"paymentMoved":false,"status":"HYBRID_OPERATOR_FAILED"}\n',
      ]);
    });
  }
});

test("package exposes the one-command local operator entry point", async () => {
  const packageJson = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(
    packageJson.scripts["bilateral:local-operator"],
    "node bin/handshake-local-operator.mjs",
  );
});
