import assert from "node:assert/strict";
import { test } from "node:test";

import { inspectParticipantPrerequisites } from "../src/bilateral/platform-tools.mjs";

function fixture({
  missing = new Set(),
  nodeVersion = "v22.23.2",
  outputs = {},
  platform = "win32",
} = {}) {
  const resolved = [];
  const executed = [];
  return {
    executed,
    nodeVersion,
    platform,
    resolved,
    async resolveExecutable(name) {
      resolved.push(name);
      return missing.has(name) ? null : name;
    },
    async execute(command, args) {
      executed.push([command, args]);
      if (command === "git.exe" || command === "git") {
        return { stderr: "", stdout: outputs.git ?? "git version 2.50.1\n" };
      }
      if (command === "npm.cmd" || command === "npm") {
        return { stderr: "", stdout: outputs.npm ?? "10.9.2\n" };
      }
      if (command === "ssh.exe" || command === "ssh") {
        return { stderr: outputs.ssh ?? "OpenSSH_9.8p1, LibreSSL 3.3.6\r\n", stdout: "" };
      }
      if (command === "openssl.exe" || command === "openssl") {
        return { stderr: "", stdout: outputs.openssl ?? "OpenSSL 3.4.1 11 Feb 2025\n" };
      }
      throw new Error("unexpected command");
    },
  };
}

test("payer prerequisite inspection resolves exact Windows tools and versions", async () => {
  const fx = fixture();
  const result = await inspectParticipantPrerequisites({
    execute: fx.execute,
    nodeVersion: fx.nodeVersion,
    platform: fx.platform,
    resolveExecutable: fx.resolveExecutable,
    role: "payer",
  });

  assert.deepEqual(result, {
    git: { command: "git.exe", version: "2.50.1" },
    node: { command: process.execPath, major: 22 },
    npm: { command: "npm.cmd", version: "10.9.2" },
    openssh: { command: "ssh.exe", version: "9.8" },
    openssl: { command: "openssl.exe", version: "3.4.1" },
    sshKeygen: { command: "ssh-keygen.exe", version: "9.8" },
  });
  assert.deepEqual(fx.resolved, [
    "git.exe",
    "npm.cmd",
    "ssh.exe",
    "ssh-keygen.exe",
    "openssl.exe",
  ]);
  assert.deepEqual(fx.executed, [
    ["git.exe", ["--version"]],
    ["npm.cmd", ["--version"]],
    ["ssh.exe", ["-V"]],
    ["openssl.exe", ["version"]],
  ]);
});

test("requestor prerequisite inspection does not require OpenSSH or OpenSSL", async () => {
  const fx = fixture({
    missing: new Set(["ssh.exe", "ssh-keygen.exe", "openssl.exe"]),
  });
  const result = await inspectParticipantPrerequisites({
    execute: fx.execute,
    nodeVersion: fx.nodeVersion,
    platform: fx.platform,
    resolveExecutable: fx.resolveExecutable,
    role: "requestor",
  });

  assert.deepEqual(result, {
    git: { command: "git.exe", version: "2.50.1" },
    node: { command: process.execPath, major: 22 },
    npm: { command: "npm.cmd", version: "10.9.2" },
  });
  assert.deepEqual(fx.resolved, ["git.exe", "npm.cmd"]);
});

test("payer prerequisite inspection uses POSIX executable names on macOS and Linux", async () => {
  for (const platform of ["darwin", "linux"]) {
    const fx = fixture({ platform });
    const result = await inspectParticipantPrerequisites({
      execute: fx.execute,
      nodeVersion: fx.nodeVersion,
      platform,
      resolveExecutable: fx.resolveExecutable,
      role: "payer",
    });
    assert.equal(result.git.command, "git");
    assert.equal(result.npm.command, "npm");
    assert.equal(result.openssh.command, "ssh");
    assert.equal(result.sshKeygen.command, "ssh-keygen");
    assert.equal(result.openssl.command, "openssl");
  }
});

test("prerequisite inspection fails closed on missing tools, wrong Node, bad output, and execution failure", async () => {
  for (const options of [
    { missing: new Set(["git.exe"]) },
    { missing: new Set(["ssh-keygen.exe"]) },
    { nodeVersion: "v20.19.0" },
    { outputs: { git: "git version 2.50.1\u0000injected\n" } },
  ]) {
    const fx = fixture(options);
    await assert.rejects(
      inspectParticipantPrerequisites({
        execute: fx.execute,
        nodeVersion: fx.nodeVersion,
        platform: fx.platform,
        resolveExecutable: fx.resolveExecutable,
        role: "payer",
      }),
      /Participant prerequisites failed safely/,
    );
  }

  const fx = fixture();
  await assert.rejects(
    inspectParticipantPrerequisites({
      execute: async () => {
        throw new Error("private command detail");
      },
      nodeVersion: fx.nodeVersion,
      platform: fx.platform,
      resolveExecutable: fx.resolveExecutable,
      role: "payer",
    }),
    (error) => {
      assert.match(error.message, /Participant prerequisites failed safely/);
      assert.equal(error.message.includes("private command detail"), false);
      return true;
    },
  );
});

test("prerequisite inspection rejects unsupported roles, platforms, and dependency shapes", async () => {
  const fx = fixture();
  for (const overrides of [
    { role: "operator" },
    { platform: "aix" },
    { execute: null },
    { resolveExecutable: null },
  ]) {
    await assert.rejects(
      inspectParticipantPrerequisites({
        execute: fx.execute,
        nodeVersion: fx.nodeVersion,
        platform: fx.platform,
        resolveExecutable: fx.resolveExecutable,
        role: "payer",
        ...overrides,
      }),
      /Participant prerequisites failed safely/,
    );
  }
});
