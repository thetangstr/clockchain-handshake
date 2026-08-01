import assert from "node:assert/strict";
import {
  chmodSync,
  linkSync,
  lstatSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  isPayerMcpReadyProjection,
  readTunnelHealthProjection,
  writeTunnelHealthProjection,
} from "../src/bilateral/aws/tunnel-health.mjs";

const NOW = 2_000_000_000_000;

function root(t) {
  const path = mkdtempSync(
    join(tmpdir(), "aws-tunnel-health-"),
  );
  t.after(() =>
    rmSync(path, {
      force: true,
      recursive: true,
    }));
  return path;
}

function readyInput(overrides = {}) {
  return {
    claimFingerprint: "a".repeat(64),
    expiresAtMs: String(NOW + 60_000),
    mcpTlsFingerprint: "b".repeat(64),
    observedAtMs: NOW,
    paymentMoved: false,
    releaseId: "release-payer-bootstrap",
    repositorySha:
      "abcdef0123456789abcdef0123456789abcdef01",
    sessionId:
      "22222222-2222-4222-8222-222222222222",
    status: "READY",
    ...overrides,
  };
}

test("writes an exact READY tunnel health projection as private machine evidence", async (t) => {
  const path = join(root(t), "health.json");
  await writeTunnelHealthProjection(path, readyInput());
  const bytes = readFileSync(path, "utf8");
  const projection = JSON.parse(bytes);

  assert.equal(bytes.endsWith("\n"), true);
  assert.deepEqual(Object.keys(projection), [
    "schema",
    "releaseId",
    "repositorySha",
    "sessionId",
    "claimFingerprint",
    "mcpTlsFingerprint",
    "observedAtMs",
    "expiresAtMs",
    "paymentMoved",
    "status",
  ]);
  assert.deepEqual(projection, {
    schema: "clockchain.payer-tunnel-health/v1",
    releaseId: "release-payer-bootstrap",
    repositorySha:
      "abcdef0123456789abcdef0123456789abcdef01",
    sessionId:
      "22222222-2222-4222-8222-222222222222",
    claimFingerprint: "a".repeat(64),
    mcpTlsFingerprint: "b".repeat(64),
    observedAtMs: String(NOW),
    expiresAtMs: String(NOW + 60_000),
    paymentMoved: false,
    status: "READY",
  });
  assert.equal((lstatSync(path).mode & 0o777), 0o600);
  assert.equal(lstatSync(path).nlink, 1);
  assert.equal(isPayerMcpReadyProjection(projection), true);
});

test("writes exact non-READY projections without secrets or advisory authority", async (t) => {
  const path = join(root(t), "health.json");
  const input = readyInput({
    capability: "capability-canary",
    mcpTlsCertificatePem: "-----BEGIN CERTIFICATE-----",
    privatePath: "/private/canary",
    sshPublicKey: "ssh-ed25519 secret-canary",
    status: "UNHEALTHY",
  });

  await writeTunnelHealthProjection(path, input);

  const text = readFileSync(path, "utf8");
  const projection = JSON.parse(text);
  assert.equal(projection.status, "UNHEALTHY");
  assert.equal(projection.paymentMoved, false);
  assert.equal(isPayerMcpReadyProjection(projection), false);
  for (const forbidden of [
    "capability-canary",
    "BEGIN CERTIFICATE",
    "/private/canary",
    "ssh-ed25519",
    "advisory",
    "authority",
  ]) {
    assert.equal(text.includes(forbidden), false);
  }
});

test("rejects ambiguous paths, timestamps, statuses, and symlink replacement", async (t) => {
  const directory = root(t);
  await assert.rejects(
    writeTunnelHealthProjection(
      "relative-health.json",
      readyInput(),
    ),
    /Tunnel health projection failed safely/,
  );
  await assert.rejects(
    writeTunnelHealthProjection(
      join(directory, "bad-time.json"),
      readyInput({ observedAtMs: NOW + 60_001 }),
    ),
    /Tunnel health projection failed safely/,
  );
  await assert.rejects(
    writeTunnelHealthProjection(
      join(directory, "bad-status.json"),
      readyInput({ status: "PAYER_MCP_READY" }),
    ),
    /Tunnel health projection failed safely/,
  );

  const target = join(directory, "target");
  const link = join(directory, "link");
  writeFileSync(target, "target", { mode: 0o600 });
  symlinkSync(target, link);
  await assert.rejects(
    writeTunnelHealthProjection(link, readyInput()),
    /Tunnel health projection failed safely/,
  );
  assert.equal(readFileSync(target, "utf8"), "target");
});

test("reads a missing tunnel health projection as polling null and fails closed on permissive files", async (t) => {
  const directory = root(t);
  const path = join(directory, "health.json");
  assert.equal(await readTunnelHealthProjection(path), null);

  await writeTunnelHealthProjection(path, readyInput());
  assert.deepEqual(
    await readTunnelHealthProjection(path),
    JSON.parse(readFileSync(path, "utf8")),
  );

  chmodSync(path, 0o644);
  await assert.rejects(
    readTunnelHealthProjection(path),
    /Tunnel health projection failed safely/,
  );

  const body = readFileSync(path, "utf8");
  const target = join(directory, "target.json");
  const hardlink = join(directory, "hardlink.json");
  const symlinkPath = join(directory, "symlink.json");
  const oversized = join(directory, "oversized.json");
  const noncanonical = join(directory, "noncanonical.json");
  writeFileSync(target, body, { mode: 0o600 });
  linkSync(target, hardlink);
  symlinkSync(target, symlinkPath);
  writeFileSync(oversized, "x".repeat(131_073), { mode: 0o600 });
  writeFileSync(noncanonical, JSON.stringify({
    status: "READY",
    paymentMoved: false,
    expiresAtMs: String(NOW + 60_000),
    observedAtMs: String(NOW),
    mcpTlsFingerprint: "b".repeat(64),
    claimFingerprint: "a".repeat(64),
    sessionId:
      "22222222-2222-4222-8222-222222222222",
    repositorySha:
      "abcdef0123456789abcdef0123456789abcdef01",
    releaseId: "release-payer-bootstrap",
    schema: "clockchain.payer-tunnel-health/v1",
  }), { mode: 0o600 });

  for (const unsafe of [
    hardlink,
    symlinkPath,
    oversized,
    noncanonical,
  ]) {
    await assert.rejects(
      readTunnelHealthProjection(unsafe),
      /Tunnel health projection failed safely/,
      unsafe,
    );
  }
});
