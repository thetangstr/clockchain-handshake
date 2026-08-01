import assert from "node:assert/strict";
import {
  createHash,
  generateKeyPairSync,
} from "node:crypto";
import {
  mkdtempSync,
  readFileSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  createAwsTunnelService,
} from "../scripts/run-aws-tunnel-service.mjs";
import {
  renderRestrictedAuthorizedKey,
} from "../src/bilateral/aws/tunnel-grant.mjs";
import {
  sshEd25519Fingerprint,
} from "../src/bilateral/local-mcp/payer-bootstrap-envelope.mjs";

const NOW = 2_000_000_000_000;

function sshString(value) {
  const bytes = Buffer.from(value);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

function sshPublicKey() {
  const pair = generateKeyPairSync("ed25519");
  const raw = pair.publicKey
    .export({ format: "der", type: "spki" })
    .subarray(-32);
  return `ssh-ed25519 ${Buffer.concat([
    sshString("ssh-ed25519"),
    sshString(raw),
  ]).toString("base64")}`;
}

function activeGrant(overrides = {}) {
  const key = sshPublicKey();
  return {
    claim: {
      mcpTlsFingerprint: createHash("sha256")
        .update("certificate")
        .digest("hex"),
      sshPublicKey: key,
      sshPublicKeyFingerprint:
        sshEd25519Fingerprint(key),
    },
    claimFingerprint: "a".repeat(64),
    connectionSequence: "1",
    connectionStatus: "CONNECTED",
    createdAtMs: String(NOW - 1_000),
    expiresAtMs: String(NOW + 60_000),
    lastConnectionAtMs: String(NOW - 1),
    paymentMoved: false,
    publicMcpHostname: "payer.clockchain.network",
    publicMcpPort: 9443,
    schema: "clockchain.payer-tunnel-grant/v1",
    status: "ACTIVE",
    tunnelPort: 443,
    ...overrides,
  };
}

function tombstone(grant, reason = "ABORT") {
  return {
    claimFingerprint: grant.claimFingerprint,
    expiresAtMs: grant.expiresAtMs,
    paymentMoved: false,
    publicMcpHostname: grant.publicMcpHostname,
    publicMcpPort: 9443,
    releaseId: "release-payer-bootstrap",
    repositorySha:
      "abcdef0123456789abcdef0123456789abcdef01",
    schema: "clockchain.payer-tunnel-tombstone/v1",
    sessionId:
      "22222222-2222-4222-8222-222222222222",
    status: "TOMBSTONED",
    terminalAtMs: String(NOW),
    terminalReason: reason,
    tunnelPort: 443,
  };
}

function fixture(t, grant = activeGrant()) {
  const stateRoot = mkdtempSync(
    join(tmpdir(), "aws-tunnel-service-"),
  );
  t.after(() =>
    rmSync(stateRoot, {
      force: true,
      recursive: true,
    }));
  const calls = [];
  const logs = [];
  let current = grant;
  const service = createAwsTunnelService({
    healthHost: "127.0.0.1",
    healthPort: 0,
    logger: {
      info(event) {
        logs.push(event);
      },
    },
    nowMs: () => NOW,
    probePinnedTls: async (input) => {
      calls.push(["probe", input]);
      return true;
    },
    processController: {
      async reload() {
        calls.push(["reload"]);
      },
      async start(input) {
        calls.push(["start", input]);
      },
      async stop() {
        calls.push(["stop"]);
      },
    },
    readGrant: async () => current,
    stateRoot,
    tombstoneGrant: ({ activeGrant, reason }) =>
      tombstone(activeGrant, reason),
    validateGrant(candidate) {
      if (
        candidate?.schema ===
        "clockchain.payer-tunnel-tombstone/v1"
      ) {
        return candidate;
      }
      if (
        candidate?.schema !==
          "clockchain.payer-tunnel-grant/v1" ||
        candidate.status !== "ACTIVE" ||
        candidate.paymentMoved !== false ||
        candidate.publicMcpPort !== 9443 ||
        candidate.tunnelPort !== 443 ||
        sshEd25519Fingerprint(
          candidate.claim?.sshPublicKey,
        ) !==
          candidate.claim?.sshPublicKeyFingerprint
      ) {
        throw new Error("invalid");
      }
      return candidate;
    },
    writeTombstone: async (value) => {
      current = value;
      calls.push(["tombstone", value]);
    },
  });
  return {
    calls,
    grant,
    logs,
    service,
    setGrant(value) {
      current = value;
    },
    stateRoot,
  };
}

test("atomically installs one restricted key and starts sshd on 2222", async (t) => {
  const fx = fixture(t);
  await fx.service.start();
  t.after(() => fx.service.stop());

  assert.deepEqual(fx.calls[0], [
    "start",
    {
      authorizedKeysPath: join(
        fx.stateRoot,
        "authorized_keys",
      ),
      port: 2222,
    },
  ]);
  assert.equal(
    readFileSync(
      join(fx.stateRoot, "authorized_keys"),
      "utf8",
    ),
    `${renderRestrictedAuthorizedKey({
      sshPublicKey: fx.grant.claim.sshPublicKey,
    })}\n`,
  );
  assert.equal(
    readFileSync(
      join(fx.stateRoot, "authorized_keys"),
    ).includes(Buffer.from("command=")),
    false,
  );
});

test("reports ready only after pinned TLS succeeds through local 9443", async (t) => {
  const fx = fixture(t);
  await fx.service.start();
  t.after(() => fx.service.stop());

  assert.equal(fx.service.health().status, "READY");
  assert.equal(fx.service.health().paymentMoved, false);
  assert.deepEqual(fx.calls.find(([kind]) => kind === "probe"), [
    "probe",
    {
      expectedFingerprint:
        fx.grant.claim.mcpTlsFingerprint,
      host: "127.0.0.1",
      port: 9443,
    },
  ]);
  const response = await fetch(fx.service.healthUrl);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    paymentMoved: false,
    status: "READY",
  });
});

test("stays attached and waits safely until an operator grant exists", async (t) => {
  const fx = fixture(t, null);
  await fx.service.start();
  t.after(() => fx.service.stop());

  assert.deepEqual(fx.service.health(), {
    paymentMoved: false,
    status: "UNHEALTHY",
  });
  assert.deepEqual(fx.calls, []);
  assert.deepEqual(fx.logs, [
    {
      paymentMoved: false,
      status: "WAITING",
    },
  ]);

  fx.setGrant(activeGrant());
  await fx.service.reconcile();
  assert.equal(fx.service.health().status, "READY");

  fx.setGrant(null);
  await fx.service.reconcile();
  assert.equal(fx.service.health().status, "UNHEALTHY");
  assert.equal(
    fx.calls.filter(([kind]) => kind === "stop")
      .length,
    1,
  );
});

test("same-key reconnect reloads while key drift and malformed records fail closed", async (t) => {
  const fx = fixture(t);
  await fx.service.start();
  t.after(() => fx.service.stop());
  fx.setGrant({
    ...fx.grant,
    connectionSequence: "2",
    lastConnectionAtMs: String(NOW),
  });
  await fx.service.reconcile();
  assert.equal(
    fx.calls.filter(([kind]) => kind === "reload")
      .length,
    1,
  );

  fx.setGrant({
    ...fx.grant,
    claim: {
      ...fx.grant.claim,
      sshPublicKey: sshPublicKey(),
    },
  });
  await assert.rejects(
    fx.service.reconcile(),
    /AWS tunnel service failed safely/,
  );
  assert.equal(fx.service.health().status, "UNHEALTHY");

  fx.setGrant({ status: "ACTIVE" });
  await assert.rejects(
    fx.service.reconcile(),
    /AWS tunnel service failed safely/,
  );
});

test("tombstones expiry and closes immediately on terminal records", async (t) => {
  const expired = activeGrant({
    expiresAtMs: String(NOW),
  });
  const fx = fixture(t, expired);
  await fx.service.start();
  t.after(() => fx.service.stop());
  const written = fx.calls.find(
    ([kind]) => kind === "tombstone",
  )?.[1];
  assert.equal(written.status, "TOMBSTONED");
  assert.equal(written.terminalReason, "EXPIRED");
  assert.equal(written.paymentMoved, false);
  assert.equal(fx.service.health().status, "UNHEALTHY");

  fx.setGrant(tombstone(expired, "ABORT"));
  await fx.service.reconcile();
  assert.equal(fx.service.health().status, "UNHEALTHY");
  assert.equal(
    fx.calls.some(([kind]) => kind === "start"),
    false,
  );
});

test("logs only bounded event names without grants, keys, certificates, paths, or commands", async (t) => {
  const fx = fixture(t);
  await fx.service.start();
  await fx.service.stop();
  const serialized = JSON.stringify(fx.logs);
  for (const forbidden of [
    fx.grant.claim.sshPublicKey,
    fx.grant.claim.mcpTlsFingerprint,
    fx.grant.claimFingerprint,
    fx.stateRoot,
    "permitlisten",
    "sshd",
  ]) {
    assert.equal(serialized.includes(forbidden), false);
  }
  assert.equal(
    fx.logs.every(
      (event) =>
        Object.keys(event).join(",") ===
          "paymentMoved,status" &&
        event.paymentMoved === false,
    ),
    true,
  );
});
