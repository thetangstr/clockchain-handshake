import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  createHash,
  generateKeyPairSync,
  X509Certificate,
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
  authorizeTunnelConnection,
  consumePayerClaim,
  createTunnelGrant,
  disconnectTunnelConnection,
  renderRestrictedAuthorizedKey,
  tombstoneTunnelGrant,
  validateTunnelGrantRecord,
} from "../src/bilateral/aws/tunnel-grant.mjs";
import {
  createPayerBootstrapKey,
  payerBootstrapClaimFingerprint,
  sshEd25519Fingerprint,
} from "../src/bilateral/local-mcp/payer-bootstrap-envelope.mjs";

const REPOSITORY_SHA = "abcdef0123456789abcdef0123456789abcdef01";
const RELEASE_ID = "release-payer-bootstrap";
const SESSION_ID = "22222222-2222-4222-8222-222222222222";
const CLAIM_NONCE = "11111111-1111-4111-8111-111111111111";
const NOW = 2_000_000_000_000;

function certificatePem() {
  const root = mkdtempSync(join(tmpdir(), "aws-tunnel-grant-"));
  try {
    const certificatePath = join(root, "payer-mcp.crt");
    const privateKeyPath = join(root, "payer-mcp.key");
    execFileSync("openssl", [
      "req", "-x509", "-newkey", "ed25519",
      "-keyout", privateKeyPath,
      "-out", certificatePath,
      "-nodes", "-days", "1",
      "-subj", "/CN=payer.clockchain.network",
      "-addext", "subjectAltName=DNS:payer.clockchain.network",
    ], { stdio: "ignore" });
    return readFileSync(certificatePath, "utf8");
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
}

const CERTIFICATE_PEM = certificatePem();

function sshString(value) {
  const bytes = Buffer.from(value);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

function openSshPublicKey(pair) {
  const raw = pair.publicKey
    .export({ format: "der", type: "spki" })
    .subarray(-32);
  return `ssh-ed25519 ${Buffer.concat([
    sshString("ssh-ed25519"),
    sshString(raw),
  ]).toString("base64")}`;
}

function payerClaim(overrides = {}) {
  const bootstrap = createPayerBootstrapKey();
  const ssh = generateKeyPairSync("ed25519");
  const sshPublicKey = openSshPublicKey(ssh);
  return {
    claimNonce: CLAIM_NONCE,
    mcpTlsCertificatePem: CERTIFICATE_PEM,
    mcpTlsFingerprint: createHash("sha256")
      .update(new X509Certificate(CERTIFICATE_PEM).raw)
      .digest("hex"),
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    role: "payer",
    schema: "clockchain.payer-bootstrap-claim/v1",
    sessionId: SESSION_ID,
    sshPublicKey,
    sshPublicKeyFingerprint: sshEd25519Fingerprint(sshPublicKey),
    x25519PublicKey: bootstrap.publicKey,
    ...overrides,
  };
}

function approve(claim, consumeClaimFingerprint = () => true) {
  return consumePayerClaim({
    claim,
    consumeClaimFingerprint,
    expectedClaimFingerprint:
      payerBootstrapClaimFingerprint(claim),
    expectedReleaseId: RELEASE_ID,
    expectedRepositorySha: REPOSITORY_SHA,
    expectedSessionId: SESSION_ID,
    nowMs: NOW,
    publicMcpHostname: "payer.clockchain.network",
    publicMcpPort: 9443,
    tunnelPort: 443,
  });
}

test("consumes one exact Payer claim and creates a fully bound active grant", () => {
  const claim = payerClaim();
  const consumed = new Set();
  const consumeClaimFingerprint = (fingerprint) => {
    if (consumed.has(fingerprint)) return false;
    consumed.add(fingerprint);
    return true;
  };
  const approved = approve(claim, consumeClaimFingerprint);

  assert.deepEqual(Object.keys(approved), [
    "approvedAtMs",
    "claim",
    "claimFingerprint",
    "paymentMoved",
    "publicMcpHostname",
    "publicMcpPort",
    "schema",
    "status",
    "tunnelPort",
  ]);
  assert.equal(approved.status, "APPROVED");
  assert.equal(approved.paymentMoved, false);
  assert.throws(
    () => approve(claim, consumeClaimFingerprint),
    /Tunnel grant validation failed safely/,
  );

  const grant = createTunnelGrant({
    approved,
    expiresAtMs: String(NOW + 60_000),
  });
  assert.equal(grant.status, "ACTIVE");
  assert.equal(grant.connectionStatus, "IDLE");
  assert.equal(grant.connectionSequence, "0");
  assert.equal(grant.publicMcpHostname, "payer.clockchain.network");
  assert.equal(grant.publicMcpPort, 9443);
  assert.equal(grant.tunnelPort, 443);
  assert.equal(grant.paymentMoved, false);
  assert.equal(grant.claim.sshPublicKey, claim.sshPublicKey);
  assert.equal(grant.claim.mcpTlsCertificatePem, claim.mcpTlsCertificatePem);
});

test("allows one connection and same-key reconnect only during the live grant", () => {
  const claim = payerClaim();
  const grant = createTunnelGrant({
    approved: approve(claim),
    expiresAtMs: String(NOW + 60_000),
  });
  const connected = authorizeTunnelConnection({
    activeGrant: grant,
    connectionFingerprint: claim.sshPublicKeyFingerprint,
    nowMs: NOW + 1,
  });
  assert.equal(connected.connectionStatus, "CONNECTED");
  assert.equal(connected.connectionSequence, "1");

  assert.throws(
    () =>
      authorizeTunnelConnection({
        activeGrant: connected,
        connectionFingerprint: claim.sshPublicKeyFingerprint,
        nowMs: NOW + 2,
      }),
    /Tunnel grant validation failed safely/,
  );
  assert.throws(
    () =>
      authorizeTunnelConnection({
        activeGrant: grant,
        connectionFingerprint: `SHA256:${"A".repeat(43)}`,
        nowMs: NOW + 2,
      }),
    /Tunnel grant validation failed safely/,
  );

  const disconnected = disconnectTunnelConnection({
    activeGrant: connected,
    connectionFingerprint: claim.sshPublicKeyFingerprint,
    nowMs: NOW + 3,
  });
  assert.equal(disconnected.connectionStatus, "IDLE");
  const reconnected = authorizeTunnelConnection({
    activeGrant: disconnected,
    connectionFingerprint: claim.sshPublicKeyFingerprint,
    nowMs: NOW + 4,
  });
  assert.equal(reconnected.connectionSequence, "2");
  assert.equal(reconnected.claimFingerprint, grant.claimFingerprint);
});

test("terminal success, failure, abort, and expiry create permanent tombstones", () => {
  for (const reason of ["SUCCESS", "FAILURE", "ABORT", "EXPIRED"]) {
    const claim = payerClaim();
    const grant = createTunnelGrant({
      approved: approve(claim),
      expiresAtMs: String(NOW + 60_000),
    });
    const tombstone = tombstoneTunnelGrant({
      activeGrant: grant,
      nowMs: reason === "EXPIRED" ? NOW + 60_001 : NOW + 1,
      reason,
    });
    assert.equal(tombstone.status, "TOMBSTONED");
    assert.equal(tombstone.terminalReason, reason);
    assert.equal(tombstone.paymentMoved, false);
    assert.equal(tombstone.claimFingerprint, grant.claimFingerprint);
    assert.equal(Object.hasOwn(tombstone, "claim"), false);
    assert.throws(
      () =>
        authorizeTunnelConnection({
          activeGrant: tombstone,
          connectionFingerprint: claim.sshPublicKeyFingerprint,
          nowMs: NOW + 2,
        }),
      /Tunnel grant validation failed safely/,
    );
  }
});

test("rejects changed claim, authority, role, session, release, SHA, hostname, and ports", () => {
  const claim = payerClaim();
  const fingerprint = payerBootstrapClaimFingerprint(claim);
  const base = {
    claim,
    consumeClaimFingerprint: () => true,
    expectedClaimFingerprint: fingerprint,
    expectedReleaseId: RELEASE_ID,
    expectedRepositorySha: REPOSITORY_SHA,
    expectedSessionId: SESSION_ID,
    nowMs: NOW,
    publicMcpHostname: "payer.clockchain.network",
    publicMcpPort: 9443,
    tunnelPort: 443,
  };
  const alternate = payerClaim();
  for (const override of [
    { claim: { ...claim, role: "requestor" } },
    { claim: { ...claim, sessionId: alternate.sessionId.replace("2222", "3333") } },
    { claim: { ...claim, releaseId: "other" } },
    { claim: { ...claim, repositorySha: "b".repeat(40) } },
    {
      claim: {
        ...claim,
        mcpTlsCertificatePem: `${claim.mcpTlsCertificatePem}changed`,
      },
    },
    { claim: { ...claim, mcpTlsFingerprint: "b".repeat(64) } },
    { claim: { ...claim, sshPublicKey: alternate.sshPublicKey } },
    {
      claim: {
        ...claim,
        sshPublicKeyFingerprint: alternate.sshPublicKeyFingerprint,
      },
    },
    { claim: { ...claim, x25519PublicKey: alternate.x25519PublicKey } },
    { expectedClaimFingerprint: "b".repeat(64) },
    { expectedReleaseId: "other" },
    { expectedRepositorySha: "b".repeat(40) },
    { expectedSessionId: "33333333-3333-4333-8333-333333333333" },
    { publicMcpHostname: "127.0.0.1" },
    { publicMcpHostname: "*.clockchain.network" },
    { publicMcpPort: 443 },
    { tunnelPort: 22 },
  ]) {
    assert.throws(
      () => consumePayerClaim({ ...base, ...override }),
      /Tunnel grant validation failed safely/,
    );
  }
});

test("renders exactly one restricted Ed25519 authorization line", () => {
  const claim = payerClaim();
  const canonicalBase64 = claim.sshPublicKey.split(" ")[1];
  assert.equal(
    renderRestrictedAuthorizedKey({
      sshPublicKey: claim.sshPublicKey,
    }),
    `restrict,port-forwarding,permitlisten="0.0.0.0:9443" ssh-ed25519 ${canonicalBase64} clockchain-payer`,
  );

  for (const sshPublicKey of [
    `command="sh" ${claim.sshPublicKey}`,
    `${claim.sshPublicKey} stakeholder-comment`,
    `ssh-rsa ${canonicalBase64}`,
    `ecdsa-sha2-nistp256 ${canonicalBase64}`,
    `${claim.sshPublicKey}\n${claim.sshPublicKey}`,
    `${claim.sshPublicKey} extra`,
    "ssh-ed25519 AAAA",
    "",
  ]) {
    assert.throws(
      () => renderRestrictedAuthorizedKey({ sshPublicKey }),
      /Tunnel grant validation failed safely/,
    );
  }
  assert.throws(
    () =>
      renderRestrictedAuthorizedKey({
        listenHost: "*",
        sshPublicKey: claim.sshPublicKey,
      }),
    /Tunnel grant validation failed safely/,
  );
  assert.throws(
    () =>
      renderRestrictedAuthorizedKey({
        listenPort: 9444,
        sshPublicKey: claim.sshPublicKey,
      }),
    /Tunnel grant validation failed safely/,
  );
});

test("validates only exact active grants and permanent tombstones for the tunnel service", () => {
  const claim = payerClaim();
  const grant = createTunnelGrant({
    approved: approve(claim),
    expiresAtMs: String(NOW + 60_000),
  });
  assert.deepEqual(
    validateTunnelGrantRecord(grant),
    grant,
  );
  const tombstone = tombstoneTunnelGrant({
    activeGrant: grant,
    nowMs: NOW + 1,
    reason: "ABORT",
  });
  assert.deepEqual(
    validateTunnelGrantRecord(tombstone),
    tombstone,
  );
  for (const candidate of [
    { ...grant, publicMcpPort: 443 },
    { ...grant, unexpected: true },
    { ...tombstone, terminalReason: "EXPIRED" },
    { ...tombstone, claim: claim },
    null,
  ]) {
    assert.throws(
      () => validateTunnelGrantRecord(candidate),
      /Tunnel grant validation failed safely/,
    );
  }
});
