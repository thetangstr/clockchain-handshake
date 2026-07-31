import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  createHash,
  generateKeyPairSync,
  sign,
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
  createPayerBootstrapKey,
  openSignedPayerBootstrapPackage,
  payerBootstrapClaimFingerprint,
  sealSignedPayerBootstrapPackage,
  sshEd25519Fingerprint,
  validatePayerBootstrapClaim,
} from "../src/bilateral/local-mcp/payer-bootstrap-envelope.mjs";
import {
  createLaunchManifest,
  validateLaunchManifest,
} from "../src/bilateral/coordination/manifest.mjs";
import {
  canonicalizeReceiptEventValue,
} from "../src/canonical.mjs";

const REPOSITORY_SHA = "abcdef0123456789abcdef0123456789abcdef01";
const RELEASE_ID = "release-payer-bootstrap";
const SESSION_ID = "22222222-2222-4222-8222-222222222222";
const CLAIM_NONCE = "11111111-1111-4111-8111-111111111111";

function certificatePem(host = "payer.clockchain.network") {
  const root = mkdtempSync(
    join(tmpdir(), "payer-bootstrap-envelope-"),
  );
  try {
    const certificatePath = join(root, "payer-mcp.crt");
    const privateKeyPath = join(root, "payer-mcp.key");
    execFileSync("openssl", [
      "req",
      "-x509",
      "-newkey",
      "ed25519",
      "-keyout",
      privateKeyPath,
      "-out",
      certificatePath,
      "-nodes",
      "-days",
      "1",
      "-subj",
      `/CN=${host}`,
      "-addext",
      `subjectAltName=DNS:${host}`,
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

function claimFixture(overrides = {}) {
  const bootstrap = createPayerBootstrapKey();
  const ssh = generateKeyPairSync("ed25519");
  const sshPublicKey = openSshPublicKey(ssh);
  return {
    bootstrap,
    claim: {
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
    },
  };
}

function canonicalBytes(value) {
  return Buffer.from(
    JSON.stringify(canonicalizeReceiptEventValue(value)),
    "utf8",
  );
}

function launchManifestFixture({
  claim,
  expiresAtMs = String(Date.now() + 60_000),
  overrides = {},
} = {}) {
  const relayCertificatePem = certificatePem(
    "relay.clockchain.network",
  );
  const manifest = createLaunchManifest({
    expectedTlsFingerprint: createHash("sha256")
      .update(new X509Certificate(relayCertificatePem).raw)
      .digest("hex"),
    nowMs:
      Number(expiresAtMs) -
      3_600_000,
    operatorKeyId: "operator",
    payerMcpIntakeCapabilityDigest: "e".repeat(64),
    randomBytes: () => Buffer.alloc(32, 7),
    relayUrl: "https://relay.clockchain.network:8443",
    releaseId: claim.releaseId,
    repositorySha: claim.repositorySha,
    role: "payer",
    sessionId: claim.sessionId,
    tlsCertificatePem: relayCertificatePem,
    ...overrides,
  }).manifest;
  return canonicalBytes(manifest);
}

function packageFixture(claim, operator) {
  const expiresAtMs = String(Date.now() + 60_000);
  return sealSignedPayerBootstrapPackage({
    bootstrapBrokerCapability: "c".repeat(64),
    bootstrapBrokerUrl: "https://bootstrap.internal.example/v1/requestor-claims",
    claim,
    expiresAtMs,
    launchManifestBytes: launchManifestFixture({
      claim,
      expiresAtMs,
    }),
    operatorKeyId: "operator",
    signer: (bytes) =>
      sign(null, bytes, operator.privateKey).toString("base64"),
    tunnelGrantBytes: canonicalBytes({
      expiresAtMs: String(Date.now() + 60_000),
      paymentMoved: false,
      schema: "clockchain.payer-tunnel-grant/v1",
      sessionId: SESSION_ID,
    }),
  });
}

test("validates the exact Payer claim and binds every public key and fingerprint", () => {
  const { claim } = claimFixture();
  assert.deepEqual(Object.keys(claim), [
    "claimNonce",
    "mcpTlsCertificatePem",
    "mcpTlsFingerprint",
    "paymentMoved",
    "releaseId",
    "repositorySha",
    "role",
    "schema",
    "sessionId",
    "sshPublicKey",
    "sshPublicKeyFingerprint",
    "x25519PublicKey",
  ]);
  assert.deepEqual(validatePayerBootstrapClaim(claim), claim);
  assert.match(payerBootstrapClaimFingerprint(claim), /^[0-9a-f]{64}$/);
});

test("seals and verifies private Payer material without exposing it in the signed response", () => {
  const operator = generateKeyPairSync("ed25519");
  const { bootstrap, claim } = claimFixture();
  const response = packageFixture(claim, operator);
  const wire = JSON.stringify(response);

  assert.deepEqual(Object.keys(response), [
    "claimFingerprint",
    "envelope",
    "expiresAtMs",
    "operatorKeyId",
    "paymentMoved",
    "schema",
    "signature",
  ]);
  for (const secret of [
    "clockchain.bilateral-launch-manifest/v1",
    "bootstrap.internal.example",
    "c".repeat(64),
    "clockchain.payer-tunnel-grant/v1",
  ]) {
    assert.equal(wire.includes(secret), false);
  }

  const consumed = new Set();
  const opened = openSignedPayerBootstrapPackage({
    claim,
    consumeClaimNonce: (nonce) => {
      if (consumed.has(nonce)) return false;
      consumed.add(nonce);
      return true;
    },
    expectedReleaseId: RELEASE_ID,
    expectedRepositorySha: REPOSITORY_SHA,
    expectedSessionId: SESSION_ID,
    nowMs: Date.now(),
    operatorPublicKey: operator.publicKey,
    payerPrivateKey: bootstrap.privateKey,
    response,
  });
  assert.equal(opened.bootstrapBrokerCapability, "c".repeat(64));
  assert.equal(
    opened.bootstrapBrokerUrl,
    "https://bootstrap.internal.example/v1/requestor-claims",
  );
  assert.equal(opened.paymentMoved, false);
  const openedManifest = validateLaunchManifest(
    JSON.parse(opened.launchManifestBytes.toString("utf8")),
  );
  assert.equal(openedManifest.role, "payer");
  assert.equal(openedManifest.releaseId, RELEASE_ID);
  assert.equal(openedManifest.repositorySha, REPOSITORY_SHA);
  assert.equal(openedManifest.sessionId, SESSION_ID);
  assert.equal(
    Object.hasOwn(
      JSON.parse(opened.launchManifestBytes.toString("utf8")),
      "paymentMoved",
    ),
    false,
  );
  assert.equal(
    JSON.parse(opened.tunnelGrantBytes.toString("utf8")).schema,
    "clockchain.payer-tunnel-grant/v1",
  );

  assert.throws(
    () =>
      openSignedPayerBootstrapPackage({
        claim,
        consumeClaimNonce: () => false,
        expectedReleaseId: RELEASE_ID,
        expectedRepositorySha: REPOSITORY_SHA,
        expectedSessionId: SESSION_ID,
        nowMs: Date.now(),
        operatorPublicKey: operator.publicKey,
        payerPrivateKey: bootstrap.privateKey,
        response,
      }),
    /Payer bootstrap envelope validation failed/,
  );
});

test("fails closed on changed claim authority, expiry, replay, and moved-payment state", () => {
  const operator = generateKeyPairSync("ed25519");
  const { bootstrap, claim } = claimFixture();
  const response = packageFixture(claim, operator);
  const base = {
    claim,
    consumeClaimNonce: () => true,
    expectedReleaseId: RELEASE_ID,
    expectedRepositorySha: REPOSITORY_SHA,
    expectedSessionId: SESSION_ID,
    nowMs: Date.now(),
    operatorPublicKey: operator.publicKey,
    payerPrivateKey: bootstrap.privateKey,
    response,
  };
  const alternate = claimFixture();

  for (const changedClaim of [
    { ...claim, role: "requestor" },
    { ...claim, sessionId: "33333333-3333-4333-8333-333333333333" },
    { ...claim, releaseId: "other-release" },
    { ...claim, repositorySha: "b".repeat(40) },
    { ...claim, mcpTlsCertificatePem: `${claim.mcpTlsCertificatePem}changed` },
    { ...claim, mcpTlsFingerprint: "b".repeat(64) },
    { ...claim, sshPublicKey: alternate.claim.sshPublicKey },
    { ...claim, sshPublicKeyFingerprint: alternate.claim.sshPublicKeyFingerprint },
    { ...claim, x25519PublicKey: alternate.claim.x25519PublicKey },
    { ...claim, paymentMoved: true },
  ]) {
    assert.throws(
      () =>
        openSignedPayerBootstrapPackage({
          ...base,
          claim: changedClaim,
        }),
      /Payer bootstrap envelope validation failed/,
    );
  }

  assert.throws(
    () =>
      openSignedPayerBootstrapPackage({
        ...base,
        nowMs: Number(response.expiresAtMs) + 1,
      }),
    /Payer bootstrap envelope validation failed/,
  );
  assert.throws(
    () =>
      openSignedPayerBootstrapPackage({
        ...base,
        expectedReleaseId: "other-release",
      }),
    /Payer bootstrap envelope validation failed/,
  );
  assert.throws(
    () =>
      openSignedPayerBootstrapPackage({
        ...base,
        expectedRepositorySha: "b".repeat(40),
      }),
    /Payer bootstrap envelope validation failed/,
  );
  assert.throws(
    () =>
      openSignedPayerBootstrapPackage({
        ...base,
        expectedSessionId: "33333333-3333-4333-8333-333333333333",
      }),
    /Payer bootstrap envelope validation failed/,
  );
  assert.throws(
    () =>
      sealSignedPayerBootstrapPackage({
        bootstrapBrokerCapability: "c".repeat(64),
        bootstrapBrokerUrl: "https://bootstrap.internal.example/v1/requestor-claims",
        claim,
        expiresAtMs: String(Date.now() + 60_000),
        launchManifestBytes: canonicalBytes({
          ...JSON.parse(
            launchManifestFixture({
              claim,
              expiresAtMs: String(Date.now() + 60_000),
            }).toString("utf8"),
          ),
          paymentMoved: false,
        }),
        operatorKeyId: "operator",
        signer: (bytes) =>
          sign(null, bytes, operator.privateKey).toString("base64"),
        tunnelGrantBytes: canonicalBytes({
          paymentMoved: false,
          schema: "clockchain.payer-tunnel-grant/v1",
        }),
      }),
    /Payer bootstrap envelope validation failed/,
  );
  assert.throws(
    () =>
      sealSignedPayerBootstrapPackage({
        bootstrapBrokerCapability: "c".repeat(64),
        bootstrapBrokerUrl: "https://bootstrap.internal.example/v1/requestor-claims",
        claim,
        expiresAtMs: String(Date.now() + 120_000),
        launchManifestBytes: launchManifestFixture({
          claim,
          expiresAtMs: String(Date.now() + 60_000),
        }),
        operatorKeyId: "operator",
        signer: (bytes) =>
          sign(null, bytes, operator.privateKey).toString("base64"),
        tunnelGrantBytes: canonicalBytes({
          paymentMoved: false,
          schema: "clockchain.payer-tunnel-grant/v1",
        }),
      }),
    /Payer bootstrap envelope validation failed/,
  );
  assert.throws(
    () =>
      sealSignedPayerBootstrapPackage({
        bootstrapBrokerCapability: "c".repeat(64),
        bootstrapBrokerUrl: "https://bootstrap.internal.example/v1/requestor-claims",
        claim,
        expiresAtMs: String(Date.now() + 60_000),
        launchManifestBytes: launchManifestFixture({
          claim,
          expiresAtMs: String(Date.now() + 60_000),
          overrides: {
            repositorySha: "b".repeat(40),
          },
        }),
        operatorKeyId: "operator",
        signer: (bytes) =>
          sign(null, bytes, operator.privateKey).toString("base64"),
        tunnelGrantBytes: canonicalBytes({
          paymentMoved: false,
          schema: "clockchain.payer-tunnel-grant/v1",
        }),
      }),
    /Payer bootstrap envelope validation failed/,
  );
});
