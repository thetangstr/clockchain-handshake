import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  createHash,
  generateKeyPairSync,
  verify,
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
  buildAwsBootstrapSealedResponse,
} from "../infra/aws/runtime/operator-bootstrap-response.mjs";
import {
  canonicalizeReceiptEventValue,
} from "../src/canonical.mjs";
import {
  requestorBootstrapClaimFingerprint,
} from "../src/bilateral/aws/bootstrap-state.mjs";
import {
  authorizeTunnelConnection,
} from "../src/bilateral/aws/tunnel-grant.mjs";
import {
  createLaunchManifest,
} from "../src/bilateral/coordination/manifest.mjs";
import {
  createRequestorBootstrapKey,
  openRequestorBootstrapEnvelope,
} from "../src/bilateral/local-mcp/bootstrap-envelope.mjs";
import {
  createPayerBootstrapKey,
  openSignedPayerBootstrapPackage,
  payerBootstrapClaimFingerprint,
  sshEd25519Fingerprint,
} from "../src/bilateral/local-mcp/payer-bootstrap-envelope.mjs";

const NOW = 2_000_000_000_000;
const REPOSITORY_SHA =
  "abcdef0123456789abcdef0123456789abcdef01";
const RELEASE_ID = "release-bd7662a5eeb41614";
const SESSION_ID =
  "11111111-1111-4111-8111-111111111111";

function certificate(host = "relay.example.test") {
  const root = mkdtempSync(
    join(tmpdir(), "aws-bootstrap-response-"),
  );
  try {
    const certificatePath = join(root, "relay.crt");
    execFileSync("openssl", [
      "req", "-x509", "-newkey", "ed25519",
      "-keyout", join(root, "relay.key"),
      "-out", certificatePath, "-nodes", "-days", "1",
      "-subj", `/CN=${host}`,
      "-addext", `subjectAltName=DNS:${host}`,
    ], { stdio: "ignore" });
    return readFileSync(certificatePath, "utf8");
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
}

function sshPublicKey(pair) {
  const field = (value) => {
    const bytes = Buffer.isBuffer(value)
      ? value
      : Buffer.from(value);
    const length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.length);
    return Buffer.concat([length, bytes]);
  };
  const raw = pair.publicKey
    .export({ format: "der", type: "spki" })
    .subarray(-32);
  return `ssh-ed25519 ${Buffer.concat([
    field("ssh-ed25519"),
    field(raw),
  ]).toString("base64")}`;
}

test("builds a decryptable, operator-signed Requestor response from the exact coordinator manifest", () => {
  const tlsCertificatePem = certificate();
  const fingerprint = createHash("sha256")
    .update(new X509Certificate(tlsCertificatePem).raw)
    .digest("hex");
  const operator = generateKeyPairSync("ed25519");
  const requestor = createRequestorBootstrapKey();
  const claim = {
    claimNonce: "22222222-2222-4222-8222-222222222222",
    paymentMoved: false,
    repositorySha: REPOSITORY_SHA,
    requestorPublicKey: requestor.publicKey,
  };
  const manifest = createLaunchManifest({
    expectedTlsFingerprint: fingerprint,
    nowMs: NOW,
    operatorKeyId: "operator",
    payerMcpIntakeCapability: "c".repeat(64),
    randomBytes: () => Buffer.alloc(32, 1),
    relayUrl: "https://relay.example.test:8443",
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    role: "payee",
    sessionId: SESSION_ID,
    tlsCertificatePem,
  }).manifest;
  const manifestBytes = Buffer.from(
    JSON.stringify(
      canonicalizeReceiptEventValue(manifest),
    ),
  );
  const result = buildAwsBootstrapSealedResponse({
    claim,
    claimFingerprint: requestorBootstrapClaimFingerprint(claim),
    config: {
      bootstrapBrokerCapability: "d".repeat(64),
      bootstrapBrokerUrl: "https://bootstrap.example.test/v1/requestor-claims",
      nowMs: NOW + 1,
      operatorKeyId: "operator",
      operatorPrivateKeyPem: operator.privateKey.export({ format: "pem", type: "pkcs8" }),
      publicMcpHostname: "payer.example.test",
      releaseId: RELEASE_ID,
      repositorySha: REPOSITORY_SHA,
      sessionId: SESSION_ID,
    },
    expiresAtMs: manifest.expiresAtMs,
    payeeLaunchManifestBytes: manifestBytes,
    payerLaunchManifestBytes: Buffer.from("unused"),
    role: "payee",
  });
  assert.equal(result.tunnelGrant, null);
  assert.deepEqual(
    openRequestorBootstrapEnvelope({
      context: result.response.context,
      envelope: result.response.envelope,
      requestorPrivateKey: requestor.privateKey,
    }),
    manifestBytes,
  );
  const { signature, ...unsigned } = result.response;
  assert.equal(
    verify(
      null,
      Buffer.from(JSON.stringify(unsigned)),
      operator.publicKey,
      Buffer.from(signature.value, "base64"),
    ),
    true,
  );
  assert.equal(JSON.stringify(result).includes("d".repeat(64)), false);
});

test("rejects a parseable non-Ed25519 operator key before signing a Requestor response", () => {
  const tlsCertificatePem = certificate();
  const fingerprint = createHash("sha256")
    .update(new X509Certificate(tlsCertificatePem).raw)
    .digest("hex");
  const operator = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  const requestor = createRequestorBootstrapKey();
  const claim = {
    claimNonce: "22222222-2222-4222-8222-222222222222",
    paymentMoved: false,
    repositorySha: REPOSITORY_SHA,
    requestorPublicKey: requestor.publicKey,
  };
  const manifest = createLaunchManifest({
    expectedTlsFingerprint: fingerprint,
    nowMs: NOW,
    operatorKeyId: "operator",
    payerMcpIntakeCapability: "c".repeat(64),
    randomBytes: () => Buffer.alloc(32, 1),
    relayUrl: "https://relay.example.test:8443",
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    role: "payee",
    sessionId: SESSION_ID,
    tlsCertificatePem,
  }).manifest;
  const manifestBytes = Buffer.from(
    JSON.stringify(
      canonicalizeReceiptEventValue(manifest),
    ),
  );

  assert.throws(
    () =>
      buildAwsBootstrapSealedResponse({
        claim,
        claimFingerprint:
          requestorBootstrapClaimFingerprint(claim),
        config: {
          bootstrapBrokerCapability: "d".repeat(64),
          bootstrapBrokerUrl: "https://bootstrap.example.test/v1/requestor-claims",
          nowMs: NOW + 1,
          operatorKeyId: "operator",
          operatorPrivateKeyPem: operator.privateKey.export({
            format: "pem",
            type: "pkcs8",
          }),
          publicMcpHostname: "payer.example.test",
          releaseId: RELEASE_ID,
          repositorySha: REPOSITORY_SHA,
          sessionId: SESSION_ID,
        },
        expiresAtMs: manifest.expiresAtMs,
        payeeLaunchManifestBytes: manifestBytes,
        payerLaunchManifestBytes: Buffer.from("unused"),
        role: "payee",
      }),
    /AWS operator bootstrap response failed safely/,
  );
});

test("builds the exact Payer package and restricted tunnel grant without exposing either plaintext", () => {
  const relayCertificate = certificate();
  const relayFingerprint = createHash("sha256")
    .update(new X509Certificate(relayCertificate).raw)
    .digest("hex");
  const payerCertificate = certificate("payer.example.test");
  const operator = generateKeyPairSync("ed25519");
  const bootstrap = createPayerBootstrapKey();
  const ssh = generateKeyPairSync("ed25519");
  const sshKey = sshPublicKey(ssh);
  const claim = {
    claimNonce: "33333333-3333-4333-8333-333333333333",
    mcpTlsCertificatePem: payerCertificate,
    mcpTlsFingerprint: createHash("sha256")
      .update(new X509Certificate(payerCertificate).raw)
      .digest("hex"),
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    role: "payer",
    schema: "clockchain.payer-bootstrap-claim/v1",
    sessionId: SESSION_ID,
    sshPublicKey: sshKey,
    sshPublicKeyFingerprint: sshEd25519Fingerprint(sshKey),
    x25519PublicKey: bootstrap.publicKey,
  };
  const manifest = createLaunchManifest({
    expectedTlsFingerprint: relayFingerprint,
    nowMs: NOW,
    operatorKeyId: "operator",
    payerMcpIntakeCapabilityDigest: "e".repeat(64),
    randomBytes: () => Buffer.alloc(32, 2),
    relayUrl: "https://relay.example.test:8443",
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    role: "payer",
    sessionId: SESSION_ID,
    tlsCertificatePem: relayCertificate,
  }).manifest;
  const manifestBytes = Buffer.from(JSON.stringify(canonicalizeReceiptEventValue(manifest)));
  const result = buildAwsBootstrapSealedResponse({
    claim,
    claimFingerprint: payerBootstrapClaimFingerprint(claim),
    config: {
      bootstrapBrokerCapability: "d".repeat(64),
      bootstrapBrokerUrl: "https://bootstrap.example.test/v1/requestor-claims",
      nowMs: NOW + 1,
      operatorKeyId: "operator",
      operatorPrivateKeyPem: operator.privateKey.export({ format: "pem", type: "pkcs8" }),
      publicMcpHostname: "payer.example.test",
      releaseId: RELEASE_ID,
      repositorySha: REPOSITORY_SHA,
      sessionId: SESSION_ID,
    },
    expiresAtMs: manifest.expiresAtMs,
    payeeLaunchManifestBytes: Buffer.from("unused"),
    payerLaunchManifestBytes: manifestBytes,
    role: "payer",
  });
  assert.equal(result.tunnelGrant.claimFingerprint, payerBootstrapClaimFingerprint(claim));
  const opened = openSignedPayerBootstrapPackage({
    claim,
    consumeClaimNonce: () => true,
    expectedReleaseId: RELEASE_ID,
    expectedRepositorySha: REPOSITORY_SHA,
    expectedSessionId: SESSION_ID,
    nowMs: NOW + 2,
    operatorPublicKey: operator.publicKey,
    payerPrivateKey: bootstrap.privateKey,
    response: result.response.packageResponse,
  });
  assert.deepEqual(opened.launchManifestBytes, manifestBytes);
  const connected = authorizeTunnelConnection({
    activeGrant: result.tunnelGrant,
    connectionFingerprint: claim.sshPublicKeyFingerprint,
    nowMs: NOW + 3,
  });
  assert.equal(connected.connectionStatus, "CONNECTED");
  assert.throws(
    () =>
      authorizeTunnelConnection({
        activeGrant: result.tunnelGrant,
        connectionFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        nowMs: NOW + 3,
      }),
    /Tunnel grant validation failed safely/,
  );
  const wire = JSON.stringify(result.response);
  assert.equal(wire.includes("d".repeat(64)), false);
  assert.equal(wire.includes(claim.sshPublicKey), false);
});
