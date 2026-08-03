import assert from "node:assert/strict";
import {
  createHash,
  generateKeyPairSync,
  sign,
} from "node:crypto";
import { test } from "node:test";

import {
  createSignedPayerBootstrapDiscovery,
  parsePayerBootstrapDiscoveryWire,
  publishPayerBootstrapDiscovery,
  sshEd25519Fingerprint,
  verifySignedPayerBootstrapDiscovery,
} from "../scripts/publish-payer-bootstrap-discovery.mjs";

const REPOSITORY_SHA = "abcdef0123456789abcdef0123456789abcdef01";
const IMAGE_DIGEST =
  "123456789012.dkr.ecr.us-west-2.amazonaws.com/clockchain-handshake@sha256:" +
  "a".repeat(64);
const RELEASE_ID = "release-payer-bootstrap";
const SESSION_ID = "22222222-2222-4222-8222-222222222222";
const OPERATOR_KEY_ID = "operator";

function rawEd25519PublicKey(pair) {
  return pair.publicKey
    .export({ format: "der", type: "spki" })
    .subarray(-32)
    .toString("base64");
}

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
  const blob = Buffer.concat([
    sshString("ssh-ed25519"),
    sshString(raw),
  ]);
  return `ssh-ed25519 ${blob.toString("base64")}`;
}

function validInput(overrides = {}) {
  const tunnel = generateKeyPairSync("ed25519");
  const tunnelHostPublicKey = openSshPublicKey(tunnel);
  return {
    expiresAtMs: String(Date.now() + 60_000),
    imageDigest: IMAGE_DIGEST,
    operatorKeyId: OPERATOR_KEY_ID,
    paymentMoved: false,
    payerClaimUrl: "https://bootstrap.clockchain.network/v1/payer-claims",
    publicMcpHostname: "payer.clockchain.network",
    publicMcpPort: 9443,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    schema: "clockchain.payer-bootstrap-discovery/v1",
    sessionId: SESSION_ID,
    tunnelHost: "tunnel.clockchain.network",
    tunnelHostPublicKey,
    tunnelHostKeyFingerprint: sshEd25519Fingerprint(tunnelHostPublicKey),
    tunnelPort: 443,
    ...overrides,
  };
}

test("creates and verifies the exact signed Payer discovery contract", () => {
  const operator = generateKeyPairSync("ed25519");
  const discovery = createSignedPayerBootstrapDiscovery({
    ...validInput(),
    signer: (bytes) =>
      sign(null, bytes, operator.privateKey).toString("base64"),
  });

  assert.deepEqual(Object.keys(discovery), [
    "expiresAtMs",
    "imageDigest",
    "operatorKeyId",
    "paymentMoved",
    "payerClaimUrl",
    "publicMcpHostname",
    "publicMcpPort",
    "releaseId",
    "repositorySha",
    "schema",
    "sessionId",
    "signature",
    "tunnelHost",
    "tunnelHostPublicKey",
    "tunnelHostKeyFingerprint",
    "tunnelPort",
  ]);
  assert.deepEqual(
    verifySignedPayerBootstrapDiscovery({
      discovery,
      expectedImageDigest: IMAGE_DIGEST,
      expectedPublicMcpHostname: "payer.clockchain.network",
      nowMs: Date.now(),
      operatorPublicKey: rawEd25519PublicKey(operator),
      repositorySha: REPOSITORY_SHA,
    }),
    discovery,
  );
  assert.equal(JSON.stringify(discovery).includes("PRIVATE KEY"), false);
});

test("discovery rejects stale, mutable, mismatched, malformed, and forged authority", () => {
  const operator = generateKeyPairSync("ed25519");
  const signDiscovery = (overrides = {}) =>
    createSignedPayerBootstrapDiscovery({
      ...validInput(overrides),
      signer: (bytes) =>
        sign(null, bytes, operator.privateKey).toString("base64"),
    });
  const verifyDiscovery = (discovery, overrides = {}) =>
    verifySignedPayerBootstrapDiscovery({
      discovery,
      expectedImageDigest: IMAGE_DIGEST,
      expectedPublicMcpHostname: "payer.clockchain.network",
      nowMs: Date.now(),
      operatorPublicKey: rawEd25519PublicKey(operator),
      repositorySha: REPOSITORY_SHA,
      ...overrides,
    });
  const valid = signDiscovery();

  for (const discovery of [
    { ...valid, expiresAtMs: "1" },
    { ...valid, imageDigest: IMAGE_DIGEST.replace("@sha256:", ":latest@sha256:") },
    { ...valid, paymentMoved: true },
    { ...valid, payerClaimUrl: "http://bootstrap.clockchain.network/v1/payer-claims" },
    { ...valid, payerClaimUrl: "https://bootstrap.clockchain.network/v1/other" },
    { ...valid, publicMcpHostname: "PAYER.clockchain.network" },
    { ...valid, publicMcpPort: 443 },
    { ...valid, repositorySha: "b".repeat(40) },
    { ...valid, schema: "clockchain.requestor-discovery/v1" },
    { ...valid, tunnelPort: 22 },
    { ...valid, tunnelHostKeyFingerprint: `SHA256:${"A".repeat(43)}` },
  ]) {
    assert.throws(
      () => verifyDiscovery(discovery),
      /Payer bootstrap discovery failed safely/,
    );
  }

  assert.throws(
    () =>
      verifyDiscovery({
        ...valid,
        signature: {
          ...valid.signature,
          value: Buffer.alloc(64).toString("base64"),
        },
      }),
    /Payer bootstrap discovery failed safely/,
  );
  assert.throws(
    () => verifyDiscovery(valid, { expectedImageDigest: IMAGE_DIGEST.replace("a", "b") }),
    /Payer bootstrap discovery failed safely/,
  );
  assert.throws(
    () => verifyDiscovery(valid, { expectedPublicMcpHostname: "other.clockchain.network" }),
    /Payer bootstrap discovery failed safely/,
  );
});

test("discovery wire parser rejects duplicate keys and noncanonical ordering", () => {
  const operator = generateKeyPairSync("ed25519");
  const discovery = createSignedPayerBootstrapDiscovery({
    ...validInput(),
    signer: (bytes) =>
      sign(null, bytes, operator.privateKey).toString("base64"),
  });
  const canonical = `${JSON.stringify(discovery)}\n`;
  assert.deepEqual(parsePayerBootstrapDiscoveryWire(canonical), discovery);

  const duplicate = canonical.replace(
    "\"imageDigest\"",
    `"expiresAtMs":"${discovery.expiresAtMs}","imageDigest"`,
  );
  const reordered = `${JSON.stringify({
    signature: discovery.signature,
    ...Object.fromEntries(
      Object.entries(discovery).filter(([key]) => key !== "signature"),
    ),
  })}\n`;
  for (const wire of [duplicate, reordered, canonical.trimEnd(), `${canonical}\n`]) {
    assert.throws(
      () => parsePayerBootstrapDiscoveryWire(wire),
      /Payer bootstrap discovery failed safely/,
    );
  }
});

test("publisher signs prepared public values and optionally uploads only public bytes", async () => {
  const operator = generateKeyPairSync("ed25519");
  const uploaded = [];
  const result = await publishPayerBootstrapDiscovery({
    ...validInput(),
    bucket: "clockchain-demo",
    discoveryKey: "demo/payer-bootstrap.json",
    putObject: async (input) => uploaded.push(input),
    region: "us-west-2",
    signer: (bytes) =>
      sign(null, bytes, operator.privateKey).toString("base64"),
  });

  assert.equal(result.paymentMoved, false);
  assert.equal(
    result.discoveryUrl,
    "https://clockchain-demo.s3.us-west-2.amazonaws.com/demo/payer-bootstrap.json",
  );
  assert.equal(uploaded.length, 1);
  assert.equal(uploaded[0].contentType, "application/json");
  assert.equal(
    createHash("sha256").update(uploaded[0].body).digest("hex"),
    createHash("sha256")
      .update(`${JSON.stringify(result.discovery)}\n`)
      .digest("hex"),
  );
  assert.equal(JSON.stringify(uploaded).includes("PRIVATE KEY"), false);

  const staged = await publishPayerBootstrapDiscovery({
    ...validInput(),
    signer: (bytes) =>
      sign(null, bytes, operator.privateKey).toString("base64"),
  });
  assert.equal(staged.discoveryUrl, null);
  assert.equal(staged.paymentMoved, false);
});
