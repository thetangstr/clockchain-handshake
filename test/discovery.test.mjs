import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";

import {
  buildDiscoveryDocument,
  DISCOVERY_SCHEMA,
  DiscoveryError,
  signDiscoveryDocument,
  verifyDiscoveryDocument,
} from "../src/roles/discovery.mjs";

const ISSUED_AT_MS = 1_800_000_000_000;

const { privateKey, publicKey } = generateKeyPairSync(
  "ed25519",
);
const PRIVATE_KEY_PEM = privateKey.export({
  format: "pem",
  type: "pkcs8",
}).toString();
const PUBLIC_KEY_BASE64 = Buffer.from(
  publicKey.export({ format: "der", type: "spki" }),
)
  .subarray(-32)
  .toString("base64");

function documentFields(overrides = {}) {
  return {
    chainId: "11155111",
    clockchainUrl: "https://mcp.clockchain.network/mcp",
    expiresAtMs: String(ISSUED_AT_MS + 3_600_000),
    issuedAtMs: String(ISSUED_AT_MS),
    kitManifestDigest: "cd".repeat(32),
    kitRepoUrl:
      "https://example.com/clockchain/handshake.git",
    operatorKeyId: "operator-demo-key",
    payerEndpoint:
      "https://relay.example.com/v1/sessions/" +
      "4a7d2e56-9c3b-4f1a-8d2e-5b6c7d8e9f0a/messages",
    paymentMoved: false,
    protocolVersion:
      "clockchain.bilateral-authorization/v1",
    registry: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
    relayUrl: "https://relay.example.com",
    repositorySha:
      "0123456789abcdef0123456789abcdef01234567",
    schema: DISCOVERY_SCHEMA,
    sessionId: "4a7d2e56-9c3b-4f1a-8d2e-5b6c7d8e9f0a",
    subjectRun: "stakeholder",
    ...overrides,
  };
}

function sign(fields = documentFields()) {
  return signDiscoveryDocument({
    document: fields,
    privateKeyPem: PRIVATE_KEY_PEM,
  });
}

test("round-trips a signed discovery document", () => {
  const signed = sign();
  const verified = verifyDiscoveryDocument({
    document: signed,
    expectedPublicKey: PUBLIC_KEY_BASE64,
    nowMs: ISSUED_AT_MS + 1_000,
  });
  assert.equal(verified.schema, DISCOVERY_SCHEMA);
  assert.equal(verified.subjectRun, "stakeholder");
  assert.equal(verified.paymentMoved, false);
  assert.equal(
    verified.signature.publicKey,
    PUBLIC_KEY_BASE64,
  );
  assert.equal(verified.signature.algorithm, "ed25519");
  assert.equal(verified.signature.keyId, "operator-demo-key");
  assert.ok(Object.isFrozen(verified));
});

test("accepts a loopback relayUrl for local runs", () => {
  const signed = sign(
    documentFields({
      relayUrl: "http://127.0.0.1:8787",
      payerEndpoint:
        "http://127.0.0.1:8787/v1/sessions/" +
        "4a7d2e56-9c3b-4f1a-8d2e-5b6c7d8e9f0a/messages",
    }),
  );
  const verified = verifyDiscoveryDocument({
    document: signed,
    nowMs: ISSUED_AT_MS + 1_000,
  });
  assert.equal(verified.relayUrl, "http://127.0.0.1:8787");
});

test("rejects tampering, wrong keys, and staleness", () => {
  const signed = sign();

  const tampered = { ...signed, relayUrl: "https://evil.example.com" };
  assert.throws(
    () =>
      verifyDiscoveryDocument({
        document: tampered,
        nowMs: ISSUED_AT_MS + 1_000,
      }),
    (error) => {
      assert.ok(error instanceof DiscoveryError);
      assert.equal(error.code, "DISCOVERY_SIGNATURE");
      return true;
    },
  );

  const other = generateKeyPairSync("ed25519");
  const otherPublic = Buffer.from(
    other.publicKey.export({ format: "der", type: "spki" }),
  )
    .subarray(-32)
    .toString("base64");
  assert.throws(
    () =>
      verifyDiscoveryDocument({
        document: signed,
        expectedPublicKey: otherPublic,
        nowMs: ISSUED_AT_MS + 1_000,
      }),
    { code: "DISCOVERY_KEY_MISMATCH" },
  );

  assert.throws(
    () =>
      verifyDiscoveryDocument({
        document: signed,
        nowMs: ISSUED_AT_MS + 3_600_000,
      }),
    { code: "DISCOVERY_EXPIRED" },
  );
  assert.throws(
    () =>
      verifyDiscoveryDocument({
        document: signed,
        nowMs: ISSUED_AT_MS - 1,
      }),
    { code: "DISCOVERY_EXPIRED" },
  );
});

test("rejects malformed documents at construction", () => {
  for (const overrides of [
    { schema: "handshake-discovery/v1" },
    { subjectRun: "production" },
    { paymentMoved: true },
    { chainId: "1" },
    { registry: `0x${"11".repeat(20)}` },
    { relayUrl: "http://relay.example.com" },
    { clockchainUrl: "http://127.0.0.1:8787" },
    { repositorySha: "latest" },
    { kitManifestDigest: "0".repeat(63) },
    { protocolVersion: "clockchain.bilateral-authorization/v0" },
    { operatorKeyId: "Bad Key" },
    { sessionId: "not-a-uuid" },
  ]) {
    assert.throws(
      () => buildDiscoveryDocument(documentFields(overrides)),
      (error) => {
        assert.ok(error instanceof DiscoveryError);
        return true;
      },
    );
  }
  assert.throws(
    () =>
      buildDiscoveryDocument({
        ...documentFields(),
        extra: true,
      }),
    DiscoveryError,
  );
  const missing = documentFields();
  delete missing.relayUrl;
  assert.throws(
    () => buildDiscoveryDocument(missing),
    DiscoveryError,
  );
});

test("enforces the human-paced expiry window at construction", () => {
  assert.throws(
    () =>
      buildDiscoveryDocument(
        documentFields({
          expiresAtMs: String(ISSUED_AT_MS + 1_799_999),
        }),
      ),
    { code: "DISCOVERY_WINDOW" },
  );
  assert.doesNotThrow(() =>
    buildDiscoveryDocument(
      documentFields({
        expiresAtMs: String(ISSUED_AT_MS + 1_800_000),
      }),
    )
  );
});

test("rejects malformed signature blocks", () => {
  const signed = sign();
  for (const signature of [
    { ...signed.signature, algorithm: "rsa" },
    { ...signed.signature, keyId: "other-key" },
    { ...signed.signature, publicKey: "short" },
    { ...signed.signature, value: "short" },
  ]) {
    assert.throws(
      () =>
        verifyDiscoveryDocument({
          document: { ...signed, signature },
          nowMs: ISSUED_AT_MS + 1_000,
        }),
      { code: "DISCOVERY_SIGNATURE_SHAPE" },
    );
  }
});
