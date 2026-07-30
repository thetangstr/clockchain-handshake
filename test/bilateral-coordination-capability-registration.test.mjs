import assert from "node:assert/strict";
import {
  generateKeyPairSync,
} from "node:crypto";
import { test } from "node:test";

import {
  canonicalBytes,
} from "../src/bilateral/canonical.mjs";
import {
  CAPABILITY_REGISTRATION_SCHEMA,
  createCapabilityRegistration,
  verifyCapabilityRegistration,
} from "../src/bilateral/coordination/capability-registration.mjs";

const REPOSITORY_SHA = "a".repeat(40);
const SESSION_ID = "8f953393-86d0-4f99-9d6a-102f525fbecd";
const RELEASE_ID = "release-capability-registration";
const NOW_MS = 1_785_120_000_000;
const operator = generateKeyPairSync("ed25519");

function rawPublicKey(pair) {
  return pair.publicKey
    .export({ format: "der", type: "spki" })
    .subarray(-32)
    .toString("base64");
}

function privateKeyPem(pair) {
  return pair.privateKey.export({
    format: "pem",
    type: "pkcs8",
  });
}

function registration(overrides = {}) {
  return createCapabilityRegistration({
    capabilities: {
      payee: {
        capabilityDigest: "b".repeat(64),
        expiresAtMs: String(NOW_MS + 60_000),
      },
      payer: {
        capabilityDigest: "c".repeat(64),
        expiresAtMs: String(NOW_MS + 120_000),
      },
    },
    operatorKeyId: "operator-release-key",
    paymentMoved: false,
    privateKeyPem: privateKeyPem(operator),
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
    ...overrides,
  });
}

test("creates a canonical signed two-role capability registration", () => {
  const value = registration();
  assert.equal(value.schema, CAPABILITY_REGISTRATION_SCHEMA);
  assert.deepEqual(
    verifyCapabilityRegistration(value, {
      expectedOperatorKeyId: "operator-release-key",
      expectedOperatorPublicKey: rawPublicKey(operator),
      expectedRepositorySha: REPOSITORY_SHA,
      nowMs: NOW_MS,
    }),
    value,
  );
  assert.equal(canonicalBytes(value).includes(Buffer.from("private", "utf8")), false);
});

test("fails closed on malformed, duplicate, expired, excessive, and mismatched authority", () => {
  const valid = registration();
  const base = {
    expectedOperatorKeyId: "operator-release-key",
    expectedOperatorPublicKey: rawPublicKey(operator),
    expectedRepositorySha: REPOSITORY_SHA,
    nowMs: NOW_MS,
  };
  const cases = [
    { label: "extra key", value: { ...valid, extra: false } },
    { label: "expired", value: registration({ capabilities: { payee: { capabilityDigest: "b".repeat(64), expiresAtMs: String(NOW_MS) }, payer: { capabilityDigest: "c".repeat(64), expiresAtMs: String(NOW_MS + 120_000) } } }) },
    { label: "future expiry", value: registration({ capabilities: { payee: { capabilityDigest: "b".repeat(64), expiresAtMs: String(NOW_MS + 3_600_001) }, payer: { capabilityDigest: "c".repeat(64), expiresAtMs: String(NOW_MS + 120_000) } } }) },
    { label: "wrong key", value: valid, options: { ...base, expectedOperatorPublicKey: rawPublicKey(generateKeyPairSync("ed25519")) } },
    { label: "cross SHA", value: valid, options: { ...base, expectedRepositorySha: "d".repeat(40) } },
  ];
  for (const { label, options = base, value } of cases) {
    assert.throws(
      () => verifyCapabilityRegistration(value, options),
      { code: "COORDINATION_CAPABILITY_REGISTRATION_INVALID" },
      label,
    );
  }
  assert.throws(
    () => registration({ capabilities: { payee: { capabilityDigest: "b".repeat(64), expiresAtMs: String(NOW_MS + 60_000) }, payer: { capabilityDigest: "b".repeat(64), expiresAtMs: String(NOW_MS + 120_000) } } }),
    { code: "COORDINATION_CAPABILITY_REGISTRATION_INVALID" },
    "duplicate digest",
  );
});
