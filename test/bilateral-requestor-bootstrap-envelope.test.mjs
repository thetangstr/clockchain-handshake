import assert from "node:assert/strict";
import test from "node:test";

import { canonicalBytes } from "../src/bilateral/canonical.mjs";
import {
  REQUESTOR_BOOTSTRAP_ENVELOPE_ALGORITHM,
  REQUESTOR_BOOTSTRAP_ENVELOPE_SCHEMA,
  createRequestorBootstrapKey,
  openRequestorBootstrapEnvelope,
  sealRequestorBootstrapManifest,
} from "../src/bilateral/local-mcp/bootstrap-envelope.mjs";

const CLAIM_NONCE = "11111111-2222-4333-8444-555555555555";
const RELEASE_ID = "release-a";
const REPOSITORY_SHA = "a".repeat(40);
const SESSION_ID = "22222222-3333-4444-8555-666666666666";
const SESSION_ID_V7 = "01890f0d-5d3b-7cc7-9f4b-123456789abc";
const PRIVATE_CANARY = "requestor-private-canary";
const KEY_CANARY = "requestor-key-canary";

function context(overrides = {}) {
  return {
    claimNonce: CLAIM_NONCE,
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
    ...overrides,
  };
}

function manifest(overrides = {}) {
  return {
    command: "launch-requestor-supervisor",
    privateSeed: PRIVATE_CANARY,
    schema: "clockchain.requestor-launch-manifest/v1",
    sessionId: SESSION_ID,
    ...overrides,
  };
}

function manifestBytes(value = manifest()) {
  return canonicalBytes(value);
}

function mutateBase64url(value) {
  const replacement = value[0] === "A" ? "B" : "A";
  return `${replacement}${value.slice(1)}`;
}

function base64urlPadBitAlias(value) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const last = alphabet.indexOf(value.at(-1));
  assert.notEqual(last, -1);
  return `${value.slice(0, -1)}${alphabet[last ^ 1]}`;
}

function assertSecretFree(error) {
  assert.ok(error instanceof Error);
  const serialized = JSON.stringify(error, Object.getOwnPropertyNames(error));
  assert.doesNotMatch(serialized, new RegExp(PRIVATE_CANARY));
  assert.doesNotMatch(serialized, new RegExp(KEY_CANARY));
}

async function assertRejectsSecretFree(fn) {
  await assert.rejects(
    async () => fn(),
    (error) => {
      assertSecretFree(error);
      return true;
    },
  );
}

test("seals and opens one exact requestor bootstrap envelope without payment movement", async () => {
  const requestorKey = await createRequestorBootstrapKey();
  const bytes = manifestBytes();
  const envelope = await sealRequestorBootstrapManifest({
    context: context(),
    manifestBytes: bytes,
    requestorPublicKey: requestorKey.publicKey,
  });

  assert.deepEqual(Object.keys(requestorKey), ["privateKey", "publicKey"]);
  assert.equal(typeof requestorKey.privateKey, "object");
  assert.equal(typeof requestorKey.publicKey, "string");
  assert.match(requestorKey.publicKey, /^[A-Za-z0-9_-]{43}$/);
  assert.deepEqual(Object.keys(envelope), [
    "algorithm",
    "ciphertextBase64url",
    "ephemeralPublicKey",
    "ivBase64url",
    "paymentMoved",
    "schema",
    "tagBase64url",
  ]);
  assert.equal(envelope.algorithm, REQUESTOR_BOOTSTRAP_ENVELOPE_ALGORITHM);
  assert.equal(envelope.schema, REQUESTOR_BOOTSTRAP_ENVELOPE_SCHEMA);
  assert.equal(envelope.paymentMoved, false);
  assert.match(envelope.ciphertextBase64url, /^[A-Za-z0-9_-]+$/);
  assert.match(envelope.ephemeralPublicKey, /^[A-Za-z0-9_-]{43}$/);
  assert.match(envelope.ivBase64url, /^[A-Za-z0-9_-]{16}$/);
  assert.match(envelope.tagBase64url, /^[A-Za-z0-9_-]{22}$/);
  assert.doesNotMatch(JSON.stringify(envelope), new RegExp(PRIVATE_CANARY));
  assert.doesNotMatch(String(requestorKey.privateKey), new RegExp(KEY_CANARY));

  const opened = await openRequestorBootstrapEnvelope({
    context: context(),
    envelope,
    requestorPrivateKey: requestorKey.privateKey,
  });
  assert.deepEqual(opened, bytes);
});

test("accepts repository session UUID versions while keeping claim nonce v4", async () => {
  const requestorKey = await createRequestorBootstrapKey();
  const bytes = manifestBytes(manifest({ sessionId: SESSION_ID_V7 }));
  const envelope = await sealRequestorBootstrapManifest({
    context: context({ sessionId: SESSION_ID_V7 }),
    manifestBytes: bytes,
    requestorPublicKey: requestorKey.publicKey,
  });

  const opened = await openRequestorBootstrapEnvelope({
    context: context({ sessionId: SESSION_ID_V7 }),
    envelope,
    requestorPrivateKey: requestorKey.privateKey,
  });
  assert.deepEqual(opened, bytes);
  await assertRejectsSecretFree(() => sealRequestorBootstrapManifest({
    context: context({ claimNonce: SESSION_ID_V7, sessionId: SESSION_ID_V7 }),
    manifestBytes: bytes,
    requestorPublicKey: requestorKey.publicKey,
  }));
});

test("rejects hostile context, envelope, key, and manifest inputs without leaking private material", async () => {
  const requestorKey = await createRequestorBootstrapKey();
  const wrongKey = await createRequestorBootstrapKey();
  const bytes = manifestBytes();
  const envelope = await sealRequestorBootstrapManifest({
    context: context(),
    manifestBytes: bytes,
    requestorPublicKey: requestorKey.publicKey,
  });

  const contextCases = [
    ["missing claim", () => { const value = context(); delete value.claimNonce; return value; }],
    ["extra field", () => context({ extra: "no" })],
    ["wrong claim", () => context({ claimNonce: "33333333-4444-4555-8666-777777777777" })],
    ["malformed claim", () => context({ claimNonce: "not-a-uuid" })],
    ["wrong release", () => context({ releaseId: "release-b" })],
    ["empty release", () => context({ releaseId: "" })],
    ["wrong session", () => context({ sessionId: "33333333-4444-4555-8666-777777777777" })],
    ["wrong sha", () => context({ repositorySha: "b".repeat(40) })],
    ["uppercase sha", () => context({ repositorySha: "A".repeat(40) })],
    ["payment moved", () => context({ paymentMoved: true })],
  ];
  for (const [, makeContext] of contextCases) {
    await assertRejectsSecretFree(() => openRequestorBootstrapEnvelope({
      context: makeContext(),
      envelope,
      requestorPrivateKey: requestorKey.privateKey,
    }));
  }

  for (const change of [
    (value) => { delete value.schema; },
    (value) => { value.extra = "no"; },
    (value) => { value.algorithm = "other"; },
    (value) => { value.paymentMoved = true; },
    (value) => { value.ciphertextBase64url = `${value.ciphertextBase64url}=`; },
    (value) => { value.ivBase64url = `${value.ivBase64url}+`; },
    (value) => { value.ephemeralPublicKey = "not-base64url"; },
    (value) => { value.ephemeralPublicKey = base64urlPadBitAlias(value.ephemeralPublicKey); },
    (value) => { value.ciphertextBase64url = mutateBase64url(value.ciphertextBase64url); },
    (value) => { value.tagBase64url = mutateBase64url(value.tagBase64url); },
    (value) => { value.tagBase64url = base64urlPadBitAlias(value.tagBase64url); },
  ]) {
    const candidate = structuredClone(envelope);
    change(candidate);
    await assertRejectsSecretFree(() => openRequestorBootstrapEnvelope({
      context: context(),
      envelope: candidate,
      requestorPrivateKey: requestorKey.privateKey,
    }));
  }

  await assertRejectsSecretFree(() => openRequestorBootstrapEnvelope({
    context: context(),
    envelope,
    requestorPrivateKey: wrongKey.privateKey,
  }));

  for (const badPublicKey of [
    "",
    "not-base64url",
    `${requestorKey.publicKey}=`,
    requestorKey.publicKey.slice(1),
  ]) {
    await assertRejectsSecretFree(() => sealRequestorBootstrapManifest({
      context: context(),
      manifestBytes: bytes,
      requestorPublicKey: badPublicKey,
    }));
  }
  await assertRejectsSecretFree(() => openRequestorBootstrapEnvelope({
    context: context(),
    envelope,
    requestorPrivateKey: { canary: KEY_CANARY },
  }));

  for (const badManifestBytes of [
    Buffer.alloc(0),
    Buffer.alloc(65_537, 0x61),
    Buffer.from(`{"schema":"x","privateSeed":"${PRIVATE_CANARY}"}`, "utf8"),
  ]) {
    await assertRejectsSecretFree(() => sealRequestorBootstrapManifest({
      context: context(),
      manifestBytes: badManifestBytes,
      requestorPublicKey: requestorKey.publicKey,
    }));
  }
});
