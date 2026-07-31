import assert from "node:assert/strict";
import {
  createCipheriv,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
} from "node:crypto";
import test from "node:test";

import { canonicalBytes } from "../src/bilateral/canonical.mjs";
import { canonicalizeReceiptEventValue } from "../src/canonical.mjs";
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
const PUBLIC_KEY_DER_PREFIX = Buffer.from("302a300506032b656e032100", "hex");
const LEGACY_HKDF_INFO = Buffer.from(REQUESTOR_BOOTSTRAP_ENVELOPE_SCHEMA, "utf8");

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

function stableJsonBytes(value) {
  return Buffer.from(JSON.stringify(canonicalizeReceiptEventValue(value)), "utf8");
}

function launchManifest(overrides = {}) {
  const tlsCertificatePem = [
    "-----BEGIN CERTIFICATE-----",
    "A".repeat(384),
    "-----END CERTIFICATE-----",
    "",
  ].join("\n");
  return {
    bootstrapCapability: "c".repeat(64),
    expectedTlsFingerprint: "d".repeat(64),
    expiresAtMs: "1785123600000",
    issuedAtMs: "1785120000000",
    operatorKeyId: "operator-demo",
    payerMcpIntakeCapability: "e".repeat(64),
    protocol: "clockchain.bilateral-authorization/v1",
    relayUrl: "https://127.0.0.1:8443",
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    role: "payee",
    schema: "clockchain.bilateral-launch-manifest/v1",
    sessionId: SESSION_ID,
    tlsCertificatePem,
    ...overrides,
  };
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

function assertThrowsSecretFree(fn) {
  assert.throws(fn, (error) => {
    assertSecretFree(error);
    return true;
  });
}

function assertNotPromise(value) {
  assert.notEqual(typeof value?.then, "function");
  return value;
}

function publicKeyFromRawBase64url(value) {
  return createPublicKey({
    key: Buffer.concat([PUBLIC_KEY_DER_PREFIX, Buffer.from(value, "base64url")]),
    format: "der",
    type: "spki",
  });
}

function rawPublicKey(publicKey) {
  return publicKey.export({ format: "der", type: "spki" }).subarray(PUBLIC_KEY_DER_PREFIX.length);
}

function legacyInfoOmittedContextEnvelope({ contextValue, manifestValue, requestorPublicKey }) {
  const ephemeral = generateKeyPairSync("x25519");
  const ephemeralPublicKeyBytes = rawPublicKey(ephemeral.publicKey);
  const sharedSecret = diffieHellman({
    privateKey: ephemeral.privateKey,
    publicKey: publicKeyFromRawBase64url(requestorPublicKey),
  });
  const contextBytes = canonicalBytes(contextValue);
  const aesKey = Buffer.from(hkdfSync(
    "sha256",
    sharedSecret,
    contextBytes,
    Buffer.concat([LEGACY_HKDF_INFO, ephemeralPublicKeyBytes]),
    32,
  ));
  try {
    const iv = Buffer.alloc(12, 7);
    const cipher = createCipheriv("aes-256-gcm", aesKey, iv);
    cipher.setAAD(contextBytes);
    const ciphertext = Buffer.concat([cipher.update(manifestValue), cipher.final()]);
    return {
      algorithm: REQUESTOR_BOOTSTRAP_ENVELOPE_ALGORITHM,
      ciphertextBase64url: ciphertext.toString("base64url"),
      ephemeralPublicKey: ephemeralPublicKeyBytes.toString("base64url"),
      ivBase64url: iv.toString("base64url"),
      paymentMoved: false,
      schema: REQUESTOR_BOOTSTRAP_ENVELOPE_SCHEMA,
      tagBase64url: cipher.getAuthTag().toString("base64url"),
    };
  } finally {
    sharedSecret.fill(0);
    aesKey.fill(0);
  }
}

test("seals and opens one exact requestor bootstrap envelope without payment movement", () => {
  const requestorKey = assertNotPromise(createRequestorBootstrapKey());
  const bytes = manifestBytes();
  const envelope = assertNotPromise(sealRequestorBootstrapManifest({
    context: context(),
    manifestBytes: bytes,
    requestorPublicKey: requestorKey.publicKey,
  }));

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

  const opened = assertNotPromise(openRequestorBootstrapEnvelope({
    context: context(),
    envelope,
    requestorPrivateKey: requestorKey.privateKey,
  }));
  assert.deepEqual(opened, bytes);
});

test("accepts repository session UUID versions while keeping claim nonce v4", () => {
  const requestorKey = assertNotPromise(createRequestorBootstrapKey());
  const bytes = manifestBytes(manifest({ sessionId: SESSION_ID_V7 }));
  const envelope = sealRequestorBootstrapManifest({
    context: context({ sessionId: SESSION_ID_V7 }),
    manifestBytes: bytes,
    requestorPublicKey: requestorKey.publicKey,
  });

  const opened = openRequestorBootstrapEnvelope({
    context: context({ sessionId: SESSION_ID_V7 }),
    envelope,
    requestorPrivateKey: requestorKey.privateKey,
  });
  assert.deepEqual(opened, bytes);
  assertThrowsSecretFree(() => sealRequestorBootstrapManifest({
    context: context({ claimNonce: SESSION_ID_V7, sessionId: SESSION_ID_V7 }),
    manifestBytes: bytes,
    requestorPublicKey: requestorKey.publicKey,
  }));
});

test("round-trips stable JSON launch manifest bytes with PEM newlines and long fields", () => {
  const requestorKey = assertNotPromise(createRequestorBootstrapKey());
  const value = launchManifest();
  const bytes = stableJsonBytes(value);
  assert.match(bytes.toString("utf8"), /\\n/);
  assert.ok(value.tlsCertificatePem.length > 256);

  const envelope = sealRequestorBootstrapManifest({
    context: context(),
    manifestBytes: bytes,
    requestorPublicKey: requestorKey.publicKey,
  });
  const opened = openRequestorBootstrapEnvelope({
    context: context(),
    envelope,
    requestorPrivateKey: requestorKey.privateKey,
  });
  assert.deepEqual(opened, bytes);

  const noncanonicalBytes = Buffer.from(`${bytes.toString("utf8")}\n`, "utf8");
  assertThrowsSecretFree(() => sealRequestorBootstrapManifest({
    context: context(),
    manifestBytes: noncanonicalBytes,
    requestorPublicKey: requestorKey.publicKey,
  }));
});

test("rejects legacy HKDF info that omitted the canonical context binding", () => {
  const requestorKey = assertNotPromise(createRequestorBootstrapKey());
  const bytes = manifestBytes();
  const legacyEnvelope = legacyInfoOmittedContextEnvelope({
    contextValue: context(),
    manifestValue: bytes,
    requestorPublicKey: requestorKey.publicKey,
  });

  assertThrowsSecretFree(() => openRequestorBootstrapEnvelope({
    context: context(),
    envelope: legacyEnvelope,
    requestorPrivateKey: requestorKey.privateKey,
  }));
});

test("rejects hostile context, envelope, key, and manifest inputs without leaking private material", () => {
  const requestorKey = assertNotPromise(createRequestorBootstrapKey());
  const wrongKey = assertNotPromise(createRequestorBootstrapKey());
  const bytes = manifestBytes();
  const envelope = sealRequestorBootstrapManifest({
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
    assertThrowsSecretFree(() => openRequestorBootstrapEnvelope({
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
    assertThrowsSecretFree(() => openRequestorBootstrapEnvelope({
      context: context(),
      envelope: candidate,
      requestorPrivateKey: requestorKey.privateKey,
    }));
  }

  const oversizedCiphertext = structuredClone(envelope);
  oversizedCiphertext.ciphertextBase64url = Buffer.alloc(65_537, 0x61).toString("base64url");
  assertThrowsSecretFree(() => openRequestorBootstrapEnvelope({
    context: context(),
    envelope: oversizedCiphertext,
    requestorPrivateKey: requestorKey.privateKey,
  }));

  assertThrowsSecretFree(() => openRequestorBootstrapEnvelope({
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
    assertThrowsSecretFree(() => sealRequestorBootstrapManifest({
      context: context(),
      manifestBytes: bytes,
      requestorPublicKey: badPublicKey,
    }));
  }
  assertThrowsSecretFree(() => openRequestorBootstrapEnvelope({
    context: context(),
    envelope,
    requestorPrivateKey: { canary: KEY_CANARY },
  }));

  for (const badManifestBytes of [
    Buffer.alloc(0),
    Buffer.alloc(65_537, 0x61),
    Buffer.from(`{"schema":"x","privateSeed":"${PRIVATE_CANARY}"}`, "utf8"),
  ]) {
    assertThrowsSecretFree(() => sealRequestorBootstrapManifest({
      context: context(),
      manifestBytes: badManifestBytes,
      requestorPublicKey: requestorKey.publicKey,
    }));
  }
});
