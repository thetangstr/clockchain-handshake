import assert from "node:assert/strict";
import {
  createPrivateKey,
  createPublicKey,
} from "node:crypto";
import { test } from "node:test";

import {
  createSealedEnvelopeKeyPair,
  openEnvelope,
  sealEnvelope,
} from "../src/bilateral/local-mcp/sealed-envelope.mjs";

const PUBLIC_KEY_DER_PREFIX = Buffer.from(
  "302a300506032b656e032100",
  "hex",
);
const PRIVATE_KEY_DER_PREFIX = Buffer.from(
  "302e020100300506032b656e04220420",
  "hex",
);
const SCHEMA = "clockchain.test-envelope/v1";
const PRIVATE_CANARY = "generic-private-envelope-canary";

function privateKeyFromByte(byte) {
  return createPrivateKey({
    key: Buffer.concat([
      PRIVATE_KEY_DER_PREFIX,
      Buffer.alloc(32, byte),
    ]),
    format: "der",
    type: "pkcs8",
  });
}

function rawPublicKey(privateKey) {
  return createPublicKey(privateKey)
    .export({ format: "der", type: "spki" })
    .subarray(PUBLIC_KEY_DER_PREFIX.length)
    .toString("base64url");
}

function privateKeyExport(privateKey) {
  return {
    format: "pkcs8-der-base64url",
    value: privateKey
      .export({ format: "der", type: "pkcs8" })
      .toString("base64url"),
  };
}

function fixedRecipient(byte = 0x11) {
  const privateKey = privateKeyFromByte(byte);
  return {
    privateKey: privateKeyExport(privateKey),
    publicKey: rawPublicKey(privateKey),
  };
}

function inputs() {
  return {
    aadBytes: Buffer.from(
      '{"paymentMoved":false,"scope":"generic-test"}',
      "utf8",
    ),
    plaintextBytes: Buffer.from(
      `{"paymentMoved":false,"private":"${PRIVATE_CANARY}"}`,
      "utf8",
    ),
    schema: SCHEMA,
  };
}

function deterministicDependencies(observed = []) {
  const ephemeralPrivateKey = privateKeyFromByte(0x22);
  return {
    generateKeyPair() {
      return {
        privateKey: ephemeralPrivateKey,
        publicKey: createPublicKey(ephemeralPrivateKey),
      };
    },
    observeDerivedSecrets(value) {
      observed.push(value);
    },
    randomBytes(length) {
      assert.equal(length, 12);
      return Buffer.from("000102030405060708090a0b", "hex");
    },
  };
}

function assertSecretFree(error) {
  const text = JSON.stringify(
    error,
    Object.getOwnPropertyNames(error),
  );
  assert.doesNotMatch(text, new RegExp(PRIVATE_CANARY));
  assert.equal(
    error.message,
    "Sealed envelope validation failed safely.",
  );
  return true;
}

function mutateBase64url(value) {
  return `${value[0] === "A" ? "B" : "A"}${value.slice(1)}`;
}

function base64urlPadBitAlias(value) {
  const alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const index = alphabet.indexOf(value.at(-1));
  assert.notEqual(index, -1);
  return `${value.slice(0, -1)}${alphabet[index ^ 1]}`;
}

test("seals and opens one exact role-neutral envelope", () => {
  const recipient = fixedRecipient();
  const value = inputs();
  const envelope = sealEnvelope({
    ...value,
    recipientPublicKey: recipient.publicKey,
  }, deterministicDependencies());
  assert.deepEqual(Object.keys(envelope), [
    "algorithm",
    "ciphertextBase64url",
    "ephemeralPublicKey",
    "ivBase64url",
    "paymentMoved",
    "schema",
    "tagBase64url",
  ]);
  assert.equal(envelope.paymentMoved, false);
  assert.equal(envelope.schema, SCHEMA);
  assert.deepEqual(
    openEnvelope({
      aadBytes: value.aadBytes,
      envelope,
      expectedSchema: SCHEMA,
      recipientPrivateKey: recipient.privateKey,
    }),
    value.plaintextBytes,
  );
  assert.doesNotMatch(
    JSON.stringify(envelope),
    new RegExp(PRIVATE_CANARY),
  );
});

test("creates an exact serializable X25519 recipient key pair", () => {
  const pair = createSealedEnvelopeKeyPair();
  assert.deepEqual(Object.keys(pair), [
    "privateKey",
    "publicKey",
  ]);
  assert.deepEqual(Object.keys(pair.privateKey), [
    "format",
    "value",
  ]);
  assert.equal(
    pair.privateKey.format,
    "pkcs8-der-base64url",
  );
  assert.match(pair.publicKey, /^[A-Za-z0-9_-]{43}$/);
  assert.doesNotThrow(() =>
    sealEnvelope({
      ...inputs(),
      recipientPublicKey: pair.publicKey,
    }),
  );
});

test("rejects wrong schema, AAD, and recipient key without leaking plaintext", () => {
  const recipient = fixedRecipient();
  const wrongRecipient = fixedRecipient(0x33);
  const value = inputs();
  const envelope = sealEnvelope({
    ...value,
    recipientPublicKey: recipient.publicKey,
  }, deterministicDependencies());
  for (const candidate of [
    {
      aadBytes: Buffer.from(
        '{"paymentMoved":false,"scope":"other"}',
        "utf8",
      ),
      envelope,
      expectedSchema: SCHEMA,
      recipientPrivateKey: recipient.privateKey,
    },
    {
      aadBytes: value.aadBytes,
      envelope,
      expectedSchema: "clockchain.other-envelope/v1",
      recipientPrivateKey: recipient.privateKey,
    },
    {
      aadBytes: value.aadBytes,
      envelope,
      expectedSchema: SCHEMA,
      recipientPrivateKey: wrongRecipient.privateKey,
    },
  ]) {
    assert.throws(
      () => openEnvelope(candidate),
      assertSecretFree,
    );
  }
});

test("rejects noncanonical, extra, oversized, and mutated envelope material", () => {
  const recipient = fixedRecipient();
  const value = inputs();
  const envelope = sealEnvelope({
    ...value,
    recipientPublicKey: recipient.publicKey,
  }, deterministicDependencies());
  const changes = [
    (candidate) => {
      candidate.extra = true;
    },
    (candidate) => {
      candidate.schema = "clockchain.other-envelope/v1";
    },
    (candidate) => {
      candidate.paymentMoved = true;
    },
    (candidate) => {
      candidate.ciphertextBase64url += "=";
    },
    (candidate) => {
      candidate.ephemeralPublicKey =
        base64urlPadBitAlias(
          candidate.ephemeralPublicKey,
        );
    },
    (candidate) => {
      candidate.ivBase64url =
        mutateBase64url(candidate.ivBase64url);
    },
    (candidate) => {
      candidate.tagBase64url =
        mutateBase64url(candidate.tagBase64url);
    },
    (candidate) => {
      candidate.ciphertextBase64url =
        mutateBase64url(
          candidate.ciphertextBase64url,
        );
    },
  ];
  for (const change of changes) {
    const candidate = structuredClone(envelope);
    change(candidate);
    assert.throws(
      () =>
        openEnvelope({
          aadBytes: value.aadBytes,
          envelope: candidate,
          expectedSchema: SCHEMA,
          recipientPrivateKey: recipient.privateKey,
        }),
      assertSecretFree,
    );
  }
  assert.throws(
    () =>
      sealEnvelope({
        aadBytes: value.aadBytes,
        plaintextBytes: Buffer.alloc(65_537, 1),
        recipientPublicKey: recipient.publicKey,
        schema: SCHEMA,
      }),
    assertSecretFree,
  );
  const oversized = structuredClone(envelope);
  oversized.ciphertextBase64url =
    Buffer.alloc(65_537, 1).toString("base64url");
  assert.throws(
    () =>
      openEnvelope({
        aadBytes: value.aadBytes,
        envelope: oversized,
        expectedSchema: SCHEMA,
        recipientPrivateKey: recipient.privateKey,
      }),
    assertSecretFree,
  );
});

test("zeroizes every shared secret and derived key on success and failure", () => {
  const recipient = fixedRecipient();
  const value = inputs();
  const sealObserved = [];
  const envelope = sealEnvelope({
    ...value,
    recipientPublicKey: recipient.publicKey,
  }, deterministicDependencies(sealObserved));
  assert.equal(sealObserved.length, 1);
  for (const bytes of Object.values(sealObserved[0])) {
    assert.equal(
      bytes.equals(Buffer.alloc(bytes.length)),
      true,
    );
  }

  const openObserved = [];
  assert.throws(
    () =>
      openEnvelope({
        aadBytes: Buffer.from("wrong", "utf8"),
        envelope,
        expectedSchema: SCHEMA,
        recipientPrivateKey: recipient.privateKey,
      }, {
        observeDerivedSecrets(value_) {
          openObserved.push(value_);
        },
      }),
    assertSecretFree,
  );
  assert.equal(openObserved.length, 1);
  for (const bytes of Object.values(openObserved[0])) {
    assert.equal(
      bytes.equals(Buffer.alloc(bytes.length)),
      true,
    );
  }
});

test("rejects hostile dependencies and callback failure after zeroization", () => {
  const recipient = fixedRecipient();
  const value = inputs();
  for (const dependencies of [
    { extra: true },
    { randomBytes: "not-a-function" },
    { generateKeyPair: () => ({}) },
  ]) {
    assert.throws(
      () =>
        sealEnvelope({
          ...value,
          recipientPublicKey: recipient.publicKey,
        }, dependencies),
      assertSecretFree,
    );
  }
  const observed = [];
  assert.throws(
    () =>
      sealEnvelope({
        ...value,
        recipientPublicKey: recipient.publicKey,
      }, {
        ...deterministicDependencies(observed),
        observeDerivedSecrets(value_) {
          observed.push(value_);
          throw new Error(PRIVATE_CANARY);
        },
      }),
    assertSecretFree,
  );
  assert.equal(observed.length, 1);
  for (const bytes of Object.values(observed[0])) {
    assert.equal(
      bytes.equals(Buffer.alloc(bytes.length)),
      true,
    );
  }
});
