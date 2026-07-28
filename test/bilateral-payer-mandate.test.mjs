import assert from "node:assert/strict";
import test from "node:test";

import { privateKeyToAccount } from "viem/accounts";

import { canonicalBytes } from "../src/bilateral/canonical.mjs";
import {
  PAYER_MANDATE_ENVELOPE_SCHEMA,
  PAYER_MANDATE_SCHEMA,
  payerMandateDigest,
  payerMandateSigningBytes,
  signPayerMandate,
  validatePayerMandate,
  verifyPayerMandate,
} from "../src/bilateral/payer-mandate.mjs";

const PAYER = privateKeyToAccount(`0x${"1".repeat(64)}`);
const PAYEE = privateKeyToAccount(`0x${"2".repeat(64)}`);
const PAYER_ADDRESS = PAYER.address.toLowerCase();
const PAYEE_ADDRESS = PAYEE.address.toLowerCase();
const SESSION_ID = "11111111-2222-4333-8444-555555555555";
const ISSUED_AT_MS = "1785294000000";
const EXPIRES_AT_MS = "1785297600000";

function mandate(overrides = {}) {
  return {
    amount: { currency: "USD", value: "100" },
    expiresAtMs: EXPIRES_AT_MS,
    invoiceReferencePrefix: "TREL-",
    issuedAtMs: ISSUED_AT_MS,
    payee: { address: PAYEE_ADDRESS, agentId: "202" },
    payer: { address: PAYER_ADDRESS, agentId: "101" },
    paymentMoved: false,
    protocol: "clockchain.bilateral-authorization/v1",
    purpose: "freight-services",
    releaseId: "2026-07-28-live-demo",
    repositorySha: "a".repeat(40),
    requestEndpoint: `/v1/sessions/${SESSION_ID}/payment-requests`,
    schema: PAYER_MANDATE_SCHEMA,
    sessionId: SESSION_ID,
    subjectRun: "stakeholder",
    ...overrides,
  };
}

function expected(overrides = {}) {
  const value = mandate();
  return {
    amount: value.amount,
    invoiceReferencePrefix: value.invoiceReferencePrefix,
    payee: value.payee,
    payer: value.payer,
    purpose: value.purpose,
    releaseId: value.releaseId,
    repositorySha: value.repositorySha,
    requestEndpoint: value.requestEndpoint,
    sessionId: value.sessionId,
    subjectRun: value.subjectRun,
    ...overrides,
  };
}

async function signed(overrides = {}) {
  const value = mandate(overrides);
  return signPayerMandate({
    mandate: value,
    signMessage: (bytes) => PAYER.signMessage({ message: { raw: bytes } }),
  });
}

test("signs the exact payer-owned mandate without any protocol write", async () => {
  const envelope = await signed();
  assert.equal(PAYER_MANDATE_SCHEMA, "clockchain.bilateral-payer-mandate/v1");
  assert.equal(PAYER_MANDATE_ENVELOPE_SCHEMA, "clockchain.bilateral-payer-mandate-envelope/v1");
  assert.deepEqual(Object.keys(envelope), ["mandate", "schema", "signature"]);
  assert.deepEqual(Object.keys(envelope.mandate), Object.keys(mandate()));
  assert.deepEqual(Object.keys(envelope.signature), ["address", "algorithm", "value"]);
  assert.equal(envelope.signature.address, PAYER_ADDRESS);
  assert.equal(envelope.signature.algorithm, "eip191");
  assert.match(envelope.signature.value, /^0x[0-9a-f]{130}$/);
  assert.deepEqual(payerMandateSigningBytes(envelope.mandate), canonicalBytes(envelope.mandate));
  assert.match(payerMandateDigest(envelope), /^[0-9a-f]{64}$/);
  await assert.doesNotReject(verifyPayerMandate({
    envelope,
    expected: expected(),
    nowMs: 1785294300000,
  }));
});

test("rejects malformed, noncanonical, and hostile mandate payloads", () => {
  const cases = [
    (() => { const value = mandate(); delete value.purpose; return value; })(),
    mandate({ unknown: "no" }),
    mandate({ amount: { currency: "USD", value: "0100" } }),
    mandate({ expiresAtMs: 1785297600000 }),
    mandate({ payer: { address: PAYER_ADDRESS.toUpperCase(), agentId: "101" } }),
    mandate({ sessionId: "not-a-uuid" }),
    mandate({ releaseId: "" }),
    mandate({ repositorySha: "A".repeat(40) }),
    mandate({ issuedAtMs: EXPIRES_AT_MS, expiresAtMs: ISSUED_AT_MS }),
    mandate({ subjectRun: "release" }),
    mandate({ requestEndpoint: "/v1/sessions/not-the-session/payment-requests" }),
    mandate({ paymentMoved: true }),
  ];
  for (const value of cases) assert.throws(() => validatePayerMandate(value));

  const accessor = mandate();
  Object.defineProperty(accessor, "purpose", { enumerable: true, get() { throw new Error("read"); } });
  assert.throws(() => validatePayerMandate(accessor));
  assert.throws(() => validatePayerMandate(new Proxy(mandate(), {})));
});

test("verification rejects altered signing material, signer mismatch, and binding mismatch", async () => {
  const envelope = await signed();
  for (const changed of [
    { ...envelope, signature: { ...envelope.signature, algorithm: "eip712" } },
    { ...envelope, signature: { ...envelope.signature, value: `0x${"0".repeat(130)}` } },
    { ...envelope, signature: { ...envelope.signature, address: PAYEE_ADDRESS } },
  ]) {
    await assert.rejects(verifyPayerMandate({ envelope: changed, expected: expected(), nowMs: 1785294300000 }));
  }
  await assert.rejects(verifyPayerMandate({ envelope, expected: expected({ sessionId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" }), nowMs: 1785294300000 }));
  await assert.rejects(verifyPayerMandate({ envelope, expected: {}, nowMs: 1785294300000 }));
});

test("verification requires a real current validity window", async () => {
  const envelope = await signed();
  await assert.rejects(verifyPayerMandate({ envelope, expected: expected(), nowMs: 1785293999999 }));
  await assert.rejects(verifyPayerMandate({ envelope, expected: expected(), nowMs: 1785297600000 }));
  await assert.rejects(verifyPayerMandate({ envelope, expected: expected(), nowMs: "1785294300000" }));
});
