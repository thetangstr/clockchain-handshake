import assert from "node:assert/strict";
import test from "node:test";

import { privateKeyToAccount } from "viem/accounts";

import { canonicalBytes } from "../src/bilateral/canonical.mjs";
import {
  PAYER_MANDATE_SCHEMA,
  payerMandateDigest,
  signPayerMandate,
} from "../src/bilateral/payer-mandate.mjs";
import {
  PAYMENT_REQUEST_ENVELOPE_SCHEMA,
  PAYMENT_REQUEST_SCHEMA,
  paymentRequestDigest,
  paymentRequestSigningBytes,
  signPaymentRequest,
  validatePaymentRequest,
  verifyPaymentRequest,
} from "../src/bilateral/payment-request.mjs";

const PAYER = privateKeyToAccount(`0x${"1".repeat(64)}`);
const PAYEE = privateKeyToAccount(`0x${"2".repeat(64)}`);
const PAYER_ADDRESS = PAYER.address.toLowerCase();
const PAYEE_ADDRESS = PAYEE.address.toLowerCase();
const SESSION_ID = "11111111-2222-4333-8444-555555555555";

function mandate() {
  return {
    amount: { currency: "USD", value: "100" }, expiresAtMs: "1785297600000",
    invoiceReferencePrefix: "TREL-", issuedAtMs: "1785294000000",
    payee: { address: PAYEE_ADDRESS, agentId: "202" }, payer: { address: PAYER_ADDRESS, agentId: "101" },
    paymentMoved: false, protocol: "clockchain.bilateral-authorization/v1", purpose: "freight-services",
    releaseId: "2026-07-28-live-demo", repositorySha: "a".repeat(40),
    requestEndpoint: `/v1/sessions/${SESSION_ID}/payment-requests`, schema: PAYER_MANDATE_SCHEMA,
    sessionId: SESSION_ID, subjectRun: "stakeholder",
  };
}

function expected(overrides = {}) {
  const value = mandate();
  return {
    amount: value.amount, invoiceReferencePrefix: value.invoiceReferencePrefix,
    payee: value.payee, payer: value.payer, purpose: value.purpose,
    releaseId: value.releaseId, repositorySha: value.repositorySha,
    sessionId: value.sessionId, subjectRun: value.subjectRun,
    ...overrides,
  };
}

async function signedMandate(overrides = {}) {
  return signPayerMandate({ mandate: { ...mandate(), ...overrides }, signMessage: (bytes) => PAYER.signMessage({ message: { raw: bytes } }) });
}

function request(mandateEnvelope, overrides = {}) {
  return {
    amount: { currency: "USD", value: "100" }, createdAtMs: "1785294300000", expiresAtMs: "1785297000000",
    invoiceReference: "TREL-2026-0001", mandateDigest: payerMandateDigest(mandateEnvelope),
    payee: { address: PAYEE_ADDRESS, agentId: "202" }, payer: { address: PAYER_ADDRESS, agentId: "101" },
    paymentMoved: false, protocol: "clockchain.bilateral-authorization/v1", purpose: "freight-services",
    releaseId: "2026-07-28-live-demo", repositorySha: "a".repeat(40),
    requestId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", schema: PAYMENT_REQUEST_SCHEMA,
    sessionId: SESSION_ID, subjectRun: "stakeholder", ...overrides,
  };
}

async function signedRequest(mandateEnvelope, overrides = {}) {
  return signPaymentRequest({ request: request(mandateEnvelope, overrides), signMessage: (bytes) => PAYEE.signMessage({ message: { raw: bytes } }) });
}

test("signs an exact payee request bound to a verified payer mandate", async () => {
  const mandateEnvelope = await signedMandate();
  const envelope = await signedRequest(mandateEnvelope);
  assert.equal(PAYMENT_REQUEST_SCHEMA, "clockchain.bilateral-payment-request/v1");
  assert.equal(PAYMENT_REQUEST_ENVELOPE_SCHEMA, "clockchain.bilateral-payment-request-envelope/v1");
  assert.deepEqual(Object.keys(envelope), ["request", "schema", "signature"]);
  assert.deepEqual(Object.keys(envelope.request), Object.keys(request(mandateEnvelope)));
  assert.deepEqual(Object.keys(envelope.signature), ["address", "algorithm", "value"]);
  assert.equal(envelope.signature.address, PAYEE_ADDRESS);
  assert.deepEqual(paymentRequestSigningBytes(envelope.request), canonicalBytes(envelope.request));
  await assert.doesNotReject(verifyPaymentRequest({ envelope, mandateEnvelope, expected: expected(), nowMs: 1785294400000 }));
});

test("rejects malformed and hostile payment requests", async () => {
  const mandateEnvelope = await signedMandate();
  const cases = [
    (() => { const value = request(mandateEnvelope); delete value.purpose; return value; })(),
    request(mandateEnvelope, { unknown: "no" }),
    request(mandateEnvelope, { createdAtMs: 1785294300000 }),
    request(mandateEnvelope, { requestId: "not-a-uuid" }),
    request(mandateEnvelope, { mandateDigest: "B".repeat(64) }),
    request(mandateEnvelope, { paymentMoved: true }),
  ];
  for (const value of cases) assert.throws(() => validatePaymentRequest(value));
  const accessor = request(mandateEnvelope);
  Object.defineProperty(accessor, "purpose", { enumerable: true, get() { throw new Error("read"); } });
  assert.throws(() => validatePaymentRequest(accessor));
  assert.throws(() => validatePaymentRequest(new Proxy(request(mandateEnvelope), {})));
});

test("verification binds signature, mandate digest, commercial terms, and time", async () => {
  const mandateEnvelope = await signedMandate();
  const envelope = await signedRequest(mandateEnvelope);
  await assert.rejects(verifyPaymentRequest({ envelope: { ...envelope, signature: { ...envelope.signature, algorithm: "eip712" } }, mandateEnvelope, expected: expected(), nowMs: 1785294400000 }));
  await assert.rejects(verifyPaymentRequest({ envelope: { ...envelope, signature: { ...envelope.signature, value: `0x${"0".repeat(130)}` } }, mandateEnvelope, expected: expected(), nowMs: 1785294400000 }));
  await assert.rejects(verifyPaymentRequest({ envelope: { ...envelope, signature: { ...envelope.signature, address: PAYER_ADDRESS } }, mandateEnvelope, expected: expected(), nowMs: 1785294400000 }));
  await assert.rejects(verifyPaymentRequest({ envelope, mandateEnvelope, expected: expected({ purpose: "other" }), nowMs: 1785294400000 }));
  await assert.rejects(verifyPaymentRequest({ envelope, mandateEnvelope: await signedMandate({ expiresAtMs: "1785297500000" }), expected: expected(), nowMs: 1785294400000 }));
  await assert.rejects(verifyPaymentRequest({ envelope, mandateEnvelope, expected: expected(), nowMs: 1785294299999 }));
  await assert.rejects(verifyPaymentRequest({ envelope, mandateEnvelope, expected: expected(), nowMs: 1785297000000 }));
});

test("digest changes for different signed bytes and remains stable for byte-identical replay", async () => {
  const mandateEnvelope = await signedMandate();
  const first = await signedRequest(mandateEnvelope);
  const replay = structuredClone(first);
  const changed = await signedRequest(mandateEnvelope, { purpose: "other-freight-services" });
  assert.equal(paymentRequestDigest(first), paymentRequestDigest(replay));
  assert.notEqual(paymentRequestDigest(first), paymentRequestDigest(changed));
});
