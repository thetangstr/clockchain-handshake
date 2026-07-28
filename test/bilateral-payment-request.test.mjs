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
const IMPOSTOR = privateKeyToAccount(`0x${"3".repeat(64)}`);
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

test("verification rejects every independently mismatched expected request binding", async () => {
  const mandateEnvelope = await signedMandate();
  const envelope = await signedRequest(mandateEnvelope);
  const otherSessionId = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
  const cases = [
    ["amount", { amount: { currency: "USD", value: "99" } }],
    ["invoiceReferencePrefix", { invoiceReferencePrefix: "OTHER-" }],
    ["payer", { payer: { address: PAYEE_ADDRESS, agentId: "101" } }],
    ["payee", { payee: { address: PAYER_ADDRESS, agentId: "202" } }],
    ["purpose", { purpose: "other-services" }],
    ["sessionId", { sessionId: otherSessionId }],
    ["releaseId", { releaseId: "2026-07-29-live-demo" }],
    ["repositorySha", { repositorySha: "b".repeat(40) }],
    ["subjectRun", { subjectRun: "rehearsal" }],
  ];
  for (const [name, override] of cases) {
    await assert.rejects(
      verifyPaymentRequest({ envelope, mandateEnvelope, expected: expected(override), nowMs: 1785294400000 }),
      name,
    );
  }
  const partial = expected();
  delete partial.subjectRun;
  await assert.rejects(verifyPaymentRequest({ envelope, mandateEnvelope, expected: partial, nowMs: 1785294400000 }));
  await assert.rejects(verifyPaymentRequest({ envelope, mandateEnvelope, expected: {}, nowMs: 1785294400000 }));
});

test("verification rejects a valid request signature recovered from the wrong signer", async () => {
  const mandateEnvelope = await signedMandate();
  const envelope = await signPaymentRequest({
    request: request(mandateEnvelope),
    signMessage: (bytes) => IMPOSTOR.signMessage({ message: { raw: bytes } }),
  });
  assert.equal(envelope.signature.address, PAYEE_ADDRESS);
  await assert.rejects(verifyPaymentRequest({ envelope, mandateEnvelope, expected: expected(), nowMs: 1785294400000 }));
});

test("payment request validation rejects malformed fields and hostile nested values", async () => {
  const mandateEnvelope = await signedMandate();
  const cases = [
    request(mandateEnvelope, { amount: { currency: "USD", value: "0100" } }),
    request(mandateEnvelope, { payer: { address: PAYER_ADDRESS, agentId: "01" } }),
    request(mandateEnvelope, { payee: { address: PAYEE_ADDRESS, agentId: "-202" } }),
    request(mandateEnvelope, { payer: { address: PAYER_ADDRESS.toUpperCase(), agentId: "101" } }),
    request(mandateEnvelope, { payee: { address: "0x123", agentId: "202" } }),
    request(mandateEnvelope, { releaseId: " " }),
    request(mandateEnvelope, { repositorySha: "A".repeat(40) }),
    request(mandateEnvelope, { sessionId: "not-a-uuid" }),
    request(mandateEnvelope, { expiresAtMs: 1785297000000 }),
    request(mandateEnvelope, { createdAtMs: "1785297000000" }),
  ];
  for (const value of cases) assert.throws(() => validatePaymentRequest(value));
  for (const nestedKey of ["amount", "payer", "payee"]) {
    const missing = request(mandateEnvelope);
    delete missing[nestedKey][nestedKey === "amount" ? "value" : "agentId"];
    assert.throws(() => validatePaymentRequest(missing));
    const unknown = request(mandateEnvelope);
    unknown[nestedKey].unknown = "no";
    assert.throws(() => validatePaymentRequest(unknown));
    const accessor = request(mandateEnvelope);
    Object.defineProperty(accessor[nestedKey], nestedKey === "amount" ? "value" : "agentId", { enumerable: true, get() { throw new Error("read"); } });
    assert.throws(() => validatePaymentRequest(accessor));
    const proxy = request(mandateEnvelope);
    proxy[nestedKey] = new Proxy(proxy[nestedKey], {});
    assert.throws(() => validatePaymentRequest(proxy));
  }
});

test("request verification rejects hostile envelope, signature, and expected objects", async () => {
  const mandateEnvelope = await signedMandate();
  const envelope = await signedRequest(mandateEnvelope);
  const verify = (candidate = envelope, context = expected()) =>
    verifyPaymentRequest({ envelope: candidate, mandateEnvelope, expected: context, nowMs: 1785294400000 });
  for (const change of [
    (value) => { delete value.schema; },
    (value) => { value.unknown = "no"; },
    (value) => Object.defineProperty(value, "schema", { enumerable: true, get() { throw new Error("read"); } }),
    (value) => new Proxy(value, {}),
  ]) {
    const candidate = structuredClone(envelope);
    const result = change(candidate) ?? candidate;
    await assert.rejects(verify(result));
  }
  for (const change of [
    (value) => { delete value.value; },
    (value) => { value.unknown = "no"; },
    (value) => Object.defineProperty(value, "value", { enumerable: true, get() { throw new Error("read"); } }),
    (value) => new Proxy(value, {}),
  ]) {
    const candidate = structuredClone(envelope);
    candidate.signature = change(candidate.signature) ?? candidate.signature;
    await assert.rejects(verify(candidate));
  }
  for (const change of [
    (value) => { delete value.subjectRun; },
    (value) => { value.unknown = "no"; },
    (value) => Object.defineProperty(value, "subjectRun", { enumerable: true, get() { throw new Error("read"); } }),
    (value) => new Proxy(value, {}),
  ]) {
    const context = expected();
    await assert.rejects(verify(envelope, change(context) ?? context));
  }
});

test("request verification fails closed before acceptance when mandate verification fails", async () => {
  const mandateEnvelope = await signedMandate();
  const envelope = await signedRequest(mandateEnvelope);
  const invalidSignature = structuredClone(mandateEnvelope);
  invalidSignature.signature.value = `0x${"0".repeat(130)}`;
  const invalidSchema = structuredClone(mandateEnvelope);
  invalidSchema.mandate.schema = "clockchain.bilateral-payer-mandate/v2";
  const paymentMoved = structuredClone(mandateEnvelope);
  paymentMoved.mandate.paymentMoved = true;
  for (const candidate of [invalidSignature, invalidSchema, paymentMoved]) {
    await assert.rejects(verifyPaymentRequest({ envelope, mandateEnvelope: candidate, expected: expected(), nowMs: 1785294400000 }));
  }
  await assert.rejects(verifyPaymentRequest({ envelope, mandateEnvelope, expected: expected({ purpose: "other-services" }), nowMs: 1785294400000 }));
});
