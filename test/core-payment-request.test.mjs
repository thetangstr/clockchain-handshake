import assert from "node:assert/strict";
import test from "node:test";

import { privateKeyToAccount } from "viem/accounts";

import { canonicalBytes } from "../src/core/canonical.mjs";
import {
  PAYER_MANDATE_SCHEMA,
  payerMandateDigest,
  signPayerMandate,
} from "../src/core/payer-mandate.mjs";
import {
  PAYMENT_REQUEST_ENVELOPE_SCHEMA,
  PAYMENT_REQUEST_SCHEMA,
  paymentRequestDigest,
  paymentRequestSigningBytes,
  signPaymentRequest,
  validatePaymentRequest,
  verifyPaymentRequest,
} from "../src/core/payment-request.mjs";

const PAYER = privateKeyToAccount(`0x${"1".repeat(64)}`);
const PAYEE = privateKeyToAccount(`0x${"2".repeat(64)}`);
const IMPOSTOR = privateKeyToAccount(`0x${"3".repeat(64)}`);
const PAYER_ADDRESS = PAYER.address.toLowerCase();
const PAYEE_ADDRESS = PAYEE.address.toLowerCase();
const SESSION_ID = "11111111-2222-4333-8444-555555555555";
const INTAKE_DIGEST = "b".repeat(64);
const INTAKE_REQUEST_ID = "22222222-3333-4444-8555-666666666666";
const OVERLONG_DECIMAL = "1".repeat(100_000);

function mandate() {
  return {
    amount: { currency: "USD", value: "100" }, expiresAtMs: "1785297600000",
    intakeDigest: INTAKE_DIGEST, intakeRequestId: INTAKE_REQUEST_ID,
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
    intakeDigest: value.intakeDigest, intakeRequestId: value.intakeRequestId,
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
    intakeDigest: INTAKE_DIGEST, intakeRequestId: INTAKE_REQUEST_ID,
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
    (() => { const value = request(mandateEnvelope); delete value.intakeRequestId; return value; })(),
    request(mandateEnvelope, { unknown: "no" }),
    request(mandateEnvelope, { intakeDigest: "B".repeat(64) }),
    request(mandateEnvelope, { intakeDigest: "b".repeat(63) }),
    request(mandateEnvelope, { intakeRequestId: "not-a-uuid" }),
    request(mandateEnvelope, { intakeRequestId: "22222222-3333-1444-8555-666666666666" }),
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

test("request digest remains bound to the verified mandate snapshot across an await", async () => {
  const originalEnvelope = await signedMandate();
  const mutableEnvelope = structuredClone(originalEnvelope);
  const mutatedEnvelope = structuredClone(originalEnvelope);
  mutatedEnvelope.mandate.expiresAtMs = "1785297500000";
  const envelope = await signedRequest(mutableEnvelope, {
    mandateDigest: payerMandateDigest(mutatedEnvelope),
  });

  const verification = verifyPaymentRequest({
    envelope,
    mandateEnvelope: mutableEnvelope,
    expected: expected(),
    nowMs: 1785294400000,
  });
  queueMicrotask(() => {
    mutableEnvelope.mandate.expiresAtMs = mutatedEnvelope.mandate.expiresAtMs;
  });

  await assert.rejects(verification);
});

test("verification rejects every independently mismatched expected request binding", async () => {
  const mandateEnvelope = await signedMandate();
  const envelope = await signedRequest(mandateEnvelope);
  const otherSessionId = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
  const cases = [
    ["amount", { amount: { currency: "USD", value: "99" } }],
    ["intakeDigest", { intakeDigest: "c".repeat(64) }],
    ["intakeRequestId", { intakeRequestId: "33333333-4444-4555-8666-777777777777" }],
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

test("payment request signing bytes, digest, and signature cover the intake binding", async () => {
  const mandateEnvelope = await signedMandate();
  const envelope = await signedRequest(mandateEnvelope);
  const changedDigest = await signedRequest(mandateEnvelope, { intakeDigest: "c".repeat(64) });
  const changedRequestId = await signedRequest(mandateEnvelope, { intakeRequestId: "33333333-4444-4555-8666-777777777777" });
  assert.notDeepEqual(paymentRequestSigningBytes(envelope.request), paymentRequestSigningBytes(changedDigest.request));
  assert.notDeepEqual(paymentRequestSigningBytes(envelope.request), paymentRequestSigningBytes(changedRequestId.request));
  assert.notEqual(paymentRequestDigest(envelope), paymentRequestDigest(changedDigest));
  assert.notEqual(paymentRequestDigest(envelope), paymentRequestDigest(changedRequestId));

  const tampered = structuredClone(envelope);
  tampered.request.intakeDigest = "c".repeat(64);
  await assert.rejects(verifyPaymentRequest({ envelope: tampered, mandateEnvelope, expected: expected({ intakeDigest: "c".repeat(64) }), nowMs: 1785294400000 }));
  tampered.request.intakeDigest = INTAKE_DIGEST;
  tampered.request.intakeRequestId = "33333333-4444-4555-8666-777777777777";
  await assert.rejects(verifyPaymentRequest({ envelope: tampered, mandateEnvelope, expected: expected({ intakeRequestId: tampered.request.intakeRequestId }), nowMs: 1785294400000 }));
});

test("payment request verification requires one intake binding across expected, mandate, and request", async () => {
  const mandateEnvelope = await signedMandate();
  const requestDifferentDigest = await signedRequest(mandateEnvelope, { intakeDigest: "c".repeat(64) });
  await assert.rejects(verifyPaymentRequest({ envelope: requestDifferentDigest, mandateEnvelope, expected: expected({ intakeDigest: "c".repeat(64) }), nowMs: 1785294400000 }));
  const requestDifferentId = await signedRequest(mandateEnvelope, { intakeRequestId: "33333333-4444-4555-8666-777777777777" });
  await assert.rejects(verifyPaymentRequest({ envelope: requestDifferentId, mandateEnvelope, expected: expected({ intakeRequestId: "33333333-4444-4555-8666-777777777777" }), nowMs: 1785294400000 }));

  const mandateDifferentDigest = await signedMandate({ intakeDigest: "c".repeat(64) });
  const requestForDifferentDigest = await signedRequest(mandateDifferentDigest, { intakeDigest: "c".repeat(64) });
  await assert.rejects(verifyPaymentRequest({ envelope: requestForDifferentDigest, mandateEnvelope: mandateDifferentDigest, expected: expected(), nowMs: 1785294400000 }));
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
    request(mandateEnvelope, { amount: { currency: "USD", value: OVERLONG_DECIMAL } }),
    request(mandateEnvelope, { createdAtMs: OVERLONG_DECIMAL }),
    request(mandateEnvelope, { expiresAtMs: OVERLONG_DECIMAL }),
    request(mandateEnvelope, { payee: { address: PAYEE_ADDRESS, agentId: OVERLONG_DECIMAL } }),
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
