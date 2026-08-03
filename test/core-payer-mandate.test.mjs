import assert from "node:assert/strict";
import test from "node:test";

import { privateKeyToAccount } from "viem/accounts";

import { canonicalBytes } from "../src/core/canonical.mjs";
import {
  PAYER_MANDATE_ENVELOPE_SCHEMA,
  PAYER_MANDATE_SCHEMA,
  payerMandateDigest,
  payerMandateSigningBytes,
  signPayerMandate,
  validatePayerMandate,
  verifyPayerMandate,
} from "../src/core/payer-mandate.mjs";

const PAYER = privateKeyToAccount(`0x${"1".repeat(64)}`);
const PAYEE = privateKeyToAccount(`0x${"2".repeat(64)}`);
const IMPOSTOR = privateKeyToAccount(`0x${"3".repeat(64)}`);
const PAYER_ADDRESS = PAYER.address.toLowerCase();
const PAYEE_ADDRESS = PAYEE.address.toLowerCase();
const SESSION_ID = "11111111-2222-4333-8444-555555555555";
const INTAKE_DIGEST = "b".repeat(64);
const INTAKE_REQUEST_ID = "22222222-3333-4444-8555-666666666666";
const ISSUED_AT_MS = "1785294000000";
const EXPIRES_AT_MS = "1785297600000";
const OVERLONG_DECIMAL = "1".repeat(100_000);

function mandate(overrides = {}) {
  return {
    amount: { currency: "USD", value: "100" },
    expiresAtMs: EXPIRES_AT_MS,
    intakeDigest: INTAKE_DIGEST,
    intakeRequestId: INTAKE_REQUEST_ID,
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
    intakeDigest: value.intakeDigest,
    intakeRequestId: value.intakeRequestId,
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
    (() => { const value = mandate(); delete value.intakeDigest; return value; })(),
    mandate({ unknown: "no" }),
    mandate({ intakeDigest: "B".repeat(64) }),
    mandate({ intakeDigest: "b".repeat(63) }),
    mandate({ intakeRequestId: "not-a-uuid" }),
    mandate({ intakeRequestId: "22222222-3333-1444-8555-666666666666" }),
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
    mandate({ amount: { currency: "USD", value: OVERLONG_DECIMAL } }),
    mandate({ issuedAtMs: OVERLONG_DECIMAL }),
    mandate({ expiresAtMs: OVERLONG_DECIMAL }),
    mandate({ payer: { address: PAYER_ADDRESS, agentId: OVERLONG_DECIMAL } }),
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

test("verification rejects every independently mismatched expected mandate binding", async () => {
  const envelope = await signed();
  const otherSessionId = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
  const cases = [
    ["amount", { amount: { currency: "USD", value: "99" } }],
    ["intakeDigest", { intakeDigest: "c".repeat(64) }],
    ["intakeRequestId", { intakeRequestId: "33333333-4444-4555-8666-777777777777" }],
    ["invoiceReferencePrefix", { invoiceReferencePrefix: "OTHER-" }],
    ["payee", { payee: { address: PAYER_ADDRESS, agentId: "202" } }],
    ["payer", { payer: { address: PAYEE_ADDRESS, agentId: "101" } }],
    ["purpose", { purpose: "other-services" }],
    ["releaseId", { releaseId: "2026-07-29-live-demo" }],
    ["repositorySha", { repositorySha: "b".repeat(40) }],
    ["requestEndpoint", { requestEndpoint: `/v1/sessions/${otherSessionId}/payment-requests`, sessionId: otherSessionId }],
    ["sessionId", { sessionId: otherSessionId, requestEndpoint: `/v1/sessions/${otherSessionId}/payment-requests` }],
    ["subjectRun", { subjectRun: "rehearsal" }],
  ];
  for (const [name, override] of cases) {
    await assert.rejects(
      verifyPayerMandate({ envelope, expected: expected(override), nowMs: 1785294300000 }),
      name,
    );
  }
  const partial = expected();
  delete partial.subjectRun;
  await assert.rejects(verifyPayerMandate({ envelope, expected: partial, nowMs: 1785294300000 }));
  await assert.rejects(verifyPayerMandate({ envelope, expected: {}, nowMs: 1785294300000 }));
});

test("mandate signing bytes, digest, and signature cover the intake binding", async () => {
  const envelope = await signed();
  const changedDigest = await signed({ intakeDigest: "c".repeat(64) });
  const changedRequestId = await signed({ intakeRequestId: "33333333-4444-4555-8666-777777777777" });
  assert.notDeepEqual(payerMandateSigningBytes(envelope.mandate), payerMandateSigningBytes(changedDigest.mandate));
  assert.notDeepEqual(payerMandateSigningBytes(envelope.mandate), payerMandateSigningBytes(changedRequestId.mandate));
  assert.notEqual(payerMandateDigest(envelope), payerMandateDigest(changedDigest));
  assert.notEqual(payerMandateDigest(envelope), payerMandateDigest(changedRequestId));

  const tampered = structuredClone(envelope);
  tampered.mandate.intakeDigest = "c".repeat(64);
  await assert.rejects(verifyPayerMandate({ envelope: tampered, expected: expected({ intakeDigest: "c".repeat(64) }), nowMs: 1785294300000 }));
  tampered.mandate.intakeDigest = INTAKE_DIGEST;
  tampered.mandate.intakeRequestId = "33333333-4444-4555-8666-777777777777";
  await assert.rejects(verifyPayerMandate({ envelope: tampered, expected: expected({ intakeRequestId: tampered.mandate.intakeRequestId }), nowMs: 1785294300000 }));
});

test("verification rejects a valid signature recovered from the wrong signer", async () => {
  const envelope = await signPayerMandate({
    mandate: mandate(),
    signMessage: (bytes) => IMPOSTOR.signMessage({ message: { raw: bytes } }),
  });
  assert.equal(envelope.signature.address, PAYER_ADDRESS);
  await assert.rejects(verifyPayerMandate({ envelope, expected: expected(), nowMs: 1785294300000 }));
});

test("mandate verification rejects hostile exact-shape nested, envelope, signature, and expected objects", async () => {
  const envelope = await signed();
  const verify = (candidate = envelope, context = expected()) =>
    verifyPayerMandate({ envelope: candidate, expected: context, nowMs: 1785294300000 });
  for (const nestedKey of ["amount", "payer", "payee"]) {
    const missing = structuredClone(envelope);
    delete missing.mandate[nestedKey].address;
    if (nestedKey === "amount") delete missing.mandate.amount.currency;
    await assert.rejects(verify(missing));
    const unknown = structuredClone(envelope);
    unknown.mandate[nestedKey].unknown = "no";
    await assert.rejects(verify(unknown));
    const accessor = structuredClone(envelope);
    Object.defineProperty(accessor.mandate[nestedKey], nestedKey === "amount" ? "value" : "agentId", { enumerable: true, get() { throw new Error("read"); } });
    await assert.rejects(verify(accessor));
    const proxy = structuredClone(envelope);
    proxy.mandate[nestedKey] = new Proxy(proxy.mandate[nestedKey], {});
    await assert.rejects(verify(proxy));
  }
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
    const result = change(candidate.signature) ?? candidate.signature;
    candidate.signature = result;
    await assert.rejects(verify(candidate));
  }
  for (const change of [
    (value) => { delete value.subjectRun; },
    (value) => { value.unknown = "no"; },
    (value) => Object.defineProperty(value, "subjectRun", { enumerable: true, get() { throw new Error("read"); } }),
    (value) => new Proxy(value, {}),
  ]) {
    const context = expected();
    const result = change(context) ?? context;
    await assert.rejects(verify(envelope, result));
  }
});
