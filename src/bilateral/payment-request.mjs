import { types } from "node:util";

import { recoverMessageAddress } from "viem";

import { canonicalBytes, digestHex } from "./canonical.mjs";
import {
  payerMandateDigest,
  verifyPayerMandate,
} from "./payer-mandate.mjs";

export const PAYMENT_REQUEST_SCHEMA =
  "clockchain.bilateral-payment-request/v1";
export const PAYMENT_REQUEST_ENVELOPE_SCHEMA =
  "clockchain.bilateral-payment-request-envelope/v1";

const REQUEST_KEYS = Object.freeze([
  "amount", "createdAtMs", "expiresAtMs", "intakeDigest",
  "intakeRequestId", "invoiceReference", "mandateDigest", "payee", "payer",
  "paymentMoved", "protocol", "purpose", "releaseId", "repositorySha",
  "requestId", "schema", "sessionId", "subjectRun",
]);
const PARTY_KEYS = Object.freeze(["address", "agentId"]);
const AMOUNT_KEYS = Object.freeze(["currency", "value"]);
const ENVELOPE_KEYS = Object.freeze(["request", "schema", "signature"]);
const SIGNATURE_KEYS = Object.freeze(["address", "algorithm", "value"]);
const EXPECTED_KEYS = Object.freeze([
  "amount", "intakeDigest", "intakeRequestId", "invoiceReferencePrefix",
  "payee", "payer", "purpose", "releaseId", "repositorySha", "sessionId",
  "subjectRun",
]);
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const INTAKE_UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const SHA_PATTERN = /^[0-9a-f]{40}$/;
const DIGEST_PATTERN = /^[0-9a-f]{64}$/;
const SIGNATURE_PATTERN = /^0x[0-9a-f]{130}$/;
const PRINTABLE_PATTERN = /^[ -~]+$/;

export class PaymentRequestError extends Error {
  constructor() {
    super("Payment request validation failed.");
    this.name = "PaymentRequestError";
    this.category = "verification";
    this.code = "PAYMENT_REQUEST_INVALID";
  }
}

function invalid() { throw new PaymentRequestError(); }

function snapshot(value, keys) {
  try {
    if (
      value === null || typeof value !== "object" || Array.isArray(value) ||
      types.isProxy(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    ) invalid();
    const ownKeys = Reflect.ownKeys(value);
    if (
      ownKeys.length !== keys.length ||
      ownKeys.some((key) => typeof key !== "string" || !keys.includes(key))
    ) invalid();
    const result = Object.create(null);
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || descriptor.enumerable !== true || !Object.hasOwn(descriptor, "value")) invalid();
      result[key] = descriptor.value;
    }
    return result;
  } catch (error) {
    if (error instanceof PaymentRequestError) throw error;
    invalid();
  }
}

function printable(value, max = 128) {
  return typeof value === "string" && value.length > 0 && value.length <= max &&
    PRINTABLE_PATTERN.test(value) && value.trim() === value;
}

function decimal(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 16 ||
    !DECIMAL_PATTERN.test(value)
  ) invalid();
  try { if (BigInt(value) > BigInt(Number.MAX_SAFE_INTEGER)) invalid(); } catch { invalid(); }
}

function party(value) {
  const result = snapshot(value, PARTY_KEYS);
  if (!ADDRESS_PATTERN.test(result.address)) invalid();
  decimal(result.agentId);
  return Object.freeze(result);
}

function amount(value) {
  const result = snapshot(value, AMOUNT_KEYS);
  if (result.currency !== "USD") invalid();
  decimal(result.value);
  return Object.freeze(result);
}

function requestSnapshot(value) {
  const result = snapshot(value, REQUEST_KEYS);
  const amountValue = amount(result.amount);
  const payer = party(result.payer);
  const payee = party(result.payee);
  decimal(result.createdAtMs);
  decimal(result.expiresAtMs);
  if (
    BigInt(result.createdAtMs) >= BigInt(result.expiresAtMs) ||
    !DIGEST_PATTERN.test(result.intakeDigest) ||
    !INTAKE_UUID_PATTERN.test(result.intakeRequestId) ||
    !printable(result.invoiceReference) || !DIGEST_PATTERN.test(result.mandateDigest) ||
    !printable(result.purpose) || !printable(result.releaseId) ||
    !SHA_PATTERN.test(result.repositorySha) || !UUID_PATTERN.test(result.requestId) ||
    !UUID_PATTERN.test(result.sessionId) || result.schema !== PAYMENT_REQUEST_SCHEMA ||
    result.protocol !== "clockchain.bilateral-authorization/v1" ||
    result.paymentMoved !== false || !["rehearsal", "stakeholder"].includes(result.subjectRun)
  ) invalid();
  return Object.freeze({ ...result, amount: amountValue, payer, payee });
}

function signature(value) {
  const result = snapshot(value, SIGNATURE_KEYS);
  if (!ADDRESS_PATTERN.test(result.address) || result.algorithm !== "eip191" || !SIGNATURE_PATTERN.test(result.value)) invalid();
  return Object.freeze(result);
}

function envelopeSnapshot(value) {
  const result = snapshot(value, ENVELOPE_KEYS);
  if (result.schema !== PAYMENT_REQUEST_ENVELOPE_SCHEMA) invalid();
  return Object.freeze({ request: requestSnapshot(result.request), schema: result.schema, signature: signature(result.signature) });
}

function expectedSnapshot(value) {
  const result = snapshot(value, EXPECTED_KEYS);
  const amountValue = amount(result.amount);
  const payer = party(result.payer);
  const payee = party(result.payee);
  if (
    !printable(result.invoiceReferencePrefix) || !printable(result.purpose) ||
    !DIGEST_PATTERN.test(result.intakeDigest) ||
    !INTAKE_UUID_PATTERN.test(result.intakeRequestId) ||
    !printable(result.releaseId) || !SHA_PATTERN.test(result.repositorySha) ||
    !UUID_PATTERN.test(result.sessionId) || !["rehearsal", "stakeholder"].includes(result.subjectRun)
  ) invalid();
  return { ...result, amount: amountValue, payer, payee };
}

function same(left, right) {
  if (left === null || typeof left !== "object") return left === right;
  return canonicalBytes(left).equals(canonicalBytes(right));
}

function assertNowMs(nowMs) {
  if (!Number.isSafeInteger(nowMs) || nowMs < 0) invalid();
}

export function validatePaymentRequest(request) { requestSnapshot(request); }

export function paymentRequestSigningBytes(request) {
  return canonicalBytes(requestSnapshot(request));
}

export function paymentRequestDigest(envelope) {
  return digestHex(envelopeSnapshot(envelope).request);
}

export async function signPaymentRequest({ request, signMessage }) {
  const signedRequest = requestSnapshot(request);
  if (typeof signMessage !== "function") invalid();
  let value;
  try { value = await signMessage(canonicalBytes(signedRequest)); } catch { invalid(); }
  const signed = signature({ address: signedRequest.payee.address, algorithm: "eip191", value });
  return Object.freeze({ request: signedRequest, schema: PAYMENT_REQUEST_ENVELOPE_SCHEMA, signature: signed });
}

export async function verifyPaymentRequest({ envelope, mandateEnvelope, expected, nowMs }) {
  const verified = envelopeSnapshot(envelope);
  const binding = expectedSnapshot(expected);
  assertNowMs(nowMs);
  const mandate = await verifyPayerMandate({
    envelope: mandateEnvelope,
    expected: {
      ...binding,
      requestEndpoint: `/v1/sessions/${binding.sessionId}/payment-requests`,
    },
    nowMs,
  });
  if (
    verified.request.mandateDigest !== payerMandateDigest(mandate) ||
    verified.signature.address !== verified.request.payee.address ||
    nowMs < Number(verified.request.createdAtMs) || nowMs >= Number(verified.request.expiresAtMs) ||
    BigInt(verified.request.createdAtMs) < BigInt(mandate.mandate.issuedAtMs) ||
    BigInt(verified.request.expiresAtMs) > BigInt(mandate.mandate.expiresAtMs) ||
    !verified.request.invoiceReference.startsWith(mandate.mandate.invoiceReferencePrefix)
  ) invalid();
  for (const key of ["amount", "payer", "payee", "purpose", "releaseId", "repositorySha", "sessionId", "subjectRun"]) {
    if (!same(verified.request[key], binding[key]) || !same(verified.request[key], mandate.mandate[key])) invalid();
  }
  for (const key of ["intakeDigest", "intakeRequestId"]) {
    if (verified.request[key] !== binding[key] || verified.request[key] !== mandate.mandate[key]) invalid();
  }
  let recovered;
  try {
    recovered = await recoverMessageAddress({
      message: { raw: canonicalBytes(verified.request) },
      signature: verified.signature.value,
    });
  } catch { invalid(); }
  if (recovered.toLowerCase() !== verified.request.payee.address) invalid();
  return verified;
}
