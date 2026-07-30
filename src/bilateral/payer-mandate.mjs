import { types } from "node:util";

import { recoverMessageAddress } from "viem";

import { canonicalBytes, digestHex } from "./canonical.mjs";

export const PAYER_MANDATE_SCHEMA =
  "clockchain.bilateral-payer-mandate/v1";
export const PAYER_MANDATE_ENVELOPE_SCHEMA =
  "clockchain.bilateral-payer-mandate-envelope/v1";

const MANDATE_KEYS = Object.freeze([
  "amount", "expiresAtMs", "intakeDigest", "intakeRequestId",
  "invoiceReferencePrefix", "issuedAtMs", "payee",
  "payer", "paymentMoved", "protocol", "purpose", "releaseId",
  "repositorySha", "requestEndpoint", "schema", "sessionId", "subjectRun",
]);
const PARTY_KEYS = Object.freeze(["address", "agentId"]);
const AMOUNT_KEYS = Object.freeze(["currency", "value"]);
const ENVELOPE_KEYS = Object.freeze(["mandate", "schema", "signature"]);
const SIGNATURE_KEYS = Object.freeze(["address", "algorithm", "value"]);
const EXPECTED_KEYS = Object.freeze([
  "amount", "intakeDigest", "intakeRequestId", "invoiceReferencePrefix",
  "payee", "payer", "purpose", "releaseId", "repositorySha",
  "requestEndpoint", "sessionId", "subjectRun",
]);
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const INTAKE_UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const SHA_PATTERN = /^[0-9a-f]{40}$/;
const DIGEST_PATTERN = /^[0-9a-f]{64}$/;
const SIGNATURE_PATTERN = /^0x[0-9a-f]{130}$/;
const PRINTABLE_PATTERN = /^[ -~]+$/;

export class PayerMandateError extends Error {
  constructor() {
    super("Payer mandate validation failed.");
    this.name = "PayerMandateError";
    this.category = "verification";
    this.code = "PAYER_MANDATE_INVALID";
  }
}

function invalid() {
  throw new PayerMandateError();
}

function snapshot(value, keys) {
  try {
    if (
      value === null || typeof value !== "object" || Array.isArray(value) ||
      types.isProxy(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))
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
    if (error instanceof PayerMandateError) throw error;
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
  try {
    if (BigInt(value) > BigInt(Number.MAX_SAFE_INTEGER)) invalid();
  } catch { invalid(); }
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

function mandateSnapshot(value) {
  const result = snapshot(value, MANDATE_KEYS);
  const amountValue = amount(result.amount);
  const payer = party(result.payer);
  const payee = party(result.payee);
  decimal(result.issuedAtMs);
  decimal(result.expiresAtMs);
  if (
    BigInt(result.issuedAtMs) >= BigInt(result.expiresAtMs) ||
    !DIGEST_PATTERN.test(result.intakeDigest) ||
    !INTAKE_UUID_PATTERN.test(result.intakeRequestId) ||
    !printable(result.invoiceReferencePrefix) ||
    !printable(result.purpose) || !printable(result.releaseId) ||
    !SHA_PATTERN.test(result.repositorySha) || !UUID_PATTERN.test(result.sessionId) ||
    result.schema !== PAYER_MANDATE_SCHEMA ||
    result.protocol !== "clockchain.bilateral-authorization/v1" ||
    result.paymentMoved !== false ||
    !["rehearsal", "stakeholder"].includes(result.subjectRun) ||
    result.requestEndpoint !== `/v1/sessions/${result.sessionId}/payment-requests`
  ) invalid();
  return Object.freeze({ ...result, amount: amountValue, payer, payee });
}

function signature(value) {
  const result = snapshot(value, SIGNATURE_KEYS);
  if (
    !ADDRESS_PATTERN.test(result.address) || result.algorithm !== "eip191" ||
    !SIGNATURE_PATTERN.test(result.value)
  ) invalid();
  return Object.freeze(result);
}

function envelopeSnapshot(value) {
  const result = snapshot(value, ENVELOPE_KEYS);
  if (result.schema !== PAYER_MANDATE_ENVELOPE_SCHEMA) invalid();
  return Object.freeze({
    mandate: mandateSnapshot(result.mandate),
    schema: result.schema,
    signature: signature(result.signature),
  });
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
    !UUID_PATTERN.test(result.sessionId) ||
    !["rehearsal", "stakeholder"].includes(result.subjectRun) ||
    result.requestEndpoint !== `/v1/sessions/${result.sessionId}/payment-requests`
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

export function validatePayerMandate(mandate) {
  mandateSnapshot(mandate);
}

export function payerMandateSigningBytes(mandate) {
  return canonicalBytes(mandateSnapshot(mandate));
}

export function payerMandateDigest(envelope) {
  return digestHex(envelopeSnapshot(envelope).mandate);
}

export async function signPayerMandate({ mandate, signMessage }) {
  const signedMandate = mandateSnapshot(mandate);
  if (typeof signMessage !== "function") invalid();
  let value;
  try { value = await signMessage(canonicalBytes(signedMandate)); } catch { invalid(); }
  const signed = signature({ address: signedMandate.payer.address, algorithm: "eip191", value });
  return Object.freeze({ mandate: signedMandate, schema: PAYER_MANDATE_ENVELOPE_SCHEMA, signature: signed });
}

export async function verifyPayerMandate({ envelope, expected, nowMs }) {
  const verified = envelopeSnapshot(envelope);
  const binding = expectedSnapshot(expected);
  assertNowMs(nowMs);
  for (const key of EXPECTED_KEYS) if (!same(verified.mandate[key], binding[key])) invalid();
  if (
    nowMs < Number(verified.mandate.issuedAtMs) ||
    nowMs >= Number(verified.mandate.expiresAtMs) ||
    verified.signature.address !== verified.mandate.payer.address
  ) invalid();
  let recovered;
  try {
    recovered = await recoverMessageAddress({
      message: { raw: canonicalBytes(verified.mandate) },
      signature: verified.signature.value,
    });
  } catch { invalid(); }
  if (recovered.toLowerCase() !== verified.mandate.payer.address) invalid();
  return verified;
}
