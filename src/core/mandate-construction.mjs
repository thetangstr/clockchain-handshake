import { randomUUID } from "node:crypto";
import { types } from "node:util";

import {
  assertMandateConstructionWindow,
} from "./deadline.mjs";
import {
  PAYER_MANDATE_SCHEMA,
  validatePayerMandate,
} from "./payer-mandate.mjs";

export const BILATERAL_PROTOCOL_ID =
  "clockchain.bilateral-authorization/v1";

export class MandateConstructionError extends Error {
  constructor() {
    super("Payer mandate construction failed.");
    this.name = "MandateConstructionError";
    this.category = "verification";
    this.code = "PAYER_MANDATE_CONSTRUCTION";
  }
}

const CONSTRUCTION_INPUT_KEYS = Object.freeze([
  "amount",
  "expiresAtMs",
  "generateIntakeRequestId",
  "intakeDigest",
  "invoiceReferencePrefix",
  "issuedAtMs",
  "payee",
  "payer",
  "purpose",
  "releaseId",
  "repositorySha",
  "sessionId",
  "subjectRun",
]);
const REQUIRED_INPUT_KEYS = Object.freeze(
  CONSTRUCTION_INPUT_KEYS.filter(
    (key) => key !== "generateIntakeRequestId",
  ),
);
const DECIMAL_PATTERN = /^(0|[1-9][0-9]*)$/;

function constructionFailure() {
  throw new MandateConstructionError();
}

function canonicalMs(value) {
  if (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= 0
  ) {
    return String(value);
  }
  if (
    typeof value === "string" &&
    DECIMAL_PATTERN.test(value)
  ) {
    return value;
  }
  constructionFailure();
}

function readConstructionInput(input) {
  if (
    input === null ||
    typeof input !== "object" ||
    Array.isArray(input) ||
    types.isProxy(input) ||
    (
      Object.getPrototypeOf(input) !== Object.prototype &&
      Object.getPrototypeOf(input) !== null
    )
  ) {
    constructionFailure();
  }
  const keys = Object.keys(input);
  if (
    !keys.every((key) =>
      CONSTRUCTION_INPUT_KEYS.includes(key)
    ) ||
    !REQUIRED_INPUT_KEYS.every((key) => keys.includes(key))
  ) {
    constructionFailure();
  }
  return input;
}

// Assembles a payer mandate with every derived field bound at
// construction: schema, protocol, paymentMoved:false, and the
// requestEndpoint derived from the sessionId are never accepted from
// the caller. The subjectRun is bound explicitly and flows into the
// signed bytes. The intakeRequestId comes from the injected generator
// (default randomUUID); distinctness across sub-runs is a property of
// that entropy source, so callers must never inject a constant outside
// tests. Construction fails closed through validatePayerMandate.
export function buildPayerMandate(input) {
  const snapshot = readConstructionInput(input);
  if (
    snapshot.subjectRun !== "rehearsal" &&
    snapshot.subjectRun !== "stakeholder"
  ) {
    constructionFailure();
  }
  const generate =
    snapshot.generateIntakeRequestId ?? randomUUID;
  if (
    typeof generate !== "function" ||
    types.isProxy(generate)
  ) {
    constructionFailure();
  }
  const issuedAtMs = canonicalMs(snapshot.issuedAtMs);
  const expiresAtMs = canonicalMs(snapshot.expiresAtMs);

  // The named window guard propagates with its own actionable code.
  assertMandateConstructionWindow({ issuedAtMs, expiresAtMs });

  let intakeRequestId;
  try {
    intakeRequestId = generate();
  } catch {
    constructionFailure();
  }

  try {
    const mandate = {
      amount: snapshot.amount,
      expiresAtMs,
      intakeDigest: snapshot.intakeDigest,
      intakeRequestId,
      invoiceReferencePrefix:
        snapshot.invoiceReferencePrefix,
      issuedAtMs,
      payee: snapshot.payee,
      payer: snapshot.payer,
      paymentMoved: false,
      protocol: BILATERAL_PROTOCOL_ID,
      purpose: snapshot.purpose,
      releaseId: snapshot.releaseId,
      repositorySha: snapshot.repositorySha,
      requestEndpoint:
        `/v1/sessions/${snapshot.sessionId}/payment-requests`,
      schema: PAYER_MANDATE_SCHEMA,
      sessionId: snapshot.sessionId,
      subjectRun: snapshot.subjectRun,
    };
    validatePayerMandate(mandate);
    return Object.freeze(mandate);
  } catch (error) {
    if (error instanceof MandateConstructionError) {
      throw error;
    }
    constructionFailure();
  }
}
