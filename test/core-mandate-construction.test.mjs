import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  BILATERAL_PROTOCOL_ID,
  buildPayerMandate,
  MandateConstructionError,
} from "../src/core/mandate-construction.mjs";
import {
  PAYER_MANDATE_SCHEMA,
  payerMandateSigningBytes,
  validatePayerMandate,
} from "../src/core/payer-mandate.mjs";
import {
  BilateralProtocolError,
} from "../src/core/protocol.mjs";

const ISSUED_AT_MS = 1_800_000_000_000;
const FIXED_INTAKE_ID =
  "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed";

function signingDigest(mandate) {
  return createHash("sha256")
    .update(payerMandateSigningBytes(mandate))
    .digest("hex");
}

function baseInput() {
  return {
    amount: { currency: "USD", value: "12500" },
    expiresAtMs: ISSUED_AT_MS + 1_800_000,
    intakeDigest: "ab".repeat(32),
    invoiceReferencePrefix: "INV-2026-",
    issuedAtMs: ISSUED_AT_MS,
    payee: {
      address: `0x${"22".repeat(20)}`,
      agentId: "2",
    },
    payer: {
      address: `0x${"11".repeat(20)}`,
      agentId: "1",
    },
    purpose: "Stakeholder demonstration payment",
    releaseId: "v2-demo",
    repositorySha:
      "0123456789abcdef0123456789abcdef01234567",
    sessionId: "4a7d2e56-9c3b-4f1a-8d2e-5b6c7d8e9f0a",
    subjectRun: "stakeholder",
  };
}

test("builds a validated mandate with every derived field bound at construction", () => {
  const mandate = buildPayerMandate(baseInput());

  validatePayerMandate(mandate);
  assert.equal(mandate.schema, PAYER_MANDATE_SCHEMA);
  assert.equal(mandate.protocol, BILATERAL_PROTOCOL_ID);
  assert.equal(mandate.paymentMoved, false);
  assert.equal(mandate.subjectRun, "stakeholder");
  assert.equal(
    mandate.requestEndpoint,
    "/v1/sessions/4a7d2e56-9c3b-4f1a-8d2e-5b6c7d8e9f0a" +
      "/payment-requests",
  );
  assert.equal(mandate.issuedAtMs, String(ISSUED_AT_MS));
  assert.equal(
    mandate.expiresAtMs,
    String(ISSUED_AT_MS + 1_800_000),
  );
  assert.ok(Object.isFrozen(mandate));
});

test("generates a distinct intakeRequestId and signing digest per sub-run", () => {
  const mandates = Array.from(
    { length: 8 },
    () => buildPayerMandate(baseInput()),
  );
  const intakeIds = new Set(
    mandates.map((mandate) => mandate.intakeRequestId),
  );
  const digests = new Set(
    mandates.map((mandate) =>
      signingDigest(mandate)
    ),
  );

  assert.equal(intakeIds.size, mandates.length);
  assert.equal(digests.size, mandates.length);
});

test("binds the subjectRun into the signed bytes", () => {
  const rehearsal = buildPayerMandate({
    ...baseInput(),
    generateIntakeRequestId: () => FIXED_INTAKE_ID,
    subjectRun: "rehearsal",
  });
  const stakeholder = buildPayerMandate({
    ...baseInput(),
    generateIntakeRequestId: () => FIXED_INTAKE_ID,
    subjectRun: "stakeholder",
  });

  assert.equal(rehearsal.subjectRun, "rehearsal");
  assert.equal(stakeholder.subjectRun, "stakeholder");
  assert.notEqual(
    signingDigest(rehearsal),
    signingDigest(stakeholder),
  );
});

test("rejects an unknown subjectRun", () => {
  for (const subjectRun of [
    "production",
    "",
    "STAKEHOLDER",
    " rehearsal",
  ]) {
    assert.throws(
      () =>
        buildPayerMandate({ ...baseInput(), subjectRun }),
      (error) => {
        assert.ok(
          error instanceof MandateConstructionError,
        );
        assert.equal(
          error.code,
          "PAYER_MANDATE_CONSTRUCTION",
        );
        return true;
      },
    );
  }
});

test("enforces the human-paced construction window with the named guard code", () => {
  assert.throws(
    () =>
      buildPayerMandate({
        ...baseInput(),
        expiresAtMs: ISSUED_AT_MS + 1_799_999,
      }),
    (error) => {
      assert.ok(
        error instanceof BilateralProtocolError,
      );
      assert.equal(
        error.code,
        "DEADLINE_MANDATE_WINDOW",
      );
      return true;
    },
  );
  assert.doesNotThrow(() =>
    buildPayerMandate({
      ...baseInput(),
      expiresAtMs: ISSUED_AT_MS + 1_800_000,
    })
  );
});

test("fails closed on a misbehaving intake generator", () => {
  for (const generateIntakeRequestId of [
    () => "not-a-uuid",
    () => {
      throw new Error("entropy source failed");
    },
    "randomUUID",
  ]) {
    assert.throws(
      () =>
        buildPayerMandate({
          ...baseInput(),
          generateIntakeRequestId,
        }),
      (error) => {
        assert.ok(
          error instanceof MandateConstructionError,
        );
        return true;
      },
    );
  }

  // A constant generator reproduces the intakeRequestId, so
  // distinctness is a property of the default entropy source.
  const constant = () => FIXED_INTAKE_ID;
  assert.equal(
    buildPayerMandate({
      ...baseInput(),
      generateIntakeRequestId: constant,
    }).intakeRequestId,
    buildPayerMandate({
      ...baseInput(),
      generateIntakeRequestId: constant,
    }).intakeRequestId,
  );
});

test("rejects hostile construction inputs", () => {
  const valid = baseInput();
  for (const input of [
    null,
    42,
    [],
    new Proxy(valid, {}),
    { ...valid, extra: true },
    (({ amount, ...rest }) => rest)(valid),
    { ...valid, sessionId: "../../etc/passwd" },
    { ...valid, issuedAtMs: "not-a-number" },
    { ...valid, issuedAtMs: -5 },
  ]) {
    assert.throws(
      () => buildPayerMandate(input),
      (error) => {
        assert.ok(
          error instanceof MandateConstructionError,
        );
        assert.equal(
          error.code,
          "PAYER_MANDATE_CONSTRUCTION",
        );
        return true;
      },
    );
  }
});
