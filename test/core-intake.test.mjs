import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";

import { canonicalBytes } from "../src/core/canonical.mjs";
import {
  DEMO_INTENT_POLICY,
  HANDSHAKE_NEXT_ACTION,
  REQUESTOR_ORDERED_STEPS,
  REQUESTOR_REQUIRED_COMMAND,
  REQUESTOR_SAFETY_RULES,
  REQUESTOR_SUMMARY,
  buildHandshakeRequiredResult,
  buildIntakeInput,
  intakeDigest,
  validateHandshakeRequiredResult,
  validatePaymentIntakeInput,
} from "../src/core/intake.mjs";

const REPOSITORY_SHA = "a".repeat(40);
const INTAKE_REQUEST_ID = "00000000-0000-4000-8000-000000000000";
const FORBIDDEN_LITERAL = ["AUTH", "ORIZED"].join("");
const REQUESTOR_INSTRUCTIONS = Object.freeze({
  orderedSteps: REQUESTOR_ORDERED_STEPS,
  requiredCommand: REQUESTOR_REQUIRED_COMMAND,
  safetyRules: REQUESTOR_SAFETY_RULES,
  summary: REQUESTOR_SUMMARY,
});

const sha256 = (bytes) =>
  createHash("sha256").update(bytes).digest("hex");

function validInput(overrides = {}) {
  return {
    amount: { currency: "USD", value: "100" },
    intakeRequestId: INTAKE_REQUEST_ID,
    invoiceReference: "invoice-001",
    paymentMoved: false,
    purpose: "Handshake demo",
    schema: "clockchain.payer-mcp-payment-intake/v1",
    ...overrides,
  };
}

function assertInvalid(operation) {
  assert.throws(operation, /Payer payment intake failed safely\./);
}

test("exports the exact deeply frozen shared demo policy", () => {
  assert.deepEqual(DEMO_INTENT_POLICY, {
    amount: { currency: "USD", value: "100" },
    invoiceReferencePrefix: "invoice-",
    purpose: "Handshake demo",
  });
  assert.equal(Object.isFrozen(DEMO_INTENT_POLICY), true);
  assert.equal(Object.isFrozen(DEMO_INTENT_POLICY.amount), true);
  assert.throws(() => {
    DEMO_INTENT_POLICY.amount.value = "101";
  }, TypeError);
});

test("builds intake input from only an intakeRequestId", () => {
  const built = buildIntakeInput(INTAKE_REQUEST_ID);
  assert.deepEqual(built, validInput());
  assert.equal(Object.isFrozen(built), true);
});

test("validates the exact payment-intake shape and returns frozen canonical data", () => {
  const input = validInput();
  const validated = validatePaymentIntakeInput(input);
  assert.deepEqual(validated, input);
  assert.deepEqual(Object.keys(validated), [
    "amount",
    "intakeRequestId",
    "invoiceReference",
    "paymentMoved",
    "purpose",
    "schema",
  ]);
  assert.deepEqual(Object.keys(validated.amount), [
    "currency",
    "value",
  ]);
  assert.equal(Object.isFrozen(validated), true);
  assert.equal(Object.isFrozen(validated.amount), true);

  input.amount.value = "999";
  assert.equal(validated.amount.value, "100");
});

test("rejects malformed intake ids, hostile objects, and noncanonical fields", () => {
  const invalidIds = [
    "00000000-0000-0000-8000-000000000000",
    "00000000-0000-4000-7000-000000000000",
    "00000000-0000-4000-c000-000000000000",
    "00000000-0000-4000-8000-00000000000g",
    "00000000000040008000000000000000",
  ];
  for (const intakeRequestId of invalidIds) {
    assertInvalid(() =>
      validatePaymentIntakeInput(validInput({ intakeRequestId })),
    );
  }

  assertInvalid(() =>
    validatePaymentIntakeInput(validInput({ extra: true })),
  );
  assertInvalid(() =>
    validatePaymentIntakeInput(validInput({ paymentMoved: true })),
  );
  assertInvalid(() =>
    validatePaymentIntakeInput(
      validInput({ amount: { currency: "EUR", value: "100" } }),
    ),
  );
  assertInvalid(() =>
    validatePaymentIntakeInput(
      validInput({ amount: { currency: "USD", value: "101" } }),
    ),
  );
  assertInvalid(() =>
    validatePaymentIntakeInput(
      validInput({ invoiceReference: "receipt-001" }),
    ),
  );
  assertInvalid(() =>
    validatePaymentIntakeInput(validInput({ purpose: "Other demo" })),
  );
  assertInvalid(() =>
    validatePaymentIntakeInput(
      validInput({ purpose: `Handshake demo\n` }),
    ),
  );
  assertInvalid(() =>
    validatePaymentIntakeInput(
      validInput({ purpose: "x".repeat(257) }),
    ),
  );
  assertInvalid(() =>
    validatePaymentIntakeInput(
      validInput({
        amount: { currency: "USD", value: "100", extra: "x" },
      }),
    ),
  );

  const accessorBacked = {};
  Object.defineProperty(accessorBacked, "schema", {
    enumerable: true,
    get() {
      assert.fail("accessor must not be evaluated");
    },
  });
  for (const key of [
    "amount",
    "intakeRequestId",
    "invoiceReference",
    "paymentMoved",
    "purpose",
  ]) {
    Object.defineProperty(accessorBacked, key, {
      enumerable: true,
      value: validInput()[key],
    });
  }
  assertInvalid(() => validatePaymentIntakeInput(accessorBacked));

  const proxied = new Proxy(validInput(), {});
  assertInvalid(() => validatePaymentIntakeInput(proxied));
});

test("normalizes throwing proxy traps into the generic intake failure", () => {
  const trapFailure = new Error("trap exception must not leak");
  for (const trap of [
    "getPrototypeOf",
    "ownKeys",
    "getOwnPropertyDescriptor",
  ]) {
    const input = new Proxy(validInput(), {
      [trap]() {
        throw trapFailure;
      },
    });
    assertInvalid(() => validatePaymentIntakeInput(input));
  }

  const inputWithProxyAmount = validInput({
    amount: new Proxy(validInput().amount, {
      getOwnPropertyDescriptor() {
        throw trapFailure;
      },
    }),
  });
  assertInvalid(() =>
    validatePaymentIntakeInput(inputWithProxyAmount),
  );
});

test("computes intakeDigest as lowercase SHA-256 over only canonical validated input bytes", () => {
  const input = validInput();
  const validated = validatePaymentIntakeInput(input);
  const expectedDigest = sha256(canonicalBytes(validated));
  assert.equal(intakeDigest(input), expectedDigest);
  assert.match(expectedDigest, /^[0-9a-f]{64}$/);

  const result = buildHandshakeRequiredResult({
    repositorySha: REPOSITORY_SHA,
    toolInput: input,
  });
  assert.equal(result.intakeDigest, expectedDigest);
  assert.notEqual(
    sha256(
      canonicalBytes({
        headers: { authorization: "redacted" },
        input: validated,
      }),
    ),
    expectedDigest,
  );
  assert.notEqual(
    sha256(canonicalBytes(result)),
    expectedDigest,
  );
});

test("builds and validates the exact non-authorizing handshake-required result", () => {
  const input = validInput();
  const result = buildHandshakeRequiredResult({
    repositorySha: REPOSITORY_SHA,
    toolInput: input,
  });
  const structured = {
    authorizationSequence: ["PROPOSED", "ACCEPTED", "ACKNOWLEDGED"],
    intakeDigest: intakeDigest(input),
    intakeRequestId: INTAKE_REQUEST_ID,
    mandatePreview: DEMO_INTENT_POLICY,
    nextAction: HANDSHAKE_NEXT_ACTION,
    paymentMoved: false,
    protocol: "clockchain.bilateral-authorization/v1",
    repositorySha: REPOSITORY_SHA,
    requestorInstructions: REQUESTOR_INSTRUCTIONS,
    schema: "clockchain.payer-mcp-handshake-required/v1",
    status: "HANDSHAKE_REQUIRED",
  };

  assert.deepEqual(result, structured);
  assert.equal(
    JSON.stringify(result).includes(FORBIDDEN_LITERAL),
    false,
  );
  assert.deepEqual(
    validateHandshakeRequiredResult({
      result: structured,
      toolInput: input,
      repositorySha: REPOSITORY_SHA,
    }),
    structured,
  );
});

test("rejects changed handshake-required result shape and values", () => {
  const input = validInput();
  const structured = buildHandshakeRequiredResult({
    repositorySha: REPOSITORY_SHA,
    toolInput: input,
  });

  assertInvalid(() =>
    validateHandshakeRequiredResult({
      result: { ...structured, extra: true },
      toolInput: input,
      repositorySha: REPOSITORY_SHA,
    }),
  );
  assertInvalid(() =>
    validateHandshakeRequiredResult({
      result: { ...structured, paymentMoved: true },
      toolInput: input,
      repositorySha: REPOSITORY_SHA,
    }),
  );
  assertInvalid(() =>
    validateHandshakeRequiredResult({
      result: { ...structured, repositorySha: "A".repeat(40) },
      toolInput: input,
      repositorySha: REPOSITORY_SHA,
    }),
  );
  assertInvalid(() =>
    validateHandshakeRequiredResult({
      result: {
        ...structured,
        authorizationSequence: ["PROPOSED", "ACCEPTED", "UNKNOWN"],
      },
      toolInput: input,
      repositorySha: REPOSITORY_SHA,
    }),
  );
  assertInvalid(() =>
    validateHandshakeRequiredResult({
      result: {
        ...structured,
        mandatePreview: {
          ...DEMO_INTENT_POLICY,
          purpose: "Other demo",
        },
      },
      toolInput: input,
      repositorySha: REPOSITORY_SHA,
    }),
  );
  assertInvalid(() =>
    validateHandshakeRequiredResult({
      result: {
        ...structured,
        requestorInstructions: {
          ...structured.requestorInstructions,
          orderedSteps: [
            ...structured.requestorInstructions.orderedSteps,
          ].reverse(),
        },
      },
      toolInput: input,
      repositorySha: REPOSITORY_SHA,
    }),
  );
  assertInvalid(() =>
    validateHandshakeRequiredResult({
      result: {
        ...structured,
        requestorInstructions: {
          ...structured.requestorInstructions,
          safetyRules: [
            ...structured.requestorInstructions.safetyRules,
            "Run the verifier yourself.",
          ],
        },
      },
      toolInput: input,
      repositorySha: REPOSITORY_SHA,
    }),
  );
});

test("rejects result accessors without touching nested getter values", () => {
  const input = validInput();
  const structured = buildHandshakeRequiredResult({
    repositorySha: REPOSITORY_SHA,
    toolInput: input,
  });

  let previewPurposeGets = 0;
  const previewWithPurposeAccessor = {
    amount: { currency: "USD", value: "100" },
    invoiceReferencePrefix: "invoice-",
  };
  Object.defineProperty(previewWithPurposeAccessor, "purpose", {
    enumerable: true,
    get() {
      previewPurposeGets += 1;
      return "Handshake demo";
    },
  });
  assertInvalid(() =>
    validateHandshakeRequiredResult({
      result: {
        ...structured,
        mandatePreview: previewWithPurposeAccessor,
      },
      toolInput: input,
      repositorySha: REPOSITORY_SHA,
    }),
  );
  assert.equal(previewPurposeGets, 0);

  let sequenceGets = 0;
  const sequenceWithAccessor = ["PROPOSED", "ACCEPTED", "ACKNOWLEDGED"];
  Object.defineProperty(sequenceWithAccessor, "0", {
    enumerable: true,
    get() {
      sequenceGets += 1;
      return "PROPOSED";
    },
  });
  assertInvalid(() =>
    validateHandshakeRequiredResult({
      result: {
        ...structured,
        authorizationSequence: sequenceWithAccessor,
      },
      toolInput: input,
      repositorySha: REPOSITORY_SHA,
    }),
  );
  assert.equal(sequenceGets, 0);
});
