import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";

import { canonicalBytes } from "../src/bilateral/canonical.mjs";
import { DEMO_INTENT_POLICY } from "../src/bilateral/demo-intent-policy.mjs";
import {
  PAYMENT_INTAKE_TOOL_DESCRIPTOR,
  buildPaymentIntakeToolResult,
  intakeDigest,
  validateHandshakeRequiredResult,
  validatePaymentIntakeInput,
  validatePaymentIntakeToolResult,
} from "../src/bilateral/local-mcp/payment-intake.mjs";

const REPOSITORY_SHA = "a".repeat(40);
const INTAKE_REQUEST_ID = "00000000-0000-4000-8000-000000000000";
const FORBIDDEN_LITERAL = ["AUTH", "ORIZED"].join("");
const REQUESTOR_INSTRUCTIONS = Object.freeze({
  orderedSteps: [
    "Keep this checkout detached, clean, and at repositorySha before handling private material.",
    "Let this command poll the Payer bootstrap broker until the operator seals the launch manifest.",
    "After the sealed manifest is written locally, let this command call request_payment once and start the Requestor supervisor.",
    "Stay attached until the three public anchors are visible: PROPOSED, ACCEPTED, ACKNOWLEDGED.",
  ],
  requiredCommand: "npm run bilateral:request-payment -- --discovery-url <signed-discovery-url> --state <absolute-private-requestor-state-root>",
  safetyRules: [
    "Do not act as Payer.",
    "Do not change payer terms.",
    "Do not fund addresses or move payment; paymentMoved must remain false.",
    "Do not print or share private keys, capabilities, tokens, launch manifests, or live evidence.",
    "Do not claim the final verdict; only the operator fresh aggregate verifier may report it.",
  ],
  summary: "The Payer requires Clockchain Handshake before this payment request can be evaluated.",
});

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

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
  assert.throws(operation, /Payer MCP payment intake failed safely\./);
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
  assert.deepEqual(Object.keys(validated.amount), ["currency", "value"]);
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
    assertInvalid(() => validatePaymentIntakeInput(validInput({ intakeRequestId })));
  }

  assertInvalid(() => validatePaymentIntakeInput(validInput({ extra: true })));
  assertInvalid(() => validatePaymentIntakeInput(validInput({ paymentMoved: true })));
  assertInvalid(() => validatePaymentIntakeInput(validInput({ amount: { currency: "EUR", value: "100" } })));
  assertInvalid(() => validatePaymentIntakeInput(validInput({ amount: { currency: "USD", value: "101" } })));
  assertInvalid(() => validatePaymentIntakeInput(validInput({ invoiceReference: "receipt-001" })));
  assertInvalid(() => validatePaymentIntakeInput(validInput({ purpose: "Other demo" })));
  assertInvalid(() => validatePaymentIntakeInput(validInput({ purpose: `Handshake demo\n` })));
  assertInvalid(() => validatePaymentIntakeInput(validInput({ purpose: "x".repeat(257) })));
  assertInvalid(() => validatePaymentIntakeInput(validInput({ amount: { currency: "USD", value: "100", extra: "x" } })));

  const accessorBacked = {};
  Object.defineProperty(accessorBacked, "schema", {
    enumerable: true,
    get() {
      assert.fail("accessor must not be evaluated");
    },
  });
  for (const key of ["amount", "intakeRequestId", "invoiceReference", "paymentMoved", "purpose"]) {
    Object.defineProperty(accessorBacked, key, { enumerable: true, value: validInput()[key] });
  }
  assertInvalid(() => validatePaymentIntakeInput(accessorBacked));

  const proxied = new Proxy(validInput(), {});
  assertInvalid(() => validatePaymentIntakeInput(proxied));
});

test("normalizes throwing proxy traps into the generic intake failure", () => {
  const trapFailure = new Error("trap exception must not leak");
  for (const trap of ["getPrototypeOf", "ownKeys", "getOwnPropertyDescriptor"]) {
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
  assertInvalid(() => validatePaymentIntakeInput(inputWithProxyAmount));
});

test("computes intakeDigest as lowercase SHA-256 over only canonical validated input bytes", () => {
  const input = validInput();
  const validated = validatePaymentIntakeInput(input);
  const expectedDigest = sha256(canonicalBytes(validated));
  assert.equal(intakeDigest(input), expectedDigest);
  assert.match(expectedDigest, /^[0-9a-f]{64}$/);

  const result = buildPaymentIntakeToolResult({ repositorySha: REPOSITORY_SHA, toolInput: input });
  assert.equal(result.structuredContent.intakeDigest, expectedDigest);
  assert.notEqual(
    sha256(canonicalBytes({ headers: { authorization: "redacted" }, input: validated })),
    expectedDigest,
  );
  assert.notEqual(sha256(canonicalBytes(result.structuredContent)), expectedDigest);
});

test("builds and validates the exact non-authorizing handshake-required tool result", () => {
  const input = validInput();
  const result = buildPaymentIntakeToolResult({ repositorySha: REPOSITORY_SHA, toolInput: input });
  const structured = {
    authorizationSequence: ["PROPOSED", "ACCEPTED", "ACKNOWLEDGED"],
    intakeDigest: intakeDigest(input),
    intakeRequestId: INTAKE_REQUEST_ID,
    mandatePreview: DEMO_INTENT_POLICY,
    nextAction: "START_REQUESTOR_SUPERVISOR",
    paymentMoved: false,
    protocol: "clockchain.bilateral-authorization/v1",
    repositorySha: REPOSITORY_SHA,
    requestorInstructions: REQUESTOR_INSTRUCTIONS,
    schema: "clockchain.payer-mcp-handshake-required/v1",
    status: "HANDSHAKE_REQUIRED",
  };

  assert.deepEqual(result, {
    structuredContent: structured,
    content: [{ type: "text", text: canonicalBytes(structured).toString("utf8") }],
  });
  assert.equal(result.content[0].text, canonicalBytes(result.structuredContent).toString("utf8"));
  assert.deepEqual(JSON.parse(result.content[0].text), result.structuredContent);
  assert.equal(JSON.stringify(result).includes(FORBIDDEN_LITERAL), false);
  assert.deepEqual(validatePaymentIntakeToolResult({ result, toolInput: input, repositorySha: REPOSITORY_SHA }), structured);
  assert.deepEqual(validateHandshakeRequiredResult({ result: structured, toolInput: input, repositorySha: REPOSITORY_SHA }), structured);
});

test("rejects changed handshake-required result shape and values", () => {
  const input = validInput();
  const result = buildPaymentIntakeToolResult({ repositorySha: REPOSITORY_SHA, toolInput: input });
  const structured = result.structuredContent;

  assertInvalid(() => validatePaymentIntakeToolResult({
    result: { ...result, extra: true },
    toolInput: input,
    repositorySha: REPOSITORY_SHA,
  }));
  assertInvalid(() => validatePaymentIntakeToolResult({
    result: { structuredContent: structured, content: [{ type: "text", text: "{}" }] },
    toolInput: input,
    repositorySha: REPOSITORY_SHA,
  }));
  assertInvalid(() => validateHandshakeRequiredResult({
    result: { ...structured, paymentMoved: true },
    toolInput: input,
    repositorySha: REPOSITORY_SHA,
  }));
  assertInvalid(() => validateHandshakeRequiredResult({
    result: { ...structured, repositorySha: "A".repeat(40) },
    toolInput: input,
    repositorySha: REPOSITORY_SHA,
  }));
  assertInvalid(() => validateHandshakeRequiredResult({
    result: { ...structured, authorizationSequence: ["PROPOSED", "ACCEPTED", "UNKNOWN"] },
    toolInput: input,
    repositorySha: REPOSITORY_SHA,
  }));
  assertInvalid(() => validateHandshakeRequiredResult({
    result: { ...structured, mandatePreview: { ...DEMO_INTENT_POLICY, purpose: "Other demo" } },
    toolInput: input,
    repositorySha: REPOSITORY_SHA,
  }));
  assertInvalid(() => validateHandshakeRequiredResult({
    result: {
      ...structured,
      requestorInstructions: {
        ...structured.requestorInstructions,
        orderedSteps: [...structured.requestorInstructions.orderedSteps].reverse(),
      },
    },
    toolInput: input,
    repositorySha: REPOSITORY_SHA,
  }));
  assertInvalid(() => validateHandshakeRequiredResult({
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
  }));
});

test("rejects result accessors without touching nested getter values", () => {
  const input = validInput();
  const result = buildPaymentIntakeToolResult({ repositorySha: REPOSITORY_SHA, toolInput: input });

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
  assertInvalid(() => validateHandshakeRequiredResult({
    result: { ...result.structuredContent, mandatePreview: previewWithPurposeAccessor },
    toolInput: input,
    repositorySha: REPOSITORY_SHA,
  }));
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
  assertInvalid(() => validateHandshakeRequiredResult({
    result: { ...result.structuredContent, authorizationSequence: sequenceWithAccessor },
    toolInput: input,
    repositorySha: REPOSITORY_SHA,
  }));
  assert.equal(sequenceGets, 0);

  let textGets = 0;
  const textBlockWithAccessor = { type: "text" };
  Object.defineProperty(textBlockWithAccessor, "text", {
    enumerable: true,
    get() {
      textGets += 1;
      return result.content[0].text;
    },
  });
  assertInvalid(() => validatePaymentIntakeToolResult({
    result: { structuredContent: result.structuredContent, content: [textBlockWithAccessor] },
    toolInput: input,
    repositorySha: REPOSITORY_SHA,
  }));
  assert.equal(textGets, 0);
});

test("exports the canonical request_payment MCP tool descriptor", () => {
  assert.deepEqual(PAYMENT_INTAKE_TOOL_DESCRIPTOR, {
    name: "request_payment",
    description: "Ask this Payer to process the fixed demo payment request. A successful intake returns the exact public Clockchain Handshake instructions the Requestor must follow; it does not move or authorize payment.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["amount", "intakeRequestId", "invoiceReference", "paymentMoved", "purpose", "schema"],
      properties: {
        amount: {
          type: "object",
          additionalProperties: false,
          required: ["currency", "value"],
          properties: {
            currency: { const: "USD" },
            value: { const: "100" },
          },
        },
        intakeRequestId: { type: "string", pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$" },
        invoiceReference: { const: "invoice-001" },
        paymentMoved: { const: false },
        purpose: { const: "Handshake demo" },
        schema: { const: "clockchain.payer-mcp-payment-intake/v1" },
      },
    },
  });
  assert.equal(Object.isFrozen(PAYMENT_INTAKE_TOOL_DESCRIPTOR), true);
  assert.equal(JSON.stringify(PAYMENT_INTAKE_TOOL_DESCRIPTOR).includes(FORBIDDEN_LITERAL), false);
});
