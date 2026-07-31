import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";

import { canonicalBytes } from "../canonical.mjs";
import { DEMO_INTENT_POLICY } from "../demo-intent-policy.mjs";

export const PAYMENT_INTAKE_SCHEMA = "clockchain.payer-mcp-payment-intake/v1";
export const HANDSHAKE_REQUIRED_SCHEMA = "clockchain.payer-mcp-handshake-required/v1";
export const REQUEST_PAYMENT_TOOL_NAME = "request_payment";

const UUID_V4_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const LOWERCASE_SHA_PATTERN = /^[0-9a-f]{40}$/;
const LOWERCASE_DIGEST_PATTERN = /^[0-9a-f]{64}$/;
const PRINTABLE_ASCII_PATTERN = /^[ -~]*$/;
const INTAKE_KEYS = ["amount", "intakeRequestId", "invoiceReference", "paymentMoved", "purpose", "schema"];
const AMOUNT_KEYS = ["currency", "value"];
const RESULT_KEYS = [
  "authorizationSequence",
  "intakeDigest",
  "intakeRequestId",
  "mandatePreview",
  "nextAction",
  "paymentMoved",
  "protocol",
  "repositorySha",
  "requestorInstructions",
  "schema",
  "status",
];
const REQUESTOR_INSTRUCTION_KEYS = ["orderedSteps", "requiredCommand", "safetyRules", "summary"];
const TOOL_RESULT_KEYS = ["structuredContent", "content"];
const TEXT_BLOCK_KEYS = ["type", "text"];
const AUTHORIZATION_SEQUENCE = Object.freeze(["PROPOSED", "ACCEPTED", "ACKNOWLEDGED"]);
const REQUESTOR_ORDERED_STEPS = Object.freeze([
  "Keep this checkout detached, clean, and at repositorySha before handling private material.",
  "Let this command poll the Payer bootstrap broker until the operator seals the launch manifest.",
  "After the sealed manifest is written locally, let this command call request_payment once and start the Requestor supervisor.",
  "Stay attached until the three public anchors are visible: PROPOSED, ACCEPTED, ACKNOWLEDGED.",
]);
const REQUESTOR_SAFETY_RULES = Object.freeze([
  "Do not act as Payer.",
  "Do not change payer terms.",
  "Do not fund addresses or move payment; paymentMoved must remain false.",
  "Do not print or share private keys, capabilities, tokens, launch manifests, or live evidence.",
  "Do not claim the final verdict; only the operator fresh aggregate verifier may report it.",
]);
const REQUESTOR_REQUIRED_COMMAND = "npm run bilateral:request-payment -- --discovery-url <signed-discovery-url> --state <absolute-private-requestor-state-root>";
const REQUESTOR_SUMMARY = "The Payer requires Clockchain Handshake before this payment request can be evaluated.";

function invalid() {
  throw new Error("Payer MCP payment intake failed safely.");
}

function deepFreeze(value) {
  if (value && typeof value === "object") {
    for (const entry of Object.values(value)) deepFreeze(entry);
    Object.freeze(value);
  }
  return value;
}

function exactDataObject(value, keys) {
  try {
    if (value === null || typeof value !== "object" || Array.isArray(value)) invalid();
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) invalid();
    const ownKeys = Reflect.ownKeys(value);
    if (
      ownKeys.length !== keys.length ||
      keys.some((key, index) => ownKeys[index] !== key)
    ) {
      invalid();
    }
    const entries = Object.create(null);
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value")) invalid();
      entries[key] = descriptor.value;
    }
    return entries;
  } catch {
    invalid();
  }
}

function exactDenseArray(value, length) {
  try {
    if (!Array.isArray(value)) invalid();
    const ownKeys = Reflect.ownKeys(value);
    const expectedKeys = [
      ...Array.from({ length }, (_, index) => String(index)),
      "length",
    ];
    if (
      ownKeys.length !== expectedKeys.length ||
      expectedKeys.some((key, index) => ownKeys[index] !== key)
    ) {
      invalid();
    }
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
    if (!lengthDescriptor || !Object.hasOwn(lengthDescriptor, "value") || lengthDescriptor.value !== length) invalid();
    return Array.from({ length }, (_, index) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value")) invalid();
      return descriptor.value;
    });
  } catch {
    invalid();
  }
}

function assertCloneablePlain(value) {
  try {
    structuredClone(value);
  } catch {
    invalid();
  }
}

function assertPrintableString(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 256 ||
    value.trim() !== value ||
    !PRINTABLE_ASCII_PATTERN.test(value)
  ) {
    invalid();
  }
}

function canonicalText(value) {
  return canonicalBytes(value).toString("utf8");
}

function clonePolicy() {
  return deepFreeze({
    amount: { ...DEMO_INTENT_POLICY.amount },
    invoiceReferencePrefix: DEMO_INTENT_POLICY.invoiceReferencePrefix,
    purpose: DEMO_INTENT_POLICY.purpose,
  });
}

function cloneRequestorInstructions() {
  return deepFreeze({
    orderedSteps: [...REQUESTOR_ORDERED_STEPS],
    requiredCommand: REQUESTOR_REQUIRED_COMMAND,
    safetyRules: [...REQUESTOR_SAFETY_RULES],
    summary: REQUESTOR_SUMMARY,
  });
}

function validatePolicyPreview(value) {
  const preview = exactDataObject(value, ["amount", "invoiceReferencePrefix", "purpose"]);
  const amount = exactDataObject(preview.amount, AMOUNT_KEYS);
  if (
    amount.currency !== DEMO_INTENT_POLICY.amount.currency ||
    amount.value !== DEMO_INTENT_POLICY.amount.value ||
    preview.invoiceReferencePrefix !== DEMO_INTENT_POLICY.invoiceReferencePrefix ||
    preview.purpose !== DEMO_INTENT_POLICY.purpose
  ) {
    invalid();
  }
  return clonePolicy();
}

function validateRequestorInstructions(value) {
  const instructions = exactDataObject(value, REQUESTOR_INSTRUCTION_KEYS);
  const orderedSteps = exactDenseArray(instructions.orderedSteps, REQUESTOR_ORDERED_STEPS.length);
  const safetyRules = exactDenseArray(instructions.safetyRules, REQUESTOR_SAFETY_RULES.length);
  if (
    !orderedSteps.every((entry, index) => entry === REQUESTOR_ORDERED_STEPS[index]) ||
    instructions.requiredCommand !== REQUESTOR_REQUIRED_COMMAND ||
    !safetyRules.every((entry, index) => entry === REQUESTOR_SAFETY_RULES[index]) ||
    instructions.summary !== REQUESTOR_SUMMARY
  ) {
    invalid();
  }
  for (const stringValue of [
    ...orderedSteps,
    instructions.requiredCommand,
    ...safetyRules,
    instructions.summary,
  ]) {
    assertPrintableString(stringValue);
  }
  return cloneRequestorInstructions();
}

export const PAYMENT_INTAKE_TOOL_DESCRIPTOR = deepFreeze({
  name: REQUEST_PAYMENT_TOOL_NAME,
  description: "Ask this Payer to process the fixed demo payment request. A successful intake returns the exact public Clockchain Handshake instructions the Requestor must follow; it does not move or authorize payment.",
  inputSchema: {
    type: "object",
    additionalProperties: false,
    required: INTAKE_KEYS,
    properties: {
      amount: {
        type: "object",
        additionalProperties: false,
        required: AMOUNT_KEYS,
        properties: {
          currency: { const: "USD" },
          value: { const: "100" },
        },
      },
      intakeRequestId: { type: "string", pattern: UUID_V4_PATTERN.source },
      invoiceReference: { const: "invoice-001" },
      paymentMoved: { const: false },
      purpose: { const: "Handshake demo" },
      schema: { const: PAYMENT_INTAKE_SCHEMA },
    },
  },
});

export function validatePaymentIntakeInput(value) {
  const input = exactDataObject(value, INTAKE_KEYS);
  const amount = exactDataObject(input.amount, AMOUNT_KEYS);
  assertCloneablePlain(value);
  for (const stringValue of [
    amount.currency,
    amount.value,
    input.intakeRequestId,
    input.invoiceReference,
    input.purpose,
    input.schema,
  ]) {
    assertPrintableString(stringValue);
  }
  if (
    amount.currency !== DEMO_INTENT_POLICY.amount.currency ||
    amount.value !== DEMO_INTENT_POLICY.amount.value ||
    !UUID_V4_PATTERN.test(input.intakeRequestId) ||
    input.invoiceReference !== `${DEMO_INTENT_POLICY.invoiceReferencePrefix}001` ||
    input.paymentMoved !== false ||
    input.purpose !== DEMO_INTENT_POLICY.purpose ||
    input.schema !== PAYMENT_INTAKE_SCHEMA
  ) {
    invalid();
  }
  return deepFreeze({
    amount: { currency: amount.currency, value: amount.value },
    intakeRequestId: input.intakeRequestId,
    invoiceReference: input.invoiceReference,
    paymentMoved: false,
    purpose: input.purpose,
    schema: PAYMENT_INTAKE_SCHEMA,
  });
}

export function intakeDigest(value) {
  return createHash("sha256")
    .update(canonicalBytes(validatePaymentIntakeInput(value)))
    .digest("hex");
}

export function buildHandshakeRequiredResult({ repositorySha, toolInput }) {
  if (typeof repositorySha !== "string" || !LOWERCASE_SHA_PATTERN.test(repositorySha)) invalid();
  const input = validatePaymentIntakeInput(toolInput);
  return deepFreeze({
    authorizationSequence: [...AUTHORIZATION_SEQUENCE],
    intakeDigest: intakeDigest(input),
    intakeRequestId: input.intakeRequestId,
    mandatePreview: clonePolicy(),
    nextAction: "START_REQUESTOR_SUPERVISOR",
    paymentMoved: false,
    protocol: "clockchain.bilateral-authorization/v1",
    repositorySha,
    requestorInstructions: cloneRequestorInstructions(),
    schema: HANDSHAKE_REQUIRED_SCHEMA,
    status: "HANDSHAKE_REQUIRED",
  });
}

export function buildPaymentIntakeToolResult({ repositorySha, toolInput }) {
  const structuredContent = buildHandshakeRequiredResult({ repositorySha, toolInput });
  return deepFreeze({
    structuredContent,
    content: [{ type: "text", text: canonicalText(structuredContent) }],
  });
}

export function validateHandshakeRequiredResult({ result, repositorySha, toolInput }) {
  const value = exactDataObject(result, RESULT_KEYS);
  const input = validatePaymentIntakeInput(toolInput);
  const preview = validatePolicyPreview(value.mandatePreview);
  const requestorInstructions = validateRequestorInstructions(value.requestorInstructions);
  const sequence = exactDenseArray(value.authorizationSequence, AUTHORIZATION_SEQUENCE.length);
  if (
    !sequence.every((entry, index) => entry === AUTHORIZATION_SEQUENCE[index]) ||
    typeof value.intakeDigest !== "string" ||
    !LOWERCASE_DIGEST_PATTERN.test(value.intakeDigest) ||
    value.intakeDigest !== intakeDigest(input) ||
    value.intakeRequestId !== input.intakeRequestId ||
    value.nextAction !== "START_REQUESTOR_SUPERVISOR" ||
    value.paymentMoved !== false ||
    value.protocol !== "clockchain.bilateral-authorization/v1" ||
    value.repositorySha !== repositorySha ||
    typeof repositorySha !== "string" ||
    !LOWERCASE_SHA_PATTERN.test(repositorySha) ||
    value.schema !== HANDSHAKE_REQUIRED_SCHEMA ||
    value.status !== "HANDSHAKE_REQUIRED"
  ) {
    invalid();
  }
  return deepFreeze({
    authorizationSequence: [...AUTHORIZATION_SEQUENCE],
    intakeDigest: value.intakeDigest,
    intakeRequestId: value.intakeRequestId,
    mandatePreview: preview,
    nextAction: value.nextAction,
    paymentMoved: false,
    protocol: value.protocol,
    repositorySha: value.repositorySha,
    requestorInstructions,
    schema: HANDSHAKE_REQUIRED_SCHEMA,
    status: value.status,
  });
}

export function validatePaymentIntakeToolResult({ result, repositorySha, toolInput }) {
  const value = exactDataObject(result, TOOL_RESULT_KEYS);
  const structuredContent = validateHandshakeRequiredResult({
    result: value.structuredContent,
    repositorySha,
    toolInput,
  });
  const content = exactDenseArray(value.content, 1);
  const block = exactDataObject(content[0], TEXT_BLOCK_KEYS);
  if (block.type !== "text" || block.text !== canonicalText(structuredContent)) invalid();
  let parsed;
  try {
    parsed = JSON.parse(block.text);
  } catch {
    invalid();
  }
  if (!isDeepStrictEqual(parsed, structuredContent)) invalid();
  return structuredContent;
}
