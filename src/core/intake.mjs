import { createHash } from "node:crypto";

import { canonicalBytes } from "./canonical.mjs";

// Payment-intake validation for the v2 relay-carried request_payment
// exchange. Adapted port of the donor's local-mcp/payment-intake.mjs:
// the exact-shape validation, digest, and result construction are
// unchanged; the MCP tool descriptor and tool-result wrappers are
// dropped (spec: boring JSON over the relay, MCP adapter optional and
// post-live-run). The instruction text describes the v2 relay flow.

export const PAYMENT_INTAKE_SCHEMA =
  "clockchain.payer-mcp-payment-intake/v1";
export const HANDSHAKE_REQUIRED_SCHEMA =
  "clockchain.payer-mcp-handshake-required/v1";

function deepFreeze(value) {
  if (value && typeof value === "object") {
    for (const entry of Object.values(value)) {
      deepFreeze(entry);
    }
    Object.freeze(value);
  }
  return value;
}

export const DEMO_INTENT_POLICY = deepFreeze({
  amount: { currency: "USD", value: "100" },
  invoiceReferencePrefix: "invoice-",
  purpose: "Handshake demo",
});

const UUID_V4_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const LOWERCASE_SHA_PATTERN = /^[0-9a-f]{40}$/;
const LOWERCASE_DIGEST_PATTERN = /^[0-9a-f]{64}$/;
const PRINTABLE_ASCII_PATTERN = /^[ -~]*$/;
const INTAKE_KEYS = [
  "amount",
  "intakeRequestId",
  "invoiceReference",
  "paymentMoved",
  "purpose",
  "schema",
];
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
const REQUESTOR_INSTRUCTION_KEYS = [
  "orderedSteps",
  "requiredCommand",
  "safetyRules",
  "summary",
];
const AUTHORIZATION_SEQUENCE = Object.freeze([
  "PROPOSED",
  "ACCEPTED",
  "ACKNOWLEDGED",
]);
export const REQUESTOR_ORDERED_STEPS = Object.freeze([
  "Keep this checkout detached, clean, and at repositorySha before handling private material.",
  "Verify the signed discovery document from the discovery URL before any protocol step.",
  "Generate a fresh owner-private keypair, announce the address through the relay, and wait for confirmed funding.",
  "Register the ERC-8004 identity, signal party-ready, then answer the published mandate with this intake and a signed payment request.",
  "Stay attached until the three public anchors are visible: PROPOSED, ACCEPTED, ACKNOWLEDGED.",
]);
export const REQUESTOR_SAFETY_RULES = Object.freeze([
  "Do not act as Payer.",
  "Do not change payer terms.",
  "Do not fund addresses or move payment; paymentMoved must remain false.",
  "Do not print or share private keys, capabilities, tokens, launch manifests, or live evidence.",
  "Do not claim the final verdict; only the operator fresh aggregate verifier may report it.",
]);
export const REQUESTOR_REQUIRED_COMMAND =
  "node src/roles/requestor.mjs --discovery-url <signed-discovery-url> --state <absolute-private-requestor-state-root>";
export const REQUESTOR_SUMMARY =
  "The Payer requires Clockchain Handshake before this payment request can be evaluated.";
export const HANDSHAKE_NEXT_ACTION = "SIGN_PAYMENT_REQUEST";

function invalid() {
  throw new Error("Payer payment intake failed safely.");
}

function exactDataObject(value, keys) {
  try {
    if (
      value === null ||
      typeof value !== "object" ||
      Array.isArray(value)
    ) {
      invalid();
    }
    const prototype = Object.getPrototypeOf(value);
    if (
      prototype !== Object.prototype &&
      prototype !== null
    ) {
      invalid();
    }
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
      if (
        !descriptor?.enumerable ||
        !Object.hasOwn(descriptor, "value")
      ) {
        invalid();
      }
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
    const lengthDescriptor = Object.getOwnPropertyDescriptor(
      value,
      "length",
    );
    if (
      !lengthDescriptor ||
      !Object.hasOwn(lengthDescriptor, "value") ||
      lengthDescriptor.value !== length
    ) {
      invalid();
    }
    return Array.from({ length }, (_, index) => {
      const descriptor = Object.getOwnPropertyDescriptor(
        value,
        String(index),
      );
      if (
        !descriptor?.enumerable ||
        !Object.hasOwn(descriptor, "value")
      ) {
        invalid();
      }
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
  const preview = exactDataObject(value, [
    "amount",
    "invoiceReferencePrefix",
    "purpose",
  ]);
  const amount = exactDataObject(preview.amount, AMOUNT_KEYS);
  if (
    amount.currency !== DEMO_INTENT_POLICY.amount.currency ||
    amount.value !== DEMO_INTENT_POLICY.amount.value ||
    preview.invoiceReferencePrefix !==
      DEMO_INTENT_POLICY.invoiceReferencePrefix ||
    preview.purpose !== DEMO_INTENT_POLICY.purpose
  ) {
    invalid();
  }
  return clonePolicy();
}

function validateRequestorInstructions(value) {
  const instructions = exactDataObject(
    value,
    REQUESTOR_INSTRUCTION_KEYS,
  );
  const orderedSteps = exactDenseArray(
    instructions.orderedSteps,
    REQUESTOR_ORDERED_STEPS.length,
  );
  const safetyRules = exactDenseArray(
    instructions.safetyRules,
    REQUESTOR_SAFETY_RULES.length,
  );
  if (
    !orderedSteps.every(
      (entry, index) => entry === REQUESTOR_ORDERED_STEPS[index],
    ) ||
    instructions.requiredCommand !== REQUESTOR_REQUIRED_COMMAND ||
    !safetyRules.every(
      (entry, index) => entry === REQUESTOR_SAFETY_RULES[index],
    ) ||
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

export function buildIntakeInput(intakeRequestId) {
  return validatePaymentIntakeInput({
    amount: { ...DEMO_INTENT_POLICY.amount },
    intakeRequestId,
    invoiceReference: `${DEMO_INTENT_POLICY.invoiceReferencePrefix}001`,
    paymentMoved: false,
    purpose: DEMO_INTENT_POLICY.purpose,
    schema: PAYMENT_INTAKE_SCHEMA,
  });
}

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
    input.invoiceReference !==
      `${DEMO_INTENT_POLICY.invoiceReferencePrefix}001` ||
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

export function buildHandshakeRequiredResult({
  repositorySha,
  toolInput,
}) {
  if (
    typeof repositorySha !== "string" ||
    !LOWERCASE_SHA_PATTERN.test(repositorySha)
  ) {
    invalid();
  }
  const input = validatePaymentIntakeInput(toolInput);
  return deepFreeze({
    authorizationSequence: [...AUTHORIZATION_SEQUENCE],
    intakeDigest: intakeDigest(input),
    intakeRequestId: input.intakeRequestId,
    mandatePreview: clonePolicy(),
    nextAction: HANDSHAKE_NEXT_ACTION,
    paymentMoved: false,
    protocol: "clockchain.bilateral-authorization/v1",
    repositorySha,
    requestorInstructions: cloneRequestorInstructions(),
    schema: HANDSHAKE_REQUIRED_SCHEMA,
    status: "HANDSHAKE_REQUIRED",
  });
}

export function validateHandshakeRequiredResult({
  result,
  repositorySha,
  toolInput,
}) {
  const value = exactDataObject(result, RESULT_KEYS);
  const input = validatePaymentIntakeInput(toolInput);
  const preview = validatePolicyPreview(value.mandatePreview);
  const requestorInstructions = validateRequestorInstructions(
    value.requestorInstructions,
  );
  const sequence = exactDenseArray(
    value.authorizationSequence,
    AUTHORIZATION_SEQUENCE.length,
  );
  if (
    !sequence.every(
      (entry, index) => entry === AUTHORIZATION_SEQUENCE[index],
    ) ||
    typeof value.intakeDigest !== "string" ||
    !LOWERCASE_DIGEST_PATTERN.test(value.intakeDigest) ||
    value.intakeDigest !== intakeDigest(input) ||
    value.intakeRequestId !== input.intakeRequestId ||
    value.nextAction !== HANDSHAKE_NEXT_ACTION ||
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
