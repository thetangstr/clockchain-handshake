import { types } from "node:util";

import { canonicalBytes } from "../core/canonical.mjs";

// Relay message catalog for the v2 role shells. The relay is dumb:
// it validates envelope shape only. Authority lives in the signed
// artifacts carried inside message bodies (mandate, payment request,
// descriptor) and in chain reads; advisory bodies (identity-announce,
// party-ready, funding-confirmed) are always re-verified against the
// chain or a signed artifact by the consumer.

export const RELAY_KINDS = Object.freeze({
  IDENTITY_ANNOUNCE: "identity-announce",
  PARTY_READY: "party-ready",
  MANDATE_PUBLISHED: "mandate-published",
  PAYMENT_REQUEST: "payment-request",
  HANDSHAKE_REQUIRED: "handshake-required",
  PAYMENT_REQUEST_SIGNED: "payment-request-signed",
  DESCRIPTOR_PUBLISHED: "descriptor-published",
  FUNDING_CONFIRMED: "funding-confirmed",
});

export const RELAY_ROLES = Object.freeze([
  "operator",
  "payee",
  "payer",
]);

const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const DECIMAL_PATTERN = /^(0|[1-9][0-9]*)$/;

export class CatalogError extends Error {
  constructor(code) {
    super(`Relay catalog failure: ${code}`);
    this.name = "CatalogError";
    this.code = code;
  }
}

function invalid(code = "CATALOG_SHAPE") {
  throw new CatalogError(code);
}

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    !types.isProxy(value) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value))
  );
}

function exactBody(value, keys) {
  if (!isPlainObject(value)) invalid();
  const own = Object.keys(value);
  if (
    own.length !== keys.length ||
    keys.some((key) => !own.includes(key))
  ) {
    invalid();
  }
  return value;
}

export function validateAddressBody(body) {
  exactBody(body, ["address"]);
  if (
    typeof body.address !== "string" ||
    !ADDRESS_PATTERN.test(body.address)
  ) {
    invalid();
  }
  return Object.freeze({ address: body.address });
}

export function validatePartyReadyBody(body) {
  exactBody(body, ["address", "agentId"]);
  if (
    typeof body.address !== "string" ||
    !ADDRESS_PATTERN.test(body.address) ||
    typeof body.agentId !== "string" ||
    !DECIMAL_PATTERN.test(body.agentId) ||
    body.agentId.length > 16
  ) {
    invalid();
  }
  return Object.freeze({
    address: body.address,
    agentId: body.agentId,
  });
}

// Exactly one message of a kind from the expected role; a second,
// divergent copy fails closed as a duplicate.
export function exactlyOneFrom(messages, kind, role) {
  const matches = messages.filter(
    (message) =>
      isPlainObject(message) &&
      message.kind === kind &&
      message.role === role,
  );
  if (matches.length === 0) return null;
  const first = JSON.stringify(matches[0].body);
  for (const match of matches) {
    if (JSON.stringify(match.body) !== first) {
      invalid("DUPLICATE");
    }
  }
  return matches[0];
}

// Sender-side helper: monotonic per-role sequence numbers with
// restart adoption, and a body signature for transport coloring.
// Consumers never grant authority from the sig field.
export function createMessenger({
  relay,
  role,
  senderKey,
  sessionId,
  sign,
}) {
  if (
    !RELAY_ROLES.includes(role) ||
    typeof senderKey !== "string" ||
    senderKey.length === 0 ||
    typeof sessionId !== "string" ||
    typeof sign !== "function"
  ) {
    invalid("MESSENGER_INPUT");
  }
  let nextSeq = 0;
  return {
    adoptPrior(messages) {
      for (const message of messages) {
        if (
          isPlainObject(message) &&
          message.role === role &&
          Number.isSafeInteger(message.seq) &&
          message.seq >= nextSeq
        ) {
          nextSeq = message.seq + 1;
        }
      }
    },
    async send(kind, body) {
      const seq = nextSeq;
      const sig = await sign(
        canonicalBytes({
          body,
          kind,
          role,
          seq: String(seq),
          sessionId,
        }),
      );
      if (typeof sig !== "string" || sig.length > 256) {
        invalid("MESSENGER_SIG");
      }
      await relay.sendMessage({
        body,
        kind,
        role,
        senderKey,
        seq,
        sessionId,
        sig,
      });
      nextSeq = seq + 1;
    },
  };
}
