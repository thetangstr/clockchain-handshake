import { types } from "node:util";

import {
  canonicalizeReceiptEventValue,
} from "../../canonical.mjs";
import { canonicalBytes } from "../canonical.mjs";
import {
  SEALED_ENVELOPE_ALGORITHM,
  createSealedEnvelopeKeyPair,
  openEnvelope,
  sealEnvelope,
} from "./sealed-envelope.mjs";

export const REQUESTOR_BOOTSTRAP_ENVELOPE_ALGORITHM =
  SEALED_ENVELOPE_ALGORITHM;
export const REQUESTOR_BOOTSTRAP_ENVELOPE_SCHEMA =
  "clockchain.requestor-bootstrap-envelope/v1";

const CONTEXT_KEYS = Object.freeze([
  "claimNonce",
  "paymentMoved",
  "releaseId",
  "repositorySha",
  "sessionId",
]);
const UUID_V4_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const LOWERCASE_SHA_PATTERN = /^[0-9a-f]{40}$/;
const PRINTABLE_ASCII_PATTERN = /^[ -~]+$/;
const MIN_MANIFEST_BYTES = 1;
const MAX_MANIFEST_BYTES = 65_536;

export class RequestorBootstrapEnvelopeError extends Error {
  constructor() {
    super(
      "Requestor bootstrap envelope validation failed.",
    );
    this.name = "RequestorBootstrapEnvelopeError";
    this.category = "verification";
    this.code =
      "REQUESTOR_BOOTSTRAP_ENVELOPE_INVALID";
  }
}

function invalid() {
  throw new RequestorBootstrapEnvelopeError();
}

function sanitize(error) {
  if (
    error instanceof
    RequestorBootstrapEnvelopeError
  ) {
    throw error;
  }
  invalid();
}

function exactDataObject(value, keys) {
  try {
    if (
      value === null ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      types.isProxy(value)
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
      keys.some(
        (key, index) => ownKeys[index] !== key,
      )
    ) {
      invalid();
    }
    const result = Object.create(null);
    for (const key of keys) {
      const descriptor =
        Object.getOwnPropertyDescriptor(value, key);
      if (
        descriptor?.enumerable !== true ||
        !Object.hasOwn(descriptor, "value")
      ) {
        invalid();
      }
      result[key] = descriptor.value;
    }
    return result;
  } catch (error) {
    sanitize(error);
  }
}

function printable(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 256 &&
    value.trim() === value &&
    PRINTABLE_ASCII_PATTERN.test(value)
  );
}

function contextSnapshot(value) {
  const result = exactDataObject(
    value,
    CONTEXT_KEYS,
  );
  if (
    !UUID_V4_PATTERN.test(result.claimNonce) ||
    result.paymentMoved !== false ||
    !printable(result.releaseId) ||
    !LOWERCASE_SHA_PATTERN.test(
      result.repositorySha,
    ) ||
    !UUID_PATTERN.test(result.sessionId)
  ) {
    invalid();
  }
  return Object.freeze({
    claimNonce: result.claimNonce,
    paymentMoved: false,
    releaseId: result.releaseId,
    repositorySha: result.repositorySha,
    sessionId: result.sessionId,
  });
}

function manifestSnapshot(value) {
  if (
    !Buffer.isBuffer(value) ||
    value.length < MIN_MANIFEST_BYTES ||
    value.length > MAX_MANIFEST_BYTES
  ) {
    invalid();
  }
  let parsed;
  try {
    parsed = JSON.parse(value.toString("utf8"));
  } catch {
    invalid();
  }
  try {
    const stable = Buffer.from(
      JSON.stringify(
        canonicalizeReceiptEventValue(parsed),
      ),
      "utf8",
    );
    if (!stable.equals(value)) invalid();
  } catch {
    invalid();
  }
  return Buffer.from(value);
}

export function createRequestorBootstrapKey() {
  try {
    return createSealedEnvelopeKeyPair();
  } catch (error) {
    sanitize(error);
  }
}

export function sealRequestorBootstrapManifest(
  {
    context,
    manifestBytes,
    requestorPublicKey,
  },
  dependencies,
) {
  try {
    const aad = contextSnapshot(context);
    return sealEnvelope({
      aadBytes: canonicalBytes(aad),
      plaintextBytes:
        manifestSnapshot(manifestBytes),
      recipientPublicKey:
        requestorPublicKey,
      schema:
        REQUESTOR_BOOTSTRAP_ENVELOPE_SCHEMA,
    }, dependencies);
  } catch (error) {
    sanitize(error);
  }
}

export function openRequestorBootstrapEnvelope(
  {
    context,
    envelope,
    requestorPrivateKey,
  },
  dependencies,
) {
  try {
    const aad = contextSnapshot(context);
    const plaintext = openEnvelope({
      aadBytes: canonicalBytes(aad),
      envelope,
      expectedSchema:
        REQUESTOR_BOOTSTRAP_ENVELOPE_SCHEMA,
      recipientPrivateKey:
        requestorPrivateKey,
    }, dependencies);
    return manifestSnapshot(plaintext);
  } catch (error) {
    sanitize(error);
  }
}
