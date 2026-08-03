export const SENSITIVE_KEY =
  /private.?key|secret|token|authorization|invite.?code|ciphertext/i;

const REDACTED = "[REDACTED]";
const LABELED_PRIVATE_KEY =
  /(\b(?:private[\s_-]?key|priv[\s_-]?key|wallet[\s_-]?key)\b\s*(?:(?:is)\s+|[:=]\s*)?)(0x[0-9a-f]{64})(?![0-9a-f])/gi;
const LABELED_PRIVATE_KEY_DETECT =
  /\b(?:private[\s_-]?key|priv[\s_-]?key|wallet[\s_-]?key)\b\s*(?:(?:is)\s+|[:=]\s*)?0x[0-9a-f]{64}(?![0-9a-f])/i;
const BEARER_TOKEN =
  /(\bBearer[ \t]+)((?:(?:clockchain|cc|mcp)[_-][A-Za-z0-9._~+/-]{8,}|[A-Za-z0-9._~+/-]{24,})(?:={0,2}))(?![A-Za-z0-9._~+/-])/gi;
const BEARER_TOKEN_DETECT =
  /\bBearer[ \t]+(?:(?:clockchain|cc|mcp)[_-][A-Za-z0-9._~+/-]{8,}|[A-Za-z0-9._~+/-]{24,})(?:={0,2})(?![A-Za-z0-9._~+/-])/i;
const CLOCKCHAIN_TOKEN =
  /\bcc_[A-Za-z0-9_-][A-Za-z0-9._-]{19,}(?![A-Za-z0-9._-])/g;
const CLOCKCHAIN_TOKEN_DETECT =
  /\bcc_[A-Za-z0-9_-][A-Za-z0-9._-]{19,}(?![A-Za-z0-9._-])/;
// An email address is classified as secret material. What is established
// in-tree: the names clientId and walletId appear nowhere in src, bin or
// scripts, and src/run.mjs asserts only agentId, owner and agentURI on a
// resolveAgent response before discarding it, so nothing here reads such a
// field on purpose today. What is NOT established in-tree: that the hosted
// Clockchain read API returns those fields as literal email addresses. That
// is an external observation from live responses seen outside this
// repository, recorded here as the reason for the rule and not as a verified
// property of this codebase.
//
// The rule still earns its place from an in-tree path: assertResolvedIdentity
// returns the provider's whole response object, and a failed stage can carry
// that object into a diagnostic, so any address the provider chooses to
// include reaches redact() without a dedicated consumer existing. Landing the
// pattern before the bilateral protocol adds a deliberate consumer is
// cheaper than retrofitting it after.
const EMAIL_ADDRESS =
  /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,63}\b/g;
const EMAIL_ADDRESS_DETECT =
  /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,63}\b/;
const SECRET_ASSIGNMENT_LABEL =
  "(?:private.?key|secret|token|(?:invitation|invite).?code|ciphertext)";
// What gates a match is the 16-character floor on the [A-Za-z0-9+/_-] run: a
// shorter value never triggers, which is what keeps ordinary agent prose
// ("token: minted successfully") from failing a healthy run. The trailing
// dot-separated groups only EXTEND an already-triggered match, so that JWT
// payload and signature segments cannot survive redaction of the header.
// Because the class contains "/", "_" and "-", a filesystem path after a
// secret label still matches ("private key: /Users/o/.handshake/wallet.json"
// triggers on "Users" only once the run reaches 16 characters). That is
// narrower than an unbounded value class and fails closed, so it is accepted.
const HIGH_ENTROPY_SECRET_VALUE =
  "[A-Za-z0-9+/_-]{16,}(?:\\.[A-Za-z0-9+/_-]{10,})*={0,2}";
const HIGH_ENTROPY_SECRET_ASSIGNMENT_SOURCE =
  `(${SECRET_ASSIGNMENT_LABEL}\\s*["']?\\s*[:=]\\s*["']?)` +
  `(${HIGH_ENTROPY_SECRET_VALUE})`;
// The broad companion, for schema-generated documents only. result.json and
// RESULT.md are rendered from an exact-key allowlist, so a secret assignment
// of ANY length is illegitimate there and an unbounded value class costs no
// false positives. Free-form prose would trip this constantly, which is why
// the high-entropy rule above stays the one that applies everywhere. An
// already-redacted placeholder is exempt so a correctly sanitized document
// still passes.
const BROAD_SECRET_VALUE =
  "(?!\"?\\[REDACTED\\]\"?)[^\\s,;}]+";
const BROAD_SECRET_ASSIGNMENT_SOURCE =
  `(${SECRET_ASSIGNMENT_LABEL}\\s*["']?\\s*[:=]\\s*)` +
  `(${BROAD_SECRET_VALUE})`;

export class SecretMaterialDetectedError extends Error {
  constructor() {
    super("Secret material detected in value.");
    this.name = "SecretMaterialDetectedError";
    this.code = "SECRET_MATERIAL_DETECTED";
  }
}

export function highEntropySecretAssignmentPattern(
  flags = "i",
) {
  return new RegExp(
    HIGH_ENTROPY_SECRET_ASSIGNMENT_SOURCE,
    flags,
  );
}

export function broadSecretAssignmentPattern(flags = "i") {
  return new RegExp(BROAD_SECRET_ASSIGNMENT_SOURCE, flags);
}

function normalizeCanaries(canaries) {
  if (
    !Array.isArray(canaries) ||
    canaries.some(
      (canary) => typeof canary !== "string" || canary.length === 0,
    )
  ) {
    throw new TypeError("Canaries must be an array of nonempty strings.");
  }

  return [...new Set(canaries)].sort(
    (left, right) => right.length - left.length,
  );
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object") {
    return false;
  }

  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function redactString(value, canaries) {
  let redacted = value;

  for (const canary of canaries) {
    redacted = redacted.split(canary).join(REDACTED);
  }

  redacted = redacted.replace(
    LABELED_PRIVATE_KEY,
    (_match, prefix) => `${prefix}${REDACTED}`,
  );
  redacted = redacted.replace(
    BEARER_TOKEN,
    (_match, prefix) => `${prefix}${REDACTED}`,
  );
  redacted = redacted.replace(EMAIL_ADDRESS, REDACTED);
  return redacted.replace(CLOCKCHAIN_TOKEN, REDACTED);
}

function redactError(error, canaries, seen) {
  const result = {};
  seen.set(error, result);

  result.name = redactValue(error.name, canaries, seen);
  result.message = redactValue(error.message, canaries, seen);
  result.stack = redactValue(error.stack, canaries, seen);

  if (Object.hasOwn(error, "cause")) {
    result.cause = redactValue(error.cause, canaries, seen);
  }

  for (const [key, value] of Object.entries(error)) {
    if (key === "name" || key === "message" || key === "stack" || key === "cause") {
      continue;
    }

    result[key] = SENSITIVE_KEY.test(key)
      ? REDACTED
      : redactValue(value, canaries, seen);
  }

  return result;
}

function redactValue(value, canaries, seen) {
  if (typeof value === "string") {
    return redactString(value, canaries);
  }

  if (value instanceof Error) {
    if (seen.has(value)) {
      return seen.get(value);
    }

    return redactError(value, canaries, seen);
  }

  if (Array.isArray(value)) {
    if (seen.has(value)) {
      return seen.get(value);
    }

    const result = [];
    seen.set(value, result);

    for (const entry of value) {
      result.push(redactValue(entry, canaries, seen));
    }

    return result;
  }

  if (isPlainObject(value)) {
    if (seen.has(value)) {
      return seen.get(value);
    }

    const result = {};
    seen.set(value, result);

    for (const [key, entry] of Object.entries(value)) {
      result[key] = SENSITIVE_KEY.test(key)
        ? REDACTED
        : redactValue(entry, canaries, seen);
    }

    return result;
  }

  return value;
}

function stringContainsSecret(value, canaries) {
  return (
    canaries.some((canary) => value.includes(canary)) ||
    LABELED_PRIVATE_KEY_DETECT.test(value) ||
    BEARER_TOKEN_DETECT.test(value) ||
    EMAIL_ADDRESS_DETECT.test(value) ||
    CLOCKCHAIN_TOKEN_DETECT.test(value)
  );
}

function containsSecret(value, canaries, seen) {
  if (typeof value === "string") {
    return stringContainsSecret(value, canaries);
  }

  if (value === null || typeof value !== "object") {
    return false;
  }

  if (seen.has(value)) {
    return false;
  }
  seen.add(value);

  if (value instanceof Error) {
    if (
      containsSecret(value.name, canaries, seen) ||
      containsSecret(value.message, canaries, seen) ||
      containsSecret(value.stack, canaries, seen)
    ) {
      return true;
    }

    if (
      Object.hasOwn(value, "cause") &&
      containsSecret(value.cause, canaries, seen)
    ) {
      return true;
    }

    return Object.entries(value).some(([key, entry]) => {
      if (
        key === "name" ||
        key === "message" ||
        key === "stack" ||
        key === "cause"
      ) {
        return false;
      }

      return (
        (SENSITIVE_KEY.test(key) && entry !== REDACTED) ||
        containsSecret(entry, canaries, seen)
      );
    });
  }

  if (Array.isArray(value)) {
    return value.some((entry) => containsSecret(entry, canaries, seen));
  }

  if (isPlainObject(value)) {
    return Object.entries(value).some(
      ([key, entry]) =>
        (SENSITIVE_KEY.test(key) && entry !== REDACTED) ||
        containsSecret(entry, canaries, seen),
    );
  }

  return false;
}

export function redact(value, canaries = []) {
  return redactValue(value, normalizeCanaries(canaries), new WeakMap());
}

export function assertSecretFree(value, canaries = []) {
  if (containsSecret(value, normalizeCanaries(canaries), new WeakSet())) {
    throw new SecretMaterialDetectedError();
  }
}
