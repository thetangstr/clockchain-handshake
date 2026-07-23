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
    throw new Error("Secret material detected in value.");
  }
}
