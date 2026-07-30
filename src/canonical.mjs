// Canonicalization core for clockchain.handshake-result/v1 receipt
// events, extracted verbatim from src/evidence.mjs (design section 4.5)
// so the bilateral profile in src/bilateral/canonical.mjs can layer on
// top of it instead of shipping a second implementation.
//
// BYTE-STABILITY CONTRACT: computeReceiptEventHash digests are pinned in
// test/evidence.test.mjs against live anchored evidence. Any behavioral
// change here breaks the deployed demo loudly. In particular the v1
// profile ACCEPTS integer-like string keys ("2", "10") even though
// JavaScript enumerates them in ascending numeric order ahead of the
// sorted string keys, silently violating the sorted-key invariant. That
// quirk is frozen for v1 (see test/canonical.test.mjs); the bilateral
// profile rejects such keys instead.

export class CanonicalizationError extends Error {
  constructor() {
    // Fixed message: rejected values are never echoed, because receipt
    // events can carry operator-provided text.
    super("Value is outside the canonical v1 domain.");
    this.name = new.target.name;
    this.category = "verification";
    this.code = "CANONICAL_VALUE_INVALID";
  }
}

export function isPlainObject(value) {
  if (value === null || typeof value !== "object") {
    return false;
  }

  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function canonicalize(value, ancestors) {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new CanonicalizationError();
    }
    return value;
  }
  if (typeof value !== "object" || ancestors.has(value)) {
    throw new CanonicalizationError();
  }

  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const keys = Reflect.ownKeys(value);
      if (
        keys.length !== value.length + 1 ||
        keys.some(
          (key) =>
            key !== "length" &&
            (typeof key !== "string" ||
              !/^(?:0|[1-9][0-9]*)$/.test(key) ||
              Number(key) >= value.length),
        )
      ) {
        throw new CanonicalizationError();
      }
      const result = [];
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(
          value,
          String(index),
        );
        if (
          !descriptor ||
          !descriptor.enumerable ||
          !Object.hasOwn(descriptor, "value")
        ) {
          throw new CanonicalizationError();
        }
        result.push(canonicalize(descriptor.value, ancestors));
      }
      return result;
    }

    if (!isPlainObject(value)) {
      throw new CanonicalizationError();
    }
    const entries = [];
    for (const key of Reflect.ownKeys(value)) {
      const descriptor = Object.getOwnPropertyDescriptor(
        value,
        key,
      );
      if (
        typeof key !== "string" ||
        !descriptor ||
        !descriptor.enumerable ||
        !Object.hasOwn(descriptor, "value")
      ) {
        throw new CanonicalizationError();
      }
      entries.push([key, descriptor.value]);
    }
    const result = Object.create(null);
    for (const [key, entryValue] of entries.sort(
      ([left], [right]) =>
        left === right ? 0 : left < right ? -1 : 1,
    )) {
      result[key] = canonicalize(entryValue, ancestors);
    }
    return result;
  } finally {
    ancestors.delete(value);
  }
}

export function canonicalizeReceiptEventValue(value) {
  return canonicalize(value, new Set());
}
