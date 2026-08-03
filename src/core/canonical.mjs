// Bilateral canonical-bytes profile for
// clockchain.bilateral-authorization/v1 (design section 4.5). The whole
// protocol rests on two machines computing the same 32 bytes, so this
// profile narrows the frozen v1 canonicalizer (src/canonical.mjs) with
// four hard rules, every one of them an error rather than a convention:
//
//   Rule 1  no numbers anywhere — amounts, heights, and sequences are
//           decimal strings; numbers and bigints are typed errors.
//   Rule 2  integer-like string keys are rejected. JavaScript enumerates
//           them in ascending numeric order ahead of sorted string keys,
//           so the v1 profile's sorted-key invariant is silently false
//           for them; here the input is refused outright.
//   Rule 3  strings (keys and values) are printable ASCII 0x20-0x7E, at
//           most 256 characters, with no leading or trailing whitespace.
//   Rule 4  addresses are lowercase with the 0x prefix: any 42-character
//           0x-hex string value that is not all-lowercase is refused, so
//           EIP-55 checksum casing can never enter a preimage.
//
// The digest is the lowercase hex SHA-256 of the UTF-8 bytes of
// JSON.stringify over the rebuilt null-prototype object; the top level
// must therefore be a plain object, as every specified preimage
// (descriptor, M1, M2, M3) is. Nesting depth is bounded so pathological
// input fails with a typed error instead of exhausting the stack.
// Rejected values are never echoed through error channels.

import { createHash } from "node:crypto";

import { isPlainObject } from "./canonical-v1.mjs";

export const MAX_CANONICAL_STRING_LENGTH = 256;
export const MAX_CANONICAL_DEPTH = 32;

const INTEGER_LIKE_KEY_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const PRINTABLE_ASCII_PATTERN = /^[ -~]*$/;
const ADDRESS_SHAPED_PATTERN = /^0[xX][0-9a-fA-F]{40}$/;

export class BilateralCanonicalError extends Error {
  constructor(message, code) {
    super(message);
    this.name = new.target.name;
    this.category = "verification";
    this.code = code;
  }
}

function invalid(message, code) {
  throw new BilateralCanonicalError(message, code);
}

function isBoundedPrintable(value) {
  return (
    PRINTABLE_ASCII_PATTERN.test(value) &&
    value.length <= MAX_CANONICAL_STRING_LENGTH &&
    value.trim() === value
  );
}

function validateKey(key) {
  if (key.length === 0 || !isBoundedPrintable(key)) {
    invalid(
      "Object keys must be non-empty trimmed printable ASCII strings.",
      "CANONICAL_KEY",
    );
  }
  if (INTEGER_LIKE_KEY_PATTERN.test(key)) {
    invalid(
      "Integer-like string keys are banned from bilateral digest preimages.",
      "CANONICAL_INTEGER_LIKE_KEY",
    );
  }
}

function validateStringValue(value) {
  if (!isBoundedPrintable(value)) {
    invalid(
      "String values must be trimmed printable ASCII of bounded length.",
      "CANONICAL_STRING",
    );
  }
  if (
    ADDRESS_SHAPED_PATTERN.test(value) &&
    value !== value.toLowerCase()
  ) {
    invalid(
      "Addresses inside digest preimages must be all-lowercase 0x hex.",
      "CANONICAL_ADDRESS_CASE",
    );
  }
}

function canonicalize(value, ancestors, depth) {
  if (value === null || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "string") {
    validateStringValue(value);
    return value;
  }
  if (typeof value === "number" || typeof value === "bigint") {
    invalid(
      "Numbers are banned from bilateral digest preimages; use decimal strings.",
      "CANONICAL_NUMBER",
    );
  }
  if (typeof value !== "object") {
    invalid(
      "Value type is outside the bilateral canonical domain.",
      "CANONICAL_VALUE",
    );
  }
  if (depth > MAX_CANONICAL_DEPTH) {
    invalid(
      "Nesting exceeds the bilateral canonical depth bound.",
      "CANONICAL_DEPTH",
    );
  }
  if (ancestors.has(value)) {
    invalid(
      "Cyclic references cannot be canonicalized.",
      "CANONICAL_CYCLE",
    );
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
              !INTEGER_LIKE_KEY_PATTERN.test(key) ||
              Number(key) >= value.length),
        )
      ) {
        invalid(
          "Arrays must be dense with index-only own keys.",
          "CANONICAL_ARRAY",
        );
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
          invalid(
            "Array elements must be enumerable data properties.",
            "CANONICAL_ARRAY",
          );
        }
        result.push(
          canonicalize(descriptor.value, ancestors, depth + 1),
        );
      }
      return result;
    }

    if (!isPlainObject(value)) {
      invalid(
        "Only plain objects may enter a bilateral digest preimage.",
        "CANONICAL_OBJECT",
      );
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
        invalid(
          "Object keys must be enumerable string data properties.",
          "CANONICAL_KEY",
        );
      }
      validateKey(key);
      entries.push([key, descriptor.value]);
    }
    const result = Object.create(null);
    for (const [key, entryValue] of entries.sort(
      ([left], [right]) =>
        left === right ? 0 : left < right ? -1 : 1,
    )) {
      result[key] = canonicalize(entryValue, ancestors, depth + 1);
    }
    return result;
  } finally {
    ancestors.delete(value);
  }
}

export function canonicalBytes(value) {
  if (!isPlainObject(value) || Array.isArray(value)) {
    invalid(
      "The top-level canonical value must be a plain object.",
      "CANONICAL_TOP_LEVEL",
    );
  }
  const canonical = canonicalize(value, new Set(), 1);
  return Buffer.from(JSON.stringify(canonical), "utf8");
}

export function digestHex(value) {
  return createHash("sha256")
    .update(canonicalBytes(value))
    .digest("hex");
}
