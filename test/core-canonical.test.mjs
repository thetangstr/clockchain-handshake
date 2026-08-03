import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  BilateralCanonicalError,
  canonicalBytes,
  digestHex,
  MAX_CANONICAL_DEPTH,
  MAX_CANONICAL_STRING_LENGTH,
} from "../src/core/canonical.mjs";

const SESSION_DIGEST = "ab".repeat(32);
const PAYER_ADDRESS = `0x${"11".repeat(20)}`;
const PAYEE_ADDRESS = `0x${"22".repeat(20)}`;
const REGISTRY = "0x8004a818bfb912233c491871b3d84c89a494bd9e";

function proposalMessage() {
  // Insertion order is deliberately unsorted at every level.
  return {
    sessionDigest: SESSION_DIGEST,
    sequence: "1",
    schema: "clockchain.bilateral-transition/v1",
    protocol: "clockchain.bilateral-authorization/v1",
    predecessor: null,
    payer: {
      reference: `eip155:11155111:${REGISTRY}:8677`,
      agentId: "8677",
      address: PAYER_ADDRESS,
    },
    payee: {
      agentId: "9001",
      address: PAYEE_ADDRESS,
    },
    kind: "proposal",
    expirySeconds: "600",
    amount: { value: "100", moved: false, currency: "USD" },
  };
}

function assertRejection(operation, code, canary) {
  assert.throws(operation, (error) => {
    assert.ok(error instanceof BilateralCanonicalError);
    assert.equal(error.name, "BilateralCanonicalError");
    assert.equal(error.code, code);
    if (canary !== undefined) {
      assert.equal(error.message.includes(canary), false);
      assert.equal(error.stack.includes(canary), false);
    }
    return true;
  });
}

test("pins the bilateral canonical constants", () => {
  assert.equal(MAX_CANONICAL_STRING_LENGTH, 256);
  assert.equal(MAX_CANONICAL_DEPTH, 32);
});

test("produces sorted-key canonical bytes independently derivable by hand", () => {
  // The expected bytes are written out by hand from the design section
  // 4.5 rules (sorted keys at every level, JSON.stringify, UTF-8), and
  // the digest is recomputed here with node:crypto, so this test does
  // not trust the implementation for either half of the claim.
  const expectedJson =
    "{\"amount\":{\"currency\":\"USD\",\"moved\":false,\"value\":\"100\"}," +
    "\"expirySeconds\":\"600\"," +
    "\"kind\":\"proposal\"," +
    `\"payee\":{\"address\":\"${PAYEE_ADDRESS}\",\"agentId\":\"9001\"},` +
    `\"payer\":{\"address\":\"${PAYER_ADDRESS}\",\"agentId\":\"8677\",` +
    `\"reference\":\"eip155:11155111:${REGISTRY}:8677\"},` +
    "\"predecessor\":null," +
    "\"protocol\":\"clockchain.bilateral-authorization/v1\"," +
    "\"schema\":\"clockchain.bilateral-transition/v1\"," +
    "\"sequence\":\"1\"," +
    `\"sessionDigest\":\"${SESSION_DIGEST}\"}`;

  const bytes = canonicalBytes(proposalMessage());
  assert.ok(Buffer.isBuffer(bytes));
  assert.equal(bytes.toString("utf8"), expectedJson);
  assert.equal(
    digestHex(proposalMessage()),
    createHash("sha256").update(expectedJson, "utf8").digest("hex"),
  );
  assert.match(digestHex(proposalMessage()), /^[0-9a-f]{64}$/);
});

test("digests every key-order permutation identically", () => {
  const reordered = {
    amount: { currency: "USD", value: "100", moved: false },
    payee: {
      address: PAYEE_ADDRESS,
      agentId: "9001",
    },
    payer: {
      address: PAYER_ADDRESS,
      agentId: "8677",
      reference: `eip155:11155111:${REGISTRY}:8677`,
    },
    kind: "proposal",
    predecessor: null,
    schema: "clockchain.bilateral-transition/v1",
    protocol: "clockchain.bilateral-authorization/v1",
    sessionDigest: SESSION_DIGEST,
    expirySeconds: "600",
    sequence: "1",
  };

  assert.equal(digestHex(reordered), digestHex(proposalMessage()));

  const permutations = [
    { b: "1", a: { y: false, x: null }, c: ["z", { n: "m" }] },
    { c: ["z", { n: "m" }], a: { x: null, y: false }, b: "1" },
    { a: { y: false, x: null }, c: ["z", { n: "m" }], b: "1" },
  ];
  const digests = new Set(
    permutations.map((value) => digestHex(value)),
  );
  assert.equal(digests.size, 1);
});

// Rule 1 — no numbers anywhere in a digest preimage. Every count and
// amount is a decimal string; this removes integer and float precision
// ambiguity between two machines.
test("rejects every number anywhere with a typed error", () => {
  const cases = [
    { sequence: 1 },
    { amount: { value: 100 } },
    { list: ["a", 0] },
    { nested: { deep: [{ n: Number.NaN }] } },
    { nested: { deep: [{ n: 0.1 }] } },
    { big: 10n },
    { negativeZero: -0 },
  ];

  for (const value of cases) {
    assertRejection(() => digestHex(value), "CANONICAL_NUMBER");
  }
});

// Rule 2 — the v1 integer-like key quirk becomes a hard error. Keys
// inserted b, "10", "2", a enumerate as "2", "10", "b", "a" in
// JavaScript, so any independent implementation that actually sorts
// computes different bytes. The bilateral profile refuses the input
// outright.
test("rejects the integer-like string keys that v1 silently accepts", () => {
  const quirky = { b: "1", 10: "2", 2: "3" };
  quirky.a = "4";
  assert.deepEqual(Reflect.ownKeys(quirky), ["2", "10", "b", "a"]);

  assertRejection(
    () => digestHex(quirky),
    "CANONICAL_INTEGER_LIKE_KEY",
  );
  assertRejection(
    () => digestHex({ wrapper: { 0: "zero" } }),
    "CANONICAL_INTEGER_LIKE_KEY",
  );
  assertRejection(
    // Beyond 2**32 - 2 JavaScript stops reordering, but the key class
    // stays banned so no implementation needs to know that boundary.
    () => digestHex({ 4294967295: "edge" }),
    "CANONICAL_INTEGER_LIKE_KEY",
  );
});

// Rule 3 — printable ASCII 0x20-0x7E only, at most 256 characters, no
// leading or trailing whitespace, applied to keys and string values.
test("rejects strings outside bounded printable ASCII", () => {
  const canary = "bilateral-string-canary";
  const valueCases = [
    { text: "café" },
    { text: "tab\tseparated" },
    { text: "line\nbreak" },
    { text: `nul\u0000${canary}` },
    { text: "del\u007f" },
    { text: " leading" },
    { text: "trailing " },
    { text: "a".repeat(MAX_CANONICAL_STRING_LENGTH + 1) },
  ];
  for (const value of valueCases) {
    assertRejection(() => digestHex(value), "CANONICAL_STRING", canary);
  }

  const keyCases = [
    { "café": "v" },
    { " leading": "v" },
    { "trailing ": "v" },
    { [`k\u0000ey`]: "v" },
    { ["x".repeat(MAX_CANONICAL_STRING_LENGTH + 1)]: "v" },
    { "": "v" },
  ];
  for (const value of keyCases) {
    assertRejection(() => digestHex(value), "CANONICAL_KEY");
  }

  // Boundary acceptance: maximal length, inner spaces, empty values.
  assert.match(
    digestHex({
      max: "a".repeat(MAX_CANONICAL_STRING_LENGTH),
      "inner space": "also fine",
      empty: "",
    }),
    /^[0-9a-f]{64}$/,
  );
});

// Rule 4 — addresses are lowercased with the 0x prefix inside every
// digest preimage. EIP-55 checksum casing never enters a preimage, so
// any 42-character 0x-hex string that is not all-lowercase is refused.
test("rejects checksum-cased addresses inside preimages", () => {
  const checksummed = "0x8004A818BFB912233c491871b3d84c89A494BD9e";
  assertRejection(
    () => digestHex({ registry: checksummed }),
    "CANONICAL_ADDRESS_CASE",
  );
  assertRejection(
    () => digestHex({ registry: `0X${"aa".repeat(20)}` }),
    "CANONICAL_ADDRESS_CASE",
  );

  assert.match(digestHex({ registry: REGISTRY }), /^[0-9a-f]{64}$/);
  // Longer or shorter hex strings are not address-shaped and keep
  // their case: digests and transaction hashes are validated by their
  // own schemas.
  assert.match(
    digestHex({ tx: `0x${"AB".repeat(32)}` }),
    /^[0-9a-f]{64}$/,
  );
});

// Decision, tested: the spec digests "the rebuilt null-prototype
// object", so the top level must be a plain object. Every specified
// preimage (descriptor, M1, M2, M3) is one.
test("rejects any non-object top level", () => {
  for (const value of ["text", true, null, ["x"], undefined]) {
    assertRejection(() => digestHex(value), "CANONICAL_TOP_LEVEL");
    assertRejection(() => canonicalBytes(value), "CANONICAL_TOP_LEVEL");
  }
});

test("rejects non-plain objects, hostile properties, and unsupported types", () => {
  const canary = "bilateral-hostile-canary";
  const accessor = {};
  Object.defineProperty(accessor, "leak", {
    enumerable: true,
    get() {
      throw new Error(canary);
    },
  });
  const nonEnumerable = {};
  Object.defineProperty(nonEnumerable, "hidden", {
    enumerable: false,
    value: canary,
  });
  const symbolKeyed = { [Symbol("hostile")]: canary };
  const sparse = ["a"];
  sparse[2] = "c";
  const decorated = ["a"];
  decorated.extra = canary;

  const cases = [
    [{ when: new Date(0) }, "CANONICAL_OBJECT"],
    [{ map: new Map([["k", canary]]) }, "CANONICAL_OBJECT"],
    [{ instance: new (class Hostile {})() }, "CANONICAL_OBJECT"],
    [accessor, "CANONICAL_KEY"],
    [nonEnumerable, "CANONICAL_KEY"],
    [symbolKeyed, "CANONICAL_KEY"],
    [{ sparse }, "CANONICAL_ARRAY"],
    [{ decorated }, "CANONICAL_ARRAY"],
    [{ missing: undefined }, "CANONICAL_VALUE"],
    [{ helper: () => canary }, "CANONICAL_VALUE"],
    [{ symbol: Symbol(canary) }, "CANONICAL_VALUE"],
  ];

  for (const [value, code] of cases) {
    assertRejection(() => digestHex(value), code, canary);
  }
});

test("rejects cycles and bounds nesting depth with typed errors", () => {
  const cyclic = { wrapper: {} };
  cyclic.wrapper.self = cyclic;
  assertRejection(() => digestHex(cyclic), "CANONICAL_CYCLE");

  const shared = { note: "shared" };
  assert.match(
    digestHex({ a: shared, b: shared }),
    /^[0-9a-f]{64}$/,
  );

  const nest = (depth) => {
    let value = { leaf: "v" };
    for (let level = 1; level < depth; level += 1) {
      value = { child: value };
    }
    return value;
  };
  assert.match(
    digestHex(nest(MAX_CANONICAL_DEPTH)),
    /^[0-9a-f]{64}$/,
  );
  assertRejection(
    () => digestHex(nest(MAX_CANONICAL_DEPTH + 1)),
    "CANONICAL_DEPTH",
  );
  // A pathological depth must fail with the same typed error, never a
  // stack overflow.
  assertRejection(() => digestHex(nest(10000)), "CANONICAL_DEPTH");
});

test("handles __proto__ and constructor keys without prototype pollution", () => {
  const hostile = { constructor: "own-constructor" };
  Object.defineProperty(hostile, "__proto__", {
    enumerable: true,
    value: "own-proto-data",
  });

  const bytes = canonicalBytes(hostile);
  assert.equal(
    bytes.toString("utf8"),
    "{\"__proto__\":\"own-proto-data\",\"constructor\":\"own-constructor\"}",
  );
  assert.notEqual(
    digestHex(hostile),
    digestHex({ constructor: "own-constructor" }),
  );
  assert.equal({}.ownProtoData, undefined);
  assert.equal(
    Object.prototype.hasOwnProperty.call(
      Object.prototype,
      "own-proto-data",
    ),
    false,
  );
  assert.equal(typeof {}.constructor, "function");
});

test("is deterministic across repeated calls", () => {
  const first = digestHex(proposalMessage());
  const second = digestHex(proposalMessage());
  assert.equal(first, second);
});
