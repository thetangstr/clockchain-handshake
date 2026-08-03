import assert from "node:assert/strict";
import test from "node:test";

import {
  CanonicalizationError,
  canonicalizeReceiptEventValue,
  isPlainObject,
} from "../src/core/canonical-v1.mjs";

function assertTypedRejection(operation, canary) {
  assert.throws(operation, (error) => {
    assert.ok(error instanceof CanonicalizationError);
    assert.equal(error.name, "CanonicalizationError");
    assert.equal(error.category, "verification");
    assert.equal(error.code, "CANONICAL_VALUE_INVALID");
    if (canary !== undefined) {
      assert.equal(error.message.includes(canary), false);
      assert.equal(error.stack.includes(canary), false);
    }
    return true;
  });
}

test("sorts object keys and rebuilds a null-prototype structure", () => {
  const canonical = canonicalizeReceiptEventValue({
    b: "1",
    a: { d: "2", c: "3" },
  });

  assert.equal(Object.getPrototypeOf(canonical), null);
  assert.equal(Object.getPrototypeOf(canonical.a), null);
  assert.equal(
    JSON.stringify(canonical),
    "{\"a\":{\"c\":\"3\",\"d\":\"2\"},\"b\":\"1\"}",
  );
});

test("canonicalizes key-order permutations to identical bytes", () => {
  const first = canonicalizeReceiptEventValue({
    a: "1",
    b: { x: true, y: null },
    c: ["z"],
  });
  const second = canonicalizeReceiptEventValue({
    c: ["z"],
    b: { y: null, x: true },
    a: "1",
  });

  assert.equal(JSON.stringify(first), JSON.stringify(second));
});

// FROZEN v1 QUIRK, documented on purpose. JavaScript enumerates
// integer-like string keys in ascending numeric order ahead of every
// other key, overriding the canonicalizer's sort: keys inserted in the
// order b, "10", "2", a enumerate as "2", "10", "b", "a". The v1
// canonicalizer ACCEPTS such keys, so the "keys are sorted" invariant is
// silently false for them. This is frozen because live anchored
// clockchain.handshake-result/v1 evidence digests depend on these exact
// bytes (see the pins in test/evidence.test.mjs). The bilateral profile
// in src/bilateral/canonical.mjs rejects such keys instead. Do not "fix"
// v1.
test("documents the frozen v1 integer-like key ordering quirk", () => {
  const quirky = { b: "1", 10: "2", 2: "3" };
  quirky.a = "4";

  assert.deepEqual(Reflect.ownKeys(quirky), ["2", "10", "b", "a"]);

  const canonical = canonicalizeReceiptEventValue(quirky);
  assert.deepEqual(
    Reflect.ownKeys(canonical),
    ["2", "10", "a", "b"],
  );
  assert.equal(
    JSON.stringify(canonical),
    "{\"2\":\"3\",\"10\":\"2\",\"a\":\"4\",\"b\":\"1\"}",
  );
});

test("keeps the v1 value domain: strings, booleans, null, finite numbers", () => {
  assert.equal(canonicalizeReceiptEventValue("text"), "text");
  assert.equal(canonicalizeReceiptEventValue(true), true);
  assert.equal(canonicalizeReceiptEventValue(null), null);
  assert.equal(canonicalizeReceiptEventValue(1234.5), 1234.5);
  assertTypedRejection(() =>
    canonicalizeReceiptEventValue(Number.NaN),
  );
  assertTypedRejection(() =>
    canonicalizeReceiptEventValue(Number.POSITIVE_INFINITY),
  );
});

test("permits repeated non-cyclic references but rejects cycles", () => {
  const shared = { note: "shared" };
  assert.equal(
    JSON.stringify(
      canonicalizeReceiptEventValue({ a: shared, b: shared }),
    ),
    "{\"a\":{\"note\":\"shared\"},\"b\":{\"note\":\"shared\"}}",
  );

  const cyclic = {};
  cyclic.self = cyclic;
  assertTypedRejection(() => canonicalizeReceiptEventValue(cyclic));
});

test("rejects values outside the v1 domain without echoing them", () => {
  const canary = "canonical-core-secret-canary";
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
    undefined,
    () => canary,
    Symbol(canary),
    10n,
    new Date("2026-07-24T00:00:00.000Z"),
    new Map([["k", canary]]),
    new (class Hostile {})(),
    accessor,
    nonEnumerable,
    symbolKeyed,
    sparse,
    decorated,
  ];

  for (const value of cases) {
    assertTypedRejection(
      () => canonicalizeReceiptEventValue(value),
      canary,
    );
  }
});

test("keeps an own enumerable __proto__ key without polluting prototypes", () => {
  const hostile = {};
  Object.defineProperty(hostile, "__proto__", {
    enumerable: true,
    value: "own-proto-data",
  });

  const canonical = canonicalizeReceiptEventValue(hostile);
  assert.equal(
    Object.getOwnPropertyDescriptor(canonical, "__proto__").value,
    "own-proto-data",
  );
  assert.equal(Object.getPrototypeOf(canonical), null);
  assert.equal(
    Object.prototype.hasOwnProperty.call({}, "own-proto-data"),
    false,
  );
  assert.equal({}.ownProtoData, undefined);
});

test("classifies plain objects exactly", () => {
  assert.equal(isPlainObject({}), true);
  assert.equal(isPlainObject(Object.create(null)), true);
  assert.equal(isPlainObject([]), false);
  assert.equal(isPlainObject(null), false);
  assert.equal(isPlainObject("text"), false);
  assert.equal(isPlainObject(new Date(0)), false);
  assert.equal(isPlainObject(new (class Hostile {})()), false);
});
