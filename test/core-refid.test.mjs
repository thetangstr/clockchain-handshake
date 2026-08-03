import assert from "node:assert/strict";
import test from "node:test";

import {
  PROBE_ROLES,
  REFID_PATTERN,
  ReferenceIdError,
  ReferenceIdFormatError,
  ReferenceIdMismatchError,
  SESSION_SLOTS,
  assertByteEqualReferenceId,
  assertReferenceId,
  probeKey,
  sessionKey,
} from "../src/core/refid.mjs";

const D_SESSION =
  "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
const NONCE = "0123456789abcdef0123456789abcdef";

test("REFID_PATTERN is exactly the spec charset", () => {
  assert.equal(REFID_PATTERN.source, "^[0-9a-z:]{1,120}$");
  assert.equal(REFID_PATTERN.flags, "");
});

test("slot and role allowlists are frozen and exact", () => {
  assert.deepEqual(SESSION_SLOTS, [
    "proposal",
    "acceptance",
    "acknowledgment",
  ]);
  assert.ok(Object.isFrozen(SESSION_SLOTS));
  assert.deepEqual(PROBE_ROLES, ["payer", "payee"]);
  assert.ok(Object.isFrozen(PROBE_ROLES));
});

test("assertReferenceId accepts only the charset and length bounds", () => {
  assert.equal(assertReferenceId("cbv1:probe:0"), undefined);
  assert.equal(assertReferenceId("a"), undefined);
  assert.equal(assertReferenceId("0".repeat(120)), undefined);

  for (const invalid of [
    "",
    "0".repeat(121),
    "CBV1:abc",
    "cbv1:abc ",
    " cbv1:abc",
    "cbv1:ab c",
    "cbv1:abc\n",
    "cbv1_abc",
    "cbv1:abc-def",
    "cbv1:abc.def",
    "cbv1:аbc", // Cyrillic а
    42,
    null,
    undefined,
  ]) {
    assert.throws(
      () => assertReferenceId(invalid),
      ReferenceIdFormatError,
      `expected rejection for ${JSON.stringify(invalid)}`,
    );
  }
});

test("sessionKey derives K(slot) = cbv1:D_session:slot", () => {
  assert.equal(
    sessionKey(D_SESSION, "proposal"),
    `cbv1:${D_SESSION}:proposal`,
  );
  assert.equal(
    sessionKey(D_SESSION, "acceptance"),
    `cbv1:${D_SESSION}:acceptance`,
  );
  assert.equal(
    sessionKey(D_SESSION, "acknowledgment"),
    `cbv1:${D_SESSION}:acknowledgment`,
  );
});

test("every session key satisfies the pattern and stays within 85 bytes", () => {
  for (const slot of SESSION_SLOTS) {
    const key = sessionKey(D_SESSION, slot);
    assert.match(key, REFID_PATTERN);
    assert.ok(Buffer.byteLength(key, "utf8") <= 85);
  }
  // Exact lengths pin the derivation against silent drift.
  assert.equal(sessionKey(D_SESSION, "proposal").length, 78);
  assert.equal(sessionKey(D_SESSION, "acceptance").length, 80);
  assert.equal(sessionKey(D_SESSION, "acknowledgment").length, 84);
});

test("sessionKey rejects any D_session that is not 64 lowercase hex", () => {
  for (const invalid of [
    D_SESSION.slice(0, 63),
    `${D_SESSION}a`,
    D_SESSION.toUpperCase(),
    D_SESSION.replace("a", "A"),
    D_SESSION.replace("a", "g"),
    D_SESSION.replace("a", ":"),
    ` ${D_SESSION.slice(1)}`,
    "",
    42,
    null,
    undefined,
  ]) {
    assert.throws(
      () => sessionKey(invalid, "proposal"),
      ReferenceIdFormatError,
      `expected rejection for ${JSON.stringify(invalid)}`,
    );
  }
});

test("uppercase hex is rejected at the session-digest gate itself", () => {
  // Pins the lowercase-only input gate directly. Without this, widening
  // D_SESSION_PATTERN to tolerate uppercase hex survives every other
  // test, masked by the downstream whole-key charset assert — the input
  // would still throw, but from the wrong gate with the generic message.
  for (const invalid of [D_SESSION.toUpperCase(), D_SESSION.replace("a", "A")]) {
    assert.throws(() => sessionKey(invalid, "proposal"), {
      name: "ReferenceIdFormatError",
      message: "Session digest must be exactly 64 lowercase hex characters.",
    });
  }
  assert.throws(() => probeKey(NONCE.toUpperCase(), "payer"), {
    name: "ReferenceIdFormatError",
    message: "Probe nonce must be exactly 32 lowercase hex characters.",
  });
});

test("sessionKey rejects any slot outside the allowlist", () => {
  for (const invalid of [
    "Proposal",
    "proposal ",
    "acknowledgement",
    "probe",
    "payer",
    "",
    42,
    null,
    undefined,
  ]) {
    assert.throws(
      () => sessionKey(D_SESSION, invalid),
      ReferenceIdFormatError,
      `expected rejection for ${JSON.stringify(invalid)}`,
    );
  }
});

test("probeKey derives cbv1:probe:nonce:role", () => {
  assert.equal(probeKey(NONCE, "payer"), `cbv1:probe:${NONCE}:payer`);
  assert.equal(probeKey(NONCE, "payee"), `cbv1:probe:${NONCE}:payee`);
  for (const role of PROBE_ROLES) {
    assert.match(probeKey(NONCE, role), REFID_PATTERN);
    assert.equal(probeKey(NONCE, role).length, 49);
  }
});

test("probeKey rejects any nonce that is not 32 lowercase hex", () => {
  for (const invalid of [
    NONCE.slice(0, 31),
    `${NONCE}0`,
    NONCE.toUpperCase(),
    NONCE.replace("a", "z"),
    NONCE.replace("a", ":"),
    "",
    42,
    null,
    undefined,
  ]) {
    assert.throws(
      () => probeKey(invalid, "payer"),
      ReferenceIdFormatError,
      `expected rejection for ${JSON.stringify(invalid)}`,
    );
  }
});

test("probeKey rejects any role outside the allowlist", () => {
  for (const invalid of [
    "Payer",
    "payer ",
    "proposal",
    "operator",
    "",
    42,
    null,
    undefined,
  ]) {
    assert.throws(
      () => probeKey(NONCE, invalid),
      ReferenceIdFormatError,
      `expected rejection for ${JSON.stringify(invalid)}`,
    );
  }
});

test("assertByteEqualReferenceId passes only on byte-identical valid ids", () => {
  const key = sessionKey(D_SESSION, "proposal");
  assert.equal(assertByteEqualReferenceId(key, key), undefined);
  assert.equal(
    assertByteEqualReferenceId(`cbv1:probe:${NONCE}:payer`, probeKey(NONCE, "payer")),
    undefined,
  );
});

test("assertByteEqualReferenceId rejects every mutation class", () => {
  const expected = sessionKey(D_SESSION, "proposal");
  const mutations = [
    // Case change.
    expected.replace("proposal", "Proposal"),
    expected.toUpperCase(),
    // Whitespace: embedded, leading, trailing space, trailing newline.
    expected.replace(":proposal", ": proposal"),
    ` ${expected}`,
    `${expected} `,
    `${expected}\n`,
    // Prefixing and suffixing.
    `x${expected}`,
    `${expected}x`,
    `cbv1:${expected}`,
    // Truncation.
    expected.slice(0, -1),
    expected.slice(1),
    expected.replace(":proposal", ""),
    // Unicode confusables: Cyrillic с (U+0441) and а (U+0430).
    expected.replace("cbv1", "сbv1"),
    expected.replace("a", "а"),
    // NFKC variants: fullwidth v (U+FF56) and superscript 1 (U+00B9)
    // normalize to "v" and "1" under NFKC but are NOT byte-equal.
    expected.replace("v", "ｖ"),
    expected.replace("1", "¹"),
    // Zero-width joiner injection.
    expected.replace(":", ":‍"),
    // Wrong slot entirely.
    sessionKey(D_SESSION, "acceptance"),
  ];

  for (const actual of mutations) {
    assert.notEqual(actual, expected);
    assert.throws(
      () => assertByteEqualReferenceId(actual, expected),
      ReferenceIdError,
      `expected rejection for ${JSON.stringify(actual)}`,
    );
  }

  // NFKC sanity: the confusable variants really do normalize back, which is
  // exactly why normalization must never happen before comparison.
  assert.equal(expected.replace("v", "ｖ").normalize("NFKC"), expected);
  assert.equal(expected.replace("1", "¹").normalize("NFKC"), expected);
});

test("charset-valid but unequal ids raise the mismatch error specifically", () => {
  const expected = sessionKey(D_SESSION, "proposal");
  for (const actual of [
    expected.slice(0, -1),
    sessionKey(D_SESSION, "acceptance"),
    `${expected}x`,
  ]) {
    assert.throws(
      () => assertByteEqualReferenceId(actual, expected),
      ReferenceIdMismatchError,
    );
  }
});

test("comparison is raw-byte-first: folding variants hit the mismatch path", () => {
  // These variants become equal to the expected id under NFKC
  // normalization or case folding. Pinning ReferenceIdMismatchError —
  // not merely some ReferenceIdError — proves the comparison runs on raw
  // bytes BEFORE any format check, so a normalize()/toLowerCase() slipped
  // in front of the equality test cannot survive.
  const expected = sessionKey(D_SESSION, "proposal");
  for (const actual of [
    expected.toUpperCase(),
    expected.replace("proposal", "PROPOSAL"),
    expected.replace("v", "ｖ"),
    expected.replace("1", "¹"),
    expected.replace("c", "с"), // Cyrillic с
  ]) {
    assert.notEqual(actual, expected);
    assert.throws(
      () => assertByteEqualReferenceId(actual, expected),
      ReferenceIdMismatchError,
      `expected raw-byte mismatch for ${JSON.stringify(actual)}`,
    );
  }
});

test("assertByteEqualReferenceId validates the expected id too", () => {
  assert.throws(
    () => assertByteEqualReferenceId("cbv1:abc", "CBV1:ABC"),
    ReferenceIdFormatError,
  );
  assert.throws(
    () => assertByteEqualReferenceId("cbv1:abc", 42),
    ReferenceIdFormatError,
  );
});

test("mismatch errors never echo reference-id bytes", () => {
  const expected = sessionKey(D_SESSION, "proposal");
  const error = (() => {
    try {
      assertByteEqualReferenceId(`${expected}x`, expected);
    } catch (thrown) {
      return thrown;
    }
    assert.fail("expected a mismatch error");
  })();

  assert.equal(error.name, "ReferenceIdMismatchError");
  assert.equal(error.code, "REFERENCE_ID_MISMATCH");
  assert.ok(!error.message.includes(D_SESSION));
});
