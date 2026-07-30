import assert from "node:assert/strict";
import test from "node:test";
import {
  createHash,
  generateKeyPairSync,
  sign,
  verify,
} from "node:crypto";

import { canonicalBytes } from "../src/bilateral/canonical.mjs";
import {
  COORDINATION_ENVELOPE_SCHEMA,
  COORDINATION_SIGNATURE_DOMAIN,
  CoordinationEnvelopeError,
  MAX_COORDINATION_ENVELOPE_BYTES,
  createCoordinationEnvelope,
  eventDigest,
  signaturePreimage,
  verifyCoordinationEnvelope,
} from "../src/bilateral/coordination/envelope.mjs";

const ENVELOPE_KEYS = Object.freeze([
  "artifactDigest",
  "eventDigest",
  "kind",
  "paymentMoved",
  "previousEventDigest",
  "releaseId",
  "repositorySha",
  "role",
  "schema",
  "sequence",
  "sessionId",
  "signature",
  "subjectRun",
]);
const SIGNATURE_KEYS = Object.freeze([
  "algorithm",
  "keyId",
  "publicKey",
  "value",
]);
const CREATE_KEYS = Object.freeze([
  "artifactDigest",
  "kind",
  "paymentMoved",
  "previousEventDigest",
  "privateKeyPem",
  "publicKey",
  "publicKeyId",
  "releaseId",
  "repositorySha",
  "role",
  "schema",
  "sequence",
  "sessionId",
  "subjectRun",
]);
const EXPECTED_REQUIRED_KEYS = Object.freeze([
  "expectedPublicKey",
  "expectedReleaseId",
  "expectedRepositorySha",
  "expectedRole",
  "expectedSessionId",
]);

function keyFixture(keyId) {
  const { privateKey, publicKey } =
    generateKeyPairSync("ed25519");
  return Object.freeze({
    keyId,
    privateKey,
    privateKeyPem: privateKey.export({
      format: "pem",
      type: "pkcs8",
    }),
    publicKey,
    publicKeyRaw: publicKey
      .export({ format: "der", type: "spki" })
      .subarray(-32)
      .toString("base64"),
  });
}

const PAYER = keyFixture("payer-release-key");
const IMPOSTOR = keyFixture("impostor-release-key");
const ARTIFACT_DIGEST =
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const PREVIOUS_DIGEST =
  "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
const RELEASE_ID = "release-2026-07-26-a";
const REPOSITORY_SHA =
  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SESSION_ID = "8f953393-86d0-4f99-9d6a-102f525fbecd";
const BASE64_PATTERN =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const BASE64_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function validInput(overrides = {}) {
  return {
    artifactDigest: null,
    kind: "ENROLLMENT_CONFIRMED",
    paymentMoved: false,
    previousEventDigest: null,
    privateKeyPem: PAYER.privateKeyPem,
    publicKey: PAYER.publicKeyRaw,
    publicKeyId: PAYER.keyId,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    role: "payer",
    schema: COORDINATION_ENVELOPE_SCHEMA,
    sequence: "0",
    sessionId: SESSION_ID,
    subjectRun: "release",
    ...overrides,
  };
}

function expectedContext(overrides = {}) {
  return {
    expectedPublicKey: PAYER.publicKeyRaw,
    expectedReleaseId: RELEASE_ID,
    expectedRepositorySha: REPOSITORY_SHA,
    expectedRole: "payer",
    expectedSessionId: SESSION_ID,
    ...overrides,
  };
}

function create(overrides = {}) {
  return createCoordinationEnvelope(validInput(overrides));
}

function reversedObject(value) {
  return Object.fromEntries(Object.entries(value).reverse());
}

function noncanonicalPadBitAlias(value) {
  const firstPadding = value.indexOf("=");
  assert.notEqual(firstPadding, -1);
  const aliasedIndex = firstPadding - 1;
  const alphabetIndex = BASE64_ALPHABET.indexOf(
    value[aliasedIndex],
  );
  assert.notEqual(alphabetIndex, -1);
  return (
    value.slice(0, aliasedIndex) +
    BASE64_ALPHABET[alphabetIndex + 1] +
    value.slice(aliasedIndex + 1)
  );
}

function signedClone(
  envelope,
  {
    key = PAYER,
    preimage = signaturePreimage(eventDigest(envelope)),
    publicKey = key.publicKeyRaw,
  } = {},
) {
  const clone = structuredClone(envelope);
  clone.eventDigest = eventDigest(clone);
  clone.signature.publicKey = publicKey;
  clone.signature.value = sign(
    null,
    preimage,
    key.privateKey,
  ).toString("base64");
  return clone;
}

function assertCoordinationError(action) {
  assert.throws(action, (error) => {
    assert.ok(
      error instanceof CoordinationEnvelopeError,
      `expected CoordinationEnvelopeError, got ${error?.name}`,
    );
    assert.equal(error.code, "COORDINATION_ENVELOPE_INVALID");
    assert.equal(
      error.message,
      "Coordination envelope validation failed.",
    );
    return true;
  });
}

test("pins the coordination schema, signature domain, and size limit", () => {
  assert.equal(
    COORDINATION_ENVELOPE_SCHEMA,
    "clockchain.bilateral-coordination-event/v1",
  );
  assert.equal(
    COORDINATION_SIGNATURE_DOMAIN,
    "clockchain.bilateral-coordination-signature/v1\n",
  );
  assert.equal(MAX_COORDINATION_ENVELOPE_BYTES, 65_536);
});

test("creates a deterministic canonical signed coordination envelope", () => {
  const first = create();
  const second = create();

  assert.deepEqual(first, second);
  assert.deepEqual(Object.keys(first), ENVELOPE_KEYS);
  assert.deepEqual(Object.keys(first.signature), SIGNATURE_KEYS);
  assert.equal(first.schema, COORDINATION_ENVELOPE_SCHEMA);
  assert.equal(first.paymentMoved, false);
  assert.equal(first.eventDigest, eventDigest(first));
  assert.equal(first.signature.algorithm, "ed25519");
  assert.equal(first.signature.keyId, PAYER.keyId);
  assert.equal(first.signature.publicKey, PAYER.publicKeyRaw);
  assert.equal(
    Buffer.from(first.signature.value, "base64").length,
    64,
  );
  assert.equal(
    verify(
      null,
      signaturePreimage(first.eventDigest),
      PAYER.publicKey,
      Buffer.from(first.signature.value, "base64"),
    ),
    true,
  );
  assert.deepEqual(
    verifyCoordinationEnvelope(first, expectedContext()),
    first,
  );
});

test("creation requires the caller-supplied canonical schema", () => {
  const envelope = create({
    schema: COORDINATION_ENVELOPE_SCHEMA,
  });
  assert.equal(envelope.schema, COORDINATION_ENVELOPE_SCHEMA);
  assert.deepEqual(
    verifyCoordinationEnvelope(envelope, expectedContext()),
    envelope,
  );
});

test("creation rejects missing, wrong, or additional schema properties", () => {
  const missing = validInput();
  delete missing.schema;
  assertCoordinationError(() =>
    createCoordinationEnvelope(missing),
  );

  assertCoordinationError(() =>
    create({
      schema: "clockchain.bilateral-coordination-event/v2",
    }),
  );
  assertCoordinationError(() =>
    createCoordinationEnvelope({
      ...validInput(),
      schemaVersion: "1",
    }),
  );
});

test("eventDigest hashes only the canonical unsigned event body", () => {
  const envelope = create({
    artifactDigest: ARTIFACT_DIGEST,
    previousEventDigest: PREVIOUS_DIGEST,
  });
  const body = {
    artifactDigest: ARTIFACT_DIGEST,
    kind: "ENROLLMENT_CONFIRMED",
    paymentMoved: false,
    previousEventDigest: PREVIOUS_DIGEST,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    role: "payer",
    schema: COORDINATION_ENVELOPE_SCHEMA,
    sequence: "0",
    sessionId: SESSION_ID,
    subjectRun: "release",
  };
  const expected = createHash("sha256")
    .update(canonicalBytes(body))
    .digest("hex");
  assert.equal(envelope.eventDigest, expected);

  const changedCircularFields = structuredClone(envelope);
  changedCircularFields.eventDigest = "f".repeat(64);
  changedCircularFields.signature.value =
    Buffer.alloc(64, 0xa5).toString("base64");
  assert.equal(eventDigest(changedCircularFields), expected);
});

test("signaturePreimage is the ASCII domain followed by the ASCII digest", () => {
  const digest = "a".repeat(64);
  assert.deepEqual(
    signaturePreimage(digest),
    Buffer.from(`${COORDINATION_SIGNATURE_DOMAIN}${digest}`, "ascii"),
  );
  for (const invalid of [
    null,
    42,
    "",
    "a".repeat(63),
    "a".repeat(65),
    "A".repeat(64),
    `${"a".repeat(63)}g`,
  ]) {
    assertCoordinationError(() => signaturePreimage(invalid));
  }
});

test("creation and verification are independent of input key order", () => {
  const input = reversedObject(validInput());
  const envelope = createCoordinationEnvelope(input);
  const shuffledEnvelope = reversedObject(envelope);
  shuffledEnvelope.signature = reversedObject(envelope.signature);

  assert.deepEqual(envelope, create());
  const verified = verifyCoordinationEnvelope(
    shuffledEnvelope,
    reversedObject(expectedContext()),
  );
  assert.deepEqual(verified, envelope);
  assert.deepEqual(Object.keys(verified), ENVELOPE_KEYS);
  assert.deepEqual(Object.keys(verified.signature), SIGNATURE_KEYS);
});

test("creation rejects every missing or extra own key", () => {
  for (const key of CREATE_KEYS) {
    const input = validInput();
    delete input[key];
    assertCoordinationError(() =>
      createCoordinationEnvelope(input),
    );
  }
  assertCoordinationError(() =>
    createCoordinationEnvelope({
      ...validInput(),
      extra: "not-allowed",
    }),
  );
  for (const invalid of [
    null,
    undefined,
    [],
    "input",
    42,
    true,
  ]) {
    assertCoordinationError(() =>
      createCoordinationEnvelope(invalid),
    );
  }
});

test("verification rejects every missing or extra envelope/signature key", () => {
  const good = create();
  for (const key of ENVELOPE_KEYS) {
    const envelope = structuredClone(good);
    delete envelope[key];
    assertCoordinationError(() =>
      verifyCoordinationEnvelope(envelope, expectedContext()),
    );
  }
  for (const key of SIGNATURE_KEYS) {
    const envelope = structuredClone(good);
    delete envelope.signature[key];
    assertCoordinationError(() =>
      verifyCoordinationEnvelope(envelope, expectedContext()),
    );
  }
  for (const mutate of [
    (envelope) => {
      envelope.extra = "not-allowed";
    },
    (envelope) => {
      envelope.signature.extra = "not-allowed";
    },
  ]) {
    const envelope = structuredClone(good);
    mutate(envelope);
    assertCoordinationError(() =>
      verifyCoordinationEnvelope(envelope, expectedContext()),
    );
  }
});

test("all role and subject-run enum values are accepted", () => {
  for (const role of ["operator", "payer", "payee"]) {
    for (const subjectRun of [
      "release",
      "rehearsal",
      "stakeholder",
    ]) {
      const envelope = create({ role, subjectRun });
      assert.deepEqual(
        verifyCoordinationEnvelope(
          envelope,
          expectedContext({
            expectedRole: role,
            expectedSubjectRun: subjectRun,
          }),
        ),
        envelope,
      );
    }
  }
});

test("kind accepts canonical uppercase identifiers without owning the lifecycle allowlist", () => {
  for (const kind of [
    "A",
    "ENROLLMENT_CONFIRMED",
    "FUTURE_TASK_2_KIND",
    "A1_B2",
  ]) {
    assert.equal(create({ kind }).kind, kind);
  }
  for (const kind of [
    "",
    "enrollment_confirmed",
    "EnrollmentConfirmed",
    "_LEADING",
    "TRAILING_",
    "DOUBLE__SEPARATOR",
    "HAS-DASH",
    "HAS SPACE",
    "ÉVENT",
    42,
  ]) {
    assertCoordinationError(() => create({ kind }));
  }
});

test("invalid enum values and paymentMoved values fail closed", () => {
  for (const role of [
    "",
    "PAYER",
    "payer ",
    "verifier",
    null,
  ]) {
    assertCoordinationError(() => create({ role }));
  }
  for (const subjectRun of [
    "",
    "Release",
    "stake-holder",
    "other",
    null,
  ]) {
    assertCoordinationError(() => create({ subjectRun }));
  }
  for (const paymentMoved of [
    true,
    "false",
    0,
    null,
    undefined,
  ]) {
    assertCoordinationError(() => create({ paymentMoved }));
  }
});

test("sequence is a canonical bounded nonnegative decimal string", () => {
  for (const sequence of ["0", "1", "9", "10", "9".repeat(256)]) {
    assert.equal(create({ sequence }).sequence, sequence);
  }
  for (const sequence of [
    "",
    "00",
    "01",
    "-1",
    "+1",
    "1.0",
    "1e3",
    " 1",
    "1 ",
    "9".repeat(257),
    0,
    1,
    1n,
    null,
  ]) {
    assertCoordinationError(() => create({ sequence }));
  }
});

test("digest fields enforce lowercase SHA-256 or their documented null boundary", () => {
  for (const field of [
    "artifactDigest",
    "previousEventDigest",
  ]) {
    assert.equal(create({ [field]: null })[field], null);
    assert.equal(
      create({ [field]: ARTIFACT_DIGEST })[field],
      ARTIFACT_DIGEST,
    );
    for (const value of [
      "",
      "a".repeat(63),
      "a".repeat(65),
      "A".repeat(64),
      `${"a".repeat(63)}g`,
      42,
      false,
      undefined,
    ]) {
      assertCoordinationError(() => create({ [field]: value }));
    }
  }

  const envelope = structuredClone(create());
  envelope.eventDigest = null;
  assertCoordinationError(() =>
    verifyCoordinationEnvelope(envelope, expectedContext()),
  );
});

test("repository SHA, UUID, release ID, key ID, and public key encodings are strict", () => {
  const invalidCases = [
    ["repositorySha", "a".repeat(39)],
    ["repositorySha", "a".repeat(41)],
    ["repositorySha", "A".repeat(40)],
    ["sessionId", SESSION_ID.toUpperCase()],
    ["sessionId", SESSION_ID.replaceAll("-", "")],
    ["sessionId", "8f953393-86d0-0f99-9d6a-102f525fbecd"],
    ["sessionId", "8f953393-86d0-4f99-7d6a-102f525fbecd"],
    ["releaseId", ""],
    ["releaseId", " release-a"],
    ["releaseId", "release-a "],
    ["releaseId", "release-\nsecret"],
    ["releaseId", 42],
    ["publicKeyId", ""],
    ["publicKeyId", "UPPER"],
    ["publicKeyId", "-leading"],
    ["publicKeyId", "under_score"],
    ["publicKeyId", "x".repeat(65)],
    ["publicKey", `${PAYER.publicKeyRaw}\n`],
    ["publicKey", PAYER.publicKeyRaw.slice(0, -1)],
    ["publicKey", 42],
  ];
  for (const [field, value] of invalidCases) {
    assertCoordinationError(() => create({ [field]: value }));
  }
});

test("creation requires the supplied public key to match the private key", () => {
  assertCoordinationError(() =>
    create({
      publicKey: IMPOSTOR.publicKeyRaw,
    }),
  );
  assertCoordinationError(() =>
    create({
      privateKeyPem: IMPOSTOR.privateKeyPem,
    }),
  );
  assertCoordinationError(() =>
    create({
      privateKeyPem: "not a private key",
    }),
  );
  const { privateKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });
  assertCoordinationError(() =>
    create({
      privateKeyPem: privateKey.export({
        format: "pem",
        type: "pkcs8",
      }),
    }),
  );
});

test("creation accepts only byte-exact canonical Ed25519 PKCS#8 PEM", () => {
  assert.deepEqual(create().signature.publicKey, PAYER.publicKeyRaw);

  const noncanonicalPemValues = [
    `${PAYER.privateKeyPem}\n`,
    `${PAYER.privateKeyPem} `,
    `${PAYER.privateKeyPem}trailing-junk`,
    `${PAYER.privateKeyPem}${IMPOSTOR.privateKeyPem}`,
    PAYER.privateKeyPem.replaceAll("\n", "\r\n"),
  ];
  for (const privateKeyPem of noncanonicalPemValues) {
    assertCoordinationError(() =>
      create({
        privateKeyPem,
        publicKey: PAYER.publicKeyRaw,
      }),
    );
  }

  assertCoordinationError(() =>
    create({
      privateKeyPem: PAYER.privateKeyPem.padEnd(8_192, " "),
      publicKey: PAYER.publicKeyRaw,
    }),
  );
});

test("verification rejects wrong digest, signature, signing key, and domain", () => {
  const good = create();

  const wrongDigest = structuredClone(good);
  wrongDigest.eventDigest = "f".repeat(64);
  assertCoordinationError(() =>
    verifyCoordinationEnvelope(wrongDigest, expectedContext()),
  );

  const wrongSignature = structuredClone(good);
  const signatureBytes = Buffer.from(
    wrongSignature.signature.value,
    "base64",
  );
  signatureBytes[0] ^= 0xff;
  wrongSignature.signature.value =
    signatureBytes.toString("base64");
  assertCoordinationError(() =>
    verifyCoordinationEnvelope(wrongSignature, expectedContext()),
  );

  const wrongSigningKey = signedClone(good, {
    key: IMPOSTOR,
    publicKey: PAYER.publicKeyRaw,
  });
  assertCoordinationError(() =>
    verifyCoordinationEnvelope(wrongSigningKey, expectedContext()),
  );

  const wrongDomain = signedClone(good, {
    preimage: Buffer.from(
      `clockchain.wrong-domain/v1\n${good.eventDigest}`,
      "ascii",
    ),
  });
  assertCoordinationError(() =>
    verifyCoordinationEnvelope(wrongDomain, expectedContext()),
  );

  const differentDigestSignature = signedClone(good, {
    preimage: signaturePreimage("b".repeat(64)),
  });
  assertCoordinationError(() =>
    verifyCoordinationEnvelope(
      differentDigestSignature,
      expectedContext(),
    ),
  );
});

test("signature and public-key base64 encodings must be byte-canonical", () => {
  const good = create();
  const signatureValues = [
    "",
    "not base64!",
    Buffer.alloc(63).toString("base64"),
    Buffer.alloc(65).toString("base64"),
    Buffer.alloc(64).toString("base64").replace(/=$/u, ""),
    42,
    null,
  ];
  for (const value of signatureValues) {
    const envelope = structuredClone(good);
    envelope.signature.value = value;
    assertCoordinationError(() =>
      verifyCoordinationEnvelope(envelope, expectedContext()),
    );
  }

  for (const algorithm of ["Ed25519", "rsa", "", null]) {
    const envelope = structuredClone(good);
    envelope.signature.algorithm = algorithm;
    assertCoordinationError(() =>
      verifyCoordinationEnvelope(envelope, expectedContext()),
    );
  }
});

test("regex-valid same-length base64 pad-bit aliases are rejected", () => {
  const publicKeyAlias = noncanonicalPadBitAlias(
    PAYER.publicKeyRaw,
  );
  assert.equal(publicKeyAlias.length, PAYER.publicKeyRaw.length);
  assert.match(publicKeyAlias, BASE64_PATTERN);
  assert.notEqual(publicKeyAlias, PAYER.publicKeyRaw);
  assert.deepEqual(
    Buffer.from(publicKeyAlias, "base64"),
    Buffer.from(PAYER.publicKeyRaw, "base64"),
  );
  assertCoordinationError(() =>
    create({ publicKey: publicKeyAlias }),
  );

  const envelope = structuredClone(create());
  const signatureAlias = noncanonicalPadBitAlias(
    envelope.signature.value,
  );
  assert.equal(
    signatureAlias.length,
    envelope.signature.value.length,
  );
  assert.match(signatureAlias, BASE64_PATTERN);
  assert.notEqual(signatureAlias, envelope.signature.value);
  assert.deepEqual(
    Buffer.from(signatureAlias, "base64"),
    Buffer.from(envelope.signature.value, "base64"),
  );
  envelope.signature.value = signatureAlias;
  assertCoordinationError(() =>
    verifyCoordinationEnvelope(envelope, expectedContext()),
  );
});

test("verification requires an exact, closed expected context", () => {
  const good = create();
  const contextCases = [
    { expectedPublicKey: IMPOSTOR.publicKeyRaw },
    { expectedReleaseId: "release-2026-07-26-b" },
    { expectedRepositorySha: "b".repeat(40) },
    { expectedRole: "payee" },
    {
      expectedSessionId:
        "9f953393-86d0-4f99-9d6a-102f525fbecd",
    },
    { expectedSubjectRun: "rehearsal" },
  ];
  for (const overrides of contextCases) {
    assertCoordinationError(() =>
      verifyCoordinationEnvelope(
        good,
        expectedContext(overrides),
      ),
    );
  }

  for (const key of EXPECTED_REQUIRED_KEYS) {
    const expected = expectedContext();
    delete expected[key];
    assertCoordinationError(() =>
      verifyCoordinationEnvelope(good, expected),
    );
  }
  assertCoordinationError(() =>
    verifyCoordinationEnvelope(good, {
      ...expectedContext(),
      unexpected: "not-allowed",
    }),
  );
  assertCoordinationError(() =>
    verifyCoordinationEnvelope(good, {
      ...expectedContext(),
      expectedRole: 1,
    }),
  );
});

test("creation and verification never invoke input getters", () => {
  let gets = 0;
  const input = new Proxy(validInput(), {
    get() {
      gets += 1;
      throw new Error("input [[Get]] must be unreachable");
    },
  });
  const envelope = createCoordinationEnvelope(input);
  assert.equal(gets, 0);

  const proxiedEnvelope = new Proxy(envelope, {
    get() {
      gets += 1;
      throw new Error("envelope [[Get]] must be unreachable");
    },
  });
  const expected = new Proxy(expectedContext(), {
    get() {
      gets += 1;
      throw new Error("expected [[Get]] must be unreachable");
    },
  });
  assert.deepEqual(
    verifyCoordinationEnvelope(proxiedEnvelope, expected),
    envelope,
  );
  assert.equal(gets, 0);
});

test("snapshotting never exposes private PEM through inherited setters", () => {
  const previous = Object.getOwnPropertyDescriptor(
    Object.prototype,
    "privateKeyPem",
  );
  let setterCalls = 0;
  let envelope;
  Object.defineProperty(Object.prototype, "privateKeyPem", {
    configurable: true,
    set() {
      setterCalls += 1;
    },
  });
  try {
    envelope = create();
  } finally {
    if (previous === undefined) {
      delete Object.prototype.privateKeyPem;
    } else {
      Object.defineProperty(
        Object.prototype,
        "privateKeyPem",
        previous,
      );
    }
  }

  assert.equal(setterCalls, 0);
  assert.equal(envelope.signature.publicKey, PAYER.publicKeyRaw);
});

test("accessors, custom prototypes, and get-vs-descriptor divergence are rejected", () => {
  let getterCalls = 0;
  const accessorInput = validInput();
  Object.defineProperty(accessorInput, "releaseId", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return RELEASE_ID;
    },
  });
  assertCoordinationError(() =>
    createCoordinationEnvelope(accessorInput),
  );
  assert.equal(getterCalls, 0);

  const customPrototypeInput = Object.assign(
    Object.create({ inherited: "value" }),
    validInput(),
  );
  assertCoordinationError(() =>
    createCoordinationEnvelope(customPrototypeInput),
  );

  const target = validInput({ paymentMoved: true });
  const divergent = new Proxy(target, {
    get(object, key, receiver) {
      if (key === "paymentMoved") {
        return false;
      }
      return Reflect.get(object, key, receiver);
    },
  });
  assertCoordinationError(() =>
    createCoordinationEnvelope(divergent),
  );

  const envelope = structuredClone(create());
  Object.defineProperty(envelope.signature, "value", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return create().signature.value;
    },
  });
  assertCoordinationError(() =>
    verifyCoordinationEnvelope(envelope, expectedContext()),
  );
  assert.equal(getterCalls, 0);
});

test("proxy traversal failures become safe fixed typed errors", () => {
  const canary = "sensitive-proxy-canary";
  const proxyCases = [
    new Proxy(validInput(), {
      ownKeys() {
        throw new Error(canary);
      },
    }),
    new Proxy(validInput(), {
      getOwnPropertyDescriptor() {
        throw new Error(canary);
      },
    }),
    new Proxy(validInput(), {
      getPrototypeOf() {
        throw new Error(canary);
      },
    }),
  ];
  for (const input of proxyCases) {
    assert.throws(
      () => createCoordinationEnvelope(input),
      (error) => {
        assert.ok(error instanceof CoordinationEnvelopeError);
        assert.equal(error.code, "COORDINATION_ENVELOPE_INVALID");
        assert.doesNotMatch(error.message, /sensitive|canary/u);
        return true;
      },
    );
  }
});

test("snapshot traversal rejects excessive properties before visiting descriptors", () => {
  const propertyNames = Array.from(
    { length: 65 },
    (_, index) => `property-${index}`,
  );
  let descriptorCalls = 0;
  const input = new Proxy(Object.create(null), {
    ownKeys() {
      return propertyNames;
    },
    getOwnPropertyDescriptor() {
      descriptorCalls += 1;
      return {
        configurable: true,
        enumerable: true,
        value: "x",
        writable: true,
      };
    },
  });

  assertCoordinationError(() =>
    createCoordinationEnvelope(input),
  );
  assert.equal(descriptorCalls, 0);
});

test("maximum valid current-schema envelope remains below the 64 KiB transport cap", () => {
  // These values reach every variable-length maximum admitted by the
  // current schema. Fixed-size digests, keys, UUIDs, and signatures
  // complete the maximum valid envelope without an artificial seam.
  const maximum = create({
    artifactDigest: "f".repeat(64),
    kind: "K".repeat(64),
    previousEventDigest: "f".repeat(64),
    publicKeyId: "k".repeat(64),
    releaseId: "r".repeat(256),
    role: "operator",
    sequence: "9".repeat(256),
    subjectRun: "stakeholder",
  });
  const maximumBytes = canonicalBytes(maximum).length;

  assert.equal(maximum.kind.length, 64);
  assert.equal(maximum.releaseId.length, 256);
  assert.equal(maximum.sequence.length, 256);
  assert.equal(maximum.signature.keyId.length, 64);
  assert.ok(maximumBytes < MAX_COORDINATION_ENVELOPE_BYTES);
});

test("created and verified envelopes are detached and recursively frozen", () => {
  const input = validInput({
    artifactDigest: ARTIFACT_DIGEST,
  });
  const envelope = createCoordinationEnvelope(input);
  input.artifactDigest = null;
  input.releaseId = "changed";

  assert.equal(envelope.artifactDigest, ARTIFACT_DIGEST);
  assert.equal(envelope.releaseId, RELEASE_ID);
  assert.ok(Object.isFrozen(envelope));
  assert.ok(Object.isFrozen(envelope.signature));
  assert.throws(() => {
    envelope.releaseId = "changed";
  }, TypeError);
  assert.throws(() => {
    envelope.signature.value = "changed";
  }, TypeError);

  const mutable = structuredClone(envelope);
  const verified = verifyCoordinationEnvelope(
    mutable,
    expectedContext(),
  );
  mutable.releaseId = "changed";
  mutable.signature.value = "changed";
  assert.equal(verified.releaseId, RELEASE_ID);
  assert.notEqual(verified.signature.value, "changed");
  assert.ok(Object.isFrozen(verified));
  assert.ok(Object.isFrozen(verified.signature));
});

test("error text never echoes hostile input material", () => {
  const canary = "never-echo-this-hostile-value";
  assert.throws(
    () => create({ releaseId: `${canary}\n` }),
    (error) => {
      assert.ok(error instanceof CoordinationEnvelopeError);
      assert.equal(error.code, "COORDINATION_ENVELOPE_INVALID");
      assert.doesNotMatch(error.message, new RegExp(canary, "u"));
      assert.doesNotMatch(error.stack, new RegExp(canary, "u"));
      return true;
    },
  );
});
