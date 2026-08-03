import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  link,
  lstat,
  mkdir,
  mkdtemp,
  open as nodeOpen,
  readFile,
  readdir,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  parseBlockTime,
} from "../src/core/blocktime.mjs";
import {
  canonicalBytes,
  digestHex,
} from "../src/core/canonical.mjs";
import {
  buildPartySignaturePreimage,
  BilateralEvidenceConfigurationError,
  BilateralEvidenceAmbiguousPublicationError,
  BilateralEvidenceRedactionError,
  BilateralPartyResultValidationError,
  LOCAL_VERDICTS,
  PARTY_RESULT_KEYS,
  PARTY_RESULT_SCHEMA,
  PARTY_ROLES,
  PARTY_SIGNATURE_PREIMAGE_KEYS,
  PARTY_SIGNATURE_SCHEMA,
  partySignatureBytes,
  RENDEZVOUS_CHANNELS,
  RENDEZVOUS_KEYS,
  RENDEZVOUS_TENANCIES,
  renderPartyResultMarkdown,
  rendezvousClaimSentence,
  SIGNATURE_KEYS,
  TRANSITION_ENTRY_KEYS,
  validatePartyResult,
  writePartyResult,
} from "../src/core/evidence.mjs";
import {
  closePinnedOutputDirectory,
  pinOutputDirectory,
} from "../src/core/runner.mjs";

const SESSION_DIGEST = "cd".repeat(32);
const REPOSITORY_SHA = "0123456789abcdef0123456789abcdef01234567";
const PROMPT_SHA256 = "ef".repeat(32);
const PAYER_ADDRESS = `0x${"11".repeat(20)}`;
const PAYEE_ADDRESS = `0x${"22".repeat(20)}`;
const REGISTRY = "0x8004a818bfb912233c491871b3d84c89a494bd9e";
const LEDGER_IDS = Object.freeze([
  "3f8a1c2e-9d4b-4a6c-8f2e-0123456789ab",
  "4a9b2d3f-0e5c-4b7d-9a3f-123456789abc",
  "5b0c3e40-1f6d-4c8e-ab40-23456789abcd",
]);
const RAW_TIMES = Object.freeze([
  "2026-07-24T20:00:00.100000001Z",
  "2026-07-24T20:00:31.204500000Z",
  "2026-07-24T20:01:02.309999999Z",
]);
const HEIGHTS = Object.freeze(["1869000", "1869030", "1869060"]);

function transitionHead(sessionDigest = SESSION_DIGEST) {
  return {
    amount: { currency: "USD", moved: false, value: "100" },
    expirySeconds: "600",
    payee: { address: PAYEE_ADDRESS, agentId: "9001" },
    payer: {
      address: PAYER_ADDRESS,
      agentId: "8677",
      reference: `eip155:11155111:${REGISTRY}:8677`,
    },
    protocol: "clockchain.bilateral-authorization/v1",
    schema: "clockchain.bilateral-transition/v1",
    sessionDigest,
  };
}

// Builds an internally consistent party-result fixture: every digest,
// anchored hash, predecessor triple, block-time and deadline value is
// recomputed here from the messages, so tamper tests can flip exactly
// one derived relation at a time.
function buildFixture({
  role = "payer",
  transitionsCount = 3,
  heights = HEIGHTS,
  rawTimes = RAW_TIMES,
  sessionDigest = SESSION_DIGEST,
  messageExtras = {},
  tamperPredecessor = false,
} = {}) {
  const m1 = {
    ...transitionHead(sessionDigest),
    kind: "proposal",
    predecessor: null,
    sequence: "1",
    ...(messageExtras.proposal ?? {}),
  };
  const h1 = digestHex(m1);
  const proposalTriple = {
    anchoredHash: h1,
    blockHeight: heights[0],
    kind: "proposal",
    ledgerId: LEDGER_IDS[0],
  };

  const m2 = {
    ...transitionHead(sessionDigest),
    decision: "ACCEPT",
    kind: "acceptance",
    predecessor: tamperPredecessor
      ? { ...proposalTriple, blockHeight: "999" }
      : proposalTriple,
    sequence: "2",
    ...(messageExtras.acceptance ?? {}),
  };
  const h2 = digestHex(m2);
  const acceptanceTriple = {
    anchoredHash: h2,
    blockHeight: heights[1],
    kind: "acceptance",
    ledgerId: LEDGER_IDS[1],
  };

  const m3 = {
    ...transitionHead(sessionDigest),
    kind: "acknowledgment",
    outcome: "ACKNOWLEDGED",
    paymentMoved: false,
    predecessor: acceptanceTriple,
    proposal: proposalTriple,
    sequence: "3",
    ...(messageExtras.acknowledgment ?? {}),
  };
  const h3 = digestHex(m3);

  const messages = [m1, m2, m3];
  const digests = [h1, h2, h3];
  const transitions = messages.map((message, index) => {
    const blockTimeMs = parseBlockTime(rawTimes[index]);
    return {
      blockTimeMs: String(blockTimeMs),
      blockTimeRaw: rawTimes[index],
      digest: digests[index],
      message,
      onChain: {
        anchoredHash: digests[index],
        blockHeight: heights[index],
        ledgerId: LEDGER_IDS[index],
      },
      upperBoundMs:
        index === 0 ? null : String(blockTimeMs + 1100),
    };
  });

  return {
    ackObserved: transitionsCount === 3,
    deadlineMs: String(parseBlockTime(rawTimes[0]) + 600000),
    localVerdict: "LOCAL_OK",
    paymentMoved: false,
    poolHealth: {
      degradedAtSubmission: true,
      nodeParticipationPct: "0.0",
      totalNodes: "1.0",
    },
    promptSha256: PROMPT_SHA256,
    protocolVersion: "1",
    rendezvous: {
      channel: "derived-reference-id",
      degradedAtSubmission: true,
      tenancy: "cross-client",
    },
    repositorySha: REPOSITORY_SHA,
    role,
    schema: PARTY_RESULT_SCHEMA,
    sessionDigest,
    signature: {
      address: role === "payer" ? PAYER_ADDRESS : PAYEE_ADDRESS,
      algorithm: "eip191",
      signature: `0x${"ab".repeat(65)}`,
    },
    transitions: transitions.slice(0, transitionsCount),
  };
}

function assertInvalid(mutate, options) {
  const result = buildFixture(options);
  if (mutate) {
    mutate(result);
  }
  assert.throws(
    () => validatePartyResult(result),
    (error) => {
      assert.ok(
        error instanceof BilateralPartyResultValidationError,
      );
      assert.equal(error.code, "BILATERAL_PARTY_RESULT_INVALID");
      return true;
    },
  );
}

async function temporaryDirectory(t) {
  const directory = await mkdtemp(
    join(tmpdir(), "bilateral-evidence-test-"),
  );
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}

function assertRedactionFailure(action, rejectedText) {
  assert.throws(
    action,
    (error) => {
      assert.ok(error instanceof BilateralEvidenceRedactionError);
      assert.equal(error.code, "BILATERAL_EVIDENCE_REDACTION");
      if (rejectedText !== undefined) {
        assert.equal(error.message.includes(rejectedText), false);
        assert.equal(error.stack.includes(rejectedText), false);
      }
      return true;
    },
  );
}

function recomputeEntryDigest(result, index) {
  const digest = digestHex(result.transitions[index].message);
  result.transitions[index].digest = digest;
  result.transitions[index].onChain.anchoredHash = digest;
}

function observedTriple(result, index) {
  const entry = result.transitions[index];
  return {
    anchoredHash: entry.onChain.anchoredHash,
    blockHeight: entry.onChain.blockHeight,
    kind: entry.message.kind,
    ledgerId: entry.onChain.ledgerId,
  };
}

function rebindObservedChain(result) {
  for (let index = 1; index < result.transitions.length; index += 1) {
    result.transitions[index].message.predecessor =
      observedTriple(result, index - 1);
    if (index === 2) {
      result.transitions[index].message.proposal =
        observedTriple(result, 0);
    }
    recomputeEntryDigest(result, index);
  }
}

function defineEnumerableProto(target, value) {
  Object.defineProperty(target, "__proto__", {
    configurable: true,
    enumerable: true,
    value,
    writable: true,
  });
}

function differentHash(value) {
  const replacement = value.endsWith("0") ? "1" : "0";
  return `${value.slice(0, -1)}${replacement}`;
}

function signatureInput(result, role = result.role) {
  return {
    role,
    sessionDigest: result.sessionDigest,
    transitions: result.transitions,
  };
}

function assertPartySignatureInvalid(input) {
  assert.throws(
    () => buildPartySignaturePreimage(input),
    (error) => {
      assert.ok(
        error instanceof BilateralPartyResultValidationError,
      );
      assert.equal(error.code, "BILATERAL_PARTY_RESULT_INVALID");
      return true;
    },
  );
}

function reverseKeyOrder(value) {
  if (Array.isArray(value)) {
    return value.map(reverseKeyOrder);
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .reverse()
        .map(([key, entry]) => [
          key,
          reverseKeyOrder(entry),
        ]),
    );
  }
  return value;
}

function assertDeeplyFrozen(value) {
  if (value === null || typeof value !== "object") {
    return;
  }
  assert.equal(Object.isFrozen(value), true);
  for (const entry of Object.values(value)) {
    assertDeeplyFrozen(entry);
  }
}

test("pins the party-result schema constants", () => {
  assert.equal(
    PARTY_RESULT_SCHEMA,
    "clockchain.bilateral-party-result/v1",
  );
  assert.deepEqual([...PARTY_ROLES], ["payer", "payee"]);
  assert.deepEqual(
    [...LOCAL_VERDICTS],
    [
      "LOCAL_OK",
      "RENDEZVOUS_UNAVAILABLE",
      "EXPIRED",
      "DUPLICATE",
      "AMBIGUOUS_WRITE",
      "BINDING_MISMATCH",
      "ANCHOR_UNVERIFIED",
      "RATE_BLOCKED",
      "AMOUNT_UNRESOLVED",
      "FAILED",
    ],
  );
  assert.equal(LOCAL_VERDICTS.includes("AUTHORIZED"), false);
  assert.deepEqual(
    [...RENDEZVOUS_CHANNELS],
    ["derived-reference-id", "digest-hash", "out-of-band-pointer"],
  );
  assert.deepEqual(
    [...RENDEZVOUS_TENANCIES],
    ["same-client", "cross-client", "unknown"],
  );
  assert.deepEqual(
    [...PARTY_RESULT_KEYS],
    [
      "ackObserved",
      "deadlineMs",
      "localVerdict",
      "paymentMoved",
      "poolHealth",
      "promptSha256",
      "protocolVersion",
      "rendezvous",
      "repositorySha",
      "role",
      "schema",
      "sessionDigest",
      "signature",
      "transitions",
    ],
  );
  assert.deepEqual(
    [...TRANSITION_ENTRY_KEYS],
    [
      "blockTimeMs",
      "blockTimeRaw",
      "digest",
      "message",
      "onChain",
      "upperBoundMs",
    ],
  );
  assert.deepEqual(
    [...RENDEZVOUS_KEYS],
    ["channel", "degradedAtSubmission", "tenancy"],
  );
  assert.deepEqual(
    [...SIGNATURE_KEYS],
    ["address", "algorithm", "signature"],
  );
  assert.equal(Object.isFrozen(PARTY_RESULT_KEYS), true);
  assert.equal(Object.isFrozen(LOCAL_VERDICTS), true);
});

test("pins the bilateral party-signature domain and exact preimage keys", () => {
  assert.equal(
    PARTY_SIGNATURE_SCHEMA,
    "clockchain.bilateral-party-signature/v1",
  );
  assert.deepEqual(
    [...PARTY_SIGNATURE_PREIMAGE_KEYS],
    ["messages", "role", "schema", "sessionDigest"],
  );
  assert.equal(
    Object.isFrozen(PARTY_SIGNATURE_PREIMAGE_KEYS),
    true,
  );
});

test("builds a detached deeply frozen payer preimage from M1 and M3 in protocol order", () => {
  const result = buildFixture();
  const preimage = buildPartySignaturePreimage(
    signatureInput(result),
  );

  assert.deepEqual(Object.keys(preimage), [
    "messages",
    "role",
    "schema",
    "sessionDigest",
  ]);
  assert.equal(preimage.role, "payer");
  assert.equal(preimage.schema, PARTY_SIGNATURE_SCHEMA);
  assert.equal(preimage.sessionDigest, SESSION_DIGEST);
  assert.deepEqual(
    preimage.messages.map((message) => message.kind),
    ["proposal", "acknowledgment"],
  );
  assert.equal(
    canonicalBytes({ messages: preimage.messages }).toString(
      "hex",
    ),
    canonicalBytes({
      messages: [
        result.transitions[0].message,
        result.transitions[2].message,
      ],
    }).toString("hex"),
  );
  assert.notEqual(
    preimage.messages[0],
    result.transitions[0].message,
  );
  assert.notEqual(
    preimage.messages[1],
    result.transitions[2].message,
  );
  assertDeeplyFrozen(preimage);
});

test("builds the same payee M2 preimage from accepted and acknowledged prefixes", () => {
  const accepted = buildFixture({
    role: "payee",
    transitionsCount: 2,
  });
  const acknowledged = buildFixture({ role: "payee" });
  const acceptedPreimage = buildPartySignaturePreimage(
    signatureInput(accepted),
  );

  assert.deepEqual(
    acceptedPreimage.messages.map((message) => message.kind),
    ["acceptance"],
  );
  assert.equal(
    canonicalBytes({
      messages: acceptedPreimage.messages,
    }).toString("hex"),
    canonicalBytes({
      messages: [accepted.transitions[1].message],
    }).toString("hex"),
  );
  assert.equal(
    partySignatureBytes(signatureInput(accepted)).toString("utf8"),
    partySignatureBytes(signatureInput(acknowledged)).toString(
      "utf8",
    ),
  );
});

test("party signature bytes commit transitively to the descriptor session digest", () => {
  const baseline = buildFixture({ role: "payer" });
  const intentBound = buildFixture({
    role: "payer",
    sessionDigest: "ab".repeat(32),
  });
  assert.notEqual(
    partySignatureBytes(signatureInput(baseline)).toString("hex"),
    partySignatureBytes(signatureInput(intentBound)).toString("hex"),
  );
});

test("pins exact payer and payee signing bytes and SHA-256 digests", () => {
  const payerBytes = partySignatureBytes(
    signatureInput(buildFixture()),
  );
  const payeeBytes = partySignatureBytes(
    signatureInput(
      buildFixture({
        role: "payee",
        transitionsCount: 2,
      }),
    ),
  );

  assert.equal(
    payerBytes.toString("utf8"),
    `{"messages":[{"amount":{"currency":"USD","moved":false,"value":"100"},"expirySeconds":"600","kind":"proposal","payee":{"address":"0x2222222222222222222222222222222222222222","agentId":"9001"},"payer":{"address":"0x1111111111111111111111111111111111111111","agentId":"8677","reference":"eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:8677"},"predecessor":null,"protocol":"clockchain.bilateral-authorization/v1","schema":"clockchain.bilateral-transition/v1","sequence":"1","sessionDigest":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"},{"amount":{"currency":"USD","moved":false,"value":"100"},"expirySeconds":"600","kind":"acknowledgment","outcome":"ACKNOWLEDGED","payee":{"address":"0x2222222222222222222222222222222222222222","agentId":"9001"},"payer":{"address":"0x1111111111111111111111111111111111111111","agentId":"8677","reference":"eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:8677"},"paymentMoved":false,"predecessor":{"anchoredHash":"e0b145701a28e6d4a7e2085e6cffab67a79f63461931821e0276b39a687b4c09","blockHeight":"1869030","kind":"acceptance","ledgerId":"4a9b2d3f-0e5c-4b7d-9a3f-123456789abc"},"proposal":{"anchoredHash":"06241c854132d39cf0aaa5f8d780da884dcdab15cbd0dbd07d63158192071230","blockHeight":"1869000","kind":"proposal","ledgerId":"3f8a1c2e-9d4b-4a6c-8f2e-0123456789ab"},"protocol":"clockchain.bilateral-authorization/v1","schema":"clockchain.bilateral-transition/v1","sequence":"3","sessionDigest":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"}],"role":"payer","schema":"clockchain.bilateral-party-signature/v1","sessionDigest":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"}`,
  );
  assert.equal(
    createHash("sha256").update(payerBytes).digest("hex"),
    "093f3b0a05cd5d305e3d7907670bb7b12ee9bcc825305bc5fdd97eb3f2d17c23",
  );
  assert.equal(
    payeeBytes.toString("utf8"),
    `{"messages":[{"amount":{"currency":"USD","moved":false,"value":"100"},"decision":"ACCEPT","expirySeconds":"600","kind":"acceptance","payee":{"address":"0x2222222222222222222222222222222222222222","agentId":"9001"},"payer":{"address":"0x1111111111111111111111111111111111111111","agentId":"8677","reference":"eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:8677"},"predecessor":{"anchoredHash":"06241c854132d39cf0aaa5f8d780da884dcdab15cbd0dbd07d63158192071230","blockHeight":"1869000","kind":"proposal","ledgerId":"3f8a1c2e-9d4b-4a6c-8f2e-0123456789ab"},"protocol":"clockchain.bilateral-authorization/v1","schema":"clockchain.bilateral-transition/v1","sequence":"2","sessionDigest":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"}],"role":"payee","schema":"clockchain.bilateral-party-signature/v1","sessionDigest":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"}`,
  );
  assert.equal(
    createHash("sha256").update(payeeBytes).digest("hex"),
    "5f29c24f63ecc6c08081295f69e963e4581fd3754a7065b38f2a34b0e6c43bd7",
  );
});

test("makes signing bytes independent of input key order and later mutation", () => {
  const result = buildFixture();
  const input = signatureInput(result);
  const preimage = buildPartySignaturePreimage(input);
  const bytes = canonicalBytes(preimage);
  const reordered = reverseKeyOrder(
    signatureInput(buildFixture()),
  );

  assert.equal(
    partySignatureBytes(reordered).toString("hex"),
    bytes.toString("hex"),
  );

  result.transitions[0].message.amount.value = "999";
  result.transitions[2].message.outcome = "FAILED";
  input.role = "payee";
  input.sessionDigest = "00".repeat(32);
  assert.equal(
    canonicalBytes(preimage).toString("hex"),
    bytes.toString("hex"),
  );
});

test("rejects unsupported roles, session mismatch, and inexact signature inputs", () => {
  const result = buildFixture();

  assertPartySignatureInvalid(
    signatureInput(result, "operator"),
  );
  assertPartySignatureInvalid({
    ...signatureInput(result),
    sessionDigest: "00".repeat(32),
  });
  assertPartySignatureInvalid({
    ...signatureInput(result),
    advisoryStatus: "verified",
  });
  const missingRole = signatureInput(result);
  delete missingRole.role;
  assertPartySignatureInvalid(missingRole);
});

test("enforces complete role-specific observed prefixes before signing", () => {
  assertPartySignatureInvalid(
    signatureInput(buildFixture({ transitionsCount: 0 })),
  );
  assertPartySignatureInvalid(
    signatureInput(buildFixture({ transitionsCount: 1 })),
  );
  assertPartySignatureInvalid(
    signatureInput(buildFixture({ transitionsCount: 2 })),
  );
  assertPartySignatureInvalid(
    signatureInput(
      buildFixture({
        role: "payee",
        transitionsCount: 0,
      }),
    ),
  );
  assertPartySignatureInvalid(
    signatureInput(
      buildFixture({
        role: "payee",
        transitionsCount: 1,
      }),
    ),
  );
});

test("rejects malformed or advisory transition chains before signing", () => {
  assertPartySignatureInvalid(
    signatureInput(buildFixture({ tamperPredecessor: true })),
  );

  const advisory = buildFixture();
  advisory.transitions[1].message.cachedStatus = "accepted";
  assertPartySignatureInvalid(signatureInput(advisory));

  const reordered = buildFixture();
  [
    reordered.transitions[1],
    reordered.transitions[2],
  ] = [
    reordered.transitions[2],
    reordered.transitions[1],
  ];
  assertPartySignatureInvalid(signatureInput(reordered));
});

test("rejects hostile signature inputs without invoking accessors or Proxy traps", () => {
  const result = buildFixture();
  let getterCalls = 0;
  const accessorInput = {
    sessionDigest: result.sessionDigest,
    transitions: result.transitions,
  };
  Object.defineProperty(accessorInput, "role", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return "payer";
    },
  });
  assertPartySignatureInvalid(accessorInput);
  assert.equal(getterCalls, 0);

  let trapCalls = 0;
  const proxyInput = new Proxy(signatureInput(result), {
    ownKeys() {
      trapCalls += 1;
      return [];
    },
  });
  assertPartySignatureInvalid(proxyInput);
  assert.equal(trapCalls, 0);
});

test("accepts a fully consistent payer package", () => {
  const result = buildFixture();
  assert.equal(validatePartyResult(result), result);
});

test("accepts a payee package with ackObserved false", () => {
  const result = buildFixture({
    role: "payee",
    transitionsCount: 2,
  });
  assert.equal(result.ackObserved, false);
  assert.equal(validatePartyResult(result), result);
});

test("accepts a terminal-code package with no transitions", () => {
  const result = buildFixture({ transitionsCount: 0 });
  result.localVerdict = "RENDEZVOUS_UNAVAILABLE";
  result.deadlineMs = null;
  assert.equal(validatePartyResult(result), result);
});

test("rejects an unknown top-level key", () => {
  assertInvalid((result) => {
    result.extra = "x";
  });
});

test("rejects a missing top-level key", () => {
  assertInvalid((result) => {
    delete result.rendezvous;
  });
});

test("rejects a wrong schema string", () => {
  assertInvalid((result) => {
    result.schema = "clockchain.handshake-result/v1";
  });
});

test("rejects number smuggling anywhere in the package", () => {
  assertInvalid((result) => {
    result.poolHealth.totalNodes = 1;
  });
  assertInvalid((result) => {
    result.deadlineMs = Number(result.deadlineMs);
  });
  // Deep inside an embedded message: the canonical-domain gate fires
  // before any digest arithmetic can normalize it away.
  assertInvalid((result) => {
    result.transitions[0].message.amount.value = 100;
  });
});

test("rejects AUTHORIZED as the local verdict", () => {
  assertInvalid((result) => {
    result.localVerdict = "AUTHORIZED";
  });
});

test("rejects AUTHORIZED smuggled into any field", () => {
  assertInvalid((result) => {
    result.protocolVersion = "AUTHORIZED";
  });
  // Inside an embedded message, with the digest chain recomputed so the
  // package stays internally consistent: the deep scan must still fire.
  assertInvalid(undefined, {
    messageExtras: { acknowledgment: { note: "AUTHORIZED" } },
  });
  assertInvalid(undefined, {
    messageExtras: {
      proposal: { note: "outcome AUTHORIZED by payer" },
    },
  });
});

test("rejects secret-shaped values in embedded messages", () => {
  assertRedactionFailure(() =>
    validatePartyResult(buildFixture({
      messageExtras: {
        acceptance: { note: `cc_${"a1b2c3d4e5".repeat(3)}` },
      },
    })),
  );
  assertRedactionFailure(() =>
    validatePartyResult(buildFixture({
      messageExtras: {
        acceptance: { note: "operator@example.com" },
      },
    })),
  );
});

test("rejects an unknown role or local verdict", () => {
  assertInvalid((result) => {
    result.role = "observer";
  });
  assertInvalid((result) => {
    result.localVerdict = "PASSED";
  });
});

test("rejects paymentMoved true", () => {
  assertInvalid((result) => {
    result.paymentMoved = true;
  });
});

test("rejects malformed session, repository, and prompt pins", () => {
  assertInvalid((result) => {
    result.sessionDigest = SESSION_DIGEST.toUpperCase();
  });
  assertInvalid((result) => {
    result.repositorySha = REPOSITORY_SHA.slice(0, 39);
  });
  assertInvalid((result) => {
    result.promptSha256 = `${PROMPT_SHA256.slice(0, 63)}g`;
  });
});

test("rejects a transition entry with unknown or missing keys", () => {
  assertInvalid((result) => {
    result.transitions[0].extra = "x";
  });
  assertInvalid((result) => {
    delete result.transitions[1].upperBoundMs;
  });
});

test("rejects a digest that does not recompute from the message", () => {
  assertInvalid((result) => {
    const digest = differentHash(result.transitions[0].digest);
    result.transitions[0].digest = digest;
    result.transitions[0].onChain.anchoredHash = digest;
  });
});

test("rejects an anchored hash different from the digest", () => {
  assertInvalid((result) => {
    result.transitions[1].onChain.anchoredHash = differentHash(
      result.transitions[1].digest,
    );
  });
});

test("rejects out-of-order transition kinds and sequences", () => {
  assertInvalid((result) => {
    const [first, second, third] = result.transitions;
    result.transitions = [second, first, third];
  });
  assertInvalid((result) => {
    result.transitions = [result.transitions[1]];
  });
});

test("rejects more than three transitions", () => {
  assertInvalid((result) => {
    result.transitions.push(result.transitions[2]);
  });
});

test("rejects non-increasing block heights", () => {
  assertInvalid(undefined, {
    heights: ["1869000", "1869000", "1869060"],
  });
  assertInvalid(undefined, {
    heights: ["1869030", "1869000", "1869060"],
  });
});

test("rejects a blockTimeMs not derived from the raw block time", () => {
  assertInvalid((result) => {
    result.transitions[0].blockTimeMs = String(
      Number(result.transitions[0].blockTimeMs) + 1,
    );
  });
});

test("rejects a malformed raw block time", () => {
  assertInvalid((result) => {
    result.transitions[0].blockTimeRaw = "24-07-2026_20:00:00:100";
  });
});

test("rejects non-monotonic authoritative block times", () => {
  assertInvalid(undefined, {
    rawTimes: [
      "2026-07-24T20:00:00.100000001Z",
      "2026-07-24T20:00:00.100000001Z",
      "2026-07-24T20:01:02.309999999Z",
    ],
  });
  assertInvalid(undefined, {
    rawTimes: [
      "2026-07-24T20:00:00.100000001Z",
      "2026-07-24T19:59:59.999999999Z",
      "2026-07-24T20:01:02.309999999Z",
    ],
  });
});

test("rejects a deadline not derived from the proposal block time", () => {
  assertInvalid((result) => {
    result.deadlineMs = String(Number(result.deadlineMs) + 1);
  });
  assertInvalid((result) => {
    result.deadlineMs = null;
  });
});

test("requires a null deadline when no transition was observed", () => {
  const result = buildFixture({ transitionsCount: 0 });
  result.localVerdict = "EXPIRED";
  result.deadlineMs = String(600000);
  assert.throws(
    () => validatePartyResult(result),
    BilateralPartyResultValidationError,
  );
  result.deadlineMs = null;
  assert.equal(validatePartyResult(result), result);
});

test("rejects a wrong or missing upper bound on later transitions", () => {
  assertInvalid((result) => {
    result.transitions[1].upperBoundMs = String(
      Number(result.transitions[1].blockTimeMs) + 1101,
    );
  });
  assertInvalid((result) => {
    result.transitions[2].upperBoundMs = null;
  });
  assertInvalid((result) => {
    result.transitions[0].upperBoundMs = String(
      Number(result.transitions[0].blockTimeMs) + 1100,
    );
  });
});

test("rejects a later transition past the deadline", () => {
  assertInvalid(undefined, {
    rawTimes: [
      "2026-07-24T20:00:00.100000001Z",
      "2026-07-24T20:09:59.100000000Z",
      "2026-07-24T20:10:00.309999999Z",
    ],
  });
});

test("accepts an upper bound exactly at the deadline", () => {
  // deadline = t1 + 600000; upperBound(h3) = t3 + 1100 == deadline.
  const result = buildFixture({
    rawTimes: [
      "2026-07-24T20:00:00.100000001Z",
      "2026-07-24T20:00:31.204500000Z",
      "2026-07-24T20:09:59.000000000Z",
    ],
  });
  assert.equal(
    Number(result.transitions[2].upperBoundMs),
    Number(result.deadlineMs),
  );
  assert.equal(validatePartyResult(result), result);
});

test("rejects a predecessor triple that does not match the observed one", () => {
  assertInvalid(undefined, { tamperPredecessor: true });
});

test("rejects rendezvous disclosure violations", () => {
  assertInvalid((result) => {
    result.rendezvous.channel = "same-host-filesystem";
  });
  assertInvalid((result) => {
    result.rendezvous.tenancy = "shared";
  });
  assertInvalid((result) => {
    result.rendezvous.degradedAtSubmission = false;
  });
  assertInvalid((result) => {
    delete result.rendezvous.tenancy;
  });
});

test("accepts a consistently non-degraded disclosure", () => {
  const result = buildFixture();
  result.poolHealth.degradedAtSubmission = false;
  result.poolHealth.nodeParticipationPct = "50.0";
  result.poolHealth.totalNodes = "3.0";
  result.rendezvous.degradedAtSubmission = false;
  assert.equal(validatePartyResult(result), result);
});

test("rejects signature shape violations", () => {
  assertInvalid((result) => {
    result.signature.algorithm = "ed25519";
  });
  assertInvalid((result) => {
    result.signature.address = `0x${"AB".repeat(20)}`;
  });
  assertInvalid((result) => {
    result.signature.signature = `0x${"ab".repeat(64)}`;
  });
  assertInvalid((result) => {
    result.signature.extra = "x";
  });
});

test("binds the signature address to the reporting role", () => {
  assertInvalid(
    (result) => {
      result.signature.address = PAYER_ADDRESS;
    },
    { role: "payee", transitionsCount: 2 },
  );
});

test("rejects ackObserved inconsistent with the transitions", () => {
  assertInvalid((result) => {
    result.ackObserved = false;
  });
  assertInvalid(
    (result) => {
      result.ackObserved = true;
    },
    { role: "payee", transitionsCount: 2 },
  );
});

test("rejects LOCAL_OK without the transitions that would justify it", () => {
  assertInvalid(undefined, { transitionsCount: 2 });
  assertInvalid(undefined, {
    role: "payee",
    transitionsCount: 1,
  });
});

test("rejects integer-like keys and non-ASCII strings anywhere", () => {
  assertInvalid((result) => {
    result.transitions[0].message.note = "café";
  });
  const result = buildFixture();
  result.transitions[0].message["10"] = "x";
  assert.throws(
    () => validatePartyResult(result),
    BilateralPartyResultValidationError,
  );
});

test("requires exact pool-health and on-chain schemas", () => {
  assertInvalid((result) => {
    result.poolHealth.status = "degraded";
  });
  assertInvalid((result) => {
    delete result.poolHealth.totalNodes;
  });
  assertInvalid((result) => {
    result.transitions[0].onChain.status = "anchored";
  });
  assertInvalid((result) => {
    delete result.transitions[0].onChain.ledgerId;
  });
  assertInvalid((result) => {
    result.transitions[0].onChain.ledgerId =
      "00000000-0000-0000-0000-000000000000";
  });
  assertInvalid((result) => {
    result.poolHealth.nodeParticipationPct = "101";
  });
});

test("rejects every pairwise duplicate authoritative ledger id after full downstream rebinding", () => {
  for (const [left, right] of [
    [0, 1],
    [0, 2],
    [1, 2],
  ]) {
    const result = buildFixture();
    result.transitions[right].onChain.ledgerId =
      result.transitions[left].onChain.ledgerId;
    rebindObservedChain(result);
    assert.throws(
      () => validatePartyResult(result),
      BilateralPartyResultValidationError,
      `duplicate ledger pair ${left}/${right}`,
    );
  }
});

test("binds every embedded message to the package session digest", () => {
  const result = buildFixture({ transitionsCount: 1 });
  result.localVerdict = "FAILED";
  result.ackObserved = false;
  result.transitions[0].message.sessionDigest = "ab".repeat(32);
  recomputeEntryDigest(result, 0);
  assert.doesNotThrow(() => digestHex(result.transitions[0].message));
  assert.throws(
    () => validatePartyResult(result),
    BilateralPartyResultValidationError,
  );
});

test("rejects acknowledgment predecessor or proposal divergence after digest recomputation", () => {
  assertInvalid((result) => {
    result.transitions[2].message.predecessor.blockHeight = "1869031";
    recomputeEntryDigest(result, 2);
  });
  assertInvalid((result) => {
    result.transitions[2].message.proposal.ledgerId = LEDGER_IDS[1];
    recomputeEntryDigest(result, 2);
  });
});

test("compares canonical block heights without Number precision loss", () => {
  const prefix = "9".repeat(99);
  const result = buildFixture({
    heights: [`1${prefix}`, `2${prefix}`, `3${prefix}`],
  });
  assert.equal(validatePartyResult(result), result);

  assertInvalid(undefined, {
    heights: [`2${prefix}`, `1${prefix}`, `3${prefix}`],
  });
});

test("allows terminal packages to preserve any valid observed prefix", () => {
  for (const transitionsCount of [0, 1, 2, 3]) {
    const result = buildFixture({ transitionsCount });
    result.localVerdict = "FAILED";
    result.ackObserved = transitionsCount === 3;
    if (transitionsCount === 0) {
      result.deadlineMs = null;
    }
    assert.equal(validatePartyResult(result), result);
  }
});

test("rejects messages that are canonical-digestible but outside the bilateral transition schema", () => {
  const result = buildFixture();
  result.transitions[0].message.amount.moved = true;
  recomputeEntryDigest(result, 0);
  assert.doesNotThrow(() => digestHex(result.transitions[0].message));
  assertInvalid((candidate) => {
    candidate.transitions[0].message.amount.moved = true;
    recomputeEntryDigest(candidate, 0);
  });

  assertInvalid((candidate) => {
    candidate.transitions[1].message.decision = "DECLINE";
    recomputeEntryDigest(candidate, 1);
  });
});

test("rejects hostile object graphs without invoking accessors or proxy get traps", () => {
  let accessorCalls = 0;
  const accessorResult = buildFixture();
  Object.defineProperty(accessorResult, "role", {
    enumerable: true,
    get() {
      accessorCalls += 1;
      return "payer";
    },
  });
  assert.throws(
    () => validatePartyResult(accessorResult),
    BilateralPartyResultValidationError,
  );
  assert.equal(accessorCalls, 0);

  let proxyGetCalls = 0;
  const proxyResult = new Proxy(buildFixture(), {
    get() {
      proxyGetCalls += 1;
      throw new Error("proxy get trap must stay unreachable");
    },
  });
  assert.throws(
    () => validatePartyResult(proxyResult),
    BilateralPartyResultValidationError,
  );
  assert.equal(proxyGetCalls, 0);

  const cyclicResult = buildFixture();
  cyclicResult.poolHealth.self = cyclicResult.poolHealth;
  assert.throws(
    () => validatePartyResult(cyclicResult),
    BilateralPartyResultValidationError,
  );

  const sparseResult = buildFixture();
  delete sparseResult.transitions[1];
  assert.throws(
    () => validatePartyResult(sparseResult),
    BilateralPartyResultValidationError,
  );

  const propertyArrayResult = buildFixture();
  propertyArrayResult.transitions.note = "not an index";
  assert.throws(
    () => validatePartyResult(propertyArrayResult),
    BilateralPartyResultValidationError,
  );

  const symbolResult = buildFixture();
  symbolResult[Symbol("hidden")] = "x";
  assert.throws(
    () => validatePartyResult(symbolResult),
    BilateralPartyResultValidationError,
  );

  const deepResult = buildFixture();
  let cursor = deepResult.poolHealth;
  for (let depth = 0; depth < 40; depth += 1) {
    cursor.child = {};
    cursor = cursor.child;
  }
  assert.throws(
    () => validatePartyResult(deepResult),
    BilateralPartyResultValidationError,
  );

  const oversizedResult = buildFixture();
  oversizedResult.protocolVersion = "x".repeat(257);
  assert.throws(
    () => validatePartyResult(oversizedResult),
    BilateralPartyResultValidationError,
  );

  const tooManyObjectsResult = buildFixture();
  tooManyObjectsResult.extra = {};
  for (let index = 0; index < 300; index += 1) {
    tooManyObjectsResult.extra[`item-${index}`] = {};
  }
  assert.throws(
    () => validatePartyResult(tooManyObjectsResult),
    BilateralPartyResultValidationError,
  );

  for (const unsupported of [
    undefined,
    1n,
    Symbol("unsupported"),
  ]) {
    const unsupportedResult = buildFixture();
    unsupportedResult.protocolVersion = unsupported;
    assert.throws(
      () => validatePartyResult(unsupportedResult),
      BilateralPartyResultValidationError,
    );
  }
});

test("scans authorizing and secret-shaped text in keys as well as values", () => {
  const authorizingKey = buildFixture();
  authorizingKey.AUTHORIZED = "no";
  assert.throws(
    () => validatePartyResult(authorizingKey),
    BilateralPartyResultValidationError,
  );

  const secretKey = buildFixture();
  secretKey.privateKey = "not-even-secret-material";
  assertRedactionFailure(
    () => validatePartyResult(secretKey),
    "not-even-secret-material",
  );

  const emailKey = buildFixture();
  emailKey["operator@example.com"] = "x";
  assertRedactionFailure(
    () => validatePartyResult(emailKey),
    "operator@example.com",
  );

  const secretValue = buildFixture();
  secretValue.protocolVersion = `Bearer ${"a".repeat(32)}`;
  assertRedactionFailure(
    () => validatePartyResult(secretValue),
    "a".repeat(32),
  );

  const privateKeyValue = buildFixture();
  privateKeyValue.protocolVersion =
    "-----BEGIN PRIVATE KEY-----";
  assertRedactionFailure(
    () => validatePartyResult(privateKeyValue),
    "BEGIN PRIVATE KEY",
  );

  const invitationValue = buildFixture();
  invitationValue.protocolVersion =
    "invitation code: abcdefghijklmnop";
  assertRedactionFailure(
    () => validatePartyResult(invitationValue),
    "abcdefghijklmnop",
  );
});

test("preserves hostile __proto__ data keys for fail-closed deep scanning", () => {
  const topLevelAuthorizing = buildFixture();
  defineEnumerableProto(topLevelAuthorizing, "AUTHORIZED");
  assert.throws(
    () => validatePartyResult(topLevelAuthorizing),
    BilateralPartyResultValidationError,
  );

  const nestedPrivateKey = buildFixture();
  defineEnumerableProto(
    nestedPrivateKey.poolHealth,
    "-----BEGIN PRIVATE KEY-----",
  );
  assertRedactionFailure(
    () => validatePartyResult(nestedPrivateKey),
    "BEGIN PRIVATE KEY",
  );

  const nestedEmail = buildFixture();
  defineEnumerableProto(
    nestedEmail.transitions[0].onChain,
    "operator@example.com",
  );
  assertRedactionFailure(
    () => validatePartyResult(nestedEmail),
    "operator@example.com",
  );

  const nestedClockchainToken = buildFixture();
  defineEnumerableProto(
    nestedClockchainToken.transitions[1].message,
    `cc_${"f".repeat(32)}`,
  );
  assertRedactionFailure(
    () => validatePartyResult(nestedClockchainToken),
    "f".repeat(32),
  );
});

test("derives strong rendezvous wording only from cross-client reference-id facts", () => {
  assert.equal(
    rendezvousClaimSentence({
      channel: "derived-reference-id",
      degradedAtSubmission: true,
      tenancy: "cross-client",
    }),
    "Peer evidence was discovered by derived reference ID across separate client tenancies.",
  );
  assert.equal(
    rendezvousClaimSentence({
      channel: "derived-reference-id",
      degradedAtSubmission: true,
      tenancy: "same-client",
    }),
    "Peer evidence was discovered by derived reference ID; separate-client tenancy was not proven.",
  );
  assert.equal(
    rendezvousClaimSentence({
      channel: "derived-reference-id",
      degradedAtSubmission: true,
      tenancy: "unknown",
    }),
    "Peer evidence was discovered by derived reference ID; separate-client tenancy was not proven.",
  );
  assert.equal(
    rendezvousClaimSentence({
      channel: "digest-hash",
      degradedAtSubmission: true,
      tenancy: "cross-client",
    }),
    "Peer evidence was discovered by digest hash; Clockchain reference-ID rendezvous was not proven.",
  );
  assert.equal(
    rendezvousClaimSentence({
      channel: "out-of-band-pointer",
      degradedAtSubmission: true,
      tenancy: "cross-client",
    }),
    "Peer evidence was exchanged by out-of-band pointer; Clockchain rendezvous was not proven.",
  );

  for (const channel of RENDEZVOUS_CHANNELS) {
    for (const tenancy of RENDEZVOUS_TENANCIES) {
      const sentence = rendezvousClaimSentence({
        channel,
        degradedAtSubmission: true,
        tenancy,
      });
      assert.equal(
        sentence.includes("across separate client tenancies"),
        channel === "derived-reference-id" &&
          tenancy === "cross-client",
        `${channel}/${tenancy}`,
      );
    }
  }
});

test("renders deterministic byte-pinned Markdown from only the validated JSON", () => {
  const first = buildFixture();
  const reordered = Object.fromEntries(
    Object.entries(buildFixture()).reverse(),
  );
  const markdown = renderPartyResultMarkdown(first);

  assert.equal(renderPartyResultMarkdown(reordered), markdown);
  assert.equal(
    createHash("sha256").update(markdown, "utf8").digest("hex"),
    "e7bee36ab2753c5a9cc73204bfb2451de7d349723db09a73b4002ba5af6ddb86",
  );
  assert.match(
    markdown,
    /Peer evidence was discovered by derived reference ID across separate client tenancies\./,
  );
  const jsonMatch = /```json\n([\s\S]+)\n```\n$/.exec(markdown);
  assert.ok(jsonMatch);
  assert.deepEqual(JSON.parse(jsonMatch[1]), first);
});

test("writes and cross-checks deterministic JSON and Markdown artifacts", async (t) => {
  const directory = await temporaryDirectory(t);
  const result = buildFixture();
  const paths = await writePartyResult({
    directory,
    result,
    canaries: [],
  });

  assert.deepEqual(paths, {
    jsonPath: join(directory, "party-result.json"),
    markdownPath: join(directory, "PARTY-RESULT.md"),
    markerPath: join(directory, ".party-result.complete.json"),
  });
  const json = await readFile(paths.jsonPath, "utf8");
  const markdown = await readFile(paths.markdownPath, "utf8");
  assert.deepEqual(
    JSON.parse(json),
    result,
  );
  assert.equal(
    markdown,
    renderPartyResultMarkdown(result),
  );
  assert.deepEqual(
    JSON.parse(await readFile(paths.markerPath, "utf8")),
    {
      jsonSha256:
        createHash("sha256").update(json, "utf8").digest("hex"),
      markdownSha256:
        createHash("sha256")
          .update(markdown, "utf8")
          .digest("hex"),
      schema:
        "clockchain.bilateral-party-result-completion/v1",
    },
  );
  assert.deepEqual(
    (await readdir(directory)).sort(),
    [
      ".party-result.complete.json",
      "PARTY-RESULT.md",
      "party-result.json",
    ],
  );
});

test("accepts the bounded role-canary ceiling without persisting canaries", async (t) => {
  const canaries = Array.from(
    { length: 65 },
    (_value, index) =>
      `${String(index).padStart(3, "0")}${"x".repeat(253)}`,
  );

  for (const count of [53, 64]) {
    await t.test(`${count} canaries`, async (t) => {
      const directory = await temporaryDirectory(t);
      const paths = await writePartyResult({
        canaries: canaries.slice(0, count),
        directory,
        result: buildFixture(),
      });
      const artifacts = await Promise.all(
        Object.values(paths).map((path) => readFile(path, "utf8")),
      );

      assert.ok(canaries.slice(0, count).every(
        (canary) => canary.length === 256,
      ));
      assert.ok(artifacts.every((artifact) =>
        canaries.slice(0, count).every(
          (canary) => artifact.includes(canary) === false,
        ),
      ));
    });
  }

  const directory = await temporaryDirectory(t);
  await assert.rejects(
    writePartyResult({
      canaries,
      directory,
      result: buildFixture(),
    }),
    BilateralEvidenceConfigurationError,
  );
  assert.deepEqual(await readdir(directory), []);
});

test("evidence publication cannot escape a pinned output directory", async (t) => {
  const root = await temporaryDirectory(t);
  const directory = join(root, "output");
  const moved = join(root, "moved-output");
  const replacement = join(root, "replacement");
  await mkdir(directory, { mode: 0o700 });
  await mkdir(replacement, { mode: 0o700 });
  const pin = await pinOutputDirectory({
    directory,
    fileSystem: {
      lstat,
      open: nodeOpen,
    },
  });
  await rename(directory, moved);
  await rename(replacement, directory);
  try {
    await assert.rejects(
      writePartyResult({
        canaries: [],
        directory,
        directoryPin: pin,
        result: buildFixture(),
      }),
      BilateralEvidenceConfigurationError,
    );
    assert.deepEqual(await readdir(directory), []);
  } finally {
    await closePinnedOutputDirectory(pin);
  }
});

test("validates and redacts before persistence", async (t) => {
  const directory = await temporaryDirectory(t);
  const canary = "fresh-invitation-code-canary";
  const result = buildFixture();
  result.protocolVersion = canary;
  let mkdirCalls = 0;

  await assert.rejects(
    () =>
      writePartyResult({
        directory,
        result,
        canaries: [canary],
        fileSystem: {
          async mkdir(...args) {
            mkdirCalls += 1;
            return mkdir(...args);
          },
        },
      }),
    BilateralEvidenceRedactionError,
  );
  assert.equal(mkdirCalls, 0);
  assert.deepEqual(await readdir(directory), []);
});

test("refuses overwrite without disturbing either existing artifact", async (t) => {
  const directory = await temporaryDirectory(t);
  const jsonPath = join(directory, "party-result.json");
  const markdownPath = join(directory, "PARTY-RESULT.md");
  await writeFile(jsonPath, "prior-json\n", "utf8");
  await writeFile(markdownPath, "prior-markdown\n", "utf8");
  let linkCalls = 0;

  await assert.rejects(
    () =>
      writePartyResult({
        directory,
        result: buildFixture(),
        canaries: [],
        fileSystem: {
          async link(...args) {
            linkCalls += 1;
            return link(...args);
          },
        },
      }),
    BilateralEvidenceConfigurationError,
  );
  assert.equal(linkCalls, 0);
  assert.equal(await readFile(jsonPath, "utf8"), "prior-json\n");
  assert.equal(
    await readFile(markdownPath, "utf8"),
    "prior-markdown\n",
  );
});

test("refuses a stale completion marker without creating data artifacts", async (t) => {
  const directory = await temporaryDirectory(t);
  const markerPath = join(
    directory,
    ".party-result.complete.json",
  );
  await writeFile(markerPath, "{\"stale\":true}\n", "utf8");

  await assert.rejects(
    () =>
      writePartyResult({
        directory,
        result: buildFixture(),
        canaries: [],
      }),
    BilateralEvidenceConfigurationError,
  );
  assert.equal(
    await readFile(markerPath, "utf8"),
    "{\"stale\":true}\n",
  );
  assert.deepEqual(
    await readdir(directory),
    [".party-result.complete.json"],
  );
});

test("cleans temporary files and leaves no partial final on second temporary write failure", async (t) => {
  const directory = await temporaryDirectory(t);
  let writeCalls = 0;

  await assert.rejects(
    () =>
      writePartyResult({
        directory,
        result: buildFixture(),
        canaries: [],
        fileSystem: {
          async writeFile(...args) {
            writeCalls += 1;
            if (writeCalls === 2) {
              throw new Error("injected second temporary write failure");
            }
            return writeFile(...args);
          },
        },
      }),
    BilateralEvidenceConfigurationError,
  );
  assert.equal(writeCalls, 2);
  assert.deepEqual(await readdir(directory), []);
});

test("preserves the first final without a marker when second exclusive publication fails", async (t) => {
  const directory = await temporaryDirectory(t);
  const markerPath = join(
    directory,
    ".party-result.complete.json",
  );
  let linkCalls = 0;

  await assert.rejects(
    () =>
      writePartyResult({
        directory,
        result: buildFixture(),
        canaries: [],
        fileSystem: {
          async link(...args) {
            linkCalls += 1;
            if (linkCalls === 2) {
              throw new Error("injected second publication failure");
            }
            return link(...args);
          },
        },
      }),
    BilateralEvidenceAmbiguousPublicationError,
  );
  assert.equal(linkCalls, 2);
  assert.deepEqual(await readdir(directory), [
    "party-result.json",
  ]);
  await assert.rejects(() => readFile(markerPath, "utf8"), {
    code: "ENOENT",
  });
});

test("preserves both finals without a marker when second publication reports an ambiguous failure", async (t) => {
  const directory = await temporaryDirectory(t);
  const markerPath = join(
    directory,
    ".party-result.complete.json",
  );
  let linkCalls = 0;

  await assert.rejects(
    () =>
      writePartyResult({
        directory,
        result: buildFixture(),
        canaries: [],
        fileSystem: {
          async link(...args) {
            linkCalls += 1;
            const linked = await link(...args);
            if (linkCalls === 2) {
              throw new Error(
                "injected ambiguous second publication failure",
              );
            }
            return linked;
          },
        },
      }),
    BilateralEvidenceAmbiguousPublicationError,
  );
  assert.equal(linkCalls, 2);
  assert.deepEqual((await readdir(directory)).sort(), [
    "PARTY-RESULT.md",
    "party-result.json",
  ]);
  await assert.rejects(() => readFile(markerPath, "utf8"), {
    code: "ENOENT",
  });
});

test("publishes no completion marker when final artifact read-back fails validation", async (t) => {
  const directory = await temporaryDirectory(t);
  const jsonPath = join(directory, "party-result.json");
  let linkCalls = 0;
  let corruptedRead = false;

  await assert.rejects(
    () =>
      writePartyResult({
        directory,
        result: buildFixture(),
        canaries: [],
        fileSystem: {
          async link(...args) {
            linkCalls += 1;
            return link(...args);
          },
          async readFile(path, options) {
            if (
              linkCalls === 2 &&
              path === jsonPath &&
              !corruptedRead
            ) {
              corruptedRead = true;
              return "{\"schema\":\"corrupted\"}\n";
            }
            return readFile(path, options);
          },
        },
      }),
    BilateralEvidenceAmbiguousPublicationError,
  );
  assert.equal(linkCalls, 2);
  assert.equal(corruptedRead, true);
  assert.deepEqual((await readdir(directory)).sort(), [
    "PARTY-RESULT.md",
    "party-result.json",
  ]);
  assert.equal(
    (await readdir(directory)).includes(
      ".party-result.complete.json",
    ),
    false,
  );
});

test("never asks the filesystem to remove published final paths after publication begins", async (t) => {
  const directory = await temporaryDirectory(t);
  const jsonPath = join(directory, "party-result.json");
  const markdownPath = join(directory, "PARTY-RESULT.md");
  const markerPath = join(
    directory,
    ".party-result.complete.json",
  );
  let linkCalls = 0;
  const removedPaths = [];

  await assert.rejects(
    () =>
      writePartyResult({
        directory,
        result: buildFixture(),
        canaries: [],
        fileSystem: {
          async link(...args) {
            linkCalls += 1;
            const linked = await link(...args);
            if (linkCalls === 2) {
              throw new Error(
                "injected ambiguous second publication failure",
              );
            }
            return linked;
          },
          async rm(path, options) {
            removedPaths.push(path);
            return rm(path, options);
          },
        },
      }),
    (error) => {
      assert.ok(
        error instanceof
          BilateralEvidenceAmbiguousPublicationError,
      );
      assert.equal(
        error.code,
        "BILATERAL_EVIDENCE_PUBLICATION_AMBIGUOUS",
      );
      return true;
    },
  );
  assert.equal(linkCalls, 2);
  assert.equal(removedPaths.includes(jsonPath), false);
  assert.equal(removedPaths.includes(markdownPath), false);
  assert.equal(removedPaths.includes(markerPath), false);
  assert.equal(
    (await readdir(directory)).includes(
      ".party-result.complete.json",
    ),
    false,
  );
  await assert.rejects(() => readFile(markerPath, "utf8"), {
    code: "ENOENT",
  });
  assert.equal(
    JSON.parse(await readFile(jsonPath, "utf8")).schema,
    PARTY_RESULT_SCHEMA,
  );
  assert.equal(
    JSON.parse(await readFile(markdownPath, "utf8").then(
      (markdown) =>
        /```json\n([\s\S]+)\n```\n$/.exec(markdown)[1],
    )).schema,
    PARTY_RESULT_SCHEMA,
  );
});

test("preserves a foreign replacement final for operator inspection", async (t) => {
  const directory = await temporaryDirectory(t);
  const jsonPath = join(directory, "party-result.json");
  const foreignBytes = "{\"foreign\":true}\n";
  let linkCalls = 0;

  await assert.rejects(
    () =>
      writePartyResult({
        directory,
        result: buildFixture(),
        canaries: [],
        fileSystem: {
          async link(source, destination) {
            linkCalls += 1;
            if (linkCalls === 1) {
              await rm(source, { force: true });
              await writeFile(source, foreignBytes, {
                encoding: "utf8",
                flag: "wx",
                mode: 0o600,
              });
            }
            return link(source, destination);
          },
        },
      }),
    (error) => {
      assert.ok(
        error instanceof
          BilateralEvidenceAmbiguousPublicationError,
      );
      assert.equal(
        error.code,
        "BILATERAL_EVIDENCE_PUBLICATION_AMBIGUOUS",
      );
      return true;
    },
  );
  assert.equal(linkCalls, 2);
  assert.equal(await readFile(jsonPath, "utf8"), foreignBytes);
  assert.deepEqual((await readdir(directory)).sort(), [
    "PARTY-RESULT.md",
    "party-result.json",
  ]);
});

test("rejects malformed filesystem injection before touching disk", async (t) => {
  const directory = await temporaryDirectory(t);
  await assert.rejects(
    () =>
      writePartyResult({
        directory,
        result: buildFixture(),
        canaries: [],
        fileSystem: { readFile: "not a function" },
      }),
    BilateralEvidenceConfigurationError,
  );
  assert.deepEqual(await readdir(directory), []);
});
