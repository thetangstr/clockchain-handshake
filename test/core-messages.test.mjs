import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  MAX_CANONICAL_STRING_LENGTH,
  canonicalBytes,
} from "../src/core/canonical.mjs";
import {
  DescriptorValidationError,
  dSession,
} from "../src/core/descriptor.mjs";
import {
  ACCEPTANCE_KEYS,
  ACKNOWLEDGMENT_KEYS,
  AMOUNT_KEYS,
  COMMON_HEAD_KEYS,
  DERIVABLE_TRANSITION_FIELDS,
  PAYEE_BINDING_KEYS,
  PAYER_BINDING_KEYS,
  PREDECESSOR_TRIPLE_KEYS,
  PROPOSAL_KEYS,
  TRANSITION_SCHEMA,
  ProposalAmountAmbiguousError,
  ProposalAmountNotFoundError,
  TransitionValidationError,
  authoritativeTriple,
  buildAcceptance,
  buildAcknowledgment,
  buildProposal,
  recoverProposalByDigest,
  selectUniqueProposalMatch,
  transitionDigest,
  validateTransition,
} from "../src/core/messages.mjs";

const PAYER_ADDRESS =
  "0x00112233445566778899aabbccddeeff00112233";
const PAYEE_ADDRESS =
  "0xffeeddccbbaa99887766554433221100ffeeddcc";
const SESSION_DIGEST =
  "04e932d5144bb18a12481657c5c351be3dc760927748c966fee64bc891bd3d73";
const LEDGER_ID = "370c7672-3a78-4c17-853c-e3037799562c";
const H1 =
  "b8fc5a5e8dca9126799f2780c198042989c78a2e6e871b9638bc144149f2ac47";
const H2 =
  "16028a05a3707f8fc4701e5cd074ddd8a170416e054d1f1717b0c4400559e229";
const H3 =
  "b87bf37ab6ec96f355b883bb5bc80aba8f5a3c504bf790dcc0206a05a677ca61";

const M1_BYTES =
  '{"amount":{"currency":"USD","moved":false,"value":"100"},"expirySeconds":"600","kind":"proposal","payee":{"address":"0xffeeddccbbaa99887766554433221100ffeeddcc","agentId":"8678"},"payer":{"address":"0x00112233445566778899aabbccddeeff00112233","agentId":"8677","reference":"eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:8677"},"predecessor":null,"protocol":"clockchain.bilateral-authorization/v1","schema":"clockchain.bilateral-transition/v1","sequence":"1","sessionDigest":"04e932d5144bb18a12481657c5c351be3dc760927748c966fee64bc891bd3d73"}';
const M2_BYTES =
  '{"amount":{"currency":"USD","moved":false,"value":"100"},"decision":"ACCEPT","expirySeconds":"600","kind":"acceptance","payee":{"address":"0xffeeddccbbaa99887766554433221100ffeeddcc","agentId":"8678"},"payer":{"address":"0x00112233445566778899aabbccddeeff00112233","agentId":"8677","reference":"eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:8677"},"predecessor":{"anchoredHash":"b8fc5a5e8dca9126799f2780c198042989c78a2e6e871b9638bc144149f2ac47","blockHeight":"3375636","kind":"proposal","ledgerId":"370c7672-3a78-4c17-853c-e3037799562c"},"protocol":"clockchain.bilateral-authorization/v1","schema":"clockchain.bilateral-transition/v1","sequence":"2","sessionDigest":"04e932d5144bb18a12481657c5c351be3dc760927748c966fee64bc891bd3d73"}';
const M3_BYTES =
  '{"amount":{"currency":"USD","moved":false,"value":"100"},"expirySeconds":"600","kind":"acknowledgment","outcome":"ACKNOWLEDGED","payee":{"address":"0xffeeddccbbaa99887766554433221100ffeeddcc","agentId":"8678"},"payer":{"address":"0x00112233445566778899aabbccddeeff00112233","agentId":"8677","reference":"eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:8677"},"paymentMoved":false,"predecessor":{"anchoredHash":"16028a05a3707f8fc4701e5cd074ddd8a170416e054d1f1717b0c4400559e229","blockHeight":"3375637","kind":"acceptance","ledgerId":"370c7672-3a78-4c17-853c-e3037799562c"},"proposal":{"anchoredHash":"b8fc5a5e8dca9126799f2780c198042989c78a2e6e871b9638bc144149f2ac47","blockHeight":"3375636","kind":"proposal","ledgerId":"370c7672-3a78-4c17-853c-e3037799562c"},"protocol":"clockchain.bilateral-authorization/v1","schema":"clockchain.bilateral-transition/v1","sequence":"3","sessionDigest":"04e932d5144bb18a12481657c5c351be3dc760927748c966fee64bc891bd3d73"}';

const DESCRIPTOR = Object.freeze({
  amountOptions: Object.freeze([
    Object.freeze({ currency: "USD", value: "100" }),
    Object.freeze({ currency: "USD", value: "250" }),
  ]),
  chainId: "11155111",
  expirySeconds: "600",
  mandateDigest: "b".repeat(64),
  namespace: "cbv1",
  payee: Object.freeze({
    address: PAYEE_ADDRESS,
    agentId: "8678",
    displayName: "Iris",
    role: "payee",
  }),
  payer: Object.freeze({
    address: PAYER_ADDRESS,
    agentId: "8677",
    displayName: "Billy",
    role: "payer",
  }),
  paymentMoved: false,
  promptSha256:
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  protocol: "clockchain.bilateral-authorization/v1",
  protocolVersion: "1",
  registry: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
  repositorySha: "0123456789abcdef0123456789abcdef01234567",
  requestDigest: "c".repeat(64),
  schema: "clockchain.bilateral-session-descriptor/v2",
  sessionId: "00112233445566778899aabbccddeeff",
  settlement: "not-executed",
});

function cloneDescriptor() {
  return structuredClone(DESCRIPTOR);
}

function buildFixtureMessages() {
  const proposal = buildProposal({
    descriptor: cloneDescriptor(),
    sessionDigest: SESSION_DIGEST,
    amount: { currency: "USD", value: "100" },
  });
  const proposalTriple = authoritativeTriple({
    kind: "proposal",
    ledgerId: LEDGER_ID,
    blockHeight: "3375636",
    anchoredHash: H1,
  });
  const acceptance = buildAcceptance({
    proposal,
    proposalTriple,
  });
  const acceptanceTriple = authoritativeTriple({
    kind: "acceptance",
    ledgerId: LEDGER_ID,
    blockHeight: "3375637",
    anchoredHash: H2,
  });
  const acknowledgment = buildAcknowledgment({
    acceptance,
    acceptanceTriple,
    proposalTriple,
  });
  return {
    proposal,
    proposalTriple,
    acceptance,
    acceptanceTriple,
    acknowledgment,
  };
}

function assertDeepFrozen(value, seen = new Set()) {
  if (value === null || typeof value !== "object" || seen.has(value)) {
    return;
  }
  seen.add(value);
  assert.ok(Object.isFrozen(value));
  for (const key of Reflect.ownKeys(value)) {
    const property = Object.getOwnPropertyDescriptor(value, key);
    if (property && Object.hasOwn(property, "value")) {
      assertDeepFrozen(property.value, seen);
    }
  }
}

function enumerateKeyPaths(value, prefix = "") {
  const paths = [];
  for (const key of Object.keys(value)) {
    const path = prefix === "" ? key : `${prefix}.${key}`;
    paths.push(path);
    if (
      value[key] !== null &&
      typeof value[key] === "object" &&
      !Array.isArray(value[key])
    ) {
      paths.push(...enumerateKeyPaths(value[key], path));
    }
  }
  return paths.sort();
}

function assertTransitionRejected(message, code) {
  assert.throws(
    () => validateTransition(message),
    (error) => {
      assert.ok(error instanceof TransitionValidationError);
      if (code !== undefined) {
        assert.equal(error.code, code);
      }
      return true;
    },
  );
}

test("transition constants and frozen exact-key lists match the approved schema", () => {
  assert.equal(
    TRANSITION_SCHEMA,
    "clockchain.bilateral-transition/v1",
  );
  assert.deepEqual(AMOUNT_KEYS, ["currency", "moved", "value"]);
  assert.deepEqual(PAYEE_BINDING_KEYS, ["address", "agentId"]);
  assert.deepEqual(PAYER_BINDING_KEYS, [
    "address",
    "agentId",
    "reference",
  ]);
  assert.deepEqual(PREDECESSOR_TRIPLE_KEYS, [
    "anchoredHash",
    "blockHeight",
    "kind",
    "ledgerId",
  ]);
  assert.deepEqual(COMMON_HEAD_KEYS, [
    "amount",
    "expirySeconds",
    "payee",
    "payer",
    "protocol",
    "schema",
    "sessionDigest",
  ]);
  assert.deepEqual(PROPOSAL_KEYS, [
    "amount",
    "expirySeconds",
    "kind",
    "payee",
    "payer",
    "predecessor",
    "protocol",
    "schema",
    "sequence",
    "sessionDigest",
  ]);
  assert.deepEqual(ACCEPTANCE_KEYS, [
    "amount",
    "decision",
    "expirySeconds",
    "kind",
    "payee",
    "payer",
    "predecessor",
    "protocol",
    "schema",
    "sequence",
    "sessionDigest",
  ]);
  assert.deepEqual(ACKNOWLEDGMENT_KEYS, [
    "amount",
    "expirySeconds",
    "kind",
    "outcome",
    "payee",
    "payer",
    "paymentMoved",
    "predecessor",
    "proposal",
    "protocol",
    "schema",
    "sequence",
    "sessionDigest",
  ]);
  for (const list of [
    AMOUNT_KEYS,
    PAYEE_BINDING_KEYS,
    PAYER_BINDING_KEYS,
    PREDECESSOR_TRIPLE_KEYS,
    COMMON_HEAD_KEYS,
    PROPOSAL_KEYS,
    ACCEPTANCE_KEYS,
    ACKNOWLEDGMENT_KEYS,
    DERIVABLE_TRANSITION_FIELDS,
  ]) {
    assert.ok(Object.isFrozen(list));
  }
});

test("M1 derives the exact proposal head from the validated descriptor", () => {
  const { proposal } = buildFixtureMessages();
  assert.deepEqual(proposal, {
    amount: { currency: "USD", moved: false, value: "100" },
    expirySeconds: "600",
    kind: "proposal",
    payee: { address: PAYEE_ADDRESS, agentId: "8678" },
    payer: {
      address: PAYER_ADDRESS,
      agentId: "8677",
      reference:
        "eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:8677",
    },
    predecessor: null,
    protocol: "clockchain.bilateral-authorization/v1",
    schema: "clockchain.bilateral-transition/v1",
    sequence: "1",
    sessionDigest: SESSION_DIGEST,
  });
  assertDeepFrozen(proposal);
});

test("M2 copies M1 and binds the authoritative proposal triple", () => {
  const { acceptance, proposalTriple } = buildFixtureMessages();
  assert.equal(acceptance.decision, "ACCEPT");
  assert.equal(acceptance.kind, "acceptance");
  assert.equal(acceptance.sequence, "2");
  assert.deepEqual(acceptance.predecessor, proposalTriple);
  assert.deepEqual(
    Object.fromEntries(
      COMMON_HEAD_KEYS.map((key) => [key, acceptance[key]]),
    ),
    Object.fromEntries(
      COMMON_HEAD_KEYS.map((key) => [
        key,
        buildFixtureMessages().proposal[key],
      ]),
    ),
  );
  assertDeepFrozen(acceptance);
});

test("M3 copies the head and binds both authoritative triples", () => {
  const {
    acknowledgment,
    acceptance,
    acceptanceTriple,
    proposalTriple,
  } = buildFixtureMessages();
  assert.equal(acknowledgment.kind, "acknowledgment");
  assert.equal(acknowledgment.sequence, "3");
  assert.equal(acknowledgment.outcome, "ACKNOWLEDGED");
  assert.equal(acknowledgment.paymentMoved, false);
  assert.deepEqual(acknowledgment.predecessor, acceptanceTriple);
  assert.deepEqual(acknowledgment.proposal, proposalTriple);
  for (const key of COMMON_HEAD_KEYS) {
    assert.deepEqual(acknowledgment[key], acceptance[key]);
  }
  assertDeepFrozen(acknowledgment);
});

test("M1, M2, and M3 canonical bytes and SHA-256 digests are byte-pinned", () => {
  const { proposal, acceptance, acknowledgment } =
    buildFixtureMessages();
  for (const [message, bytes, digest] of [
    [proposal, M1_BYTES, H1],
    [acceptance, M2_BYTES, H2],
    [acknowledgment, M3_BYTES, H3],
  ]) {
    assert.equal(canonicalBytes(message).toString("utf8"), bytes);
    assert.equal(transitionDigest(message), digest);
  }
});

test("the fixture session digest is pinned to the deterministic Billy/Iris descriptor", () => {
  assert.equal(dSession(cloneDescriptor()), SESSION_DIGEST);
});

test("each intent digest changes the derived proposal session binding", () => {
  const baselineDescriptor = cloneDescriptor();
  const baselineSession = dSession(baselineDescriptor);
  const baselineProposal = buildProposal({
    amount: { currency: "USD", value: "100" },
    descriptor: baselineDescriptor,
    sessionDigest: baselineSession,
  });
  for (const key of ["mandateDigest", "requestDigest"]) {
    const descriptor = cloneDescriptor();
    descriptor[key] = "d".repeat(64);
    const sessionDigest = dSession(descriptor);
    const proposal = buildProposal({
      amount: { currency: "USD", value: "100" },
      descriptor,
      sessionDigest,
    });
    assert.notEqual(sessionDigest, baselineSession);
    assert.notEqual(proposal.sessionDigest, baselineProposal.sessionDigest);
    assert.notEqual(transitionDigest(proposal), transitionDigest(baselineProposal));
  }
});

test("authoritative triples have exact data keys and are detached and frozen", () => {
  const input = {
    kind: "proposal",
    ledgerId: LEDGER_ID,
    blockHeight: "3375636",
    anchoredHash: H1,
  };
  const triple = authoritativeTriple(input);
  assert.deepEqual(triple, {
    anchoredHash: H1,
    blockHeight: "3375636",
    kind: "proposal",
    ledgerId: LEDGER_ID,
  });
  input.blockHeight = "9";
  assert.equal(triple.blockHeight, "3375636");
  assertDeepFrozen(triple);
});

test("authoritative triples reject extra fields and malformed bindings", () => {
  const base = {
    kind: "proposal",
    ledgerId: LEDGER_ID,
    blockHeight: "3375636",
    anchoredHash: H1,
  };
  for (const mutation of [
    (value) => {
      value.cacheTimestamp = "2026-07-26T00:00:00Z";
    },
    (value) => {
      value.anchoredHash = H1.toUpperCase();
    },
    (value) => {
      value.blockHeight = "03375636";
    },
    (value) => {
      value.blockHeight = 3375636;
    },
    (value) => {
      value.ledgerId = "not-a-uuid";
    },
    (value) => {
      value.kind = "unknown";
    },
  ]) {
    const value = { ...base };
    mutation(value);
    assert.throws(
      () => authoritativeTriple(value),
      TransitionValidationError,
    );
  }
});

test("authoritative triples accept lowercase RFC UUID versions 1 through 8", () => {
  for (const version of "12345678") {
    for (const variant of "89ab") {
      const triple = authoritativeTriple({
        kind: "proposal",
        ledgerId:
          `370c7672-3a78-${version}c17-${variant}53c-e3037799562c`,
        blockHeight: "3375636",
        anchoredHash: H1,
      });
      assert.equal(
        triple.ledgerId,
        `370c7672-3a78-${version}c17-${variant}53c-e3037799562c`,
      );
    }
  }
});

test("authoritative triples reject nil, invalid-version, invalid-variant, and uppercase UUIDs", () => {
  for (const ledgerId of [
    "00000000-0000-0000-0000-000000000000",
    "370c7672-3a78-0c17-853c-e3037799562c",
    "370c7672-3a78-9c17-853c-e3037799562c",
    "370c7672-3a78-4c17-753c-e3037799562c",
    "370c7672-3a78-4c17-c53c-e3037799562c",
    LEDGER_ID.toUpperCase(),
  ]) {
    assert.throws(
      () =>
        authoritativeTriple({
          kind: "proposal",
          ledgerId,
          blockHeight: "3375636",
          anchoredHash: H1,
        }),
      TransitionValidationError,
      ledgerId,
    );
  }
});

test("M2 and M3 validation apply the RFC UUID contract to every triple", () => {
  const { acceptance, acknowledgment } = buildFixtureMessages();
  for (const [message, path, ledgerId] of [
    [
      acceptance,
      "predecessor",
      "00000000-0000-0000-0000-000000000000",
    ],
    [
      acknowledgment,
      "predecessor",
      "370c7672-3a78-4c17-753c-e3037799562c",
    ],
    [
      acknowledgment,
      "proposal",
      "370c7672-3a78-9c17-853c-e3037799562c",
    ],
  ]) {
    const invalid = structuredClone(message);
    invalid[path].ledgerId = ledgerId;
    assertTransitionRejected(invalid, "TRANSITION_TRIPLE");
  }
});

test("validation accepts only the three pinned kinds and sequences", () => {
  const { proposal, acceptance, acknowledgment } =
    buildFixtureMessages();
  for (const message of [proposal, acceptance, acknowledgment]) {
    assert.equal(validateTransition(message), undefined);
  }
  for (const [message, mutation] of [
    [proposal, (value) => (value.sequence = "2")],
    [proposal, (value) => (value.kind = "acceptance")],
    [acceptance, (value) => (value.decision = "REJECT")],
    [acceptance, (value) => (value.sequence = "02")],
    [acknowledgment, (value) => (value.outcome = "ACKNOWLEDGE")],
    [acknowledgment, (value) => (value.paymentMoved = true)],
  ]) {
    const invalid = structuredClone(message);
    mutation(invalid);
    assertTransitionRejected(invalid);
  }
});

test("validation rejects memo, local timestamp, and nonce free entropy", () => {
  const { proposal, acceptance, acknowledgment } =
    buildFixtureMessages();
  for (const [message, key, value] of [
    [proposal, "memo", "pay vendor"],
    [acceptance, "timestamp", "2026-07-26T00:00:00Z"],
    [acknowledgment, "nonce", "abc123"],
  ]) {
    const invalid = structuredClone(message);
    invalid[key] = value;
    assertTransitionRejected(invalid, "TRANSITION_SHAPE");
  }
});

test("constructors reject memo, local timestamp, nonce, and other extra inputs", () => {
  const { proposal, proposalTriple, acceptance, acceptanceTriple } =
    buildFixtureMessages();
  assert.throws(
    () =>
      buildProposal({
        descriptor: cloneDescriptor(),
        sessionDigest: SESSION_DIGEST,
        amount: { currency: "USD", value: "100" },
        memo: "pay vendor",
      }),
    TransitionValidationError,
  );
  assert.throws(
    () =>
      buildAcceptance({
        proposal,
        proposalTriple,
        timestamp: "2026-07-26T00:00:00Z",
      }),
    TransitionValidationError,
  );
  assert.throws(
    () =>
      buildAcknowledgment({
        acceptance,
        acceptanceTriple,
        proposalTriple,
        nonce: "abc123",
      }),
    TransitionValidationError,
  );
});

test("constructors reject non-authoritative or mismatched predecessor triples", () => {
  const { proposal, proposalTriple, acceptance, acceptanceTriple } =
    buildFixtureMessages();
  assert.throws(
    () =>
      buildAcceptance({
        proposal,
        proposalTriple: {
          ...proposalTriple,
          anchoredHash: "f".repeat(64),
        },
      }),
    TransitionValidationError,
  );
  assert.throws(
    () =>
      buildAcceptance({
        proposal,
        proposalTriple: {
          ...proposalTriple,
          kind: "acceptance",
        },
      }),
    TransitionValidationError,
  );
  assert.throws(
    () =>
      buildAcknowledgment({
        acceptance,
        acceptanceTriple: {
          ...acceptanceTriple,
          anchoredHash: "f".repeat(64),
        },
        proposalTriple,
      }),
    TransitionValidationError,
  );
  assert.throws(
    () =>
      buildAcknowledgment({
        acceptance,
        acceptanceTriple,
        proposalTriple: {
          ...proposalTriple,
          blockHeight: "3375635",
        },
      }),
    TransitionValidationError,
  );
});

test("M1 requires the descriptor digest and one exact signed amount option", () => {
  for (const amount of [
    { currency: "USD", value: "101" },
    { currency: "EUR", value: "100" },
    { currency: "USD", value: "100", moved: false },
    "100",
  ]) {
    assert.throws(
      () =>
        buildProposal({
          descriptor: cloneDescriptor(),
          sessionDigest: SESSION_DIGEST,
          amount,
        }),
      TransitionValidationError,
    );
  }
  assert.throws(
    () =>
      buildProposal({
        descriptor: cloneDescriptor(),
        sessionDigest: "f".repeat(64),
        amount: { currency: "USD", value: "100" },
      }),
    TransitionValidationError,
  );
});

test("payer agentId is bounded by the completed canonical reference", () => {
  const acceptedDescriptor = cloneDescriptor();
  acceptedDescriptor.payer.agentId = "1".repeat(197);
  const proposal = buildProposal({
    descriptor: acceptedDescriptor,
    sessionDigest: dSession(acceptedDescriptor),
    amount: { currency: "USD", value: "100" },
  });
  assert.equal(
    proposal.payer.reference.length,
    MAX_CANONICAL_STRING_LENGTH,
  );
  assert.match(transitionDigest(proposal), /^[0-9a-f]{64}$/);

  const rejectedDescriptor = cloneDescriptor();
  rejectedDescriptor.payer.agentId = "1".repeat(198);
  assert.throws(
    () => dSession(rejectedDescriptor),
    DescriptorValidationError,
  );
  assert.throws(
    () =>
      buildProposal({
        descriptor: rejectedDescriptor,
        sessionDigest: SESSION_DIGEST,
        amount: { currency: "USD", value: "100" },
      }),
    TransitionValidationError,
  );
});

test("message nested shapes and payer reference are exact", () => {
  const { proposal, acceptance, acknowledgment } =
    buildFixtureMessages();
  for (const base of [proposal, acceptance, acknowledgment]) {
    for (const mutation of [
      (value) => {
        value.amount.memo = "x";
      },
      (value) => {
        value.amount.moved = true;
      },
      (value) => {
        value.payee.displayName = "Iris";
      },
      (value) => {
        value.payer.reference =
          "eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:8678";
      },
      (value) => {
        value.payer.address = value.payer.address.toUpperCase();
      },
    ]) {
      const invalid = structuredClone(base);
      mutation(invalid);
      assertTransitionRejected(invalid);
    }
  }
});

test("transition validation and construction never invoke hostile accessors", () => {
  let reads = 0;
  const hostile = {};
  Object.defineProperty(hostile, "schema", {
    enumerable: true,
    get() {
      reads += 1;
      return TRANSITION_SCHEMA;
    },
  });
  assert.throws(
    () => validateTransition(hostile),
    TransitionValidationError,
  );
  assert.equal(reads, 0);

  const constructorInput = {};
  Object.defineProperty(constructorInput, "descriptor", {
    enumerable: true,
    get() {
      reads += 1;
      return cloneDescriptor();
    },
  });
  assert.throws(
    () => buildProposal(constructorInput),
    TransitionValidationError,
  );
  assert.equal(reads, 0);
});

test("payer agentId rejects hostile coercion shapes before reference interpolation", () => {
  let coercions = 0;
  const hostileAgentIds = [
    () => Object.create(null),
    () => ({ toString: null }),
    () => ({
      toString() {
        coercions += 1;
        return "8677";
      },
    }),
    () => "1".repeat(MAX_CANONICAL_STRING_LENGTH * 1024),
  ];
  const operations = [
    (message) => validateTransition(message),
    (message) => transitionDigest(message),
    (message) => selectUniqueProposalMatch([message]),
  ];

  for (const createAgentId of hostileAgentIds) {
    for (const operation of operations) {
      const { proposal } = buildFixtureMessages();
      const invalid = structuredClone(proposal);
      invalid.payer.agentId = createAgentId();
      assert.throws(
        () => operation(invalid),
        (error) => {
          assert.ok(
            error instanceof TransitionValidationError,
            `expected fixed transition error, got ${error?.name}`,
          );
          assert.equal(
            error.message,
            "Bilateral transition validation failed.",
          );
          return true;
        },
      );
    }
  }
  assert.equal(coercions, 0);
});

test("constructor results are detached from all mutable inputs", () => {
  const descriptor = cloneDescriptor();
  const amount = { currency: "USD", value: "100" };
  const proposal = buildProposal({
    descriptor,
    sessionDigest: SESSION_DIGEST,
    amount,
  });
  descriptor.payer.agentId = "999";
  amount.value = "250";
  assert.equal(proposal.payer.agentId, "8677");
  assert.equal(proposal.amount.value, "100");

  const tripleInput = {
    kind: "proposal",
    ledgerId: LEDGER_ID,
    blockHeight: "3375636",
    anchoredHash: H1,
  };
  const acceptance = buildAcceptance({
    proposal,
    proposalTriple: tripleInput,
  });
  tripleInput.blockHeight = "999";
  assert.equal(acceptance.predecessor.blockHeight, "3375636");
});

test("the explicit derivability allowlist contains every M2 and M3 key path", () => {
  const { acceptance, acknowledgment } = buildFixtureMessages();
  const allowlist = new Set(DERIVABLE_TRANSITION_FIELDS);
  for (const [kind, message] of [
    ["acceptance", acceptance],
    ["acknowledgment", acknowledgment],
  ]) {
    const paths = enumerateKeyPaths(message);
    assert.ok(paths.length > 0);
    for (const path of paths) {
      assert.ok(
        allowlist.has(path),
        `${kind} contains non-derivable path ${path}`,
      );
    }
  }
});

test("the derivability allowlist itself is exact and contains no free-entropy path", () => {
  assert.deepEqual(DERIVABLE_TRANSITION_FIELDS, [
    "amount",
    "amount.currency",
    "amount.moved",
    "amount.value",
    "decision",
    "expirySeconds",
    "kind",
    "outcome",
    "payee",
    "payee.address",
    "payee.agentId",
    "payer",
    "payer.address",
    "payer.agentId",
    "payer.reference",
    "paymentMoved",
    "predecessor",
    "predecessor.anchoredHash",
    "predecessor.blockHeight",
    "predecessor.kind",
    "predecessor.ledgerId",
    "proposal",
    "proposal.anchoredHash",
    "proposal.blockHeight",
    "proposal.kind",
    "proposal.ledgerId",
    "protocol",
    "schema",
    "sequence",
    "sessionDigest",
  ]);
  for (const forbidden of ["memo", "timestamp", "nonce", "writeResponse"]) {
    assert.ok(
      !DERIVABLE_TRANSITION_FIELDS.some(
        (path) => path === forbidden || path.endsWith(`.${forbidden}`),
      ),
    );
  }
});

test("amount recovery enumerates signed options and returns the unique M1 match", () => {
  const recovered = recoverProposalByDigest({
    descriptor: cloneDescriptor(),
    sessionDigest: SESSION_DIGEST,
    anchoredHash: H1,
  });
  assert.equal(transitionDigest(recovered), H1);
  assert.deepEqual(recovered.amount, {
    currency: "USD",
    moved: false,
    value: "100",
  });
  assertDeepFrozen(recovered);
});

test("amount recovery throws a distinct typed zero-match error", () => {
  assert.throws(
    () =>
      recoverProposalByDigest({
        descriptor: cloneDescriptor(),
        sessionDigest: SESSION_DIGEST,
        anchoredHash: "f".repeat(64),
      }),
    (error) => {
      assert.ok(error instanceof ProposalAmountNotFoundError);
      assert.equal(error.code, "PROPOSAL_AMOUNT_NOT_FOUND");
      assert.equal(error.category, "verification");
      assert.ok(!error.message.includes("f".repeat(64)));
      return true;
    },
  );
});

test("amount recovery normalizes invalid descriptors to the message boundary", () => {
  const descriptor = cloneDescriptor();
  descriptor.payer.agentId = "1".repeat(198);
  assert.throws(
    () =>
      recoverProposalByDigest({
        anchoredHash: H1,
        descriptor,
        sessionDigest: SESSION_DIGEST,
      }),
    TransitionValidationError,
  );
});

test("proposal match selection enforces zero, one, or multiple cardinality", () => {
  const { proposal, acceptance } = buildFixtureMessages();
  assert.throws(
    () => selectUniqueProposalMatch([]),
    ProposalAmountNotFoundError,
  );
  assert.throws(
    () => selectUniqueProposalMatch([proposal, proposal]),
    (error) => {
      assert.ok(error instanceof ProposalAmountAmbiguousError);
      assert.equal(error.code, "PROPOSAL_AMOUNT_AMBIGUOUS");
      assert.equal(error.category, "verification");
      return true;
    },
  );
  assert.throws(
    () => selectUniqueProposalMatch([acceptance]),
    TransitionValidationError,
  );

  const mutableProposal = structuredClone(proposal);
  const selected = selectUniqueProposalMatch([mutableProposal]);
  mutableProposal.amount.value = "999";
  assert.equal(selected.amount.value, "100");
  assertDeepFrozen(selected);
});

test("amount recovery rejects a second argument and cannot recover a real-digest mismatch", () => {
  assert.throws(
    () =>
      recoverProposalByDigest(
        {
          descriptor: cloneDescriptor(),
          sessionDigest: SESSION_DIGEST,
          anchoredHash: H3,
        },
        {
          candidateBuilder(input) {
            return buildProposal(input);
          },
          candidateDigest(candidate) {
            return candidate.amount.value === "100"
              ? H3
              : "f".repeat(64);
          },
        },
      ),
    TransitionValidationError,
  );
  assert.throws(
    () =>
      recoverProposalByDigest({
        descriptor: cloneDescriptor(),
        sessionDigest: SESSION_DIGEST,
        anchoredHash: H3,
      }),
    ProposalAmountNotFoundError,
  );
});

test("amount recovery validates its exact input", () => {
  assert.throws(
    () =>
      recoverProposalByDigest({
        descriptor: cloneDescriptor(),
        sessionDigest: SESSION_DIGEST,
        anchoredHash: H1,
        advisoryHash: H1,
      }),
    TransitionValidationError,
  );
});

test("transitionDigest validates before hashing and cannot hash an extra field", () => {
  const { proposal } = buildFixtureMessages();
  const invalid = structuredClone(proposal);
  invalid.writeResponse = { status: "anchored" };
  assert.throws(
    () => transitionDigest(invalid),
    TransitionValidationError,
  );
});

test("runner-side message code does not name an authorizing verdict", async () => {
  const source = await readFile(
    new URL("../src/core/messages.mjs", import.meta.url),
    "utf8",
  );
  assert.ok(!source.includes("AUTHOR" + "IZED"));
});
