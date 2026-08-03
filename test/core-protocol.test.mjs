import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { McpRateLimitedError } from "../src/core/clockchain.mjs";
import { parseBlockTime } from "../src/core/blocktime.mjs";
import { dSession } from "../src/core/descriptor.mjs";
import {
  ProposalAmountAmbiguousError,
  ProposalAmountNotFoundError,
  TRANSITION_SCHEMA,
  authoritativeTriple,
  buildAcceptance,
  buildAcknowledgment,
  buildProposal,
  transitionDigest,
} from "../src/core/messages.mjs";
import { sessionKey } from "../src/core/refid.mjs";
import {
  BilateralProtocolError,
  ProtocolFailureError,
  RUNNER_STATES,
  TERMINAL_FAILURE_CODES,
  WriteIntentMarkerExistsError,
  createRunnerStateMachine,
  mapProposalRecoveryFailure,
  recoverAnchoredProposal,
  verifyTransition,
} from "../src/core/protocol.mjs";
import {
  FakeClockchainError,
  createFakeBilateralClockchain,
} from "./helpers/fake-bilateral-clockchain.mjs";

const D_SESSION =
  "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
const OTHER_D_SESSION =
  "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
const K_PROPOSAL = sessionKey(D_SESSION, "proposal");
const PROPOSAL = Object.freeze({
  amount: Object.freeze({
    currency: "USD",
    moved: false,
    value: "100",
  }),
  expirySeconds: "600",
  kind: "proposal",
  payee: Object.freeze({
    address: "0xffeeddccbbaa99887766554433221100ffeeddcc",
    agentId: "8678",
  }),
  payer: Object.freeze({
    address: "0x00112233445566778899aabbccddeeff00112233",
    agentId: "8677",
    reference:
      "eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:8677",
  }),
  predecessor: null,
  protocol: "clockchain.bilateral-authorization/v1",
  schema: TRANSITION_SCHEMA,
  sequence: "1",
  sessionDigest: D_SESSION,
});
const H1 = transitionDigest(PROPOSAL);
const PROPOSAL_TRIPLE = authoritativeTriple({
  anchoredHash: H1,
  blockHeight: "3375601",
  kind: "proposal",
  ledgerId: "00000000-0000-4000-8000-000000000001",
});
const ACCEPTANCE = buildAcceptance({
  proposal: PROPOSAL,
  proposalTriple: PROPOSAL_TRIPLE,
});
const H2 = transitionDigest(ACCEPTANCE);
const ACCEPTANCE_TRIPLE = authoritativeTriple({
  anchoredHash: H2,
  blockHeight: "3375602",
  kind: "acceptance",
  ledgerId: "00000000-0000-4000-8000-000000000002",
});
const ACKNOWLEDGMENT = buildAcknowledgment({
  acceptance: ACCEPTANCE,
  acceptanceTriple: ACCEPTANCE_TRIPLE,
  proposalTriple: PROPOSAL_TRIPLE,
});
const H3 = transitionDigest(ACKNOWLEDGMENT);
const PAYER_AGENT_ID = PROPOSAL.payer.agentId;
const PAYER_ADDRESS = PROPOSAL.payer.address;
const PAYEE_AGENT_ID = PROPOSAL.payee.agentId;
const PAYEE_ADDRESS = PROPOSAL.payee.address;
const RECOVERY_DESCRIPTOR = Object.freeze({
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
    agentId: PAYEE_AGENT_ID,
    displayName: "Iris",
    role: "payee",
  }),
  payer: Object.freeze({
    address: PAYER_ADDRESS,
    agentId: PAYER_AGENT_ID,
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
const RECOVERY_D_SESSION = dSession(RECOVERY_DESCRIPTOR);
const RECOVERABLE_PROPOSAL = buildProposal({
  amount: { currency: "USD", value: "100" },
  descriptor: RECOVERY_DESCRIPTOR,
  sessionDigest: RECOVERY_D_SESSION,
});

function createSessionFake(options = {}) {
  const fake = createFakeBilateralClockchain(options);
  fake.registerAgent({
    agentId: PAYER_AGENT_ID,
    owner: PAYER_ADDRESS,
    status: "active",
  });
  fake.registerAgent({
    agentId: PAYEE_AGENT_ID,
    owner: PAYEE_ADDRESS,
    status: "active",
  });
  return fake;
}

async function writeTransition(
  fake,
  message = PROPOSAL,
  assetHash = transitionDigest(message),
) {
  return fake.logAction({
    asset_reference_id: sessionKey(D_SESSION, message.kind),
    asset_hash: assetHash,
    hash_type: "SHA-256",
    version_number: 1,
    idempotency_key: "0123456789abcdef0123456789abcdef",
    wait: true,
    wait_ms: 20000,
    allow_degraded: true,
  });
}

const writeProposal = (fake, assetHash = H1) =>
  writeTransition(fake, PROPOSAL, assetHash);

function verifyMessage(fake, message = PROPOSAL, overrides = {}) {
  return verifyTransition({
    client: fake,
    message,
    referenceId: sessionKey(D_SESSION, message.kind),
    expectedDigest: transitionDigest(message),
    ...overrides,
  });
}

const verifyProposal = (fake, overrides = {}) =>
  verifyMessage(fake, PROPOSAL, overrides);

function clientWith(fake, overrides = {}) {
  return {
    getBlock: fake.getBlock,
    resolveAgent: fake.resolveAgent,
    searchActions: fake.searchActions,
    verifyCrossParty: fake.verifyCrossParty,
    ...overrides,
  };
}

async function terminalCodeOf(promise) {
  try {
    await promise;
  } catch (error) {
    assert.ok(
      error instanceof ProtocolFailureError,
      `expected a ProtocolFailureError, got ${error.name}: ${error.message}`,
    );
    return error.terminalCode;
  }
  assert.fail("expected a terminal protocol failure");
}

// --- Section A: states, codes, errors, and the state machine ---

test("RUNNER_STATES is exactly the spec 5.1 runner-side ladder, frozen", () => {
  assert.deepEqual(RUNNER_STATES, [
    "UNSTARTED",
    "RENDEZVOUS_OK",
    "PROPOSED",
    "ACCEPTED",
    "ACKNOWLEDGED",
  ]);
  assert.ok(Object.isFrozen(RUNNER_STATES));
});

test("TERMINAL_FAILURE_CODES is exactly the spec 5.1 terminal list, frozen", () => {
  assert.deepEqual(TERMINAL_FAILURE_CODES, [
    "RENDEZVOUS_UNAVAILABLE",
    "EXPIRED",
    "DUPLICATE",
    "AMBIGUOUS_WRITE",
    "BINDING_MISMATCH",
    "ANCHOR_UNVERIFIED",
    "RATE_BLOCKED",
    "AMOUNT_UNRESOLVED",
    "FAILED",
  ]);
  assert.ok(Object.isFrozen(TERMINAL_FAILURE_CODES));
});

test("AUTHORIZED appears in no state or code list this module exports", () => {
  assert.ok(!RUNNER_STATES.includes("AUTHORIZED"));
  assert.ok(!TERMINAL_FAILURE_CODES.includes("AUTHORIZED"));
});

test("the module source never contains the AUTHORIZED literal at all", async () => {
  // The strongest pin available: the runner-side module cannot emit, name,
  // or special-case a state it does not even spell. Only the operator's
  // aggregate verifier may produce it (spec section 5.1).
  const source = await readFile(
    new URL("../src/core/protocol.mjs", import.meta.url),
    "utf8",
  );
  assert.ok(!source.includes("AUTHOR" + "IZED"));
});

test("ProtocolFailureError carries a terminal code from the frozen list", () => {
  for (const code of TERMINAL_FAILURE_CODES) {
    const error = new ProtocolFailureError("terminal.", code);
    assert.ok(error instanceof BilateralProtocolError);
    assert.equal(error.name, "ProtocolFailureError");
    assert.equal(error.code, code);
    assert.equal(error.terminalCode, code);
    assert.equal(error.category, "verification");
  }
});

test("ProtocolFailureError refuses any code outside the terminal list", () => {
  for (const invalid of [
    "AUTHOR" + "IZED",
    "LOCAL_OK",
    "expired",
    "",
    42,
    null,
    undefined,
  ]) {
    assert.throws(
      () => new ProtocolFailureError("terminal.", invalid),
      BilateralProtocolError,
      `expected rejection for ${JSON.stringify(invalid)}`,
    );
  }
});

test("state machine walks the ladder one state at a time", () => {
  const machine = createRunnerStateMachine();
  assert.equal(machine.state, "UNSTARTED");
  assert.equal(machine.failureCode, null);
  assert.equal(machine.isTerminal(), false);

  machine.advance("RENDEZVOUS_OK");
  machine.advance("PROPOSED");
  machine.advance("ACCEPTED");
  machine.advance("ACKNOWLEDGED");
  assert.equal(machine.state, "ACKNOWLEDGED");
  assert.equal(machine.failureCode, null);
});

test("state machine rejects null, undefined, and exhausted advances without changing state", () => {
  const machine = createRunnerStateMachine();
  for (const nextState of [null, undefined]) {
    assert.throws(
      () => machine.advance(nextState),
      BilateralProtocolError,
    );
    assert.equal(machine.state, "UNSTARTED");
  }

  machine.advance("RENDEZVOUS_OK");
  machine.advance("PROPOSED");
  machine.advance("ACCEPTED");
  machine.advance("ACKNOWLEDGED");
  for (const nextState of [null, undefined, "ACKNOWLEDGED"]) {
    assert.throws(
      () => machine.advance(nextState),
      BilateralProtocolError,
    );
    assert.equal(machine.state, "ACKNOWLEDGED");
    assert.equal(machine.failureCode, null);
  }
});

test("state machine rejects skipping, regressing, and unknown states", () => {
  const machine = createRunnerStateMachine();
  for (const invalid of [
    "PROPOSED", // skip
    "UNSTARTED", // self
    "ACKNOWLEDGED", // far skip
    "AUTHOR" + "IZED", // unknown by construction
    "EXPIRED", // terminal codes are not advance targets
    "",
    42,
    null,
    undefined,
  ]) {
    assert.throws(
      () => machine.advance(invalid),
      BilateralProtocolError,
      `expected rejection for ${JSON.stringify(invalid)}`,
    );
  }
  assert.equal(machine.state, "UNSTARTED");
});

test("state machine can never advance into or fail into an authorizing state", () => {
  // Exhaustive: from every reachable ladder position, every advance target
  // outside the single successor throws, so no input sequence reaches any
  // state outside the five runner states and the nine terminal codes.
  for (let position = 0; position < RUNNER_STATES.length; position += 1) {
    const machine = createRunnerStateMachine();
    for (let step = 1; step <= position; step += 1) {
      machine.advance(RUNNER_STATES[step]);
    }
    assert.throws(() => machine.fail("AUTHOR" + "IZED"), BilateralProtocolError);
    assert.throws(
      () => machine.advance("AUTHOR" + "IZED"),
      BilateralProtocolError,
    );
    assert.ok(RUNNER_STATES.includes(machine.state));
  }
});

test("fail() marks a terminal failure from any live state and locks the machine", () => {
  const machine = createRunnerStateMachine();
  machine.advance("RENDEZVOUS_OK");
  machine.fail("EXPIRED");
  assert.equal(machine.state, "RENDEZVOUS_OK");
  assert.equal(machine.failureCode, "EXPIRED");
  assert.equal(machine.isTerminal(), true);

  assert.throws(() => machine.advance("PROPOSED"), BilateralProtocolError);
  assert.throws(() => machine.fail("FAILED"), BilateralProtocolError);
  assert.equal(machine.failureCode, "EXPIRED");
});

test("fail() accepts only terminal codes", () => {
  const machine = createRunnerStateMachine();
  for (const invalid of ["LOCAL_OK", "PROPOSED", "", 42, null, undefined]) {
    assert.throws(
      () => machine.fail(invalid),
      BilateralProtocolError,
      `expected rejection for ${JSON.stringify(invalid)}`,
    );
  }
  assert.equal(machine.isTerminal(), false);
});

test("WriteIntentMarkerExistsError is typed with its own code", () => {
  const error = new WriteIntentMarkerExistsError();
  assert.ok(error instanceof BilateralProtocolError);
  assert.equal(error.code, "WRITE_INTENT_EXISTS");
});

test("protocol proposal recovery maps zero matches to AMOUNT_UNRESOLVED", () => {
  assert.throws(
    () =>
      recoverAnchoredProposal({
        anchoredHash: "f".repeat(64),
        descriptor: RECOVERY_DESCRIPTOR,
        sessionDigest: RECOVERY_D_SESSION,
      }),
    (error) => {
      assert.ok(error instanceof ProtocolFailureError);
      assert.equal(error.terminalCode, "AMOUNT_UNRESOLVED");
      return true;
    },
  );

  assert.deepEqual(
    recoverAnchoredProposal({
      anchoredHash: transitionDigest(RECOVERABLE_PROPOSAL),
      descriptor: RECOVERY_DESCRIPTOR,
      sessionDigest: RECOVERY_D_SESSION,
    }),
    RECOVERABLE_PROPOSAL,
  );
});

test("proposal recovery failure mapping is typed, terminal, and trap-safe", () => {
  for (const recoveryError of [
    new ProposalAmountNotFoundError(),
    new ProposalAmountAmbiguousError(),
  ]) {
    const mapped = mapProposalRecoveryFailure(recoveryError);
    assert.ok(mapped instanceof ProtocolFailureError);
    assert.equal(mapped.terminalCode, "AMOUNT_UNRESOLVED");
  }

  const secret = "hostile-proposal-recovery-secret";
  const hostile = new Proxy(
    {},
    {
      get() {
        throw new Error(secret);
      },
      getPrototypeOf() {
        throw new Error(secret);
      },
    },
  );
  const mapped = mapProposalRecoveryFailure(hostile);
  assert.ok(mapped instanceof ProtocolFailureError);
  assert.equal(mapped.terminalCode, "FAILED");
  assert.ok(!mapped.message.includes(secret));

  assert.throws(
    () => recoverAnchoredProposal({ hostile: secret }),
    (error) => {
      assert.ok(error instanceof ProtocolFailureError);
      assert.equal(error.terminalCode, "FAILED");
      assert.ok(!error.message.includes(secret));
      return true;
    },
  );

  const spoofed = Object.create(
    ProposalAmountNotFoundError.prototype,
  );
  const spoofMapped = mapProposalRecoveryFailure(spoofed);
  assert.ok(spoofMapped instanceof ProtocolFailureError);
  assert.ok(
    ["AMOUNT_UNRESOLVED", "FAILED"].includes(
      spoofMapped.terminalCode,
    ),
  );
});

// Fail-closed matrix coverage (design 5.5).
//
// Direct Task-4 tests:
//  2  "search result shapes distinguish rate limiting from malformed replies"
//  3  "duplicate search results fail with DUPLICATE"
//  5  "cross-party verification must be on-chain and keyless"
//  6  "every cross-party receipt binding is byte-exact"
//  7  "the message digest is recomputed and caller input cannot redefine it"
// 10  "peer identity must be active with the descriptor owner"
// 18  "missing, 502-like, and malformed block time are non-verification"
// 19  "missing or pending cross-party verification is non-verification"
// 22  "record status and cache timestamps cannot affect verification"
// 23  "package, asset, cache, and advisory fields cannot affect verification"
// 28  "validation and time advisory methods are unreachable"
//
// Exact existing targeted tests:
//  8  this file: "protocol proposal recovery maps zero matches to
//     AMOUNT_UNRESOLVED" and "proposal recovery failure mapping is typed,
//     terminal, and trap-safe"
// 13  bilateral-descriptor: "verifyDescriptorEnvelope verifies against the
//     repository key and returns dSession" plus wrong-key/tamper cases
// 15  bilateral-evidence: "rejects a predecessor triple that does not match
//     the observed one" and acknowledgment divergence
// 16  bilateral-evidence: "rejects non-increasing block heights"
// 17  bilateral-evidence: "rejects a later transition past the deadline"
// 26  bilateral-evidence: secret-shaped values, key/value scanning, and
//     validate-before-persist tests
// 27  this file: "the module source never contains the AUTHORIZED literal at
//     all" and the runner state-machine reachability test
//
// Round-3-owned open rows (not claimed complete here):
//  1 preflight rendezvous; 4 pre-deadline poll continuation; 9 mandatory
// post-write runner read-back; 11 ownerOf; 12 distinct owners; 14 package
// pins; 20 ambiguous-write runner state; 21 marker recovery; 24 refused
// write; 25 polling transport/rate-limit budget.

test("fake writes deterministic anchors and repeated references become duplicates", async () => {
  const fake = createSessionFake();
  const first = await writeProposal(fake);
  const second = await writeProposal(fake);

  assert.deepEqual(first, {
    blockHeight: "3375601",
    ledgerId: "00000000-0000-4000-8000-000000000001",
  });
  assert.deepEqual(second, {
    blockHeight: "3375602",
    ledgerId: "00000000-0000-4000-8000-000000000002",
  });
  assert.match(
    (
      await fake.getBlock({ height: first.blockHeight })
    ).blockTime,
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z$/,
  );
  assert.equal(
    (
      await fake.searchActions({
        asset_reference_id: K_PROPOSAL,
      })
    ).length,
    2,
  );
  assert.deepEqual(
    await fake.generateAuditTrail({
      asset_reference_id: K_PROPOSAL,
    }),
    { assetReferenceId: K_PROPOSAL, count: "2" },
  );
});

test("fake mutation hooks and call observations are isolated snapshots", async () => {
  let searchHookInput;
  const fake = createSessionFake({
    mutateSearch(records) {
      searchHookInput = records;
      records[0].assetHash = H2;
    },
  });
  const writeArgs = {
    allow_degraded: true,
    asset_hash: H1,
    asset_reference_id: K_PROPOSAL,
    hash_type: "SHA-256",
    idempotency_key: "0123456789abcdef0123456789abcdef",
    version_number: 1,
    wait: true,
    wait_ms: 20000,
  };
  await fake.logAction(writeArgs);
  writeArgs.asset_hash = H3;

  const first = await fake.searchActions({
    asset_reference_id: K_PROPOSAL,
  });
  first[0].assetHash = H3;
  searchHookInput[0].assetHash = H3;
  const second = await fake.searchActions({
    asset_reference_id: K_PROPOSAL,
  });

  assert.equal(second[0].assetHash, H2);
  assert.equal(fake.calls.logAction[0].asset_hash, H1);
  const observations = fake.calls;
  observations.logAction[0].asset_hash = H3;
  assert.equal(fake.calls.logAction[0].asset_hash, H1);
});

test("fake exposes missing, rate-limited, identity, block, and audit controls", async () => {
  assert.throws(
    () => createFakeBilateralClockchain({ baseHeight: "01" }),
    FakeClockchainError,
  );
  assert.throws(
    () => createFakeBilateralClockchain({ auditCount: -1 }),
    FakeClockchainError,
  );

  const missing = createSessionFake({
    auditCount: 7,
    missingBlocks: true,
    missingRecords: true,
  });
  const receipt = await writeProposal(missing);
  assert.deepEqual(
    await missing.searchActions({
      asset_reference_id: K_PROPOSAL,
    }),
    [],
  );
  assert.deepEqual(
    await missing.generateAuditTrail({
      asset_reference_id: K_PROPOSAL,
    }),
    { assetReferenceId: K_PROPOSAL, count: "7" },
  );
  await assert.rejects(
    missing.getBlock({ height: receipt.blockHeight }),
    FakeClockchainError,
  );

  const rateLimited = createSessionFake({ rateLimitSearch: true });
  await assert.rejects(
    rateLimited.searchActions({
      asset_reference_id: K_PROPOSAL,
    }),
    McpRateLimitedError,
  );
  const unknown = await missing.resolveAgent("999999");
  assert.deepEqual(unknown, {
    agentId: "999999",
    status: "unknown",
  });
  assert.equal(Object.hasOwn(unknown, "owner"), false);
});

test("fake models refused-before-storage and ambiguous-after-storage outcomes", async () => {
  const refused = createSessionFake({ refuseWrite: true });
  await assert.rejects(writeProposal(refused), (error) => {
    assert.ok(error instanceof FakeClockchainError);
    assert.equal(error.code, "FAKE_WRITE_REFUSED");
    return true;
  });
  assert.deepEqual(
    await refused.searchActions({
      asset_reference_id: K_PROPOSAL,
    }),
    [],
  );

  const ambiguous = createSessionFake({
    ambiguousWrite: "after-storage",
  });
  await assert.rejects(writeProposal(ambiguous), (error) => {
    assert.ok(error instanceof FakeClockchainError);
    assert.equal(error.code, "FAKE_AMBIGUOUS_WRITE");
    return true;
  });
  assert.equal(
    (
      await ambiguous.searchActions({
        asset_reference_id: K_PROPOSAL,
      })
    ).length,
    1,
  );
});

test("verifyTransition returns only detached frozen authoritative fields", async () => {
  const fake = createSessionFake();
  const written = await writeProposal(fake);
  const result = await verifyProposal(fake);
  const block = await fake.getBlock({ height: written.blockHeight });

  assert.deepEqual(result, {
    anchoredHash: H1,
    assetReferenceId: K_PROPOSAL,
    blockHeight: written.blockHeight,
    blockTimeMs: parseBlockTime(block.blockTime),
    blockTimeRaw: block.blockTime,
    ledgerId: written.ledgerId,
  });
  assert.deepEqual(Object.keys(result).sort(), [
    "anchoredHash",
    "assetReferenceId",
    "blockHeight",
    "blockTimeMs",
    "blockTimeRaw",
    "ledgerId",
  ]);
  assert.ok(Object.isFrozen(result));
});

test("verification calls search, cross-party, block, and identity in exact order", async () => {
  const fake = createSessionFake();
  const written = await writeProposal(fake);
  await verifyProposal(fake);

  assert.deepEqual(
    fake.callSequence.slice(1).map(({ name }) => name),
    [
      "searchActions",
      "verifyCrossParty",
      "getBlock",
      "resolveAgent",
    ],
  );
  assert.deepEqual(fake.calls.verifyCrossParty, [
    {
      blockHeight: written.blockHeight,
      ledgerId: written.ledgerId,
    },
  ]);
  assert.equal(
    Object.hasOwn(fake.calls.verifyCrossParty[0], "hash"),
    false,
  );
  assert.deepEqual(fake.calls.searchActions, [
    { asset_reference_id: K_PROPOSAL },
  ]);
  assert.deepEqual(fake.calls.resolveAgent, [PAYER_AGENT_ID]);
  const calls = fake.calls;
  calls.verifyCrossParty[0].ledgerId = "mutated";
  assert.equal(
    fake.calls.verifyCrossParty[0].ledgerId,
    written.ledgerId,
  );
});

test("verification input is exact-key, data-only, and bounded", async () => {
  const fake = createSessionFake();
  await writeProposal(fake);

  assert.equal(
    await terminalCodeOf(
      verifyProposal(fake, { extra: "not permitted" }),
    ),
    "FAILED",
  );

  let getterCalls = 0;
  const hostile = {
    client: fake,
    expectedDigest: H1,
    get message() {
      getterCalls += 1;
      return PROPOSAL;
    },
    referenceId: K_PROPOSAL,
  };
  assert.equal(
    await terminalCodeOf(verifyTransition(hostile)),
    "FAILED",
  );
  assert.equal(getterCalls, 0);

  assert.equal(
    await terminalCodeOf(
      verifyProposal(fake, {
        peerAgentId: "9".repeat(257),
        peerAddress: PAYER_ADDRESS,
      }),
    ),
    "FAILED",
  );
  assert.equal(
    await terminalCodeOf(
      verifyProposal(fake, {
        referenceId: K_PROPOSAL.toUpperCase(),
      }),
    ),
    "BINDING_MISMATCH",
  );
});

test("reference ids are derived from message session and kind before transport", async () => {
  for (const referenceId of [
    sessionKey(D_SESSION, "acceptance"),
    sessionKey(OTHER_D_SESSION, "proposal"),
  ]) {
    const fake = createSessionFake();
    assert.equal(
      await terminalCodeOf(
        verifyProposal(fake, { referenceId }),
      ),
      "BINDING_MISMATCH",
    );
    assert.deepEqual(fake.callSequence, []);
  }
});

test("a terminal one-shot verification miss fails with EXPIRED", async () => {
  // Round 3's poller owns pre-deadline continuation. This function is the
  // terminal verifier after discovery/poll exhaustion, so an empty result
  // cannot be treated as a soft success here.
  const fake = createSessionFake();
  assert.equal(await terminalCodeOf(verifyProposal(fake)), "EXPIRED");
});

test("duplicate search results fail with DUPLICATE", async () => {
  const fake = createSessionFake({ duplicateSearch: true });
  await writeProposal(fake);
  assert.equal(await terminalCodeOf(verifyProposal(fake)), "DUPLICATE");
});

test("search result shapes distinguish rate limiting from malformed replies", async () => {
  for (const options of [
    { rateLimitBody: true },
    { rateLimitSearch: true },
  ]) {
    const fake = createSessionFake(options);
    await writeProposal(fake);
    assert.equal(
      await terminalCodeOf(verifyProposal(fake)),
      "RATE_BLOCKED",
    );
  }

  const malformed = createSessionFake({ nonArraySearch: true });
  await writeProposal(malformed);
  assert.equal(
    await terminalCodeOf(verifyProposal(malformed)),
    "FAILED",
  );

  const hostileArray = createSessionFake({
    mutateSearch(records) {
      return new Proxy(records, {
        getOwnPropertyDescriptor(_target, key) {
          if (key === "length" || key === "0") {
            throw new Error("hostile search trap");
          }
          return Reflect.getOwnPropertyDescriptor(records, key);
        },
      });
    },
  });
  await writeProposal(hostileArray);
  assert.equal(
    await terminalCodeOf(verifyProposal(hostileArray)),
    "FAILED",
  );

  const direct = createSessionFake();
  await writeProposal(direct);
  let directSearchCalled = false;
  const directClient = {
    getBlock: direct.getBlock,
    resolveAgent: direct.resolveAgent,
    searchActions: async () => {
      directSearchCalled = true;
      return new Proxy([], {
        get() {
          throw new Error("hostile array get trap");
        },
      });
    },
    verifyCrossParty: direct.verifyCrossParty,
  };
  assert.equal(
    await terminalCodeOf(verifyProposal(directClient)),
    "FAILED",
  );
  assert.equal(directSearchCalled, true);
});

test("every read step maps McpRateLimitedError to RATE_BLOCKED", async () => {
  for (const method of [
    "searchActions",
    "verifyCrossParty",
    "getBlock",
    "resolveAgent",
  ]) {
    const fake = createSessionFake();
    await writeProposal(fake);
    const client = clientWith(fake, {
      async [method]() {
        throw new McpRateLimitedError(
          "rate-limited test response",
          { retryAfterMs: 20000 },
        );
      },
    });
    assert.equal(
      await terminalCodeOf(verifyProposal(client)),
      "RATE_BLOCKED",
      method,
    );
  }
});

test("hostile thrown objects cannot escape fixed typed failures or echo text", async () => {
  const secret = "attacker-controlled-secret-text";
  for (const [method, expectedCode] of [
    ["searchActions", "FAILED"],
    ["verifyCrossParty", "ANCHOR_UNVERIFIED"],
    ["getBlock", "ANCHOR_UNVERIFIED"],
    ["resolveAgent", "FAILED"],
  ]) {
    const hostileError = new Proxy(
      {},
      {
        get() {
          throw new Error(secret);
        },
        getPrototypeOf() {
          throw new Error(secret);
        },
      },
    );
    const fake = createSessionFake();
    await writeProposal(fake);
    const client = clientWith(fake, {
      async [method]() {
        throw hostileError;
      },
    });

    try {
      await verifyProposal(client);
      assert.fail("expected fixed fail-closed rejection");
    } catch (error) {
      assert.ok(error instanceof ProtocolFailureError);
      assert.equal(error.terminalCode, expectedCode);
      assert.ok(!error.message.includes(secret));
    }
  }
});

test("search cardinality and index traps are handled without invoking getters", async () => {
  const fake = createSessionFake();
  await writeProposal(fake);
  const [record] = await fake.searchActions({
    asset_reference_id: K_PROPOSAL,
  });

  let lengthGets = 0;
  const hostileLength = new Proxy([record], {
    get(target, key, receiver) {
      if (key === "length") {
        lengthGets += 1;
        throw new Error("hostile length getter text");
      }
      return Reflect.get(target, key, receiver);
    },
  });
  const lengthClient = clientWith(fake, {
    searchActions() {
      return hostileLength;
    },
  });
  assert.equal(
    (await verifyProposal(lengthClient)).anchoredHash,
    H1,
  );
  assert.equal(lengthGets, 0);

  let indexGets = 0;
  const hostileIndex = [];
  Object.defineProperty(hostileIndex, "0", {
    configurable: true,
    enumerable: true,
    get() {
      indexGets += 1;
      throw new Error("hostile index getter text");
    },
  });
  hostileIndex.length = 1;
  const indexClient = clientWith(fake, {
    searchActions() {
      return hostileIndex;
    },
  });
  assert.equal(
    await terminalCodeOf(verifyProposal(indexClient)),
    "FAILED",
  );
  assert.equal(indexGets, 0);
});

test("a protocol-like hostile proxy cannot be rethrown as a trusted failure", async () => {
  const secret = "forged-protocol-error-secret";
  const protocolLike = new Proxy(
    Object.create(ProtocolFailureError.prototype),
    {
      get() {
        throw new Error(secret);
      },
    },
  );
  const hostileArray = new Proxy([], {
    get(target, key, receiver) {
      if (key === "then") {
        return undefined;
      }
      return Reflect.get(target, key, receiver);
    },
    getOwnPropertyDescriptor() {
      throw protocolLike;
    },
  });
  const fake = createSessionFake();
  await writeProposal(fake);
  const client = clientWith(fake, {
    searchActions() {
      return hostileArray;
    },
  });

  try {
    await verifyProposal(client);
    assert.fail("expected fixed fail-closed rejection");
  } catch (error) {
    assert.notEqual(error, protocolLike);
    assert.ok(error instanceof ProtocolFailureError);
    assert.equal(error.terminalCode, "FAILED");
    assert.ok(!error.message.includes(secret));
  }
});

test("search reference-id divergence is FAILED before peer reliance", async () => {
  const fake = createSessionFake({
    mutateSearch(records) {
      records[0].assetReferenceId =
        "cbv1:" + OTHER_D_SESSION + ":proposal";
    },
  });
  await writeProposal(fake);
  assert.equal(
    await terminalCodeOf(verifyProposal(fake)),
    "FAILED",
  );
  assert.equal(fake.calls.verifyCrossParty.length, 0);
});

test("search hash and hash-type divergence fail with BINDING_MISMATCH", async () => {
  for (const mutateSearch of [
    (records) => {
      records[0].assetHash = H2;
    },
    (records) => {
      records[0].hashType = "sha256";
    },
  ]) {
    const fake = createSessionFake({ mutateSearch });
    await writeProposal(fake);
    assert.equal(
      await terminalCodeOf(verifyProposal(fake)),
      "BINDING_MISMATCH",
    );
  }
});

test("cross-party verification must be on-chain and keyless", async () => {
  for (const mutateCrossParty of [
    (result) => {
      result.onChain.verifiedAgainst = "none";
    },
    (result) => {
      result.onChain.keyless = false;
    },
  ]) {
    const fake = createSessionFake({ mutateCrossParty });
    await writeProposal(fake);
    assert.equal(
      await terminalCodeOf(verifyProposal(fake)),
      "ANCHOR_UNVERIFIED",
    );
  }
});

test("missing or pending cross-party verification is non-verification", async () => {
  const fake = createSessionFake({
    mutateCrossParty() {
      return {
        onChain: {
          anchoredHash: null,
          assetReferenceId: null,
          blockHeight: "3375601",
          keyless: false,
          ledgerId: "00000000-0000-4000-8000-000000000099",
          verifiedAgainst: "none",
        },
      };
    },
  });
  await writeProposal(fake);
  assert.equal(
    await terminalCodeOf(verifyProposal(fake)),
    "ANCHOR_UNVERIFIED",
  );
});

test("every cross-party receipt binding is byte-exact", async () => {
  const mutations = [
    (result) => {
      result.onChain.ledgerId =
        "00000000-0000-4000-8000-000000000099";
    },
    (result) => {
      result.onChain.blockHeight = "3375602";
    },
    (result) => {
      result.onChain.anchoredHash = H2;
    },
    (result) => {
      result.onChain.assetReferenceId =
        "cbv1:" + OTHER_D_SESSION + ":proposal";
    },
  ];
  for (const mutateCrossParty of mutations) {
    const fake = createSessionFake({ mutateCrossParty });
    await writeProposal(fake);
    assert.equal(
      await terminalCodeOf(verifyProposal(fake)),
      "BINDING_MISMATCH",
    );
  }
});

test("the message digest is recomputed and caller input cannot redefine it", async () => {
  const fake = createSessionFake();
  await writeProposal(fake);
  const changedMessage = structuredClone(PROPOSAL);
  changedMessage.amount.value = "101";
  const changedDigest = transitionDigest(changedMessage);

  assert.equal(
    await terminalCodeOf(
      verifyProposal(fake, {
        expectedDigest: changedDigest,
        message: changedMessage,
      }),
    ),
    "BINDING_MISMATCH",
  );
  assert.equal(
    await terminalCodeOf(
      verifyProposal(fake, { expectedDigest: H2 }),
    ),
    "BINDING_MISMATCH",
  );
});

test("wrong-height advisory success cannot repair on-chain non-verification", async () => {
  const fake = createSessionFake({
    mutateCrossParty(result) {
      result.onChain.verifiedAgainst = "none";
      result.onChain.keyless = false;
      Object.defineProperty(result, "advisoryHashCheck", {
        enumerable: true,
        get() {
          throw new Error("advisory hash must not be read");
        },
      });
    },
  });
  await writeProposal(fake);
  assert.equal(
    await terminalCodeOf(verifyProposal(fake)),
    "ANCHOR_UNVERIFIED",
  );
});

test("missing, 502-like, and malformed block time are non-verification", async () => {
  const missing = createSessionFake({ missingBlocks: true });
  await writeProposal(missing);
  assert.equal(
    await terminalCodeOf(verifyProposal(missing)),
    "ANCHOR_UNVERIFIED",
  );

  const malformed = createSessionFake({
    mutateBlock(block) {
      block.blockTime = "24-07-2026_20:08:42:979";
    },
  });
  await writeProposal(malformed);
  assert.equal(
    await terminalCodeOf(verifyProposal(malformed)),
    "ANCHOR_UNVERIFIED",
  );
});

test("an independently fetched wrong block height is BINDING_MISMATCH", async () => {
  const fake = createSessionFake({
    mutateBlock(block) {
      block.blockHeight = String(Number(block.blockHeight) + 1);
    },
  });
  await writeProposal(fake);
  assert.equal(
    await terminalCodeOf(verifyProposal(fake)),
    "BINDING_MISMATCH",
  );
});

test("a malformed independently fetched block height is FAILED", async () => {
  const fake = createSessionFake({
    mutateBlock(block) {
      block.blockHeight = "01";
    },
  });
  await writeProposal(fake);
  assert.equal(
    await terminalCodeOf(verifyProposal(fake)),
    "FAILED",
  );
});

test("peer identity status is non-authoritative while the descriptor owner remains required", async () => {
  for (const resolveAgent of [
    async () => ({
      owner: PAYER_ADDRESS,
      status: "inactive",
    }),
    async () => ({ owner: PAYER_ADDRESS }),
    async () => {
      const identity = { owner: PAYER_ADDRESS };
      Object.defineProperty(identity, "status", {
        enumerable: true,
        get() {
          throw new Error("status must not be read");
        },
      });
      return identity;
    },
  ]) {
    const fake = createSessionFake();
    await writeProposal(fake);
    const verified = await verifyProposal(
      clientWith(fake, { resolveAgent }),
    );
    assert.equal(verified.anchoredHash, H1);
  }

  const mismatched = createSessionFake({
    mismatchedIdentityOwner:
      "0x9999999999999999999999999999999999999999",
  });
  await writeProposal(mismatched);
  assert.equal(
    await terminalCodeOf(verifyProposal(mismatched)),
    "FAILED",
  );

  const missing = createFakeBilateralClockchain();
  await writeProposal(missing);
  assert.equal(
    await terminalCodeOf(verifyProposal(missing)),
    "FAILED",
  );
});

test("transition kind derives the author identity for all three slots", async () => {
  const cases = [
    {
      agentId: PAYER_AGENT_ID,
      address: PAYER_ADDRESS,
      message: PROPOSAL,
    },
    {
      agentId: PAYEE_AGENT_ID,
      address: PAYEE_ADDRESS,
      message: ACCEPTANCE,
    },
    {
      agentId: PAYER_AGENT_ID,
      address: PAYER_ADDRESS,
      message: ACKNOWLEDGMENT,
    },
  ];

  for (const { agentId, address, message } of cases) {
    const fake = createSessionFake();
    fake.registerAgent({
      agentId: "9999",
      owner: "0x9999999999999999999999999999999999999999",
      status: "active",
    });
    await writeTransition(fake, message);
    const result = await verifyMessage(fake, message);
    assert.equal(result.anchoredHash, transitionDigest(message));
    assert.deepEqual(fake.calls.resolveAgent, [agentId]);
    assert.notEqual(address, "0x9999999999999999999999999999999999999999");
  }
});

test("an unrelated active identity cannot substitute for the transition author", async () => {
  const fake = createFakeBilateralClockchain();
  fake.registerAgent({
    agentId: "9999",
    owner: "0x9999999999999999999999999999999999999999",
    status: "active",
  });
  await writeTransition(fake, ACCEPTANCE);
  assert.equal(
    await terminalCodeOf(verifyMessage(fake, ACCEPTANCE)),
    "FAILED",
  );
  assert.deepEqual(fake.calls.resolveAgent, [PAYEE_AGENT_ID]);
});

test("peer owner comparison is case-insensitive", async () => {
  const fake = createFakeBilateralClockchain();
  fake.registerAgent({
    agentId: PAYER_AGENT_ID,
    owner: PAYER_ADDRESS.toUpperCase().replace("0X", "0x"),
    status: "active",
  });
  await writeProposal(fake);
  const result = await verifyProposal(fake);
  assert.equal(result.anchoredHash, H1);
});

test("malformed generic service shapes map to FAILED", async () => {
  const malformedSearchRecord = createSessionFake({
    mutateSearch(records) {
      return [{ ledgerId: records[0].ledgerId }];
    },
  });
  await writeProposal(malformedSearchRecord);
  assert.equal(
    await terminalCodeOf(verifyProposal(malformedSearchRecord)),
    "FAILED",
  );

  const malformedCrossParty = createSessionFake({
    mutateCrossParty() {
      return { onChain: null };
    },
  });
  await writeProposal(malformedCrossParty);
  assert.equal(
    await terminalCodeOf(verifyProposal(malformedCrossParty)),
    "FAILED",
  );
});

test("forged anchored hash, reference, and rehydrated event hash cannot pass", async () => {
  const cases = [
    {
      expectedCode: "BINDING_MISMATCH",
      mutateCrossParty(result) {
        result.onChain.anchoredHash = H3;
      },
    },
    {
      expectedCode: "BINDING_MISMATCH",
      mutateCrossParty(result) {
        result.onChain.assetReferenceId =
          "cbv1:" + OTHER_D_SESSION + ":proposal";
      },
    },
    {
      expectedCode: null,
      mutateCrossParty(result) {
        Object.defineProperty(result, "eventHash", {
          enumerable: true,
          get() {
            throw new Error("rehydrated event hash must not be read");
          },
        });
      },
    },
  ];
  for (const { expectedCode, mutateCrossParty } of cases) {
    const fake = createSessionFake({ mutateCrossParty });
    await writeProposal(fake);
    const outcome = verifyProposal(fake);
    if (expectedCode === null) {
      assert.equal((await outcome).anchoredHash, H1);
    } else {
      assert.equal(
        await terminalCodeOf(outcome),
        expectedCode,
      );
    }
  }
});

test("record status and cache timestamps cannot affect verification", async () => {
  const fake = createSessionFake({
    mutateSearch(records) {
      for (const name of [
        "status",
        "createdTimestamp",
        "updatedTimestamp",
        "additionalInfo",
        "versionNumber",
        "assetName",
        "type",
      ]) {
        Object.defineProperty(records[0], name, {
          enumerable: true,
          get() {
            throw new Error(`${name} must not be read`);
          },
        });
      }
    },
  });
  await writeProposal(fake);
  assert.equal((await verifyProposal(fake)).anchoredHash, H1);
});

test("package, asset, cache, and advisory fields cannot affect verification", async () => {
  const fake = createSessionFake({
    mutateCrossParty(result) {
      for (const name of [
        "advisoryHashCheck",
        "record",
        "verify_package",
        "verify_asset",
        "additionalInfo",
        "versionNumber",
        "assetName",
        "type",
        "createdTimestamp",
        "updatedTimestamp",
        "block",
        "validation",
      ]) {
        Object.defineProperty(result, name, {
          enumerable: true,
          get() {
            throw new Error(`${name} must not be read`);
          },
        });
      }
    },
    mutateBlock(block) {
      for (const name of [
        "createdTimestamp",
        "updatedTimestamp",
        "validation",
      ]) {
        Object.defineProperty(block, name, {
          enumerable: true,
          get() {
            throw new Error(`${name} must not be read`);
          },
        });
      }
    },
  });
  await writeProposal(fake);
  assert.equal((await verifyProposal(fake)).anchoredHash, H1);
});

test("validation and time advisory methods are unreachable", async () => {
  const fake = createSessionFake();
  await writeProposal(fake);
  assert.equal((await verifyProposal(fake)).anchoredHash, H1);
  assert.deepEqual(Object.keys(fake.calls).sort(), [
    "generateAuditTrail",
    "getBlock",
    "logAction",
    "resolveAgent",
    "searchActions",
    "verifyCrossParty",
  ]);
  assert.equal(fake.calls.generateAuditTrail.length, 0);
});
