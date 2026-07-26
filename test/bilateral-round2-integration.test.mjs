import assert from "node:assert/strict";
import {
  createHash,
  generateKeyPairSync,
} from "node:crypto";
import test from "node:test";

import {
  deadlineMs,
  liveUpperBoundMs,
} from "../src/bilateral/blocktime.mjs";
import {
  canonicalBytes,
} from "../src/bilateral/canonical.mjs";
import {
  createSignedEnvelope,
  dSession,
  rawPublicKeyBase64FromPem,
  verifyDescriptorEnvelope,
} from "../src/bilateral/descriptor.mjs";
import {
  PARTY_RESULT_SCHEMA,
  buildPartySignaturePreimage,
  partySignatureBytes,
  renderPartyResultMarkdown,
  validatePartyResult,
} from "../src/bilateral/evidence.mjs";
import {
  authoritativeTriple,
  buildAcceptance,
  buildAcknowledgment,
  buildProposal,
  transitionDigest,
} from "../src/bilateral/messages.mjs";
import { verifyTransition } from "../src/bilateral/protocol.mjs";
import { sessionKey } from "../src/bilateral/refid.mjs";
import {
  createFakeBilateralClockchain,
} from "./helpers/fake-bilateral-clockchain.mjs";

const PAYER_ADDRESS =
  "0x00112233445566778899aabbccddeeff00112233";
const PAYEE_ADDRESS =
  "0xffeeddccbbaa99887766554433221100ffeeddcc";
const REPOSITORY_SHA =
  "0123456789abcdef0123456789abcdef01234567";
const PROMPT_SHA256 =
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

function createDescriptor() {
  return {
    amountOptions: [
      { currency: "USD", value: "100" },
      { currency: "USD", value: "250" },
    ],
    chainId: "11155111",
    expirySeconds: "600",
    namespace: "cbv1",
    payee: {
      address: PAYEE_ADDRESS,
      agentId: "8678",
      displayName: "Iris",
      role: "payee",
    },
    payer: {
      address: PAYER_ADDRESS,
      agentId: "8677",
      displayName: "Billy",
      role: "payer",
    },
    paymentMoved: false,
    promptSha256: PROMPT_SHA256,
    protocol: "clockchain.bilateral-authorization/v1",
    protocolVersion: "1",
    registry:
      "0x8004a818bfb912233c491871b3d84c89a494bd9e",
    repositorySha: REPOSITORY_SHA,
    schema: "clockchain.bilateral-session-descriptor/v1",
    sessionId: "00112233445566778899aabbccddeeff",
    settlement: "not-executed",
  };
}

function idempotencyKey(sessionDigest, kind) {
  return createHash("sha256")
    .update(`${sessionDigest}|${kind}`, "utf8")
    .digest("hex")
    .slice(0, 32);
}

async function anchorAndVerify(fake, message) {
  const digest = transitionDigest(message);
  const referenceId = sessionKey(
    message.sessionDigest,
    message.kind,
  );
  await fake.logAction({
    allow_degraded: true,
    asset_hash: digest,
    asset_reference_id: referenceId,
    hash_type: "SHA-256",
    idempotency_key: idempotencyKey(
      message.sessionDigest,
      message.kind,
    ),
    version_number: 1,
    wait: true,
    wait_ms: 20000,
  });
  return verifyTransition({
    client: fake,
    expectedDigest: digest,
    message,
    referenceId,
  });
}

function tripleFromVerified(kind, verified) {
  return authoritativeTriple({
    anchoredHash: verified.anchoredHash,
    blockHeight: verified.blockHeight,
    kind,
    ledgerId: verified.ledgerId,
  });
}

function evidenceEntry(message, verified, index) {
  return {
    blockTimeMs: String(verified.blockTimeMs),
    blockTimeRaw: verified.blockTimeRaw,
    digest: transitionDigest(message),
    message,
    onChain: {
      anchoredHash: verified.anchoredHash,
      blockHeight: verified.blockHeight,
      ledgerId: verified.ledgerId,
    },
    upperBoundMs:
      index === 0
        ? null
        : String(liveUpperBoundMs(verified.blockTimeMs)),
  };
}

function partyResult({
  address,
  descriptor,
  role,
  sessionDigest,
  transitions,
}) {
  return {
    ackObserved: transitions.length === 3,
    deadlineMs: String(
      deadlineMs(Number(transitions[0].blockTimeMs)),
    ),
    localVerdict: "LOCAL_OK",
    paymentMoved: false,
    poolHealth: {
      degradedAtSubmission: true,
      nodeParticipationPct: "0.0",
      totalNodes: "1.0",
    },
    promptSha256: descriptor.promptSha256,
    protocolVersion: descriptor.protocolVersion,
    rendezvous: {
      channel: "derived-reference-id",
      degradedAtSubmission: true,
      tenancy: "cross-client",
    },
    repositorySha: descriptor.repositorySha,
    role,
    schema: PARTY_RESULT_SCHEMA,
    sessionDigest,
    signature: {
      address,
      algorithm: "eip191",
      signature: `0x${(
        role === "payer" ? "ab" : "cd"
      ).repeat(65)}`,
    },
    transitions,
  };
}

test("composes a complete signed $100 bilateral session through one deterministic Clockchain", async () => {
  const descriptor = createDescriptor();
  const { privateKey, publicKey } =
    generateKeyPairSync("ed25519");
  const privateKeyPem = privateKey.export({
    format: "pem",
    type: "pkcs8",
  });
  const publicKeyPem = publicKey.export({
    format: "pem",
    type: "spki",
  });
  const repositoryPublicKey =
    rawPublicKeyBase64FromPem(publicKeyPem);
  const envelope = createSignedEnvelope(descriptor, {
    keyId: "round2-integration-operator",
    privateKeyPem,
  });
  const verifiedEnvelope = verifyDescriptorEnvelope(envelope, {
    repositoryPublicKey,
  });
  const sessionDigest = dSession(descriptor);

  assert.deepEqual(verifiedEnvelope, { dSession: sessionDigest });
  assert.equal(envelope.descriptor.paymentMoved, false);

  const fake = createFakeBilateralClockchain();
  fake.registerAgent({
    agentId: descriptor.payer.agentId,
    owner: descriptor.payer.address,
    status: "active",
  });
  fake.registerAgent({
    agentId: descriptor.payee.agentId,
    owner: descriptor.payee.address,
    status: "active",
  });

  const proposal = buildProposal({
    amount: { currency: "USD", value: "100" },
    descriptor,
    sessionDigest,
  });
  const verifiedProposal = await anchorAndVerify(
    fake,
    proposal,
  );
  const proposalTriple = tripleFromVerified(
    "proposal",
    verifiedProposal,
  );

  const acceptance = buildAcceptance({
    proposal,
    proposalTriple,
  });
  const verifiedAcceptance = await anchorAndVerify(
    fake,
    acceptance,
  );
  const acceptanceTriple = tripleFromVerified(
    "acceptance",
    verifiedAcceptance,
  );

  const acknowledgment = buildAcknowledgment({
    acceptance,
    acceptanceTriple,
    proposalTriple,
  });
  const verifiedAcknowledgment = await anchorAndVerify(
    fake,
    acknowledgment,
  );

  const verified = [
    verifiedProposal,
    verifiedAcceptance,
    verifiedAcknowledgment,
  ];
  assert.deepEqual(
    verified.map(({ anchoredHash }) => anchoredHash),
    [
      transitionDigest(proposal),
      transitionDigest(acceptance),
      transitionDigest(acknowledgment),
    ],
  );
  assert.equal(new Set(verified.map(({ ledgerId }) => ledgerId)).size, 3);
  assert.ok(
    BigInt(verifiedProposal.blockHeight) <
      BigInt(verifiedAcceptance.blockHeight),
  );
  assert.ok(
    BigInt(verifiedAcceptance.blockHeight) <
      BigInt(verifiedAcknowledgment.blockHeight),
  );
  assert.ok(
    verifiedProposal.blockTimeMs <
      verifiedAcceptance.blockTimeMs,
  );
  assert.ok(
    verifiedAcceptance.blockTimeMs <
      verifiedAcknowledgment.blockTimeMs,
  );

  assert.deepEqual(acceptance.predecessor, proposalTriple);
  assert.deepEqual(
    acknowledgment.predecessor,
    acceptanceTriple,
  );
  assert.deepEqual(acknowledgment.proposal, proposalTriple);
  assert.equal(proposal.amount.moved, false);
  assert.equal(acceptance.amount.moved, false);
  assert.equal(acknowledgment.amount.moved, false);
  assert.equal(acknowledgment.paymentMoved, false);

  const transitions = [
    evidenceEntry(proposal, verifiedProposal, 0),
    evidenceEntry(acceptance, verifiedAcceptance, 1),
    evidenceEntry(
      acknowledgment,
      verifiedAcknowledgment,
      2,
    ),
  ];
  const payer = partyResult({
    address: descriptor.payer.address,
    descriptor,
    role: "payer",
    sessionDigest,
    transitions,
  });
  const payee = partyResult({
    address: descriptor.payee.address,
    descriptor,
    role: "payee",
    sessionDigest,
    transitions,
  });

  assert.equal(validatePartyResult(payer), payer);
  assert.equal(validatePartyResult(payee), payee);
  assert.equal(payer.ackObserved, true);
  assert.equal(payee.ackObserved, true);
  assert.equal(payer.paymentMoved, false);
  assert.equal(payee.paymentMoved, false);

  const payerSignatureInput = {
    role: "payer",
    sessionDigest,
    transitions,
  };
  const payeeSignatureInput = {
    role: "payee",
    sessionDigest,
    transitions,
  };
  const payerPreimage = buildPartySignaturePreimage(
    payerSignatureInput,
  );
  const payeePreimage = buildPartySignaturePreimage(
    payeeSignatureInput,
  );
  const payerBytes = partySignatureBytes(
    payerSignatureInput,
  );
  const payeeBytes = partySignatureBytes(
    payeeSignatureInput,
  );

  assert.deepEqual(
    payerPreimage.messages.map(transitionDigest),
    [
      transitionDigest(proposal),
      transitionDigest(acknowledgment),
    ],
  );
  assert.deepEqual(
    payeePreimage.messages.map(transitionDigest),
    [transitionDigest(acceptance)],
  );
  assert.deepEqual(payerBytes, canonicalBytes(payerPreimage));
  assert.deepEqual(payeeBytes, canonicalBytes(payeePreimage));
  assert.deepEqual(
    JSON.parse(payerBytes.toString("utf8")).messages.map(
      ({ kind }) => kind,
    ),
    ["proposal", "acknowledgment"],
  );
  assert.deepEqual(
    JSON.parse(payeeBytes.toString("utf8")).messages.map(
      ({ kind }) => kind,
    ),
    ["acceptance"],
  );
  assert.notDeepEqual(payerBytes, payeeBytes);

  const payerMarkdown = renderPartyResultMarkdown(payer);
  const payeeMarkdown = renderPartyResultMarkdown(payee);
  assert.equal(payerMarkdown.includes("AUTHORIZED"), false);
  assert.equal(payeeMarkdown.includes("AUTHORIZED"), false);
});
