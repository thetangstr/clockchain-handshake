// Shared bilateral session fixture: signed intent envelopes, a signed
// descriptor, a writer chain carrying the three anchors, signed party
// evidence on disk, and a seeded in-process relay. Used by the
// verifier-run tests and the negative-checks harness.

import { createHash, generateKeyPairSync } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  generatePrivateKey,
  privateKeyToAccount,
} from "viem/accounts";

import {
  deadlineMs,
  liveUpperBoundMs,
} from "../../src/core/blocktime.mjs";
import { McpNetworkError } from "../../src/core/clockchain.mjs";
import {
  createSignedEnvelope,
  dSession,
  rawPublicKeyBase64FromPem,
} from "../../src/core/descriptor.mjs";
import {
  PARTY_RESULT_SCHEMA,
  partySignatureBytes,
  writePartyResult,
} from "../../src/core/evidence.mjs";
import {
  authoritativeTriple,
  buildAcceptance,
  buildAcknowledgment,
  buildProposal,
  transitionDigest,
} from "../../src/core/messages.mjs";
import {
  payerMandateDigest,
  signPayerMandate,
} from "../../src/core/payer-mandate.mjs";
import {
  paymentRequestDigest,
  signPaymentRequest,
} from "../../src/core/payment-request.mjs";
import { verifyTransition } from "../../src/core/protocol.mjs";
import { sessionKey } from "../../src/core/refid.mjs";
import { createRelayClient } from "../../src/relay/client.mjs";
import { createRelayServer } from "../../src/relay/server.mjs";
import { RELAY_KINDS } from "../../src/roles/catalog.mjs";
import {
  createFakeBilateralClockchain,
} from "./fake-bilateral-clockchain.mjs";

export const PAYER = privateKeyToAccount(generatePrivateKey());
export const PAYEE = privateKeyToAccount(generatePrivateKey());
export const REPOSITORY_SHA =
  "0123456789abcdef0123456789abcdef01234567";
export const PROMPT_SHA256 = "a".repeat(64);
const INTAKE_DIGEST = "b".repeat(64);
const INTAKE_REQUEST_ID =
  "22222222-3333-4444-8555-666666666666";
export const KEY_ID = "verdict-test-operator";
export const RELAY_SESSION_ID =
  "4a7d2e56-9c3b-4f1a-8d2e-5b6c7d8e9f0a";

function descriptorFixture({ mandateDigest, requestDigest }) {
  return {
    amountOptions: [
      { currency: "USD", value: "100" },
      { currency: "USD", value: "250" },
    ],
    chainId: "11155111",
    expirySeconds: "600",
    mandateDigest,
    namespace: "cbv1",
    payee: {
      address: PAYEE.address.toLowerCase(),
      agentId: "8678",
      displayName: "Iris",
      role: "payee",
    },
    payer: {
      address: PAYER.address.toLowerCase(),
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
    requestDigest,
    schema: "clockchain.bilateral-session-descriptor/v2",
    sessionId: "00112233445566778899aabbccddeeff",
    settlement: "not-executed",
  };
}

async function intentEnvelopes({ subjectRun }) {
  const sessionId = "00112233-4455-6677-8899-aabbccddeeff";
  const mandate = {
    amount: { currency: "USD", value: "100" },
    expiresAtMs: "1784923800000",
    intakeDigest: INTAKE_DIGEST,
    intakeRequestId: INTAKE_REQUEST_ID,
    invoiceReferencePrefix: "INV-",
    issuedAtMs: "1784923100000",
    payee: {
      address: PAYEE.address.toLowerCase(),
      agentId: "8678",
    },
    payer: {
      address: PAYER.address.toLowerCase(),
      agentId: "8677",
    },
    paymentMoved: false,
    protocol: "clockchain.bilateral-authorization/v1",
    purpose: "Invoice settlement",
    releaseId: "release-1",
    repositorySha: REPOSITORY_SHA,
    requestEndpoint:
      `/v1/sessions/${sessionId}/payment-requests`,
    schema: "clockchain.bilateral-payer-mandate/v1",
    sessionId,
    subjectRun,
  };
  const mandateEnvelope = await signPayerMandate({
    mandate,
    signMessage: (raw) =>
      PAYER.signMessage({ message: { raw } }),
  });
  const requestEnvelope = await signPaymentRequest({
    request: {
      amount: mandate.amount,
      createdAtMs: "1784923150000",
      expiresAtMs: "1784923700000",
      intakeDigest: mandate.intakeDigest,
      intakeRequestId: mandate.intakeRequestId,
      invoiceReference: "INV-0001",
      mandateDigest: payerMandateDigest(mandateEnvelope),
      payee: mandate.payee,
      payer: mandate.payer,
      paymentMoved: false,
      protocol: mandate.protocol,
      purpose: mandate.purpose,
      releaseId: mandate.releaseId,
      repositorySha: mandate.repositorySha,
      requestId: "00000000-0000-4000-8000-000000000001",
      schema: "clockchain.bilateral-payment-request/v1",
      sessionId,
      subjectRun: mandate.subjectRun,
    },
    signMessage: (raw) =>
      PAYEE.signMessage({ message: { raw } }),
  });
  return Object.freeze({ mandateEnvelope, requestEnvelope });
}

function idempotencyKey(sessionDigest, kind) {
  return createHash("sha256")
    .update(`${sessionDigest}|${kind}`, "utf8")
    .digest("hex")
    .slice(0, 32);
}

async function anchor(fake, message) {
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
    message,
    referenceId,
  });
}

async function plantRecord(fake, sessionDigest, kind, digest) {
  await fake.logAction({
    allow_degraded: true,
    asset_hash: digest,
    asset_reference_id: sessionKey(sessionDigest, kind),
    hash_type: "SHA-256",
    idempotency_key: idempotencyKey(sessionDigest, kind),
    version_number: 1,
    wait: true,
    wait_ms: 20000,
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
  descriptor,
  role,
  sessionDigest,
  transitions,
}) {
  return {
    ackObserved: true,
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
      address: descriptor[role].address,
      algorithm: "eip191",
      signature: `0x${"00".repeat(65)}`,
    },
    transitions,
  };
}

function clockchainWith(clockchain, overrides = {}) {
  return {
    generateAuditTrail:
      overrides.generateAuditTrail ??
      clockchain.generateAuditTrail.bind(clockchain),
    getBlock:
      overrides.getBlock ??
      clockchain.getBlock.bind(clockchain),
    resolveAgent:
      overrides.resolveAgent ??
      clockchain.resolveAgent.bind(clockchain),
    searchActions:
      overrides.searchActions ??
      clockchain.searchActions.bind(clockchain),
    verifyCrossParty:
      overrides.verifyCrossParty ??
      clockchain.verifyCrossParty.bind(clockchain),
  };
}

async function evidenceTriple(directory) {
  return {
    json: await readFile(
      join(directory, "party-result.json"),
      "utf8",
    ),
    markdown: await readFile(
      join(directory, "PARTY-RESULT.md"),
      "utf8",
    ),
    marker: await readFile(
      join(directory, ".party-result.complete.json"),
      "utf8",
    ),
  };
}

export function captureStdout() {
  const lines = [];
  return {
    lines,
    write(chunk) {
      lines.push(String(chunk));
      return true;
    },
  };
}

// Builds the complete session: signed intent envelopes, a signed
// descriptor, a writer chain carrying all three anchors, signed party
// evidence on disk, and a seeded in-process relay. Returns everything
// a verifier-run test needs, including a fresh verifier chain whose
// slot population is controlled by the anchors mode.
export async function buildFixture(
  t,
  {
    subjectRun = "stakeholder",
    anchors = "all",
    evidence = true,
    descriptorMessage = true,
    duplicateMandate = false,
    tamperMandate = false,
  } = {},
) {
  const cleanups = [];
  const defer = (fn) => {
    if (t) {
      t.after(fn);
    } else {
      cleanups.push(fn);
    }
  };
  const { mandateEnvelope, requestEnvelope } =
    await intentEnvelopes({ subjectRun });
  const descriptor = descriptorFixture({
    mandateDigest: payerMandateDigest(mandateEnvelope),
    requestDigest: paymentRequestDigest(requestEnvelope),
  });
  const sessionDigest = dSession(descriptor);
  const { privateKey, publicKey } =
    generateKeyPairSync("ed25519");
  const operatorPrivateKeyPem = privateKey.export({
    format: "pem",
    type: "pkcs8",
  });
  const operatorPublicKeyPem = publicKey.export({
    format: "pem",
    type: "spki",
  });
  const repositoryPublicKey = rawPublicKeyBase64FromPem(
    operatorPublicKeyPem,
  );
  const descriptorEnvelope = createSignedEnvelope(
    descriptor,
    { keyId: KEY_ID, privateKeyPem: operatorPrivateKeyPem },
  );

  const writer = createFakeBilateralClockchain();
  for (const role of ["payer", "payee"]) {
    writer.registerAgent({
      agentId: descriptor[role].agentId,
      owner: descriptor[role].address,
      status: "active",
    });
  }
  const proposal = buildProposal({
    amount: { currency: "USD", value: "100" },
    descriptor,
    sessionDigest,
  });
  const verifiedProposal = await anchor(writer, proposal);
  const proposalTriple = authoritativeTriple({
    anchoredHash: verifiedProposal.anchoredHash,
    blockHeight: verifiedProposal.blockHeight,
    kind: "proposal",
    ledgerId: verifiedProposal.ledgerId,
  });
  const acceptance = buildAcceptance({
    proposal,
    proposalTriple,
  });
  const verifiedAcceptance = await anchor(writer, acceptance);
  const acceptanceTriple = authoritativeTriple({
    anchoredHash: verifiedAcceptance.anchoredHash,
    blockHeight: verifiedAcceptance.blockHeight,
    kind: "acceptance",
    ledgerId: verifiedAcceptance.ledgerId,
  });
  const acknowledgment = buildAcknowledgment({
    acceptance,
    acceptanceTriple,
    proposalTriple,
  });
  const verifiedAcknowledgment = await anchor(
    writer,
    acknowledgment,
  );
  const transitions = [
    evidenceEntry(proposal, verifiedProposal, 0),
    evidenceEntry(acceptance, verifiedAcceptance, 1),
    evidenceEntry(acknowledgment, verifiedAcknowledgment, 2),
  ];

  const root = await mkdtemp(
    join(tmpdir(), "verifier-run-"),
  );
  defer(() => rm(root, { recursive: true, force: true }));
  const payerDirectory = join(root, "payer");
  const payeeDirectory = join(root, "payee");
  const payer = partyResult({
    descriptor,
    role: "payer",
    sessionDigest,
    transitions,
  });
  const payee = partyResult({
    descriptor,
    role: "payee",
    sessionDigest,
    transitions,
  });
  payer.signature.signature = await PAYER.signMessage({
    message: {
      raw: partySignatureBytes({
        role: "payer",
        sessionDigest,
        transitions,
      }),
    },
  });
  payee.signature.signature = await PAYEE.signMessage({
    message: {
      raw: partySignatureBytes({
        role: "payee",
        sessionDigest,
        transitions,
      }),
    },
  });
  await writePartyResult({
    directory: payerDirectory,
    result: payer,
  });
  await writePartyResult({
    directory: payeeDirectory,
    result: payee,
  });

  const relayStateDir = await mkdtemp(
    join(tmpdir(), "verifier-run-relay-"),
  );
  defer(() =>
    rm(relayStateDir, { recursive: true, force: true }),
  );
  const server = createRelayServer({
    stateDir: relayStateDir,
  });
  const address = await server.listen();
  defer(() => server.close());
  const relayUrl = `http://127.0.0.1:${address.port}`;
  const relay = createRelayClient({ relayUrl });
  await relay.createSession({
    senderKey: "operator-key",
    sessionId: RELAY_SESSION_ID,
    sig: "cafe",
    subjectRun,
  });
  const send = (kind, role, senderKey, seq, body) =>
    relay.sendMessage({
      body,
      kind,
      role,
      senderKey,
      seq,
      sessionId: RELAY_SESSION_ID,
      sig: "deadbeef",
    });
  const relayedMandateEnvelope = tamperMandate
    ? {
        ...mandateEnvelope,
        signature: {
          ...mandateEnvelope.signature,
          value:
            mandateEnvelope.signature.value.slice(0, -2) +
            (mandateEnvelope.signature.value.endsWith("00")
              ? "01"
              : "00"),
        },
      }
    : mandateEnvelope;
  await send(
    RELAY_KINDS.MANDATE_PUBLISHED,
    "payer",
    "payer-key",
    0,
    { envelope: relayedMandateEnvelope },
  );
  if (duplicateMandate) {
    await send(
      RELAY_KINDS.MANDATE_PUBLISHED,
      "payer",
      "payer-key",
      1,
      { envelope: { tampered: true } },
    );
  }
  await send(
    RELAY_KINDS.PAYMENT_REQUEST_SIGNED,
    "payee",
    "payee-key",
    0,
    { envelope: requestEnvelope },
  );
  if (descriptorMessage) {
    await send(
      RELAY_KINDS.DESCRIPTOR_PUBLISHED,
      "operator",
      "operator-key",
      0,
      { envelope: descriptorEnvelope },
    );
  }
  if (evidence) {
    await relay.putEvidence(
      RELAY_SESSION_ID,
      "payer",
      await evidenceTriple(payerDirectory),
    );
    await relay.putEvidence(
      RELAY_SESSION_ID,
      "payee",
      await evidenceTriple(payeeDirectory),
    );
  }

  // The verifier reads a chain whose slot population matches the
  // requested mode; the writer chain always carries the full set so
  // the evidence fixtures stay well-formed.
  let verifier;
  if (anchors === "all") {
    verifier = writer;
  } else {
    verifier = createFakeBilateralClockchain();
    for (const role of ["payer", "payee"]) {
      verifier.registerAgent({
        agentId: descriptor[role].agentId,
        owner: descriptor[role].address,
        status: "active",
      });
    }
    if (anchors === "reordered") {
      await plantRecord(
        verifier,
        sessionDigest,
        "acceptance",
        transitionDigest(acceptance),
      );
      await plantRecord(
        verifier,
        sessionDigest,
        "acknowledgment",
        transitionDigest(acknowledgment),
      );
    }
  }
  const verifierClockchain = clockchainWith(verifier, {
    async getBlock(args) {
      try {
        return await verifier.getBlock(args);
      } catch {
        throw new McpNetworkError(
          "deterministic MCP read exhausted retries",
        );
      }
    },
  });

  const repoRoot = join(root, "repo");
  await mkdir(join(repoRoot, ".context", "operator-keys"), {
    recursive: true,
  });
  await mkdir(join(repoRoot, "docs", "operator-keys"), {
    recursive: true,
  });
  await writeFile(
    join(
      repoRoot,
      ".context",
      "operator-keys",
      `${KEY_ID}.ed25519.pem`,
    ),
    operatorPrivateKeyPem,
    { encoding: "utf8", mode: 0o600 },
  );
  await writeFile(
    join(repoRoot, "docs", "operator-keys", `${KEY_ID}.pub`),
    `${repositoryPublicKey}\n`,
    { encoding: "utf8", mode: 0o644 },
  );
  const stateDir = join(root, "verdict-state");

  const ownerOf = async ({ agentId }) =>
    agentId === descriptor.payer.agentId
      ? descriptor.payer.address
      : descriptor.payee.address;

  return {
    cleanup: async () => {
      for (const fn of cleanups.reverse()) {
        await fn();
      }
    },
    clockchain: verifierClockchain,
    descriptor,
    descriptorEnvelope,
    mandateEnvelope,
    operatorPrivateKeyPem,
    operatorPublicKeyPem,
    ownerOf,
    relay,
    relayUrl,
    repoRoot,
    repositoryPublicKey,
    requestEnvelope,
    sessionDigest,
    stateDir,
    subjectRun,
  };
}
