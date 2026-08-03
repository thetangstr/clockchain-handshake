import assert from "node:assert/strict";
import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  verify as cryptoVerify,
} from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  generatePrivateKey,
  privateKeyToAccount,
} from "viem/accounts";

import {
  deadlineMs,
  liveUpperBoundMs,
} from "../src/core/blocktime.mjs";
import { canonicalBytes } from "../src/core/canonical.mjs";
import { McpNetworkError } from "../src/core/clockchain.mjs";
import {
  createSignedEnvelope,
  dSession,
  rawPublicKeyBase64FromPem,
} from "../src/core/descriptor.mjs";
import {
  PARTY_RESULT_SCHEMA,
  partySignatureBytes,
  writePartyResult,
} from "../src/core/evidence.mjs";
import {
  authoritativeTriple,
  buildAcceptance,
  buildAcknowledgment,
  buildProposal,
  transitionDigest,
} from "../src/core/messages.mjs";
import {
  payerMandateDigest,
  signPayerMandate,
} from "../src/core/payer-mandate.mjs";
import {
  paymentRequestDigest,
  signPaymentRequest,
} from "../src/core/payment-request.mjs";
import { verifyTransition } from "../src/core/protocol.mjs";
import { sessionKey } from "../src/core/refid.mjs";
import { BilateralVerdictError } from "../src/core/verdict.mjs";
import { createRelayClient } from "../src/relay/client.mjs";
import { createRelayServer } from "../src/relay/server.mjs";
import { RELAY_KINDS } from "../src/roles/catalog.mjs";
import {
  main,
  runVerification,
  VERDICT_DOCUMENT_SCHEMA,
} from "../src/verifier/run.mjs";
import {
  createFakeBilateralClockchain,
} from "./helpers/fake-bilateral-clockchain.mjs";

const PAYER = privateKeyToAccount(generatePrivateKey());
const PAYEE = privateKeyToAccount(generatePrivateKey());
const REPOSITORY_SHA =
  "0123456789abcdef0123456789abcdef01234567";
const PROMPT_SHA256 = "a".repeat(64);
const INTAKE_DIGEST = "b".repeat(64);
const INTAKE_REQUEST_ID =
  "22222222-3333-4444-8555-666666666666";
const KEY_ID = "verdict-test-operator";
const RELAY_SESSION_ID =
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

function captureStdout() {
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
async function buildHarness(
  t,
  {
    subjectRun = "stakeholder",
    anchors = "all",
    evidence = true,
    descriptorMessage = true,
    duplicateMandate = false,
  } = {},
) {
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
  t.after(() => rm(root, { recursive: true, force: true }));
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
  t.after(() =>
    rm(relayStateDir, { recursive: true, force: true }),
  );
  const server = createRelayServer({
    stateDir: relayStateDir,
  });
  const address = await server.listen();
  t.after(() => server.close());
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
  await send(
    RELAY_KINDS.MANDATE_PUBLISHED,
    "payer",
    "payer-key",
    0,
    { envelope: mandateEnvelope },
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

function baseInput(harness) {
  return {
    clockchain: harness.clockchain,
    operatorKeyId: KEY_ID,
    operatorPrivateKeyPem: harness.operatorPrivateKeyPem,
    ownerOf: harness.ownerOf,
    relay: harness.relay,
    repositoryPublicKeyResolver: async () =>
      harness.repositoryPublicKey,
    sessionId: RELAY_SESSION_ID,
    subjectRun: harness.subjectRun,
  };
}

async function snapshotVerdict(harness) {
  const response = await fetch(
    `${harness.relayUrl}/v1/sessions/${RELAY_SESSION_ID}/snapshot`,
  );
  assert.equal(response.status, 200);
  const snapshot = await response.json();
  return snapshot.verdict;
}

test(
  "stakeholder happy path publishes a signed verdict",
  async (t) => {
    const harness = await buildHarness(t);
    const stdout = captureStdout();
    const code = await main(
      [
        "--session",
        RELAY_SESSION_ID,
        "--relay",
        harness.relayUrl,
        "--state",
        harness.stateDir,
        "--key-id",
        KEY_ID,
        "--subject-run",
        "stakeholder",
      ],
      {
        clockchain: harness.clockchain,
        ownerOf: harness.ownerOf,
        repoRoot: harness.repoRoot,
        stdout,
      },
    );
    assert.equal(code, 0);
    assert.equal(stdout.lines.length, 1);
    assert.match(
      stdout.lines[0],
      /^VERDICT_PUBLISHED AUTHORIZED session=/,
    );

    const document = await snapshotVerdict(harness);
    assert.equal(document.schema, VERDICT_DOCUMENT_SCHEMA);
    assert.equal(document.sessionId, RELAY_SESSION_ID);
    assert.equal(document.signature.algorithm, "ed25519");
    assert.equal(document.signature.keyId, KEY_ID);
    assert.equal(
      document.signature.publicKey,
      harness.repositoryPublicKey,
    );
    assert.equal(document.verdict.outcome, "AUTHORIZED");
    assert.equal(document.verdict.paymentMoved, false);
    assert.equal(document.verdict.transitions.length, 3);
    assert.equal(
      document.verdict.sessionDigest,
      harness.sessionDigest,
    );

    const publicKey = createPublicKey(
      harness.operatorPublicKeyPem,
    );
    assert.equal(
      cryptoVerify(
        null,
        canonicalBytes(document.verdict),
        publicKey,
        Buffer.from(document.signature.value, "base64"),
      ),
      true,
    );
    const otherKey = generateKeyPairSync(
      "ed25519",
    ).publicKey;
    assert.equal(
      cryptoVerify(
        null,
        canonicalBytes(document.verdict),
        otherKey,
        Buffer.from(document.signature.value, "base64"),
      ),
      false,
    );

    const written = JSON.parse(
      await readFile(
        join(harness.stateDir, "verdict.json"),
        "utf8",
      ),
    );
    assert.deepEqual(written, JSON.parse(JSON.stringify(document)));
    const markdown = await readFile(
      join(harness.stateDir, "verdict.md"),
      "utf8",
    );
    assert.match(markdown, /AUTHORIZED/);
  },
);

test(
  "rehearsal sub-run publishes a rehearsal result",
  async (t) => {
    const harness = await buildHarness(t, {
      subjectRun: "rehearsal",
    });
    const stdout = captureStdout();
    const code = await main(
      [
        "--session",
        RELAY_SESSION_ID,
        "--relay",
        harness.relayUrl,
        "--state",
        harness.stateDir,
        "--key-id",
        KEY_ID,
        "--subject-run",
        "rehearsal",
      ],
      {
        clockchain: harness.clockchain,
        ownerOf: harness.ownerOf,
        repoRoot: harness.repoRoot,
        stdout,
      },
    );
    assert.equal(code, 0);
    assert.match(
      stdout.lines[0],
      /^VERDICT_PUBLISHED REHEARSAL_PASSED session=/,
    );
    const document = await snapshotVerdict(harness);
    assert.equal(
      document.verdict.outcome,
      "REHEARSAL_PASSED",
    );
    await assert.rejects(
      readFile(join(harness.stateDir, "verdict.md"), "utf8"),
    );
  },
);

test(
  "a later slot anchored without its predecessor fails closed as REORDERED",
  async (t) => {
    const harness = await buildHarness(t, {
      anchors: "reordered",
    });
    await assert.rejects(
      runVerification(baseInput(harness)),
      (error) => {
        assert.ok(error instanceof BilateralVerdictError);
        assert.equal(error.terminalCode, "REORDERED");
        return true;
      },
    );
    assert.equal(await snapshotVerdict(harness), null);
  },
);

test(
  "an unanchored session fails closed as MISSING",
  async (t) => {
    const harness = await buildHarness(t, {
      anchors: "none",
    });
    await assert.rejects(
      runVerification(baseInput(harness)),
      (error) => {
        assert.ok(error instanceof BilateralVerdictError);
        assert.equal(error.terminalCode, "MISSING");
        return true;
      },
    );
  },
);

test(
  "absent party evidence fails closed as MISSING",
  async (t) => {
    const harness = await buildHarness(t, {
      evidence: false,
    });
    await assert.rejects(
      runVerification(baseInput(harness)),
      (error) => {
        assert.ok(error instanceof BilateralVerdictError);
        assert.equal(error.terminalCode, "MISSING");
        return true;
      },
    );
  },
);

test(
  "an absent descriptor artifact fails closed as MISSING",
  async (t) => {
    const harness = await buildHarness(t, {
      descriptorMessage: false,
    });
    await assert.rejects(
      runVerification(baseInput(harness)),
      (error) => {
        assert.ok(error instanceof BilateralVerdictError);
        assert.equal(error.terminalCode, "MISSING");
        return true;
      },
    );
  },
);

test(
  "divergent duplicate mandate artifacts fail closed as DUPLICATE",
  async (t) => {
    const harness = await buildHarness(t, {
      duplicateMandate: true,
    });
    await assert.rejects(
      runVerification(baseInput(harness)),
      (error) => {
        assert.ok(error instanceof BilateralVerdictError);
        assert.equal(error.terminalCode, "DUPLICATE");
        return true;
      },
    );
  },
);

test(
  "republishing an identical verdict is idempotent",
  async (t) => {
    const harness = await buildHarness(t);
    const first = await runVerification(baseInput(harness));
    assert.equal(first.republished, false);
    const second = await runVerification(baseInput(harness));
    assert.equal(second.republished, true);
    assert.deepEqual(
      JSON.parse(JSON.stringify(second.document)),
      JSON.parse(JSON.stringify(first.document)),
    );
  },
);

test("usage failures exit 2", async () => {
  const stdout = captureStdout();
  assert.equal(await main([], { stdout }), 2);
  assert.match(stdout.lines[0], /^usage: run\.mjs/);

  const badSubject = captureStdout();
  assert.equal(
    await main(
      [
        "--session",
        RELAY_SESSION_ID,
        "--relay",
        "http://127.0.0.1:1",
        "--state",
        "/tmp/verifier-run-unused",
        "--key-id",
        KEY_ID,
        "--subject-run",
        "practice",
      ],
      { stdout: badSubject },
    ),
    2,
  );

  const badKey = captureStdout();
  assert.equal(
    await main(
      [
        "--session",
        RELAY_SESSION_ID,
        "--relay",
        "http://127.0.0.1:1",
        "--state",
        "/tmp/verifier-run-unused",
        "--key-id",
        "../escape",
        "--subject-run",
        "stakeholder",
      ],
      { stdout: badKey },
    ),
    2,
  );
});
