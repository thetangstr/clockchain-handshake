import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  createHash,
  generateKeyPairSync,
} from "node:crypto";
import { constants } from "node:fs";
import {
  chmod,
  lstat,
  link,
  mkdir,
  mkdtemp,
  open,
  readFile,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import {
  basename,
  dirname,
  join,
} from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import {
  generatePrivateKey,
  privateKeyToAccount,
} from "viem/accounts";

import {
  deadlineMs,
  liveUpperBoundMs,
} from "../src/bilateral/blocktime.mjs";
import { canonicalBytes } from "../src/bilateral/canonical.mjs";
import {
  createSignedEnvelope,
  dSession,
  rawPublicKeyBase64FromPem,
} from "../src/bilateral/descriptor.mjs";
import {
  PARTY_RESULT_SCHEMA,
  partySignatureBytes,
  writePartyResult,
} from "../src/bilateral/evidence.mjs";
import {
  authoritativeTriple,
  buildAcceptance,
  buildAcknowledgment,
  buildProposal,
  transitionDigest,
} from "../src/bilateral/messages.mjs";
import {
  payerMandateDigest,
  signPayerMandate,
} from "../src/bilateral/payer-mandate.mjs";
import {
  paymentRequestDigest,
  signPaymentRequest,
} from "../src/bilateral/payment-request.mjs";
import { verifyTransition } from "../src/bilateral/protocol.mjs";
import { sessionKey } from "../src/bilateral/refid.mjs";
import {
  BilateralVerdictError,
  VERDICT_KEYS,
  VERDICT_SCHEMA,
  renderBilateralVerdictMarkdown,
  validatePublishedBilateralVerdict,
  verifyBilateralAuthorization,
} from "../src/bilateral/verdict.mjs";
import {
  createFakeBilateralClockchain,
} from "./helpers/fake-bilateral-clockchain.mjs";
import {
  McpNetworkError,
  McpProtocolError,
  McpRateLimitedError,
} from "../src/mcp.mjs";
import {
  CLI_ARGUMENTS,
  main as runVerifierCli,
} from "../scripts/verify-bilateral-results.mjs";

const PAYER = privateKeyToAccount(generatePrivateKey());
const PAYEE = privateKeyToAccount(generatePrivateKey());
const execFileAsync = promisify(execFile);
const REPOSITORY_SHA =
  "0123456789abcdef0123456789abcdef01234567";
const PROMPT_SHA256 =
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const INTAKE_DIGEST = "b".repeat(64);
const INTAKE_REQUEST_ID = "22222222-3333-4444-8555-666666666666";

async function writePublishedVerdict(directory, verdict, options = {}) {
  const json = Buffer.from(`${JSON.stringify(verdict, null, 2)}\n`, "utf8");
  const markdown = Buffer.from(renderBilateralVerdictMarkdown(verdict), "utf8");
  const marker = Buffer.from(
    options.marker ??
      `${JSON.stringify({
        jsonSha256: createHash("sha256").update(json).digest("hex"),
        markdownSha256: createHash("sha256").update(markdown).digest("hex"),
        schema: "clockchain.bilateral-authorization-verdict-completion/v2",
        ...options.markerFields,
      })}\n`,
    "utf8",
  );
  await mkdir(directory, { mode: 0o700, recursive: true });
  await writeFile(join(directory, "bilateral-verdict.json"), json, { mode: 0o600 });
  await writeFile(join(directory, "BILATERAL-VERDICT.md"), markdown, { mode: 0o600 });
  await writeFile(join(directory, ".bilateral-verdict.complete.json"), marker, { mode: 0o600 });
  return { json, markdown, marker };
}

function publicationMarker(json, markdown) {
  return `${JSON.stringify({
    jsonSha256: createHash("sha256").update(json).digest("hex"),
    markdownSha256: createHash("sha256").update(markdown).digest("hex"),
    schema: "clockchain.bilateral-authorization-verdict-completion/v2",
  })}\n`;
}

function publishedExpected(directory, verdict) {
  return {
    mandateDigest: verdict.mandateDigest,
    outputDirectory: directory,
    repositorySha: REPOSITORY_SHA,
    requestDigest: verdict.requestDigest,
    sessionDigest: verdict.sessionDigest,
  };
}

test("validates an exact marker-complete published verdict", async (t) => {
  const fixture = await completeFixture(t);
  const verdict = await verifyBilateralAuthorization(fixture.input);
  const directory = join(fixture.root, "published-verdict");
  const publication = await writePublishedVerdict(directory, verdict);

  const result = await validatePublishedBilateralVerdict(
    publishedExpected(directory, verdict),
  );

  assert.deepEqual(result, {
    publicationDigest: createHash("sha256")
      .update(
        JSON.stringify({
          jsonSha256: createHash("sha256")
            .update(publication.json)
            .digest("hex"),
          markdownSha256: createHash("sha256")
            .update(publication.markdown)
            .digest("hex"),
          markerSha256: createHash("sha256")
            .update(publication.marker)
            .digest("hex"),
        }),
      )
      .digest("hex"),
    status: "VERIFICATION_PASSED",
  });
  assert.equal(Object.isFrozen(result), true);
});

test("rejects marker-incomplete, malformed, and hash-mismatched publications", async (t) => {
  const fixture = await completeFixture(t);
  const verdict = await verifyBilateralAuthorization(fixture.input);
  const directory = join(fixture.root, "invalid-publication");
  const expected = publishedExpected(directory, verdict);
  await mkdir(directory, { mode: 0o700 });
  await assert.rejects(() => validatePublishedBilateralVerdict(expected), BilateralVerdictError);

  await writePublishedVerdict(directory, verdict, {
    marker: "{not-json}\n",
  });
  await assert.rejects(() => validatePublishedBilateralVerdict(expected), BilateralVerdictError);

  await rm(directory, { recursive: true, force: true });
  await writePublishedVerdict(directory, verdict, {
    markerFields: { jsonSha256: "0".repeat(64) },
  });
  await assert.rejects(() => validatePublishedBilateralVerdict(expected), BilateralVerdictError);

  await rm(directory, { recursive: true, force: true });
  const publication = await writePublishedVerdict(directory, verdict);
  const moved = JSON.parse(publication.json.toString("utf8"));
  moved.paymentMoved = true;
  const movedJson = Buffer.from(`${JSON.stringify(moved, null, 2)}\n`, "utf8");
  await writeFile(join(directory, "bilateral-verdict.json"), movedJson);
  await writeFile(
    join(directory, ".bilateral-verdict.complete.json"),
    `${JSON.stringify({
      jsonSha256: createHash("sha256").update(movedJson).digest("hex"),
      markdownSha256: createHash("sha256")
        .update(publication.markdown)
        .digest("hex"),
      schema: "clockchain.bilateral-authorization-verdict-completion/v2",
    })}\n`,
  );
  await assert.rejects(() => validatePublishedBilateralVerdict(expected), BilateralVerdictError);
});

test("rejects stale expected bindings and symlinked or replaced publication paths", async (t) => {
  const fixture = await completeFixture(t);
  const verdict = await verifyBilateralAuthorization(fixture.input);
  const directory = join(fixture.root, "published-verdict");
  const expected = publishedExpected(directory, verdict);
  await writePublishedVerdict(directory, verdict);
  await assert.rejects(
    () => validatePublishedBilateralVerdict({ ...expected, repositorySha: "f".repeat(40) }),
    BilateralVerdictError,
  );
  await assert.rejects(
    () => validatePublishedBilateralVerdict({ ...expected, sessionDigest: "f".repeat(64) }),
    BilateralVerdictError,
  );

  const linkedMarker = join(fixture.root, "marker-link");
  await writeFile(linkedMarker, await readFile(join(directory, ".bilateral-verdict.complete.json")));
  await rm(join(directory, ".bilateral-verdict.complete.json"));
  await symlink(linkedMarker, join(directory, ".bilateral-verdict.complete.json"));
  await assert.rejects(() => validatePublishedBilateralVerdict(expected), BilateralVerdictError);

  await rm(directory, { recursive: true, force: true });
  const replacement = join(fixture.root, "replacement-publication");
  await writePublishedVerdict(replacement, verdict);
  await symlink(replacement, directory);
  await assert.rejects(() => validatePublishedBilateralVerdict(expected), BilateralVerdictError);
});

test("rejects non-private directories and publication files, including hardlinks", async (t) => {
  const fixture = await completeFixture(t);
  const verdict = await verifyBilateralAuthorization(fixture.input);
  const directory = join(fixture.root, "private-publication");
  const expected = publishedExpected(directory, verdict);

  await writePublishedVerdict(directory, verdict);
  await chmod(directory, 0o755);
  await assert.rejects(() => validatePublishedBilateralVerdict(expected), BilateralVerdictError);

  await chmod(directory, 0o700);
  await chmod(join(directory, "bilateral-verdict.json"), 0o644);
  await assert.rejects(() => validatePublishedBilateralVerdict(expected), BilateralVerdictError);

  await chmod(join(directory, "bilateral-verdict.json"), 0o600);
  await link(
    join(directory, "bilateral-verdict.json"),
    join(fixture.root, "hardlinked-verdict.json"),
  );
  await assert.rejects(() => validatePublishedBilateralVerdict(expected), BilateralVerdictError);
});

test("rejects alternate valid JSON bytes even with matching marker and markdown", async (t) => {
  const fixture = await completeFixture(t);
  const verdict = await verifyBilateralAuthorization(fixture.input);
  const directory = join(fixture.root, "alternate-json-publication");
  const publication = await writePublishedVerdict(directory, verdict);
  const compactJson = Buffer.from(JSON.stringify(verdict), "utf8");
  await writeFile(join(directory, "bilateral-verdict.json"), compactJson, { mode: 0o600 });
  await writeFile(
    join(directory, ".bilateral-verdict.complete.json"),
    publicationMarker(compactJson, publication.markdown),
    { mode: 0o600 },
  );

  await assert.rejects(
    () => validatePublishedBilateralVerdict(
      publishedExpected(directory, verdict),
    ),
    BilateralVerdictError,
  );

  const reordered = Object.fromEntries(
    Object.entries(verdict).reverse(),
  );
  const reorderedJson = Buffer.from(
    `${JSON.stringify(reordered, null, 2)}\n`,
    "utf8",
  );
  const reorderedMarkdown = Buffer.from(
    renderBilateralVerdictMarkdown(reordered),
    "utf8",
  );
  await writeFile(join(directory, "bilateral-verdict.json"), reorderedJson, { mode: 0o600 });
  await writeFile(join(directory, "BILATERAL-VERDICT.md"), reorderedMarkdown, { mode: 0o600 });
  await writeFile(
    join(directory, ".bilateral-verdict.complete.json"),
    publicationMarker(reorderedJson, reorderedMarkdown),
    { mode: 0o600 },
  );
  await assert.rejects(
    () => validatePublishedBilateralVerdict(
      publishedExpected(directory, verdict),
    ),
    BilateralVerdictError,
  );
});

function descriptorFixture({
  mandateDigest = "b".repeat(64),
  requestDigest = "c".repeat(64),
} = {}) {
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

async function intentEnvelopes() {
  const sessionId = "00112233-4455-6677-8899-aabbccddeeff";
  const mandate = {
    amount: { currency: "USD", value: "100" },
    expiresAtMs: "1784923800000",
    intakeDigest: INTAKE_DIGEST,
    intakeRequestId: INTAKE_REQUEST_ID,
    invoiceReferencePrefix: "INV-",
    issuedAtMs: "1784923100000",
    payee: { address: PAYEE.address.toLowerCase(), agentId: "8678" },
    payer: { address: PAYER.address.toLowerCase(), agentId: "8677" },
    paymentMoved: false,
    protocol: "clockchain.bilateral-authorization/v1",
    purpose: "Invoice settlement",
    releaseId: "release-1",
    repositorySha: REPOSITORY_SHA,
    requestEndpoint: `/v1/sessions/${sessionId}/payment-requests`,
    schema: "clockchain.bilateral-payer-mandate/v1",
    sessionId,
    subjectRun: "rehearsal",
  };
  const mandateEnvelope = await signPayerMandate({
    mandate,
    signMessage: (raw) => PAYER.signMessage({ message: { raw } }),
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
    signMessage: (raw) => PAYEE.signMessage({ message: { raw } }),
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

async function completeFixture(t) {
  const { mandateEnvelope, requestEnvelope } =
    await intentEnvelopes();
  const descriptor = descriptorFixture({
    mandateDigest: payerMandateDigest(mandateEnvelope),
    requestDigest: paymentRequestDigest(requestEnvelope),
  });
  const sessionDigest = dSession(descriptor);
  const { privateKey, publicKey } =
    generateKeyPairSync("ed25519");
  const repositoryPrivateKeyPem = privateKey.export({
    format: "pem",
    type: "pkcs8",
  });
  const repositoryPublicKey = rawPublicKeyBase64FromPem(
    publicKey.export({ format: "pem", type: "spki" }),
  );
  const descriptorEnvelope = createSignedEnvelope(descriptor, {
    keyId: "verdict-test-operator",
    privateKeyPem: repositoryPrivateKeyPem,
  });
  const clockchain = createFakeBilateralClockchain();
  for (const role of ["payer", "payee"]) {
    clockchain.registerAgent({
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
  const verifiedProposal = await anchor(clockchain, proposal);
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
  const verifiedAcceptance = await anchor(
    clockchain,
    acceptance,
  );
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
    clockchain,
    acknowledgment,
  );
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

  const root = await mkdtemp(join(tmpdir(), "bilateral-verdict-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const payerDirectory = join(root, "payer");
  const payeeDirectory = join(root, "payee");
  await writePartyResult({
    directory: payerDirectory,
    result: payer,
  });
  await writePartyResult({
    directory: payeeDirectory,
    result: payee,
  });
  const verifierClockchain = clockchainWith(clockchain, {
    async getBlock(args) {
      try {
        return await clockchain.getBlock(args);
      } catch {
        throw new McpNetworkError(
          "deterministic MCP read exhausted retries",
        );
      }
    },
  });

  return {
    descriptor,
    descriptorEnvelope,
    mandateEnvelope,
    input: {
      canaries: [],
      clockchain: verifierClockchain,
      descriptorEnvelope,
      mandateEnvelope,
      ownerOf: async ({ agentId }) =>
        agentId === descriptor.payer.agentId
          ? descriptor.payer.address
          : descriptor.payee.address,
      payeeDirectory,
      payerDirectory,
      requestEnvelope,
      repositoryPublicKeyResolver: async () =>
        repositoryPublicKey,
    },
    payee,
    payeeDirectory,
    payer,
    payerDirectory,
    repositoryPublicKey,
    repositoryPrivateKeyPem,
    requestEnvelope,
    root,
    sessionDigest,
    transitions,
  };
}

function cloned(value) {
  return JSON.parse(JSON.stringify(value));
}

async function signedIntentVariant(
  fixture,
  { mandateOverrides = {}, requestOverrides = {} } = {},
) {
  const mandateEnvelope = await signPayerMandate({
    mandate: {
      ...fixture.mandateEnvelope.mandate,
      ...mandateOverrides,
    },
    signMessage: (raw) => PAYER.signMessage({ message: { raw } }),
  });
  const requestEnvelope = await signPaymentRequest({
    request: {
      ...fixture.requestEnvelope.request,
      ...requestOverrides,
      mandateDigest: payerMandateDigest(mandateEnvelope),
    },
    signMessage: (raw) => PAYEE.signMessage({ message: { raw } }),
  });
  return { mandateEnvelope, requestEnvelope };
}

function descriptorBoundIntentInput(
  fixture,
  mandateEnvelope,
  requestEnvelope,
) {
  const descriptor = {
    ...fixture.descriptor,
    mandateDigest: payerMandateDigest(mandateEnvelope),
    requestDigest: paymentRequestDigest(requestEnvelope),
  };
  return {
    descriptorEnvelope: createSignedEnvelope(descriptor, {
      keyId: fixture.descriptorEnvelope.operator.keyId,
      privateKeyPem: fixture.repositoryPrivateKeyPem,
    }),
    mandateEnvelope,
    requestEnvelope,
  };
}

function corruptedIntentSignature(envelope) {
  const value = envelope.signature.value;
  return {
    ...envelope,
    signature: {
      ...envelope.signature,
      value: `${value.slice(0, -1)}${value.endsWith("0") ? "1" : "0"}`,
    },
  };
}

function clockchainWith(clockchain, overrides = {}) {
  const adapted = {
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
  if ("calls" in clockchain) {
    Object.defineProperty(adapted, "calls", {
      enumerable: true,
      get: () => clockchain.calls,
    });
  }
  return adapted;
}

function countingVerifierInput(fixture, overrides = {}) {
  const calls = { clockchain: 0, files: 0 };
  const clockchain = clockchainWith(fixture.input.clockchain, {
    async generateAuditTrail(args) {
      calls.clockchain += 1;
      return fixture.input.clockchain.generateAuditTrail(args);
    },
    async getBlock(args) {
      calls.clockchain += 1;
      return fixture.input.clockchain.getBlock(args);
    },
    async resolveAgent(args) {
      calls.clockchain += 1;
      return fixture.input.clockchain.resolveAgent(args);
    },
    async searchActions(args) {
      calls.clockchain += 1;
      return fixture.input.clockchain.searchActions(args);
    },
    async verifyCrossParty(args) {
      calls.clockchain += 1;
      return fixture.input.clockchain.verifyCrossParty(args);
    },
  });
  return {
    calls,
    input: {
      ...fixture.input,
      ...overrides,
      clockchain,
      fileSystem: {
        async open(path, flags) {
          calls.files += 1;
          return open(path, flags);
        },
      },
    },
  };
}

async function writeVariant(fixture, name, result) {
  const directory = join(fixture.root, name);
  await writePartyResult({ directory, result });
  return directory;
}

async function assertVerdictFailure(input, terminalCode) {
  await assert.rejects(
    () => verifyBilateralAuthorization(input),
    (error) => {
      assert.ok(error instanceof BilateralVerdictError);
      assert.equal(error.terminalCode, terminalCode);
      assert.equal(
        error.code,
        `BILATERAL_VERDICT_${terminalCode}`,
      );
      assert.equal(error.message.includes("AUTHORIZED"), false);
      return true;
    },
  );
}

test("emits only the exact independently verified bilateral authorization verdict", async (t) => {
  const fixture = await completeFixture(t);
  const verdict = await verifyBilateralAuthorization(fixture.input);

  assert.equal(
    VERDICT_SCHEMA,
    "clockchain.bilateral-authorization-verdict/v2",
  );
  assert.deepEqual(Object.keys(verdict), [...VERDICT_KEYS]);
  assert.equal(verdict.outcome, "AUTHORIZED");
  assert.equal(verdict.paymentMoved, false);
  assert.equal(verdict.sessionDigest, dSession(fixture.descriptor));
  assert.equal(verdict.transitions.length, 3);
  assert.equal(
    renderBilateralVerdictMarkdown(verdict),
    [
      "# Bilateral Payment Authorization Verdict",
      "",
      "- Outcome: `AUTHORIZED`",
      "- Payment moved: no",
      `- Payer mandate digest: \`${verdict.mandateDigest}\``,
      `- Payment request digest: \`${verdict.requestDigest}\``,
      `- Session digest: \`${verdict.sessionDigest}\``,
      `- Repository SHA: \`${REPOSITORY_SHA}\``,
      `- Prompt SHA-256: \`${PROMPT_SHA256}\``,
      "",
      "```json",
      JSON.stringify(verdict, null, 2),
      "```",
      "",
    ].join("\n"),
  );
});

test("snapshots Clockchain method receivers before an earlier await", async (t) => {
  const fixture = await completeFixture(t);
  const calls = { replacement: 0 };
  const clockchain = {
    delegate: fixture.input.clockchain,
    async generateAuditTrail(args) {
      return this.delegate.generateAuditTrail(args);
    },
    async getBlock(args) {
      return this.delegate.getBlock(args);
    },
    async resolveAgent(args) {
      return this.delegate.resolveAgent(args);
    },
    async searchActions(args) {
      return this.delegate.searchActions(args);
    },
    async verifyCrossParty(args) {
      return this.delegate.verifyCrossParty(args);
    },
  };
  const verdict = await verifyBilateralAuthorization({
    ...fixture.input,
    clockchain,
    async repositoryPublicKeyResolver() {
      await Promise.resolve();
      clockchain.searchActions = async () => {
        calls.replacement += 1;
        return [];
      };
      return fixture.repositoryPublicKey;
    },
  });
  assert.equal(verdict.outcome, "AUTHORIZED");
  assert.equal(calls.replacement, 0);
});

test("rejects accessor, proxy, and non-function Clockchain methods before I/O", async (t) => {
  const fixture = await completeFixture(t);
  for (const scenario of [
    {
      mutate(clockchain, counters) {
        Object.defineProperty(clockchain, "searchActions", {
          enumerable: true,
          get() {
            counters.getter += 1;
            return async () => [];
          },
        });
      },
      name: "accessor",
    },
    {
      mutate(clockchain) {
        clockchain.searchActions = new Proxy(
          async () => [],
          {},
        );
      },
      name: "proxy",
    },
    {
      mutate(clockchain) {
        clockchain.searchActions = "not-a-function";
      },
      name: "non-function",
    },
  ]) {
    await t.test(scenario.name, async () => {
      const { calls, input } = countingVerifierInput(fixture);
      const counters = { getter: 0 };
      scenario.mutate(input.clockchain, counters);
      await assertVerdictFailure(input, "FAILED");
      assert.equal(counters.getter, 0);
      assert.equal(calls.files, 0);
      assert.equal(calls.clockchain, 0);
    });
  }
});

test("rejects unbound descriptor and intent envelopes before package or Clockchain I/O", async (t) => {
  const fixture = await completeFixture(t);
  const scenarios = [
    {
      name: "mutated mandate digest",
      overrides: {
        descriptorEnvelope: {
          ...fixture.descriptorEnvelope,
          descriptor: {
            ...fixture.descriptor,
            mandateDigest: "f".repeat(64),
          },
        },
      },
    },
    {
      name: "mutated request digest",
      overrides: {
        descriptorEnvelope: {
          ...fixture.descriptorEnvelope,
          descriptor: {
            ...fixture.descriptor,
            requestDigest: "f".repeat(64),
          },
        },
      },
    },
    {
      name: "malformed descriptor envelope",
      overrides: { descriptorEnvelope: {} },
    },
    {
      name: "malformed payer mandate envelope",
      overrides: { mandateEnvelope: {} },
    },
    {
      name: "malformed payment request envelope",
      overrides: { requestEnvelope: {} },
    },
  ];
  for (const scenario of scenarios) {
    await t.test(scenario.name, async () => {
      const { calls, input } = countingVerifierInput(
        fixture,
        scenario.overrides,
      );
      await assertVerdictFailure(input, "FAILED");
      assert.equal(calls.files, 0);
      assert.equal(calls.clockchain, 0);
    });
  }
});

test("rejects descriptor-bound invalid intent signatures and windows before I/O", async (t) => {
  const fixture = await completeFixture(t);
  const requestBeforeMandate = await signedIntentVariant(fixture, {
    requestOverrides: { createdAtMs: "1784923000000" },
  });
  const requestPastMandate = await signedIntentVariant(fixture, {
    requestOverrides: { expiresAtMs: "1784923900000" },
  });
  const requestMismatchedIntake = await signedIntentVariant(fixture, {
    requestOverrides: { intakeDigest: "c".repeat(64) },
  });
  const scenarios = [
    {
      mandateEnvelope: corruptedIntentSignature(
        fixture.mandateEnvelope,
      ),
      name: "invalid payer mandate signature",
      requestEnvelope: fixture.requestEnvelope,
    },
    {
      mandateEnvelope: fixture.mandateEnvelope,
      name: "invalid payment request signature",
      requestEnvelope: corruptedIntentSignature(
        fixture.requestEnvelope,
      ),
    },
    {
      ...requestBeforeMandate,
      name: "request begins before mandate",
    },
    {
      ...requestPastMandate,
      name: "request ends after mandate",
    },
    {
      ...requestMismatchedIntake,
      name: "request intake differs from mandate intake",
    },
  ];
  for (const scenario of scenarios) {
    await t.test(scenario.name, async () => {
      const { calls, input } = countingVerifierInput(
        fixture,
        descriptorBoundIntentInput(
          fixture,
          scenario.mandateEnvelope,
          scenario.requestEnvelope,
        ),
      );
      await assertVerdictFailure(input, "FAILED");
      assert.equal(calls.files, 0);
      assert.equal(calls.clockchain, 0);
    });
  }
});

test("requires both valid completion markers before any live verification", async (t) => {
  const fixture = await completeFixture(t);
  await rm(
    join(
      fixture.payeeDirectory,
      ".party-result.complete.json",
    ),
  );
  const searchCalls =
    fixture.input.clockchain.calls.searchActions.length;

  await assertVerdictFailure(fixture.input, "FAILED");
  assert.equal(
    fixture.input.clockchain.calls.searchActions.length,
    searchCalls,
  );
});

test("rejects symlinked completion markers without following them", async (t) => {
  const fixture = await completeFixture(t);
  const markerPath = join(
    fixture.payeeDirectory,
    ".party-result.complete.json",
  );
  const savedMarker = join(fixture.root, "saved-marker.json");
  await writeFile(
    savedMarker,
    await readFile(markerPath),
  );
  await rm(markerPath);
  await symlink(savedMarker, markerPath);

  await assertVerdictFailure(fixture.input, "FAILED");
});

test("opens untrusted artifact paths with no-follow and nonblocking flags", async (t) => {
  const fixture = await completeFixture(t);
  let observedFlags = null;
  await assertVerdictFailure(
    {
      ...fixture.input,
      fileSystem: {
        async open(_path, flags) {
          observedFlags = flags;
          throw new Error("refused");
        },
      },
    },
    "FAILED",
  );
  assert.equal(
    (observedFlags & constants.O_NOFOLLOW) !== 0,
    true,
  );
  assert.equal(
    (observedFlags & constants.O_NONBLOCK) !== 0,
    true,
  );
});

function adversarialVerdictReadHandle(
  handle,
  {
    metadataField,
    onRead,
    overflow = false,
    truncate = false,
  } = {},
) {
  let statCalls = 0;
  return {
    close: () => handle.close(),
    async read(buffer, offset, length, position) {
      onRead?.(length);
      if (overflow) {
        buffer.fill(0x78, offset, offset + length);
        return { buffer, bytesRead: length };
      }
      if (truncate) {
        return { buffer, bytesRead: 0 };
      }
      return handle.read(buffer, offset, length, position);
    },
    readFile() {
      assert.fail("bounded readers must not call readFile()");
    },
    async stat() {
      const metadata = await handle.stat();
      statCalls += 1;
      if (statCalls === 1 || metadataField === undefined) {
        return metadata;
      }
      return {
        ...metadata,
        [metadataField]: metadata[metadataField] + 1,
        isFile: () => true,
      };
    },
  };
}

function adversarialBuilderFileSystem(targetPath, options) {
  return {
    async open(path, flags) {
      const handle = await open(path, flags);
      return path === targetPath
        ? adversarialVerdictReadHandle(handle, options)
        : handle;
    },
  };
}

test("aggregate verifier bounds party-package reads and rejects metadata races", async (t) => {
  for (const scenario of [
    { metadataField: undefined, overflow: true },
    { metadataField: "ctimeMs", overflow: false },
  ]) {
    await t.test(
      scenario.overflow ? "growth" : "metadata",
      async (t) => {
        const fixture = await completeFixture(t);
        const target = join(
          fixture.payerDirectory,
          "party-result.json",
        );
        let readLength = 0;
        await assertVerdictFailure(
          {
            ...fixture.input,
            fileSystem: {
              async open(path, flags) {
                const handle = await open(path, flags);
                return path === target
                  ? adversarialVerdictReadHandle(handle, {
                      ...scenario,
                      onRead(length) {
                        readLength = Math.max(readLength, length);
                      },
                    })
                  : handle;
              },
            },
          },
          "FAILED",
        );
        assert.equal(
          readLength,
          scenario.overflow ? (1024 * 1024) + 1 : 1024 * 1024 + 1,
        );
      },
    );
  }
});

test("rejects marker hash mismatch and secret-bearing artifacts before parsing", async (t) => {
  const fixture = await completeFixture(t);
  const markdownPath = join(
    fixture.payeeDirectory,
    "PARTY-RESULT.md",
  );
  await writeFile(
    markdownPath,
    `${await readFile(markdownPath, "utf8")}\ncanary-value\n`,
    "utf8",
  );
  const json = await readFile(
    join(fixture.payeeDirectory, "party-result.json"),
  );
  const markdown = await readFile(markdownPath);
  await writeFile(
    join(
      fixture.payeeDirectory,
      ".party-result.complete.json",
    ),
    `${JSON.stringify({
      jsonSha256: createHash("sha256")
        .update(json)
        .digest("hex"),
      markdownSha256: createHash("sha256")
        .update(markdown)
        .digest("hex"),
      schema:
        "clockchain.bilateral-party-result-completion/v1",
    })}\n`,
    "utf8",
  );
  fixture.input.canaries = ["canary-value"];

  await assertVerdictFailure(fixture.input, "FAILED");
});

test("authorizes a valid acceptance-only payee package using payer and live M3", async (t) => {
  const fixture = await completeFixture(t);
  const prefix = cloned(fixture.payee);
  prefix.ackObserved = false;
  prefix.transitions = prefix.transitions.slice(0, 2);
  const prefixDirectory = await writeVariant(
    fixture,
    "payee-prefix",
    prefix,
  );
  const verdict = await verifyBilateralAuthorization({
    ...fixture.input,
    payeeDirectory: prefixDirectory,
  });
  assert.equal(verdict.outcome, "AUTHORIZED");
  assert.equal(verdict.transitions.length, 3);
  assert.equal(
    verdict.transitions[2].ledgerId,
    fixture.payer.transitions[2].onChain.ledgerId,
  );

  const tamperedPrefix = cloned(prefix);
  tamperedPrefix.transitions[1].onChain.ledgerId =
    "ffffffff-ffff-4fff-8fff-ffffffffffff";
  const tamperedDirectory = await writeVariant(
    fixture,
    "payee-prefix-tampered",
    tamperedPrefix,
  );
  await assertVerdictFailure(
    {
      ...fixture.input,
      payeeDirectory: tamperedDirectory,
    },
    "BINDING_MISMATCH",
  );
});

test("still requires a valid role-owned payee signature", async (t) => {
  const fixture = await completeFixture(t);
  const forged = cloned(fixture.payee);
  forged.signature.signature = await PAYER.signMessage({
    message: {
      raw: partySignatureBytes({
        role: "payee",
        sessionDigest: fixture.sessionDigest,
        transitions: forged.transitions,
      }),
    },
  });
  const forgedDirectory = await writeVariant(
    fixture,
    "payee-forged",
    forged,
  );
  await assertVerdictFailure(
    {
      ...fixture.input,
      payeeDirectory: forgedDirectory,
    },
    "FAILED",
  );
});

test("requires descriptor provenance and descriptor/package pins", async (t) => {
  const fixture = await completeFixture(t);
  const { publicKey } = generateKeyPairSync("ed25519");
  const wrongRepositoryKey = rawPublicKeyBase64FromPem(
    publicKey.export({ format: "pem", type: "spki" }),
  );
  await assertVerdictFailure(
    {
      ...fixture.input,
      repositoryPublicKeyResolver: async () =>
        wrongRepositoryKey,
    },
    "FAILED",
  );

  const mismatched = cloned(fixture.payee);
  mismatched.repositorySha = "f".repeat(40);
  const mismatchedDirectory = await writeVariant(
    fixture,
    "payee-mismatched",
    mismatched,
  );
  await assertVerdictFailure(
    {
      ...fixture.input,
      payeeDirectory: mismatchedDirectory,
    },
    "FAILED",
  );
});

test("rejects duplicated roles and payment/advisory field smuggling", async (t) => {
  const fixture = await completeFixture(t);
  const duplicateRoleDirectory = await writeVariant(
    fixture,
    "duplicate-role",
    fixture.payer,
  );
  await assertVerdictFailure(
    {
      ...fixture.input,
      payeeDirectory: duplicateRoleDirectory,
    },
    "FAILED",
  );

  const tampered = cloned(fixture.payee);
  tampered.paymentMoved = true;
  tampered.status = "verified";
  const json = `${JSON.stringify(tampered, null, 2)}\n`;
  const markdown = await readFile(
    join(fixture.payeeDirectory, "PARTY-RESULT.md"),
    "utf8",
  );
  await writeFile(
    join(fixture.payeeDirectory, "party-result.json"),
    json,
    "utf8",
  );
  await writeFile(
    join(
      fixture.payeeDirectory,
      ".party-result.complete.json",
    ),
    `${JSON.stringify({
      jsonSha256: createHash("sha256")
        .update(json)
        .digest("hex"),
      markdownSha256: createHash("sha256")
        .update(markdown)
        .digest("hex"),
      schema:
        "clockchain.bilateral-party-result-completion/v1",
    })}\n`,
    "utf8",
  );
  await assertVerdictFailure(fixture.input, "FAILED");
});

test("requires direct ownerOf, signature, descriptor, and resolveAgent owner agreement", async (t) => {
  const fixture = await completeFixture(t);
  await assertVerdictFailure(
    {
      ...fixture.input,
      ownerOf: async () => PAYER.address,
    },
    "FAILED",
  );
  for (const statusVariant of [
    "inactive",
    undefined,
    "hostile-getter",
  ]) {
    const verdict = await verifyBilateralAuthorization({
      ...fixture.input,
      clockchain: clockchainWith(fixture.input.clockchain, {
        async resolveAgent(agentId) {
          const resolved =
            await fixture.input.clockchain.resolveAgent(agentId);
          const identity = { owner: resolved.owner };
          if (statusVariant === "hostile-getter") {
            Object.defineProperty(identity, "status", {
              enumerable: true,
              get() {
                throw new Error("status must not be read");
              },
            });
          } else if (statusVariant !== undefined) {
            identity.status = statusVariant;
          }
          return identity;
        },
      }),
    });
    assert.equal(verdict.outcome, "AUTHORIZED");
  }
});

test("fails closed on duplicate discovery and every non-unit audit count", async (t) => {
  const fixture = await completeFixture(t);
  await assertVerdictFailure(
    {
      ...fixture.input,
      clockchain: clockchainWith(fixture.input.clockchain, {
        async searchActions(args) {
          const records =
            await fixture.input.clockchain.searchActions(args);
          return [records[0], records[0]];
        },
      }),
    },
    "DUPLICATE",
  );

  for (const count of ["0", "2"]) {
    await assertVerdictFailure(
      {
        ...fixture.input,
        clockchain: clockchainWith(fixture.input.clockchain, {
          async generateAuditTrail(args) {
            return {
              assetReferenceId: args.asset_reference_id,
              count,
            };
          },
        }),
      },
      "DUPLICATE",
    );
  }
});

test("maps rate-limited and absent proposal discovery to fixed terminal outcomes", async (t) => {
  const fixture = await completeFixture(t);
  await assertVerdictFailure(
    {
      ...fixture.input,
      clockchain: clockchainWith(fixture.input.clockchain, {
        async searchActions() {
          throw new McpRateLimitedError("rate limited", {
            retryAfterMs: 20000,
          });
        },
      }),
    },
    "RATE_BLOCKED",
  );
  await assertVerdictFailure(
    {
      ...fixture.input,
      clockchain: clockchainWith(fixture.input.clockchain, {
        async searchActions() {
          return [];
        },
      }),
    },
    "EXPIRED",
  );
});

test("rejects wrong-height correct-hash anchors and ambiguous next-block failures", async (t) => {
  const fixture = await completeFixture(t);
  await assertVerdictFailure(
    {
      ...fixture.input,
      clockchain: clockchainWith(fixture.input.clockchain, {
        async verifyCrossParty(args) {
          const result =
            await fixture.input.clockchain.verifyCrossParty(args);
          return {
            onChain: {
              ...result.onChain,
              blockHeight: String(
                BigInt(result.onChain.blockHeight) + 1n,
              ),
            },
          };
        },
      }),
    },
    "BINDING_MISMATCH",
  );

  const finalHeight =
    fixture.transitions[2].onChain.blockHeight;
  await assertVerdictFailure(
    {
      ...fixture.input,
      clockchain: clockchainWith(fixture.input.clockchain, {
        async getBlock(args) {
          if (
            args.height ===
            String(BigInt(finalHeight) + 1n)
          ) {
            throw new Error("secret: should-not-leak");
          }
          return fixture.input.clockchain.getBlock(args);
        },
      }),
    },
    "ANCHOR_UNVERIFIED",
  );
});

test("uses h+1 when present and falls back only for a branded MCP network failure", async (t) => {
  const fixture = await completeFixture(t);
  const finalHeight =
    fixture.transitions[2].onChain.blockHeight;
  const nextHeight = String(BigInt(finalHeight) + 1n);
  const successful = await verifyBilateralAuthorization({
    ...fixture.input,
    clockchain: clockchainWith(fixture.input.clockchain, {
      async getBlock(args) {
        if (args.height === nextHeight) {
          return {
            blockHeight: nextHeight,
            blockTime: "2026-07-24T20:00:04.000000000Z",
          };
        }
        return fixture.input.clockchain.getBlock(args);
      },
    }),
  });
  assert.equal(successful.outcome, "AUTHORIZED");
  assert.equal(
    successful.transitions[2].upperBoundMs,
    String(Date.parse("2026-07-24T20:00:04.000Z")),
  );

  const unavailable = await verifyBilateralAuthorization({
    ...fixture.input,
    clockchain: clockchainWith(fixture.input.clockchain, {
      async getBlock(args) {
        if (args.height === nextHeight) {
          throw new McpNetworkError(
            "production 502 after read retries",
            "MCP_HTTP_STATUS",
          );
        }
        return fixture.input.clockchain.getBlock(args);
      },
    }),
  });
  assert.equal(unavailable.outcome, "AUTHORIZED");
  assert.equal(
    unavailable.transitions[2].upperBoundMs,
    String(
      liveUpperBoundMs(
        Number(fixture.transitions[2].blockTimeMs),
      ),
    ),
  );

  for (const ambiguous of [
    new Error("generic ambiguity"),
    new McpProtocolError("malformed response"),
  ]) {
    await assertVerdictFailure(
      {
        ...fixture.input,
        clockchain: clockchainWith(
          fixture.input.clockchain,
          {
            async getBlock(args) {
              if (args.height === nextHeight) {
                throw ambiguous;
              }
              return fixture.input.clockchain.getBlock(args);
            },
          },
        ),
      },
      "ANCHOR_UNVERIFIED",
    );
  }
});

test("uses verifier next-block bounds and expires a late acceptance upper bound", async (t) => {
  const fixture = await completeFixture(t);
  const acknowledgmentHeight =
    fixture.transitions[2].onChain.blockHeight;
  let acknowledgmentReads = 0;
  await assertVerdictFailure(
    {
      ...fixture.input,
      clockchain: clockchainWith(fixture.input.clockchain, {
        async getBlock(args) {
          const block =
            await fixture.input.clockchain.getBlock(args);
          if (args.height === acknowledgmentHeight) {
            acknowledgmentReads += 1;
            if (acknowledgmentReads === 2) {
              return {
                ...block,
                blockTime:
                  "2026-07-24T20:20:00.000000000Z",
              };
            }
          }
          return block;
        },
      }),
    },
    "EXPIRED",
  );
});

test("rejects a non-monotonic next-block timestamp instead of accepting an optimistic bound", async (t) => {
  const fixture = await completeFixture(t);
  const acknowledgmentHeight =
    fixture.transitions[2].onChain.blockHeight;
  let acknowledgmentReads = 0;

  await assertVerdictFailure(
    {
      ...fixture.input,
      clockchain: clockchainWith(fixture.input.clockchain, {
        async getBlock(args) {
          const block =
            await fixture.input.clockchain.getBlock(args);
          if (args.height === acknowledgmentHeight) {
            acknowledgmentReads += 1;
            if (acknowledgmentReads === 2) {
              return {
                ...block,
                blockTime:
                  "2026-07-24T19:59:59.000000000Z",
              };
            }
          }
          return block;
        },
      }),
    },
    "ANCHOR_UNVERIFIED",
  );
});

test("rejects hostile descriptor accessors without invoking them", async (t) => {
  const fixture = await completeFixture(t);
  let getterCalls = 0;
  const hostile = {
    operator: fixture.descriptorEnvelope.operator,
  };
  Object.defineProperty(hostile, "descriptor", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return fixture.descriptorEnvelope.descriptor;
    },
  });

  await assertVerdictFailure(
    {
      ...fixture.input,
      descriptorEnvelope: hostile,
    },
    "FAILED",
  );
  assert.equal(getterCalls, 0);
});

function captureStream() {
  let value = "";
  return {
    get value() {
      return value;
    },
    write(chunk) {
      value += chunk;
    },
  };
}

async function defaultBuilderHarness(
  t,
  {
    token = "clockchain-token-secret-canary",
  } = {},
) {
  const fixture = await completeFixture(t);
  const descriptorPath = join(fixture.root, "descriptor.json");
  const mandatePath = join(fixture.root, "payer-mandate.json");
  const requestPath = join(fixture.root, "payment-request.json");
  const tokenPath = join(fixture.root, "clockchain.token");
  const output = join(fixture.root, "builder-output");
  await writeFile(
    descriptorPath,
    `${JSON.stringify(fixture.descriptorEnvelope)}\n`,
    { mode: 0o600 },
  );
  await writeFile(
    mandatePath,
    canonicalBytes(fixture.mandateEnvelope),
    { mode: 0o600 },
  );
  await writeFile(
    requestPath,
    canonicalBytes(fixture.requestEnvelope),
    { mode: 0o600 },
  );
  await writeFile(
    tokenPath,
    token.length === 4096 ? token : `${token}\n`,
    { mode: 0o600 },
  );
  const values = Object.freeze({
    clockchainTokenFile: tokenPath,
    descriptor: descriptorPath,
    output,
    payerMandate: mandatePath,
    payeeResults: fixture.payeeDirectory,
    payerResults: fixture.payerDirectory,
    paymentRequest: requestPath,
    rpcUrl: "https://rpc.example",
  });
  const arguments_ = [
    "--clockchain-token-file",
    tokenPath,
    "--descriptor",
    descriptorPath,
    "--output",
    output,
    "--payer-mandate",
    mandatePath,
    "--payee-results",
    fixture.payeeDirectory,
    "--payer-results",
    fixture.payerDirectory,
    "--payment-request",
    requestPath,
    "--rpc-url",
    values.rpcUrl,
  ];
  const metrics = {
    clockchainCreates: 0,
    events: [],
    ownerReads: 0,
    rpcCreates: 0,
  };
  function dependencies(overrides = {}) {
    return {
      createClockchainClient({ token: suppliedToken }) {
        metrics.clockchainCreates += 1;
        metrics.events.push("clockchain:create");
        assert.equal(suppliedToken, token);
        return fixture.input.clockchain;
      },
      createIdentityClient({ rpcUrl }) {
        metrics.rpcCreates += 1;
        metrics.events.push("rpc:create");
        assert.equal(rpcUrl, values.rpcUrl);
        return {
          async getChainId() {
            metrics.events.push("rpc:getChainId");
            return overrides.chainId ?? 11155111;
          },
          async readContract({ args }) {
            metrics.ownerReads += 1;
            metrics.events.push("rpc:ownerOf");
            return String(args[0]) ===
              fixture.descriptor.payer.agentId
              ? fixture.descriptor.payer.address
              : fixture.descriptor.payee.address;
          },
        };
      },
      fileSystem: overrides.fileSystem,
      async runGit({ args, cwd }) {
        assert.equal(
          cwd,
          dirname(dirname(fileURLToPath(import.meta.url))),
        );
        const command = args.join(" ");
        metrics.events.push(`git:${command}`);
        if (args[0] === "show") {
          return {
            stdout: `${fixture.repositoryPublicKey}\n`,
          };
        }
        if (args[0] === "rev-parse") {
          return {
            stdout: `${
              overrides.head ?? fixture.descriptor.repositorySha
            }\n`,
          };
        }
        if (args[0] === "status") {
          return {
            stdout: overrides.status ?? "",
          };
        }
        throw new Error("unexpected git operation");
      },
    };
  }
  return {
    arguments_,
    dependencies,
    descriptorPath,
    fixture,
    mandatePath,
    metrics,
    output,
    token,
    tokenPath,
    requestPath,
    values,
  };
}

test("default verifier builder authenticates local provenance and chain before creating Clockchain", async (t) => {
  const {
    VERIFIER_REPOSITORY_ROOT,
    buildDefaultVerifierInput,
  } = await import("../scripts/verify-bilateral-results.mjs");
  assert.equal(typeof buildDefaultVerifierInput, "function");
  assert.equal(
    VERIFIER_REPOSITORY_ROOT,
    dirname(dirname(fileURLToPath(import.meta.url))),
  );
  const harness = await defaultBuilderHarness(t);
  const input = await buildDefaultVerifierInput(
    harness.values,
    harness.dependencies(),
  );
  assert.equal(
    await input.repositoryPublicKeyResolver({
      keyId: harness.fixture.descriptorEnvelope.operator.keyId,
      repositoryPath:
        "docs/operator-keys/verdict-test-operator.pub",
      repositorySha:
        harness.fixture.descriptor.repositorySha,
    }),
    harness.fixture.repositoryPublicKey,
  );
  assert.deepEqual(harness.metrics.events, [
    "git:show 0123456789abcdef0123456789abcdef01234567:docs/operator-keys/verdict-test-operator.pub",
    "git:rev-parse --verify HEAD",
    "git:status --porcelain=v1 --untracked-files=all",
    "rpc:create",
    "rpc:getChainId",
    "clockchain:create",
  ]);
  assert.equal(
    await input.ownerOf({
      agentId: harness.fixture.descriptor.payer.agentId,
      registry: harness.fixture.descriptor.registry,
    }),
    harness.fixture.descriptor.payer.address,
  );
  assert.equal(harness.metrics.ownerReads, 1);
});

test("a 4096-byte token survives the default builder-to-verifier contract", async (t) => {
  const { buildDefaultVerifierInput } =
    await import("../scripts/verify-bilateral-results.mjs");
  const token = "t".repeat(4096);
  const harness = await defaultBuilderHarness(t, { token });
  const input = await buildDefaultVerifierInput(
    harness.values,
    harness.dependencies(),
  );
  assert.deepEqual(input.canaries, [token]);
  const verdict = await verifyBilateralAuthorization(input);
  assert.equal(verdict.outcome, "AUTHORIZED");
});

test("default verifier builder bounds descriptor, token, and intent reads and rejects races", async (t) => {
  const { buildDefaultVerifierInput } =
    await import("../scripts/verify-bilateral-results.mjs");
  for (const target of [
    "descriptor",
    "token",
    "payer mandate",
    "payment request",
  ]) {
    for (const scenario of [
      { metadataField: undefined, overflow: true },
      { metadataField: "ctimeMs", overflow: false },
      { truncate: true },
    ]) {
      await t.test(
        `${target} ${
          scenario.overflow
            ? "growth"
            : scenario.truncate
              ? "truncation"
              : "metadata"
        }`,
        async (t) => {
          const harness = await defaultBuilderHarness(t);
          const targetPath =
            target === "descriptor"
              ? harness.descriptorPath
              : target === "token"
                ? harness.tokenPath
                : target === "payer mandate"
                  ? harness.mandatePath
                  : harness.requestPath;
          let readLength = 0;
          await assert.rejects(
            buildDefaultVerifierInput(
              harness.values,
              harness.dependencies({
                fileSystem: {
                  async open(path, flags) {
                    const handle = await open(path, flags);
                    return path === targetPath
                      ? adversarialVerdictReadHandle(handle, {
                          ...scenario,
                          onRead(length) {
                            readLength = Math.max(
                              readLength,
                              length,
                            );
                          },
                        })
                      : handle;
                  },
                },
              }),
            ),
            BilateralVerdictError,
          );
          assert.equal(
            readLength,
            target === "descriptor"
              ? (1024 * 1024) + 1
              : target === "token"
                ? 4097
                : 65_537,
          );
        },
      );
    }
  }
});

test("default verifier CLI rejects unsafe local state and wrong chain before Clockchain without leaking secrets", async (t) => {
  const { buildDefaultVerifierInput } =
    await import("../scripts/verify-bilateral-results.mjs");
  const scenarios = [
    {
      name: "wrong full HEAD",
      overrides: { head: "f".repeat(40) },
    },
    {
      name: "dirty worktree",
      overrides: { status: " M README.md\n" },
    },
    {
      name: "wrong RPC chain",
      overrides: { chainId: 1 },
    },
    {
      async setup(harness) {
        const target = join(harness.fixture.root, "descriptor-target.json");
        await writeFile(
          target,
          await readFile(harness.descriptorPath),
          { mode: 0o600 },
        );
        await rm(harness.descriptorPath);
        await symlink(target, harness.descriptorPath);
      },
      name: "symlinked descriptor",
    },
    {
      async setup(harness) {
        const target = join(harness.fixture.root, "mandate-target.json");
        await writeFile(target, await readFile(harness.mandatePath), {
          mode: 0o600,
        });
        await rm(harness.mandatePath);
        await symlink(target, harness.mandatePath);
      },
      name: "symlinked payer mandate",
    },
    {
      async setup(harness) {
        const target = join(harness.fixture.root, "request-target.json");
        await writeFile(target, await readFile(harness.requestPath), {
          mode: 0o600,
        });
        await rm(harness.requestPath);
        await symlink(target, harness.requestPath);
      },
      name: "symlinked payment request",
    },
    {
      async setup(harness) {
        await rm(harness.tokenPath);
        await execFileAsync("mkfifo", [harness.tokenPath]);
      },
      name: "FIFO token",
    },
    {
      async setup(harness) {
        await rm(harness.mandatePath);
        await execFileAsync("mkfifo", [harness.mandatePath]);
      },
      name: "FIFO payer mandate",
    },
    {
      async setup(harness) {
        await rm(harness.requestPath);
        await execFileAsync("mkfifo", [harness.requestPath]);
      },
      name: "FIFO payment request",
    },
    {
      async setup(harness) {
        await rm(harness.mandatePath);
        await mkdir(harness.mandatePath, { mode: 0o700 });
      },
      name: "directory payer mandate path",
    },
    {
      async setup(harness) {
        await rm(harness.requestPath);
        await mkdir(harness.requestPath, { mode: 0o700 });
      },
      name: "directory payment request path",
    },
    {
      async setup(harness) {
        await chmod(harness.tokenPath, 0o644);
      },
      name: "permissive token mode",
    },
    {
      async setup(harness) {
        const defaultOpen = open;
        harness.overrides = {
          fileSystem: {
            async open(path, flags) {
              const handle = await defaultOpen(path, flags);
              if (path !== harness.descriptorPath) {
                return handle;
              }
              let statCalls = 0;
              return {
                close: () => handle.close(),
                read: (...args) => handle.read(...args),
                async stat() {
                  const metadata = await handle.stat();
                  statCalls += 1;
                  if (statCalls === 1) {
                    return metadata;
                  }
                  return {
                    ...metadata,
                    isFile: () => true,
                    mtimeMs: metadata.mtimeMs + 1,
                  };
                },
              };
            },
          },
        };
      },
      name: "changed descriptor metadata",
    },
    {
      async setup(harness) {
        harness.overrides = {
          fileSystem: adversarialBuilderFileSystem(
            harness.mandatePath,
            { metadataField: "ctimeMs" },
          ),
        };
      },
      name: "changed payer mandate metadata",
    },
    {
      async setup(harness) {
        harness.overrides = {
          fileSystem: adversarialBuilderFileSystem(
            harness.requestPath,
            { truncate: true },
          ),
        };
      },
      name: "truncated payment request",
    },
    {
      async setup(harness) {
        await writeFile(harness.mandatePath, "{", { mode: 0o600 });
      },
      name: "malformed payer mandate JSON",
    },
    {
      async setup(harness) {
        await writeFile(harness.requestPath, "{", { mode: 0o600 });
      },
      name: "malformed payment request JSON",
    },
    {
      async setup(harness) {
        await writeFile(
          harness.mandatePath,
          Buffer.concat([
            canonicalBytes(harness.fixture.mandateEnvelope),
            Buffer.from("\n", "utf8"),
          ]),
          { mode: 0o600 },
        );
      },
      name: "noncanonical payer mandate JSON",
    },
    {
      async setup(harness) {
        await writeFile(
          harness.requestPath,
          Buffer.concat([
            canonicalBytes(harness.fixture.requestEnvelope),
            Buffer.from("\n", "utf8"),
          ]),
          { mode: 0o600 },
        );
      },
      name: "noncanonical payment request JSON",
    },
  ];

  for (const scenario of scenarios) {
    await t.test(scenario.name, async (t) => {
      const harness = await defaultBuilderHarness(t);
      await scenario.setup?.(harness);
      const stdout = captureStream();
      const stderr = captureStream();
      let verifierCalls = 0;
      const exitCode = await runVerifierCli(harness.arguments_, {
        buildVerifierInput: (values) =>
          buildDefaultVerifierInput(
            values,
            harness.dependencies({
              ...scenario.overrides,
              ...harness.overrides,
            }),
          ),
        async verify() {
          verifierCalls += 1;
          throw new Error("unreachable");
        },
        stderr,
        stdout,
      });
      assert.equal(exitCode, 1);
      assert.equal(verifierCalls, 0);
      assert.equal(harness.metrics.clockchainCreates, 0);
      assert.equal(
        stdout.value,
        '{"outcome":"FAILED","paymentMoved":false,"schema":"clockchain.bilateral-authorization-verdict/v2"}\n',
      );
      assert.equal(stderr.value, "BILATERAL_VERDICT_FAILED\n");
      assert.equal(stdout.value.includes(harness.token), false);
      assert.equal(stderr.value.includes(harness.token), false);
      await assert.rejects(() => lstat(harness.output), {
        code: "ENOENT",
      });
    });
  }
});

test("pins the exact verifier CLI and publishes a hashed completion marker before stdout", async (t) => {
  const fixture = await completeFixture(t);
  const output = join(fixture.root, "verdict-output");
  const stdout = captureStream();
  const stderr = captureStream();
  const arguments_ = [
    "--clockchain-token-file",
    "clockchain.token",
    "--descriptor",
    "descriptor.json",
    "--output",
    output,
    "--payer-mandate",
    "payer-mandate.json",
    "--payee-results",
    fixture.payeeDirectory,
    "--payer-results",
    fixture.payerDirectory,
    "--payment-request",
    "payment-request.json",
    "--rpc-url",
    "https://rpc.example",
  ];

  assert.deepEqual([...CLI_ARGUMENTS], [
    "--clockchain-token-file",
    "--descriptor",
    "--output",
    "--payer-mandate",
    "--payee-results",
    "--payer-results",
    "--payment-request",
    "--rpc-url",
  ]);
  const exitCode = await runVerifierCli(arguments_, {
    async buildVerifierInput(values) {
      assert.deepEqual(values, {
        clockchainTokenFile: "clockchain.token",
        descriptor: "descriptor.json",
        output,
        payerMandate: "payer-mandate.json",
        payeeResults: fixture.payeeDirectory,
        payerResults: fixture.payerDirectory,
        paymentRequest: "payment-request.json",
        rpcUrl: "https://rpc.example",
      });
      return fixture.input;
    },
    stderr,
    stdout,
  });

  assert.equal(exitCode, 0);
  assert.equal(stdout.value, "AUTHORIZED\n");
  assert.equal(stderr.value, "");
  const json = await readFile(
    join(output, "bilateral-verdict.json"),
    "utf8",
  );
  const markdown = await readFile(
    join(output, "BILATERAL-VERDICT.md"),
    "utf8",
  );
  const marker = JSON.parse(
    await readFile(
      join(output, ".bilateral-verdict.complete.json"),
      "utf8",
    ),
  );
  assert.equal(
    markdown,
    renderBilateralVerdictMarkdown(JSON.parse(json)),
  );
  assert.deepEqual(marker, {
    jsonSha256: createHash("sha256")
      .update(json)
      .digest("hex"),
    markdownSha256: createHash("sha256")
      .update(markdown)
      .digest("hex"),
    schema:
      "clockchain.bilateral-authorization-verdict-completion/v2",
  });
});

test("runs a fresh-task publication gate after the durable verdict marker and before authorizing stdout", async (t) => {
  const fixture = await completeFixture(t);
  const output = join(
    fixture.root,
    "fresh-task-publication-gate",
  );
  const stdout = captureStream();
  const order = [];
  const arguments_ = [
    "--clockchain-token-file",
    "clockchain.token",
    "--descriptor",
    "descriptor.json",
    "--output",
    output,
    "--payer-mandate",
    "payer-mandate.json",
    "--payee-results",
    fixture.payeeDirectory,
    "--payer-results",
    fixture.payerDirectory,
    "--payment-request",
    "payment-request.json",
    "--rpc-url",
    "https://rpc.example",
  ];
  const exitCode = await runVerifierCli(arguments_, {
    async beforeAuthorizationOutput(value) {
      assert.equal(value.output, output);
      assert.equal(value.verdict.paymentMoved, false);
      assert.equal(
        await readFile(
          join(
            output,
            ".bilateral-verdict.complete.json",
          ),
          "utf8",
        ).then((bytes) => bytes.length > 0),
        true,
      );
      assert.equal(stdout.value, "");
      order.push("gate");
    },
    async buildVerifierInput() {
      return fixture.input;
    },
    stderr: captureStream(),
    stdout: {
      write(value) {
        order.push("stdout");
        stdout.write(value);
      },
    },
  });
  assert.equal(exitCode, 0);
  assert.deepEqual(order, ["gate", "stdout"]);
  assert.equal(stdout.value, "AUTHORIZED\n");

  const rejectedOutput = join(
    fixture.root,
    "fresh-task-publication-rejected",
  );
  const rejectedStdout = captureStream();
  assert.equal(
    await runVerifierCli(
      arguments_.map((value) =>
        value === output ? rejectedOutput : value),
      {
        async beforeAuthorizationOutput() {
          throw new Error("publication rejected");
        },
        async buildVerifierInput() {
          return fixture.input;
        },
        stderr: captureStream(),
        stdout: rejectedStdout,
      },
    ),
    1,
  );
  assert.equal(
    rejectedStdout.value.includes("AUTHORIZED"),
    false,
  );
  await assert.rejects(
    lstat(
      join(
        rejectedOutput,
        ".bilateral-verdict.complete.json",
      ),
    ),
    { code: "ENOENT" },
  );
});

function publicationFileSystem(trace, failAfter) {
  let step = 0;
  async function observed(label, operation) {
    const result = await operation();
    trace.push(label);
    step += 1;
    if (step === failAfter) {
      throw new Error(`injected publication failure at ${label}`);
    }
    return result;
  }
  function wrapHandle(path, handle) {
    const label = basename(path) || "output-directory";
    return {
      close: () =>
        observed(`close:${label}`, () => handle.close()),
      read: (...args) => handle.read(...args),
      stat: () => handle.stat(),
      sync: () =>
        observed(`sync:${label}`, () => handle.sync()),
      writeFile: (...args) =>
        observed(
          `write:${label}`,
          () => handle.writeFile(...args),
        ),
    };
  }
  return {
    lstat: (path) =>
      observed(`lstat:${basename(path)}`, () => lstat(path)),
    mkdir: (path, options) =>
      observed(
        `mkdir:${basename(path)}`,
        () => mkdir(path, options),
      ),
    async open(path, flags, mode) {
      const label =
        `open:${basename(path) || "output-directory"}`;
      const handle = await open(path, flags, mode);
      trace.push(label);
      step += 1;
      if (step === failAfter) {
        await handle.close();
        throw new Error(
          `injected publication failure at ${label}`,
        );
      }
      return wrapHandle(path, handle);
    },
    rename: (from, to) =>
      observed(
        `rename:${basename(to)}`,
        () => rename(from, to),
      ),
    rm,
  };
}

test("every aggregate publication-step failure removes marker authority and suppresses authorizing stdout", async (t) => {
  const fixture = await completeFixture(t);
  const argumentsFor = (output) => [
    "--clockchain-token-file",
    "clockchain.token",
    "--descriptor",
    "descriptor.json",
    "--output",
    output,
    "--payer-mandate",
    "payer-mandate.json",
    "--payee-results",
    fixture.payeeDirectory,
    "--payer-results",
    fixture.payerDirectory,
    "--payment-request",
    "payment-request.json",
    "--rpc-url",
    "https://rpc.example",
  ];
  const successfulOutput = join(fixture.root, "publication-trace");
  const trace = [];
  assert.equal(
    await runVerifierCli(argumentsFor(successfulOutput), {
      async buildVerifierInput() {
        return fixture.input;
      },
      fileSystem: publicationFileSystem(trace),
      stderr: captureStream(),
      stdout: captureStream(),
    }),
    0,
  );
  assert.ok(
    trace.includes("rename:.bilateral-verdict.complete.json"),
  );
  assert.ok(
    trace.indexOf("rename:.bilateral-verdict.complete.json") >
      trace.indexOf("rename:BILATERAL-VERDICT.md"),
  );
  assert.ok(
    trace.lastIndexOf("sync:publication-trace") >
      trace.indexOf("rename:.bilateral-verdict.complete.json"),
  );

  for (let failAfter = 1; failAfter <= trace.length; failAfter += 1) {
    const output = join(
      fixture.root,
      `publication-failure-${failAfter}`,
    );
    const stdout = captureStream();
    const stderr = captureStream();
    const exitCode = await runVerifierCli(argumentsFor(output), {
      async buildVerifierInput() {
        return fixture.input;
      },
      fileSystem: publicationFileSystem([], failAfter),
      stderr,
      stdout,
    });
    assert.equal(exitCode, 1, trace[failAfter - 1]);
    assert.equal(
      stdout.value.includes("AUTHORIZED"),
      false,
      trace[failAfter - 1],
    );
    await assert.rejects(
      () =>
        lstat(
          join(
            output,
            ".bilateral-verdict.complete.json",
          ),
        ),
      { code: "ENOENT" },
    );
  }
});

test("an authorizing stdout crash revokes the completion marker", async (t) => {
  const fixture = await completeFixture(t);
  const output = join(fixture.root, "stdout-crash");
  const stdout = {
    value: "",
    write(chunk) {
      if (chunk === "AUTHORIZED\n") {
        throw new Error("stdout crashed");
      }
      this.value += chunk;
    },
  };
  const exitCode = await runVerifierCli(
    [
      "--clockchain-token-file",
      "clockchain.token",
      "--descriptor",
      "descriptor.json",
      "--output",
      output,
      "--payee-results",
      fixture.payeeDirectory,
      "--payer-results",
      fixture.payerDirectory,
      "--rpc-url",
      "https://rpc.example",
    ],
    {
      async buildVerifierInput() {
        return fixture.input;
      },
      stderr: captureStream(),
      stdout,
    },
  );
  assert.equal(exitCode, 1);
  assert.equal(stdout.value.includes("AUTHORIZED"), false);
  await assert.rejects(
    () =>
      lstat(
        join(output, ".bilateral-verdict.complete.json"),
      ),
    { code: "ENOENT" },
  );
});

test("CLI failures emit only a fixed non-authorizing terminal result and no artifacts", async (t) => {
  const fixture = await completeFixture(t);
  const output = join(fixture.root, "failed-output");
  const stdout = captureStream();
  const stderr = captureStream();
  const arguments_ = [
    "--clockchain-token-file",
    "clockchain.token",
    "--descriptor",
    "descriptor.json",
    "--output",
    output,
    "--payer-mandate",
    "payer-mandate.json",
    "--payee-results",
    fixture.payeeDirectory,
    "--payer-results",
    fixture.payerDirectory,
    "--payment-request",
    "payment-request.json",
    "--rpc-url",
    "https://rpc.example",
  ];

  const exitCode = await runVerifierCli(arguments_, {
    async buildVerifierInput() {
      throw new BilateralVerdictError("EXPIRED");
    },
    stderr,
    stdout,
  });
  assert.equal(exitCode, 1);
  assert.equal(
    stdout.value,
    '{"outcome":"EXPIRED","paymentMoved":false,"schema":"clockchain.bilateral-authorization-verdict/v2"}\n',
  );
  assert.equal(stderr.value, "BILATERAL_VERDICT_FAILED\n");
  await assert.rejects(() => readFile(output), {
    code: "ENOENT",
  });
});

test("CLI rejects missing, duplicate, and unknown arguments before dependency calls", async () => {
  let calls = 0;
  const dependencies = {
    async buildVerifierInput() {
      calls += 1;
      throw new Error("unreachable");
    },
    stderr: captureStream(),
    stdout: captureStream(),
  };
  for (const arguments_ of [
    [],
    ["--descriptor", "one", "--descriptor", "two"],
    ["--unknown", "value"],
  ]) {
    assert.equal(
      await runVerifierCli(arguments_, dependencies),
      1,
    );
  }
  assert.equal(calls, 0);
});
