import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs, promisify } from "node:util";

import { createRelayClient } from "../relay/client.mjs";
import { MANDATE_MIN_WINDOW_MS } from "../core/deadline.mjs";
import {
  REGISTRY_ADDRESS,
  operatorPublicKeyPath,
  verifyDescriptorEnvelope,
} from "../core/descriptor.mjs";
import {
  DEMO_INTENT_POLICY,
  buildHandshakeRequiredResult,
  buildIntakeInput,
  intakeDigest,
  validatePaymentIntakeInput,
} from "../core/intake.mjs";
import { buildPayerMandate } from "../core/mandate-construction.mjs";
import {
  payerMandateDigest,
  signPayerMandate,
  verifyPayerMandate,
} from "../core/payer-mandate.mjs";
import {
  paymentRequestDigest,
  verifyPaymentRequest,
} from "../core/payment-request.mjs";
import { runPayerRole } from "../core/roles-core.mjs";
import { publishPartyEvidence } from "../core/runner.mjs";
import {
  RELAY_KINDS,
  createMessenger,
  exactlyOneFrom,
  validatePartyReadyBody,
} from "./catalog.mjs";
import {
  RoleShellError,
  accountFromPrivateKeyHex,
  connectClockchain,
  createOwnerOf,
  createStatusReporter,
  emitStatus,
  loadPrivateKeyHex,
  readJsonFile,
  signerFromAccount,
  startHeartbeat,
  waitForRelayMessage,
} from "./common.mjs";

// Payer role shell. The operator enrolls the payer identity; this
// process binds the payer role on the relay, waits for the requestor's
// party-ready, constructs and publishes the signed mandate, answers
// the intake, verifies the signed payment request, waits for the
// operator-signed descriptor, then runs the proven anchor sequence.
// Every cross-process wait is unbounded with heartbeat (human-paced);
// the in-window watch bound is computed inside runPayerRole. Restart
// safety comes from adopting prior relay artifacts and the proven
// on-chain adoption inside the role core.

const MANDATE_WINDOW_MS = MANDATE_MIN_WINDOW_MS * 2;
const MAX_MANIFEST_BYTES = 65_536;
const MAX_OPERATOR_KEY_BYTES = 4_096;
const EVIDENCE_UPLOAD_ATTEMPTS = 3;
const REPOSITORY_ROOT = dirname(
  dirname(dirname(fileURLToPath(import.meta.url))),
);

const MANIFEST_SCHEMA = "handshake-payer-manifest/v2";
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SHA_PATTERN = /^[0-9a-f]{40}$/;
const DIGEST_PATTERN = /^[0-9a-f]{64}$/;
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const DECIMAL_PATTERN = /^(0|[1-9][0-9]*)$/;
const PRINTABLE_PATTERN = /^[ -~]+$/;
const RAW_KEY_PATTERN = /^[A-Za-z0-9+/]{43}=$/;

const execFileAsync = promisify(execFile);

function shellFailure(code) {
  throw new RoleShellError(code);
}

function printable(value, max = 128) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= max &&
    PRINTABLE_PATTERN.test(value) &&
    value.trim() === value
  );
}

export function validatePayerManifest(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value)
  ) {
    shellFailure("MANIFEST_SHAPE");
  }
  const keys = Object.keys(value);
  const expected = [
    "payer",
    "operatorKeyId",
    "relayUrl",
    "releaseId",
    "repositorySha",
    "schema",
    "sessionId",
    "subjectRun",
  ];
  if (
    keys.length !== expected.length ||
    expected.some((key) => !keys.includes(key))
  ) {
    shellFailure("MANIFEST_SHAPE");
  }
  const payer = value.payer;
  if (
    payer === null ||
    typeof payer !== "object" ||
    Array.isArray(payer)
  ) {
    shellFailure("MANIFEST_SHAPE");
  }
  const payerKeys = Object.keys(payer);
  const expectedPayer = ["address", "agentId", "keyFile"];
  if (
    payerKeys.length !== expectedPayer.length ||
    expectedPayer.some((key) => !payerKeys.includes(key))
  ) {
    shellFailure("MANIFEST_SHAPE");
  }
  let relayUrl;
  try {
    relayUrl = new URL(value.relayUrl);
  } catch {
    shellFailure("MANIFEST_SHAPE");
  }
  const loopback =
    relayUrl.protocol === "http:" &&
    ["127.0.0.1", "localhost", "::1"].includes(relayUrl.hostname);
  if (
    value.schema !== MANIFEST_SCHEMA ||
    !UUID_PATTERN.test(value.sessionId) ||
    !SHA_PATTERN.test(value.repositorySha) ||
    !printable(value.releaseId) ||
    !printable(value.operatorKeyId) ||
    !["rehearsal", "stakeholder"].includes(value.subjectRun) ||
    !(relayUrl.protocol === "https:" || loopback) ||
    !ADDRESS_PATTERN.test(payer.address) ||
    !DECIMAL_PATTERN.test(payer.agentId) ||
    payer.agentId.length > 16 ||
    !printable(payer.keyFile, 512) ||
    !payer.keyFile.startsWith("/")
  ) {
    shellFailure("MANIFEST_SHAPE");
  }
  return Object.freeze({
    operatorKeyId: value.operatorKeyId,
    payer: Object.freeze({
      address: payer.address,
      agentId: payer.agentId,
      keyFile: payer.keyFile,
    }),
    relayUrl: value.relayUrl,
    releaseId: value.releaseId,
    repositorySha: value.repositorySha,
    sessionId: value.sessionId,
    subjectRun: value.subjectRun,
  });
}

async function readOperatorPublicKey(operatorKeyId) {
  const path = join(
    REPOSITORY_ROOT,
    operatorPublicKeyPath(operatorKeyId),
  );
  let raw;
  try {
    raw = await readFile(path, "utf8");
  } catch {
    shellFailure("OPERATOR_KEY_UNAVAILABLE");
  }
  if (Buffer.byteLength(raw, "utf8") > MAX_OPERATOR_KEY_BYTES) {
    shellFailure("OPERATOR_KEY_UNAVAILABLE");
  }
  const trimmed = raw.endsWith("\n") ? raw.slice(0, -1) : raw;
  if (!RAW_KEY_PATTERN.test(trimmed)) {
    shellFailure("OPERATOR_KEY_UNAVAILABLE");
  }
  return trimmed;
}

async function assertRepositoryPinned(repositorySha) {
  let stdout;
  try {
    ({ stdout } = await execFileAsync(
      "git",
      ["rev-parse", "HEAD"],
      { cwd: REPOSITORY_ROOT },
    ));
  } catch {
    shellFailure("REPOSITORY_MISMATCH");
  }
  if (stdout.trim() !== repositorySha) {
    shellFailure("REPOSITORY_MISMATCH");
  }
}

async function collectMessages(relay, sessionId) {
  const messages = [];
  let cursor = 0;
  for (;;) {
    const page = await relay.pollMessages({
      sessionId,
      after: cursor,
      waitMs: 0,
    });
    if (
      page === null ||
      typeof page !== "object" ||
      !Array.isArray(page.messages) ||
      typeof page.next !== "number"
    ) {
      shellFailure("WAIT_RELAY_RESPONSE");
    }
    messages.push(...page.messages);
    if (page.next === cursor) return messages;
    cursor = page.next;
  }
}

async function waitForPeerKind(relay, sessionId, kind, role) {
  const { message } = await waitForRelayMessage({
    relay,
    sessionId,
    kinds: [kind],
  });
  if (message.role !== role) {
    shellFailure("UNEXPECTED_ROLE");
  }
  return message;
}

async function uploadEvidence(relay, sessionId, triple) {
  let lastError;
  for (
    let attempt = 0;
    attempt < EVIDENCE_UPLOAD_ATTEMPTS;
    attempt += 1
  ) {
    try {
      await relay.putEvidence(sessionId, "payer", triple);
      return;
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError;
}

export async function main(argv = process.argv.slice(2)) {
  const { values } = parseArgs({
    args: argv,
    options: {
      manifest: { type: "string" },
      state: { type: "string" },
    },
    strict: true,
  });
  if (
    typeof values.manifest !== "string" ||
    typeof values.state !== "string" ||
    !values.state.startsWith("/")
  ) {
    shellFailure("ARGS");
  }
  const manifest = validatePayerManifest(
    await readJsonFile(values.manifest, MAX_MANIFEST_BYTES),
  );
  const stateRoot = values.state;
  const stdout = process.stdout;
  const sessionId = manifest.sessionId;

  emitStatus(stdout, "PAYER_STARTING", { sessionId });
  await assertRepositoryPinned(manifest.repositorySha);
  const operatorPublicKey = await readOperatorPublicKey(
    manifest.operatorKeyId,
  );
  const privateKeyHex = await loadPrivateKeyHex(
    manifest.payer.keyFile,
  );
  const account = accountFromPrivateKeyHex(privateKeyHex);
  if (account.address.toLowerCase() !== manifest.payer.address) {
    shellFailure("IDENTITY_MISMATCH");
  }
  const signMessage = signerFromAccount(account);

  const relay = createRelayClient({ relayUrl: manifest.relayUrl });
  const messenger = createMessenger({
    relay,
    role: "payer",
    senderKey: `payer:${manifest.payer.address}`,
    sessionId,
    sign: signMessage,
  });
  const reporter = createStatusReporter({
    relay,
    sessionId,
    role: "payer",
  });
  const outputDirectory = join(stateRoot, "evidence");
  await mkdir(outputDirectory, { recursive: true, mode: 0o700 });

  const prior = await collectMessages(relay, sessionId);
  messenger.adoptPrior(prior);

  let heartbeat = startHeartbeat(reporter, "PAYER_WAITING");
  try {
    // 1. Requestor readiness (human-paced wait).
    let readyMessage = exactlyOneFrom(
      prior,
      RELAY_KINDS.PARTY_READY,
      "payee",
    );
    if (readyMessage === null) {
      emitStatus(stdout, "PAYER_AWAITING_REQUESTOR", {});
      readyMessage = await waitForPeerKind(
        relay,
        sessionId,
        RELAY_KINDS.PARTY_READY,
        "payee",
      );
    }
    const payee = validatePartyReadyBody(readyMessage.body);
    const ownerOf = createOwnerOf();
    const registeredOwner = await ownerOf({
      agentId: payee.agentId,
      registry: REGISTRY_ADDRESS,
    });
    if (registeredOwner !== payee.address) {
      shellFailure("IDENTITY_MISMATCH");
    }
    emitStatus(stdout, "PAYER_REQUESTOR_READY", {
      payee: payee.address,
    });

    // 2. Mandate: adopt a prior publication or construct fresh. The
    // per-construction identifiers are read back from the signed
    // envelope; every security-critical field binds to local authority.
    let mandateEnvelope;
    const priorMandate = exactlyOneFrom(
      prior,
      RELAY_KINDS.MANDATE_PUBLISHED,
      "payer",
    );
    if (priorMandate !== null) {
      mandateEnvelope = priorMandate.body?.envelope;
    } else {
      const intakeRequestId = randomUUID();
      const issuedAtMs = Date.now();
      const mandate = buildPayerMandate({
        amount: DEMO_INTENT_POLICY.amount,
        expiresAtMs: issuedAtMs + MANDATE_WINDOW_MS,
        generateIntakeRequestId: () => intakeRequestId,
        intakeDigest: intakeDigest(
          buildIntakeInput(intakeRequestId),
        ),
        invoiceReferencePrefix:
          DEMO_INTENT_POLICY.invoiceReferencePrefix,
        issuedAtMs,
        payee: { address: payee.address, agentId: payee.agentId },
        payer: {
          address: manifest.payer.address,
          agentId: manifest.payer.agentId,
        },
        purpose: DEMO_INTENT_POLICY.purpose,
        releaseId: manifest.releaseId,
        repositorySha: manifest.repositorySha,
        sessionId,
        subjectRun: manifest.subjectRun,
      });
      mandateEnvelope = await signPayerMandate({
        mandate,
        signMessage,
      });
      await messenger.send(RELAY_KINDS.MANDATE_PUBLISHED, {
        envelope: mandateEnvelope,
      });
      emitStatus(stdout, "PAYER_MANDATE_PUBLISHED", {
        mandateDigest: payerMandateDigest(mandateEnvelope),
      });
    }
    const rawMandate = mandateEnvelope?.mandate;
    if (
      rawMandate === null ||
      typeof rawMandate !== "object" ||
      typeof rawMandate.intakeDigest !== "string" ||
      !DIGEST_PATTERN.test(rawMandate.intakeDigest) ||
      typeof rawMandate.intakeRequestId !== "string"
    ) {
      shellFailure("MANDATE_INVALID");
    }
    const verifiedMandate = await verifyPayerMandate({
      envelope: mandateEnvelope,
      expected: {
        amount: DEMO_INTENT_POLICY.amount,
        intakeDigest: rawMandate.intakeDigest,
        intakeRequestId: rawMandate.intakeRequestId,
        invoiceReferencePrefix:
          DEMO_INTENT_POLICY.invoiceReferencePrefix,
        payee: { address: payee.address, agentId: payee.agentId },
        payer: {
          address: manifest.payer.address,
          agentId: manifest.payer.agentId,
        },
        purpose: DEMO_INTENT_POLICY.purpose,
        releaseId: manifest.releaseId,
        repositorySha: manifest.repositorySha,
        requestEndpoint: `/v1/sessions/${sessionId}/payment-requests`,
        sessionId,
        subjectRun: manifest.subjectRun,
      },
      nowMs: Date.now(),
    });

    // 3. Intake: await request_payment, answer HANDSHAKE_REQUIRED.
    let intakeMessage = exactlyOneFrom(
      prior,
      RELAY_KINDS.PAYMENT_REQUEST,
      "payee",
    );
    if (intakeMessage === null) {
      emitStatus(stdout, "PAYER_AWAITING_INTAKE", {});
      intakeMessage = await waitForPeerKind(
        relay,
        sessionId,
        RELAY_KINDS.PAYMENT_REQUEST,
        "payee",
      );
    }
    const intakeInput = validatePaymentIntakeInput(
      intakeMessage.body?.intake,
    );
    if (
      intakeInput.intakeRequestId !==
        verifiedMandate.mandate.intakeRequestId ||
      intakeDigest(intakeInput) !==
        verifiedMandate.mandate.intakeDigest
    ) {
      shellFailure("INTAKE_MISMATCH");
    }
    if (
      exactlyOneFrom(
        prior,
        RELAY_KINDS.HANDSHAKE_REQUIRED,
        "payer",
      ) === null
    ) {
      const result = buildHandshakeRequiredResult({
        repositorySha: manifest.repositorySha,
        toolInput: intakeInput,
      });
      await messenger.send(RELAY_KINDS.HANDSHAKE_REQUIRED, {
        result,
      });
      emitStatus(stdout, "PAYER_INTAKE_ANSWERED", {});
    }

    // 4. Signed payment request from the requestor.
    let requestMessage = exactlyOneFrom(
      prior,
      RELAY_KINDS.PAYMENT_REQUEST_SIGNED,
      "payee",
    );
    if (requestMessage === null) {
      emitStatus(stdout, "PAYER_AWAITING_SIGNED_REQUEST", {});
      requestMessage = await waitForPeerKind(
        relay,
        sessionId,
        RELAY_KINDS.PAYMENT_REQUEST_SIGNED,
        "payee",
      );
    }
    const requestEnvelope = requestMessage.body?.envelope;
    await verifyPaymentRequest({
      envelope: requestEnvelope,
      mandateEnvelope,
      expected: {
        amount: verifiedMandate.mandate.amount,
        intakeDigest: verifiedMandate.mandate.intakeDigest,
        intakeRequestId:
          verifiedMandate.mandate.intakeRequestId,
        invoiceReferencePrefix:
          verifiedMandate.mandate.invoiceReferencePrefix,
        payee: verifiedMandate.mandate.payee,
        payer: verifiedMandate.mandate.payer,
        purpose: verifiedMandate.mandate.purpose,
        releaseId: verifiedMandate.mandate.releaseId,
        repositorySha: verifiedMandate.mandate.repositorySha,
        sessionId,
        subjectRun: manifest.subjectRun,
      },
      nowMs: Date.now(),
    });
    emitStatus(stdout, "PAYER_REQUEST_VERIFIED", {
      requestDigest: paymentRequestDigest(requestEnvelope),
    });

    // 5. Operator-signed descriptor.
    let descriptorMessage = exactlyOneFrom(
      prior,
      RELAY_KINDS.DESCRIPTOR_PUBLISHED,
      "operator",
    );
    if (descriptorMessage === null) {
      emitStatus(stdout, "PAYER_AWAITING_DESCRIPTOR", {});
      descriptorMessage = await waitForPeerKind(
        relay,
        sessionId,
        RELAY_KINDS.DESCRIPTOR_PUBLISHED,
        "operator",
      );
    }
    const descriptorEnvelope = descriptorMessage.body?.envelope;
    verifyDescriptorEnvelope(descriptorEnvelope, {
      repositoryPublicKey: operatorPublicKey,
    });
    const descriptor = descriptorEnvelope.descriptor;
    if (
      descriptor.mandateDigest !==
        payerMandateDigest(mandateEnvelope) ||
      descriptor.requestDigest !==
        paymentRequestDigest(requestEnvelope) ||
      descriptor.paymentMoved !== false ||
      descriptor.payer.address !== manifest.payer.address ||
      descriptor.payer.agentId !== manifest.payer.agentId ||
      descriptor.payee.address !== payee.address ||
      descriptor.payee.agentId !== payee.agentId ||
      descriptor.registry !== REGISTRY_ADDRESS
    ) {
      shellFailure("DESCRIPTOR_MISMATCH");
    }
    emitStatus(stdout, "PAYER_DESCRIPTOR_VERIFIED", {});

    // 6. Anchors through the proven core; evidence uploads through the
    // publication seam before PARTY_COMPLETE.
    heartbeat.stop();
    heartbeat = startHeartbeat(reporter, "PAYER_ANCHORING");
    const client = await connectClockchain();
    const result = await runPayerRole({
      canaries: [],
      client,
      descriptorEnvelope,
      outputDirectory,
      ownerOf,
      publishEvidence: async (options) => {
        await publishPartyEvidence({
          ...options,
          publish: (triple) =>
            uploadEvidence(relay, sessionId, triple),
        });
      },
      repositoryPublicKey: operatorPublicKey,
      signMessage,
    });
    if (
      result.paymentMoved !== false ||
      result.state !== "ACKNOWLEDGED"
    ) {
      shellFailure("ROLE_RESULT");
    }
    await reporter.report("PARTY_COMPLETE", {
      state: result.state,
    });
    emitStatus(stdout, "PAYER_COMPLETE", {
      state: result.state,
    });
  } finally {
    heartbeat.stop();
  }
}

const invokedAsScript =
  process.argv[1] !== undefined &&
  fileURLToPath(import.meta.url) === resolve(process.argv[1]);

if (invokedAsScript) {
  main().then(
    () => {
      process.exitCode = 0;
    },
    (error) => {
      const code =
        error instanceof RoleShellError ? error.code : "FAILED";
      process.stderr.write(`PAYER_FAILED ${code}\n`);
      process.exitCode = 1;
    },
  );
}
