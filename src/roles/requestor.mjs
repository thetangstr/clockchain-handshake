import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  mkdir,
  readFile,
  writeFile,
} from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs, promisify } from "node:util";

import { createPublicClient, http } from "viem";
import { generatePrivateKey } from "viem/accounts";

import { createRelayClient } from "../relay/client.mjs";
import { RPC_URL } from "../core/constants.mjs";
import {
  REGISTRY_ADDRESS,
  operatorPublicKeyPath,
  verifyDescriptorEnvelope,
} from "../core/descriptor.mjs";
import {
  buildIntakeInput,
  intakeDigest,
  validateHandshakeRequiredResult,
} from "../core/intake.mjs";
import {
  payerMandateDigest,
  verifyPayerMandate,
} from "../core/payer-mandate.mjs";
import {
  paymentRequestDigest,
  signPaymentRequest,
} from "../core/payment-request.mjs";
import { registerIdentity } from "../core/registration.mjs";
import { runPayeeRole } from "../core/roles-core.mjs";
import { publishPartyEvidence } from "../core/runner.mjs";
import { verifyDiscoveryDocument } from "./discovery.mjs";
import {
  RELAY_KINDS,
  createMessenger,
  exactlyOneFrom,
  validateAddressBody,
} from "./catalog.mjs";
import {
  RoleShellError,
  accountFromPrivateKeyHex,
  connectClockchain,
  createOwnerOf,
  createStatusReporter,
  emitStatus,
  loadPrivateKeyHex,
  signerFromAccount,
  startHeartbeat,
  waitForRelayMessage,
} from "./common.mjs";

// Requestor role shell (the stakeholder kit). One pasted prompt leads
// here: fetch the signed discovery, verify it against the pinned
// checkout, create a fresh identity, wait for operator funding,
// self-register ERC-8004, answer the payer mandate through the intake
// exchange, sign the formal payment request, then anchor ACCEPTED and
// publish evidence. Every wait is unbounded with heartbeat. This
// process never authorizes anything; the final verdict belongs only
// to the operator's fresh aggregate verifier.

const BALANCE_POLL_INTERVAL_MS = 15_000;
const MAX_DISCOVERY_BYTES = 65_536;
const MAX_OPERATOR_KEY_BYTES = 4_096;
const MAX_CHECKPOINT_BYTES = 65_536;
const EVIDENCE_UPLOAD_ATTEMPTS = 3;
const REPOSITORY_ROOT = dirname(
  dirname(dirname(fileURLToPath(import.meta.url))),
);

const SHA_PATTERN = /^[0-9a-f]{40}$/;
const DIGEST_PATTERN = /^[0-9a-f]{64}$/;
const RAW_KEY_PATTERN = /^[A-Za-z0-9+/]{43}=$/;

const execFileAsync = promisify(execFile);

function shellFailure(code) {
  throw new RoleShellError(code);
}

async function git(...args) {
  let stdout;
  try {
    ({ stdout } = await execFileAsync("git", args, {
      cwd: REPOSITORY_ROOT,
      maxBuffer: 64 * 1024 * 1024,
    }));
  } catch {
    shellFailure("REPOSITORY_MISMATCH");
  }
  return stdout;
}

async function assertKitPinned(document) {
  const head = (await git("rev-parse", "HEAD")).trim();
  if (head !== document.repositorySha) {
    shellFailure("REPOSITORY_MISMATCH");
  }
  const tree = await git("ls-tree", "-r", "-z", "HEAD");
  const digest = createHash("sha256")
    .update(tree)
    .digest("hex");
  if (digest !== document.kitManifestDigest) {
    shellFailure("REPOSITORY_MISMATCH");
  }
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

async function fetchDiscovery(discoveryUrl) {
  let url;
  try {
    url = new URL(discoveryUrl);
  } catch {
    shellFailure("DISCOVERY_UNAVAILABLE");
  }
  const loopback =
    url.protocol === "http:" &&
    ["127.0.0.1", "localhost", "::1"].includes(url.hostname);
  if (!(url.protocol === "https:" || loopback)) {
    shellFailure("DISCOVERY_UNAVAILABLE");
  }
  let response;
  try {
    response = await fetch(url, {
      headers: { accept: "application/json" },
    });
  } catch {
    shellFailure("DISCOVERY_UNAVAILABLE");
  }
  if (!response.ok) {
    shellFailure("DISCOVERY_UNAVAILABLE");
  }
  const raw = await response.text();
  if (Buffer.byteLength(raw, "utf8") > MAX_DISCOVERY_BYTES) {
    shellFailure("DISCOVERY_INVALID");
  }
  try {
    return JSON.parse(raw);
  } catch {
    shellFailure("DISCOVERY_INVALID");
  }
}

async function loadOrCreateIdentity(stateRoot) {
  const keyPath = join(stateRoot, "identity.key");
  try {
    const existing = await loadPrivateKeyHex(keyPath);
    return {
      account: accountFromPrivateKeyHex(existing),
      privateKeyHex: existing,
    };
  } catch {
    // No prior identity: create one and persist it owner-only.
  }
  const privateKey = generatePrivateKey();
  await writeFile(keyPath, `${privateKey}\n`, { mode: 0o600 });
  return {
    account: accountFromPrivateKeyHex(privateKey),
    privateKeyHex: privateKey,
  };
}

async function readCheckpoint(stateRoot) {
  try {
    const raw = await readFile(
      join(stateRoot, "registration-checkpoint.json"),
      "utf8",
    );
    if (Buffer.byteLength(raw, "utf8") > MAX_CHECKPOINT_BYTES) {
      return null;
    }
    return JSON.parse(raw);
  } catch {
    return null;
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

function sleep(milliseconds) {
  return new Promise((resolvePromise) => {
    setTimeout(resolvePromise, milliseconds);
  });
}

async function uploadEvidence(relay, sessionId, triple) {
  let lastError;
  for (
    let attempt = 0;
    attempt < EVIDENCE_UPLOAD_ATTEMPTS;
    attempt += 1
  ) {
    try {
      await relay.putEvidence(sessionId, "payee", triple);
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
      "discovery-url": { type: "string" },
      state: { type: "string" },
    },
    strict: true,
  });
  if (
    typeof values["discovery-url"] !== "string" ||
    typeof values.state !== "string" ||
    !values.state.startsWith("/")
  ) {
    shellFailure("ARGS");
  }
  const stdout = process.stdout;
  const stateRoot = values.state;
  await mkdir(stateRoot, { recursive: true, mode: 0o700 });

  emitStatus(stdout, "REQUESTOR_STARTING", {});
  const document = await fetchDiscovery(values["discovery-url"]);
  if (
    document === null ||
    typeof document !== "object" ||
    typeof document.repositorySha !== "string" ||
    !SHA_PATTERN.test(document.repositorySha) ||
    typeof document.kitManifestDigest !== "string" ||
    !DIGEST_PATTERN.test(document.kitManifestDigest)
  ) {
    shellFailure("DISCOVERY_INVALID");
  }
  if (document.paymentMoved !== false) {
    shellFailure("DISCOVERY_INVALID");
  }

  // Trust order: the checkout must match the pinned commit before the
  // operator key it carries can verify the discovery signature.
  await assertKitPinned(document);
  const operatorPublicKey = await readOperatorPublicKey(
    document.operatorKeyId,
  );
  const discovery = verifyDiscoveryDocument({
    document,
    expectedPublicKey: operatorPublicKey,
    nowMs: Date.now(),
  });
  emitStatus(stdout, "REQUESTOR_DISCOVERY_VERIFIED", {
    sessionId: discovery.sessionId,
  });

  const sessionId = discovery.sessionId;
  const relay = createRelayClient({ relayUrl: discovery.relayUrl });
  const { account, privateKeyHex } =
    await loadOrCreateIdentity(stateRoot);
  const address = account.address.toLowerCase();
  const signMessage = signerFromAccount(account);
  const messenger = createMessenger({
    relay,
    role: "payee",
    senderKey: `payee:${address}`,
    sessionId,
    sign: signMessage,
  });
  const reporter = createStatusReporter({
    relay,
    sessionId,
    role: "payee",
  });
  const outputDirectory = join(stateRoot, "evidence");
  await mkdir(outputDirectory, { recursive: true, mode: 0o700 });

  const prior = await collectMessages(relay, sessionId);
  messenger.adoptPrior(prior);

  const publicClient = createPublicClient({
    transport: http(RPC_URL),
  });

  let heartbeat = startHeartbeat(reporter, "REQUESTOR_WAITING");
  try {
    // 1. Announce the fresh identity (advisory; the operator funds it
    // and every later artifact binds it cryptographically).
    if (
      exactlyOneFrom(
        prior,
        RELAY_KINDS.IDENTITY_ANNOUNCE,
        "payee",
      ) === null
    ) {
      await messenger.send(RELAY_KINDS.IDENTITY_ANNOUNCE, {
        address,
      });
    }
    emitStatus(stdout, "REQUESTOR_IDENTITY_ANNOUNCED", {
      address,
    });

    // 2. Funding: the operator's message is only a hint; authority is
    // the on-chain balance of the fresh address.
    let balance = await publicClient.getBalance({ address });
    if (balance === 0n) {
      emitStatus(stdout, "REQUESTOR_AWAITING_FUNDING", {});
      if (
        exactlyOneFrom(
          prior,
          RELAY_KINDS.FUNDING_CONFIRMED,
          "operator",
        ) === null
      ) {
        for (;;) {
          const message = await waitForPeerKind(
            relay,
            sessionId,
            RELAY_KINDS.FUNDING_CONFIRMED,
            "operator",
          );
          const body = validateAddressBody(message.body);
          if (body.address === address) break;
        }
      }
      for (;;) {
        balance = await publicClient.getBalance({ address });
        if (balance > 0n) break;
        await sleep(BALANCE_POLL_INTERVAL_MS);
      }
    }
    emitStatus(stdout, "REQUESTOR_FUNDED", {
      balanceWei: balance.toString(10),
    });

    // 3. ERC-8004 self-registration (checkpoint-resumable).
    let agentId;
    const checkpoint = await readCheckpoint(stateRoot);
    if (
      checkpoint !== null &&
      typeof checkpoint.agentId === "string" &&
      checkpoint.address === address
    ) {
      agentId = checkpoint.agentId;
    } else {
      const registration = await registerIdentity({
        privateKey: privateKeyHex,
        expectedAddress: address,
        displayName: "Requestor",
        intent: checkpoint ?? undefined,
        publicClient,
        onCheckpoint: async (stage) => {
          await writeFile(
            join(stateRoot, "registration-checkpoint.json"),
            JSON.stringify(stage),
            { mode: 0o600 },
          );
        },
      });
      agentId = registration.agentId;
      await writeFile(
        join(stateRoot, "registration-checkpoint.json"),
        JSON.stringify({
          address,
          agentId,
        }),
        { mode: 0o600 },
      );
    }
    emitStatus(stdout, "REQUESTOR_REGISTERED", { agentId });

    if (
      exactlyOneFrom(prior, RELAY_KINDS.PARTY_READY, "payee") ===
      null
    ) {
      await messenger.send(RELAY_KINDS.PARTY_READY, {
        address,
        agentId,
      });
    }
    emitStatus(stdout, "REQUESTOR_READY", { agentId });

    // 4. Payer mandate. Per-construction identifiers are read back
    // from the signed envelope; every security-critical field binds
    // to the verified discovery and the local identity.
    let mandateMessage = exactlyOneFrom(
      prior,
      RELAY_KINDS.MANDATE_PUBLISHED,
      "payer",
    );
    if (mandateMessage === null) {
      emitStatus(stdout, "REQUESTOR_AWAITING_MANDATE", {});
      mandateMessage = await waitForPeerKind(
        relay,
        sessionId,
        RELAY_KINDS.MANDATE_PUBLISHED,
        "payer",
      );
    }
    const mandateEnvelope = mandateMessage.body?.envelope;
    const rawMandate = mandateEnvelope?.mandate;
    if (
      rawMandate === null ||
      typeof rawMandate !== "object" ||
      typeof rawMandate.intakeDigest !== "string" ||
      !DIGEST_PATTERN.test(rawMandate.intakeDigest) ||
      typeof rawMandate.intakeRequestId !== "string" ||
      typeof rawMandate.releaseId !== "string" ||
      rawMandate.releaseId.length === 0
    ) {
      shellFailure("MANDATE_INVALID");
    }
    const verifiedMandate = await verifyPayerMandate({
      envelope: mandateEnvelope,
      expected: {
        amount: { currency: "USD", value: "100" },
        intakeDigest: rawMandate.intakeDigest,
        intakeRequestId: rawMandate.intakeRequestId,
        invoiceReferencePrefix: "invoice-",
        payee: { address, agentId },
        payer: rawMandatePayer(rawMandate),
        purpose: "Handshake demo",
        releaseId: rawMandate.releaseId,
        repositorySha: discovery.repositorySha,
        requestEndpoint: `/v1/sessions/${sessionId}/payment-requests`,
        sessionId,
        subjectRun: discovery.subjectRun,
      },
      nowMs: Date.now(),
    });
    emitStatus(stdout, "REQUESTOR_MANDATE_VERIFIED", {
      mandateDigest: payerMandateDigest(mandateEnvelope),
    });

    // 5. Intake: request_payment, then validate HANDSHAKE_REQUIRED.
    const intakeInput = buildIntakeInput(
      verifiedMandate.mandate.intakeRequestId,
    );
    if (
      exactlyOneFrom(
        prior,
        RELAY_KINDS.PAYMENT_REQUEST,
        "payee",
      ) === null
    ) {
      await messenger.send(RELAY_KINDS.PAYMENT_REQUEST, {
        intake: intakeInput,
      });
    }
    let handshakeMessage = exactlyOneFrom(
      prior,
      RELAY_KINDS.HANDSHAKE_REQUIRED,
      "payer",
    );
    if (handshakeMessage === null) {
      handshakeMessage = await waitForPeerKind(
        relay,
        sessionId,
        RELAY_KINDS.HANDSHAKE_REQUIRED,
        "payer",
      );
    }
    validateHandshakeRequiredResult({
      result: handshakeMessage.body?.result,
      repositorySha: discovery.repositorySha,
      toolInput: intakeInput,
    });
    emitStatus(stdout, "REQUESTOR_INTAKE_VALIDATED", {});

    // 6. Sign the formal payment request.
    let requestEnvelope;
    const priorRequest = exactlyOneFrom(
      prior,
      RELAY_KINDS.PAYMENT_REQUEST_SIGNED,
      "payee",
    );
    if (priorRequest !== null) {
      requestEnvelope = priorRequest.body?.envelope;
    } else {
      const createdAtMs = Date.now();
      requestEnvelope = await signPaymentRequest({
        request: {
          amount: verifiedMandate.mandate.amount,
          createdAtMs: String(createdAtMs),
          expiresAtMs: verifiedMandate.mandate.expiresAtMs,
          intakeDigest: verifiedMandate.mandate.intakeDigest,
          intakeRequestId:
            verifiedMandate.mandate.intakeRequestId,
          invoiceReference: "invoice-001",
          mandateDigest: payerMandateDigest(mandateEnvelope),
          payee: { address, agentId },
          payer: verifiedMandate.mandate.payer,
          paymentMoved: false,
          protocol: "clockchain.bilateral-authorization/v1",
          purpose: verifiedMandate.mandate.purpose,
          releaseId: verifiedMandate.mandate.releaseId,
          repositorySha: verifiedMandate.mandate.repositorySha,
          requestId: randomUUID(),
          schema: "clockchain.bilateral-payment-request/v1",
          sessionId,
          subjectRun: discovery.subjectRun,
        },
        signMessage,
      });
      await messenger.send(RELAY_KINDS.PAYMENT_REQUEST_SIGNED, {
        envelope: requestEnvelope,
      });
    }
    emitStatus(stdout, "REQUESTOR_REQUEST_SIGNED", {
      requestDigest: paymentRequestDigest(requestEnvelope),
    });

    // 7. Operator-signed descriptor.
    let descriptorMessage = exactlyOneFrom(
      prior,
      RELAY_KINDS.DESCRIPTOR_PUBLISHED,
      "operator",
    );
    if (descriptorMessage === null) {
      emitStatus(stdout, "REQUESTOR_AWAITING_DESCRIPTOR", {});
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
      descriptor.payee.address !== address ||
      descriptor.payee.agentId !== agentId ||
      descriptor.repositorySha !== discovery.repositorySha ||
      descriptor.registry !== REGISTRY_ADDRESS
    ) {
      shellFailure("DESCRIPTOR_MISMATCH");
    }
    emitStatus(stdout, "REQUESTOR_DESCRIPTOR_VERIFIED", {});

    // 8. Anchors: watch PROPOSED, write ACCEPTED, watch ACKNOWLEDGED;
    // evidence uploads through the publication seam before
    // PARTY_COMPLETE.
    heartbeat.stop();
    heartbeat = startHeartbeat(
      reporter,
      "REQUESTOR_ANCHORING",
    );
    const client = await connectClockchain();
    const ownerOf = createOwnerOf({ publicClient });
    const result = await runPayeeRole({
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
    if (result.paymentMoved !== false) {
      shellFailure("ROLE_RESULT");
    }
    await reporter.report("PARTY_COMPLETE", {
      state: result.state,
    });
    emitStatus(stdout, "REQUESTOR_COMPLETE", {
      ackObserved: result.ackObserved,
      state: result.state,
    });
    stdout.write(
      "This requestor completed the handshake evidence flow. " +
        "This is not authorization; only the operator fresh " +
        "aggregate verifier may report the final verdict.\n",
    );
  } finally {
    heartbeat.stop();
  }
}

function rawMandatePayer(rawMandate) {
  const payer = rawMandate.payer;
  if (
    payer === null ||
    typeof payer !== "object" ||
    typeof payer.address !== "string" ||
    !/^0x[0-9a-f]{40}$/.test(payer.address) ||
    typeof payer.agentId !== "string"
  ) {
    shellFailure("MANDATE_INVALID");
  }
  return { address: payer.address, agentId: payer.agentId };
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
      process.stderr.write(`REQUESTOR_FAILED ${code}\n`);
      process.exitCode = 1;
    },
  );
}
