#!/usr/bin/env node

// Operator orchestrator (G1a). One command drives the whole session:
// config + release pin + preflight, four generated participant keys,
// replay-safe funding batches, ERC-8004 payer registrations, payer
// manifests, the rehearsal sub-run (operator-hosted payer + stub
// requestor), then the live sub-run (operator-hosted payer + external
// requestor). Each sub-run's descriptor is built only after the
// signed payment request exists, and each sub-run's verdict is
// produced by a fresh verifier subprocess — never by this process.
//
// This file is the declared FUNDING_REPLAYED emission site: a funding
// batch whose addresses diverge from the persisted batch binding fails
// closed before any treasury process starts.

import { spawn } from "node:child_process";
import {
  createHash,
  createPrivateKey,
  randomUUID,
  sign,
} from "node:crypto";
import {
  mkdir,
  readFile,
  rename,
  writeFile,
} from "node:fs/promises";
import {
  dirname,
  join,
  resolve,
} from "node:path";
import { fileURLToPath } from "node:url";
import {
  parseArgs,
  types,
} from "node:util";

import {
  createPublicClient,
  http,
} from "viem";
import { generatePrivateKey } from "viem/accounts";

import { RPC_URL } from "../core/constants.mjs";
import { KEY_ID_PATTERN } from "../core/descriptor.mjs";
import {
  FUNDING_RECORD_SCHEMA,
} from "../core/funding/record.mjs";
import {
  FUNDING_PASSWORD_FILE_ENV,
} from "../core/funding/wallet.mjs";
import {
  BILATERAL_PROTOCOL_ID,
} from "../core/mandate-construction.mjs";
import { payerMandateDigest } from "../core/payer-mandate.mjs";
import {
  paymentRequestDigest,
} from "../core/payment-request.mjs";
import { registerIdentity } from "../core/registration.mjs";
import { createRelayClient } from "../relay/client.mjs";
import {
  createMessenger,
  exactlyOneFrom,
  RELAY_KINDS,
  validateAddressBody,
  validatePartyReadyBody,
} from "./catalog.mjs";
import {
  accountFromPrivateKeyHex,
  createStatusReporter,
  emitStatus,
  loadPrivateKeyHex,
  readJsonFile,
  startHeartbeat,
  waitForRelayMessage,
} from "./common.mjs";
import {
  DISCOVERY_SCHEMA,
  signDiscoveryDocument,
} from "./discovery.mjs";
import { readReleasePin } from "../../scripts/release-pin.mjs";
import { runPreflight } from "../../scripts/preflight.mjs";
import {
  main as createSessionMain,
} from "../../scripts/create-session.mjs";

export const OPERATOR_CONFIG_SCHEMA =
  "handshake-operator-config/v2";
export const OPERATOR_SESSION_SCHEMA =
  "handshake-operator-session/v2";

// Human-paced session bound: the signed discovery document stays valid
// for four hours so staggered stakeholder schedules never expire
// mid-run. Evidence availability is polled on a short cadence; every
// other wait is an unbounded relay long-poll with a heartbeat.
export const OPERATOR_SESSION_WINDOW_MS = 14_400_000;
export const EVIDENCE_POLL_INTERVAL_MS = 5_000;

const REPO_ROOT = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
);
const PAYER_SCRIPT = join(REPO_ROOT, "src", "roles", "payer.mjs");
const REQUESTOR_SCRIPT = join(
  REPO_ROOT,
  "src",
  "roles",
  "requestor.mjs",
);
const VERIFIER_SCRIPT = join(
  REPO_ROOT,
  "src",
  "verifier",
  "run.mjs",
);
const FUNDING_SCRIPT = join(
  REPO_ROOT,
  "scripts",
  "fund-addresses.mjs",
);
const PROMPT_FILE = join(REPO_ROOT, "prompts", "requestor.md");

const SUB_RUNS = Object.freeze(["rehearsal", "stakeholder"]);
// Funding records require exactly four nonce-0 participants. Batch A
// funds the three role keys plus one reserve before any identity
// exists. Batch B funds the live requestor plus three fresh reserves;
// already-active participants can never appear in a later record
// because the ported funding validation rejects any nonce > 0.
const BATCH_A_SLOTS = Object.freeze([
  "rehearsal-payer",
  "rehearsal-stub",
  "stakeholder-payer",
  "reserve",
]);
const BATCH_B_RESERVE_SLOTS = Object.freeze([
  "reserve-b-1",
  "reserve-b-2",
  "reserve-b-3",
]);
const KEY_SLOTS = Object.freeze([
  ...BATCH_A_SLOTS,
  ...BATCH_B_RESERVE_SLOTS,
]);
const MAX_CONFIG_BYTES = 65_536;
const MAX_SESSION_STATE_BYTES = 1_048_576;
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;

export class OperatorError extends Error {
  constructor(code) {
    super(`Operator failure: ${code}`);
    this.name = "OperatorError";
    this.code = code;
  }
}

function operatorFailure(code) {
  throw new OperatorError(code);
}

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    !types.isProxy(value)
  );
}

function sleep(milliseconds) {
  return new Promise((resolvePromise) => {
    setTimeout(resolvePromise, milliseconds);
  });
}

export function validateOperatorConfig(value) {
  if (!isPlainObject(value)) {
    operatorFailure("CONFIG_SHAPE");
  }
  const expected = [
    "operatorKeyId",
    "relayUrl",
    "rpcUrlFile",
    "schema",
    "treasuryAddress",
    "treasuryKeystoreFile",
    "treasuryPasswordFile",
  ];
  const keys = Object.keys(value);
  if (
    keys.length !== expected.length ||
    expected.some((key) => !keys.includes(key))
  ) {
    operatorFailure("CONFIG_SHAPE");
  }
  let relayUrl;
  try {
    relayUrl = new URL(value.relayUrl);
  } catch {
    operatorFailure("CONFIG_SHAPE");
  }
  const loopback =
    relayUrl.protocol === "http:" &&
    ["127.0.0.1", "localhost", "::1"].includes(
      relayUrl.hostname,
    );
  if (
    value.schema !== OPERATOR_CONFIG_SCHEMA ||
    !(relayUrl.protocol === "https:" || loopback) ||
    !KEY_ID_PATTERN.test(value.operatorKeyId) ||
    !ADDRESS_PATTERN.test(value.treasuryAddress) ||
    typeof value.treasuryKeystoreFile !== "string" ||
    !value.treasuryKeystoreFile.startsWith("/") ||
    typeof value.treasuryPasswordFile !== "string" ||
    !value.treasuryPasswordFile.startsWith("/") ||
    typeof value.rpcUrlFile !== "string" ||
    !value.rpcUrlFile.startsWith("/")
  ) {
    operatorFailure("CONFIG_SHAPE");
  }
  return Object.freeze({
    operatorKeyId: value.operatorKeyId,
    relayUrl: value.relayUrl.replace(/\/+$/, ""),
    rpcUrlFile: value.rpcUrlFile,
    treasuryAddress: value.treasuryAddress,
    treasuryKeystoreFile: value.treasuryKeystoreFile,
    treasuryPasswordFile: value.treasuryPasswordFile,
  });
}

async function loadSessionState(stateDir) {
  let value;
  try {
    value = await readJsonFile(
      join(stateDir, "operator-session.json"),
      MAX_SESSION_STATE_BYTES,
    );
  } catch (error) {
    if (
      error !== null &&
      typeof error === "object" &&
      error.code === "FILE_UNREADABLE"
    ) {
      return null;
    }
    operatorFailure("SESSION_STATE_SHAPE");
  }
  if (
    isPlainObject(value) &&
    value.schema === OPERATOR_SESSION_SCHEMA
  ) {
    return value;
  }
  operatorFailure("SESSION_STATE_SHAPE");
}

async function saveSessionState(stateDir, state) {
  const path = join(stateDir, "operator-session.json");
  const temporary = join(
    stateDir,
    ".operator-session.json.tmp",
  );
  await writeFile(temporary, `${JSON.stringify(state, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
  await rename(temporary, path);
}

async function loadOrCreateKeys(stateDir) {
  const keysDirectory = join(stateDir, "keys");
  await mkdir(keysDirectory, { recursive: true, mode: 0o700 });
  const keys = {};
  for (const slot of KEY_SLOTS) {
    const path = join(keysDirectory, `${slot}.key`);
    let privateKeyHex;
    try {
      privateKeyHex = await loadPrivateKeyHex(path);
    } catch {
      privateKeyHex = generatePrivateKey();
      await writeFile(path, `${privateKeyHex}\n`, {
        encoding: "utf8",
        mode: 0o600,
      });
    }
    keys[slot] = Object.freeze({
      address:
        accountFromPrivateKeyHex(privateKeyHex).address.toLowerCase(),
      keyFile: path,
      privateKeyHex,
    });
  }
  return Object.freeze(keys);
}

async function collectMessages(relay, sessionId) {
  const messages = [];
  let cursor = 0;
  for (;;) {
    const page = await relay.pollMessages({
      after: cursor,
      sessionId,
      waitMs: 0,
    });
    if (
      !isPlainObject(page) ||
      !Array.isArray(page.messages) ||
      typeof page.next !== "number"
    ) {
      operatorFailure("RELAY_RESPONSE");
    }
    messages.push(...page.messages);
    if (page.messages.length === 0 || page.next <= cursor) {
      return messages;
    }
    cursor = page.next;
  }
}

async function awaitKind(relay, sessionId, kind, role) {
  const prior = await collectMessages(relay, sessionId);
  const existing = exactlyOneFrom(prior, kind, role);
  if (existing !== null) {
    return existing;
  }
  for (;;) {
    const { message } = await waitForRelayMessage({
      relay,
      sessionId,
      kinds: [kind],
    });
    if (message.role === role) {
      return message;
    }
  }
}

async function awaitEvidence(relay, sessionId, role, intervalMs) {
  for (;;) {
    try {
      return await relay.getEvidence(sessionId, role);
    } catch (error) {
      if (
        error !== null &&
        typeof error === "object" &&
        error.code === "NO_EVIDENCE"
      ) {
        await sleep(intervalMs);
        continue;
      }
      throw error;
    }
  }
}

async function participantFacts(publicClient, addresses) {
  const facts = [];
  for (const address of addresses) {
    const [balance, nonce] = await Promise.all([
      publicClient.getBalance({ address }),
      publicClient.getTransactionCount({ address }),
    ]);
    facts.push(
      Object.freeze({
        address,
        balanceWei: balance.toString(10),
        nonce: nonce.toString(10),
      }),
    );
  }
  return facts;
}

function defaultSpawnProcess({ script, args, env }) {
  const child = spawn(process.execPath, [script, ...args], {
    env: env ?? process.env,
    stdio: ["ignore", "inherit", "inherit"],
  });
  const exited = new Promise((resolvePromise, rejectPromise) => {
    child.once("error", rejectPromise);
    child.once("exit", (code) => {
      resolvePromise(code ?? 1);
    });
  });
  return {
    exited,
    kill: () => {
      child.kill("SIGKILL");
    },
  };
}

async function defaultFundBatch({
  config,
  journalDirectory,
  recordPath,
  spawnProcess,
}) {
  const handle = spawnProcess({
    args: [
      "--funding-record",
      recordPath,
      "--journal-directory",
      journalDirectory,
      "--keystore",
      config.treasuryKeystoreFile,
      "--rpc-url-file",
      config.rpcUrlFile,
    ],
    env: {
      ...process.env,
      [FUNDING_PASSWORD_FILE_ENV]: config.treasuryPasswordFile,
    },
    script: FUNDING_SCRIPT,
  });
  const code = await handle.exited;
  if (code !== 0) {
    operatorFailure("FUNDING_FAILED");
  }
}

async function fundBatch({
  addresses,
  batchName,
  deps,
  config,
  sessionState,
  stateDir,
  stdout,
}) {
  const persisted = sessionState.funding[batchName];
  if (persisted !== null) {
    // Declared replay check: a batch whose addresses diverge from the
    // persisted binding fails closed before any treasury process.
    if (
      JSON.stringify(persisted.addresses) !==
      JSON.stringify(addresses)
    ) {
      operatorFailure("FUNDING_REPLAYED");
    }
    if (persisted.completed === true) {
      return;
    }
    // Resume path: the funding record is a byte-pinned declaration of
    // fresh, unused participants. Regenerating it after a partial batch
    // would record the observed post-funding balances and the funding
    // script would correctly reject it. Keep the original declaration
    // and let the journal drive idempotent completion.
    emitStatus(stdout, "OPERATOR_FUNDING_BATCH", {
      batch: batchName,
    });
    const resumeRecordPath = join(
      stateDir,
      "funding",
      `${batchName}.json`,
    );
    const resumeJournalDirectory = join(
      stateDir,
      "funding",
      `journal-${batchName}`,
    );
    await deps.fundBatch({
      config,
      journalDirectory: resumeJournalDirectory,
      recordPath: resumeRecordPath,
      spawnProcess: deps.spawnProcess,
    });
    sessionState.funding[batchName].completed = true;
    await saveSessionState(stateDir, sessionState);
    emitStatus(stdout, "OPERATOR_FUNDED", { batch: batchName });
    return;
  }
  emitStatus(stdout, "OPERATOR_FUNDING_BATCH", {
    batch: batchName,
  });
  const fundingDirectory = join(stateDir, "funding");
  await mkdir(fundingDirectory, {
    recursive: true,
    mode: 0o700,
  });
  const recordPath = join(
    fundingDirectory,
    `${batchName}.json`,
  );
  const record = {
    addresses,
    participants: await participantFacts(
      deps.publicClient,
      addresses,
    ),
    paymentMoved: false,
    schema: FUNDING_RECORD_SCHEMA,
  };
  await writeFile(
    recordPath,
    `${JSON.stringify(record, null, 2)}\n`,
    { encoding: "utf8", mode: 0o600 },
  );
  sessionState.funding[batchName] = {
    addresses,
    completed: false,
  };
  await saveSessionState(stateDir, sessionState);
  const journalDirectory = join(
    fundingDirectory,
    `journal-${batchName}`,
  );
  await mkdir(journalDirectory, {
    recursive: true,
    mode: 0o700,
  });
  await deps.fundBatch({
    config,
    journalDirectory,
    recordPath,
    spawnProcess: deps.spawnProcess,
  });
  sessionState.funding[batchName].completed = true;
  await saveSessionState(stateDir, sessionState);
  emitStatus(stdout, "OPERATOR_FUNDED", { batch: batchName });
}

async function registerPayer({
  address,
  deps,
  displayName,
  key,
  sessionState,
  stateDir,
  subRun,
  stdout,
}) {
  const runState = sessionState.subRuns[subRun];
  if (
    typeof runState.payerAgentId === "string" &&
    runState.payerAgentId.length > 0
  ) {
    return runState.payerAgentId;
  }
  emitStatus(stdout, "OPERATOR_REGISTERING_PAYER", {
    subRun,
  });
  const checkpointDirectory = join(
    stateDir,
    "states",
    `${subRun}-payer`,
  );
  await mkdir(checkpointDirectory, {
    recursive: true,
    mode: 0o700,
  });
  const checkpointPath = join(
    checkpointDirectory,
    "registration-checkpoint.json",
  );
  let checkpoint = null;
  try {
    const parsed = JSON.parse(
      await readFile(checkpointPath, "utf8"),
    );
    if (
      isPlainObject(parsed) &&
      parsed.address === address
    ) {
      checkpoint = parsed;
    }
  } catch {
    checkpoint = null;
  }
  // Terminal-checkpoint adoption: a checkpoint that already carries a
  // registered agentId for this exact payer address is a completed
  // registration, not an in-flight intent. Adopting it lets the
  // operator restart after a post-registration verification failure;
  // without this the wallet nonce guard would permanently brick the
  // funded payer identity key. Mirrors the requestor's own adoption.
  if (
    checkpoint !== null &&
    typeof checkpoint.agentId === "string" &&
    checkpoint.agentId.length > 0
  ) {
    runState.payerAgentId = checkpoint.agentId;
    await saveSessionState(stateDir, sessionState);
    emitStatus(stdout, "OPERATOR_PAYER_REGISTERED", {
      agentId: checkpoint.agentId,
      subRun,
    });
    return checkpoint.agentId;
  }
  const registration = await deps.registerIdentity({
    privateKey: key.privateKeyHex,
    expectedAddress: address,
    displayName,
    ...(checkpoint === null ? {} : { intent: checkpoint }),
    publicClient: deps.publicClient,
    onCheckpoint: async (stage) => {
      await writeFile(
        checkpointPath,
        JSON.stringify(stage),
        { encoding: "utf8", mode: 0o600 },
      );
    },
  });
  if (
    typeof registration.agentId !== "string" ||
    registration.agentId.length === 0
  ) {
    operatorFailure("REGISTRATION_RESULT");
  }
  await writeFile(
    checkpointPath,
    JSON.stringify({ address, agentId: registration.agentId }),
    { encoding: "utf8", mode: 0o600 },
  );
  runState.payerAgentId = registration.agentId;
  await saveSessionState(stateDir, sessionState);
  emitStatus(stdout, "OPERATOR_PAYER_REGISTERED", {
    agentId: registration.agentId,
    subRun,
  });
  return registration.agentId;
}

async function writePayerManifest({
  address,
  agentId,
  config,
  keyFile,
  pin,
  sessionId,
  stateDir,
  subRun,
}) {
  const manifestDirectory = join(stateDir, "manifests");
  await mkdir(manifestDirectory, {
    recursive: true,
    mode: 0o700,
  });
  const path = join(
    manifestDirectory,
    `${subRun}-payer.json`,
  );
  const manifest = {
    operatorKeyId: config.operatorKeyId,
    payer: { address, agentId, keyFile },
    relayUrl: config.relayUrl,
    releaseId: `release-${pin.repositorySha.slice(0, 12)}`,
    repositorySha: pin.repositorySha,
    schema: "handshake-payer-manifest/v2",
    sessionId,
    subjectRun: subRun,
  };
  await writeFile(path, `${JSON.stringify(manifest, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
  return path;
}

async function ensureDiscovery({
  config,
  deps,
  pin,
  relay,
  runState,
  sessionId,
  stateDir,
  sessionState,
  subRun,
}) {
  if (isPlainObject(runState.discovery)) {
    const persisted = runState.discovery;
    if (
      BigInt(persisted.expiresAtMs) <= BigInt(deps.now())
    ) {
      operatorFailure("SESSION_EXPIRED");
    }
    await relay.putDiscovery(sessionId, persisted);
    return persisted;
  }
  const issuedAtMs = deps.now();
  const document = {
    chainId: pin.chainId,
    clockchainUrl: pin.clockchainUrl,
    expiresAtMs: String(
      issuedAtMs + OPERATOR_SESSION_WINDOW_MS,
    ),
    issuedAtMs: String(issuedAtMs),
    kitManifestDigest: pin.kitManifestDigest,
    kitRepoUrl: pin.kitRepoUrl,
    operatorKeyId: config.operatorKeyId,
    payerEndpoint: `${config.relayUrl}/v1/sessions/${sessionId}`,
    paymentMoved: false,
    protocolVersion: BILATERAL_PROTOCOL_ID,
    registry: pin.registry,
    relayUrl: config.relayUrl,
    repositorySha: pin.repositorySha,
    schema: DISCOVERY_SCHEMA,
    sessionId,
    subjectRun: subRun,
  };
  const signed = signDiscoveryDocument({
    document,
    privateKeyPem: deps.operatorPrivateKeyPem,
  });
  await relay.putDiscovery(sessionId, signed);
  runState.discovery = signed;
  await saveSessionState(stateDir, sessionState);
  return signed;
}

async function ensureDescriptorPublished({
  deps,
  messenger,
  pin,
  relay,
  sessionId,
  stateDir,
  subRun,
  payerFacts,
  promptSha256,
  stdout,
}) {
  const prior = await collectMessages(relay, sessionId);
  const existing = exactlyOneFrom(
    prior,
    RELAY_KINDS.DESCRIPTOR_PUBLISHED,
    "operator",
  );
  if (existing !== null) {
    return;
  }
  const mandateMessage = exactlyOneFrom(
    prior,
    RELAY_KINDS.MANDATE_PUBLISHED,
    "payer",
  );
  const requestMessage = exactlyOneFrom(
    prior,
    RELAY_KINDS.PAYMENT_REQUEST_SIGNED,
    "payee",
  );
  const readyMessage = exactlyOneFrom(
    prior,
    RELAY_KINDS.PARTY_READY,
    "payee",
  );
  if (
    mandateMessage === null ||
    requestMessage === null ||
    readyMessage === null
  ) {
    operatorFailure("DESCRIPTOR_INPUTS");
  }
  const mandateEnvelope = mandateMessage.body?.envelope;
  const requestEnvelope = requestMessage.body?.envelope;
  const ready = validatePartyReadyBody(readyMessage.body);
  if (
    !isPlainObject(mandateEnvelope) ||
    !isPlainObject(requestEnvelope) ||
    !isPlainObject(mandateEnvelope.mandate) ||
    !isPlainObject(mandateEnvelope.mandate.amount)
  ) {
    operatorFailure("DESCRIPTOR_INPUTS");
  }
  const amount = mandateEnvelope.mandate.amount;
  const descriptorDirectory = join(stateDir, "descriptor");
  await mkdir(descriptorDirectory, {
    recursive: true,
    mode: 0o700,
  });
  const output = join(
    descriptorDirectory,
    `${subRun}.json`,
  );
  const { envelope } = await deps.buildDescriptor({
    amounts: `${amount.currency}:${amount.value}`,
    keyId: deps.operatorKeyId,
    mandateDigest: payerMandateDigest(mandateEnvelope),
    output,
    payee: {
      address: ready.address,
      agentId: ready.agentId,
      displayName: "Requestor",
    },
    payer: payerFacts,
    promptSha256,
    repositorySha: pin.repositorySha,
    requestDigest: paymentRequestDigest(requestEnvelope),
  });
  await messenger.send(RELAY_KINDS.DESCRIPTOR_PUBLISHED, {
    envelope,
  });
  emitStatus(stdout, "OPERATOR_DESCRIPTOR_PUBLISHED", {
    subRun,
  });
}

async function runVerifier({
  config,
  deps,
  sessionId,
  stateDir,
  subRun,
  stdout,
}) {
  const verdictDirectory = join(
    stateDir,
    "verdicts",
    subRun,
  );
  await mkdir(verdictDirectory, {
    recursive: true,
    mode: 0o700,
  });
  const handle = deps.spawnProcess({
    args: [
      "--session",
      sessionId,
      "--relay",
      config.relayUrl,
      "--state",
      verdictDirectory,
      "--key-id",
      config.operatorKeyId,
      "--subject-run",
      subRun,
    ],
    script: VERIFIER_SCRIPT,
  });
  const code = await handle.exited;
  if (code !== 0) {
    operatorFailure("VERIFIER_FAILED");
  }
  emitStatus(stdout, "OPERATOR_VERIFIER_PASSED", { subRun });
}

async function runSubRun({
  config,
  deps,
  keys,
  pin,
  promptSha256,
  relay,
  sessionState,
  stateDir,
  stdout,
  subRun,
  operatorSign,
}) {
  const runState = sessionState.subRuns[subRun];
  const sessionId = runState.sessionId;
  const reporter = createStatusReporter({
    relay,
    role: "operator",
    sessionId,
  });
  const messenger = createMessenger({
    relay,
    role: "operator",
    senderKey: `operator:${config.operatorKeyId}`,
    sessionId,
    sign: operatorSign,
  });
  messenger.adoptPrior(await collectMessages(relay, sessionId));

  // Payer is operator-hosted in M1a; the requestor is the stub in
  // the rehearsal and the external stakeholder in the live sub-run.
  const payerKey = keys[`${subRun}-payer`];
  const payerFacts = {
    address: payerKey.address,
    agentId: runState.payerAgentId,
    displayName: "Payer",
  };
  const manifestPath = await writePayerManifest({
    address: payerKey.address,
    agentId: runState.payerAgentId,
    config,
    keyFile: payerKey.keyFile,
    pin,
    sessionId,
    stateDir,
    subRun,
  });

  const children = [];
  try {
    children.push(
      deps.spawnProcess({
        args: [
          "--manifest",
          manifestPath,
          "--state",
          join(stateDir, "states", `${subRun}-payer`),
        ],
        script: PAYER_SCRIPT,
      }),
    );
    if (subRun === "rehearsal") {
      children.push(
        deps.spawnProcess({
          args: [
            "--discovery-url",
            `${config.relayUrl}/v1/discovery/${sessionId}`,
            "--state",
            join(stateDir, "states", "rehearsal-stub"),
          ],
        script: REQUESTOR_SCRIPT,
        }),
      );
    } else {
      emitStatus(stdout, "REQUESTOR_HANDOFF", {
        discoveryUrl:
          `${config.relayUrl}/v1/discovery/${sessionId}`,
      });
    }

    // A crashed role child must fail the sub-run; a clean exit after
    // PARTY_COMPLETE is expected and ignored.
    let childFailed = null;
    const childFailure = new Promise((_, reject) => {
      for (const handle of children) {
        handle.exited.then((code) => {
          if (code !== 0 && childFailed === null) {
            childFailed = new OperatorError("ROLE_EXITED");
            reject(childFailed);
          }
        }, reject);
      }
    });
    childFailure.catch(() => {});

    const phaseWork = async () => {
      if (subRun === "stakeholder") {
      emitStatus(stdout, "OPERATOR_AWAITING_REQUESTOR", {});
      const announce = await awaitKind(
        relay,
        sessionId,
        RELAY_KINDS.IDENTITY_ANNOUNCE,
        "payee",
      );
      const { address } = validateAddressBody(announce.body);
      await fundBatch({
        addresses: [
          address,
          ...BATCH_B_RESERVE_SLOTS.map(
            (slot) => keys[slot].address,
          ),
        ],
        batchName: "batch-b",
        config,
        deps,
        sessionState,
        stateDir,
        stdout,
      });
      await messenger.send(RELAY_KINDS.FUNDING_CONFIRMED, {
        address,
      });
      }

      const heartbeat = startHeartbeat(
        reporter,
        "OPERATOR_SESSION_RUNNING",
        { subRun },
      );
      try {
        await awaitKind(
          relay,
          sessionId,
          RELAY_KINDS.PAYMENT_REQUEST_SIGNED,
          "payee",
        );
        await ensureDescriptorPublished({
          deps,
          messenger,
          payerFacts,
          pin,
          promptSha256,
          relay,
          sessionId,
          stateDir,
          stdout,
          subRun,
        });
        const evidencePollMs =
          deps.evidencePollIntervalMs ??
          EVIDENCE_POLL_INTERVAL_MS;
        await awaitEvidence(
          relay,
          sessionId,
          "payer",
          evidencePollMs,
        );
        await awaitEvidence(
          relay,
          sessionId,
          "payee",
          evidencePollMs,
        );
        emitStatus(stdout, "OPERATOR_EVIDENCE_COMPLETE", {
          subRun,
        });
      } finally {
        heartbeat.stop();
      }

      await runVerifier({
        config,
        deps,
        sessionId,
        stateDir,
        stdout,
        subRun,
      });
    };
    await Promise.race([phaseWork(), childFailure]);
  } finally {
    for (const child of children) {
      child.kill();
    }
    await Promise.allSettled(
      children.map((child) => child.exited),
    );
  }
}

export async function runOperator({
  config,
  deps = {},
  stateDir,
}) {
  const activeDeps = {
    ...deps,
  };
  activeDeps.now ??= () => Date.now();
  activeDeps.operatorKeyId = config.operatorKeyId;
  activeDeps.publicClient ??= createPublicClient({
    transport: http(RPC_URL),
  });
  activeDeps.registerIdentity ??= registerIdentity;
  activeDeps.spawnProcess ??= defaultSpawnProcess;
  activeDeps.stdout ??= process.stdout;
  const stdout = activeDeps.stdout;
  if (activeDeps.buildDescriptor === undefined) {
    activeDeps.buildDescriptor = async (inputs) =>
      createSessionMain([
        "create",
        "--amounts",
        inputs.amounts,
        "--key-id",
        inputs.keyId,
        "--mandate-digest",
        inputs.mandateDigest,
        "--output",
        inputs.output,
        "--payee-address",
        inputs.payee.address,
        "--payee-agent-id",
        inputs.payee.agentId,
        "--payee-name",
        inputs.payee.displayName,
        "--payer-address",
        inputs.payer.address,
        "--payer-agent-id",
        inputs.payer.agentId,
        "--payer-name",
        inputs.payer.displayName,
        "--prompt-sha256",
        inputs.promptSha256,
        "--repository-sha",
        inputs.repositorySha,
        "--request-digest",
        inputs.requestDigest,
      ]);
  }
  if (activeDeps.fundBatch === undefined) {
    activeDeps.fundBatch = defaultFundBatch;
  }
  if (activeDeps.preflight === undefined) {
    activeDeps.preflight = runPreflight;
  }
  const repoRoot = deps.repoRoot ?? REPO_ROOT;
  if (activeDeps.releasePin === undefined) {
    activeDeps.releasePin = await readReleasePin({
      cwd: repoRoot,
    });
  }
  const pin = activeDeps.releasePin;
  if (activeDeps.operatorPrivateKeyPem === undefined) {
    activeDeps.operatorPrivateKeyPem = await readFile(
      join(
        repoRoot,
        ".context",
        "operator-keys",
        `${config.operatorKeyId}.ed25519.pem`,
      ),
      "utf8",
    );
  }
  if (activeDeps.promptSha256 === undefined) {
    activeDeps.promptSha256 = createHash("sha256")
      .update(await readFile(PROMPT_FILE))
      .digest("hex");
  }
  const relayFactory =
    activeDeps.relayFactory ?? createRelayClient;

  emitStatus(stdout, "OPERATOR_CONFIG_LOADED", {});

  await activeDeps.preflight({
    publicClient: activeDeps.publicClient,
    relayUrl: config.relayUrl,
    treasuryAddress: config.treasuryAddress,
    ...(activeDeps.clockchain === undefined
      ? {}
      : { clockchain: activeDeps.clockchain }),
  });
  emitStatus(stdout, "OPERATOR_PREFLIGHT_PASSED", {});

  await mkdir(stateDir, { recursive: true, mode: 0o700 });
  let sessionState = await loadSessionState(stateDir);
  if (sessionState === null) {
    sessionState = {
      funding: { "batch-a": null, "batch-b": null },
      operatorKeyId: config.operatorKeyId,
      relayUrl: config.relayUrl,
      schema: OPERATOR_SESSION_SCHEMA,
      subRuns: Object.fromEntries(
        SUB_RUNS.map((subRun) => [
          subRun,
          {
            discovery: null,
            payerAgentId: null,
            sessionId: randomUUID(),
          },
        ]),
      ),
    };
    await saveSessionState(stateDir, sessionState);
  }
  if (
    sessionState.operatorKeyId !== config.operatorKeyId ||
    sessionState.relayUrl !== config.relayUrl
  ) {
    operatorFailure("SESSION_STATE_MISMATCH");
  }

  const keys = await loadOrCreateKeys(stateDir);
  emitStatus(stdout, "OPERATOR_KEYS_READY", {});

  const operatorKey = createPrivateKey({
    key: activeDeps.operatorPrivateKeyPem,
    format: "pem",
  });
  const operatorSign = async (bytes) =>
    sign(null, bytes, operatorKey).toString("base64");

  for (const subRun of SUB_RUNS) {
    const runState = sessionState.subRuns[subRun];
    const relay = relayFactory({ relayUrl: config.relayUrl });
    await relay.createSession({
      senderKey: `operator:${config.operatorKeyId}`,
      sessionId: runState.sessionId,
      sig: await operatorSign(
        Buffer.from(
          `${runState.sessionId}:${subRun}`,
          "utf8",
        ),
      ),
      subjectRun: subRun,
    });
    await ensureDiscovery({
      config,
      deps: activeDeps,
      pin,
      relay,
      runState,
      sessionId: runState.sessionId,
      sessionState,
      stateDir,
      subRun,
    });
    emitStatus(stdout, "OPERATOR_SESSION_READY", { subRun });
  }

  await fundBatch({
    addresses: BATCH_A_SLOTS.map((slot) => keys[slot].address),
    batchName: "batch-a",
    config,
    deps: activeDeps,
    sessionState,
    stateDir,
    stdout,
  });

  for (const subRun of SUB_RUNS) {
    const key = keys[`${subRun}-payer`];
    await registerPayer({
      address: key.address,
      deps: activeDeps,
      displayName: "Payer",
      key,
      sessionState,
      stateDir,
      stdout,
      subRun,
    });
  }

  // The rehearsal stub is the real requestor kit pointed at a
  // pre-seeded state directory; only its identity key is provisioned.
  const stubStateDirectory = join(
    stateDir,
    "states",
    "rehearsal-stub",
  );
  await mkdir(stubStateDirectory, {
    recursive: true,
    mode: 0o700,
  });
  const stubKeyPath = join(
    stubStateDirectory,
    "identity.key",
  );
  try {
    await loadPrivateKeyHex(stubKeyPath);
  } catch {
    await writeFile(
      stubKeyPath,
      `${keys["rehearsal-stub"].privateKeyHex}\n`,
      { encoding: "utf8", mode: 0o600 },
    );
  }

  for (const subRun of SUB_RUNS) {
    const relay = relayFactory({ relayUrl: config.relayUrl });
    // A published verdict is the sub-run completion marker. After a
    // crash, roles that are asked to re-enter an out-of-window session
    // correctly fail closed on the deadline; the operator must instead
    // adopt the finished sub-run and move on.
    const snapshot = await relay
      .getSnapshot(sessionState.subRuns[subRun].sessionId)
      .catch(() => null);
    if (
      snapshot !== null &&
      typeof snapshot === "object" &&
      snapshot.verdict !== null &&
      snapshot.verdict !== undefined
    ) {
      emitStatus(stdout, "OPERATOR_SUBRUN_ADOPTED", { subRun });
      continue;
    }
    emitStatus(stdout, "OPERATOR_SUBRUN_STARTED", { subRun });
    await runSubRun({
      config,
      deps: activeDeps,
      keys,
      operatorSign,
      pin,
      promptSha256: activeDeps.promptSha256,
      relay,
      sessionState,
      stateDir,
      stdout,
      subRun,
    });
    emitStatus(stdout, "OPERATOR_SUBRUN_PASSED", { subRun });
  }

  emitStatus(stdout, "OPERATOR_RUN_COMPLETE", {
    rehearsalSessionId:
      sessionState.subRuns.rehearsal.sessionId,
    stakeholderSessionId:
      sessionState.subRuns.stakeholder.sessionId,
  });
}

export async function main(
  argv = process.argv.slice(2),
  seams = {},
) {
  const stdout = seams.stdout ?? process.stdout;
  let values;
  try {
    ({ values } = parseArgs({
      args: argv,
      options: { state: { type: "string" } },
      strict: true,
    }));
  } catch {
    stdout.write(
      "usage: operator.mjs --state <dir>\n",
    );
    return 2;
  }
  if (
    typeof values.state !== "string" ||
    !values.state.startsWith("/")
  ) {
    stdout.write("usage: operator.mjs --state <dir>\n");
    return 2;
  }
  try {
    const config = validateOperatorConfig(
      await readJsonFile(
        join(values.state, "operator-config.json"),
        MAX_CONFIG_BYTES,
      ),
    );
    await runOperator({
      config,
      deps: seams.deps ?? {},
      stateDir: values.state,
    });
    return 0;
  } catch (error) {
    if (error instanceof OperatorError) {
      stdout.write(`OPERATOR_FAILED ${error.code}\n`);
      return 1;
    }
    throw error;
  }
}

const invokedAsScript =
  process.argv[1] !== undefined &&
  fileURLToPath(import.meta.url) === resolve(process.argv[1]);

if (invokedAsScript) {
  main().then(
    (code) => {
      process.exitCode = code;
    },
    (error) => {
      process.stderr.write(
        `operator crashed: ${
          error instanceof Error ? error.message : "unknown"
        }\n`,
      );
      process.exitCode = 1;
    },
  );
}
