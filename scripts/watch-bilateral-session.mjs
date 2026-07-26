import { execFile } from "node:child_process";
import { constants as fsConstants } from "node:fs";
import { open } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";

import {
  deadlineMs,
} from "../src/bilateral/blocktime.mjs";
import {
  dSession,
  operatorPublicKeyPath,
  verifyDescriptorEnvelope,
} from "../src/bilateral/descriptor.mjs";
import {
  authoritativeTriple,
  buildAcceptance,
  buildAcknowledgment,
  transitionDigest,
} from "../src/bilateral/messages.mjs";
import {
  ProtocolFailureError,
  recoverAnchoredProposal,
  verifyTransition,
} from "../src/bilateral/protocol.mjs";
import { sessionKey } from "../src/bilateral/refid.mjs";
import {
  McpRateLimitedError,
  createMcpClient,
} from "../src/mcp.mjs";
import {
  assertSecretFree,
  redact,
} from "../src/redact.mjs";

export const WATCHER_REPORT_SCHEMA =
  "clockchain.bilateral-session-watcher/v1";
export const WATCHER_INTERVAL_MS = 20_000;
export const WATCHER_WINDOW_MS = 480_000;

const SLOTS = Object.freeze([
  "proposal",
  "acceptance",
  "acknowledgment",
]);
const STATES = Object.freeze([
  "UNSTARTED",
  "PROPOSED",
  "ACCEPTED",
  "ACKNOWLEDGED",
]);
const MAX_TEXT_BYTES = 65_536;
const MAX_TOKEN_BYTES = 4_096;
const MAX_ADVISORY_LENGTH = 256;
const TOKEN_PATTERN = /^[!-~]{1,4096}$/;
const READ_FLAGS =
  fsConstants.O_RDONLY |
  (fsConstants.O_NOFOLLOW ?? 0) |
  (fsConstants.O_NONBLOCK ?? 0);
const FORBIDDEN_OUTCOME = ["AUTHOR", "IZED"].join("");
const execFileAsync = promisify(execFile);

export class BilateralWatcherError extends Error {
  constructor() {
    super("Bilateral session watcher failed safely.");
    this.name = "BilateralWatcherError";
    this.code = "BILATERAL_WATCHER_FAILED";
  }
}

class WatcherTerminal extends Error {
  constructor(code) {
    super("Watcher observation terminated safely.");
    this.code = code;
  }
}

function fail() {
  throw new BilateralWatcherError();
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object") {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function dataField(value, key) {
  if (!isPlainObject(value)) {
    return undefined;
  }
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (
    descriptor === undefined ||
    !Object.hasOwn(descriptor, "value")
  ) {
    return undefined;
  }
  return descriptor.value;
}

function assertClient(client) {
  if (!isPlainObject(client)) {
    fail();
  }
  for (const name of [
    "getBlock",
    "resolveAgent",
    "searchActions",
    "verifyCrossParty",
  ]) {
    if (typeof dataField(client, name) !== "function") {
      fail();
    }
  }
}

function canonicalNow(now, previous = null) {
  let value;
  try {
    value = now();
  } catch {
    fail();
  }
  if (
    !Number.isSafeInteger(value) ||
    value < 0 ||
    (previous !== null && value < previous)
  ) {
    fail();
  }
  return value;
}

function validatedCanaries(canaries) {
  if (
    !Array.isArray(canaries) ||
    canaries.some(
      (entry) =>
        typeof entry !== "string" ||
        entry.length === 0 ||
        Buffer.byteLength(entry, "utf8") >
          MAX_TOKEN_BYTES,
    )
  ) {
    fail();
  }
  return [...new Set(canaries)];
}

function safeAdvisoryValue(value, canaries) {
  if (value === null || value === undefined) {
    return null;
  }
  if (typeof value !== "string") {
    return "[UNAVAILABLE]";
  }
  let safe;
  try {
    safe = redact(value, canaries);
  } catch {
    return "[UNAVAILABLE]";
  }
  safe = safe
    .replace(new RegExp(FORBIDDEN_OUTCOME, "gi"), "[REDACTED]")
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, " ")
    .trim()
    .slice(0, MAX_ADVISORY_LENGTH);
  return safe.length === 0 ? null : safe;
}

function advisorySnapshot(advisory, canaries) {
  if (!isPlainObject(advisory)) {
    return {
      health: null,
      label: "DISCLOSURE_ONLY",
      status: null,
    };
  }
  return {
    health: safeAdvisoryValue(
      dataField(advisory, "health"),
      canaries,
    ),
    label: "DISCLOSURE_ONLY",
    status: safeAdvisoryValue(
      dataField(advisory, "status"),
      canaries,
    ),
  };
}

function deepFreeze(value) {
  if (value === null || typeof value !== "object") {
    return value;
  }
  for (const entry of Object.values(value)) {
    deepFreeze(entry);
  }
  return Object.freeze(value);
}

function transitionDisplay(slot, referenceId) {
  return {
    blockHeight: null,
    blockTimeMs: null,
    blockTimeRaw: null,
    cardinality: "0",
    ledgerId: null,
    referenceId,
    slot,
    verified: false,
  };
}

function safeRecordDigest(record) {
  const value = dataField(record, "assetHash");
  return typeof value === "string" ? value : null;
}

function terminalCode(error) {
  if (error instanceof WatcherTerminal) {
    return error.code;
  }
  if (error instanceof McpRateLimitedError) {
    return "RATE_BLOCKED";
  }
  if (error instanceof ProtocolFailureError) {
    return error.terminalCode;
  }
  return "FAILED";
}

function verifiedDisplay(display, verified) {
  display.blockHeight = verified.blockHeight;
  display.blockTimeMs = String(verified.blockTimeMs);
  display.blockTimeRaw = verified.blockTimeRaw;
  display.ledgerId = verified.ledgerId;
  display.verified = true;
}

function triple(kind, verified) {
  return authoritativeTriple({
    anchoredHash: verified.anchoredHash,
    blockHeight: verified.blockHeight,
    kind,
    ledgerId: verified.ledgerId,
  });
}

async function verifyObservedPrefix({
  client,
  descriptor,
  displays,
  records,
  sessionDigest,
}) {
  if (records.some((recordsForSlot) => recordsForSlot.length > 1)) {
    throw new WatcherTerminal("DUPLICATE");
  }
  const populated = records.map(
    (recordsForSlot) => recordsForSlot.length === 1,
  );
  if (
    (populated[1] && !populated[0]) ||
    (
      populated[2] &&
      (!populated[0] || !populated[1])
    )
  ) {
    throw new WatcherTerminal("REORDERED");
  }

  let stateIndex = 0;
  let proposal;
  let proposalTriple;
  let acceptance;
  let acceptanceTriple;

  if (records[0].length === 1) {
    const anchoredHash = safeRecordDigest(records[0][0]);
    if (anchoredHash === null) {
      throw new WatcherTerminal("FAILED");
    }
    try {
      proposal = recoverAnchoredProposal({
        anchoredHash,
        descriptor,
        sessionDigest,
      });
    } catch (error) {
      throw new WatcherTerminal(terminalCode(error));
    }
    const verified = await verifyTransition({
      client,
      expectedDigest: transitionDigest(proposal),
      message: proposal,
      referenceId: displays[0].referenceId,
    });
    verifiedDisplay(displays[0], verified);
    proposalTriple = triple("proposal", verified);
    stateIndex = 1;
  }

  if (stateIndex === 1 && records[1].length === 1) {
    acceptance = buildAcceptance({
      proposal,
      proposalTriple,
    });
    const verified = await verifyTransition({
      client,
      expectedDigest: transitionDigest(acceptance),
      message: acceptance,
      referenceId: displays[1].referenceId,
    });
    verifiedDisplay(displays[1], verified);
    acceptanceTriple = triple("acceptance", verified);
    stateIndex = 2;
  }

  if (stateIndex === 2 && records[2].length === 1) {
    const acknowledgment = buildAcknowledgment({
      acceptance,
      acceptanceTriple,
      proposalTriple,
    });
    const verified = await verifyTransition({
      client,
      expectedDigest: transitionDigest(acknowledgment),
      message: acknowledgment,
      referenceId: displays[2].referenceId,
    });
    verifiedDisplay(displays[2], verified);
    stateIndex = 3;
  }

  return STATES[stateIndex];
}

function baseSnapshot({
  advisory,
  displays,
  observedAtMs,
  sessionDigest,
}) {
  return {
    advisory,
    deadlineMs: null,
    observedAtMs: String(observedAtMs),
    paymentMoved: false,
    schema: WATCHER_REPORT_SCHEMA,
    sessionDigest,
    state: "UNSTARTED",
    terminal: null,
    transitions: displays,
  };
}

function secureSnapshot(snapshot, canaries) {
  try {
    assertSecretFree(snapshot, canaries);
  } catch {
    fail();
  }
  return deepFreeze(snapshot);
}

export async function observeBilateralSession(options) {
  if (!isPlainObject(options)) {
    fail();
  }
  const client = dataField(options, "client");
  const descriptor = dataField(options, "descriptor");
  const now = dataField(options, "now");
  const canaries = validatedCanaries(
    dataField(options, "canaries") ?? [],
  );
  const advisory = advisorySnapshot(
    dataField(options, "advisory"),
    canaries,
  );
  assertClient(client);
  if (typeof now !== "function") {
    fail();
  }

  let sessionDigest;
  try {
    sessionDigest = dSession(descriptor);
  } catch {
    fail();
  }
  const observedAtMs = canonicalNow(now);
  const displays = SLOTS.map((slot) =>
    transitionDisplay(slot, sessionKey(sessionDigest, slot)),
  );
  const snapshot = baseSnapshot({
    advisory,
    displays,
    observedAtMs,
    sessionDigest,
  });

  try {
    const records = [];
    for (let index = 0; index < displays.length; index += 1) {
      const result = await client.searchActions({
        asset_reference_id: displays[index].referenceId,
      });
      if (!Array.isArray(result)) {
        throw new WatcherTerminal("FAILED");
      }
      displays[index].cardinality = String(result.length);
      records.push(result);
    }
    snapshot.state = await verifyObservedPrefix({
      client,
      descriptor,
      displays,
      records,
      sessionDigest,
    });
    if (displays[0].verified) {
      snapshot.deadlineMs = String(
        deadlineMs(Number(displays[0].blockTimeMs)),
      );
    }
  } catch (error) {
    snapshot.terminal = terminalCode(error);
  }
  return secureSnapshot(snapshot, canaries);
}

export async function watchBilateralSession(options) {
  if (!isPlainObject(options)) {
    fail();
  }
  const now = dataField(options, "now");
  const sleeper = dataField(options, "sleeper");
  const output = dataField(options, "output");
  const intervalMs =
    dataField(options, "intervalMs") ?? WATCHER_INTERVAL_MS;
  const windowMs =
    dataField(options, "windowMs") ?? WATCHER_WINDOW_MS;
  if (
    typeof now !== "function" ||
    typeof sleeper !== "function" ||
    typeof output !== "function" ||
    !Number.isSafeInteger(intervalMs) ||
    intervalMs < WATCHER_INTERVAL_MS ||
    intervalMs > WATCHER_WINDOW_MS ||
    !Number.isSafeInteger(windowMs) ||
    windowMs < 0 ||
    windowMs > WATCHER_WINDOW_MS
  ) {
    fail();
  }
  const startedAtMs = canonicalNow(now);
  let previousTime = startedAtMs;
  const maximumIterations =
    Math.ceil(windowMs / intervalMs) + 1;
  let latest;

  for (
    let iteration = 0;
    iteration < maximumIterations;
    iteration += 1
  ) {
    latest = await observeBilateralSession({
      advisory: dataField(options, "advisory"),
      canaries: dataField(options, "canaries") ?? [],
      client: dataField(options, "client"),
      descriptor: dataField(options, "descriptor"),
      now,
    });
    try {
      await output(latest);
    } catch {
      fail();
    }
    if (
      latest.state === "ACKNOWLEDGED" ||
      latest.terminal !== null
    ) {
      return latest;
    }
    previousTime = canonicalNow(now, previousTime);
    const remaining =
      startedAtMs + windowMs - previousTime;
    if (remaining <= 0 || iteration + 1 >= maximumIterations) {
      return latest;
    }
    const delay = Math.min(intervalMs, remaining);
    try {
      await sleeper(delay);
    } catch {
      fail();
    }
    previousTime = canonicalNow(now, previousTime);
  }
  return latest;
}

function parseArguments(arguments_) {
  if (!Array.isArray(arguments_)) {
    fail();
  }
  const values = new Map();
  for (let index = 0; index < arguments_.length; index += 2) {
    const key = arguments_[index];
    const value = arguments_[index + 1];
    if (
      !["--descriptor-file", "--token-file"].includes(key) ||
      values.has(key) ||
      typeof value !== "string" ||
      value.length === 0 ||
      value.startsWith("--")
    ) {
      fail();
    }
    values.set(key, value);
  }
  if (values.size !== 2) {
    fail();
  }
  return {
    descriptorPath: values.get("--descriptor-file"),
    tokenPath: values.get("--token-file"),
  };
}

function sameFile(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.mode === right.mode
  );
}

export async function readBoundedText(
  path,
  kind,
  openFile = open,
) {
  if (
    !["descriptor", "token"].includes(kind) ||
    typeof openFile !== "function"
  ) {
    fail();
  }
  let handle;
  let failure;
  let result;
  try {
    handle = await openFile(path, READ_FLAGS);
    const before = await handle.stat();
    const maximum =
      kind === "token" ? MAX_TOKEN_BYTES : MAX_TEXT_BYTES;
    if (
      !before.isFile() ||
      before.size <= 0 ||
      before.size > maximum ||
      (
        kind === "token" &&
        process.platform !== "win32" &&
        (before.mode & 0o777) !== 0o600
      )
    ) {
      fail();
    }
    const buffer = Buffer.allocUnsafe(maximum + 1);
    let offset = 0;
    while (offset < buffer.length) {
      const read = await handle.read(
        buffer,
        offset,
        buffer.length - offset,
        null,
      );
      if (
        !isPlainObject(read) ||
        !Number.isSafeInteger(read.bytesRead) ||
        read.bytesRead < 0 ||
        read.bytesRead > buffer.length - offset
      ) {
        fail();
      }
      if (read.bytesRead === 0) {
        break;
      }
      offset += read.bytesRead;
    }
    if (offset > maximum) {
      fail();
    }
    const bytes = buffer.subarray(0, offset);
    const after = await handle.stat();
    if (
      bytes.length !== before.size ||
      !after.isFile() ||
      !sameFile(before, after)
    ) {
      fail();
    }
    const value = bytes.toString("utf8");
    if (kind === "token") {
      const token = value.replace(/\r?\n$/, "");
      if (!TOKEN_PATTERN.test(token)) {
        fail();
      }
      result = token;
    } else {
      result = value;
    }
  } catch (error) {
    failure =
      error instanceof BilateralWatcherError
        ? error
        : new BilateralWatcherError();
  } finally {
    if (handle !== undefined) {
      try {
        await handle.close();
      } catch {
        failure ??= new BilateralWatcherError();
      }
    }
  }
  if (failure !== undefined) {
    throw failure;
  }
  return result;
}

async function defaultRepositoryPublicKeyResolver(
  {
    repositoryPath,
    repositorySha,
  },
  runGit,
) {
  let result;
  try {
    await runGit(
      "git",
      [
        "cat-file",
        "-e",
        `${repositorySha}^{commit}`,
      ],
      {
        cwd: process.cwd(),
        encoding: "utf8",
        maxBuffer: 128,
      },
    );
    result = await runGit(
      "git",
      ["show", `${repositorySha}:${repositoryPath}`],
      {
        cwd: process.cwd(),
        encoding: "utf8",
        maxBuffer: 4096,
      },
    );
  } catch {
    fail();
  }
  if (
    !isPlainObject(result) ||
    typeof dataField(result, "stdout") !== "string"
  ) {
    fail();
  }
  return dataField(result, "stdout").trim();
}

async function verifiedDescriptorEnvelope(
  descriptorText,
  repositoryPublicKeyResolver,
) {
  let envelope;
  try {
    envelope = JSON.parse(descriptorText);
  } catch {
    fail();
  }
  const repositorySha = dataField(
    dataField(envelope, "descriptor"),
    "repositorySha",
  );
  const keyId = dataField(
    dataField(envelope, "operator"),
    "keyId",
  );
  if (
    typeof repositorySha !== "string" ||
    !/^[0-9a-f]{40}$/.test(repositorySha)
  ) {
    fail();
  }
  let repositoryPath;
  try {
    repositoryPath = operatorPublicKeyPath(keyId);
  } catch {
    fail();
  }
  let repositoryPublicKey;
  try {
    repositoryPublicKey =
      await repositoryPublicKeyResolver({
        repositoryPath,
        repositorySha,
      });
  } catch {
    fail();
  }
  if (
    typeof repositoryPublicKey !== "string" ||
    repositoryPublicKey.trim().length === 0
  ) {
    fail();
  }
  try {
    verifyDescriptorEnvelope(envelope, {
      repositoryPublicKey:
        repositoryPublicKey.trim(),
    });
  } catch {
    fail();
  }
  return envelope;
}

export async function main(
  arguments_ = process.argv.slice(2),
  dependencies = {},
) {
  const configuration = parseArguments(arguments_);
  const {
    createClient = createMcpClient,
    now = Date.now,
    openFile = open,
    output = (line) => process.stdout.write(line),
    readText,
    repositoryPublicKeyResolver,
    runGit = execFileAsync,
    sleeper = (milliseconds) =>
      new Promise((resolve) => setTimeout(resolve, milliseconds)),
    windowMs = WATCHER_WINDOW_MS,
  } = dependencies;
  if (
    typeof createClient !== "function" ||
    typeof output !== "function" ||
    (
      readText !== undefined &&
      typeof readText !== "function"
    ) ||
    (
      readText === undefined &&
      typeof openFile !== "function"
    ) ||
    (
      repositoryPublicKeyResolver !== undefined &&
      typeof repositoryPublicKeyResolver !== "function"
    ) ||
    typeof runGit !== "function"
  ) {
    fail();
  }
  const activeReader =
    readText ??
    ((path, kind) =>
      readBoundedText(path, kind, openFile));
  const descriptorText = await activeReader(
    configuration.descriptorPath,
    "descriptor",
  );
  if (
    typeof descriptorText !== "string" ||
    Buffer.byteLength(descriptorText, "utf8") === 0 ||
    Buffer.byteLength(descriptorText, "utf8") >
      MAX_TEXT_BYTES
  ) {
    fail();
  }
  const descriptorEnvelope =
    await verifiedDescriptorEnvelope(
      descriptorText,
      repositoryPublicKeyResolver ??
        ((request) =>
          defaultRepositoryPublicKeyResolver(
            request,
            runGit,
          )),
    );
  const token = await activeReader(
    configuration.tokenPath,
    "token",
  );
  if (
    typeof token !== "string" ||
    !TOKEN_PATTERN.test(token)
  ) {
    fail();
  }
  return watchBilateralSession({
    advisory: { health: null, status: null },
    canaries: [token],
    client: createClient({ token }),
    descriptor: descriptorEnvelope.descriptor,
    now,
    output: (snapshot) =>
      output(`${JSON.stringify(snapshot)}\n`),
    sleeper,
    windowMs,
  });
}

export async function runCli(
  arguments_ = process.argv.slice(2),
  dependencies = {},
) {
  const writeError =
    dependencies.writeError ??
    ((line) => process.stderr.write(line));
  try {
    const result = await main(arguments_, dependencies);
    return result.terminal === null ? 0 : 2;
  } catch {
    writeError("Bilateral session watcher failed safely.\n");
    return 1;
  }
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  process.exitCode = await runCli();
}
