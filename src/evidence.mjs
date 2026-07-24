import { createHash, randomUUID } from "node:crypto";
import {
  link,
  lstat,
  mkdir,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { isDeepStrictEqual } from "node:util";

import {
  CHAIN_ID,
  REGISTRY_ADDRESS,
  RESULT_SCHEMA,
  SINGLE_VALIDATOR_DISCLAIMER,
} from "./constants.mjs";
import { assertSecretFree, redact } from "./redact.mjs";

const RESULT_KEYS = Object.freeze([
  "schema",
  "status",
  "runId",
  "startedAt",
  "completedAt",
  "elapsedMs",
  "scenario",
  "identity",
  "clockchain",
  "disclaimer",
]);
const SCENARIO_KEYS = Object.freeze([
  "action",
  "amount",
  "counterparty",
]);
const AMOUNT_KEYS = Object.freeze([
  "value",
  "currency",
  "moved",
]);
const IDENTITY_KEYS = Object.freeze([
  "reference",
  "agentId",
  "displayName",
  "owner",
  "registerTx",
  "metadataTx",
]);
const CLOCKCHAIN_KEYS = Object.freeze([
  "ledgerId",
  "blockHeight",
  "consensusTime",
  "receiptStatus",
  "receiptVerified",
  "crossPartyVerified",
  "verifiedAgainst",
  "keyless",
  "poolHealth",
]);
const POOL_HEALTH_KEYS = Object.freeze([
  "totalNodes",
  "nodeParticipationPct",
  "degradedAtSubmission",
]);
const RECEIPT_EVENT_KEYS = Object.freeze([
  "agentId",
  "action",
  "inputs",
  "outputs",
]);
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/i;
const TRANSACTION_PATTERN = /^0x[0-9a-f]{64}$/i;
const RFC3339_PATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const MAX_TEXT_LENGTH = 512;
const FILE_SYSTEM_KEYS = new Set([
  "link",
  "lstat",
  "mkdir",
  "readFile",
  "rm",
  "writeFile",
]);
const DEFAULT_FILE_SYSTEM = Object.freeze({
  link,
  lstat,
  mkdir,
  readFile,
  rm,
  writeFile,
});

export class EvidenceError extends Error {
  constructor(message, {
    category = "verification",
    code = "HANDSHAKE_EVIDENCE_FAILED",
  } = {}) {
    super(message);
    this.name = new.target.name;
    this.category = category;
    this.code = code;
  }
}

export class EvidenceValidationError extends EvidenceError {
  constructor() {
    super("Handshake PASS result is invalid.", {
      category: "verification",
      code: "HANDSHAKE_RESULT_INVALID",
    });
  }
}

export class EvidenceRedactionError extends EvidenceError {
  constructor() {
    super("Handshake evidence failed the secret-redaction gate.", {
      category: "redaction",
      code: "HANDSHAKE_EVIDENCE_REDACTION",
    });
  }
}

export class EvidenceConfigurationError extends EvidenceError {
  constructor() {
    super("Handshake evidence output configuration is invalid.", {
      category: "configuration",
      code: "HANDSHAKE_EVIDENCE_CONFIGURATION",
    });
  }
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object") {
    return false;
  }

  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function canonicalizeReceiptEventValue(
  value,
  ancestors = new Set(),
) {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new EvidenceValidationError();
    }
    return value;
  }
  if (typeof value !== "object" || ancestors.has(value)) {
    throw new EvidenceValidationError();
  }

  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const keys = Reflect.ownKeys(value);
      if (
        keys.length !== value.length + 1 ||
        keys.some(
          (key) =>
            key !== "length" &&
            (typeof key !== "string" ||
              !/^(?:0|[1-9][0-9]*)$/.test(key) ||
              Number(key) >= value.length),
        )
      ) {
        throw new EvidenceValidationError();
      }
      const result = [];
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(
          value,
          String(index),
        );
        if (
          !descriptor ||
          !descriptor.enumerable ||
          !Object.hasOwn(descriptor, "value")
        ) {
          throw new EvidenceValidationError();
        }
        result.push(
          canonicalizeReceiptEventValue(
            descriptor.value,
            ancestors,
          ),
        );
      }
      return result;
    }

    if (!isPlainObject(value)) {
      throw new EvidenceValidationError();
    }
    const entries = [];
    for (const key of Reflect.ownKeys(value)) {
      const descriptor = Object.getOwnPropertyDescriptor(
        value,
        key,
      );
      if (
        typeof key !== "string" ||
        !descriptor ||
        !descriptor.enumerable ||
        !Object.hasOwn(descriptor, "value")
      ) {
        throw new EvidenceValidationError();
      }
      entries.push([key, descriptor.value]);
    }
    const result = Object.create(null);
    for (const [key, entryValue] of entries.sort(
      ([left], [right]) =>
        left === right ? 0 : left < right ? -1 : 1,
    )) {
      result[key] = canonicalizeReceiptEventValue(
        entryValue,
        ancestors,
      );
    }
    return result;
  } finally {
    ancestors.delete(value);
  }
}

export function computeReceiptEventHash(event) {
  try {
    const canonicalEvent =
      canonicalizeReceiptEventValue(event);
    if (
      !hasExactKeys(canonicalEvent, RECEIPT_EVENT_KEYS) ||
      typeof canonicalEvent.agentId !== "string" ||
      typeof canonicalEvent.action !== "string"
    ) {
      throw new EvidenceValidationError();
    }
    return createHash("sha256")
      .update(JSON.stringify(canonicalEvent), "utf8")
      .digest("hex");
  } catch {
    throw new EvidenceValidationError();
  }
}

function hasExactKeys(value, expectedKeys) {
  if (!isPlainObject(value)) {
    return false;
  }

  const keys = Reflect.ownKeys(value);
  return (
    keys.length === expectedKeys.length &&
    expectedKeys.every((key) => keys.includes(key))
  );
}

function mergeFileSystem(fileSystem = {}) {
  if (!isPlainObject(fileSystem)) {
    throw new EvidenceConfigurationError();
  }

  const active = { ...DEFAULT_FILE_SYSTEM };
  for (const key of Reflect.ownKeys(fileSystem)) {
    const descriptor = Object.getOwnPropertyDescriptor(
      fileSystem,
      key,
    );
    if (
      typeof key !== "string" ||
      !FILE_SYSTEM_KEYS.has(key) ||
      !descriptor ||
      !Object.hasOwn(descriptor, "value") ||
      typeof descriptor.value !== "function"
    ) {
      throw new EvidenceConfigurationError();
    }
    active[key] = descriptor.value;
  }
  return active;
}

function isBoundedString(
  value,
  {
    maximum = MAX_TEXT_LENGTH,
    trimmed = true,
    controls = false,
  } = {},
) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= maximum &&
    (!trimmed || value.trim() === value) &&
    (controls || !/[\u0000-\u001f\u007f-\u009f]/.test(value))
  );
}

function isRfc3339(value) {
  return (
    typeof value === "string" &&
    RFC3339_PATTERN.test(value) &&
    Number.isFinite(Date.parse(value)) &&
    new Date(value).toISOString() === value
  );
}

function invalidResult() {
  throw new EvidenceValidationError();
}

function validateScenario(scenario) {
  if (
    !hasExactKeys(scenario, SCENARIO_KEYS) ||
    scenario.action !== "trust_handshake" ||
    scenario.counterparty !== "clockchain:handshake" ||
    !hasExactKeys(scenario.amount, AMOUNT_KEYS) ||
    scenario.amount.value !== "100" ||
    scenario.amount.currency !== "USD" ||
    scenario.amount.moved !== false
  ) {
    invalidResult();
  }
}

function validateIdentity(identity) {
  if (
    !hasExactKeys(identity, IDENTITY_KEYS) ||
    typeof identity.agentId !== "string" ||
    !DECIMAL_PATTERN.test(identity.agentId) ||
    !isBoundedString(identity.displayName, {
      maximum: 128,
      controls: true,
      trimmed: false,
    }) ||
    identity.displayName.trim().length === 0 ||
    !ADDRESS_PATTERN.test(identity.owner) ||
    !TRANSACTION_PATTERN.test(identity.registerTx) ||
    !TRANSACTION_PATTERN.test(identity.metadataTx)
  ) {
    invalidResult();
  }

  const expectedReference =
    `eip155:${CHAIN_ID}:${REGISTRY_ADDRESS}:${identity.agentId}`;
  if (identity.reference !== expectedReference) {
    invalidResult();
  }
}

function validatePoolHealth(poolHealth) {
  if (
    !hasExactKeys(poolHealth, POOL_HEALTH_KEYS) ||
    !Number.isSafeInteger(poolHealth.totalNodes) ||
    poolHealth.totalNodes < 0 ||
    typeof poolHealth.nodeParticipationPct !== "number" ||
    !Number.isFinite(poolHealth.nodeParticipationPct) ||
    poolHealth.nodeParticipationPct < 0 ||
    poolHealth.nodeParticipationPct > 100 ||
    typeof poolHealth.degradedAtSubmission !== "boolean" ||
    poolHealth.degradedAtSubmission !==
      (poolHealth.nodeParticipationPct === 0)
  ) {
    invalidResult();
  }
}

function validateClockchain(clockchain) {
  if (
    !hasExactKeys(clockchain, CLOCKCHAIN_KEYS) ||
    !UUID_PATTERN.test(clockchain.ledgerId) ||
    typeof clockchain.blockHeight !== "string" ||
    !DECIMAL_PATTERN.test(clockchain.blockHeight) ||
    !isBoundedString(clockchain.consensusTime) ||
    clockchain.receiptStatus !== "anchored" ||
    clockchain.receiptVerified !== true ||
    clockchain.crossPartyVerified !== true ||
    clockchain.verifiedAgainst !== "on-chain block" ||
    clockchain.keyless !== true
  ) {
    invalidResult();
  }

  validatePoolHealth(clockchain.poolHealth);
}

export function validatePassResult(result) {
  try {
    if (
      !hasExactKeys(result, RESULT_KEYS) ||
      result.schema !== RESULT_SCHEMA ||
      result.status !== "PASS" ||
      !UUID_PATTERN.test(result.runId) ||
      !isRfc3339(result.startedAt) ||
      !isRfc3339(result.completedAt) ||
      !Number.isSafeInteger(result.elapsedMs) ||
      result.elapsedMs < 0 ||
      result.disclaimer !== SINGLE_VALIDATOR_DISCLAIMER
    ) {
      invalidResult();
    }

    const elapsed =
      Date.parse(result.completedAt) - Date.parse(result.startedAt);
    if (elapsed !== result.elapsedMs) {
      invalidResult();
    }

    validateScenario(result.scenario);
    validateIdentity(result.identity);
    validateClockchain(result.clockchain);
    assertSecretFree(result);
    return result;
  } catch (error) {
    if (error instanceof EvidenceValidationError) {
      throw error;
    }
    throw new EvidenceValidationError();
  }
}

function escapeMarkdown(value) {
  return value
    .replace(/[\u0000-\u001f\u007f-\u009f]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/([\\`*_[\]{}()#+.!|<>])/g, "\\$1");
}

export function renderResultMarkdown(result) {
  validatePassResult(result);

  const { identity, clockchain, scenario } = result;
  const registerUrl =
    `https://sepolia.etherscan.io/tx/${identity.registerTx}`;
  const metadataUrl =
    `https://sepolia.etherscan.io/tx/${identity.metadataTx}`;
  const degraded =
    clockchain.poolHealth.degradedAtSubmission ? "yes" : "no";

  return [
    "# Clockchain Handshake result",
    "",
    `Status: ${result.status}`,
    "",
    "## Scenario",
    "",
    `- Action: \`${scenario.action}\``,
    `- Authorization: ${scenario.amount.value} ${scenario.amount.currency}`,
    "- Payment moved: no",
    `- Counterparty: \`${scenario.counterparty}\``,
    "",
    "## ERC-8004 identity",
    "",
    `- Display name: ${escapeMarkdown(identity.displayName)}`,
    `- Agent ID: \`${identity.agentId}\``,
    `- Identity reference: \`${identity.reference}\``,
    `- Owner: \`${identity.owner}\``,
    `- Registration transaction: [\`${identity.registerTx}\`](${registerUrl})`,
    `- Metadata transaction: [\`${identity.metadataTx}\`](${metadataUrl})`,
    "",
    "## Clockchain receipt",
    "",
    `- Ledger ID: \`${clockchain.ledgerId}\``,
    `- Block height: \`${clockchain.blockHeight}\``,
    `- Consensus time: ${escapeMarkdown(clockchain.consensusTime)}`,
    `- Receipt status: ${clockchain.receiptStatus}`,
    `- Receipt commitment verified: ${clockchain.receiptVerified ? "yes" : "no"}`,
    `- Cross-party verification: ${clockchain.crossPartyVerified ? "yes" : "no"}`,
    `- Verified against: ${clockchain.verifiedAgainst}`,
    `- Keyless verification path: ${clockchain.keyless ? "yes" : "no"}`,
    `- Degraded at submission: ${degraded}`,
    `- Node participation: ${clockchain.poolHealth.nodeParticipationPct}%`,
    `- Total nodes at submission: ${clockchain.poolHealth.totalNodes}`,
    "",
    "## Run",
    "",
    `- Run ID: \`${result.runId}\``,
    `- Started: \`${result.startedAt}\``,
    `- Completed: \`${result.completedAt}\``,
    `- Elapsed: ${result.elapsedMs} ms`,
    "",
    "## Testnet limitation",
    "",
    result.disclaimer,
    "",
  ].join("\n");
}

function validateDirectory(directory) {
  return (
    typeof directory === "string" &&
    directory.length > 0 &&
    !directory.includes("\0")
  );
}

async function assertEntriesAbsent(fileSystem, paths) {
  for (const path of paths) {
    try {
      await fileSystem.lstat(path);
    } catch (error) {
      if (error?.code === "ENOENT") {
        continue;
      }
      throw new EvidenceConfigurationError();
    }
    throw new EvidenceConfigurationError();
  }
}

export async function beginEvidenceAttempt({
  directory,
  runId,
  fileSystem = {},
}) {
  if (!validateDirectory(directory) || !UUID_PATTERN.test(runId)) {
    throw new EvidenceConfigurationError();
  }
  const activeFileSystem = mergeFileSystem(fileSystem);
  const jsonPath = join(directory, "result.json");
  const markdownPath = join(directory, "RESULT.md");
  await assertEntriesAbsent(
    activeFileSystem,
    [jsonPath, markdownPath],
  );

  return {
    archived: false,
    archiveDirectory: null,
  };
}

function validateWriteOptions({
  directory,
  canaries,
  fileSystem,
}) {
  if (
    !validateDirectory(directory) ||
    !Array.isArray(canaries) ||
    canaries.some(
      (canary) =>
        typeof canary !== "string" || canary.length === 0,
    )
  ) {
    throw new EvidenceConfigurationError();
  }
  return mergeFileSystem(fileSystem);
}

async function removeTemporaryFiles(paths, fileSystem) {
  await Promise.all(
    paths.map((path) =>
      fileSystem.rm(path, { force: true }).catch(() => {}),
    ),
  );
}

async function removePublishedFiles(entries, fileSystem) {
  let cleanupFailed = false;
  for (const entry of [...entries].reverse()) {
    try {
      const [temporary, final] = await Promise.all([
        fileSystem.lstat(entry.temporaryPath),
        fileSystem.lstat(entry.finalPath),
      ]);
      if (
        temporary.dev === final.dev &&
        temporary.ino === final.ino
      ) {
        await fileSystem.rm(entry.finalPath, { force: true });
      }
    } catch (error) {
      if (error?.code !== "ENOENT") {
        cleanupFailed = true;
      }
    }
  }
  if (cleanupFailed) {
    throw new EvidenceError(
      "Handshake evidence publication rollback failed.",
      {
        category: "configuration",
        code: "HANDSHAKE_EVIDENCE_ROLLBACK",
      },
    );
  }
}

export async function writeEvidence({
  directory,
  result,
  canaries,
  fileSystem = {},
}) {
  const activeFileSystem = validateWriteOptions({
    directory,
    canaries,
    fileSystem,
  });

  let sanitized;
  try {
    sanitized = redact(result, canaries);
    assertSecretFree(sanitized, canaries);
  } catch {
    throw new EvidenceRedactionError();
  }

  if (!isDeepStrictEqual(sanitized, result)) {
    throw new EvidenceRedactionError();
  }

  validatePassResult(sanitized);
  const json = `${JSON.stringify(sanitized, null, 2)}\n`;
  const markdown = renderResultMarkdown(sanitized);
  const suffix = randomUUID();
  const jsonPath = join(directory, "result.json");
  const markdownPath = join(directory, "RESULT.md");
  const temporaryJsonPath = join(
    directory,
    `.result.${suffix}.json.tmp`,
  );
  const temporaryMarkdownPath = join(
    directory,
    `.result.${suffix}.md.tmp`,
  );
  const temporaryPaths = [
    temporaryJsonPath,
    temporaryMarkdownPath,
  ];
  const published = [];

  try {
    await activeFileSystem.mkdir(directory, { recursive: true });
    await assertEntriesAbsent(
      activeFileSystem,
      [jsonPath, markdownPath],
    );
    await activeFileSystem.writeFile(temporaryJsonPath, json, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
    await activeFileSystem.writeFile(
      temporaryMarkdownPath,
      markdown,
      {
        encoding: "utf8",
        flag: "wx",
        mode: 0o600,
      },
    );

    const temporaryJson = await activeFileSystem.readFile(
      temporaryJsonPath,
      "utf8",
    );
    const temporaryMarkdown = await activeFileSystem.readFile(
      temporaryMarkdownPath,
      "utf8",
    );
    const temporaryResult = JSON.parse(temporaryJson);
    validatePassResult(temporaryResult);
    assertSecretFree(temporaryResult, canaries);
    assertSecretFree(temporaryMarkdown, canaries);
    if (
      !isDeepStrictEqual(temporaryResult, sanitized) ||
      temporaryMarkdown !== markdown
    ) {
      throw new EvidenceError(
        "Handshake temporary evidence cross-check failed.",
      );
    }

    await activeFileSystem.link(
      temporaryJsonPath,
      jsonPath,
    );
    published.push({
      temporaryPath: temporaryJsonPath,
      finalPath: jsonPath,
    });
    await activeFileSystem.link(
      temporaryMarkdownPath,
      markdownPath,
    );
    published.push({
      temporaryPath: temporaryMarkdownPath,
      finalPath: markdownPath,
    });

    const finalJson = await activeFileSystem.readFile(
      jsonPath,
      "utf8",
    );
    const finalMarkdown = await activeFileSystem.readFile(
      markdownPath,
      "utf8",
    );
    const finalResult = JSON.parse(finalJson);
    validatePassResult(finalResult);
    assertSecretFree(finalResult, canaries);
    assertSecretFree(finalMarkdown, canaries);
    if (
      !isDeepStrictEqual(finalResult, sanitized) ||
      finalMarkdown !== markdown
    ) {
      throw new EvidenceError(
        "Handshake final evidence cross-check failed.",
      );
    }

    return { jsonPath, markdownPath };
  } catch (error) {
    if (published.length > 0) {
      await removePublishedFiles(published, activeFileSystem);
    }
    if (error instanceof EvidenceError) {
      throw error;
    }
    throw new EvidenceError(
      "Handshake evidence could not be written and verified.",
      {
        category: "configuration",
        code: "HANDSHAKE_EVIDENCE_IO",
      },
    );
  } finally {
    await removeTemporaryFiles(temporaryPaths, activeFileSystem);
  }
}
