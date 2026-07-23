import { randomUUID } from "node:crypto";
import {
  mkdir,
  readFile,
  rename,
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
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/i;
const TRANSACTION_PATTERN = /^0x[0-9a-f]{64}$/i;
const RFC3339_PATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const MAX_TEXT_LENGTH = 512;

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

function validateWriteOptions({ directory, canaries }) {
  if (
    typeof directory !== "string" ||
    directory.length === 0 ||
    directory.includes("\0") ||
    !Array.isArray(canaries) ||
    canaries.some(
      (canary) =>
        typeof canary !== "string" || canary.length === 0,
    )
  ) {
    throw new EvidenceConfigurationError();
  }
}

async function removeTemporaryFiles(paths) {
  await Promise.all(
    paths.map((path) => rm(path, { force: true }).catch(() => {})),
  );
}

export async function writeEvidence({
  directory,
  result,
  canaries,
}) {
  validateWriteOptions({ directory, canaries });

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

  try {
    await mkdir(directory, { recursive: true });
    await writeFile(temporaryJsonPath, json, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
    await writeFile(temporaryMarkdownPath, markdown, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });

    const temporaryJson = await readFile(
      temporaryJsonPath,
      "utf8",
    );
    const temporaryMarkdown = await readFile(
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

    await rename(temporaryJsonPath, jsonPath);
    await rename(temporaryMarkdownPath, markdownPath);

    const finalJson = await readFile(jsonPath, "utf8");
    const finalMarkdown = await readFile(
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
    await removeTemporaryFiles(temporaryPaths);
  }
}
