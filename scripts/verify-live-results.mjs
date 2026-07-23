import {
  createHash,
  randomUUID as defaultRandomUUID,
} from "node:crypto";
import {
  lstat,
  mkdir,
  readFile,
  readdir,
  realpath,
  rename,
  writeFile,
} from "node:fs/promises";
import {
  dirname,
  extname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";
import { fileURLToPath } from "node:url";

import {
  createPublicClient,
  http,
} from "viem";
import { sepolia } from "viem/chains";

import {
  CHAIN_ID,
  REGISTRY_ADDRESS,
  RPC_URL,
} from "../src/constants.mjs";
import {
  renderResultMarkdown,
  validatePassResult,
} from "../src/evidence.mjs";
import {
  assertCrossPartyVerification,
  createMcpClient,
  mintDemoToken,
} from "../src/mcp.mjs";
import {
  ERC8004_ABI,
  buildRegistrationDocument,
  registrationDataUri,
} from "../src/registration.mjs";
import {
  SENSITIVE_KEY,
  assertSecretFree,
} from "../src/redact.mjs";

const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_DIRECTORY = resolve(SCRIPT_DIRECTORY, "..");
const DEFAULT_RESULT_DIRECTORIES = Object.freeze({
  codex: join(REPOSITORY_DIRECTORY, "artifacts", "codex"),
  claude: join(REPOSITORY_DIRECTORY, "artifacts", "claude"),
});
const DEFAULT_OUTPUT_FILE = join(
  REPOSITORY_DIRECTORY,
  "artifacts",
  "acceptance-verdict.json",
);
const CLIENT_NAMES = Object.freeze(["codex", "claude"]);
const MAX_ARTIFACT_FILE_BYTES = 2 * 1_024 * 1_024;
const MAX_ARTIFACT_TOTAL_BYTES = 8 * 1_024 * 1_024;
const MAX_ARTIFACT_FILES = 256;
const MAX_ARTIFACT_DEPTH = 8;
const MAX_CANARY_FILE_BYTES = 128 * 1_024;
const SECRET_ASSIGNMENT_PATTERN =
  /(?:private.?key|secret|token|invite(?:ation)?.?code|ciphertext)\s*["']?\s*[:=]\s*(?!"?\[REDACTED\]"?)[^\s,;}]+/i;
const HASH_PATTERN = /^[0-9a-f]{64}$/;

class LiveVerificationConfigurationError extends Error {
  constructor() {
    super("Live-result verification configuration is invalid.");
    this.name = "LiveVerificationConfigurationError";
    this.code = "LIVE_VERIFICATION_CONFIGURATION";
  }
}

class LiveVerificationError extends Error {
  constructor(code) {
    super("Live-result verification failed.");
    this.name = "LiveVerificationError";
    this.code = code;
  }
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object") {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function absolutePath(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 4_096 ||
    value.trim() !== value ||
    !isAbsolute(value) ||
    /[\u0000-\u001f\u007f-\u009f]/.test(value)
  ) {
    throw new LiveVerificationConfigurationError();
  }
  return resolve(value);
}

function normalizedCanaries(canaries) {
  if (
    !Array.isArray(canaries) ||
    canaries.some(
      (value) =>
        typeof value !== "string" ||
        value.length === 0 ||
        value.length > MAX_CANARY_FILE_BYTES,
    )
  ) {
    throw new LiveVerificationConfigurationError();
  }
  return [...new Set(canaries)];
}

function sortDeep(value) {
  if (Array.isArray(value)) {
    return value.map(sortDeep);
  }
  if (value && typeof value === "object") {
    const result = {};
    for (const key of Object.keys(value).sort()) {
      result[key] = sortDeep(value[key]);
    }
    return result;
  }
  return value;
}

function canonicalize(value) {
  return JSON.stringify(sortDeep(value) ?? null);
}

export function expectedReceiptHash(result) {
  validatePassResult(result);
  const event = {
    agentId: result.identity.agentId,
    action: result.scenario.action,
    inputs: {
      runId: result.runId,
      identityReference: result.identity.reference,
      counterparty: result.scenario.counterparty,
      authorization: {
        amount: result.scenario.amount.value,
        currency: result.scenario.amount.currency,
        settlement: "not-executed",
      },
    },
    outputs: {
      decision: "approved-for-demo",
      scope: "identity-and-time-receipt-only",
      paymentMoved: false,
    },
  };
  return createHash("sha256")
    .update(canonicalize(event), "utf8")
    .digest("hex");
}

function collectSensitiveCanaries(value, underSensitiveKey = false) {
  const canaries = [];
  if (typeof value === "string") {
    if (underSensitiveKey && value.length > 0) {
      canaries.push(value);
    }
    return canaries;
  }
  if (Array.isArray(value)) {
    for (const entry of value) {
      canaries.push(
        ...collectSensitiveCanaries(entry, underSensitiveKey),
      );
    }
    return canaries;
  }
  if (!isPlainObject(value)) {
    return canaries;
  }
  for (const [key, entry] of Object.entries(value)) {
    const sensitiveKey =
      underSensitiveKey ||
      key.toLowerCase() === "code" ||
      SENSITIVE_KEY.test(key);
    canaries.push(
      ...collectSensitiveCanaries(
        entry,
        sensitiveKey,
      ),
    );
  }
  return canaries;
}

async function loadCanaryFiles(canaryFiles) {
  if (
    !Array.isArray(canaryFiles) ||
    canaryFiles.some((path) => typeof path !== "string")
  ) {
    throw new LiveVerificationConfigurationError();
  }
  const canaries = [];
  for (const candidate of canaryFiles) {
    const path = absolutePath(candidate);
    const stat = await lstat(path);
    if (
      !stat.isFile() ||
      stat.isSymbolicLink() ||
      stat.size < 1 ||
      stat.size > MAX_CANARY_FILE_BYTES
    ) {
      throw new LiveVerificationConfigurationError();
    }
    const text = await readFile(path, "utf8");
    try {
      const parsed = JSON.parse(text);
      canaries.push(...collectSensitiveCanaries(parsed));
    } catch {
      canaries.push(
        ...text
          .split(/\r?\n/)
          .map((line) => line.trim())
          .filter(Boolean),
      );
    }
  }
  return normalizedCanaries(canaries);
}

function isWithin(root, candidate) {
  const path = relative(root, candidate);
  return (
    path === "" ||
    (!path.startsWith(`..${sep}`) && path !== ".." && !isAbsolute(path))
  );
}

function assertArtifactText(text, canaries) {
  assertSecretFree(text, canaries);
  if (SECRET_ASSIGNMENT_PATTERN.test(text)) {
    throw new LiveVerificationError(
      "ARTIFACT_SECRET_DETECTED",
    );
  }
}

async function scanArtifactDirectory(directory, canaries) {
  const rootStat = await lstat(directory);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
    throw new LiveVerificationError(
      "ARTIFACT_DIRECTORY_INVALID",
    );
  }
  const canonicalRoot = await realpath(directory);
  const queue = [{ directory: canonicalRoot, depth: 0 }];
  let fileCount = 0;
  let totalBytes = 0;

  while (queue.length > 0) {
    const current = queue.shift();
    const entries = await readdir(current.directory, {
      withFileTypes: true,
    });
    for (const entry of entries) {
      const path = join(current.directory, entry.name);
      if (entry.isSymbolicLink()) {
        throw new LiveVerificationError(
          "ARTIFACT_SYMLINK_REJECTED",
        );
      }
      if (entry.isDirectory()) {
        if (current.depth >= MAX_ARTIFACT_DEPTH) {
          throw new LiveVerificationError(
            "ARTIFACT_SCAN_LIMIT",
          );
        }
        const canonicalChild = await realpath(path);
        if (!isWithin(canonicalRoot, canonicalChild)) {
          throw new LiveVerificationError(
            "ARTIFACT_PATH_ESCAPE",
          );
        }
        queue.push({
          directory: canonicalChild,
          depth: current.depth + 1,
        });
        continue;
      }
      if (!entry.isFile()) {
        throw new LiveVerificationError(
          "ARTIFACT_FILE_INVALID",
        );
      }
      const stat = await lstat(path);
      fileCount += 1;
      totalBytes += stat.size;
      if (
        fileCount > MAX_ARTIFACT_FILES ||
        stat.size > MAX_ARTIFACT_FILE_BYTES ||
        totalBytes > MAX_ARTIFACT_TOTAL_BYTES
      ) {
        throw new LiveVerificationError(
          "ARTIFACT_SCAN_LIMIT",
        );
      }
      const text = await readFile(path, "utf8");
      assertArtifactText(text, canaries);
      if (extname(path).toLowerCase() === ".json") {
        try {
          assertSecretFree(JSON.parse(text), canaries);
        } catch (error) {
          if (/Secret material detected/i.test(error?.message)) {
            throw new LiveVerificationError(
              "ARTIFACT_SECRET_DETECTED",
            );
          }
        }
      }
    }
  }
}

async function loadLocalResult(directory, canaries) {
  await scanArtifactDirectory(directory, canaries);
  const jsonPath = join(directory, "result.json");
  const markdownPath = join(directory, "RESULT.md");
  const [jsonStat, markdownStat] = await Promise.all([
    lstat(jsonPath),
    lstat(markdownPath),
  ]);
  if (
    !jsonStat.isFile() ||
    jsonStat.isSymbolicLink() ||
    !markdownStat.isFile() ||
    markdownStat.isSymbolicLink() ||
    jsonStat.size > MAX_ARTIFACT_FILE_BYTES ||
    markdownStat.size > MAX_ARTIFACT_FILE_BYTES
  ) {
    throw new LiveVerificationError("RESULT_FILES_INVALID");
  }
  let result;
  try {
    result = JSON.parse(await readFile(jsonPath, "utf8"));
    validatePassResult(result);
  } catch {
    throw new LiveVerificationError("RESULT_SCHEMA_INVALID");
  }
  const markdown = await readFile(markdownPath, "utf8");
  if (markdown !== renderResultMarkdown(result)) {
    throw new LiveVerificationError(
      "RESULT_MARKDOWN_MISMATCH",
    );
  }
  assertSecretFree(result, canaries);
  assertSecretFree(markdown, canaries);
  return {
    directory,
    jsonPath,
    markdownPath,
    result,
  };
}

function addressesEqual(left, right) {
  return (
    typeof left === "string" &&
    typeof right === "string" &&
    /^0x[0-9a-f]{40}$/i.test(left) &&
    /^0x[0-9a-f]{40}$/i.test(right) &&
    left.toLowerCase() === right.toLowerCase()
  );
}

async function verifyIdentity(publicClient, result) {
  const agentId = BigInt(result.identity.agentId);
  const common = {
    address: REGISTRY_ADDRESS,
    abi: ERC8004_ABI,
    args: [agentId],
  };
  const owner = await publicClient.readContract({
    ...common,
    functionName: "ownerOf",
  });
  const agentWallet = await publicClient.readContract({
    ...common,
    functionName: "getAgentWallet",
  });
  const tokenUri = await publicClient.readContract({
    ...common,
    functionName: "tokenURI",
  });
  const expectedUri = registrationDataUri(
    buildRegistrationDocument({
      displayName: result.identity.displayName,
      agentId,
    }),
  );
  if (
    !addressesEqual(owner, result.identity.owner) ||
    !addressesEqual(agentWallet, result.identity.owner) ||
    tokenUri !== expectedUri
  ) {
    throw new LiveVerificationError(
      "ERC8004_IDENTITY_MISMATCH",
    );
  }
  return {
    agentId: result.identity.agentId,
    reference: result.identity.reference,
    owner: result.identity.owner,
    ownerOfMatches: true,
    agentWalletMatches: true,
    metadataUriMatches: true,
  };
}

async function verifyClockchain(mcpClient, result) {
  const identifiers = {
    ledgerId: result.clockchain.ledgerId,
    blockHeight: result.clockchain.blockHeight,
  };
  const verification = await mcpClient.verifyCrossParty(
    identifiers,
  );
  assertCrossPartyVerification(verification);
  const { onChain } = verification;
  const expectedHash = expectedReceiptHash(result);
  const expectedReferencePrefix =
    `${result.identity.agentId}:trust_handshake:`;
  if (
    onChain.ledgerId !== result.clockchain.ledgerId ||
    String(onChain.blockHeight) !==
      result.clockchain.blockHeight ||
    onChain.verifiedAgainst !==
      result.clockchain.verifiedAgainst ||
    onChain.keyless !== result.clockchain.keyless ||
    typeof onChain.anchoredHash !== "string" ||
    !HASH_PATTERN.test(onChain.anchoredHash) ||
    onChain.anchoredHash !== expectedHash ||
    typeof onChain.assetReferenceId !== "string" ||
    !onChain.assetReferenceId.startsWith(
      expectedReferencePrefix,
    ) ||
    !/^\d+$/.test(
      onChain.assetReferenceId.slice(
        expectedReferencePrefix.length,
      ),
    )
  ) {
    throw new LiveVerificationError(
      "CLOCKCHAIN_RECEIPT_MISMATCH",
    );
  }
  return {
    ledgerId: result.clockchain.ledgerId,
    blockHeight: result.clockchain.blockHeight,
    anchoredHash: expectedHash,
    hashMatches: true,
    verifiedAgainst: result.clockchain.verifiedAgainst,
    keyless: result.clockchain.keyless,
  };
}

function safeFailureCode(error, fallback) {
  return (
    typeof error?.code === "string" &&
    /^[A-Z][A-Z0-9_]{2,80}$/.test(error.code)
  )
    ? error.code
    : fallback;
}

function distinctAggregate(localResults) {
  const results = CLIENT_NAMES.map(
    (name) => localResults[name]?.result,
  );
  if (results.some((result) => !result)) {
    return {
      distinctRunIds: false,
      distinctIdentities: false,
      distinctLedgerIds: false,
      distinctBlockHeights: false,
    };
  }
  const distinct = (values) => new Set(values).size === values.length;
  return {
    distinctRunIds: distinct(results.map(({ runId }) => runId)),
    distinctIdentities:
      distinct(results.map(({ identity }) => identity.agentId)) &&
      distinct(results.map(({ identity }) => identity.reference)) &&
      distinct(
        results.map(({ identity }) => identity.owner.toLowerCase()),
      ),
    distinctLedgerIds: distinct(
      results.map(({ clockchain }) => clockchain.ledgerId),
    ),
    distinctBlockHeights: distinct(
      results.map(({ clockchain }) => clockchain.blockHeight),
    ),
  };
}

async function verifyPlatform(publicClient) {
  const chainId = await publicClient.getChainId();
  if (chainId !== CHAIN_ID) {
    throw new LiveVerificationError("ETHEREUM_CHAIN_MISMATCH");
  }
  const code = await publicClient.getCode({
    address: REGISTRY_ADDRESS,
  });
  if (
    typeof code !== "string" ||
    !/^0x(?:[0-9a-f]{2})+$/i.test(code)
  ) {
    throw new LiveVerificationError(
      "ERC8004_REGISTRY_UNAVAILABLE",
    );
  }
}

async function writeVerdict(outputFile, verdict, canaries) {
  assertSecretFree(verdict, canaries);
  const directory = dirname(outputFile);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const temporary = `${outputFile}.tmp-${process.pid}`;
  await writeFile(
    temporary,
    `${JSON.stringify(verdict, null, 2)}\n`,
    { mode: 0o600 },
  );
  await rename(temporary, outputFile);
}

export async function verifyLiveResults({
  canaries = [],
  canaryFiles = [],
  clientFactory = createMcpClient,
  now = () => new Date(),
  outputFile = DEFAULT_OUTPUT_FILE,
  publicClient = createPublicClient({
    chain: sepolia,
    transport: http(RPC_URL),
  }),
  randomUUID = defaultRandomUUID,
  resultDirectories = DEFAULT_RESULT_DIRECTORIES,
  tokenIssuer = mintDemoToken,
} = {}) {
  if (
    !isPlainObject(resultDirectories) ||
    typeof clientFactory !== "function" ||
    typeof now !== "function" ||
    typeof randomUUID !== "function" ||
    typeof tokenIssuer !== "function" ||
    !publicClient ||
    typeof publicClient.getChainId !== "function" ||
    typeof publicClient.getCode !== "function" ||
    typeof publicClient.readContract !== "function"
  ) {
    throw new LiveVerificationConfigurationError();
  }
  const directories = Object.fromEntries(
    CLIENT_NAMES.map((name) => [
      name,
      absolutePath(resultDirectories[name]),
    ]),
  );
  const canonicalDirectories = await Promise.all(
    CLIENT_NAMES.map((name) => realpath(directories[name])),
  );
  if (
    canonicalDirectories[0] === canonicalDirectories[1] ||
    isWithin(canonicalDirectories[0], canonicalDirectories[1]) ||
    isWithin(canonicalDirectories[1], canonicalDirectories[0])
  ) {
    throw new LiveVerificationConfigurationError();
  }
  const activeOutputFile = absolutePath(outputFile);
  const activeCanaries = normalizedCanaries([
    ...normalizedCanaries(canaries),
    ...(await loadCanaryFiles(canaryFiles)),
  ]);
  const localResults = {};
  const clients = {};

  for (const name of CLIENT_NAMES) {
    try {
      localResults[name] = await loadLocalResult(
        directories[name],
        activeCanaries,
      );
    } catch (error) {
      clients[name] = {
        status: "FAIL",
        resultPath: join(directories[name], "result.json"),
        errorCode: safeFailureCode(
          error,
          "LOCAL_RESULT_VERIFICATION_FAILED",
        ),
      };
    }
  }

  let sharedError = null;
  if (Object.keys(localResults).length > 0) {
    try {
      await verifyPlatform(publicClient);
    } catch (error) {
      sharedError = safeFailureCode(
        error,
        "ETHEREUM_VERIFICATION_FAILED",
      );
    }
  }

  let token;
  let mcpClient;
  if (!sharedError && Object.keys(localResults).length > 0) {
    try {
      token = await tokenIssuer({
        subject: `handshake-verifier-${randomUUID()}`,
      });
      if (typeof token !== "string" || token.length === 0) {
        throw new LiveVerificationError(
          "CLOCKCHAIN_TOKEN_INVALID",
        );
      }
      mcpClient = clientFactory({ token });
      if (
        !mcpClient ||
        typeof mcpClient.verifyCrossParty !== "function"
      ) {
        throw new LiveVerificationError(
          "CLOCKCHAIN_CLIENT_INVALID",
        );
      }
    } catch (error) {
      sharedError = safeFailureCode(
        error,
        "CLOCKCHAIN_TOKEN_FAILED",
      );
    }
  }

  for (const name of CLIENT_NAMES) {
    if (!localResults[name]) {
      continue;
    }
    if (sharedError) {
      clients[name] = {
        status: "FAIL",
        resultPath: localResults[name].jsonPath,
        errorCode: sharedError,
      };
      continue;
    }
    try {
      const result = localResults[name].result;
      clients[name] = {
        status: "PASS",
        resultPath: localResults[name].jsonPath,
        identity: await verifyIdentity(publicClient, result),
        clockchain: await verifyClockchain(mcpClient, result),
      };
    } catch (error) {
      clients[name] = {
        status: "FAIL",
        resultPath: localResults[name].jsonPath,
        errorCode: safeFailureCode(
          error,
          "LIVE_RESULT_MISMATCH",
        ),
      };
    }
  }

  const aggregate = distinctAggregate(localResults);
  const status =
    CLIENT_NAMES.every(
      (name) => clients[name]?.status === "PASS",
    ) &&
    Object.values(aggregate).every(Boolean)
      ? "PASS"
      : "FAIL";
  const verdict = {
    schema: "clockchain.handshake-acceptance-verdict/v1",
    status,
    verifiedAt: now().toISOString(),
    clients,
    aggregate,
  };
  await writeVerdict(
    activeOutputFile,
    verdict,
    [...activeCanaries, ...(token ? [token] : [])],
  );
  return verdict;
}

function parseArguments(argv) {
  const values = {
    resultDirectories: { ...DEFAULT_RESULT_DIRECTORIES },
    outputFile: DEFAULT_OUTPUT_FILE,
    canaryFiles: [],
  };
  for (let index = 0; index < argv.length;) {
    const option = argv[index];
    const value = argv[index + 1];
    if (value === undefined) {
      throw new LiveVerificationConfigurationError();
    }
    if (option === "--codex") {
      values.resultDirectories.codex = resolve(value);
    } else if (option === "--claude") {
      values.resultDirectories.claude = resolve(value);
    } else if (option === "--output") {
      values.outputFile = resolve(value);
    } else if (option === "--canary-file") {
      values.canaryFiles.push(resolve(value));
    } else {
      throw new LiveVerificationConfigurationError();
    }
    index += 2;
  }
  return values;
}

export async function main({
  argv = process.argv.slice(2),
  stderr = process.stderr,
  stdout = process.stdout,
} = {}) {
  try {
    const verdict = await verifyLiveResults(
      parseArguments(argv),
    );
    stdout.write(
      `${verdict.status} ${DEFAULT_OUTPUT_FILE}\n`,
    );
    return verdict.status === "PASS" ? 0 : 1;
  } catch {
    stderr.write("Live-result verification configuration failed.\n");
    return 2;
  }
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  process.exitCode = await main();
}
