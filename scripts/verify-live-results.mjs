import {
  createHash,
  randomUUID as defaultRandomUUID,
} from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import {
  constants as fileSystemConstants,
} from "node:fs";
import {
  lstat,
  mkdir,
  open,
  readdir,
  realpath,
  rename,
  writeFile,
} from "node:fs/promises";
import {
  basename,
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
  decodeFunctionData,
  encodeFunctionData,
  http,
} from "viem";
import { sepolia } from "viem/chains";

import {
  CHAIN_ID,
  REGISTRY_ADDRESS,
  RPC_URL,
} from "../src/constants.mjs";
import {
  computeReceiptEventHash,
  renderResultMarkdown,
  validatePassResult,
} from "../src/evidence.mjs";
import { readSecretInvitation } from "../src/invitation.mjs";
import {
  assertCrossPartyVerification,
  createMcpClient,
  mintDemoToken,
} from "../src/mcp.mjs";
import {
  ERC8004_ABI,
  buildRegistrationDocument,
  parseRegisteredAgentId,
  registrationDataUri,
} from "../src/registration.mjs";
import {
  SecretMaterialDetectedError,
  assertSecretFree,
  broadSecretAssignmentPattern,
  highEntropySecretAssignmentPattern,
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
const DEFAULT_PROMPT_FILE = join(
  REPOSITORY_DIRECTORY,
  "prompts",
  "run-turnkey-demo.md",
);
const CLIENT_NAMES = Object.freeze(["codex", "claude"]);
const MAX_ARTIFACT_FILE_BYTES = 2 * 1_024 * 1_024;
const MAX_ARTIFACT_TOTAL_BYTES = 8 * 1_024 * 1_024;
const MAX_ARTIFACT_FILES = 256;
const MAX_ARTIFACT_DEPTH = 8;
const MAX_CANARY_FILE_BYTES = 128 * 1_024;
const MAX_MANIFEST_BYTES = 256 * 1_024;
const MAX_PROMPT_BYTES = 256 * 1_024;
const VERIFIER_READ_FLAGS =
  fileSystemConstants.O_RDONLY |
  (fileSystemConstants.O_NOFOLLOW ?? 0) |
  (fileSystemConstants.O_NONBLOCK ?? 0);
export const VERIFIER_READ_FLAGS_FOR_TESTING =
  VERIFIER_READ_FLAGS;
const REPOSITORY_SHA_PATTERN = /^[0-9a-f]{40}$/i;
const CODEX_VERSION_PATTERN =
  /^codex-cli \d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;
const CLAUDE_VERSION_PATTERN =
  /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)? \(Claude Code\)$/;
const RFC3339_PATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const DEFAULT_CLIENT_COMMANDS = Object.freeze({
  codex: Object.freeze({
    executable: "codex",
    args: Object.freeze([
      "exec",
      "--ephemeral",
      "--skip-git-repo-check",
      "--ignore-user-config",
      "--ignore-rules",
      "--dangerously-bypass-approvals-and-sandbox",
      "-",
    ]),
  }),
  claude: Object.freeze({
    executable: "claude",
    args: Object.freeze([
      "-p",
      "--no-session-persistence",
      "--permission-mode",
      "bypassPermissions",
      "--dangerously-skip-permissions",
      "--safe-mode",
    ]),
  }),
});
const SECRET_ASSIGNMENT_PATTERN =
  highEntropySecretAssignmentPattern();
const CANONICAL_SECRET_ASSIGNMENT_PATTERN =
  broadSecretAssignmentPattern();
// result.json and RESULT.md are rendered from an exact-key allowlist, so they
// are held to the broad rule as well as the high-entropy one. Matched against
// the scan-relative name, so only the two root entries loadLocalResult treats
// as canonical qualify; a nested "sub/result.json" is an ordinary artifact
// this pipeline never generated and stays on the high-entropy rule alone.
const CANONICAL_ARTIFACT_NAMES = Object.freeze([
  "result.json",
  "RESULT.md",
]);
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

function expectedReceiptEvent(result) {
  validatePassResult(result);
  return {
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
}

export function expectedReceiptHash(result) {
  return computeReceiptEventHash(expectedReceiptEvent(result));
}

function normalizeRepositorySha(value) {
  if (
    typeof value !== "string" ||
    !REPOSITORY_SHA_PATTERN.test(value)
  ) {
    throw new LiveVerificationConfigurationError();
  }
  return value.toLowerCase();
}

async function loadOperatorInvitations(
  canaryFiles,
  readInvitation,
) {
  if (
    !Array.isArray(canaryFiles) ||
    canaryFiles.length !== CLIENT_NAMES.length ||
    canaryFiles.some((path) => typeof path !== "string") ||
    typeof readInvitation !== "function"
  ) {
    throw new LiveVerificationConfigurationError();
  }
  const paths = canaryFiles.map(absolutePath);
  if (new Set(paths).size !== paths.length) {
    throw new LiveVerificationConfigurationError();
  }
  const invitations = {};
  const canaries = [];
  for (let index = 0; index < CLIENT_NAMES.length; index += 1) {
    const invitation = await readInvitation(paths[index]);
    const code = invitation?.code;
    const bundle = invitation?.bundle;
    const ciphertext = bundle?.crypto?.ciphertext;
    if (
      typeof code !== "string" ||
      code.length === 0 ||
      code.length > MAX_CANARY_FILE_BYTES ||
      typeof ciphertext !== "string" ||
      ciphertext.length === 0 ||
      ciphertext.length > MAX_CANARY_FILE_BYTES ||
      !addressesEqual(bundle?.address, bundle?.address) ||
      typeof bundle?.displayName !== "string" ||
      bundle.displayName.length === 0 ||
      bundle.displayName.length > 128
    ) {
      throw new LiveVerificationConfigurationError();
    }
    invitations[CLIENT_NAMES[index]] = {
      address: bundle.address,
      displayName: bundle.displayName,
    };
    canaries.push(code, ciphertext);
  }
  return {
    canaries: normalizedCanaries(canaries),
    invitations,
  };
}

function isWithin(root, candidate) {
  const path = relative(root, candidate);
  return (
    path === "" ||
    (!path.startsWith(`..${sep}`) && path !== ".." && !isAbsolute(path))
  );
}

// Two heuristics with two error codes, so an operator can tell a prose-safe
// high-entropy hit from an illegitimate assignment in a generated document.
//
// Residual blind spot, stated plainly: a SHORT secret assignment in a
// NON-canonical artifact ("token: abc123" in stdout.log) is not caught here.
// The high-entropy floor that keeps agent narration from failing a healthy run
// is exactly what hides it. Such a value is only caught when it is an operator
// canary, a labelled private key, a bearer or cc_ token, or an address — the
// known-shape checks inside assertSecretFree — or, for a .json artifact, when
// it sits under a sensitive key visible after parsing.
function assertArtifactText(text, canaries, canonical) {
  try {
    assertSecretFree(text, canaries);
  } catch (error) {
    if (error instanceof SecretMaterialDetectedError) {
      throw new LiveVerificationError(
        "ARTIFACT_SECRET_DETECTED",
      );
    }
    throw error;
  }
  if (SECRET_ASSIGNMENT_PATTERN.test(text)) {
    throw new LiveVerificationError(
      "ARTIFACT_SECRET_ASSIGNMENT_SUSPECTED",
    );
  }
  if (
    canonical &&
    CANONICAL_SECRET_ASSIGNMENT_PATTERN.test(text)
  ) {
    throw new LiveVerificationError(
      "CANONICAL_ARTIFACT_SECRET_ASSIGNMENT_SUSPECTED",
    );
  }
}

function unchangedDescriptor(before, after) {
  return (
    after.isFile() &&
    before.dev === after.dev &&
    before.ino === after.ino &&
    before.mode === after.mode &&
    before.nlink === after.nlink &&
    before.uid === after.uid &&
    before.gid === after.gid &&
    before.rdev === after.rdev &&
    before.size === after.size &&
    before.mtimeNs === after.mtimeNs &&
    before.ctimeNs === after.ctimeNs
  );
}

async function readStableVerifierFile(path, {
  afterRead,
  errorFactory,
  maximum,
  minimum,
}) {
  let bytes;
  let failure;
  let handle;
  try {
    handle = await open(path, VERIFIER_READ_FLAGS);
    const before = await handle.stat({ bigint: true });
    if (
      !before.isFile() ||
      before.size < BigInt(minimum) ||
      before.size > BigInt(maximum)
    ) {
      throw new Error("Verifier file boundary rejected.");
    }
    bytes = await handle.readFile();
    await afterRead?.();
    const after = await handle.stat({ bigint: true });
    if (
      !unchangedDescriptor(before, after) ||
      BigInt(bytes.length) !== before.size
    ) {
      throw new Error("Verifier file boundary rejected.");
    }
  } catch (error) {
    failure = error;
  }
  if (handle) {
    try {
      await handle.close();
    } catch (error) {
      failure ??= error;
    }
  }
  if (failure) {
    throw errorFactory();
  }
  return bytes;
}

async function readArtifactFile(path, afterRead) {
  const bytes = await readStableVerifierFile(path, {
    afterRead,
    errorFactory: () =>
      new LiveVerificationError("ARTIFACT_FILE_INVALID"),
    maximum: MAX_ARTIFACT_FILE_BYTES,
    minimum: 0,
  });
  return Object.freeze({
    bytes,
    size: bytes.length,
    text: bytes.toString("utf8"),
  });
}

async function readTrustedFile(path, maximum, afterRead) {
  return readStableVerifierFile(absolutePath(path), {
    afterRead,
    errorFactory: () =>
      new LiveVerificationConfigurationError(),
    maximum,
    minimum: 1,
  });
}

export async function readVerifierFileForTesting(
  path,
  maximum,
  {
    afterRead,
    trusted = false,
  } = {},
) {
  if (
    !Number.isSafeInteger(maximum) ||
    maximum < 1 ||
    typeof trusted !== "boolean" ||
    (
      afterRead !== undefined &&
      typeof afterRead !== "function"
    )
  ) {
    throw new LiveVerificationConfigurationError();
  }
  if (trusted) {
    return readTrustedFile(path, maximum, afterRead);
  }
  return (
    await readArtifactFile(path, afterRead)
  ).bytes;
}

async function scanArtifactDirectory(directory, canaries) {
  const rootStat = await lstat(directory);
  let scanError = null;
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
    scanError = new LiveVerificationError(
      "ARTIFACT_DIRECTORY_INVALID",
    );
  }
  const canonicalRoot = await realpath(directory);
  const queue = [{ directory: canonicalRoot, depth: 0 }];
  const files = new Map();
  let fileCount = 0;
  let totalBytes = 0;

  const retainScanError = (error) => {
    scanError ??= error instanceof LiveVerificationError
      ? error
      : new LiveVerificationError("ARTIFACT_FILE_INVALID");
  };

  while (queue.length > 0) {
    const current = queue.shift();
    let entries;
    try {
      entries = await readdir(current.directory, {
        withFileTypes: true,
      });
    } catch (error) {
      retainScanError(error);
      continue;
    }
    entries.sort((left, right) => {
      const priority = (name) => {
        if (name === "result.json") {
          return 0;
        }
        if (name === "RESULT.md") {
          return 1;
        }
        return 2;
      };
      return (
        priority(left.name) - priority(right.name) ||
        left.name.localeCompare(right.name)
      );
    });
    for (const entry of entries) {
      const path = join(current.directory, entry.name);
      if (entry.isSymbolicLink()) {
        retainScanError(
          new LiveVerificationError(
            "ARTIFACT_SYMLINK_REJECTED",
          ),
        );
        continue;
      }
      if (entry.isDirectory()) {
        if (current.depth >= MAX_ARTIFACT_DEPTH) {
          retainScanError(
            new LiveVerificationError(
              "ARTIFACT_SCAN_LIMIT",
            ),
          );
          continue;
        }
        let canonicalChild;
        try {
          canonicalChild = await realpath(path);
        } catch (error) {
          retainScanError(error);
          continue;
        }
        if (!isWithin(canonicalRoot, canonicalChild)) {
          retainScanError(
            new LiveVerificationError(
              "ARTIFACT_PATH_ESCAPE",
            ),
          );
          continue;
        }
        queue.push({
          directory: canonicalChild,
          depth: current.depth + 1,
        });
        continue;
      }
      if (!entry.isFile()) {
        retainScanError(
          new LiveVerificationError(
            "ARTIFACT_FILE_INVALID",
          ),
        );
        continue;
      }
      fileCount += 1;
      if (fileCount > MAX_ARTIFACT_FILES) {
        retainScanError(
          new LiveVerificationError(
            "ARTIFACT_SCAN_LIMIT",
          ),
        );
        continue;
      }
      let file;
      try {
        file = await readArtifactFile(path);
      } catch (error) {
        retainScanError(error);
        continue;
      }
      if (
        totalBytes + file.size >
        MAX_ARTIFACT_TOTAL_BYTES
      ) {
        retainScanError(
          new LiveVerificationError(
            "ARTIFACT_SCAN_LIMIT",
          ),
        );
        continue;
      }
      totalBytes += file.size;
      const { text } = file;
      const artifactName = relative(canonicalRoot, path);
      try {
        assertArtifactText(
          text,
          canaries,
          CANONICAL_ARTIFACT_NAMES.includes(artifactName),
        );
      } catch (error) {
        retainScanError(error);
      }
      if (extname(path).toLowerCase() === ".json") {
        try {
          assertSecretFree(JSON.parse(text), canaries);
        } catch (error) {
          if (error instanceof SecretMaterialDetectedError) {
            retainScanError(
              new LiveVerificationError(
                "ARTIFACT_SECRET_DETECTED",
              ),
            );
          }
        }
      }
      files.set(artifactName, file);
    }
  }
  return Object.freeze({
    error: scanError,
    files,
  });
}

function loadLocalResult(directory, artifactScan, canaries) {
  if (artifactScan.error) {
    throw artifactScan.error;
  }
  const { files } = artifactScan;
  const jsonPath = join(directory, "result.json");
  const markdownPath = join(directory, "RESULT.md");
  const jsonText = files.get("result.json")?.text;
  const markdown = files.get("RESULT.md")?.text;
  if (
    typeof jsonText !== "string" ||
    typeof markdown !== "string"
  ) {
    throw new LiveVerificationError("RESULT_FILES_INVALID");
  }
  let result;
  try {
    result = JSON.parse(jsonText);
    validatePassResult(result);
  } catch {
    throw new LiveVerificationError("RESULT_SCHEMA_INVALID");
  }
  if (markdown !== renderResultMarkdown(result)) {
    throw new LiveVerificationError(
      "RESULT_MARKDOWN_MISMATCH",
    );
  }
  // Defence in depth only, and unreachable today: scanArtifactDirectory
  // already ran assertSecretFree over this exact markdown text and over
  // JSON.parse of this exact result.json text, with the identical canary set,
  // and loadLocalResult rethrows artifactScan.error above before reaching
  // here. Instrumenting these two calls to log on throw produced zero hits
  // across the whole acceptance-harness suite. No test can pin the branch
  // while it stays unreachable; it is retained because it becomes the only
  // guard the moment the scan stops covering a canonical file. The wrap keeps
  // SecretMaterialDetectedError's own code out of the published verdict, so a
  // client errorCode never leaves this verifier's vocabulary.
  try {
    assertSecretFree(result, canaries);
    assertSecretFree(markdown, canaries);
  } catch (error) {
    if (error instanceof SecretMaterialDetectedError) {
      throw new LiveVerificationError(
        "ARTIFACT_SECRET_DETECTED",
      );
    }
    throw error;
  }
  return {
    directory,
    jsonPath,
    markdownPath,
    result,
  };
}

function hasExactKeys(value, keys) {
  return (
    isPlainObject(value) &&
    Reflect.ownKeys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key))
  );
}

function isCanonicalTimestamp(value) {
  return (
    typeof value === "string" &&
    RFC3339_PATTERN.test(value) &&
    Number.isFinite(Date.parse(value)) &&
    new Date(value).toISOString() === value
  );
}

function timestampMilliseconds(value) {
  if (!isCanonicalTimestamp(value)) {
    throw new LiveVerificationConfigurationError();
  }
  return Date.parse(value);
}

function resultTimestampMilliseconds(value) {
  if (!isCanonicalTimestamp(value)) {
    throw new LiveVerificationError(
      "RESULT_OUTSIDE_RUN_WINDOW",
    );
  }
  return Date.parse(value);
}

// Establishes only that a result's self-reported timestamps fall inside the
// window recorded by the manifest it shipped with, so a result cannot be
// swapped in from a different run in the same artifact set. It does NOT make
// the evidence replay-proof: the manifest's own startedAt/completedAt are
// operator-chosen and bound to no external clock, and
// clockchain.consensusTime is not bound to this window at all. An operator
// who re-signs a manifest around old results still passes this check.
function assertResultWithinRunWindow(result, window) {
  const startedAt = resultTimestampMilliseconds(
    result.startedAt,
  );
  const completedAt = resultTimestampMilliseconds(
    result.completedAt,
  );
  if (
    startedAt < window.started ||
    completedAt < startedAt ||
    completedAt > window.completed
  ) {
    throw new LiveVerificationError(
      "RESULT_OUTSIDE_RUN_WINDOW",
    );
  }
}

function commandMatches(clientName, command) {
  const expected = DEFAULT_CLIENT_COMMANDS[clientName];
  return (
    hasExactKeys(command, ["executable", "args"]) &&
    command.executable === expected.executable &&
    isDeepStrictEqual(command.args, expected.args)
  );
}

function versionMatches(clientName, value) {
  return (
    typeof value === "string" &&
    (
      clientName === "codex"
        ? CODEX_VERSION_PATTERN.test(value)
        : CLAUDE_VERSION_PATTERN.test(value)
    )
  );
}

function validateManifestEvidenceReference(
  evidence,
  expectedPath,
) {
  if (
    !hasExactKeys(evidence, ["path", "sha256"]) ||
    absolutePath(evidence.path) !== expectedPath ||
    typeof evidence.sha256 !== "string" ||
    !HASH_PATTERN.test(evidence.sha256)
  ) {
    throw new LiveVerificationConfigurationError();
  }
}

function validateManifestEvidence(
  evidence,
  expectedPath,
  file,
) {
  validateManifestEvidenceReference(evidence, expectedPath);
  if (!file) {
    throw new LiveVerificationConfigurationError();
  }
  const digest = createHash("sha256")
    .update(file.bytes)
    .digest("hex");
  if (digest !== evidence.sha256) {
    throw new LiveVerificationConfigurationError();
  }
}

async function validateAcceptanceManifest({
  directories,
  expectedRepositorySha,
  manifestFile,
}) {
  const activeManifestFile = absolutePath(manifestFile);
  const commonDirectory = dirname(directories.codex);
  if (
    basename(activeManifestFile) !==
      "client-acceptance.json" ||
    dirname(activeManifestFile) !== commonDirectory ||
    dirname(directories.claude) !== commonDirectory ||
    basename(directories.codex) !== "codex" ||
    basename(directories.claude) !== "claude"
  ) {
    throw new LiveVerificationConfigurationError();
  }
  const bytes = await readTrustedFile(
    activeManifestFile,
    MAX_MANIFEST_BYTES,
  );
  let manifest;
  try {
    manifest = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new LiveVerificationConfigurationError();
  }
  if (
    !hasExactKeys(manifest, [
      "schema",
      "status",
      "repositorySha",
      "promptSha256",
      "startedAt",
      "completedAt",
      "clients",
    ]) ||
    manifest.schema !==
      "clockchain.handshake-client-acceptance/v1" ||
    manifest.status !== "PASS" ||
    manifest.repositorySha !== expectedRepositorySha ||
    typeof manifest.promptSha256 !== "string" ||
    !HASH_PATTERN.test(manifest.promptSha256) ||
    !hasExactKeys(manifest.clients, CLIENT_NAMES) ||
    !bytes.equals(
      Buffer.from(
        `${JSON.stringify(manifest, null, 2)}\n`,
        "utf8",
      ),
    )
  ) {
    throw new LiveVerificationConfigurationError();
  }
  const promptSha256 = createHash("sha256")
    .update(
      await readTrustedFile(
        DEFAULT_PROMPT_FILE,
        MAX_PROMPT_BYTES,
      ),
    )
    .digest("hex");
  if (manifest.promptSha256 !== promptSha256) {
    throw new LiveVerificationConfigurationError();
  }

  const overallStarted =
    timestampMilliseconds(manifest.startedAt);
  const overallCompleted =
    timestampMilliseconds(manifest.completedAt);
  const times = {};
  for (const name of CLIENT_NAMES) {
    const client = manifest.clients[name];
    if (
      !hasExactKeys(client, [
        "status",
        "command",
        "cliVersion",
        "startedAt",
        "completedAt",
        "exitCode",
        "signal",
        "timedOut",
        "outputLimitExceeded",
        "errorCode",
        "evidence",
      ]) ||
      client.status !== "PASS" ||
      !commandMatches(name, client.command) ||
      !versionMatches(name, client.cliVersion) ||
      client.exitCode !== 0 ||
      client.signal !== null ||
      client.timedOut !== false ||
      client.outputLimitExceeded !== false ||
      client.errorCode !== null ||
      !hasExactKeys(client.evidence, ["json", "markdown"])
    ) {
      throw new LiveVerificationConfigurationError();
    }
    times[name] = {
      started: timestampMilliseconds(client.startedAt),
      completed: timestampMilliseconds(client.completedAt),
    };
    if (times[name].started > times[name].completed) {
      throw new LiveVerificationConfigurationError();
    }
    validateManifestEvidenceReference(
      client.evidence.json,
      join(directories[name], "result.json"),
    );
    validateManifestEvidenceReference(
      client.evidence.markdown,
      join(directories[name], "RESULT.md"),
    );
  }
  if (
    overallStarted > times.codex.started ||
    times.codex.completed > times.claude.started ||
    times.claude.completed > overallCompleted ||
    overallStarted > overallCompleted
  ) {
    throw new LiveVerificationConfigurationError();
  }
  return Object.freeze({ manifest, windows: times });
}

export async function loadAcceptanceArtifactForTesting({
  directory,
  evidence,
}) {
  if (!hasExactKeys(evidence, ["json", "markdown"])) {
    throw new LiveVerificationConfigurationError();
  }
  const activeDirectory = absolutePath(directory);
  const artifactScan = await scanArtifactDirectory(
    activeDirectory,
    [],
  );
  if (artifactScan.error) {
    throw artifactScan.error;
  }
  validateManifestEvidence(
    evidence.json,
    join(activeDirectory, "result.json"),
    artifactScan.files.get("result.json"),
  );
  validateManifestEvidence(
    evidence.markdown,
    join(activeDirectory, "RESULT.md"),
    artifactScan.files.get("RESULT.md"),
  );
  return Object.freeze({
    parse() {
      return loadLocalResult(
        activeDirectory,
        artifactScan,
        [],
      );
    },
  });
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

function assertOperatorIdentity(result, operator) {
  if (
    !addressesEqual(result.identity.owner, operator.address) ||
    result.identity.displayName !== operator.displayName
  ) {
    throw new LiveVerificationError(
      "OPERATOR_IDENTITY_MISMATCH",
    );
  }
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

function sameHash(left, right) {
  return (
    typeof left === "string" &&
    typeof right === "string" &&
    /^0x[0-9a-f]{64}$/i.test(left) &&
    /^0x[0-9a-f]{64}$/i.test(right) &&
    left.toLowerCase() === right.toLowerCase()
  );
}

function transactionIndex(value) {
  if (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= 0
  ) {
    return BigInt(value);
  }
  if (typeof value === "bigint" && value >= 0n) {
    return value;
  }
  throw new LiveVerificationError(
    "ERC8004_TRANSACTION_MISMATCH",
  );
}

function assertTransactionEnvelope({
  expectedHash,
  expectedNonce,
  minimumNonce,
  receipt,
  transaction,
  owner,
}) {
  const nonceMatches =
    expectedNonce === undefined
      ? Number.isSafeInteger(transaction?.nonce) &&
        Number.isSafeInteger(minimumNonce) &&
        transaction.nonce >= minimumNonce
      : transaction?.nonce === expectedNonce;
  if (
    !isPlainObject(transaction) ||
    !isPlainObject(receipt) ||
    !sameHash(transaction.hash, expectedHash) ||
    transaction.chainId !== CHAIN_ID ||
    !addressesEqual(transaction.from, owner) ||
    !addressesEqual(transaction.to, REGISTRY_ADDRESS) ||
    transaction.value !== 0n ||
    !nonceMatches ||
    typeof transaction.input !== "string" ||
    typeof transaction.blockNumber !== "bigint" ||
    receipt.status !== "success" ||
    !sameHash(receipt.transactionHash, expectedHash) ||
    receipt.blockNumber !== transaction.blockNumber ||
    !addressesEqual(receipt.from, owner) ||
    !addressesEqual(receipt.to, REGISTRY_ADDRESS) ||
    transactionIndex(receipt.transactionIndex) !==
      transactionIndex(transaction.transactionIndex) ||
    !Array.isArray(receipt.logs)
  ) {
    throw new LiveVerificationError(
      "ERC8004_TRANSACTION_MISMATCH",
    );
  }
}

function assertExactCalldata({
  args,
  functionName,
  input,
}) {
  try {
    const decoded = decodeFunctionData({
      abi: ERC8004_ABI,
      data: input,
    });
    const expected = encodeFunctionData({
      abi: ERC8004_ABI,
      functionName,
      args,
    });
    if (
      decoded.functionName !== functionName ||
      decoded.args.length !== args.length ||
      decoded.args.some(
        (value, index) => value !== args[index],
      ) ||
      input.toLowerCase() !== expected.toLowerCase()
    ) {
      throw new Error();
    }
  } catch {
    throw new LiveVerificationError(
      "ERC8004_TRANSACTION_MISMATCH",
    );
  }
}

async function verifyIdentityTransactions(publicClient, result) {
  const [
    registerTransaction,
    registerReceipt,
    metadataTransaction,
    metadataReceipt,
  ] = await Promise.all([
    publicClient.getTransaction({
      hash: result.identity.registerTx,
    }),
    publicClient.getTransactionReceipt({
      hash: result.identity.registerTx,
    }),
    publicClient.getTransaction({
      hash: result.identity.metadataTx,
    }),
    publicClient.getTransactionReceipt({
      hash: result.identity.metadataTx,
    }),
  ]);
  assertTransactionEnvelope({
    expectedHash: result.identity.registerTx,
    expectedNonce: 0,
    owner: result.identity.owner,
    receipt: registerReceipt,
    transaction: registerTransaction,
  });
  assertTransactionEnvelope({
    expectedHash: result.identity.metadataTx,
    minimumNonce: 1,
    owner: result.identity.owner,
    receipt: metadataReceipt,
    transaction: metadataTransaction,
  });

  const agentId = BigInt(result.identity.agentId);
  const initialUri = registrationDataUri(
    buildRegistrationDocument({
      displayName: result.identity.displayName,
      agentId: null,
    }),
  );
  const finalUri = registrationDataUri(
    buildRegistrationDocument({
      displayName: result.identity.displayName,
      agentId,
    }),
  );
  assertExactCalldata({
    args: [initialUri],
    functionName: "register",
    input: registerTransaction.input,
  });
  assertExactCalldata({
    args: [agentId, finalUri],
    functionName: "setAgentURI",
    input: metadataTransaction.input,
  });
  let registeredAgentId;
  try {
    registeredAgentId = parseRegisteredAgentId(
      registerReceipt,
      {
        expectedOwner: result.identity.owner,
        expectedAgentURI: initialUri,
      },
    );
  } catch {
    throw new LiveVerificationError(
      "ERC8004_TRANSACTION_MISMATCH",
    );
  }
  if (registeredAgentId.toString() !== result.identity.agentId) {
    throw new LiveVerificationError(
      "ERC8004_TRANSACTION_MISMATCH",
    );
  }

  const registerIndex = transactionIndex(
    registerTransaction.transactionIndex,
  );
  const metadataIndex = transactionIndex(
    metadataTransaction.transactionIndex,
  );
  if (
    metadataTransaction.blockNumber <
      registerTransaction.blockNumber ||
    (
      metadataTransaction.blockNumber ===
        registerTransaction.blockNumber &&
      metadataIndex <= registerIndex
    )
  ) {
    throw new LiveVerificationError(
      "ERC8004_TRANSACTION_MISMATCH",
    );
  }
  return {
    registerBlock: registerTransaction.blockNumber.toString(),
    metadataBlock: metadataTransaction.blockNumber.toString(),
    transactionOrderMatches: true,
  };
}

async function verifyClockchain(mcpClient, result) {
  const event = expectedReceiptEvent(result);
  const expectedHash = expectedReceiptHash(result);
  const identifiers = {
    ledgerId: result.clockchain.ledgerId,
    blockHeight: result.clockchain.blockHeight,
    hash: expectedHash,
  };
  const verification = await mcpClient.verifyCrossParty(
    identifiers,
  );
  assertCrossPartyVerification(verification, {
    ledgerId: result.clockchain.ledgerId,
    blockHeight: result.clockchain.blockHeight,
    anchoredHash: expectedHash,
  });
  const { onChain } = verification;
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

  const rehydrated = await mcpClient.completeAttestation({
    schema: "clockchain.receipt/v1",
    network: "testnet",
    status: "anchored",
    agentId: event.agentId,
    action: event.action,
    eventHash: expectedHash,
    hashType: "SHA-256",
    payload: {
      inputs: event.inputs,
      outputs: event.outputs,
    },
    anchor: {
      ledgerId: result.clockchain.ledgerId,
      assetReferenceId: onChain.assetReferenceId,
      blockHeight: result.clockchain.blockHeight,
      consensusTime: null,
      confirmed: true,
    },
    identity: {
      resolved: true,
      status: "active",
    },
  });
  const poolHealth = rehydrated?.poolHealth;
  if (
    !isPlainObject(rehydrated) ||
    rehydrated.schema !== "clockchain.receipt/v1" ||
    rehydrated.network !== "testnet" ||
    rehydrated.status !== result.clockchain.receiptStatus ||
    rehydrated.agentId !== event.agentId ||
    rehydrated.action !== event.action ||
    rehydrated.eventHash !== expectedHash ||
    rehydrated.hashType !== "SHA-256" ||
    !isDeepStrictEqual(rehydrated.payload, {
      inputs: event.inputs,
      outputs: event.outputs,
    }) ||
    rehydrated.anchor?.ledgerId !==
      result.clockchain.ledgerId ||
    rehydrated.anchor?.assetReferenceId !==
      onChain.assetReferenceId ||
    rehydrated.anchor?.blockHeight !==
      result.clockchain.blockHeight ||
    rehydrated.anchor?.consensusTime !==
      result.clockchain.consensusTime ||
    rehydrated.anchor?.confirmed !== true ||
    !isPlainObject(poolHealth) ||
    poolHealth.totalNodes !==
      result.clockchain.poolHealth.totalNodes ||
    poolHealth.nodeParticipationPct !==
      result.clockchain.poolHealth.nodeParticipationPct ||
    poolHealth.degraded !==
      result.clockchain.poolHealth.degradedAtSubmission
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
    consensusTimeMatches: true,
    poolHealthMatchesCurrentRead: true,
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
  expectedRepositorySha,
  manifestFile,
  now = () => new Date(),
  outputFile = DEFAULT_OUTPUT_FILE,
  publicClient = createPublicClient({
    chain: sepolia,
    transport: http(RPC_URL),
  }),
  randomUUID = defaultRandomUUID,
  readInvitation = readSecretInvitation,
  resultDirectories = DEFAULT_RESULT_DIRECTORIES,
  tokenIssuer = mintDemoToken,
} = {}) {
  if (
    !isPlainObject(resultDirectories) ||
    typeof clientFactory !== "function" ||
    typeof now !== "function" ||
    typeof randomUUID !== "function" ||
    typeof readInvitation !== "function" ||
    typeof tokenIssuer !== "function" ||
    !publicClient ||
    typeof publicClient.getChainId !== "function" ||
    typeof publicClient.getCode !== "function" ||
    typeof publicClient.getTransaction !== "function" ||
    typeof publicClient.getTransactionReceipt !== "function" ||
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
  const activeRepositorySha = normalizeRepositorySha(
    expectedRepositorySha,
  );
  const operatorData = await loadOperatorInvitations(
    canaryFiles,
    readInvitation,
  );
  const activeCanaries = normalizedCanaries([
    ...normalizedCanaries(canaries),
    ...operatorData.canaries,
  ]);
  const { manifest, windows } =
    await validateAcceptanceManifest({
      directories,
      expectedRepositorySha: activeRepositorySha,
      manifestFile,
    });
  const artifactScans = {};
  for (const name of CLIENT_NAMES) {
    try {
      artifactScans[name] = await scanArtifactDirectory(
        directories[name],
        activeCanaries,
      );
    } catch (error) {
      artifactScans[name] = Object.freeze({
        error,
        files: new Map(),
      });
    }
  }
  for (const name of CLIENT_NAMES) {
    validateManifestEvidence(
      manifest.clients[name].evidence.json,
      join(directories[name], "result.json"),
      artifactScans[name].files.get("result.json"),
    );
    validateManifestEvidence(
      manifest.clients[name].evidence.markdown,
      join(directories[name], "RESULT.md"),
      artifactScans[name].files.get("RESULT.md"),
    );
  }
  const localResults = {};
  const clients = {};

  for (const name of CLIENT_NAMES) {
    try {
      const localResult = loadLocalResult(
        directories[name],
        artifactScans[name],
        activeCanaries,
      );
      assertResultWithinRunWindow(
        localResult.result,
        windows[name],
      );
      assertOperatorIdentity(
        localResult.result,
        operatorData.invitations[name],
      );
      localResults[name] = localResult;
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
        typeof mcpClient.verifyCrossParty !== "function" ||
        typeof mcpClient.completeAttestation !== "function"
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
        identityTransactions:
          await verifyIdentityTransactions(publicClient, result),
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
    resultFiles: [],
    outputFile: DEFAULT_OUTPUT_FILE,
    canaryFiles: [],
    expectedRepositorySha: undefined,
    manifestFile: undefined,
  };
  for (let index = 0; index < argv.length;) {
    const option = argv[index];
    if (option === "--output") {
      const value = argv[index + 1];
      if (value === undefined) {
        throw new LiveVerificationConfigurationError();
      }
      values.outputFile = resolve(value);
      index += 2;
    } else if (option === "--canary-file") {
      const value = argv[index + 1];
      if (value === undefined) {
        throw new LiveVerificationConfigurationError();
      }
      values.canaryFiles.push(resolve(value));
      index += 2;
    } else if (option === "--manifest") {
      const value = argv[index + 1];
      if (value === undefined) {
        throw new LiveVerificationConfigurationError();
      }
      values.manifestFile = resolve(value);
      index += 2;
    } else if (option === "--repo-sha") {
      const value = argv[index + 1];
      if (value === undefined) {
        throw new LiveVerificationConfigurationError();
      }
      values.expectedRepositorySha =
        normalizeRepositorySha(value);
      index += 2;
    } else if (
      typeof option === "string" &&
      !option.startsWith("--")
    ) {
      values.resultFiles.push(resolve(option));
      index += 1;
    } else {
      throw new LiveVerificationConfigurationError();
    }
  }
  if (
    values.resultFiles.length !== 2 ||
    values.resultFiles.some(
      (path) => basename(path) !== "result.json",
    ) ||
    values.manifestFile === undefined ||
    values.expectedRepositorySha === undefined ||
    ![0, 2].includes(values.canaryFiles.length)
  ) {
    throw new LiveVerificationConfigurationError();
  }
  if (values.canaryFiles.length === 0) {
    values.canaryFiles = [
      join(
        REPOSITORY_DIRECTORY,
        ".context",
        "invitations",
        "codex.secret.json",
      ),
      join(
        REPOSITORY_DIRECTORY,
        ".context",
        "invitations",
        "claude.secret.json",
      ),
    ];
  }
  values.resultDirectories = {
    codex: dirname(values.resultFiles[0]),
    claude: dirname(values.resultFiles[1]),
  };
  delete values.resultFiles;
  return values;
}

export async function main({
  argv = process.argv.slice(2),
  stderr = process.stderr,
  stdout = process.stdout,
  verify = verifyLiveResults,
} = {}) {
  try {
    const options = parseArguments(argv);
    const verdict = await verify(options);
    stdout.write(
      `${verdict.status} ${options.outputFile}\n`,
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
