import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { constants as fileSystemConstants } from "node:fs";
import {
  access,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readdir,
  realpath,
  rename,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import {
  delimiter,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";
import { fileURLToPath } from "node:url";

import {
  renderResultMarkdown,
  validatePassResult,
} from "../src/evidence.mjs";
import { readSecretInvitation } from "../src/invitation.mjs";
import {
  assertSecretFree,
  redact,
} from "../src/redact.mjs";

const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_DIRECTORY = resolve(SCRIPT_DIRECTORY, "..");
const DEFAULT_PROMPT_FILE = join(
  REPOSITORY_DIRECTORY,
  "prompts",
  "run-turnkey-demo.md",
);
const DEFAULT_OUTPUT_ROOT = join(
  REPOSITORY_DIRECTORY,
  "artifacts",
);
const DEFAULT_TIMEOUT_MS = 15 * 60 * 1_000;
const DEFAULT_TERMINATION_GRACE_MS = 2_000;
const DEFAULT_MAX_OUTPUT_BYTES = 2 * 1_024 * 1_024;
const DEFAULT_MAX_PROMPT_BYTES = 256 * 1_024;
const PROCESS_GROUP_CONFIRMATION_TIMEOUT_MS = 1_000;
const PROCESS_GROUP_POLL_INTERVAL_MS = 10;
const MAX_DISCOVERY_ENTRIES = 20_000;
const MAX_DISCOVERY_DEPTH = 16;
const MAX_EVIDENCE_BYTES = 2 * 1_024 * 1_024;
const OPERATOR_RISK_ACKNOWLEDGEMENT_FLAG =
  "--acknowledge-agent-permission-risk";
const OPERATOR_RISK_WARNING =
  `Clean-client acceptance is operator-only: it disables client permission safeguards, inherits selected local credentials, HOME, and invitation access, and is not an OS or container sandbox. Re-run only with ${OPERATOR_RISK_ACKNOWLEDGEMENT_FLAG}.\n`;
const COMMIT_REF_PATTERN = /^[0-9a-f]{40}$/i;
const PRIVATE_KEY_SHAPE = /0x[0-9a-f]{64}(?![0-9a-f])/i;
const PRIVATE_KEY_SHAPE_GLOBAL =
  /0x[0-9a-f]{64}(?![0-9a-f])/gi;
const ALLOWED_TRANSACTION_HASH_PATHS = new Set([
  "identity.registerTx",
  "identity.metadataTx",
]);
const CLIENT_NAMES = Object.freeze(["codex", "claude"]);
const COMMON_ENVIRONMENT_KEYS = Object.freeze([
  "PATH",
  "HOME",
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "TERM",
  "COLORTERM",
  "NO_COLOR",
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "NO_PROXY",
  "ALL_PROXY",
  "SSL_CERT_FILE",
  "SSL_CERT_DIR",
  "NODE_EXTRA_CA_CERTS",
]);
const CLIENT_CREDENTIAL_KEYS = Object.freeze({
  codex: Object.freeze([
    "CODEX_HOME",
    "OPENAI_API_KEY",
    "OPENAI_ORG_ID",
    "OPENAI_ORGANIZATION",
    "OPENAI_PROJECT_ID",
  ]),
  claude: Object.freeze([
    "CLAUDE_CONFIG_DIR",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "CLAUDE_CODE_OAUTH_TOKEN",
  ]),
});

export const DEFAULT_CLIENT_COMMANDS = Object.freeze({
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
    versionArgs: Object.freeze(["--version"]),
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
    versionArgs: Object.freeze(["--version"]),
  }),
});

class HarnessConfigurationError extends Error {
  constructor() {
    super("Clean-client acceptance configuration is invalid.");
    this.name = "HarnessConfigurationError";
    this.code = "HARNESS_CONFIGURATION";
  }
}

class MissingRiskAcknowledgementError
  extends HarnessConfigurationError {
  constructor() {
    super();
    this.name = "MissingRiskAcknowledgementError";
  }
}

class UnsupportedAcceptancePlatformError
  extends HarnessConfigurationError {
  constructor() {
    super();
    this.name = "UnsupportedAcceptancePlatformError";
    this.code = "HARNESS_UNSUPPORTED_PLATFORM";
  }
}

function assertAcceptanceHarnessPlatform(platform) {
  if (platform !== "darwin" && platform !== "linux") {
    throw new UnsupportedAcceptancePlatformError();
  }
}

export function assertAcceptanceHarnessPlatformForTesting(
  platform,
) {
  assertAcceptanceHarnessPlatform(platform);
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object") {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function boundedInteger(value, {
  maximum = Number.MAX_SAFE_INTEGER,
  minimum = 1,
} = {}) {
  if (
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    throw new HarnessConfigurationError();
  }
  return value;
}

function nonemptyString(value, maximum = 4_096) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximum ||
    value.trim() !== value ||
    /[\u0000-\u001f\u007f-\u009f]/.test(value)
  ) {
    throw new HarnessConfigurationError();
  }
  return value;
}

function absolutePath(value) {
  const path = nonemptyString(value);
  if (!isAbsolute(path)) {
    throw new HarnessConfigurationError();
  }
  return resolve(path);
}

function commandSpec(value) {
  if (
    !isPlainObject(value) ||
    !Array.isArray(value.args) ||
    !Array.isArray(value.versionArgs) ||
    value.args.some((entry) => typeof entry !== "string") ||
    value.versionArgs.some((entry) => typeof entry !== "string")
  ) {
    throw new HarnessConfigurationError();
  }
  return {
    executable: nonemptyString(value.executable),
    args: [...value.args],
    versionArgs: [...value.versionArgs],
  };
}

function normalizeCommands(commands) {
  if (!isPlainObject(commands)) {
    throw new HarnessConfigurationError();
  }
  return Object.fromEntries(
    CLIENT_NAMES.map((name) => [
      name,
      commandSpec(commands[name]),
    ]),
  );
}

function environmentValue(source, key) {
  const value = source[key];
  return typeof value === "string" && value.length > 0
    ? value
    : undefined;
}

function normalizeRepositoryRef(value) {
  if (
    typeof value !== "string" ||
    !COMMIT_REF_PATTERN.test(value)
  ) {
    throw new HarnessConfigurationError();
  }
  return value.toLowerCase();
}

export function buildClientEnvironment({
  baseEnvironment,
  clientName,
  invitationFile,
  repositoryRef,
  temporaryDirectory,
}) {
  if (
    baseEnvironment === null ||
    typeof baseEnvironment !== "object" ||
    Array.isArray(baseEnvironment) ||
    !CLIENT_NAMES.includes(clientName)
  ) {
    throw new HarnessConfigurationError();
  }

  const environment = {};
  for (const key of COMMON_ENVIRONMENT_KEYS) {
    const value = environmentValue(baseEnvironment, key);
    if (value !== undefined) {
      environment[key] = value;
    }
  }
  for (const key of CLIENT_CREDENTIAL_KEYS[clientName]) {
    const value = environmentValue(baseEnvironment, key);
    if (value !== undefined) {
      environment[key] = value;
    }
  }

  if (
    environmentValue(baseEnvironment, "PATH") === undefined ||
    environmentValue(baseEnvironment, "HOME") === undefined
  ) {
    throw new HarnessConfigurationError();
  }
  environment.TMPDIR = absolutePath(temporaryDirectory);
  environment.HANDSHAKE_INVITE_FILE =
    absolutePath(invitationFile);
  const commitRef = normalizeRepositoryRef(repositoryRef);
  environment.HANDSHAKE_REPO_REF = commitRef;
  return environment;
}

function invitationCanaries(invitation) {
  const code = invitation?.code;
  const ciphertext = invitation?.bundle?.crypto?.ciphertext;
  if (
    typeof code !== "string" ||
    code.length === 0 ||
    code.length > 16_384 ||
    typeof ciphertext !== "string" ||
    ciphertext.length === 0 ||
    ciphertext.length > 16_384
  ) {
    throw new HarnessConfigurationError();
  }
  return [code, ciphertext];
}

function secretEnvironmentCanaries(
  environment,
  clientName,
  derivedInvitationCanaries,
) {
  return [
    environment.HANDSHAKE_INVITE_FILE,
    ...derivedInvitationCanaries,
    ...CLIENT_CREDENTIAL_KEYS[clientName]
      .map((key) => environment[key])
      .filter((value) => typeof value === "string"),
    ...[
      "HTTP_PROXY",
      "HTTPS_PROXY",
      "ALL_PROXY",
      "NODE_EXTRA_CA_CERTS",
    ]
      .map((key) => environment[key])
      .filter((value) => typeof value === "string"),
  ];
}

function sanitizeLog(value, canaries) {
  let clean = redact(
    typeof value === "string" ? value : "",
    canaries,
  );
  clean = clean.replace(
    PRIVATE_KEY_SHAPE_GLOBAL,
    "[REDACTED]",
  );
  clean = clean.replace(
    /("(?:[^"\\]|\\.)*(?:private.?key|secret|token|authorization|invite.?code|ciphertext)(?:[^"\\]|\\.)*"\s*:\s*)("(?:[^"\\]|\\.)*"|[^,\s}\]]+)/gi,
    "$1\"[REDACTED]\"",
  );
  clean = clean.replace(
    /(\b(?:invitation|invite)[\s_-]?code\b\s*(?:(?:is)\s+|[:=]\s*)?)([^\s,;]+)/gi,
    "$1[REDACTED]",
  );
  try {
    assertSecretFree(clean, canaries);
    return clean;
  } catch {
    return "[REDACTED UNSAFE CLIENT OUTPUT]\n";
  }
}

function assertNoPrivateKeyShapedEvidence(value, path = []) {
  if (typeof value === "string") {
    if (
      PRIVATE_KEY_SHAPE.test(value) &&
      !ALLOWED_TRANSACTION_HASH_PATHS.has(path.join("."))
    ) {
      throw new Error(
        "Evidence contains private-key-shaped material.",
      );
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((entry, index) =>
      assertNoPrivateKeyShapedEvidence(entry, [
        ...path,
        String(index),
      ]));
    return;
  }
  if (value !== null && typeof value === "object") {
    for (const [key, entry] of Object.entries(value)) {
      assertNoPrivateKeyShapedEvidence(entry, [...path, key]);
    }
  }
}

function terminateProcessGroup(child, signal) {
  if (!child || !Number.isSafeInteger(child.pid) || child.pid <= 0) {
    return;
  }
  try {
    if (process.platform === "win32") {
      child.kill(signal);
    } else {
      process.kill(-child.pid, signal);
    }
  } catch (error) {
    if (error?.code !== "ESRCH") {
      try {
        child.kill(signal);
      } catch {
        // A concurrently exited process needs no further termination.
      }
    }
  }
}

function processGroupExists(child) {
  if (
    process.platform === "win32" ||
    !child ||
    !Number.isSafeInteger(child.pid) ||
    child.pid <= 0
  ) {
    return false;
  }
  try {
    process.kill(-child.pid, 0);
    return true;
  } catch (error) {
    return error?.code !== "ESRCH";
  }
}

function waitForCleanupPoll(milliseconds) {
  return new Promise((resolvePoll) => {
    setTimeout(resolvePoll, milliseconds);
  });
}

async function confirmProcessGroupAbsent(child) {
  const deadline =
    Date.now() + PROCESS_GROUP_CONFIRMATION_TIMEOUT_MS;
  while (processGroupExists(child)) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      return false;
    }
    await waitForCleanupPoll(
      Math.min(PROCESS_GROUP_POLL_INTERVAL_MS, remaining),
    );
  }
  return true;
}

async function runProcess({
  args,
  cwd,
  environment,
  executable,
  input,
  maxOutputBytes,
  spawnImpl,
  terminationGraceMs,
  timeoutMs,
}) {
  return new Promise((resolveProcess) => {
    let child;
    try {
      child = spawnImpl(executable, args, {
        cwd,
        detached: process.platform !== "win32",
        env: environment,
        shell: false,
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch {
      resolveProcess({
        cleanupFailed: false,
        exitCode: null,
        outputLimitExceeded: false,
        signal: null,
        spawnFailed: true,
        stderr: Buffer.alloc(0),
        stdout: Buffer.alloc(0),
        timedOut: false,
      });
      return;
    }

    const stdout = [];
    const stderr = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let settled = false;
    let timedOut = false;
    let outputLimitExceeded = false;
    let spawnFailed = false;
    let terminationStarted = false;
    let cleanupCompleted = false;
    let cleanupFailed = false;
    let exitResult;
    let closeResult;

    const finalize = () => {
      if (
        settled ||
        (!cleanupFailed && closeResult === undefined) ||
        (terminationStarted && !cleanupCompleted)
      ) {
        return;
      }
      const processResult = closeResult ??
        exitResult ??
        { exitCode: null, signal: null };
      settled = true;
      resolveProcess({
        cleanupFailed,
        exitCode: processResult.exitCode,
        outputLimitExceeded,
        signal: processResult.signal,
        spawnFailed,
        stderr: Buffer.concat(stderr),
        stdout: Buffer.concat(stdout),
        timedOut,
      });
    };

    const finishCleanup = async () => {
      if (processGroupExists(child)) {
        terminateProcessGroup(child, "SIGKILL");
      }
      cleanupFailed = !(await confirmProcessGroupAbsent(child));
      cleanupCompleted = true;
      if (cleanupFailed) {
        child.stdin?.destroy();
        child.stdout?.destroy();
        child.stderr?.destroy();
        child.unref?.();
      }
      finalize();
    };

    const terminate = (reason = null) => {
      if (settled || terminationStarted) {
        return;
      }
      terminationStarted = true;
      if (reason === "timeout") {
        timedOut = true;
      } else if (reason === "output") {
        outputLimitExceeded = true;
      }
      terminateProcessGroup(child, "SIGTERM");
      setTimeout(() => {
        void finishCleanup();
      }, terminationGraceMs);
    };

    const capture = (chunks, chunk, stream) => {
      const buffer = Buffer.isBuffer(chunk)
        ? chunk
        : Buffer.from(chunk);
      if (stream === "stdout") {
        stdoutBytes += buffer.length;
        if (stdoutBytes <= maxOutputBytes) {
          chunks.push(buffer);
        } else {
          terminate("output");
        }
      } else {
        stderrBytes += buffer.length;
        if (stderrBytes <= maxOutputBytes) {
          chunks.push(buffer);
        } else {
          terminate("output");
        }
      }
    };

    child.stdout?.on("data", (chunk) =>
      capture(stdout, chunk, "stdout"));
    child.stderr?.on("data", (chunk) =>
      capture(stderr, chunk, "stderr"));
    child.on("error", () => {
      spawnFailed = true;
    });
    child.stdin?.on("error", () => {
      // EPIPE is expected when a child rejects input and exits early.
    });

    const timeout = setTimeout(() => {
      terminate("timeout");
    }, timeoutMs);
    timeout.unref?.();

    child.once("exit", (exitCode, signal) => {
      clearTimeout(timeout);
      exitResult = { exitCode, signal };
      if (!terminationStarted && processGroupExists(child)) {
        terminate();
      }
      finalize();
    });

    child.once("close", (exitCode, signal) => {
      clearTimeout(timeout);
      closeResult = { exitCode, signal };
      if (!terminationStarted && processGroupExists(child)) {
        terminate();
      }
      finalize();
    });

    child.stdin?.end(input);
  });
}

const BOUNDED_READ_FLAGS =
  fileSystemConstants.O_RDONLY |
  fileSystemConstants.O_NOFOLLOW |
  fileSystemConstants.O_NONBLOCK;

export const BOUNDED_READ_FLAGS_FOR_TESTING =
  BOUNDED_READ_FLAGS;

function unchangedFile(before, after) {
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
    before.mtimeMs === after.mtimeMs &&
    before.ctimeMs === after.ctimeMs
  );
}

async function readBoundedFile(path, maximum, afterRead) {
  let bytes;
  let failure;
  let handle;
  try {
    handle = await open(path, BOUNDED_READ_FLAGS);
    const before = await handle.stat();
    if (
      !before.isFile() ||
      before.size < 1 ||
      before.size > maximum
    ) {
      throw new Error("File boundary rejected.");
    }
    bytes = await handle.readFile();
    await afterRead?.();
    const after = await handle.stat();
    if (
      !unchangedFile(before, after) ||
      bytes.length !== before.size
    ) {
      throw new Error("File boundary rejected.");
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
    throw failure;
  }
  return bytes;
}

export async function readBoundedFileForTesting(
  path,
  maximum,
  { afterRead } = {},
) {
  if (
    afterRead !== undefined &&
    typeof afterRead !== "function"
  ) {
    throw new HarnessConfigurationError();
  }
  return readBoundedFile(path, maximum, afterRead);
}

function isWithin(root, candidate) {
  const path = relative(root, candidate);
  return (
    path === "" ||
    (!path.startsWith(`..${sep}`) && path !== ".." && !isAbsolute(path))
  );
}

async function resolveExecutableFromPath(executable, searchPath) {
  for (const directory of searchPath.split(delimiter)) {
    if (!isAbsolute(directory)) {
      continue;
    }
    const candidate = join(directory, executable);
    try {
      await access(candidate, fileSystemConstants.X_OK);
      const canonical = await realpath(candidate);
      const stat = await lstat(canonical);
      if (stat.isFile() && !stat.isSymbolicLink()) {
        return canonical;
      }
    } catch {
      // Continue through the inherited PATH.
    }
  }
  throw new HarnessConfigurationError();
}

function shellSingleQuote(value) {
  return `'${value.replaceAll("'", "'\"'\"'")}'`;
}

async function writeMktempShim({
  directory,
  systemMktemp,
  temporaryDirectory,
}) {
  const path = join(directory, "mktemp");
  const executable = shellSingleQuote(systemMktemp);
  const template = shellSingleQuote(
    join(
      temporaryDirectory,
      "clockchain-handshake.XXXXXXXXXX",
    ),
  );
  await writeFile(
    path,
    `#!/bin/sh
if [ "$#" -eq 1 ] && [ "$1" = "-d" ]; then
  exec ${executable} -d ${template}
fi
exec ${executable} "$@"
`,
    { flag: "wx", mode: 0o700 },
  );
  return path;
}

async function discoverEvidence(root) {
  const canonicalRoot = await realpath(root);
  const queue = [{ directory: canonicalRoot, depth: 0 }];
  const pairs = [];
  let entriesSeen = 0;

  while (queue.length > 0) {
    const { directory, depth } = queue.shift();
    const entries = await readdir(directory, {
      withFileTypes: true,
    });
    entriesSeen += entries.length;
    if (entriesSeen > MAX_DISCOVERY_ENTRIES) {
      throw new Error("Evidence discovery boundary exceeded.");
    }

    const names = new Set(entries.map(({ name }) => name));
    if (names.has("result.json") && names.has("RESULT.md")) {
      pairs.push({
        json: join(directory, "result.json"),
        markdown: join(directory, "RESULT.md"),
      });
    }

    if (depth >= MAX_DISCOVERY_DEPTH) {
      continue;
    }
    for (const entry of entries) {
      if (!entry.isDirectory() || entry.isSymbolicLink()) {
        continue;
      }
      const child = await realpath(join(directory, entry.name));
      if (!isWithin(canonicalRoot, child)) {
        throw new Error("Evidence path escaped the client directory.");
      }
      queue.push({ directory: child, depth: depth + 1 });
    }
  }

  if (pairs.length !== 1) {
    throw new Error("Expected exactly one evidence pair.");
  }
  return pairs[0];
}

async function publishEvidence({
  artifactDirectory,
  canaries,
  clientRoot,
}) {
  const pair = await discoverEvidence(clientRoot);
  const jsonBytes = await readBoundedFile(
    pair.json,
    MAX_EVIDENCE_BYTES,
  );
  const markdownBytes = await readBoundedFile(
    pair.markdown,
    MAX_EVIDENCE_BYTES,
  );
  for (const bytes of [jsonBytes, markdownBytes]) {
    for (const canary of canaries) {
      if (bytes.includes(Buffer.from(canary, "utf8"))) {
        throw new Error("Raw evidence contains secret material.");
      }
    }
  }
  let result;
  try {
    result = JSON.parse(jsonBytes.toString("utf8"));
  } catch {
    throw new Error("Result JSON is invalid.");
  }
  validatePassResult(result);
  assertNoPrivateKeyShapedEvidence(result);
  assertSecretFree(result, canaries);
  const canonicalJsonBytes = Buffer.from(
    `${JSON.stringify(result, null, 2)}\n`,
    "utf8",
  );
  const canonicalMarkdownBytes = Buffer.from(
    renderResultMarkdown(result),
    "utf8",
  );
  if (!markdownBytes.equals(canonicalMarkdownBytes)) {
    throw new Error("Result Markdown does not match result JSON.");
  }
  assertSecretFree(
    canonicalMarkdownBytes.toString("utf8"),
    canaries,
  );

  const jsonPath = join(artifactDirectory, "result.json");
  const markdownPath = join(artifactDirectory, "RESULT.md");
  const jsonTemporary = `${jsonPath}.tmp-${process.pid}`;
  const markdownTemporary = `${markdownPath}.tmp-${process.pid}`;
  await writeFile(jsonTemporary, canonicalJsonBytes, {
    flag: "wx",
    mode: 0o600,
  });
  await writeFile(markdownTemporary, canonicalMarkdownBytes, {
    flag: "wx",
    mode: 0o600,
  });
  await rename(jsonTemporary, jsonPath);
  await rename(markdownTemporary, markdownPath);
  return {
    paths: { json: jsonPath, markdown: markdownPath },
    evidence: {
      json: {
        path: jsonPath,
        sha256: createHash("sha256")
          .update(canonicalJsonBytes)
          .digest("hex"),
      },
      markdown: {
        path: markdownPath,
        sha256: createHash("sha256")
          .update(canonicalMarkdownBytes)
          .digest("hex"),
      },
    },
  };
}

async function writeLog(path, value, canaries) {
  const clean = sanitizeLog(value, canaries);
  await writeFile(path, clean, {
    flag: "wx",
    mode: 0o600,
  });
  return path;
}

function publicFailureCode(processResult) {
  if (processResult.cleanupFailed) {
    return "CLIENT_PROCESS_GROUP_CLEANUP_FAILED";
  }
  if (processResult.spawnFailed) {
    return "CLIENT_SPAWN_FAILED";
  }
  if (processResult.timedOut) {
    return "CLIENT_TIMEOUT";
  }
  if (processResult.outputLimitExceeded) {
    return "CLIENT_OUTPUT_LIMIT";
  }
  if (processResult.exitCode !== 0) {
    return "CLIENT_NONZERO_EXIT";
  }
  return "CLIENT_EVIDENCE_INVALID";
}

async function runOneClient({
  artifactDirectory,
  baseEnvironment,
  baseTemporaryDirectory,
  clientName,
  command,
  invitationFile,
  derivedInvitationCanaries,
  maxOutputBytes,
  now,
  prompt,
  repositoryRef,
  spawnImpl,
  terminationGraceMs,
  timeoutMs,
}) {
  const clientRoot = await mkdtemp(
    join(baseTemporaryDirectory, `clockchain-handshake-${clientName}-`),
  );
  const workDirectory = join(clientRoot, "work");
  const temporaryDirectory = join(clientRoot, "tmp");
  const commandDirectory = join(clientRoot, "bin");
  await mkdir(workDirectory, { mode: 0o700 });
  await mkdir(temporaryDirectory, { mode: 0o700 });
  await mkdir(commandDirectory, { mode: 0o700 });
  const environment = buildClientEnvironment({
    baseEnvironment,
    clientName,
    invitationFile,
    repositoryRef,
    temporaryDirectory,
  });
  const systemMktemp = await resolveExecutableFromPath(
    "mktemp",
    environment.PATH,
  );
  await writeMktempShim({
    directory: commandDirectory,
    systemMktemp,
    temporaryDirectory,
  });
  environment.PATH = [
    commandDirectory,
    environment.PATH,
  ].join(delimiter);
  const canaries = secretEnvironmentCanaries(
    environment,
    clientName,
    derivedInvitationCanaries,
  );
  const startedAt = now().toISOString();
  const versionResult = await runProcess({
    args: command.versionArgs,
    cwd: workDirectory,
    environment,
    executable: command.executable,
    input: Buffer.alloc(0),
    maxOutputBytes,
    spawnImpl,
    terminationGraceMs,
    timeoutMs: Math.min(timeoutMs, 30_000),
  });
  const versionText = sanitizeLog(
    versionResult.stdout.toString("utf8"),
    canaries,
  )
    .split(/\r?\n/, 1)[0]
    .trim()
    .slice(0, 256);

  let processResult = versionResult;
  if (
    !versionResult.spawnFailed &&
    !versionResult.cleanupFailed &&
    !versionResult.timedOut &&
    !versionResult.outputLimitExceeded &&
    versionResult.exitCode === 0 &&
    versionText.length > 0
  ) {
    processResult = await runProcess({
      args: command.args,
      cwd: workDirectory,
      environment,
      executable: command.executable,
      input: prompt,
      maxOutputBytes,
      spawnImpl,
      terminationGraceMs,
      timeoutMs,
    });
  }

  const stdoutLog = await writeLog(
    join(artifactDirectory, "stdout.log"),
    processResult.stdout.toString("utf8"),
    canaries,
  );
  const stderrLog = await writeLog(
    join(artifactDirectory, "stderr.log"),
    processResult.stderr.toString("utf8"),
    canaries,
  );
  let resultPaths = null;
  let evidence = null;
  let status = "FAIL";
  let errorCode = publicFailureCode(processResult);
  if (
    !processResult.spawnFailed &&
    !processResult.cleanupFailed &&
    !processResult.timedOut &&
    !processResult.outputLimitExceeded &&
    processResult.exitCode === 0
  ) {
    try {
      const published = await publishEvidence({
        artifactDirectory,
        canaries,
        clientRoot,
      });
      resultPaths = published.paths;
      evidence = published.evidence;
      status = "PASS";
      errorCode = null;
    } catch {
      errorCode = "CLIENT_EVIDENCE_INVALID";
    }
  }

  return {
    status,
    command: {
      executable: command.executable,
      args: [...command.args],
    },
    cliVersion: versionText || null,
    startedAt,
    completedAt: now().toISOString(),
    exitCode: processResult.exitCode,
    signal: processResult.signal,
    timedOut: processResult.timedOut,
    outputLimitExceeded: processResult.outputLimitExceeded,
    errorCode,
    evidence,
    workDirectory,
    resultPaths,
    stdoutLog,
    stderrLog,
  };
}

function skippedClient(command, now) {
  const timestamp = now().toISOString();
  return {
    status: "FAIL",
    command: {
      executable: command.executable,
      args: [...command.args],
    },
    cliVersion: null,
    startedAt: timestamp,
    completedAt: timestamp,
    exitCode: null,
    signal: null,
    timedOut: false,
    outputLimitExceeded: false,
    errorCode: "CLIENT_SKIPPED_AFTER_CLEANUP_FAILURE",
    evidence: null,
    workDirectory: null,
    resultPaths: null,
    stdoutLog: null,
    stderrLog: null,
  };
}

function mergeCommands(overrides) {
  if (overrides === undefined) {
    return normalizeCommands(DEFAULT_CLIENT_COMMANDS);
  }
  if (!isPlainObject(overrides)) {
    throw new HarnessConfigurationError();
  }
  return normalizeCommands({
    codex: overrides.codex ?? DEFAULT_CLIENT_COMMANDS.codex,
    claude: overrides.claude ?? DEFAULT_CLIENT_COMMANDS.claude,
  });
}

async function writeManifest(outputRoot, manifest) {
  const path = join(outputRoot, "client-acceptance.json");
  const temporary = `${path}.tmp-${process.pid}`;
  await writeFile(
    temporary,
    `${JSON.stringify(manifest, null, 2)}\n`,
    { flag: "wx", mode: 0o600 },
  );
  await rename(temporary, path);
  return path;
}

export async function runCleanClients({
  baseEnvironment = process.env,
  baseTemporaryDirectory =
    environmentValue(baseEnvironment, "TMPDIR") ?? tmpdir(),
  commands,
  invitations,
  maxOutputBytes = DEFAULT_MAX_OUTPUT_BYTES,
  now = () => new Date(),
  operatorRiskAcknowledged,
  outputRoot = DEFAULT_OUTPUT_ROOT,
  promptFile = DEFAULT_PROMPT_FILE,
  readInvitation = readSecretInvitation,
  repositoryRef,
  spawnImpl = spawn,
  terminationGraceMs = DEFAULT_TERMINATION_GRACE_MS,
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  assertAcceptanceHarnessPlatform(process.platform);
  if (operatorRiskAcknowledged !== true) {
    throw new HarnessConfigurationError();
  }
  if (
    !isPlainObject(invitations) ||
    typeof now !== "function" ||
    typeof readInvitation !== "function" ||
    typeof spawnImpl !== "function"
  ) {
    throw new HarnessConfigurationError();
  }
  const activeCommands = mergeCommands(commands);
  if (
    activeCommands.codex.executable ===
      activeCommands.claude.executable
  ) {
    throw new HarnessConfigurationError();
  }
  const activeOutputRoot = absolutePath(outputRoot);
  const activePromptFile = absolutePath(promptFile);
  const activeTemporaryDirectory =
    absolutePath(baseTemporaryDirectory);
  const activeInvitations = Object.fromEntries(
    CLIENT_NAMES.map((name) => [
      name,
      absolutePath(invitations[name]),
    ]),
  );
  if (
    activeInvitations.codex === activeInvitations.claude
  ) {
    throw new HarnessConfigurationError();
  }
  const activeRepositoryRef =
    normalizeRepositoryRef(repositoryRef);
  boundedInteger(timeoutMs, { maximum: 60 * 60 * 1_000 });
  boundedInteger(terminationGraceMs, { maximum: 30_000 });
  boundedInteger(maxOutputBytes, {
    maximum: 16 * 1_024 * 1_024,
  });

  const prompt = await readBoundedFile(
    activePromptFile,
    DEFAULT_MAX_PROMPT_BYTES,
  );
  const promptSha256 = createHash("sha256")
    .update(prompt)
    .digest("hex");
  const derivedCanaries = {};
  for (const name of CLIENT_NAMES) {
    derivedCanaries[name] = invitationCanaries(
      await readInvitation(activeInvitations[name]),
    );
  }
  await mkdir(activeOutputRoot, {
    mode: 0o700,
    recursive: true,
  });
  const artifactDirectories = {};
  for (const name of CLIENT_NAMES) {
    const directory = join(activeOutputRoot, name);
    await mkdir(directory, { mode: 0o700 });
    artifactDirectories[name] = directory;
  }

  const startedAt = now().toISOString();
  const clients = {};
  let cleanupFailed = false;
  for (const name of CLIENT_NAMES) {
    clients[name] = cleanupFailed
      ? skippedClient(activeCommands[name], now)
      : await runOneClient({
          artifactDirectory: artifactDirectories[name],
          baseEnvironment,
          baseTemporaryDirectory: activeTemporaryDirectory,
          clientName: name,
          command: activeCommands[name],
          derivedInvitationCanaries: derivedCanaries[name],
          invitationFile: activeInvitations[name],
          maxOutputBytes,
          now,
          prompt,
          repositoryRef: activeRepositoryRef,
          spawnImpl,
          terminationGraceMs,
          timeoutMs,
        });
    cleanupFailed ||= clients[name].errorCode ===
      "CLIENT_PROCESS_GROUP_CLEANUP_FAILED";
  }
  const status = CLIENT_NAMES.every(
    (name) => clients[name].status === "PASS",
  )
    ? "PASS"
    : "FAIL";
  const manifestClients = Object.fromEntries(
    CLIENT_NAMES.map((name) => {
      const client = clients[name];
      return [
        name,
        {
          status: client.status,
          command: client.command,
          cliVersion: client.cliVersion,
          startedAt: client.startedAt,
          completedAt: client.completedAt,
          exitCode: client.exitCode,
          signal: client.signal,
          timedOut: client.timedOut,
          outputLimitExceeded:
            client.outputLimitExceeded,
          errorCode: client.errorCode,
          evidence: client.evidence,
        },
      ];
    }),
  );
  const manifest = {
    schema: "clockchain.handshake-client-acceptance/v1",
    status,
    repositorySha: activeRepositoryRef,
    promptSha256,
    startedAt,
    completedAt: now().toISOString(),
    clients: manifestClients,
  };
  assertSecretFree(manifest, [
    ...derivedCanaries.codex,
    ...derivedCanaries.claude,
  ]);
  const manifestPath = await writeManifest(
    activeOutputRoot,
    manifest,
  );
  return {
    ...manifest,
    clients,
    manifestPath,
  };
}

function parseArguments(argv, environment) {
  let riskAcknowledged = false;
  const seenOptions = new Set();
  const values = {
    codexInvite:
      environment.HANDSHAKE_CODEX_INVITE_FILE,
    claudeInvite:
      environment.HANDSHAKE_CLAUDE_INVITE_FILE,
    outputRoot:
      environment.HANDSHAKE_ACCEPTANCE_OUTPUT ??
      DEFAULT_OUTPUT_ROOT,
    repositoryRef:
      environment.HANDSHAKE_REPO_REF,
  };
  const keys = {
    "--codex-invite": "codexInvite",
    "--claude-invite": "claudeInvite",
    "--output": "outputRoot",
    "--repo-ref": "repositoryRef",
  };
  for (let index = 0; index < argv.length;) {
    const argument = argv[index];
    if (argument === OPERATOR_RISK_ACKNOWLEDGEMENT_FLAG) {
      if (riskAcknowledged) {
        throw new HarnessConfigurationError();
      }
      riskAcknowledged = true;
      index += 1;
      continue;
    }
    const key = Object.hasOwn(keys, argument)
      ? keys[argument]
      : undefined;
    const value = argv[index + 1];
    if (
      !key ||
      value === undefined ||
      value === OPERATOR_RISK_ACKNOWLEDGEMENT_FLAG ||
      Object.hasOwn(keys, value) ||
      seenOptions.has(argument)
    ) {
      throw new HarnessConfigurationError();
    }
    seenOptions.add(argument);
    values[key] = value;
    index += 2;
  }
  if (!riskAcknowledged) {
    throw new MissingRiskAcknowledgementError();
  }
  values.repositoryRef = normalizeRepositoryRef(
    values.repositoryRef,
  );
  return values;
}

export async function main({
  argv = process.argv.slice(2),
  environment = process.env,
  stderr = process.stderr,
  stdout = process.stdout,
  run = runCleanClients,
} = {}) {
  try {
    const options = parseArguments(argv, environment);
    const result = await run({
      baseEnvironment: environment,
      commands: DEFAULT_CLIENT_COMMANDS,
      invitations: {
        codex: resolve(options.codexInvite),
        claude: resolve(options.claudeInvite),
      },
      operatorRiskAcknowledged: true,
      outputRoot: resolve(options.outputRoot),
      repositoryRef: options.repositoryRef,
    });
    stdout.write(
      `${result.status} ${result.manifestPath}\n`,
    );
    return result.status === "PASS" ? 0 : 1;
  } catch (error) {
    stderr.write(
      error instanceof MissingRiskAcknowledgementError
        ? OPERATOR_RISK_WARNING
        : "Clean-client acceptance configuration failed.\n",
    );
    return 2;
  }
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  process.exitCode = await main();
}
