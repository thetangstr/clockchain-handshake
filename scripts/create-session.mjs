#!/usr/bin/env node

import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  randomBytes as cryptoRandomBytes,
} from "node:crypto";
import { execFile } from "node:child_process";
import { constants as fsConstants } from "node:fs";
import {
  lstat,
  mkdir,
  open,
  readFile,
  realpath,
  unlink,
} from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";

import {
  BILATERAL_PROTOCOL,
  DESCRIPTOR_CHAIN_ID,
  DESCRIPTOR_EXPIRY_SECONDS,
  DESCRIPTOR_NAMESPACE,
  DESCRIPTOR_SCHEMA,
  DESCRIPTOR_SETTLEMENT,
  OPERATOR_KEY_ALGORITHM,
  PROTOCOL_VERSION,
  REGISTRY_ADDRESS,
  createSignedEnvelope,
  dSession,
  operatorPublicKeyPath,
  publicKeyPemFromRawBase64,
  rawPublicKeyBase64FromPem,
  validateDescriptor,
} from "../src/bilateral/descriptor.mjs";

const execFileAsync = promisify(execFile);
const REPOSITORY_SHA_PATTERN = /^[0-9a-f]{40}$/;
const PROMPT_SHA256_PATTERN = /^[0-9a-f]{64}$/;
export const MAX_AMOUNTS_ARGUMENT_BYTES = 2_087;
export const MAX_PROMPT_FILE_BYTES = 65_536;
const READ_FLAGS =
  fsConstants.O_RDONLY |
  (fsConstants.O_NOFOLLOW ?? 0) |
  (fsConstants.O_NONBLOCK ?? 0);
const WRITE_FLAGS =
  fsConstants.O_WRONLY |
  fsConstants.O_CREAT |
  fsConstants.O_EXCL |
  (fsConstants.O_NOFOLLOW ?? 0);
const MAX_PRIVATE_KEY_FILE_BYTES = 4_096;
const MAX_PUBLIC_KEY_FILE_BYTES = 256;
const KEYGEN_ARGUMENTS = Object.freeze(["--key-id"]);
const CREATE_ARGUMENTS = Object.freeze([
  "--amounts",
  "--key-id",
  "--output",
  "--payee-address",
  "--payee-agent-id",
  "--payee-name",
  "--payer-address",
  "--payer-agent-id",
  "--payer-name",
  "--prompt-file",
  "--prompt-sha256",
  "--repository-sha",
]);
const REQUIRED_CREATE_ARGUMENTS = Object.freeze([
  "--amounts",
  "--key-id",
  "--output",
  "--payee-address",
  "--payee-agent-id",
  "--payee-name",
  "--payer-address",
  "--payer-agent-id",
  "--payer-name",
]);
const DEFAULT_FILE_SYSTEM = Object.freeze({
  lstat,
  mkdir,
  open,
  readFile,
  realpath,
  unlink,
});

export class SessionCreationError extends Error {
  constructor() {
    super("Bilateral session creation failed safely.");
    this.name = "SessionCreationError";
    this.code = "SESSION_CREATION_FAILED";
  }
}

function fail() {
  throw new SessionCreationError();
}

function parsePairs(arguments_, knownArguments) {
  if (!Array.isArray(arguments_) || arguments_.length % 2 !== 0) {
    fail();
  }
  const values = new Map();
  for (let index = 0; index < arguments_.length; index += 2) {
    const flag = arguments_[index];
    const value = arguments_[index + 1];
    if (
      typeof flag !== "string" ||
      !knownArguments.includes(flag) ||
      values.has(flag) ||
      typeof value !== "string" ||
      value.startsWith("--")
    ) {
      fail();
    }
    values.set(flag, value);
  }
  return values;
}

function parseInvocation(arguments_) {
  if (!Array.isArray(arguments_) || arguments_.length === 0) {
    fail();
  }
  const [mode, ...modeArguments] = arguments_;
  if (mode === "keygen") {
    const values = parsePairs(modeArguments, KEYGEN_ARGUMENTS);
    if (values.size !== 1 || !values.has("--key-id")) {
      fail();
    }
    return { mode, values };
  }
  if (mode === "create") {
    const values = parsePairs(modeArguments, CREATE_ARGUMENTS);
    if (
      !REQUIRED_CREATE_ARGUMENTS.every((flag) =>
        values.has(flag),
      ) ||
      values.has("--prompt-file") ===
        values.has("--prompt-sha256")
    ) {
      fail();
    }
    return { mode, values };
  }
  fail();
}

function activeFileSystem(dependencies) {
  const fileSystem = {
    ...DEFAULT_FILE_SYSTEM,
    ...(dependencies.fileSystem ?? {}),
  };
  for (const operation of Object.keys(DEFAULT_FILE_SYSTEM)) {
    if (typeof fileSystem[operation] !== "function") {
      fail();
    }
  }
  return fileSystem;
}

async function pathExists(path, fileSystem) {
  try {
    await fileSystem.lstat(path);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") {
      return false;
    }
    fail();
  }
}

async function closeHandle(handle) {
  try {
    await handle.close();
    return true;
  } catch {
    return false;
  }
}

async function readRegularFile(
  path,
  fileSystem,
  {
    encoding = "utf8",
    maxBytes,
    requiredMode,
  },
) {
  let handle;
  let contents;
  let metadata;
  let failed = false;
  try {
    handle = await fileSystem.open(path, READ_FLAGS);
    metadata = await handle.stat();
    if (
      !metadata.isFile() ||
      metadata.size > maxBytes ||
      (requiredMode !== undefined &&
        (metadata.mode & 0o777) !== requiredMode)
    ) {
      failed = true;
    } else {
      contents = await handle.readFile(
        encoding === null ? undefined : encoding,
      );
      const bytesRead = Buffer.isBuffer(contents)
        ? contents.length
        : Buffer.byteLength(contents, "utf8");
      if (bytesRead > maxBytes) {
        failed = true;
      }
    }
  } catch {
    failed = true;
  }
  if (handle && !(await closeHandle(handle))) {
    failed = true;
  }
  if (failed) {
    fail();
  }
  return { contents, metadata };
}

async function writeExclusiveFile(
  path,
  contents,
  mode,
  fileSystem,
  createdFiles,
  { parentIdentity } = {},
) {
  let handle;
  let failed = false;
  try {
    handle = await fileSystem.open(path, WRITE_FLAGS, mode);
    const metadata = await handle.stat();
    createdFiles.push({
      dev: metadata.dev,
      ino: metadata.ino,
      parentIdentity,
      path,
    });
    if (
      !metadata.isFile() ||
      (metadata.mode & 0o777) !== mode ||
      (
        parentIdentity !== undefined &&
        !(await directoryIdentityMatches(
          parentIdentity,
          fileSystem,
        ))
      )
    ) {
      failed = true;
    } else {
      await handle.writeFile(contents, "utf8");
      await handle.sync();
    }
  } catch {
    failed = true;
  }
  if (handle && !(await closeHandle(handle))) {
    failed = true;
  }
  if (failed) {
    fail();
  }
}

async function removeCreatedFiles(createdFiles, fileSystem) {
  await Promise.all(
    [...createdFiles].reverse().map(async (createdFile) => {
      try {
        if (
          createdFile.parentIdentity !== undefined &&
          !(await directoryIdentityMatches(
            createdFile.parentIdentity,
            fileSystem,
          ))
        ) {
          return;
        }
        const metadata = await fileSystem.lstat(
          createdFile.path,
        );
        if (
          !metadata.isFile() ||
          metadata.isSymbolicLink() ||
          metadata.dev !== createdFile.dev ||
          metadata.ino !== createdFile.ino
        ) {
          return;
        }
        await fileSystem.unlink(createdFile.path);
      } catch {
        // Only files exclusively created by this invocation are listed.
      }
    }),
  );
}

const KEY_DIRECTORY_SPECS = Object.freeze([
  Object.freeze({
    pathParts: Object.freeze([".context"]),
  }),
  Object.freeze({
    mode: 0o700,
    pathParts: Object.freeze([
      ".context",
      "operator-keys",
    ]),
  }),
  Object.freeze({
    pathParts: Object.freeze(["docs"]),
  }),
  Object.freeze({
    pathParts: Object.freeze(["docs", "operator-keys"]),
  }),
]);

async function repositoryPhysicalRoot(repoRoot, fileSystem) {
  try {
    const metadata = await fileSystem.lstat(repoRoot);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      fail();
    }
    return await fileSystem.realpath(repoRoot);
  } catch (error) {
    if (error instanceof SessionCreationError) {
      throw error;
    }
    fail();
  }
}

async function pinDirectoryIdentity(
  path,
  expectedPhysicalPath,
  fileSystem,
) {
  try {
    const metadata = await fileSystem.lstat(path);
    const physicalPath = await fileSystem.realpath(path);
    if (
      !metadata.isDirectory() ||
      metadata.isSymbolicLink() ||
      physicalPath !== expectedPhysicalPath
    ) {
      fail();
    }
    return Object.freeze({
      dev: metadata.dev,
      ino: metadata.ino,
      path,
      physicalPath,
    });
  } catch (error) {
    if (error instanceof SessionCreationError) {
      throw error;
    }
    fail();
  }
}

async function directoryIdentityMatches(identity, fileSystem) {
  try {
    const metadata = await fileSystem.lstat(identity.path);
    return (
      metadata.isDirectory() &&
      !metadata.isSymbolicLink() &&
      metadata.dev === identity.dev &&
      metadata.ino === identity.ino &&
      (await fileSystem.realpath(identity.path)) ===
        identity.physicalPath
    );
  } catch {
    return false;
  }
}

async function inspectKeyDirectories(
  repoRoot,
  fileSystem,
  { createMissing },
) {
  const physicalRoot = await repositoryPhysicalRoot(
    repoRoot,
    fileSystem,
  );
  for (const specification of KEY_DIRECTORY_SPECS) {
    const path = join(repoRoot, ...specification.pathParts);
    let metadata;
    try {
      metadata = await fileSystem.lstat(path);
    } catch (error) {
      if (error?.code !== "ENOENT" || !createMissing) {
        fail();
      }
      try {
        await fileSystem.mkdir(path, {
          mode: specification.mode ?? 0o755,
        });
        metadata = await fileSystem.lstat(path);
      } catch {
        fail();
      }
    }
    if (
      !metadata.isDirectory() ||
      metadata.isSymbolicLink() ||
      (specification.mode !== undefined &&
        (metadata.mode & 0o777) !== specification.mode)
    ) {
      fail();
    }
    let physicalPath;
    try {
      physicalPath = await fileSystem.realpath(path);
    } catch {
      fail();
    }
    if (
      physicalPath !==
      join(physicalRoot, ...specification.pathParts)
    ) {
      fail();
    }
  }
  return physicalRoot;
}

function operatorPaths(repoRoot, keyId) {
  let repositoryPath;
  try {
    repositoryPath = operatorPublicKeyPath(keyId);
  } catch {
    fail();
  }
  return {
    privateKeyPath: join(
      repoRoot,
      ".context",
      "operator-keys",
      `${keyId}.ed25519.pem`,
    ),
    publicKeyPath: join(repoRoot, repositoryPath),
    repositoryPath,
  };
}

function publicKeyFromPrivatePem(privateKeyPem) {
  try {
    const publicKeyPem = createPublicKey(privateKeyPem).export({
      format: "pem",
      type: "spki",
    });
    return rawPublicKeyBase64FromPem(publicKeyPem);
  } catch {
    fail();
  }
}

function repositoryPublicKeyFromFile(contents) {
  if (typeof contents !== "string") {
    fail();
  }
  const candidate = contents.endsWith("\n")
    ? contents.slice(0, -1)
    : contents;
  if (
    candidate.length === 0 ||
    candidate.includes("\n") ||
    candidate.includes("\r")
  ) {
    fail();
  }
  try {
    publicKeyPemFromRawBase64(candidate);
  } catch {
    fail();
  }
  return candidate;
}

function generateOperatorKey() {
  try {
    const { privateKey } = generateKeyPairSync(
      OPERATOR_KEY_ALGORITHM,
    );
    const privateKeyPem = privateKey.export({
      format: "pem",
      type: "pkcs8",
    });
    return {
      privateKeyPem,
      publicKey: publicKeyFromPrivatePem(privateKeyPem),
    };
  } catch (error) {
    if (error instanceof SessionCreationError) {
      throw error;
    }
    fail();
  }
}

async function keygenMode(values, {
  fileSystem,
  repoRoot,
}) {
  const keyId = values.get("--key-id");
  const { privateKeyPath, publicKeyPath } = operatorPaths(
    repoRoot,
    keyId,
  );
  const physicalRoot = await inspectKeyDirectories(
    repoRoot,
    fileSystem,
    {
      createMissing: true,
    },
  );
  if (
    (await pathExists(privateKeyPath, fileSystem)) ||
    (await pathExists(publicKeyPath, fileSystem))
  ) {
    fail();
  }

  const { privateKeyPem, publicKey } = generateOperatorKey();
  const createdFiles = [];
  try {
    await inspectKeyDirectories(repoRoot, fileSystem, {
      createMissing: false,
    });
    const privateParentIdentity = await pinDirectoryIdentity(
      dirname(privateKeyPath),
      join(physicalRoot, ".context", "operator-keys"),
      fileSystem,
    );
    await writeExclusiveFile(
      privateKeyPath,
      privateKeyPem,
      0o600,
      fileSystem,
      createdFiles,
      { parentIdentity: privateParentIdentity },
    );
    await inspectKeyDirectories(repoRoot, fileSystem, {
      createMissing: false,
    });
    const publicParentIdentity = await pinDirectoryIdentity(
      dirname(publicKeyPath),
      join(physicalRoot, "docs", "operator-keys"),
      fileSystem,
    );
    await writeExclusiveFile(
      publicKeyPath,
      `${publicKey}\n`,
      0o644,
      fileSystem,
      createdFiles,
      { parentIdentity: publicParentIdentity },
    );
    return Object.freeze({
      keyId,
      publicKey,
      publicKeyPath,
    });
  } catch {
    await removeCreatedFiles(createdFiles, fileSystem);
    fail();
  }
}

function parseAmounts(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    Buffer.byteLength(value, "utf8") >
      MAX_AMOUNTS_ARGUMENT_BYTES
  ) {
    fail();
  }
  const options = value.split(",").map((entry) => {
    if (
      entry.length === 0 ||
      entry.trim() !== entry ||
      entry.split(":").length !== 2
    ) {
      fail();
    }
    const [currency, amount] = entry.split(":");
    return { currency, value: amount };
  });
  options.sort((left, right) => {
    if (left.currency !== right.currency) {
      return left.currency < right.currency ? -1 : 1;
    }
    if (left.value === right.value) {
      return 0;
    }
    return left.value < right.value ? -1 : 1;
  });
  return options;
}

async function defaultResolveHeadSha(repoRoot) {
  try {
    const { stdout } = await execFileAsync(
      "git",
      ["rev-parse", "--verify", "HEAD"],
      { cwd: repoRoot, encoding: "utf8" },
    );
    return stdout.trim();
  } catch {
    fail();
  }
}

async function defaultReadRepositoryFileAtSha({
  path,
  repoRoot,
  repositorySha,
}) {
  try {
    const { stdout } = await execFileAsync(
      "git",
      ["show", `${repositorySha}:${path}`],
      { cwd: repoRoot, encoding: "utf8" },
    );
    return stdout;
  } catch {
    fail();
  }
}

async function promptDigest(values, fileSystem) {
  if (values.has("--prompt-sha256")) {
    const digest = values.get("--prompt-sha256");
    if (!PROMPT_SHA256_PATTERN.test(digest)) {
      fail();
    }
    return digest;
  }
  const { contents: prompt } = await readRegularFile(
    resolve(values.get("--prompt-file")),
    fileSystem,
    {
      encoding: null,
      maxBytes: MAX_PROMPT_FILE_BYTES,
    },
  );
  return createHash("sha256").update(prompt).digest("hex");
}

function sessionIdFrom(randomBytes) {
  let bytes;
  try {
    bytes = Buffer.from(randomBytes(16));
  } catch {
    fail();
  }
  if (bytes.length !== 16) {
    fail();
  }
  return bytes.toString("hex");
}

function buildDescriptor(values, {
  amountOptions,
  promptSha256,
  repositorySha,
  sessionId,
}) {
  const descriptor = {
    amountOptions,
    chainId: DESCRIPTOR_CHAIN_ID,
    expirySeconds: DESCRIPTOR_EXPIRY_SECONDS,
    namespace: DESCRIPTOR_NAMESPACE,
    payee: {
      address: values.get("--payee-address"),
      agentId: values.get("--payee-agent-id"),
      displayName: values.get("--payee-name"),
      role: "payee",
    },
    payer: {
      address: values.get("--payer-address"),
      agentId: values.get("--payer-agent-id"),
      displayName: values.get("--payer-name"),
      role: "payer",
    },
    paymentMoved: false,
    promptSha256,
    protocol: BILATERAL_PROTOCOL,
    protocolVersion: PROTOCOL_VERSION,
    registry: REGISTRY_ADDRESS,
    repositorySha,
    schema: DESCRIPTOR_SCHEMA,
    sessionId,
    settlement: DESCRIPTOR_SETTLEMENT,
  };
  try {
    validateDescriptor(descriptor);
  } catch {
    fail();
  }
  return descriptor;
}

async function defaultWriteSessionOutput({
  envelope,
  fileSystem,
  path,
}) {
  const createdFiles = [];
  try {
    await fileSystem.mkdir(dirname(path), {
      recursive: true,
      mode: 0o755,
    });
    const parentMetadata = await fileSystem.lstat(
      dirname(path),
    );
    if (
      !parentMetadata.isDirectory() ||
      parentMetadata.isSymbolicLink()
    ) {
      fail();
    }
    await writeExclusiveFile(
      path,
      `${JSON.stringify(envelope, null, 2)}\n`,
      0o644,
      fileSystem,
      createdFiles,
    );
  } catch {
    await removeCreatedFiles(createdFiles, fileSystem);
    fail();
  }
}

async function createMode(values, {
  dependencies,
  fileSystem,
  repoRoot,
}) {
  const keyId = values.get("--key-id");
  const outputPath = resolve(values.get("--output"));
  const {
    privateKeyPath,
    publicKeyPath,
    repositoryPath,
  } = operatorPaths(repoRoot, keyId);
  await inspectKeyDirectories(repoRoot, fileSystem, {
    createMissing: false,
  });
  if (await pathExists(outputPath, fileSystem)) {
    fail();
  }

  const amountOptions = parseAmounts(values.get("--amounts"));
  const promptSha256 = await promptDigest(values, fileSystem);
  const resolveHeadSha =
    dependencies.resolveHeadSha ?? defaultResolveHeadSha;
  let repositorySha = values.get("--repository-sha");
  if (repositorySha === undefined) {
    try {
      repositorySha = await resolveHeadSha(repoRoot);
    } catch {
      fail();
    }
  }
  if (
    typeof repositorySha !== "string" ||
    !REPOSITORY_SHA_PATTERN.test(repositorySha)
  ) {
    fail();
  }
  const randomBytes =
    dependencies.randomBytes ?? cryptoRandomBytes;
  const descriptor = buildDescriptor(values, {
    amountOptions,
    promptSha256,
    repositorySha,
    sessionId: sessionIdFrom(randomBytes),
  });

  await inspectKeyDirectories(repoRoot, fileSystem, {
    createMissing: false,
  });
  const privateFile = await readRegularFile(
    privateKeyPath,
    fileSystem,
    {
      maxBytes: MAX_PRIVATE_KEY_FILE_BYTES,
      requiredMode: 0o600,
    },
  );
  await inspectKeyDirectories(repoRoot, fileSystem, {
    createMissing: false,
  });
  const publicFile = await readRegularFile(
    publicKeyPath,
    fileSystem,
    {
      maxBytes: MAX_PUBLIC_KEY_FILE_BYTES,
    },
  );
  const workingPublicKey = repositoryPublicKeyFromFile(
    publicFile.contents,
  );
  if (
    publicKeyFromPrivatePem(privateFile.contents) !==
    workingPublicKey
  ) {
    fail();
  }

  const readRepositoryFileAtSha =
    dependencies.readRepositoryFileAtSha ??
    defaultReadRepositoryFileAtSha;
  let committedPublicKeyFile;
  try {
    committedPublicKeyFile = await readRepositoryFileAtSha({
      path: repositoryPath,
      repoRoot,
      repositorySha,
    });
  } catch {
    fail();
  }
  if (
    typeof committedPublicKeyFile !== "string" ||
    committedPublicKeyFile !== publicFile.contents
  ) {
    fail();
  }
  repositoryPublicKeyFromFile(committedPublicKeyFile);

  let envelope;
  try {
    envelope = createSignedEnvelope(descriptor, {
      keyId,
      privateKeyPem: privateFile.contents,
    });
  } catch {
    fail();
  }
  if (envelope.operator.publicKey !== workingPublicKey) {
    fail();
  }

  const writeSessionOutput =
    dependencies.writeSessionOutput ??
    defaultWriteSessionOutput;
  try {
    await writeSessionOutput({
      envelope,
      fileSystem,
      path: outputPath,
    });
  } catch {
    fail();
  }
  return Object.freeze({
    dSession: dSession(descriptor),
    envelope,
  });
}

export async function main(
  arguments_ = process.argv.slice(2),
  dependencies = {},
) {
  const invocation = parseInvocation(arguments_);
  const repoRoot = resolve(
    dependencies.repoRoot ??
      fileURLToPath(new URL("..", import.meta.url)),
  );
  const fileSystem = activeFileSystem(dependencies);
  if (invocation.mode === "keygen") {
    return keygenMode(invocation.values, {
      fileSystem,
      repoRoot,
    });
  }
  return createMode(invocation.values, {
    dependencies,
    fileSystem,
    repoRoot,
  });
}

export async function runCli(
  arguments_ = process.argv.slice(2),
  dependencies = {},
) {
  const result = await main(arguments_, dependencies);
  const payload =
    arguments_[0] === "create" ? result.envelope : result;
  const writeStdout =
    dependencies.writeStdout ??
    ((value) => process.stdout.write(value));
  try {
    await writeStdout(`${JSON.stringify(payload, null, 2)}\n`);
  } catch {
    fail();
  }
  return result;
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  runCli().catch(() => {
    process.stderr.write("Bilateral session creation failed safely.\n");
    process.exitCode = 1;
  });
}
