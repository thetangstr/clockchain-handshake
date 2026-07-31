#!/usr/bin/env node

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import {
  lstat,
  mkdir,
  open,
  rename,
  rm,
} from "node:fs/promises";
import { dirname } from "node:path";
import {
  fileURLToPath,
  pathToFileURL,
} from "node:url";
import { promisify } from "node:util";

import {
  createPublicClient,
  http,
} from "viem";

import { createMcpClient } from "../src/mcp.mjs";
import { ERC8004_ABI } from "../src/registration.mjs";
import {
  operatorPublicKeyPath,
  verifyDescriptorEnvelope,
} from "../src/bilateral/descriptor.mjs";
import { canonicalBytes } from "../src/bilateral/canonical.mjs";
import {
  BilateralVerdictError,
  VERDICT_SCHEMA,
  renderBilateralVerdictMarkdown,
  verifyBilateralAuthorization,
} from "../src/bilateral/verdict.mjs";
import {
  TERMINAL_FAILURE_CODES,
} from "../src/bilateral/protocol.mjs";

export const CLI_ARGUMENTS = Object.freeze([
  "--clockchain-token-file",
  "--descriptor",
  "--output",
  "--payer-mandate",
  "--payee-results",
  "--payer-results",
  "--payment-request",
  "--rpc-url",
]);

const execFileAsync = promisify(execFile);
const DEFAULT_FILE_SYSTEM = Object.freeze({
  lstat,
  mkdir,
  open,
  rename,
  rm,
});
const DEFAULT_BUILDER_FILE_SYSTEM = Object.freeze({ open });
const MAX_DESCRIPTOR_BYTES = 1024 * 1024;
const MAX_INTENT_BYTES = 65_536;
const MAX_TOKEN_BYTES = 4096;
const TOKEN_PATTERN = /^[!-~]{1,4096}$/;
const READ_FLAGS =
  constants.O_RDONLY |
  (constants.O_NOFOLLOW ?? 0) |
  (constants.O_NONBLOCK ?? 0);
const REPOSITORY_SHA_PATTERN = /^[0-9a-f]{40}$/;
const VERDICT_COMPLETION_SCHEMA =
  "clockchain.bilateral-authorization-verdict-completion/v2";
const VERDICT_FILES = Object.freeze({
  json: "bilateral-verdict.json",
  markdown: "BILATERAL-VERDICT.md",
  marker: ".bilateral-verdict.complete.json",
});
const DIRECTORY_FLAGS =
  constants.O_RDONLY |
  (constants.O_DIRECTORY ?? 0) |
  (constants.O_NOFOLLOW ?? 0);
const EXCLUSIVE_WRITE_FLAGS =
  constants.O_WRONLY |
  constants.O_CREAT |
  constants.O_EXCL |
  (constants.O_NOFOLLOW ?? 0);

export const VERIFIER_REPOSITORY_ROOT = dirname(
  dirname(fileURLToPath(import.meta.url)),
);

function fixedFailure(terminalCode) {
  const outcome = TERMINAL_FAILURE_CODES.includes(terminalCode)
    ? terminalCode
    : "FAILED";
  return `${JSON.stringify({
    outcome,
    paymentMoved: false,
    schema: VERDICT_SCHEMA,
  })}\n`;
}

function parseArguments(arguments_) {
  if (
    !Array.isArray(arguments_) ||
    arguments_.length !== CLI_ARGUMENTS.length * 2
  ) {
    throw new BilateralVerdictError();
  }
  const values = new Map();
  for (let index = 0; index < arguments_.length; index += 2) {
    const flag = arguments_[index];
    const value = arguments_[index + 1];
    if (
      typeof flag !== "string" ||
      !CLI_ARGUMENTS.includes(flag) ||
      values.has(flag) ||
      typeof value !== "string" ||
      value.length === 0 ||
      value.startsWith("--") ||
      value.includes("\0")
    ) {
      throw new BilateralVerdictError();
    }
    values.set(flag, value);
  }
  if (!CLI_ARGUMENTS.every((flag) => values.has(flag))) {
    throw new BilateralVerdictError();
  }
  return Object.freeze({
    clockchainTokenFile: values.get(
      "--clockchain-token-file",
    ),
    descriptor: values.get("--descriptor"),
    output: values.get("--output"),
    payerMandate: values.get("--payer-mandate"),
    payeeResults: values.get("--payee-results"),
    payerResults: values.get("--payer-results"),
    paymentRequest: values.get("--payment-request"),
    rpcUrl: values.get("--rpc-url"),
  });
}

function activeDependencies(dependencies) {
  if (
    dependencies === null ||
    typeof dependencies !== "object" ||
    Array.isArray(dependencies)
  ) {
    throw new BilateralVerdictError();
  }
  const fileSystem = {
    ...DEFAULT_FILE_SYSTEM,
    ...(dependencies.fileSystem ?? {}),
  };
  for (const operation of Object.keys(DEFAULT_FILE_SYSTEM)) {
    if (typeof fileSystem[operation] !== "function") {
      throw new BilateralVerdictError();
    }
  }
  const stdout = dependencies.stdout ?? process.stdout;
  const stderr = dependencies.stderr ?? process.stderr;
  if (
    typeof stdout?.write !== "function" ||
    typeof stderr?.write !== "function" ||
    (
      Object.hasOwn(
        dependencies,
        "beforeAuthorizationOutput",
      ) &&
      typeof dependencies.beforeAuthorizationOutput !==
        "function"
    )
  ) {
    throw new BilateralVerdictError();
  }
  return Object.freeze({
    beforeAuthorizationOutput:
      dependencies.beforeAuthorizationOutput ??
      null,
    buildVerifierInput:
      dependencies.buildVerifierInput ??
      buildDefaultVerifierInput,
    fileSystem: Object.freeze(fileSystem),
    stderr,
    stdout,
    verify:
      dependencies.verify ?? verifyBilateralAuthorization,
  });
}

function sameMetadata(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.nlink === right.nlink &&
    left.uid === right.uid &&
    left.gid === right.gid &&
    left.rdev === right.rdev &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs
  );
}

async function readBoundedRegularFile(
  path,
  maximum,
  {
    fileSystem,
    secret = false,
  },
) {
  let handle;
  let closeFailed = false;
  try {
    handle = await fileSystem.open(path, READ_FLAGS);
    if (
      handle === null ||
      typeof handle !== "object" ||
      typeof handle.stat !== "function" ||
      typeof handle.read !== "function" ||
      typeof handle.close !== "function"
    ) {
      throw new BilateralVerdictError();
    }
    const before = await handle.stat();
    if (
      typeof before?.isFile !== "function" ||
      !before.isFile() ||
      !Number.isSafeInteger(before.size) ||
      before.size <= 0 ||
      before.size > maximum ||
      (
        secret &&
        (before.mode & 0o777) !== 0o600
      )
    ) {
      throw new BilateralVerdictError();
    }
    const bytes = Buffer.alloc(maximum + 1);
    let offset = 0;
    while (offset < bytes.length) {
      const result = await handle.read(
        bytes,
        offset,
        bytes.length - offset,
        offset,
      );
      if (
        result === null ||
        typeof result !== "object" ||
        !Number.isSafeInteger(result.bytesRead) ||
        result.bytesRead < 0 ||
        result.bytesRead > bytes.length - offset
      ) {
        throw new BilateralVerdictError();
      }
      if (result.bytesRead === 0) {
        break;
      }
      offset += result.bytesRead;
    }
    const content = bytes.subarray(0, offset);
    const after = await handle.stat();
    if (
      content.length > maximum ||
      content.length !== before.size ||
      !sameMetadata(before, after)
    ) {
      throw new BilateralVerdictError();
    }
    return content;
  } catch (error) {
    if (error instanceof BilateralVerdictError) {
      throw error;
    }
    throw new BilateralVerdictError();
  } finally {
    if (handle !== undefined) {
      try {
        await handle.close();
      } catch {
        closeFailed = true;
      }
    }
    if (closeFailed) {
      throw new BilateralVerdictError();
    }
  }
}

function parseExactCanonicalJson(bytes) {
  let value;
  try {
    value = JSON.parse(bytes.toString("utf8"));
    if (!canonicalBytes(value).equals(bytes)) {
      throw new Error();
    }
  } catch {
    throw new BilateralVerdictError();
  }
  return value;
}

async function defaultRunGit({ args, cwd, maxBuffer }) {
  return execFileAsync("git", args, {
    cwd,
    encoding: "utf8",
    maxBuffer,
  });
}

function activeBuilderDependencies(dependencies) {
  if (
    dependencies === null ||
    typeof dependencies !== "object" ||
    Array.isArray(dependencies)
  ) {
    throw new BilateralVerdictError();
  }
  const fileSystem = {
    ...DEFAULT_BUILDER_FILE_SYSTEM,
    ...(dependencies.fileSystem ?? {}),
  };
  const active = {
    createClockchainClient:
      dependencies.createClockchainClient ?? createMcpClient,
    createIdentityClient:
      dependencies.createIdentityClient ??
      (({ rpcUrl }) =>
        createPublicClient({
          transport: http(rpcUrl),
        })),
    fileSystem,
    repositoryRoot:
      dependencies.repositoryRoot ?? VERIFIER_REPOSITORY_ROOT,
    runGit: dependencies.runGit ?? defaultRunGit,
  };
  if (
    typeof active.createClockchainClient !== "function" ||
    typeof active.createIdentityClient !== "function" ||
    typeof active.fileSystem.open !== "function" ||
    typeof active.repositoryRoot !== "string" ||
    active.repositoryRoot.length === 0 ||
    typeof active.runGit !== "function"
  ) {
    throw new BilateralVerdictError();
  }
  return Object.freeze(active);
}

async function gitStdout(active, args, maxBuffer = 4096) {
  let result;
  try {
    result = await active.runGit({
      args,
      cwd: active.repositoryRoot,
      maxBuffer,
    });
  } catch {
    throw new BilateralVerdictError();
  }
  if (
    result === null ||
    typeof result !== "object" ||
    typeof result.stdout !== "string"
  ) {
    throw new BilateralVerdictError();
  }
  return result.stdout;
}

export async function buildDefaultVerifierInput(
  values,
  dependencies = {},
) {
  const active = activeBuilderDependencies(dependencies);
  if (
    values === null ||
    typeof values !== "object" ||
    Array.isArray(values) ||
    typeof values.descriptor !== "string" ||
    typeof values.clockchainTokenFile !== "string" ||
    typeof values.payerMandate !== "string" ||
    typeof values.paymentRequest !== "string" ||
    typeof values.rpcUrl !== "string"
  ) {
    throw new BilateralVerdictError();
  }
  const descriptorBytes = await readBoundedRegularFile(
    values.descriptor,
    MAX_DESCRIPTOR_BYTES,
    { fileSystem: active.fileSystem },
  );
  const tokenBytes = await readBoundedRegularFile(
    values.clockchainTokenFile,
    MAX_TOKEN_BYTES,
    {
      fileSystem: active.fileSystem,
      secret: true,
    },
  );
  const mandateBytes = await readBoundedRegularFile(
    values.payerMandate,
    MAX_INTENT_BYTES,
    { fileSystem: active.fileSystem },
  );
  const requestBytes = await readBoundedRegularFile(
    values.paymentRequest,
    MAX_INTENT_BYTES,
    { fileSystem: active.fileSystem },
  );
  let descriptorEnvelope;
  try {
    descriptorEnvelope = JSON.parse(
      descriptorBytes.toString("utf8"),
    );
  } catch {
    throw new BilateralVerdictError();
  }
  const mandateEnvelope = parseExactCanonicalJson(mandateBytes);
  const requestEnvelope = parseExactCanonicalJson(requestBytes);
  const tokenText = tokenBytes.toString("utf8");
  const token = tokenText.endsWith("\n")
    ? tokenText.slice(0, -1)
    : tokenText;
  if (!TOKEN_PATTERN.test(token)) {
    throw new BilateralVerdictError();
  }

  const descriptor = descriptorEnvelope?.descriptor;
  const operator = descriptorEnvelope?.operator;
  const repositorySha = descriptor?.repositorySha;
  let repositoryPath;
  try {
    repositoryPath = operatorPublicKeyPath(operator?.keyId);
  } catch {
    throw new BilateralVerdictError();
  }
  if (
    typeof repositorySha !== "string" ||
    !REPOSITORY_SHA_PATTERN.test(repositorySha)
  ) {
    throw new BilateralVerdictError();
  }
  const repositoryPublicKey = (
    await gitStdout(
      active,
      [
        "show",
        `${repositorySha}:${repositoryPath}`,
      ],
    )
  ).trim();
  try {
    verifyDescriptorEnvelope(descriptorEnvelope, {
      repositoryPublicKey,
    });
  } catch {
    throw new BilateralVerdictError();
  }

  const head = (
    await gitStdout(
      active,
      ["rev-parse", "--verify", "HEAD"],
    )
  ).trim();
  if (
    !REPOSITORY_SHA_PATTERN.test(head) ||
    head !== repositorySha
  ) {
    throw new BilateralVerdictError();
  }
  const status = await gitStdout(
    active,
    [
      "status",
      "--porcelain=v1",
      "--untracked-files=all",
    ],
    1024 * 1024,
  );
  if (status !== "") {
    throw new BilateralVerdictError();
  }

  let publicClient;
  let chainId;
  try {
    publicClient = active.createIdentityClient({
      rpcUrl: values.rpcUrl,
    });
    if (
      publicClient === null ||
      typeof publicClient !== "object" ||
      typeof publicClient.getChainId !== "function" ||
      typeof publicClient.readContract !== "function"
    ) {
      throw new Error();
    }
    chainId = await publicClient.getChainId();
  } catch {
    throw new BilateralVerdictError();
  }
  if (
    chainId !== 11155111 ||
    descriptor.chainId !== String(chainId)
  ) {
    throw new BilateralVerdictError();
  }

  let clockchain;
  try {
    clockchain = active.createClockchainClient({ token });
  } catch {
    throw new BilateralVerdictError();
  }
  return {
    canaries: [token],
    clockchain,
    descriptorEnvelope,
    mandateEnvelope,
    ownerOf: async ({ agentId, registry }) =>
      publicClient.readContract({
        abi: ERC8004_ABI,
        address: registry,
        args: [BigInt(agentId)],
        functionName: "ownerOf",
      }),
    payeeDirectory: values.payeeResults,
    payerDirectory: values.payerResults,
    requestEnvelope,
    repositoryPublicKeyResolver: async (request) => {
      if (
        request?.keyId !== operator.keyId ||
        request?.repositoryPath !== repositoryPath ||
        request?.repositorySha !== repositorySha
      ) {
        throw new BilateralVerdictError();
      }
      return repositoryPublicKey;
    },
  };
}

async function publishVerdict(
  verdict,
  output,
  fileSystem,
) {
  const json = Buffer.from(
    `${JSON.stringify(verdict, null, 2)}\n`,
    "utf8",
  );
  const markdown = Buffer.from(
    renderBilateralVerdictMarkdown(verdict),
    "utf8",
  );
  const marker = Buffer.from(
    `${JSON.stringify({
      jsonSha256: createHash("sha256")
        .update(json)
        .digest("hex"),
      markdownSha256: createHash("sha256")
        .update(markdown)
        .digest("hex"),
      schema: VERDICT_COMPLETION_SCHEMA,
    })}\n`,
    "utf8",
  );
  const paths = Object.fromEntries(
    Object.entries(VERDICT_FILES).map(([key, name]) => [
      key,
      `${output}/${name}`,
    ]),
  );
  const temporaryPaths = Object.fromEntries(
    Object.entries(paths).map(([key, path]) => [
      key,
      `${path}.tmp`,
    ]),
  );
  let directoryHandle;
  let createdOutput = false;
  try {
    await fileSystem.mkdir(output, { mode: 0o700 });
    createdOutput = true;
    const metadata = await fileSystem.lstat(output);
    if (
      typeof metadata?.isDirectory !== "function" ||
      !metadata.isDirectory() ||
      (
        process.platform !== "win32" &&
        (
          (metadata.mode & 0o777) !== 0o700 ||
          (
            typeof process.getuid === "function" &&
            Number.isSafeInteger(metadata.uid) &&
            metadata.uid !== process.getuid()
          )
        )
      )
    ) {
      throw new BilateralVerdictError();
    }
    directoryHandle = await fileSystem.open(
      output,
      DIRECTORY_FLAGS,
    );
    if (
      directoryHandle === null ||
      typeof directoryHandle !== "object" ||
      typeof directoryHandle.stat !== "function" ||
      typeof directoryHandle.sync !== "function" ||
      typeof directoryHandle.close !== "function"
    ) {
      throw new BilateralVerdictError();
    }
    const openedMetadata = await directoryHandle.stat();
    if (
      openedMetadata.dev !== metadata.dev ||
      openedMetadata.ino !== metadata.ino ||
      openedMetadata.mode !== metadata.mode ||
      openedMetadata.nlink !== metadata.nlink ||
      openedMetadata.uid !== metadata.uid ||
      openedMetadata.gid !== metadata.gid ||
      openedMetadata.rdev !== metadata.rdev
    ) {
      throw new BilateralVerdictError();
    }
    for (const [key, bytes] of [
      ["json", json],
      ["markdown", markdown],
      ["marker", marker],
    ]) {
      await writeDurableTemporaryFile(
        temporaryPaths[key],
        bytes,
        fileSystem,
      );
      await fileSystem.rename(
        temporaryPaths[key],
        paths[key],
      );
      await directoryHandle.sync();
    }
    await directoryHandle.close();
    directoryHandle = undefined;
  } catch (error) {
    if (createdOutput) {
      await revokePublication(
        output,
        fileSystem,
        directoryHandle,
        temporaryPaths,
      );
    }
    if (error instanceof BilateralVerdictError) {
      throw error;
    }
    throw new BilateralVerdictError();
  }
}

async function writeDurableTemporaryFile(
  path,
  bytes,
  fileSystem,
) {
  let handle;
  let failure;
  try {
    handle = await fileSystem.open(
      path,
      EXCLUSIVE_WRITE_FLAGS,
      0o600,
    );
    if (
      handle === null ||
      typeof handle !== "object" ||
      typeof handle.writeFile !== "function" ||
      typeof handle.sync !== "function" ||
      typeof handle.close !== "function"
    ) {
      throw new BilateralVerdictError();
    }
    await handle.writeFile(bytes);
    await handle.sync();
  } catch (error) {
    failure = error;
  }
  if (handle !== undefined) {
    try {
      await handle.close();
    } catch (error) {
      failure ??= error;
    }
  }
  if (failure !== undefined) {
    throw failure;
  }
}

async function revokePublication(
  output,
  fileSystem,
  directoryHandle,
  temporaryPaths = {},
) {
  let markerRemoved = false;
  try {
    await fileSystem.rm(
      `${output}/${VERDICT_FILES.marker}`,
      { force: true },
    );
    markerRemoved = true;
    for (const path of Object.values(temporaryPaths)) {
      await fileSystem.rm(path, { force: true });
    }
  } catch {
    // The authorizing marker removal was attempted first. Preserve the
    // original fixed failure rather than echoing filesystem details.
  }
  try {
    await directoryHandle?.close();
  } catch {
    // A fresh handle below owns the durability check.
  }
  if (!markerRemoved) {
    return;
  }
  let cleanupHandle;
  try {
    cleanupHandle = await fileSystem.open(
      output,
      DIRECTORY_FLAGS,
    );
    if (
      cleanupHandle === null ||
      typeof cleanupHandle !== "object" ||
      typeof cleanupHandle.sync !== "function" ||
      typeof cleanupHandle.close !== "function"
    ) {
      return;
    }
    await cleanupHandle.sync();
  } catch {
    // Failure remains fixed and non-authorizing.
  } finally {
    try {
      await cleanupHandle?.close();
    } catch {
      // Failure remains fixed and non-authorizing.
    }
  }
}

export async function main(
  arguments_ = process.argv.slice(2),
  dependencies = {},
) {
  let active;
  let completedOutput;
  try {
    active = activeDependencies(dependencies);
    const values = parseArguments(arguments_);
    const input = await active.buildVerifierInput(values);
    const verdict = await active.verify(input);
    await publishVerdict(
      verdict,
      values.output,
      active.fileSystem,
    );
    completedOutput = values.output;
    if (
      active.beforeAuthorizationOutput !== null
    ) {
      await active.beforeAuthorizationOutput(
        Object.freeze({
          output: values.output,
          verdict,
        }),
      );
    }
    active.stdout.write("AUTHORIZED\n");
    return 0;
  } catch (error) {
    if (active !== undefined && completedOutput !== undefined) {
      await revokePublication(
        completedOutput,
        active.fileSystem,
      );
    }
    const terminalCode =
      error instanceof BilateralVerdictError
        ? error.terminalCode
        : "FAILED";
    const stdout =
      active?.stdout ?? dependencies.stdout ?? process.stdout;
    const stderr =
      active?.stderr ?? dependencies.stderr ?? process.stderr;
    try {
      stdout.write(fixedFailure(terminalCode));
      stderr.write("BILATERAL_VERDICT_FAILED\n");
    } catch {
      return 1;
    }
    return 1;
  }
}

if (
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  process.exitCode = await main();
}
