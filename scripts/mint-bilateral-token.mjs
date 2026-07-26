import { execFile } from "node:child_process";
import { constants as fsConstants } from "node:fs";
import {
  lstat,
  mkdir,
  open,
} from "node:fs/promises";
import {
  basename,
  dirname,
  join,
} from "node:path";
import {
  fileURLToPath,
  pathToFileURL,
} from "node:url";
import { promisify } from "node:util";

import { canonicalBytes } from "../src/bilateral/canonical.mjs";
import { mintDemoToken } from "../src/mcp.mjs";

export const TOKEN_MINT_REPOSITORY_ROOT = dirname(
  dirname(fileURLToPath(import.meta.url)),
);

const REPOSITORY_SHA_PATTERN = /^[0-9a-f]{40}$/;
const TOKEN_PATTERN = /^[!-~]{1,4096}$/;
const ROLES = Object.freeze([
  "payer",
  "payee",
  "operator",
]);
const DIRECTORY_FLAGS =
  fsConstants.O_RDONLY |
  (fsConstants.O_DIRECTORY ?? 0) |
  (fsConstants.O_NOFOLLOW ?? 0);
const execFileAsync = promisify(execFile);
const DEFAULT_FILE_SYSTEM = Object.freeze({
  lstat,
  mkdir,
  open,
});

export class BilateralTokenMintError extends Error {
  constructor() {
    super("Bilateral token mint failed safely.");
    this.name = "BilateralTokenMintError";
    this.code = "BILATERAL_TOKEN_MINT_FAILED";
  }
}

function fail() {
  throw new BilateralTokenMintError();
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object") {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, keys) {
  return (
    isPlainObject(value) &&
    Reflect.ownKeys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key))
  );
}

function parseArguments(arguments_) {
  if (
    !Array.isArray(arguments_) ||
    arguments_.length !== 6
  ) {
    fail();
  }
  const allowed = new Set([
    "--role",
    "--output",
    "--repository-sha",
  ]);
  const values = new Map();
  for (
    let index = 0;
    index < arguments_.length;
    index += 2
  ) {
    const key = arguments_[index];
    const value = arguments_[index + 1];
    if (
      !allowed.has(key) ||
      values.has(key) ||
      typeof value !== "string" ||
      value.length === 0 ||
      value.length > 4096 ||
      value.includes("\0") ||
      value.startsWith("--")
    ) {
      fail();
    }
    values.set(key, value);
  }
  const role = values.get("--role");
  const outputPath = values.get("--output");
  const repositorySha = values.get("--repository-sha");
  if (
    values.size !== allowed.size ||
    !ROLES.includes(role) ||
    !REPOSITORY_SHA_PATTERN.test(repositorySha)
  ) {
    fail();
  }
  return { outputPath, repositorySha, role };
}

async function defaultRepositoryStateResolver({
  repositoryRoot,
}) {
  try {
    const [head, status] = await Promise.all([
      execFileAsync("git", ["rev-parse", "HEAD"], {
        cwd: repositoryRoot,
        encoding: "utf8",
        maxBuffer: 128,
      }),
      execFileAsync(
        "git",
        [
          "status",
          "--porcelain=v1",
          "--untracked-files=all",
        ],
        {
          cwd: repositoryRoot,
          encoding: "utf8",
          maxBuffer: 1_048_576,
        },
      ),
    ]);
    return {
      headSha: head.stdout.trim(),
      worktreeStatus: status.stdout,
    };
  } catch {
    fail();
  }
}

async function verifyRepositoryState(
  repositorySha,
  resolver,
) {
  let state;
  try {
    state = await resolver({
      repositoryRoot: TOKEN_MINT_REPOSITORY_ROOT,
    });
  } catch (error) {
    if (error instanceof BilateralTokenMintError) {
      throw error;
    }
    fail();
  }
  if (
    !exactKeys(state, ["headSha", "worktreeStatus"]) ||
    state.headSha !== repositorySha ||
    state.worktreeStatus !== ""
  ) {
    fail();
  }
}

function activeFileSystem(dependencies) {
  const fileSystem =
    dependencies.fileSystem ?? DEFAULT_FILE_SYSTEM;
  if (
    !isPlainObject(fileSystem) ||
    ["lstat", "mkdir", "open"].some(
      (name) => typeof fileSystem[name] !== "function",
    )
  ) {
    fail();
  }
  return fileSystem;
}

function isPrivateDirectory(metadata, nofollow = false) {
  return (
    metadata.isDirectory() &&
    (
      !nofollow ||
      typeof metadata.isSymbolicLink !== "function" ||
      !metadata.isSymbolicLink()
    ) &&
    (
      process.platform === "win32" ||
      (metadata.mode & 0o777) === 0o700
    )
  );
}

function sameDirectoryIdentity(metadata, pinned) {
  return (
    metadata.dev === pinned.dev &&
    metadata.ino === pinned.ino &&
    metadata.mode === pinned.mode
  );
}

async function pinPrivateDirectory(path, fileSystem) {
  let metadata;
  let handle;
  let pinned;
  try {
    metadata = await fileSystem.lstat(path);
  } catch (error) {
    if (error?.code !== "ENOENT") {
      fail();
    }
    try {
      await fileSystem.mkdir(path, {
        mode: 0o700,
        recursive: false,
      });
      metadata = await fileSystem.lstat(path);
    } catch {
      fail();
    }
  }
  if (
    !isPrivateDirectory(metadata, true)
  ) {
    fail();
  }
  try {
    handle = await fileSystem.open(path, DIRECTORY_FLAGS);
    const opened = await handle.stat();
    const current = await fileSystem.lstat(path);
    pinned = {
      dev: metadata.dev,
      handle,
      ino: metadata.ino,
      mode: metadata.mode,
      path,
    };
    if (
      !isPrivateDirectory(opened) ||
      !isPrivateDirectory(current, true) ||
      !sameDirectoryIdentity(opened, pinned) ||
      !sameDirectoryIdentity(current, pinned)
    ) {
      fail();
    }
    return pinned;
  } catch (error) {
    if (error instanceof BilateralTokenMintError) {
      throw error;
    }
    fail();
  } finally {
    if (pinned === undefined && handle !== undefined) {
      try {
        await handle.close();
      } catch {
        fail();
      }
    }
  }
}

async function assertPinnedDirectory(
  pinned,
  fileSystem,
) {
  try {
    const [opened, current] = await Promise.all([
      pinned.handle.stat(),
      fileSystem.lstat(pinned.path),
    ]);
    if (
      !isPrivateDirectory(opened) ||
      !isPrivateDirectory(current, true) ||
      !sameDirectoryIdentity(opened, pinned) ||
      !sameDirectoryIdentity(current, pinned)
    ) {
      fail();
    }
  } catch (error) {
    if (error instanceof BilateralTokenMintError) {
      throw error;
    }
    fail();
  }
}

async function syncPinnedDirectory(
  pinned,
  fileSystem,
) {
  await assertPinnedDirectory(pinned, fileSystem);
  try {
    await pinned.handle.sync();
  } catch {
    fail();
  }
  await assertPinnedDirectory(pinned, fileSystem);
}

async function writeExclusive(
  pinned,
  path,
  bytes,
  fileSystem,
) {
  if (
    dirname(path) !== pinned.path ||
    !Buffer.isBuffer(bytes)
  ) {
    fail();
  }
  let handle;
  let failure;
  try {
    await assertPinnedDirectory(pinned, fileSystem);
    handle = await fileSystem.open(path, "wx", 0o600);
    await assertPinnedDirectory(pinned, fileSystem);
    const metadata = await handle.stat();
    if (
      !metadata.isFile() ||
      (
        process.platform !== "win32" &&
        (metadata.mode & 0o777) !== 0o600
      )
    ) {
      fail();
    }
    await handle.writeFile(bytes);
    await handle.sync();
    await assertPinnedDirectory(pinned, fileSystem);
  } catch (error) {
    failure =
      error instanceof BilateralTokenMintError
        ? error
        : new BilateralTokenMintError();
  } finally {
    if (handle !== undefined) {
      try {
        await handle.close();
      } catch {
        failure ??= new BilateralTokenMintError();
      }
    }
  }
  if (failure !== undefined) {
    throw failure;
  }
  await assertPinnedDirectory(pinned, fileSystem);
  await syncPinnedDirectory(pinned, fileSystem);
}

async function assertAbsent(
  pinned,
  path,
  fileSystem,
) {
  if (dirname(path) !== pinned.path) {
    fail();
  }
  await assertPinnedDirectory(pinned, fileSystem);
  try {
    await fileSystem.lstat(path);
  } catch (error) {
    if (error?.code === "ENOENT") {
      await assertPinnedDirectory(pinned, fileSystem);
      return;
    }
    fail();
  }
  fail();
}

export async function main(
  arguments_ = process.argv.slice(2),
  dependencies = {},
) {
  if (!isPlainObject(dependencies)) {
    fail();
  }
  const configuration = parseArguments(arguments_);
  const repositoryStateResolver =
    dependencies.repositoryStateResolver ??
    defaultRepositoryStateResolver;
  const mintToken =
    dependencies.mintToken ?? mintDemoToken;
  const fileSystem = activeFileSystem(dependencies);
  if (
    typeof repositoryStateResolver !== "function" ||
    typeof mintToken !== "function"
  ) {
    fail();
  }
  await verifyRepositoryState(
    configuration.repositorySha,
    repositoryStateResolver,
  );
  const parent = dirname(configuration.outputPath);
  let pinned;
  let failure;
  let result;
  try {
    pinned = await pinPrivateDirectory(
      parent,
      fileSystem,
    );
    const intentPath = join(
      parent,
      `.${basename(configuration.outputPath)}.mint-intent.json`,
    );
    await assertAbsent(
      pinned,
      configuration.outputPath,
      fileSystem,
    );
    await assertAbsent(pinned, intentPath, fileSystem);
    await writeExclusive(
      pinned,
      intentPath,
      canonicalBytes({
        repositorySha: configuration.repositorySha,
        role: configuration.role,
        schema:
          "clockchain.bilateral-token-mint-intent/v1",
      }),
      fileSystem,
    );
    let token;
    try {
      token = await mintToken({
        subject:
          `bilateral-${configuration.role}-` +
          configuration.repositorySha,
      });
    } catch {
      fail();
    }
    if (
      typeof token !== "string" ||
      !TOKEN_PATTERN.test(token)
    ) {
      fail();
    }
    await writeExclusive(
      pinned,
      configuration.outputPath,
      Buffer.from(token, "utf8"),
      fileSystem,
    );
    result = Object.freeze({
      role: configuration.role,
      status: "TOKEN_READY",
    });
  } catch (error) {
    failure =
      error instanceof BilateralTokenMintError
        ? error
        : new BilateralTokenMintError();
  } finally {
    if (pinned !== undefined) {
      try {
        await pinned.handle.close();
      } catch {
        failure ??= new BilateralTokenMintError();
      }
    }
  }
  if (failure !== undefined) {
    throw failure;
  }
  return result;
}

export async function runCli(
  arguments_ = process.argv.slice(2),
  dependencies = {},
) {
  const output =
    dependencies.output ??
    ((line) => process.stdout.write(line));
  const writeError =
    dependencies.writeError ??
    ((line) => process.stderr.write(line));
  try {
    await main(arguments_, dependencies);
    output("TOKEN_READY\n");
    return 0;
  } catch {
    writeError("Bilateral token mint failed safely.\n");
    return 1;
  }
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  process.exitCode = await runCli();
}
