import { randomBytes } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import {
  link,
  lstat,
  mkdir,
  open,
  readdir,
  realpath,
  rename,
  unlink,
} from "node:fs/promises";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";
import { fileURLToPath } from "node:url";

import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

import { encryptInvitation } from "../src/invitation.mjs";

const ID_PATTERN =
  /^(?=.{1,32}$)[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/u;
const MAX_DISPLAY_NAME_LENGTH = 128;
const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001f\u007f-\u009f]/u;
const WRITE_FLAGS =
  fsConstants.O_WRONLY |
  fsConstants.O_CREAT |
  fsConstants.O_EXCL |
  (fsConstants.O_NOFOLLOW ?? 0);
const READ_FLAGS =
  fsConstants.O_RDONLY |
  (fsConstants.O_NOFOLLOW ?? 0) |
  (fsConstants.O_NONBLOCK ?? 0);
const DIRECTORY_READ_FLAGS =
  fsConstants.O_RDONLY |
  (fsConstants.O_DIRECTORY ?? 0) |
  (fsConstants.O_NOFOLLOW ?? 0);
const LOCK_FILENAME = ".handshake-invitations.lock";
const DEFAULT_FILE_SYSTEM = Object.freeze({
  link,
  lstat,
  mkdir,
  open,
  readdir,
  realpath,
  rename,
  unlink,
});

class InvitationCreationError extends Error {
  constructor() {
    super("Invitation creation failed safely.");
    this.name = "InvitationCreationError";
  }
}

function fail() {
  throw new InvitationCreationError();
}

function parseArguments(arguments_) {
  const values = new Map();
  let force = false;

  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];

    if (argument === "--force") {
      if (force) {
        fail();
      }
      force = true;
      continue;
    }

    if (
      argument !== "--output-public" &&
      argument !== "--output-secret" &&
      argument !== "--ids" &&
      argument !== "--names"
    ) {
      fail();
    }

    if (values.has(argument) || index + 1 >= arguments_.length) {
      fail();
    }

    const value = arguments_[index + 1];
    if (
      typeof value !== "string" ||
      value.length === 0 ||
      value.startsWith("--")
    ) {
      fail();
    }
    values.set(argument, value);
    index += 1;
  }

  const required = [
    "--output-public",
    "--output-secret",
    "--ids",
    "--names",
  ];
  if (!required.every((key) => values.has(key))) {
    fail();
  }

  const ids = parseList(values.get("--ids"));
  const names = parseList(values.get("--names"));
  if (
    ids.length === 0 ||
    ids.length !== names.length ||
    new Set(ids).size !== ids.length ||
    !ids.every((id) => ID_PATTERN.test(id)) ||
    !names.every(isSafeDisplayName)
  ) {
    fail();
  }

  return {
    force,
    ids,
    names,
    publicDirectory: resolve(values.get("--output-public")),
    secretDirectory: resolve(values.get("--output-secret")),
  };
}

function parseList(value) {
  const parts = value.split(",");
  if (
    parts.some(
      (part) => part.length === 0 || part !== part.trim(),
    )
  ) {
    fail();
  }
  return parts;
}

function isSafeDisplayName(value) {
  return (
    value.length > 0 &&
    value.length <= MAX_DISPLAY_NAME_LENGTH &&
    value === value.trim() &&
    !CONTROL_CHARACTER_PATTERN.test(value)
  );
}

async function inspectDirectory(path, fileSystem) {
  try {
    const metadata = await fileSystem.lstat(path);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      fail();
    }
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") {
      return false;
    }
    if (error instanceof InvitationCreationError) {
      throw error;
    }
    fail();
  }
}

async function prepareDirectories(
  publicDirectory,
  secretDirectory,
  fileSystem,
) {
  const publicExists = await inspectDirectory(
    publicDirectory,
    fileSystem,
  );
  const secretExists =
    secretDirectory === publicDirectory
      ? publicExists
      : await inspectDirectory(secretDirectory, fileSystem);

  if (!publicExists) {
    await createDirectory(publicDirectory, 0o755, fileSystem);
  }
  if (!secretExists && secretDirectory !== publicDirectory) {
    await createDirectory(secretDirectory, 0o700, fileSystem);
  }
}

async function createDirectory(path, mode, fileSystem) {
  try {
    await fileSystem.mkdir(path, { recursive: true, mode });
  } catch {
    fail();
  }
  if (!(await inspectDirectory(path, fileSystem))) {
    fail();
  }
}

function isSameOrNestedDirectory(parent, candidate) {
  const pathFromParent = relative(parent, candidate);
  return (
    pathFromParent === "" ||
    (pathFromParent !== ".." &&
      !pathFromParent.startsWith(`..${sep}`) &&
      !isAbsolute(pathFromParent))
  );
}

function assertSeparatedDirectories(
  publicDirectory,
  secretDirectory,
) {
  if (
    isSameOrNestedDirectory(publicDirectory, secretDirectory) ||
    isSameOrNestedDirectory(secretDirectory, publicDirectory)
  ) {
    fail();
  }
}

async function canonicalOutputDirectories(
  publicDirectory,
  secretDirectory,
  fileSystem,
) {
  try {
    const [canonicalPublic, canonicalSecret] = await Promise.all([
      fileSystem.realpath(publicDirectory),
      fileSystem.realpath(secretDirectory),
    ]);
    const [publicMetadata, secretMetadata] = await Promise.all([
      fileSystem.lstat(canonicalPublic),
      fileSystem.lstat(canonicalSecret),
    ]);
    if (
      !publicMetadata.isDirectory() ||
      publicMetadata.isSymbolicLink() ||
      !secretMetadata.isDirectory() ||
      secretMetadata.isSymbolicLink() ||
      (publicMetadata.dev === secretMetadata.dev &&
        publicMetadata.ino === secretMetadata.ino)
    ) {
      fail();
    }
    assertSeparatedDirectories(canonicalPublic, canonicalSecret);
    return {
      publicDirectory: canonicalPublic,
      secretDirectory: canonicalSecret,
    };
  } catch (error) {
    if (error instanceof InvitationCreationError) {
      throw error;
    }
    fail();
  }
}

async function inspectTarget(path, force, fileSystem) {
  try {
    const metadata = await fileSystem.lstat(path);
    if (
      !force ||
      !metadata.isFile() ||
      metadata.isSymbolicLink()
    ) {
      fail();
    }
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") {
      return false;
    }
    if (error instanceof InvitationCreationError) {
      throw error;
    }
    fail();
  }
}

async function preflightTargets(targets, force, fileSystem) {
  for (const target of targets) {
    target.existed = await inspectTarget(
      target.path,
      force,
      fileSystem,
    );
  }
}

function temporaryPath(path, purpose) {
  return join(
    dirname(path),
    `.${basename(path)}.${process.pid}.${randomBytes(12).toString("hex")}.${purpose}`,
  );
}

function isTransactionArtifact(name) {
  return (
    name.endsWith(".tmp") ||
    name.endsWith(".bak") ||
    name.endsWith(".lock")
  );
}

async function assertCleanOutputDirectory(
  path,
  role,
  fileSystem,
) {
  let entries;
  try {
    entries = await fileSystem.readdir(path, {
      withFileTypes: true,
    });
  } catch {
    fail();
  }

  for (const entry of entries) {
    if (entry.name === LOCK_FILENAME) {
      if (!entry.isFile() || entry.isSymbolicLink()) {
        fail();
      }
      continue;
    }
    if (
      isTransactionArtifact(entry.name) ||
      (role === "public" &&
        entry.name.endsWith(".secret.json")) ||
      (role === "secret" &&
        entry.name.endsWith(".enc.json"))
    ) {
      fail();
    }
  }
}

async function assertCleanOutputDirectories(
  publicDirectory,
  secretDirectory,
  fileSystem,
) {
  await assertCleanOutputDirectory(
    publicDirectory,
    "public",
    fileSystem,
  );
  await assertCleanOutputDirectory(
    secretDirectory,
    "secret",
    fileSystem,
  );
}

async function syncDirectories(directories, fileSystem) {
  for (const directory of [...new Set(directories)].sort()) {
    let fileHandle;
    try {
      fileHandle = await fileSystem.open(
        directory,
        DIRECTORY_READ_FLAGS,
      );
      await fileHandle.sync();
      await fileHandle.close();
      fileHandle = undefined;
    } catch (error) {
      if (fileHandle !== undefined) {
        try {
          await fileHandle.close();
        } catch {
          // The public CLI still emits only its fixed safe failure.
        }
      }
      if (error instanceof InvitationCreationError) {
        throw error;
      }
      fail();
    }
  }
}

async function releaseBatchLocks(locks, fileSystem) {
  let firstError;
  for (const lock of [...locks].reverse()) {
    try {
      await lock.fileHandle.close();
    } catch (error) {
      firstError ??= error;
    }
    try {
      await fileSystem.unlink(lock.path);
    } catch (error) {
      firstError ??= error;
    }
  }

  try {
    await syncDirectories(
      locks.map(({ directory }) => directory),
      fileSystem,
    );
  } catch (error) {
    firstError ??= error;
  }
  return firstError;
}

async function acquireBatchLocks(directories, fileSystem) {
  const locks = [];
  const orderedDirectories = [...new Set(directories)].sort();

  try {
    for (const directory of orderedDirectories) {
      const path = join(directory, LOCK_FILENAME);
      const fileHandle = await fileSystem.open(
        path,
        WRITE_FLAGS,
        0o600,
      );
      const lock = { directory, fileHandle, path };
      locks.push(lock);
      await fileHandle.chmod(0o600);
      await fileHandle.writeFile(
        `${JSON.stringify({
          schema: "clockchain.handshake-invitation-lock/v1",
          pid: process.pid,
        })}\n`,
        "utf8",
      );
      await fileHandle.sync();
    }
    await syncDirectories(orderedDirectories, fileSystem);
    return locks;
  } catch {
    await releaseBatchLocks(locks, fileSystem);
    fail();
  }
}

async function withBatchLocks(directories, fileSystem, operation) {
  const locks = await acquireBatchLocks(directories, fileSystem);
  let result;
  let operationError;
  try {
    result = await operation();
  } catch (error) {
    operationError = error;
  }

  const releaseError = await releaseBatchLocks(locks, fileSystem);
  if (
    operationError instanceof InvitationCreationError &&
    releaseError === undefined
  ) {
    throw operationError;
  }
  if (operationError !== undefined || releaseError !== undefined) {
    fail();
  }
  return result;
}

async function stageTarget(target, fileSystem) {
  const temporary = temporaryPath(target.path, "tmp");
  let fileHandle;

  try {
    fileHandle = await fileSystem.open(
      temporary,
      WRITE_FLAGS,
      target.mode,
    );
    await fileHandle.writeFile(target.contents, "utf8");
    await fileHandle.chmod(target.mode);
    await fileHandle.sync();
    await fileHandle.close();
    fileHandle = undefined;
    target.temporary = temporary;
  } catch (error) {
    if (fileHandle !== undefined) {
      try {
        await fileHandle.close();
      } catch {
        // The public CLI still emits only its fixed safe failure.
      }
    }
    try {
      await fileSystem.unlink(temporary);
    } catch {
      // The temporary may not have been created.
    }
    if (error instanceof InvitationCreationError) {
      throw error;
    }
    fail();
  }
}

async function removePaths(paths, fileSystem) {
  let firstError;

  for (const path of paths) {
    if (path === undefined) {
      continue;
    }
    try {
      await fileSystem.unlink(path);
    } catch (error) {
      if (error?.code !== "ENOENT" && firstError === undefined) {
        firstError = error;
      }
    }
  }

  return firstError;
}

function sameFileMetadata(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.mode === right.mode
  );
}

async function readPublishedTarget(target, fileSystem) {
  let fileHandle;
  try {
    fileHandle = await fileSystem.open(target.path, READ_FLAGS);
    const metadata = await fileHandle.stat();
    if (
      !metadata.isFile() ||
      (metadata.mode & 0o777) !== target.mode ||
      metadata.size !== Buffer.byteLength(target.contents, "utf8")
    ) {
      fail();
    }
    const contents = await fileHandle.readFile("utf8");
    const finalMetadata = await fileHandle.stat();
    if (
      contents !== target.contents ||
      !sameFileMetadata(metadata, finalMetadata)
    ) {
      fail();
    }
    return JSON.parse(contents);
  } catch (error) {
    if (error instanceof InvitationCreationError) {
      throw error;
    }
    fail();
  } finally {
    if (fileHandle !== undefined) {
      try {
        await fileHandle.close();
      } catch {
        fail();
      }
    }
  }
}

async function verifyPublishedTargets(targets, fileSystem) {
  const documents = new Map();
  for (const target of targets) {
    documents.set(
      `${target.id}:${target.kind}`,
      await readPublishedTarget(target, fileSystem),
    );
  }

  for (const id of new Set(targets.map((target) => target.id))) {
    const secret = documents.get(`${id}:secret`);
    const publicBundle = documents.get(`${id}:public`);
    if (
      secret === undefined ||
      publicBundle === undefined ||
      JSON.stringify(secret.bundle) !== JSON.stringify(publicBundle)
    ) {
      fail();
    }
  }
}

async function prepareBackups(targets, fileSystem) {
  for (const target of targets) {
    if (!target.existed) {
      continue;
    }

    if (!(await inspectTarget(target.path, true, fileSystem))) {
      fail();
    }
    const backup = temporaryPath(target.path, "bak");
    await fileSystem.link(target.path, backup);
    target.backup = backup;
    const metadata = await fileSystem.lstat(backup);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      await removePaths([backup], fileSystem);
      target.backup = undefined;
      fail();
    }
  }
}

async function assertTargetState(target, fileSystem) {
  if (target.existed) {
    if (!(await inspectTarget(target.path, true, fileSystem))) {
      fail();
    }
    return;
  }

  await inspectTarget(target.path, false, fileSystem);
}

async function publishTargets(targets, force, fileSystem) {
  const published = [];
  const directories = targets.map(({ path }) => dirname(path));

  try {
    if (force) {
      await prepareBackups(targets, fileSystem);
    }
    await syncDirectories(directories, fileSystem);

    for (const target of targets) {
      if (force) {
        await assertTargetState(target, fileSystem);
        await fileSystem.rename(target.temporary, target.path);
      } else {
        await fileSystem.link(target.temporary, target.path);
      }
      target.published = true;
      published.push(target);
    }
    await syncDirectories(directories, fileSystem);
    await verifyPublishedTargets(targets, fileSystem);
  } catch (publicationError) {
    let rollbackError;
    for (const target of published.reverse()) {
      try {
        if (target.backup !== undefined) {
          await fileSystem.rename(target.backup, target.path);
          target.backup = undefined;
        } else {
          await fileSystem.unlink(target.path);
        }
        target.published = false;
      } catch (error) {
        rollbackError ??= error;
      }
    }

    const recoveryBackups = new Set(
      targets
        .filter((target) => target.published)
        .map((target) => target.backup),
    );
    const cleanupError = await removePaths(
      [
        ...targets.map((target) => target.temporary),
        ...targets
          .map((target) => target.backup)
          .filter((path) => !recoveryBackups.has(path)),
      ],
      fileSystem,
    );
    let syncError;
    try {
      await syncDirectories(directories, fileSystem);
    } catch (error) {
      syncError = error;
    }

    if (
      publicationError instanceof InvitationCreationError &&
      rollbackError === undefined &&
      cleanupError === undefined &&
      syncError === undefined
    ) {
      throw publicationError;
    }
    fail();
  }

  const cleanupError = await removePaths(
    [
      ...targets.map((target) => target.temporary),
      ...targets.map((target) => target.backup),
    ],
    fileSystem,
  );
  if (cleanupError !== undefined) {
    fail();
  }
  await syncDirectories(directories, fileSystem);
}

async function writeInvitationBatch(targets, force, fileSystem) {
  try {
    for (const target of targets) {
      await stageTarget(target, fileSystem);
    }
    await publishTargets(targets, force, fileSystem);
  } catch (error) {
    const recoveryBackups = new Set(
      targets
        .filter((target) => target.published)
        .map((target) => target.backup),
    );
    const cleanupError = await removePaths(
      [
        ...targets.map((target) => target.temporary),
        ...targets
          .map((target) => target.backup)
          .filter((path) => !recoveryBackups.has(path)),
      ],
      fileSystem,
    );
    let syncError;
    try {
      await syncDirectories(
        targets.map(({ path }) => dirname(path)),
        fileSystem,
      );
    } catch (caught) {
      syncError = caught;
    }
    if (
      error instanceof InvitationCreationError &&
      cleanupError === undefined &&
      syncError === undefined
    ) {
      throw error;
    }
    fail();
  }
}

async function createDistinctInvitation({
  displayName,
  usedAddresses,
  usedCodes,
}) {
  for (let attempt = 0; attempt < 16; attempt += 1) {
    const privateKey = generatePrivateKey();
    const address = privateKeyToAccount(privateKey).address;
    const code = randomBytes(32).toString("hex");

    if (
      usedAddresses.has(address.toLowerCase()) ||
      usedCodes.has(code)
    ) {
      continue;
    }

    const bundle = await encryptInvitation(
      { privateKey, address, displayName },
      code,
    );
    usedAddresses.add(address.toLowerCase());
    usedCodes.add(code);
    return { address, bundle, code };
  }

  fail();
}

async function createInvitations(configuration, fileSystem) {
  const {
    force,
    ids,
    names,
    publicDirectory: requestedPublicDirectory,
    secretDirectory: requestedSecretDirectory,
  } = configuration;

  assertSeparatedDirectories(
    requestedPublicDirectory,
    requestedSecretDirectory,
  );
  await prepareDirectories(
    requestedPublicDirectory,
    requestedSecretDirectory,
    fileSystem,
  );
  const { publicDirectory, secretDirectory } =
    await canonicalOutputDirectories(
      requestedPublicDirectory,
      requestedSecretDirectory,
      fileSystem,
    );

  return withBatchLocks(
    [publicDirectory, secretDirectory],
    fileSystem,
    async () => {
      await assertCleanOutputDirectories(
        publicDirectory,
        secretDirectory,
        fileSystem,
      );
      const targets = ids.flatMap((id) => [
        {
          id,
          kind: "secret",
          mode: 0o600,
          path: join(secretDirectory, `${id}.secret.json`),
        },
        {
          id,
          kind: "public",
          mode: 0o644,
          path: join(publicDirectory, `${id}.enc.json`),
        },
      ]);
      await preflightTargets(targets, force, fileSystem);

      const usedAddresses = new Set();
      const usedCodes = new Set();
      const invitations = [];
      for (let index = 0; index < ids.length; index += 1) {
        invitations.push({
          id: ids[index],
          ...(await createDistinctInvitation({
            displayName: names[index],
            usedAddresses,
            usedCodes,
          })),
        });
      }

      for (
        let index = 0;
        index < invitations.length;
        index += 1
      ) {
        const invitation = invitations[index];
        targets[index * 2].contents = `${JSON.stringify(
          {
            bundle: invitation.bundle,
            code: invitation.code,
          },
          null,
          2,
        )}\n`;
        targets[index * 2 + 1].contents = `${JSON.stringify(
          invitation.bundle,
          null,
          2,
        )}\n`;
      }

      await writeInvitationBatch(targets, force, fileSystem);
      await assertCleanOutputDirectories(
        publicDirectory,
        secretDirectory,
        fileSystem,
      );

      return {
        created: invitations.map(({ id, address }) => ({
          id,
          address,
        })),
      };
    },
  );
}

export async function main(
  arguments_ = process.argv.slice(2),
  { fileSystem: fileSystemOverrides = {} } = {},
) {
  const configuration = parseArguments(arguments_);
  const fileSystem = {
    ...DEFAULT_FILE_SYSTEM,
    ...fileSystemOverrides,
  };
  return createInvitations(configuration, fileSystem);
}

const isEntryPoint =
  process.argv[1] !== undefined &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isEntryPoint) {
  try {
    const report = await main();
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } catch {
    process.stderr.write("Invitation creation failed safely.\n");
    process.exitCode = 1;
  }
}
