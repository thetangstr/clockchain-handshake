import { execFile } from "node:child_process";
import {
  createHash,
  randomUUID,
} from "node:crypto";
import { constants as fsConstants } from "node:fs";
import {
  lstat,
  mkdir,
  open,
  rename,
  rm,
} from "node:fs/promises";
import {
  dirname,
  join,
} from "node:path";
import {
  fileURLToPath,
  pathToFileURL,
} from "node:url";
import { promisify } from "node:util";

import { canonicalBytes } from "../src/bilateral/canonical.mjs";
import {
  CHAIN_ID,
  REGISTRY_ADDRESS,
} from "../src/constants.mjs";
import {
  decryptInvitation,
} from "../src/invitation.mjs";
import {
  PartialRegistrationError,
  finalizeIdentityRegistration,
  registerIdentity,
} from "../src/registration.mjs";
import {
  INTENT_SCHEMA,
  RECOVERY_SCHEMA,
  validateRecovery,
  validateRegistrationIntent,
} from "../src/registration-internal.mjs";
import { assertSecretFree } from "../src/redact.mjs";

export const REGISTRATION_REPOSITORY_ROOT = dirname(
  dirname(fileURLToPath(import.meta.url)),
);
export const IDENTITY_ARTIFACT_SCHEMA =
  "clockchain.bilateral-identity-registration/v1";

const COMPLETION_SCHEMA =
  "clockchain.bilateral-identity-registration-completion/v1";
const PUBLICATION_CHECKPOINT_SCHEMA =
  "clockchain.bilateral-identity-registration-publication/v1";
const IDENTITY_FILE = "identity.json";
const COMPLETION_FILE = ".identity.complete.json";
const CHECKPOINT_FILE = "registration-checkpoint.json";
const MAX_INVITATION_BYTES = 16_384;
const MAX_CHECKPOINT_BYTES = 32_768;
const MAX_IDENTITY_BYTES = 32_768;
const REPOSITORY_SHA_PATTERN = /^[0-9a-f]{40}$/;
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/i;
const TRANSACTION_PATTERN = /^0x[0-9a-f]{64}$/i;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const READ_FLAGS =
  fsConstants.O_RDONLY |
  (fsConstants.O_NOFOLLOW ?? 0) |
  (fsConstants.O_NONBLOCK ?? 0);
const DIRECTORY_FLAGS =
  fsConstants.O_RDONLY |
  (fsConstants.O_DIRECTORY ?? 0) |
  (fsConstants.O_NOFOLLOW ?? 0);
const RISK_FLAG =
  "--i-understand-this-writes-to-sepolia";
const execFileAsync = promisify(execFile);
const DEFAULT_FILE_SYSTEM = Object.freeze({
  lstat,
  mkdir,
  open,
  rename,
  rm,
});

export class BilateralIdentityRegistrationError extends Error {
  constructor() {
    super("Bilateral identity registration failed safely.");
    this.name = "BilateralIdentityRegistrationError";
    this.code = "BILATERAL_IDENTITY_REGISTRATION_FAILED";
  }
}

function fail() {
  throw new BilateralIdentityRegistrationError();
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

function activeFileSystem(dependencies) {
  const fileSystem =
    dependencies.fileSystem ?? DEFAULT_FILE_SYSTEM;
  if (
    !isPlainObject(fileSystem) ||
    ["lstat", "mkdir", "open", "rename", "rm"].some(
      (name) => typeof fileSystem[name] !== "function",
    )
  ) {
    fail();
  }
  return fileSystem;
}

function parseArguments(arguments_) {
  if (
    !Array.isArray(arguments_) ||
    arguments_.length !== 7
  ) {
    fail();
  }
  const allowed = new Set([
    "--invitation",
    "--output",
    "--repository-sha",
  ]);
  const values = new Map();
  let acknowledged = false;
  for (
    let index = 0;
    index < arguments_.length;
    index += 1
  ) {
    const key = arguments_[index];
    if (key === RISK_FLAG) {
      if (acknowledged) {
        fail();
      }
      acknowledged = true;
      continue;
    }
    if (
      !allowed.has(key) ||
      values.has(key) ||
      index + 1 >= arguments_.length
    ) {
      fail();
    }
    const value = arguments_[index + 1];
    if (
      typeof value !== "string" ||
      value.length === 0 ||
      value.length > 4096 ||
      value.includes("\0") ||
      value.startsWith("--")
    ) {
      fail();
    }
    values.set(key, value);
    index += 1;
  }
  const repositorySha = values.get("--repository-sha");
  if (
    !acknowledged ||
    values.size !== allowed.size ||
    !REPOSITORY_SHA_PATTERN.test(repositorySha)
  ) {
    fail();
  }
  return {
    invitationPath: values.get("--invitation"),
    outputDirectory: values.get("--output"),
    repositorySha,
  };
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
      repositoryRoot: REGISTRATION_REPOSITORY_ROOT,
    });
  } catch (error) {
    if (
      error instanceof
      BilateralIdentityRegistrationError
    ) {
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

function sameMetadata(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.mode === right.mode
  );
}

export async function readBoundedFile(
  path,
  {
    allowMissing = false,
    maximum,
    privateFile = false,
  },
  fileSystem = DEFAULT_FILE_SYSTEM,
) {
  if (
    typeof path !== "string" ||
    path.length === 0 ||
    !Number.isSafeInteger(maximum) ||
    maximum <= 0 ||
    typeof allowMissing !== "boolean" ||
    typeof privateFile !== "boolean" ||
    !isPlainObject(fileSystem) ||
    typeof fileSystem.open !== "function"
  ) {
    fail();
  }
  let handle;
  let failure;
  let bytes;
  try {
    try {
      handle = await fileSystem.open(path, READ_FLAGS);
    } catch (error) {
      if (allowMissing && error?.code === "ENOENT") {
        return null;
      }
      throw error;
    }
    const before = await handle.stat();
    if (
      !before.isFile() ||
      before.size <= 0 ||
      before.size > maximum ||
      (
        privateFile &&
        process.platform !== "win32" &&
        (before.mode & 0o777) !== 0o600
      )
    ) {
      fail();
    }
    const buffer = Buffer.allocUnsafe(maximum + 1);
    let offset = 0;
    while (offset < buffer.length) {
      const result = await handle.read(
        buffer,
        offset,
        buffer.length - offset,
        null,
      );
      if (
        !isPlainObject(result) ||
        !Number.isSafeInteger(result.bytesRead) ||
        result.bytesRead < 0 ||
        result.bytesRead > buffer.length - offset
      ) {
        fail();
      }
      if (result.bytesRead === 0) {
        break;
      }
      offset += result.bytesRead;
    }
    if (offset > maximum) {
      fail();
    }
    bytes = buffer.subarray(0, offset);
    const after = await handle.stat();
    if (
      bytes.length !== before.size ||
      !after.isFile() ||
      !sameMetadata(before, after)
    ) {
      fail();
    }
  } catch (error) {
    failure =
      error instanceof BilateralIdentityRegistrationError
        ? error
        : new BilateralIdentityRegistrationError();
  } finally {
    if (handle !== undefined) {
      try {
        await handle.close();
      } catch {
        failure ??=
          new BilateralIdentityRegistrationError();
      }
    }
  }
  if (failure !== undefined) {
    throw failure;
  }
  return bytes;
}

async function readInvitation(
  path,
  fileSystem = DEFAULT_FILE_SYSTEM,
) {
  const bytes = await readBoundedFile(path, {
    maximum: MAX_INVITATION_BYTES,
    privateFile: true,
  }, fileSystem);
  let value;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch {
    fail();
  }
  if (!exactKeys(value, ["bundle", "code"])) {
    fail();
  }
  return value;
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
    if (
      error instanceof
      BilateralIdentityRegistrationError
    ) {
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
    if (
      error instanceof
      BilateralIdentityRegistrationError
    ) {
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
      error instanceof
      BilateralIdentityRegistrationError
        ? error
        : new BilateralIdentityRegistrationError();
  } finally {
    if (handle !== undefined) {
      try {
        await handle.close();
      } catch {
        failure ??=
          new BilateralIdentityRegistrationError();
      }
    }
  }
  if (failure !== undefined) {
    throw failure;
  }
  await assertPinnedDirectory(pinned, fileSystem);
  await syncPinnedDirectory(pinned, fileSystem);
}

async function readEntryMetadata(
  pinned,
  path,
  fileSystem,
) {
  if (dirname(path) !== pinned.path) {
    fail();
  }
  await assertPinnedDirectory(pinned, fileSystem);
  try {
    const metadata = await fileSystem.lstat(path);
    await assertPinnedDirectory(pinned, fileSystem);
    return metadata;
  } catch (error) {
    if (error?.code === "ENOENT") {
      await assertPinnedDirectory(pinned, fileSystem);
      return null;
    }
    fail();
  }
}

function isPrivateRegularFile(metadata) {
  return (
    metadata.isFile() &&
    (
      typeof metadata.isSymbolicLink !== "function" ||
      !metadata.isSymbolicLink()
    ) &&
    (
      process.platform === "win32" ||
      (metadata.mode & 0o777) === 0o600
    )
  );
}

async function publicationState(pinned, fileSystem) {
  const identityPath = join(pinned.path, IDENTITY_FILE);
  const completionPath = join(
    pinned.path,
    COMPLETION_FILE,
  );
  const identity = await readEntryMetadata(
    pinned,
    identityPath,
    fileSystem,
  );
  const completion = await readEntryMetadata(
    pinned,
    completionPath,
    fileSystem,
  );
  if (completion !== null) {
    fail();
  }
  if (identity === null) {
    return "fresh";
  }
  if (!isPrivateRegularFile(identity)) {
    fail();
  }
  return "resume";
}

function validatedCheckpoint(
  checkpoint,
  invitation,
  repositorySha,
) {
  try {
    if (checkpoint?.schema === INTENT_SCHEMA) {
      return validateRegistrationIntent(checkpoint, {
        expectedAddress: invitation.address,
        displayName: invitation.displayName,
      });
    }
    if (checkpoint?.schema === RECOVERY_SCHEMA) {
      return validateRecovery(checkpoint, {
        expectedAddress: invitation.address,
        displayName: invitation.displayName,
      });
    }
    if (
      checkpoint?.schema ===
      PUBLICATION_CHECKPOINT_SCHEMA
    ) {
      return validatedPublicationCheckpoint(
        checkpoint,
        invitation,
        repositorySha,
      );
    }
  } catch {
    fail();
  }
  fail();
}

function checkpointBytes(checkpoint) {
  try {
    if (
      checkpoint?.schema ===
      PUBLICATION_CHECKPOINT_SCHEMA
    ) {
      return canonicalBytes(checkpoint);
    }
    return Buffer.from(
      JSON.stringify(checkpoint),
      "utf8",
    );
  } catch {
    fail();
  }
}

export async function readCheckpoint(
  outputDirectory,
  invitation,
  fileSystem = DEFAULT_FILE_SYSTEM,
  repositorySha,
) {
  const path = join(outputDirectory, CHECKPOINT_FILE);
  const bytes = await readBoundedFile(path, {
    allowMissing: true,
    maximum: MAX_CHECKPOINT_BYTES,
    privateFile: true,
  }, fileSystem);
  if (bytes === null) {
    return null;
  }
  let checkpoint;
  try {
    checkpoint = JSON.parse(bytes.toString("utf8"));
  } catch {
    fail();
  }
  if (!checkpointBytes(checkpoint).equals(bytes)) {
    fail();
  }
  return validatedCheckpoint(
    checkpoint,
    invitation,
    repositorySha,
  );
}

async function persistCheckpointBytes(
  pinned,
  bytes,
  fileSystem,
) {
  if (!Buffer.isBuffer(bytes)) {
    fail();
  }
  const temporaryPath = join(
    pinned.path,
    `.${CHECKPOINT_FILE}.${randomUUID()}.tmp`,
  );
  let handle;
  let failure;
  try {
    await assertPinnedDirectory(pinned, fileSystem);
    handle = await fileSystem.open(
      temporaryPath,
      "wx",
      0o600,
    );
    await assertPinnedDirectory(pinned, fileSystem);
    const metadata = await handle.stat();
    if (!isPrivateRegularFile(metadata)) {
      fail();
    }
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await assertPinnedDirectory(pinned, fileSystem);
    await fileSystem.rename(
      temporaryPath,
      join(pinned.path, CHECKPOINT_FILE),
    );
    await assertPinnedDirectory(pinned, fileSystem);
    await syncPinnedDirectory(pinned, fileSystem);
  } catch (error) {
    failure =
      error instanceof
      BilateralIdentityRegistrationError
        ? error
        : new BilateralIdentityRegistrationError();
  } finally {
    if (handle !== undefined) {
      try {
        await handle.close();
      } catch {
        failure ??=
          new BilateralIdentityRegistrationError();
      }
    }
    if (failure !== undefined) {
      try {
        await assertPinnedDirectory(
          pinned,
          fileSystem,
        );
        await fileSystem.rm(temporaryPath, {
          force: true,
        });
        await syncPinnedDirectory(
          pinned,
          fileSystem,
        );
      } catch {
        // A hostile path swap leaves the private temporary
        // file attached to the pinned directory rather than
        // deleting through an untrusted pathname.
      }
    }
  }
  if (failure !== undefined) {
    throw failure;
  }
}

async function persistCheckpoint(
  pinned,
  checkpoint,
  invitation,
  canaries,
  fileSystem,
) {
  const validated = validatedCheckpoint(
    checkpoint,
    invitation,
  );
  try {
    assertSecretFree(validated, canaries);
  } catch {
    fail();
  }
  await persistCheckpointBytes(
    pinned,
    checkpointBytes(validated),
    fileSystem,
  );
  return validated;
}

function registrationArtifact(
  registration,
  invitation,
  repositorySha,
) {
  const expectedRegistryNamespace =
    `eip155:${CHAIN_ID}:${REGISTRY_ADDRESS}`;
  if (
    !isPlainObject(registration) ||
    registration.chainId !== CHAIN_ID ||
    typeof registration.registryAddress !== "string" ||
    registration.registryAddress.toLowerCase() !==
      REGISTRY_ADDRESS.toLowerCase() ||
    registration.registryNamespace !==
      expectedRegistryNamespace ||
    typeof registration.address !== "string" ||
    !ADDRESS_PATTERN.test(registration.address) ||
    registration.address.toLowerCase() !==
      invitation.address.toLowerCase() ||
    registration.displayName !== invitation.displayName ||
    typeof registration.agentId !== "string" ||
    !DECIMAL_PATTERN.test(registration.agentId) ||
    registration.identityReference !==
      `${expectedRegistryNamespace}:${registration.agentId}` ||
    !TRANSACTION_PATTERN.test(registration.registerTx) ||
    !DECIMAL_PATTERN.test(registration.registerBlock) ||
    !TRANSACTION_PATTERN.test(registration.metadataTx) ||
    !DECIMAL_PATTERN.test(registration.metadataBlock)
  ) {
    fail();
  }
  return {
    address: registration.address.toLowerCase(),
    agentId: registration.agentId,
    chainId: String(CHAIN_ID),
    displayName: registration.displayName,
    identityReference: registration.identityReference,
    metadata: {
      blockHeight: registration.metadataBlock,
      transactionHash: registration.metadataTx,
    },
    paymentMoved: false,
    register: {
      blockHeight: registration.registerBlock,
      transactionHash: registration.registerTx,
    },
    registryAddress:
      registration.registryAddress.toLowerCase(),
    repositorySha,
    schema: IDENTITY_ARTIFACT_SCHEMA,
  };
}

function validatedIdentityArtifact(
  artifact,
  invitation,
  repositorySha,
) {
  if (
    !exactKeys(artifact, [
      "address",
      "agentId",
      "chainId",
      "displayName",
      "identityReference",
      "metadata",
      "paymentMoved",
      "register",
      "registryAddress",
      "repositorySha",
      "schema",
    ]) ||
    !exactKeys(artifact.metadata, [
      "blockHeight",
      "transactionHash",
    ]) ||
    !exactKeys(artifact.register, [
      "blockHeight",
      "transactionHash",
    ]) ||
    artifact.chainId !== String(CHAIN_ID) ||
    artifact.paymentMoved !== false ||
    artifact.schema !== IDENTITY_ARTIFACT_SCHEMA ||
    typeof repositorySha !== "string" ||
    !REPOSITORY_SHA_PATTERN.test(repositorySha)
  ) {
    fail();
  }
  let validated;
  try {
    validated = registrationArtifact(
      {
        address: artifact.address,
        agentId: artifact.agentId,
        chainId: CHAIN_ID,
        displayName: artifact.displayName,
        identityReference: artifact.identityReference,
        metadataBlock:
          artifact.metadata.blockHeight,
        metadataTx:
          artifact.metadata.transactionHash,
        registerBlock:
          artifact.register.blockHeight,
        registerTx:
          artifact.register.transactionHash,
        registryAddress: artifact.registryAddress,
        registryNamespace:
          `eip155:${CHAIN_ID}:${REGISTRY_ADDRESS}`,
      },
      invitation,
      repositorySha,
    );
  } catch {
    fail();
  }
  if (
    !canonicalBytes(validated).equals(
      canonicalBytes(artifact),
    )
  ) {
    fail();
  }
  return validated;
}

function validatedPublicationCheckpoint(
  checkpoint,
  invitation,
  repositorySha,
) {
  if (
    !exactKeys(checkpoint, ["artifact", "schema"]) ||
    checkpoint.schema !== PUBLICATION_CHECKPOINT_SCHEMA
  ) {
    fail();
  }
  return {
    artifact: validatedIdentityArtifact(
      checkpoint.artifact,
      invitation,
      repositorySha,
    ),
    schema: PUBLICATION_CHECKPOINT_SCHEMA,
  };
}

async function persistPublicationCheckpoint(
  pinned,
  artifact,
  invitation,
  repositorySha,
  canaries,
  fileSystem,
) {
  const checkpoint = validatedPublicationCheckpoint(
    {
      artifact,
      schema: PUBLICATION_CHECKPOINT_SCHEMA,
    },
    invitation,
    repositorySha,
  );
  try {
    assertSecretFree(checkpoint, canaries);
  } catch {
    fail();
  }
  await persistCheckpointBytes(
    pinned,
    canonicalBytes(checkpoint),
    fileSystem,
  );
  return checkpoint;
}

async function recoverPublishedArtifact(
  pinned,
  checkpoint,
  invitation,
  repositorySha,
  fileSystem,
) {
  const artifact = validatedPublicationCheckpoint(
    checkpoint,
    invitation,
    repositorySha,
  ).artifact;
  await assertPinnedDirectory(pinned, fileSystem);
  const bytes = await readBoundedFile(
    join(pinned.path, IDENTITY_FILE),
    {
      maximum: MAX_IDENTITY_BYTES,
      privateFile: true,
    },
    fileSystem,
  );
  await assertPinnedDirectory(pinned, fileSystem);
  if (!canonicalBytes(artifact).equals(bytes)) {
    fail();
  }
  return artifact;
}

async function publishIdentity(
  pinned,
  artifact,
  canaries,
  fileSystem,
  state,
) {
  try {
    assertSecretFree(artifact, canaries);
  } catch {
    fail();
  }
  const bytes = canonicalBytes(artifact);
  const identityPath = join(pinned.path, IDENTITY_FILE);
  if (state === "resume") {
    await assertPinnedDirectory(pinned, fileSystem);
    const existing = await readBoundedFile(
      identityPath,
      {
        maximum: MAX_IDENTITY_BYTES,
        privateFile: true,
      },
      fileSystem,
    );
    await assertPinnedDirectory(pinned, fileSystem);
    if (!existing.equals(bytes)) {
      fail();
    }
  } else if (state === "fresh") {
    await writeExclusive(
      pinned,
      identityPath,
      bytes,
      fileSystem,
    );
  } else {
    fail();
  }
  await writeExclusive(
    pinned,
    join(pinned.path, COMPLETION_FILE),
    canonicalBytes({
      fileSha256: createHash("sha256")
        .update(bytes)
        .digest("hex"),
      schema: COMPLETION_SCHEMA,
    }),
    fileSystem,
  );
}

async function completeRegistration({
  checkpoint,
  fileSystem,
  finalizeRegistration,
  invitation,
  pinned,
  register,
}) {
  const canaries = [
    invitation.code,
    invitation.privateKey,
  ];
  let intentWrites = 0;
  let recoveryWrites = 0;
  const onCheckpoint = async (record) => {
    const persisted = await persistCheckpoint(
      pinned,
      record,
      invitation,
      canaries,
      fileSystem,
    );
    if (persisted.schema === INTENT_SCHEMA) {
      intentWrites += 1;
    } else {
      recoveryWrites += 1;
    }
  };
  try {
    if (checkpoint?.schema === RECOVERY_SCHEMA) {
      return await finalizeRegistration({
        displayName: invitation.displayName,
        expectedAddress: invitation.address,
        onCheckpoint,
        privateKey: invitation.privateKey,
        recovery: checkpoint,
      });
    }
    const result = await register({
      displayName: invitation.displayName,
      expectedAddress: invitation.address,
      ...(checkpoint === null
        ? {}
        : { intent: checkpoint }),
      onCheckpoint,
      privateKey: invitation.privateKey,
    });
    const requiredIntentWrites =
      checkpoint === null ? 1 : 0;
    if (
      intentWrites < requiredIntentWrites ||
      intentWrites > 1 ||
      recoveryWrites < 1
    ) {
      fail();
    }
    return result;
  } catch (error) {
    if (error instanceof PartialRegistrationError) {
      try {
        await onCheckpoint(error.recovery);
      } catch {
        fail();
      }
    }
    if (
      error instanceof
      BilateralIdentityRegistrationError
    ) {
      throw error;
    }
    fail();
  }
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
  const fileSystem = activeFileSystem(dependencies);
  const readSecret =
    dependencies.readInvitation ??
    ((path) => readInvitation(path, fileSystem));
  const decrypt =
    dependencies.decrypt ?? decryptInvitation;
  const register =
    dependencies.register ?? registerIdentity;
  const finalizeRegistration =
    dependencies.finalizeRegistration ??
    finalizeIdentityRegistration;
  if (
    typeof repositoryStateResolver !== "function" ||
    typeof readSecret !== "function" ||
    typeof decrypt !== "function" ||
    typeof register !== "function" ||
    typeof finalizeRegistration !== "function"
  ) {
    fail();
  }
  await verifyRepositoryState(
    configuration.repositorySha,
    repositoryStateResolver,
  );
  let pinned;
  let failure;
  let result;
  try {
    pinned = await pinPrivateDirectory(
      configuration.outputDirectory,
      fileSystem,
    );
    const state = await publicationState(
      pinned,
      fileSystem,
    );
    let secretInvitation;
    let invitation;
    try {
      secretInvitation = await readSecret(
        configuration.invitationPath,
      );
      invitation = await decrypt(
        secretInvitation?.bundle,
        secretInvitation?.code,
      );
    } catch {
      fail();
    }
    if (
      !isPlainObject(secretInvitation) ||
      !isPlainObject(invitation) ||
      typeof secretInvitation.code !== "string" ||
      secretInvitation.code.length === 0 ||
      typeof invitation.privateKey !== "string" ||
      invitation.privateKey.length === 0 ||
      invitation.address !==
        secretInvitation.bundle?.address ||
      invitation.displayName !==
        secretInvitation.bundle?.displayName
    ) {
      fail();
    }
    invitation = {
      ...invitation,
      code: secretInvitation.code,
    };
    await assertPinnedDirectory(pinned, fileSystem);
    const checkpoint = await readCheckpoint(
      configuration.outputDirectory,
      invitation,
      fileSystem,
      configuration.repositorySha,
    );
    await assertPinnedDirectory(pinned, fileSystem);
    if (
      state === "resume" &&
      checkpoint?.schema !==
        PUBLICATION_CHECKPOINT_SCHEMA
    ) {
      fail();
    }
    const canaries = [
      invitation.code,
      invitation.privateKey,
    ];
    let artifact;
    if (
      checkpoint?.schema ===
      PUBLICATION_CHECKPOINT_SCHEMA
    ) {
      artifact =
        state === "resume"
          ? await recoverPublishedArtifact(
              pinned,
              checkpoint,
              invitation,
              configuration.repositorySha,
              fileSystem,
            )
          : checkpoint.artifact;
    } else {
      const registration = await completeRegistration({
        checkpoint,
        fileSystem,
        finalizeRegistration,
        invitation,
        pinned,
        register,
      });
      artifact = registrationArtifact(
        registration,
        invitation,
        configuration.repositorySha,
      );
      const publicationCheckpoint =
        await persistPublicationCheckpoint(
          pinned,
          artifact,
          invitation,
          configuration.repositorySha,
          canaries,
          fileSystem,
        );
      artifact = publicationCheckpoint.artifact;
    }
    await publishIdentity(
      pinned,
      artifact,
      canaries,
      fileSystem,
      state,
    );
    result = Object.freeze(artifact);
  } catch (error) {
    failure =
      error instanceof
      BilateralIdentityRegistrationError
        ? error
        : new BilateralIdentityRegistrationError();
  } finally {
    if (pinned !== undefined) {
      try {
        await pinned.handle.close();
      } catch {
        failure ??=
          new BilateralIdentityRegistrationError();
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
    output("IDENTITY_READY\n");
    return 0;
  } catch {
    writeError(
      "Bilateral identity registration failed safely.\n",
    );
    return 1;
  }
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  process.exitCode = await runCli();
}
