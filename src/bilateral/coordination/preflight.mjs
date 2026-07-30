import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes as secureRandomBytes,
  sign,
  timingSafeEqual,
  verify,
} from "node:crypto";
import {
  constants as fsConstants,
} from "node:fs";
import {
  link,
  lstat,
  mkdir,
  open,
  unlink,
} from "node:fs/promises";
import {
  join,
} from "node:path";

import {
  canonicalBytes,
} from "../canonical.mjs";
import {
  assertSecretFree,
} from "../../redact.mjs";

export const PREFLIGHT_KEY_ENROLLMENT_SCHEMA =
  "clockchain.bilateral-preflight-key-enrollment/v1";
export const TOKEN_COMMITMENT_SCHEMA =
  "clockchain.bilateral-token-commitment/v1";
export const PREFLIGHT_KEY_ENROLLMENT_SIGNATURE_DOMAIN =
  "clockchain.bilateral-preflight-key-enrollment-signature/v1\n";
export const TOKEN_COMMITMENT_SIGNATURE_DOMAIN =
  "clockchain.bilateral-token-commitment-signature/v1\n";

const PRIVATE_KEY_FILE = "preflight.ed25519.pem";
const PUBLIC_ARTIFACT_FILE =
  "preflight-key-enrollment.json";
const MAX_PRIVATE_KEY_BYTES = 8_192;
const MAX_TOKEN_BYTES = 4_096;
const MAX_PUBLIC_ARTIFACT_BYTES = 65_536;
const ROLE_PATTERN = /^(?:payer|payee)$/;
const REPOSITORY_SHA_PATTERN = /^[0-9a-f]{40}$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const TOKEN_PATTERN = /^[!-~]{1,4096}$/;
const BASE64_PATTERN =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const ED25519_SPKI_PREFIX = Buffer.from(
  "302a300506032b6570032100",
  "hex",
);
const READ_FLAGS =
  fsConstants.O_RDONLY |
  (fsConstants.O_NOFOLLOW ?? 0) |
  (fsConstants.O_NONBLOCK ?? 0);
const DIRECTORY_FLAGS =
  fsConstants.O_RDONLY |
  (fsConstants.O_DIRECTORY ?? 0) |
  (fsConstants.O_NOFOLLOW ?? 0);
const DEFAULT_FILE_SYSTEM = Object.freeze({
  link,
  lstat,
  mkdir,
  open,
  unlink,
});
const CREATE_INPUT_KEYS = Object.freeze([
  "outputDirectory",
  "repositorySha",
  "role",
]);
const CREATE_INPUT_KEYS_WITH_DEPENDENCIES = Object.freeze([
  "dependencies",
  ...CREATE_INPUT_KEYS,
]);
const COMMITMENT_INPUT_KEYS = Object.freeze([
  "coordinationPrivateKeyPem",
  "coordinationPublicKey",
  "repositorySha",
  "role",
  "tokenPath",
]);
const COMMITMENT_INPUT_KEYS_WITH_DEPENDENCIES =
  Object.freeze([
    "dependencies",
    ...COMMITMENT_INPUT_KEYS,
  ]);
const ENROLLMENT_KEYS = Object.freeze([
  "algorithm",
  "paymentMoved",
  "publicKey",
  "repositorySha",
  "role",
  "schema",
  "signature",
]);
const UNSIGNED_ENROLLMENT_KEYS = Object.freeze(
  ENROLLMENT_KEYS.filter((key) => key !== "signature"),
);
const TOKEN_COMMITMENT_KEYS = Object.freeze([
  "algorithm",
  "coordinationPublicKey",
  "paymentMoved",
  "repositorySha",
  "role",
  "schema",
  "signature",
  "tokenSha256",
]);
const UNSIGNED_TOKEN_COMMITMENT_KEYS = Object.freeze(
  TOKEN_COMMITMENT_KEYS.filter(
    (key) => key !== "signature",
  ),
);

export class CoordinationPreflightError extends Error {
  constructor() {
    super("Coordination preflight validation failed safely.");
    this.name = new.target.name;
    this.category = "verification";
    this.code = "COORDINATION_PREFLIGHT_INVALID";
  }
}

function invalid() {
  throw new CoordinationPreflightError();
}

function guarded(operation) {
  try {
    return operation();
  } catch (error) {
    if (error instanceof CoordinationPreflightError) {
      throw error;
    }
    invalid();
  }
}

async function guardedAsync(operation) {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof CoordinationPreflightError) {
      throw error;
    }
    invalid();
  }
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object") {
    return false;
  }
  try {
    const prototype = Object.getPrototypeOf(value);
    return (
      prototype === Object.prototype || prototype === null
    );
  } catch {
    return false;
  }
}

function readExactData(value, keys) {
  if (!isPlainObject(value)) {
    invalid();
  }
  let ownKeys;
  try {
    ownKeys = Reflect.ownKeys(value);
  } catch {
    invalid();
  }
  if (
    ownKeys.length !== keys.length ||
    ownKeys.some(
      (key) =>
        typeof key !== "string" || !keys.includes(key),
    )
  ) {
    invalid();
  }
  const result = Object.create(null);
  for (const key of keys) {
    let descriptor;
    try {
      descriptor = Object.getOwnPropertyDescriptor(
        value,
        key,
      );
    } catch {
      invalid();
    }
    if (
      descriptor?.enumerable !== true ||
      !Object.hasOwn(descriptor, "value")
    ) {
      invalid();
    }
    Object.defineProperty(result, key, {
      enumerable: true,
      value: descriptor.value,
    });
  }
  return Object.freeze(result);
}

function inputData(value, withoutDependencies, withDependencies) {
  if (!isPlainObject(value)) {
    invalid();
  }
  let hasDependencies;
  try {
    hasDependencies = Object.hasOwn(value, "dependencies");
  } catch {
    invalid();
  }
  return readExactData(
    value,
    hasDependencies ? withDependencies : withoutDependencies,
  );
}

function assertRole(value) {
  if (
    typeof value !== "string" ||
    !ROLE_PATTERN.test(value)
  ) {
    invalid();
  }
  return value;
}

function assertRepositorySha(value) {
  if (
    typeof value !== "string" ||
    !REPOSITORY_SHA_PATTERN.test(value)
  ) {
    invalid();
  }
  return value;
}

function assertSha256(value) {
  if (
    typeof value !== "string" ||
    !SHA256_PATTERN.test(value)
  ) {
    invalid();
  }
  return value;
}

function assertPath(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 4096 ||
    value.includes("\0")
  ) {
    invalid();
  }
  return value;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function signaturePreimage(domain, value) {
  return Buffer.concat([
    Buffer.from(domain, "ascii"),
    Buffer.from(sha256(canonicalBytes(value)), "ascii"),
  ]);
}

function rawPublicKey(value) {
  if (
    typeof value !== "string" ||
    value.length !== 44 ||
    !BASE64_PATTERN.test(value)
  ) {
    invalid();
  }
  const bytes = Buffer.from(value, "base64");
  if (
    bytes.length !== 32 ||
    bytes.toString("base64") !== value
  ) {
    invalid();
  }
  return value;
}

function publicKeyObject(rawBase64) {
  return guarded(() =>
    createPublicKey({
      key: Buffer.concat([
        ED25519_SPKI_PREFIX,
        Buffer.from(rawBase64, "base64"),
      ]),
      format: "der",
      type: "spki",
    }));
}

function signatureBytes(value) {
  if (
    typeof value !== "string" ||
    value.length !== 88 ||
    !BASE64_PATTERN.test(value)
  ) {
    invalid();
  }
  const bytes = Buffer.from(value, "base64");
  if (
    bytes.length !== 64 ||
    bytes.toString("base64") !== value
  ) {
    invalid();
  }
  return bytes;
}

function privateIdentity(privateKeyPem, expectedPublicKey) {
  if (
    typeof privateKeyPem !== "string" ||
    privateKeyPem.length === 0 ||
    Buffer.byteLength(privateKeyPem, "utf8") >
      MAX_PRIVATE_KEY_BYTES
  ) {
    invalid();
  }
  let privateKey;
  let canonicalPem;
  let publicKey;
  try {
    privateKey = createPrivateKey(privateKeyPem);
    canonicalPem = privateKey.export({
      format: "pem",
      type: "pkcs8",
    });
    publicKey = createPublicKey(privateKey);
  } catch {
    invalid();
  }
  if (
    privateKey.asymmetricKeyType !== "ed25519" ||
    canonicalPem !== privateKeyPem ||
    publicKey.asymmetricKeyType !== "ed25519"
  ) {
    invalid();
  }
  const raw = publicKey
    .export({ format: "der", type: "spki" })
    .subarray(-32)
    .toString("base64");
  if (
    expectedPublicKey !== undefined &&
    !timingSafeEqual(
      Buffer.from(raw, "ascii"),
      Buffer.from(
        rawPublicKey(expectedPublicKey),
        "ascii",
      ),
    )
  ) {
    invalid();
  }
  return Object.freeze({
    privateKey,
    privateKeyPem,
    publicKey: raw,
  });
}

function unsignedEnrollment(value) {
  const data = readExactData(
    value,
    UNSIGNED_ENROLLMENT_KEYS,
  );
  const snapshot = Object.freeze({
    algorithm:
      data.algorithm === "ed25519"
        ? data.algorithm
        : invalid(),
    paymentMoved:
      data.paymentMoved === false
        ? false
        : invalid(),
    publicKey: rawPublicKey(data.publicKey),
    repositorySha: assertRepositorySha(
      data.repositorySha,
    ),
    role: assertRole(data.role),
    schema:
      data.schema === PREFLIGHT_KEY_ENROLLMENT_SCHEMA
        ? data.schema
        : invalid(),
  });
  try {
    assertSecretFree(snapshot);
  } catch {
    invalid();
  }
  return snapshot;
}

function expectedEnrollment(value) {
  const data = readExactData(value, [
    "repositorySha",
    "role",
  ]);
  return Object.freeze({
    repositorySha: assertRepositorySha(
      data.repositorySha,
    ),
    role: assertRole(data.role),
  });
}

export function verifyPreflightKeyEnrollment(
  artifact,
  expected,
) {
  return guarded(() => {
    const data = readExactData(artifact, ENROLLMENT_KEYS);
    const unsigned = unsignedEnrollment({
      algorithm: data.algorithm,
      paymentMoved: data.paymentMoved,
      publicKey: data.publicKey,
      repositorySha: data.repositorySha,
      role: data.role,
      schema: data.schema,
    });
    const expectation = expectedEnrollment(expected);
    if (
      unsigned.repositorySha !==
        expectation.repositorySha ||
      unsigned.role !== expectation.role ||
      !verify(
        null,
        signaturePreimage(
          PREFLIGHT_KEY_ENROLLMENT_SIGNATURE_DOMAIN,
          unsigned,
        ),
        publicKeyObject(unsigned.publicKey),
        signatureBytes(data.signature),
      )
    ) {
      invalid();
    }
    return Object.freeze({
      ...unsigned,
      signature: data.signature,
    });
  });
}

function unsignedTokenCommitment(value) {
  const data = readExactData(
    value,
    UNSIGNED_TOKEN_COMMITMENT_KEYS,
  );
  return Object.freeze({
    algorithm:
      data.algorithm === "ed25519"
        ? data.algorithm
        : invalid(),
    coordinationPublicKey: rawPublicKey(
      data.coordinationPublicKey,
    ),
    paymentMoved:
      data.paymentMoved === false
        ? false
        : invalid(),
    repositorySha: assertRepositorySha(
      data.repositorySha,
    ),
    role: assertRole(data.role),
    schema:
      data.schema === TOKEN_COMMITMENT_SCHEMA
        ? data.schema
        : invalid(),
    tokenSha256: assertSha256(data.tokenSha256),
  });
}

function expectedCommitment(value) {
  if (!isPlainObject(value)) {
    invalid();
  }
  const keys = Reflect.ownKeys(value);
  const expectedKeys = [
    "coordinationPublicKey",
    "repositorySha",
    "role",
  ];
  const hasDigest = keys.includes("tokenSha256");
  const data = readExactData(
    value,
    hasDigest
      ? [...expectedKeys, "tokenSha256"]
      : expectedKeys,
  );
  return Object.freeze({
    coordinationPublicKey: rawPublicKey(
      data.coordinationPublicKey,
    ),
    repositorySha: assertRepositorySha(
      data.repositorySha,
    ),
    role: assertRole(data.role),
    tokenSha256:
      data.tokenSha256 === undefined
        ? undefined
        : assertSha256(data.tokenSha256),
  });
}

export function verifyTokenCommitment(
  artifact,
  expected,
) {
  return guarded(() => {
    const data = readExactData(
      artifact,
      TOKEN_COMMITMENT_KEYS,
    );
    const unsigned = unsignedTokenCommitment({
      algorithm: data.algorithm,
      coordinationPublicKey:
        data.coordinationPublicKey,
      paymentMoved: data.paymentMoved,
      repositorySha: data.repositorySha,
      role: data.role,
      schema: data.schema,
      tokenSha256: data.tokenSha256,
    });
    const expectation = expectedCommitment(expected);
    if (
      unsigned.coordinationPublicKey !==
        expectation.coordinationPublicKey ||
      unsigned.repositorySha !==
        expectation.repositorySha ||
      unsigned.role !== expectation.role ||
      (
        expectation.tokenSha256 !== undefined &&
        unsigned.tokenSha256 !==
          expectation.tokenSha256
      ) ||
      !verify(
        null,
        signaturePreimage(
          TOKEN_COMMITMENT_SIGNATURE_DOMAIN,
          unsigned,
        ),
        publicKeyObject(
          unsigned.coordinationPublicKey,
        ),
        signatureBytes(data.signature),
      )
    ) {
      invalid();
    }
    const artifactSnapshot = Object.freeze({
      ...unsigned,
      signature: data.signature,
    });
    try {
      assertSecretFree({
        algorithm: artifactSnapshot.algorithm,
        commitmentSha256:
          artifactSnapshot.tokenSha256,
        coordinationPublicKey:
          artifactSnapshot.coordinationPublicKey,
        paymentMoved:
          artifactSnapshot.paymentMoved,
        repositorySha:
          artifactSnapshot.repositorySha,
        role: artifactSnapshot.role,
        schema: artifactSnapshot.schema,
        signature: artifactSnapshot.signature,
      });
    } catch {
      invalid();
    }
    return artifactSnapshot;
  });
}

function activeFileSystem(value, operations) {
  const fileSystem = value ?? DEFAULT_FILE_SYSTEM;
  if (!isPlainObject(fileSystem)) {
    invalid();
  }
  for (const operation of operations) {
    let candidate;
    try {
      candidate = fileSystem[operation];
    } catch {
      invalid();
    }
    if (typeof candidate !== "function") {
      invalid();
    }
  }
  return fileSystem;
}

function dependencies(value, operations) {
  if (value === undefined) {
    return Object.freeze({
      fileSystem: activeFileSystem(undefined, operations),
      generateKeyPair: () =>
        generateKeyPairSync("ed25519"),
      randomBytes: secureRandomBytes,
    });
  }
  const data = readExactData(
    value,
    Reflect.ownKeys(value),
  );
  const allowed = [
    "fileSystem",
    "generateKeyPair",
    "randomBytes",
  ];
  if (
    Reflect.ownKeys(data).some(
      (key) => !allowed.includes(key),
    )
  ) {
    invalid();
  }
  const fileSystem = activeFileSystem(
    data.fileSystem,
    operations,
  );
  const generateKeyPair =
    data.generateKeyPair ?? (() =>
      generateKeyPairSync("ed25519"));
  const randomBytes =
    data.randomBytes ?? secureRandomBytes;
  if (
    typeof generateKeyPair !== "function" ||
    typeof randomBytes !== "function"
  ) {
    invalid();
  }
  return Object.freeze({
    fileSystem,
    generateKeyPair,
    randomBytes,
  });
}

function validFileMetadata(metadata, maximum) {
  try {
    return (
      metadata.isFile() &&
      !metadata.isSymbolicLink() &&
      metadata.nlink === 1 &&
      metadata.size > 0 &&
      metadata.size <= maximum &&
      (
        process.platform === "win32" ||
        (metadata.mode & 0o777) === 0o600
      )
    );
  } catch {
    return false;
  }
}

function sameFileMetadata(left, right) {
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

async function readMaximumPlusOne(handle, maximum) {
  const buffer = Buffer.alloc(maximum + 1);
  let offset = 0;
  while (offset < buffer.length) {
    const result = await handle.read(
      buffer,
      offset,
      buffer.length - offset,
      offset,
    );
    if (
      !isPlainObject(result) ||
      !Number.isSafeInteger(result.bytesRead) ||
      result.bytesRead < 0 ||
      result.bytesRead > buffer.length - offset
    ) {
      invalid();
    }
    if (result.bytesRead === 0) {
      break;
    }
    offset += result.bytesRead;
  }
  return buffer.subarray(0, offset);
}

async function readStableFile(
  path,
  maximum,
  fileSystem,
  expectedMetadata,
) {
  let handle;
  let failure;
  let result;
  try {
    const pathnameBefore = await fileSystem.lstat(path);
    if (
      !validFileMetadata(pathnameBefore, maximum) ||
      (
        expectedMetadata !== undefined &&
        !sameFileMetadata(
          expectedMetadata,
          pathnameBefore,
        )
      )
    ) {
      invalid();
    }
    handle = await fileSystem.open(path, READ_FLAGS);
    const handleBefore = await handle.stat();
    if (
      !validFileMetadata(handleBefore, maximum) ||
      !sameFileMetadata(pathnameBefore, handleBefore)
    ) {
      invalid();
    }
    const bytes = await readMaximumPlusOne(
      handle,
      maximum,
    );
    const [handleAfter, pathnameAfter] =
      await Promise.all([
        handle.stat(),
        fileSystem.lstat(path),
      ]);
    if (
      bytes.length !== handleBefore.size ||
      !sameFileMetadata(handleBefore, handleAfter) ||
      !sameFileMetadata(handleAfter, pathnameAfter)
    ) {
      invalid();
    }
    result = bytes;
  } catch (error) {
    failure =
      error instanceof CoordinationPreflightError
        ? error
        : new CoordinationPreflightError();
  }
  try {
    await handle?.close();
  } catch {
    failure ??= new CoordinationPreflightError();
  }
  if (failure !== undefined) {
    throw failure;
  }
  return result;
}

function validDirectoryMetadata(
  metadata,
  { pathname = false } = {},
) {
  try {
    return (
      metadata.isDirectory() &&
      (!pathname || !metadata.isSymbolicLink()) &&
      metadata.nlink > 0 &&
      (
        process.platform === "win32" ||
        (metadata.mode & 0o777) === 0o700
      )
    );
  } catch {
    return false;
  }
}

function directoryIdentity(metadata) {
  return Object.freeze({
    dev: metadata.dev,
    gid: metadata.gid,
    ino: metadata.ino,
    mode: metadata.mode,
    rdev: metadata.rdev,
    uid: metadata.uid,
  });
}

function sameDirectoryIdentity(metadata, identity) {
  return (
    metadata.dev === identity.dev &&
    metadata.ino === identity.ino &&
    metadata.mode === identity.mode &&
    metadata.uid === identity.uid &&
    metadata.gid === identity.gid &&
    metadata.rdev === identity.rdev
  );
}

async function ensurePrivateDirectory(path, fileSystem) {
  let metadata;
  try {
    metadata = await fileSystem.lstat(path);
  } catch (error) {
    if (error?.code !== "ENOENT") {
      invalid();
    }
    await fileSystem.mkdir(path, {
      mode: 0o700,
      recursive: false,
    });
    metadata = await fileSystem.lstat(path);
  }
  if (
    !validDirectoryMetadata(metadata, {
      pathname: true,
    })
  ) {
    invalid();
  }
  return metadata;
}

async function pinPrivateDirectory(path, fileSystem) {
  const initial = await ensurePrivateDirectory(
    path,
    fileSystem,
  );
  let handle;
  try {
    handle = await fileSystem.open(
      path,
      DIRECTORY_FLAGS,
    );
    const identity = directoryIdentity(initial);
    const [handleMetadata, pathnameMetadata] =
      await Promise.all([
        handle.stat(),
        fileSystem.lstat(path),
      ]);
    if (
      !validDirectoryMetadata(handleMetadata) ||
      !validDirectoryMetadata(pathnameMetadata, {
        pathname: true,
      }) ||
      !sameDirectoryIdentity(
        handleMetadata,
        identity,
      ) ||
      !sameDirectoryIdentity(
        pathnameMetadata,
        identity,
      )
    ) {
      invalid();
    }
    return {
      fileSystem,
      handle,
      identity,
      path,
    };
  } catch (error) {
    try {
      await handle?.close();
    } catch {
      invalid();
    }
    throw error;
  }
}

async function assertDirectoryBinding(binding) {
  const [handleMetadata, pathnameMetadata] =
    await Promise.all([
      binding.handle.stat(),
      binding.fileSystem.lstat(binding.path),
    ]);
  if (
    !validDirectoryMetadata(handleMetadata) ||
    !validDirectoryMetadata(pathnameMetadata, {
      pathname: true,
    }) ||
    !sameDirectoryIdentity(
      handleMetadata,
      binding.identity,
    ) ||
    !sameDirectoryIdentity(
      pathnameMetadata,
      binding.identity,
    )
  ) {
    invalid();
  }
}

async function closeDirectoryBinding(binding) {
  let failure;
  try {
    await assertDirectoryBinding(binding);
  } catch (error) {
    failure = error;
  }
  try {
    await binding.handle.close();
  } catch {
    failure ??= new CoordinationPreflightError();
  }
  if (failure !== undefined) {
    throw failure;
  }
}

async function optionalMetadata(path, fileSystem) {
  try {
    return await fileSystem.lstat(path);
  } catch (error) {
    if (error?.code === "ENOENT") {
      return null;
    }
    invalid();
  }
}

async function writePrivateIdentity(
  binding,
  generateKeyPair,
) {
  const path = join(binding.path, PRIVATE_KEY_FILE);
  const existing = await optionalMetadata(
    path,
    binding.fileSystem,
  );
  if (existing !== null) {
    if (
      !validFileMetadata(
        existing,
        MAX_PRIVATE_KEY_BYTES,
      )
    ) {
      invalid();
    }
    const bytes = await readStableFile(
      path,
      MAX_PRIVATE_KEY_BYTES,
      binding.fileSystem,
      existing,
    );
    return privateIdentity(bytes.toString("utf8"));
  }

  let pair;
  let identity;
  try {
    pair = generateKeyPair();
    identity = privateIdentity(
      pair.privateKey.export({
        format: "pem",
        type: "pkcs8",
      }),
    );
  } catch {
    invalid();
  }
  let handle;
  let failure;
  try {
    await assertDirectoryBinding(binding);
    handle = await binding.fileSystem.open(
      path,
      "wx",
      0o600,
    );
    await assertDirectoryBinding(binding);
    await handle.writeFile(
      Buffer.from(identity.privateKeyPem, "utf8"),
    );
    await assertDirectoryBinding(binding);
    await handle.sync();
    await assertDirectoryBinding(binding);
    const metadata = await handle.stat();
    if (
      !validFileMetadata(
        metadata,
        MAX_PRIVATE_KEY_BYTES,
      )
    ) {
      invalid();
    }
    await handle.close();
    handle = undefined;
    await binding.handle.sync();
    await assertDirectoryBinding(binding);
  } catch (error) {
    failure =
      error instanceof CoordinationPreflightError
        ? error
        : new CoordinationPreflightError();
  }
  try {
    await handle?.close();
  } catch {
    failure ??= new CoordinationPreflightError();
  }
  if (failure !== undefined) {
    throw failure;
  }
  const persisted = await readStableFile(
    path,
    MAX_PRIVATE_KEY_BYTES,
    binding.fileSystem,
  );
  const recovered = privateIdentity(
    persisted.toString("utf8"),
  );
  if (recovered.publicKey !== identity.publicKey) {
    invalid();
  }
  return recovered;
}

function randomSuffix(randomBytes) {
  let bytes;
  try {
    bytes = randomBytes(16);
  } catch {
    invalid();
  }
  if (
    !(
      Buffer.isBuffer(bytes) ||
      bytes instanceof Uint8Array
    ) ||
    bytes.byteLength !== 16
  ) {
    invalid();
  }
  return Buffer.from(bytes).toString("hex");
}

async function writePublicArtifact(
  binding,
  bytes,
  randomBytes,
) {
  if (
    !Buffer.isBuffer(bytes) ||
    bytes.length === 0 ||
    bytes.length > MAX_PUBLIC_ARTIFACT_BYTES
  ) {
    invalid();
  }
  const path = join(binding.path, PUBLIC_ARTIFACT_FILE);
  const existing = await optionalMetadata(
    path,
    binding.fileSystem,
  );
  if (existing !== null) {
    if (
      !validFileMetadata(
        existing,
        MAX_PUBLIC_ARTIFACT_BYTES,
      )
    ) {
      invalid();
    }
    const persisted = await readStableFile(
      path,
      MAX_PUBLIC_ARTIFACT_BYTES,
      binding.fileSystem,
      existing,
    );
    if (
      persisted.length !== bytes.length ||
      !timingSafeEqual(persisted, bytes)
    ) {
      invalid();
    }
    return;
  }
  const temporaryPath = join(
    binding.path,
    `.${PUBLIC_ARTIFACT_FILE}.${randomSuffix(
      randomBytes,
    )}.tmp`,
  );
  let handle;
  let temporaryExists = false;
  let publishedMetadata;
  let failure;
  try {
    await assertDirectoryBinding(binding);
    handle = await binding.fileSystem.open(
      temporaryPath,
      "wx",
      0o600,
    );
    temporaryExists = true;
    await assertDirectoryBinding(binding);
    await handle.writeFile(bytes);
    await assertDirectoryBinding(binding);
    await handle.sync();
    await assertDirectoryBinding(binding);
    const metadata = await handle.stat();
    if (
      !validFileMetadata(
        metadata,
        MAX_PUBLIC_ARTIFACT_BYTES,
      ) ||
      metadata.size !== bytes.length
    ) {
      invalid();
    }
    await handle.close();
    handle = undefined;
    await assertDirectoryBinding(binding);
    await binding.fileSystem.link(
      temporaryPath,
      path,
    );
    await binding.fileSystem.unlink(temporaryPath);
    temporaryExists = false;
    await binding.handle.sync();
    await assertDirectoryBinding(binding);
    publishedMetadata =
      await binding.fileSystem.lstat(path);
    if (
      !validFileMetadata(
        publishedMetadata,
        MAX_PUBLIC_ARTIFACT_BYTES,
      ) ||
      publishedMetadata.size !== bytes.length
    ) {
      invalid();
    }
  } catch (error) {
    failure =
      error instanceof CoordinationPreflightError
        ? error
        : new CoordinationPreflightError();
  }
  try {
    await handle?.close();
  } catch {
    failure ??= new CoordinationPreflightError();
  }
  if (temporaryExists) {
    try {
      await binding.fileSystem.unlink(temporaryPath);
    } catch {
      failure ??= new CoordinationPreflightError();
    }
  }
  if (failure !== undefined) {
    throw failure;
  }
  const persisted = await readStableFile(
    path,
    MAX_PUBLIC_ARTIFACT_BYTES,
    binding.fileSystem,
    publishedMetadata,
  );
  if (!timingSafeEqual(persisted, bytes)) {
    invalid();
  }
}

export async function createLocalPreflightEnrollment(
  input,
) {
  return guardedAsync(async () => {
    const data = inputData(
      input,
      CREATE_INPUT_KEYS,
      CREATE_INPUT_KEYS_WITH_DEPENDENCIES,
    );
    const outputDirectory = assertPath(
      data.outputDirectory,
    );
    const repositorySha = assertRepositorySha(
      data.repositorySha,
    );
    const role = assertRole(data.role);
    const active = dependencies(data.dependencies, [
      "link",
      "lstat",
      "mkdir",
      "open",
      "unlink",
    ]);
    const binding = await pinPrivateDirectory(
      outputDirectory,
      active.fileSystem,
    );
    let result;
    let failure;
    try {
      const identity = await writePrivateIdentity(
        binding,
        active.generateKeyPair,
      );
      const unsigned = unsignedEnrollment({
        algorithm: "ed25519",
        paymentMoved: false,
        publicKey: identity.publicKey,
        repositorySha,
        role,
        schema: PREFLIGHT_KEY_ENROLLMENT_SCHEMA,
      });
      const publicArtifact =
        verifyPreflightKeyEnrollment(
          {
            ...unsigned,
            signature: sign(
              null,
              signaturePreimage(
                PREFLIGHT_KEY_ENROLLMENT_SIGNATURE_DOMAIN,
                unsigned,
              ),
              identity.privateKey,
            ).toString("base64"),
          },
          { repositorySha, role },
        );
      try {
        assertSecretFree(publicArtifact, [
          identity.privateKeyPem,
        ]);
      } catch {
        invalid();
      }
      await writePublicArtifact(
        binding,
        canonicalBytes(publicArtifact),
        active.randomBytes,
      );
      result = Object.freeze({
        privateKeyPath: join(
          outputDirectory,
          PRIVATE_KEY_FILE,
        ),
        publicArtifact,
        publicArtifactPath: join(
          outputDirectory,
          PUBLIC_ARTIFACT_FILE,
        ),
      });
    } catch (error) {
      failure =
        error instanceof CoordinationPreflightError
          ? error
          : new CoordinationPreflightError();
    }
    try {
      await closeDirectoryBinding(binding);
    } catch (error) {
      failure ??=
        error instanceof CoordinationPreflightError
          ? error
          : new CoordinationPreflightError();
    }
    if (failure !== undefined) {
      throw failure;
    }
    return result;
  });
}

export async function readAndSignTokenCommitment(input) {
  return guardedAsync(async () => {
    const data = inputData(
      input,
      COMMITMENT_INPUT_KEYS,
      COMMITMENT_INPUT_KEYS_WITH_DEPENDENCIES,
    );
    const coordinationPublicKey = rawPublicKey(
      data.coordinationPublicKey,
    );
    const identity = privateIdentity(
      data.coordinationPrivateKeyPem,
      coordinationPublicKey,
    );
    const repositorySha = assertRepositorySha(
      data.repositorySha,
    );
    const role = assertRole(data.role);
    const tokenPath = assertPath(data.tokenPath);
    const active = dependencies(data.dependencies, [
      "lstat",
      "open",
    ]);
    const tokenBytes = await readStableFile(
      tokenPath,
      MAX_TOKEN_BYTES,
      active.fileSystem,
    );
    const token = tokenBytes.toString("utf8");
    if (
      Buffer.byteLength(token, "utf8") !==
        tokenBytes.length ||
      !TOKEN_PATTERN.test(token)
    ) {
      invalid();
    }
    const unsigned = unsignedTokenCommitment({
      algorithm: "ed25519",
      coordinationPublicKey,
      paymentMoved: false,
      repositorySha,
      role,
      schema: TOKEN_COMMITMENT_SCHEMA,
      tokenSha256: sha256(tokenBytes),
    });
    const artifact = verifyTokenCommitment(
      {
        ...unsigned,
        signature: sign(
          null,
          signaturePreimage(
            TOKEN_COMMITMENT_SIGNATURE_DOMAIN,
            unsigned,
          ),
          identity.privateKey,
        ).toString("base64"),
      },
      {
        coordinationPublicKey,
        repositorySha,
        role,
        tokenSha256: unsigned.tokenSha256,
      },
    );
    try {
      assertSecretFree(
        {
          algorithm: artifact.algorithm,
          commitmentSha256: artifact.tokenSha256,
          coordinationPublicKey:
            artifact.coordinationPublicKey,
          paymentMoved: artifact.paymentMoved,
          repositorySha: artifact.repositorySha,
          role: artifact.role,
          schema: artifact.schema,
          signature: artifact.signature,
        },
        [token, identity.privateKeyPem],
      );
    } catch {
      invalid();
    }
    return artifact;
  });
}
