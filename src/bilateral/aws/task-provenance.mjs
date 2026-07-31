import {
  createHash,
} from "node:crypto";
import { types } from "node:util";

export const AWS_BUILD_PROVENANCE_SCHEMA =
  "clockchain.aws-build-provenance/v1";

const BUILD_KEYS = Object.freeze([
  "operatorPublicKeySha256",
  "repositorySha",
  "schema",
  "sourceTreeSha256",
]);
const INSPECTION_KEYS = Object.freeze([
  "clean",
  "operatorPublicKey",
  "repositorySha",
  "sourceTreeSha256",
]);
const VERIFY_KEYS = Object.freeze([
  "operatorKeyId",
  "repositorySha",
]);
const ASSERT_REPOSITORY_KEYS = Object.freeze([
  "repositorySha",
]);
const SHA40_PATTERN = /^[0-9a-f]{40}$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const KEY_ID_PATTERN =
  /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
const IMAGE_PATTERN =
  /^(?<repository>[a-z0-9][a-z0-9./_-]{0,254})@sha256:(?<digest>[0-9a-f]{64})$/;
const RAW_PUBLIC_KEY_PATTERN =
  /^(?:[A-Za-z0-9+/]{43}=)$/;

export class AwsTaskProvenanceError extends Error {
  constructor() {
    super("AWS task provenance failed safely.");
    this.name = "AwsTaskProvenanceError";
    this.code = "AWS_TASK_PROVENANCE_INVALID";
    this.category = "verification";
  }
}

function invalid() {
  throw new AwsTaskProvenanceError();
}

function sanitize(error) {
  if (error instanceof AwsTaskProvenanceError) {
    throw error;
  }
  invalid();
}

function exactObject(value, keys) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    types.isProxy(value) ||
    ![Object.prototype, null].includes(
      Object.getPrototypeOf(value),
    )
  ) {
    invalid();
  }
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== keys.length ||
    keys.some((key, index) => ownKeys[index] !== key)
  ) {
    invalid();
  }
  return value;
}

function repositorySha(value) {
  if (
    typeof value !== "string" ||
    !SHA40_PATTERN.test(value)
  ) {
    invalid();
  }
  return value;
}

function sha256(value) {
  if (
    typeof value !== "string" ||
    !SHA256_PATTERN.test(value)
  ) {
    invalid();
  }
  return value;
}

function operatorKeyId(value) {
  if (
    typeof value !== "string" ||
    !KEY_ID_PATTERN.test(value)
  ) {
    invalid();
  }
  return value;
}

function operatorPublicKey(value) {
  if (
    typeof value !== "string" ||
    !RAW_PUBLIC_KEY_PATTERN.test(value)
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

function publicKeyDigest(value) {
  return createHash("sha256")
    .update(
      Buffer.from(operatorPublicKey(value), "base64"),
    )
    .digest("hex");
}

function image(value) {
  if (typeof value !== "string") invalid();
  const match = IMAGE_PATTERN.exec(value);
  if (match === null) invalid();
  return Object.freeze({
    digest: `sha256:${match.groups.digest}`,
    value,
  });
}

function metadataImageId(value) {
  if (
    typeof value !== "string" ||
    !/^sha256:[0-9a-f]{64}$/.test(value)
  ) {
    invalid();
  }
  return value;
}

function verifiedResult({
  imageDigest,
  operatorPublicKey: publicKey,
  repositorySha: sha,
  sourceTreeSha256,
}) {
  return Object.freeze({
    imageDigest,
    operatorPublicKey: publicKey,
    repositorySha: sha,
    sourceTreeSha256,
  });
}

export function validateAwsBuildProvenance({
  buildRecord,
  expectedImage,
  expectedRepositorySha,
  expectedSourceTreeSha256,
  metadataImageId: metadata,
  operatorPublicKey: publicKey,
} = {}) {
  try {
    const record = exactObject(
      buildRecord,
      BUILD_KEYS,
    );
    const expectedSha =
      repositorySha(expectedRepositorySha);
    const expectedTree =
      sha256(expectedSourceTreeSha256);
    const boundKey = operatorPublicKey(publicKey);
    const immutableImage = image(expectedImage);
    const runningImage =
      metadataImageId(metadata);
    if (
      record.schema !==
        AWS_BUILD_PROVENANCE_SCHEMA ||
      repositorySha(record.repositorySha) !==
        expectedSha ||
      sha256(record.sourceTreeSha256) !==
        expectedTree ||
      sha256(record.operatorPublicKeySha256) !==
        publicKeyDigest(boundKey) ||
      immutableImage.digest !== runningImage
    ) {
      invalid();
    }
    return verifiedResult({
      imageDigest: immutableImage.digest,
      operatorPublicKey: boundKey,
      repositorySha: expectedSha,
      sourceTreeSha256: expectedTree,
    });
  } catch (error) {
    sanitize(error);
  }
}

export function createAwsTaskProvenanceProvider({
  buildRecord,
  expectedImage,
  expectedRepositorySha,
  expectedSourceTreeSha256,
  metadataImageId: metadata,
  operatorKeyId: expectedOperatorKeyId,
  operatorPublicKey: publicKey,
} = {}) {
  try {
    const keyId = operatorKeyId(
      expectedOperatorKeyId,
    );
    const verified = validateAwsBuildProvenance({
      buildRecord,
      expectedImage,
      expectedRepositorySha,
      expectedSourceTreeSha256,
      metadataImageId: metadata,
      operatorPublicKey: publicKey,
    });
    return Object.freeze({
      async assertRepository(value) {
        try {
          const input = exactObject(
            value,
            ASSERT_REPOSITORY_KEYS,
          );
          if (
            repositorySha(input.repositorySha) !==
              verified.repositorySha
          ) {
            invalid();
          }
          return verified;
        } catch (error) {
          sanitize(error);
        }
      },
      async verify(value) {
        try {
          const input = exactObject(
            value,
            VERIFY_KEYS,
          );
          if (
            operatorKeyId(input.operatorKeyId) !==
              keyId ||
            repositorySha(input.repositorySha) !==
              verified.repositorySha
          ) {
            invalid();
          }
          return verified;
        } catch (error) {
          sanitize(error);
        }
      },
    });
  } catch (error) {
    sanitize(error);
  }
}

export function createLocalTaskProvenanceProvider({
  inspect,
  operatorKeyId: expectedOperatorKeyId,
  operatorPublicKey: expectedOperatorPublicKey,
} = {}) {
  try {
    if (typeof inspect !== "function") invalid();
    const keyId = operatorKeyId(
      expectedOperatorKeyId,
    );
    const expectedKey = operatorPublicKey(
      expectedOperatorPublicKey,
    );
    const inspectRepository = async (
      expectedRepositorySha,
    ) => {
      const inspected = exactObject(
        await inspect(),
        INSPECTION_KEYS,
      );
      if (
        inspected.clean !== true ||
        repositorySha(
          inspected.repositorySha,
        ) !== repositorySha(
          expectedRepositorySha,
        ) ||
        operatorPublicKey(
          inspected.operatorPublicKey,
        ) !== expectedKey
      ) {
        invalid();
      }
      return verifiedResult({
        imageDigest: null,
        operatorPublicKey:
          expectedKey,
        repositorySha:
          inspected.repositorySha,
        sourceTreeSha256: sha256(
          inspected.sourceTreeSha256,
        ),
      });
    };
    return Object.freeze({
      async assertRepository(value) {
        try {
          const input = exactObject(
            value,
            ASSERT_REPOSITORY_KEYS,
          );
          return await inspectRepository(
            input.repositorySha,
          );
        } catch (error) {
          sanitize(error);
        }
      },
      async verify(value) {
        try {
          const input = exactObject(
            value,
            VERIFY_KEYS,
          );
          if (
            operatorKeyId(input.operatorKeyId) !==
              keyId
          ) {
            invalid();
          }
          return await inspectRepository(
            input.repositorySha,
          );
        } catch (error) {
          sanitize(error);
        }
      },
    });
  } catch (error) {
    sanitize(error);
  }
}
