import assert from "node:assert/strict";
import {
  createHash,
  generateKeyPairSync,
} from "node:crypto";
import { test } from "node:test";

import {
  createAwsTaskProvenanceProvider,
  createLocalTaskProvenanceProvider,
  validateAwsBuildProvenance,
} from "../src/bilateral/aws/task-provenance.mjs";

const REPOSITORY_SHA =
  "abcdef0123456789abcdef0123456789abcdef01";
const SOURCE_TREE_SHA256 = "b".repeat(64);
const IMAGE_DIGEST = "c".repeat(64);
const IMAGE =
  "123456789012.dkr.ecr.us-west-2.amazonaws.com/clockchain-handshake@sha256:" +
  IMAGE_DIGEST;
const OPERATOR_KEY_ID = "operator-demo";
const OPERATOR_PUBLIC_KEY = generateKeyPairSync(
  "ed25519",
).publicKey
  .export({ format: "der", type: "spki" })
  .subarray(-32)
  .toString("base64");
const OPERATOR_PUBLIC_KEY_SHA256 = createHash("sha256")
  .update(Buffer.from(OPERATOR_PUBLIC_KEY, "base64"))
  .digest("hex");

function buildRecord(overrides = {}) {
  return {
    operatorPublicKeySha256:
      OPERATOR_PUBLIC_KEY_SHA256,
    repositorySha: REPOSITORY_SHA,
    schema: "clockchain.aws-build-provenance/v1",
    sourceTreeSha256: SOURCE_TREE_SHA256,
    ...overrides,
  };
}

test("binds reviewed source, operator key, immutable image, and ECS metadata", async () => {
  const verified = validateAwsBuildProvenance({
    buildRecord: buildRecord(),
    expectedImage: IMAGE,
    expectedRepositorySha: REPOSITORY_SHA,
    expectedSourceTreeSha256: SOURCE_TREE_SHA256,
    metadataImageId: `sha256:${IMAGE_DIGEST}`,
    operatorPublicKey: OPERATOR_PUBLIC_KEY,
  });
  assert.deepEqual(verified, {
    imageDigest: `sha256:${IMAGE_DIGEST}`,
    operatorPublicKey: OPERATOR_PUBLIC_KEY,
    repositorySha: REPOSITORY_SHA,
    sourceTreeSha256: SOURCE_TREE_SHA256,
  });

  const provider = createAwsTaskProvenanceProvider({
    buildRecord: buildRecord(),
    expectedImage: IMAGE,
    expectedRepositorySha: REPOSITORY_SHA,
    expectedSourceTreeSha256: SOURCE_TREE_SHA256,
    metadataImageId: `sha256:${IMAGE_DIGEST}`,
    operatorKeyId: OPERATOR_KEY_ID,
    operatorPublicKey: OPERATOR_PUBLIC_KEY,
  });
  assert.deepEqual(
    await provider.verify({
      operatorKeyId: OPERATOR_KEY_ID,
      repositorySha: REPOSITORY_SHA,
    }),
    verified,
  );
  assert.deepEqual(
    await provider.assertRepository({
      repositorySha: REPOSITORY_SHA,
    }),
    verified,
  );
});

test("rejects changed source, operator, repository, image, metadata, and extra fields", () => {
  const base = {
    buildRecord: buildRecord(),
    expectedImage: IMAGE,
    expectedRepositorySha: REPOSITORY_SHA,
    expectedSourceTreeSha256: SOURCE_TREE_SHA256,
    metadataImageId: `sha256:${IMAGE_DIGEST}`,
    operatorPublicKey: OPERATOR_PUBLIC_KEY,
  };
  for (const override of [
    {
      buildRecord: buildRecord({
        extra: "not-authority",
      }),
    },
    {
      buildRecord: buildRecord({
        operatorPublicKeySha256: "d".repeat(64),
      }),
    },
    {
      buildRecord: buildRecord({
        repositorySha: "d".repeat(40),
      }),
    },
    {
      buildRecord: buildRecord({
        sourceTreeSha256: "d".repeat(64),
      }),
    },
    {
      expectedImage:
        "123456789012.dkr.ecr.us-west-2.amazonaws.com/clockchain-handshake:latest",
    },
    {
      expectedImage:
        "123456789012.dkr.ecr.us-west-2.amazonaws.com/clockchain-handshake",
    },
    {
      metadataImageId: `sha256:${"d".repeat(64)}`,
    },
    {
      metadataImageId: IMAGE_DIGEST,
    },
    {
      operatorPublicKey:
        Buffer.alloc(32, 9).toString("base64"),
    },
  ]) {
    assert.throws(
      () => validateAwsBuildProvenance({
        ...base,
        ...override,
      }),
      /AWS task provenance failed safely/,
    );
  }
});

test("local fallback requires a clean exact checkout and the same operator key", async () => {
  const clean = createLocalTaskProvenanceProvider({
    inspect: async () => ({
      clean: true,
      operatorPublicKey: OPERATOR_PUBLIC_KEY,
      repositorySha: REPOSITORY_SHA,
      sourceTreeSha256: SOURCE_TREE_SHA256,
    }),
    operatorKeyId: OPERATOR_KEY_ID,
    operatorPublicKey: OPERATOR_PUBLIC_KEY,
  });
  assert.equal(
    (await clean.verify({
      operatorKeyId: OPERATOR_KEY_ID,
      repositorySha: REPOSITORY_SHA,
    })).repositorySha,
    REPOSITORY_SHA,
  );
  assert.equal(
    (await clean.assertRepository({
      repositorySha: REPOSITORY_SHA,
    })).repositorySha,
    REPOSITORY_SHA,
  );

  for (const inspection of [
    {
      clean: false,
      operatorPublicKey: OPERATOR_PUBLIC_KEY,
      repositorySha: REPOSITORY_SHA,
      sourceTreeSha256: SOURCE_TREE_SHA256,
    },
    {
      clean: true,
      operatorPublicKey: OPERATOR_PUBLIC_KEY,
      repositorySha: "d".repeat(40),
      sourceTreeSha256: SOURCE_TREE_SHA256,
    },
    {
      clean: true,
      operatorPublicKey:
        Buffer.alloc(32, 9).toString("base64"),
      repositorySha: REPOSITORY_SHA,
      sourceTreeSha256: SOURCE_TREE_SHA256,
    },
  ]) {
    const provider = createLocalTaskProvenanceProvider({
      inspect: async () => inspection,
      operatorKeyId: OPERATOR_KEY_ID,
      operatorPublicKey: OPERATOR_PUBLIC_KEY,
    });
    await assert.rejects(
      provider.verify({
        operatorKeyId: OPERATOR_KEY_ID,
        repositorySha: REPOSITORY_SHA,
      }),
      /AWS task provenance failed safely/,
    );
  }
});
