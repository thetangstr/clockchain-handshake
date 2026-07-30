import assert from "node:assert/strict";
import {
  createHash,
  generateKeyPairSync,
} from "node:crypto";
import {
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  rename,
  rm,
  stat,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { execFile } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import {
  canonicalBytes,
} from "../src/bilateral/canonical.mjs";
import {
  rawPublicKeyBase64FromPem,
} from "../src/bilateral/descriptor.mjs";
import {
  PREFLIGHT_KEY_ENROLLMENT_SCHEMA,
  TOKEN_COMMITMENT_SCHEMA,
  createLocalPreflightEnrollment,
  readAndSignTokenCommitment,
  verifyPreflightKeyEnrollment,
  verifyTokenCommitment,
} from "../src/bilateral/coordination/preflight.mjs";

const execFileAsync = promisify(execFile);
const REPOSITORY_SHA = "1".repeat(40);

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function coordinationIdentity() {
  const pair = generateKeyPairSync("ed25519");
  return {
    privateKeyPem: pair.privateKey.export({
      format: "pem",
      type: "pkcs8",
    }),
    publicKey: rawPublicKeyBase64FromPem(
      pair.publicKey.export({
        format: "pem",
        type: "spki",
      }),
    ),
  };
}

async function temporaryRoot(t, name) {
  const root = await mkdtemp(
    join(tmpdir(), `bilateral-${name}-`),
  );
  t.after(() =>
    rm(root, { force: true, recursive: true }));
  return root;
}

async function writeSecret(path, bytes) {
  await writeFile(path, bytes, { mode: 0o600 });
  await chmod(path, 0o600);
}

async function tokenFixture(t, token = "payer-token-canary") {
  const root = await temporaryRoot(t, "preflight-token");
  const tokenPath = join(root, "clockchain.token");
  await writeSecret(tokenPath, token);
  const coordination = coordinationIdentity();
  return {
    coordination,
    root,
    token,
    tokenPath,
  };
}

test("creates a self-signed role-local preflight enrollment without returning private material", async (t) => {
  const root = await temporaryRoot(t, "preflight-key");
  const outputDirectory = join(root, "payer");
  const enrollment =
    await createLocalPreflightEnrollment({
      outputDirectory,
      repositorySha: REPOSITORY_SHA,
      role: "payer",
    });

  assert.deepEqual(
    Object.keys(enrollment).sort(),
    [
      "privateKeyPath",
      "publicArtifact",
      "publicArtifactPath",
    ],
  );
  assert.deepEqual(
    Object.keys(enrollment.publicArtifact).sort(),
    [
      "algorithm",
      "paymentMoved",
      "publicKey",
      "repositorySha",
      "role",
      "schema",
      "signature",
    ],
  );
  assert.equal(
    enrollment.publicArtifact.schema,
    PREFLIGHT_KEY_ENROLLMENT_SCHEMA,
  );
  assert.equal(enrollment.publicArtifact.paymentMoved, false);
  assert.equal(enrollment.publicArtifact.role, "payer");
  assert.equal(
    enrollment.publicArtifact.repositorySha,
    REPOSITORY_SHA,
  );
  assert.equal(enrollment.publicArtifact.algorithm, "ed25519");
  assert.equal(
    Object.hasOwn(enrollment.publicArtifact, "privateKey"),
    false,
  );
  assert.equal(
    (await stat(outputDirectory)).mode & 0o777,
    0o700,
  );
  assert.equal(
    (await stat(enrollment.privateKeyPath)).mode & 0o777,
    0o600,
  );
  assert.equal(
    (await stat(enrollment.publicArtifactPath)).mode & 0o777,
    0o600,
  );
  assert.deepEqual(
    await readFile(enrollment.publicArtifactPath),
    canonicalBytes(enrollment.publicArtifact),
  );
  const privateKeyPem = await readFile(
    enrollment.privateKeyPath,
    "utf8",
  );
  assert.equal(
    JSON.stringify(enrollment).includes(privateKeyPem),
    false,
  );
  assert.equal(Object.isFrozen(enrollment), true);
  assert.equal(
    Object.isFrozen(enrollment.publicArtifact),
    true,
  );
  assert.deepEqual(
    verifyPreflightKeyEnrollment(
      enrollment.publicArtifact,
      {
        repositorySha: REPOSITORY_SHA,
        role: "payer",
      },
    ),
    enrollment.publicArtifact,
  );
});

test("preflight enrollment verification rejects wrong self-signature, public key, role, SHA, schema, payment state, and extra keys", async (t) => {
  const root = await temporaryRoot(
    t,
    "preflight-enrollment-verification",
  );
  const { publicArtifact } =
    await createLocalPreflightEnrollment({
      outputDirectory: join(root, "payer"),
      repositorySha: REPOSITORY_SHA,
      role: "payer",
    });
  const wrongKey = coordinationIdentity().publicKey;
  for (const hostile of [
    {
      ...publicArtifact,
      signature: Buffer.alloc(64, 3).toString("base64"),
    },
    { ...publicArtifact, publicKey: wrongKey },
    { ...publicArtifact, role: "payee" },
    {
      ...publicArtifact,
      repositorySha: "2".repeat(40),
    },
    {
      ...publicArtifact,
      schema: `${PREFLIGHT_KEY_ENROLLMENT_SCHEMA}-next`,
    },
    { ...publicArtifact, paymentMoved: true },
    { ...publicArtifact, extra: "untrusted" },
  ]) {
    assert.throws(
      () =>
        verifyPreflightKeyEnrollment(hostile, {
          repositorySha: REPOSITORY_SHA,
          role: "payer",
        }),
      /preflight/i,
    );
  }
});

test("signs and independently verifies the exact bounded token commitment", async (t) => {
  const fixture = await tokenFixture(t);
  const commitment = await readAndSignTokenCommitment({
    coordinationPrivateKeyPem:
      fixture.coordination.privateKeyPem,
    coordinationPublicKey:
      fixture.coordination.publicKey,
    repositorySha: REPOSITORY_SHA,
    role: "payer",
    tokenPath: fixture.tokenPath,
  });

  assert.deepEqual(Object.keys(commitment).sort(), [
    "algorithm",
    "coordinationPublicKey",
    "paymentMoved",
    "repositorySha",
    "role",
    "schema",
    "signature",
    "tokenSha256",
  ]);
  assert.equal(commitment.schema, TOKEN_COMMITMENT_SCHEMA);
  assert.equal(commitment.paymentMoved, false);
  assert.equal(
    commitment.tokenSha256,
    sha256(Buffer.from(fixture.token, "utf8")),
  );
  assert.equal(
    commitment.coordinationPublicKey,
    fixture.coordination.publicKey,
  );
  assert.equal(
    JSON.stringify(commitment).includes(fixture.token),
    false,
  );
  assert.equal(
    JSON.stringify(commitment).includes(
      fixture.coordination.privateKeyPem,
    ),
    false,
  );
  assert.deepEqual(
    verifyTokenCommitment(commitment, {
      coordinationPublicKey:
        fixture.coordination.publicKey,
      repositorySha: REPOSITORY_SHA,
      role: "payer",
      tokenSha256: commitment.tokenSha256,
    }),
    commitment,
  );
  assert.equal(Object.isFrozen(commitment), true);
});

test("token commitment verification rejects role, SHA, key, digest, schema, signature, and exact-key mismatches", async (t) => {
  const fixture = await tokenFixture(t);
  const commitment = await readAndSignTokenCommitment({
    coordinationPrivateKeyPem:
      fixture.coordination.privateKeyPem,
    coordinationPublicKey:
      fixture.coordination.publicKey,
    repositorySha: REPOSITORY_SHA,
    role: "payer",
    tokenPath: fixture.tokenPath,
  });
  const wrong = coordinationIdentity();
  const mutations = [
    (value) => ({ ...value, extra: true }),
    (value) => ({ ...value, paymentMoved: true }),
    (value) => ({ ...value, repositorySha: "2".repeat(40) }),
    (value) => ({ ...value, role: "payee" }),
    (value) => ({ ...value, schema: `${value.schema}-next` }),
    (value) => ({
      ...value,
      coordinationPublicKey: wrong.publicKey,
    }),
    (value) => ({ ...value, tokenSha256: "f".repeat(64) }),
    (value) => ({
      ...value,
      signature: Buffer.alloc(64, 7).toString("base64"),
    }),
  ];
  for (const mutate of mutations) {
    assert.throws(
      () =>
        verifyTokenCommitment(mutate(commitment), {
          coordinationPublicKey:
            fixture.coordination.publicKey,
          repositorySha: REPOSITORY_SHA,
          role: "payer",
          tokenSha256: commitment.tokenSha256,
        }),
      /preflight/i,
    );
  }
  for (const expected of [
    {
      coordinationPublicKey: wrong.publicKey,
      repositorySha: REPOSITORY_SHA,
      role: "payer",
      tokenSha256: commitment.tokenSha256,
    },
    {
      coordinationPublicKey:
        fixture.coordination.publicKey,
      repositorySha: "2".repeat(40),
      role: "payer",
      tokenSha256: commitment.tokenSha256,
    },
    {
      coordinationPublicKey:
        fixture.coordination.publicKey,
      repositorySha: REPOSITORY_SHA,
      role: "payee",
      tokenSha256: commitment.tokenSha256,
    },
    {
      coordinationPublicKey:
        fixture.coordination.publicKey,
      repositorySha: REPOSITORY_SHA,
      role: "payer",
      tokenSha256: "f".repeat(64),
    },
  ]) {
    assert.throws(
      () => verifyTokenCommitment(commitment, expected),
      /preflight/i,
    );
  }
});

test("rejects oversized, nonprintable, symlinked, nonprivate, FIFO, and device token inputs", async (t) => {
  const fixture = await tokenFixture(t);
  const inputs = [];

  const oversized = join(fixture.root, "oversized.token");
  await writeSecret(oversized, "x".repeat(4097));
  inputs.push(oversized);

  const nonprintable = join(
    fixture.root,
    "nonprintable.token",
  );
  await writeSecret(nonprintable, "valid\u0007token");
  inputs.push(nonprintable);

  const newline = join(fixture.root, "newline.token");
  await writeSecret(newline, "valid-token\n");
  inputs.push(newline);

  const nonprivate = join(fixture.root, "nonprivate.token");
  await writeSecret(nonprivate, "valid-token");
  await chmod(nonprivate, 0o644);
  inputs.push(nonprivate);

  const symbolic = join(fixture.root, "symbolic.token");
  await symlink(fixture.tokenPath, symbolic);
  inputs.push(symbolic);

  const fifo = join(fixture.root, "fifo.token");
  await execFileAsync("mkfifo", [fifo]);
  inputs.push(fifo);

  inputs.push("/dev/null");

  for (const tokenPath of inputs) {
    await assert.rejects(
      () =>
        readAndSignTokenCommitment({
          coordinationPrivateKeyPem:
            fixture.coordination.privateKeyPem,
          coordinationPublicKey:
            fixture.coordination.publicKey,
          repositorySha: REPOSITORY_SHA,
          role: "payer",
          tokenPath,
        }),
      /preflight/i,
    );
  }
});

test("reuses an exact existing identity, regenerates a deleted public artifact, and rejects stale public content", async (t) => {
  const root = await temporaryRoot(t, "preflight-restart");
  const outputDirectory = join(root, "payer");
  const first = await createLocalPreflightEnrollment({
    outputDirectory,
    repositorySha: REPOSITORY_SHA,
    role: "payer",
  });
  const privateKeyPem = await readFile(
    first.privateKeyPath,
    "utf8",
  );
  const publicMetadata = await lstat(
    first.publicArtifactPath,
  );

  const second = await createLocalPreflightEnrollment({
    outputDirectory,
    repositorySha: REPOSITORY_SHA,
    role: "payer",
  });

  assert.equal(
    await readFile(second.privateKeyPath, "utf8"),
    privateKeyPem,
  );
  assert.deepEqual(
    second.publicArtifact,
    first.publicArtifact,
  );
  assert.equal(
    (await lstat(second.publicArtifactPath)).ino,
    publicMetadata.ino,
  );

  await unlink(second.publicArtifactPath);
  const regenerated =
    await createLocalPreflightEnrollment({
      outputDirectory,
      repositorySha: REPOSITORY_SHA,
      role: "payer",
    });
  assert.deepEqual(
    await readFile(regenerated.publicArtifactPath),
    canonicalBytes(regenerated.publicArtifact),
  );
  assert.equal(
    await readFile(regenerated.privateKeyPath, "utf8"),
    privateKeyPem,
  );

  await writeSecret(
    regenerated.publicArtifactPath,
    "stale-public-artifact",
  );
  await assert.rejects(
    () =>
      createLocalPreflightEnrollment({
        outputDirectory,
        repositorySha: REPOSITORY_SHA,
        role: "payer",
      }),
    /preflight/i,
  );
  assert.equal(
    await readFile(regenerated.publicArtifactPath, "utf8"),
    "stale-public-artifact",
  );
  assert.equal(
    await readFile(regenerated.privateKeyPath, "utf8"),
    privateKeyPem,
  );
});

test("rejects and preserves a valid private identity swapped after its metadata snapshot", async (t) => {
  const root = await temporaryRoot(
    t,
    "preflight-private-snapshot-swap",
  );
  const outputDirectory = join(root, "payer");
  const first = await createLocalPreflightEnrollment({
    outputDirectory,
    repositorySha: REPOSITORY_SHA,
    role: "payer",
  });
  const originalPrivateKey = await readFile(
    first.privateKeyPath,
    "utf8",
  );
  const replacementPair = generateKeyPairSync("ed25519");
  const replacementPrivateKey =
    replacementPair.privateKey.export({
      format: "pem",
      type: "pkcs8",
    });
  const replacementPath = join(
    root,
    "valid-replacement.ed25519.pem",
  );
  const originalBackupPath = join(
    root,
    "original-private.ed25519.pem",
  );
  await writeSecret(
    replacementPath,
    replacementPrivateKey,
  );
  let privateLstatCalls = 0;
  let swapped = false;
  const fileSystem = {
    link,
    async lstat(path) {
      if (path === first.privateKeyPath) {
        privateLstatCalls += 1;
        if (privateLstatCalls === 2) {
          await rename(
            first.privateKeyPath,
            originalBackupPath,
          );
          await rename(
            replacementPath,
            first.privateKeyPath,
          );
          swapped = true;
        }
      }
      return lstat(path);
    },
    mkdir,
    open,
    rename,
    unlink,
  };

  await assert.rejects(
    () =>
      createLocalPreflightEnrollment({
        dependencies: { fileSystem },
        outputDirectory,
        repositorySha: REPOSITORY_SHA,
        role: "payer",
      }),
    /preflight/i,
  );
  assert.equal(swapped, true);
  assert.equal(
    await readFile(first.privateKeyPath, "utf8"),
    replacementPrivateKey,
  );
  assert.equal(
    await readFile(originalBackupPath, "utf8"),
    originalPrivateKey,
  );
});

test("rejects and preserves a public artifact inserted at the no-overwrite publication boundary", async (t) => {
  const root = await temporaryRoot(
    t,
    "preflight-public-insertion",
  );
  const outputDirectory = join(root, "payer");
  const first = await createLocalPreflightEnrollment({
    outputDirectory,
    repositorySha: REPOSITORY_SHA,
    role: "payer",
  });
  await unlink(first.publicArtifactPath);
  const attackerArtifact = "attacker-public-canary";
  let inserted = false;
  async function insertAtPublication(target) {
    if (!inserted) {
      inserted = true;
      await writeSecret(target, attackerArtifact);
    }
  }
  const fileSystem = {
    async link(source, target) {
      await insertAtPublication(target);
      return link(source, target);
    },
    lstat,
    mkdir,
    open,
    async rename(source, target) {
      await insertAtPublication(target);
      return rename(source, target);
    },
    unlink,
  };

  await assert.rejects(
    () =>
      createLocalPreflightEnrollment({
        dependencies: { fileSystem },
        outputDirectory,
        repositorySha: REPOSITORY_SHA,
        role: "payer",
      }),
    /preflight/i,
  );
  assert.equal(inserted, true);
  assert.equal(
    await readFile(first.publicArtifactPath, "utf8"),
    attackerArtifact,
  );
});

test("rejects unsafe private-directory and enrollment path replacement attempts without rotating identity", async (t) => {
  const root = await temporaryRoot(t, "preflight-paths");
  const wrongMode = join(root, "wrong-mode");
  await mkdir(wrongMode, { mode: 0o755 });
  await chmod(wrongMode, 0o755);
  await assert.rejects(
    () =>
      createLocalPreflightEnrollment({
        outputDirectory: wrongMode,
        repositorySha: REPOSITORY_SHA,
        role: "payer",
      }),
    /preflight/i,
  );

  const real = join(root, "real");
  await mkdir(real, { mode: 0o700 });
  const linked = join(root, "linked");
  await symlink(real, linked);
  await assert.rejects(
    () =>
      createLocalPreflightEnrollment({
        outputDirectory: linked,
        repositorySha: REPOSITORY_SHA,
        role: "payer",
      }),
    /preflight/i,
  );

  const malformedPrivateDirectory = join(
    root,
    "malformed-private",
  );
  await mkdir(malformedPrivateDirectory, { mode: 0o700 });
  const malformedPrivatePath = join(
    malformedPrivateDirectory,
    "preflight.ed25519.pem",
  );
  await writeSecret(
    malformedPrivatePath,
    "do-not-overwrite",
  );
  await assert.rejects(
    () =>
      createLocalPreflightEnrollment({
        outputDirectory: malformedPrivateDirectory,
        repositorySha: REPOSITORY_SHA,
        role: "payer",
      }),
    /preflight/i,
  );
  assert.equal(
    await readFile(malformedPrivatePath, "utf8"),
    "do-not-overwrite",
  );

  const publicSymlinkDirectory = join(
    root,
    "public-symlink",
  );
  await mkdir(publicSymlinkDirectory, { mode: 0o700 });
  const first = await createLocalPreflightEnrollment({
    outputDirectory: publicSymlinkDirectory,
    repositorySha: REPOSITORY_SHA,
    role: "payer",
  });
  const privateKeyPem = await readFile(
    first.privateKeyPath,
    "utf8",
  );
  await rm(first.publicArtifactPath);
  const outside = join(root, "outside-public.json");
  await writeSecret(outside, "outside-canary");
  await symlink(outside, first.publicArtifactPath);
  await assert.rejects(
    () =>
      createLocalPreflightEnrollment({
        outputDirectory: publicSymlinkDirectory,
        repositorySha: REPOSITORY_SHA,
        role: "payer",
      }),
    /preflight/i,
  );
  assert.equal(await readFile(outside, "utf8"), "outside-canary");
  assert.equal(
    await readFile(first.privateKeyPath, "utf8"),
    privateKeyPem,
  );

  const wrongPrivateModeDirectory = join(
    root,
    "wrong-private-mode",
  );
  const correct =
    await createLocalPreflightEnrollment({
      outputDirectory: wrongPrivateModeDirectory,
      repositorySha: REPOSITORY_SHA,
      role: "payer",
    });
  const correctPrivateKey = await readFile(
    correct.privateKeyPath,
    "utf8",
  );
  await chmod(correct.privateKeyPath, 0o644);
  await assert.rejects(
    () =>
      createLocalPreflightEnrollment({
        outputDirectory: wrongPrivateModeDirectory,
        repositorySha: REPOSITORY_SHA,
        role: "payer",
      }),
    /preflight/i,
  );
  assert.equal(
    await readFile(correct.privateKeyPath, "utf8"),
    correctPrivateKey,
  );

  const privateSymlinkDirectory = join(
    root,
    "private-symlink",
  );
  await mkdir(privateSymlinkDirectory, { mode: 0o700 });
  const outsidePrivateKey = join(
    root,
    "outside-private.pem",
  );
  await writeSecret(outsidePrivateKey, correctPrivateKey);
  const privateSymlinkPath = join(
    privateSymlinkDirectory,
    "preflight.ed25519.pem",
  );
  await symlink(outsidePrivateKey, privateSymlinkPath);
  await assert.rejects(
    () =>
      createLocalPreflightEnrollment({
        outputDirectory: privateSymlinkDirectory,
        repositorySha: REPOSITORY_SHA,
        role: "payer",
      }),
    /preflight/i,
  );
  assert.equal(
    await readFile(outsidePrivateKey, "utf8"),
    correctPrivateKey,
  );

  const privateFifoDirectory = join(
    root,
    "private-fifo",
  );
  await mkdir(privateFifoDirectory, { mode: 0o700 });
  await execFileAsync("mkfifo", [
    join(
      privateFifoDirectory,
      "preflight.ed25519.pem",
    ),
  ]);
  await assert.rejects(
    () =>
      createLocalPreflightEnrollment({
        outputDirectory: privateFifoDirectory,
        repositorySha: REPOSITORY_SHA,
        role: "payer",
      }),
    /preflight/i,
  );

  const privateDeviceDirectory = join(
    root,
    "private-device",
  );
  await mkdir(privateDeviceDirectory, { mode: 0o700 });
  const privateDevicePath = join(
    privateDeviceDirectory,
    "preflight.ed25519.pem",
  );
  const deviceMetadata = await lstat("/dev/null");
  await assert.rejects(
    () =>
      createLocalPreflightEnrollment({
        dependencies: {
          fileSystem: {
            link,
            lstat: async (path) =>
              path === privateDevicePath
                ? deviceMetadata
                : lstat(path),
            mkdir,
            open,
            rename,
            unlink,
          },
        },
        outputDirectory: privateDeviceDirectory,
        repositorySha: REPOSITORY_SHA,
        role: "payer",
      }),
    /preflight/i,
  );
});

test("rejects token metadata changes during its bounded nofollow read", async (t) => {
  const fixture = await tokenFixture(t, "race-token-value");
  let changed = false;
  const fileSystem = {
    lstat,
    mkdir,
    async open(path, flags, mode) {
      const handle = await open(path, flags, mode);
      if (path !== fixture.tokenPath) {
        return handle;
      }
      return {
        close: (...arguments_) => handle.close(...arguments_),
        read: async (...arguments_) => {
          const result = await handle.read(...arguments_);
          if (!changed) {
            changed = true;
            await writeSecret(path, "swapped-token-value");
          }
          return result;
        },
        stat: (...arguments_) => handle.stat(...arguments_),
      };
    },
  };

  await assert.rejects(
    () =>
      readAndSignTokenCommitment({
        coordinationPrivateKeyPem:
          fixture.coordination.privateKeyPem,
        coordinationPublicKey:
          fixture.coordination.publicKey,
        dependencies: { fileSystem },
        repositorySha: REPOSITORY_SHA,
        role: "payer",
        tokenPath: fixture.tokenPath,
      }),
    /preflight/i,
  );
});
