import assert from "node:assert/strict";
import {
  createCipheriv,
  createHash,
  scrypt as scryptCallback,
} from "node:crypto";
import { constants } from "node:fs";
import {
  chmod,
  link,
  lstat,
  mkdtemp,
  open,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import { keccak256 } from "viem";
import { privateKeyToAccount } from "viem/accounts";

import {
  FUNDING_PASSWORD_FILE_ENV,
  openFundingWallet,
} from "../src/core/funding/wallet.mjs";

const scrypt = promisify(scryptCallback);
const CHAIN_ID = 11155111;
const PASSWORD_CANARY = "pw-canary-not-in-output";
const PRIVATE_KEY_CANARY =
  "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const RPC_CANARY = "https://rpc-canary.invalid/secret";
const ADDRESS = privateKeyToAccount(PRIVATE_KEY_CANARY).address.toLowerCase();
const PUBLIC_METADATA_KEYS = Object.freeze([
  "schemaVersion",
  "chainId",
  "fundingAddress",
  "keystoreSha256",
  "createdAt",
]);
const passwordCalls = new WeakMap();

function hexBuffer(value) {
  return Buffer.from(value.replace(/^0x/u, ""), "hex");
}

async function createKeystore({
  privateKey = PRIVATE_KEY_CANARY,
  password = PASSWORD_CANARY,
  address = privateKeyToAccount(privateKey).address.toLowerCase(),
  version = 3,
  cipher = "aes-128-ctr",
  kdf = "scrypt",
  n = 2,
  r = 8,
  p = 1,
  dklen = 32,
  salt = "11".repeat(32),
  iv = "22".repeat(16),
} = {}) {
  const derivedKey = await scrypt(password, hexBuffer(salt), dklen, { N: n, r, p });
  const cipherKey = derivedKey.subarray(0, 16);
  const macKey = derivedKey.subarray(16, 32);
  const cipherText = Buffer.concat([
    createCipheriv(cipher, cipherKey, hexBuffer(iv)).update(hexBuffer(privateKey)),
  ]);
  const mac = keccak256(Buffer.concat([macKey, cipherText])).slice(2);
  return {
    version,
    id: "11111111-2222-4333-8444-555555555555",
    address: address.slice(2),
    crypto: {
      ciphertext: cipherText.toString("hex"),
      cipherparams: { iv },
      cipher,
      kdf,
      kdfparams: { dklen, salt, n, r, p },
      mac,
    },
  };
}

async function writePrivateJson(path, value) {
  await writeFile(path, `${JSON.stringify(value)}\n`, { mode: 0o600 });
  await chmod(path, 0o600);
}

async function writeFixture(t, {
  keystore,
  metadata = undefined,
} = {}) {
  const wallet = keystore ?? await createKeystore();
  const root = await mkdtemp(join(tmpdir(), "funding-keystore-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const keystorePath = join(root, "funding-wallet.json");
  const metadataPath = join(root, "funding-wallet.public.json");
  await writePrivateJson(keystorePath, wallet);
  const keystoreBytes = await readFile(keystorePath);
  await writePrivateJson(metadataPath, metadata ?? {
    schemaVersion: 1,
    chainId: CHAIN_ID,
    fundingAddress: `0x${wallet.address}`,
    keystoreSha256: createHash("sha256").update(keystoreBytes).digest("hex"),
    createdAt: "2026-07-28T07:11:27.911Z",
  });
  return { keystorePath, metadataPath, root };
}

function passwordReader(password = PASSWORD_CANARY) {
  const calls = [];
  const reader = {
    readPassword: async () => {
      calls.push({});
      return password;
    },
  };
  passwordCalls.set(reader, calls);
  return reader;
}

async function captureBoundaryFailure(options) {
  return openFundingWallet(options).then(
    () => assert.fail("hostile boundary input must fail"),
    (error) => error,
  );
}

function assertSanitizedBoundaryError(error) {
  assert.equal(error.message, "Bilateral funding failed safely.");
  for (const canary of [
    PASSWORD_CANARY,
    PRIVATE_KEY_CANARY.slice(2),
    "option-getter-canary",
    "dependency-getter-canary",
    "revoked",
  ]) {
    assert.doesNotMatch(error.message, new RegExp(canary, "u"));
  }
}

async function assertFails(t, mutator) {
  const fixture = await writeFixture(t);
  await mutator(fixture);
  await assert.rejects(
    openFundingWallet({
      keystorePath: fixture.keystorePath,
      metadataPath: fixture.metadataPath,
      dependencies: passwordReader(),
    }),
    /Bilateral funding failed safely\./u,
  );
}

test("openFundingWallet normalizes missing and hostile option boundary errors", async () => {
  const hostileOptions = {};
  Object.defineProperty(hostileOptions, "keystorePath", {
    enumerable: true,
    get() {
      throw new Error("option-getter-canary");
    },
  });
  const hostileMetadata = { keystorePath: "funding-wallet.json" };
  Object.defineProperty(hostileMetadata, "metadataPath", {
    enumerable: true,
    get() {
      throw new Error("option-getter-canary");
    },
  });
  const { proxy: revokedProxy, revoke } = Proxy.revocable({}, {});
  revoke();

  for (const options of [
    undefined,
    {},
    hostileOptions,
    hostileMetadata,
    new Proxy({}, {
      ownKeys() {
        throw new Error("option-getter-canary");
      },
    }),
    revokedProxy,
  ]) {
    assertSanitizedBoundaryError(await captureBoundaryFailure(options));
  }
});

test("openFundingWallet snapshots dependencies before use and rejects hostile dependency objects", async (t) => {
  const fixture = await writeFixture(t);
  const dependencyAccessor = {};
  Object.defineProperty(dependencyAccessor, "fs", {
    enumerable: true,
    get() {
      throw new Error("dependency-getter-canary");
    },
  });
  const { proxy: revokedDependencies, revoke } = Proxy.revocable({}, {});
  revoke();

  for (const dependencies of [
    dependencyAccessor,
    new Proxy({}, {
      ownKeys() {
        throw new Error("dependency-getter-canary");
      },
    }),
    revokedDependencies,
  ]) {
    assertSanitizedBoundaryError(
      await captureBoundaryFailure({
        keystorePath: fixture.keystorePath,
        metadataPath: fixture.metadataPath,
        dependencies,
      }),
    );
  }
});

test("openFundingWallet decrypts a strict Web3 v3 treasury and returns only public data plus a viem account", async (t) => {
  const fixture = await writeFixture(t);
  const reader = passwordReader();

  const result = await openFundingWallet({
    keystorePath: fixture.keystorePath,
    metadataPath: fixture.metadataPath,
    dependencies: reader,
  });

  assert.equal(passwordCalls.get(reader).length, 1);
  assert.equal(result.account.address.toLowerCase(), ADDRESS);
  assert.equal(typeof result.account.signTransaction, "function");
  assert.deepEqual(Object.keys(result.metadata), PUBLIC_METADATA_KEYS);
  assert.equal(result.metadata.fundingAddress, ADDRESS);
  assert.doesNotMatch(JSON.stringify(result), new RegExp(PASSWORD_CANARY, "u"));
  assert.doesNotMatch(JSON.stringify(result), new RegExp(PRIVATE_KEY_CANARY.slice(2), "u"));
  assert.equal("privateKey" in result, false);
  assert.equal("password" in result, false);
});

test("openFundingWallet derives the default adjacent public metadata path", async (t) => {
  const fixture = await writeFixture(t);
  const result = await openFundingWallet({
    keystorePath: fixture.keystorePath,
    dependencies: passwordReader(),
  });

  assert.equal(result.metadata.fundingAddress, ADDRESS);
});

test("openFundingWallet rejects unsafe files and unstable reads", async (t) => {
  await assertFails(t, async ({ keystorePath }) => {
    await rm(keystorePath);
    await symlink("missing-target", keystorePath);
  });
  await assertFails(t, async ({ keystorePath, root }) => {
    await link(keystorePath, join(root, "second-link.json"));
  });
  await assertFails(t, async ({ keystorePath }) => {
    await chmod(keystorePath, 0o644);
  });
  await assertFails(t, async ({ metadataPath }) => {
    await writeFile(metadataPath, "x".repeat(65_537), { mode: 0o600 });
  });

  const fixture = await writeFixture(t);
  const changingFs = {
    lstat,
    open: async (...args) => {
      const handle = await open(...args);
      if (args[0] === fixture.keystorePath) {
        return {
          async read(buffer, offset, length, position) {
            return handle.read(buffer, offset, length, position);
          },
          async stat() {
            const stats = await handle.stat();
            return { ...stats, ino: stats.ino + 1 };
          },
          close: () => handle.close(),
        };
      }
      return handle;
    },
  };
  await assert.rejects(
    openFundingWallet({
      keystorePath: fixture.keystorePath,
      metadataPath: fixture.metadataPath,
      dependencies: { ...passwordReader(), fs: changingFs },
    }),
    /Bilateral funding failed safely\./u,
  );

  const fifoStats = {
    dev: 1,
    ino: 2,
    isFile: () => false,
    isSymbolicLink: () => false,
    nlink: 1,
    mode: 0o10600,
    size: 0,
  };
  await assert.rejects(
    openFundingWallet({
      keystorePath: "fifo",
      metadataPath: "metadata",
      dependencies: {
        ...passwordReader(),
        fs: {
          lstat: async () => fifoStats,
          open: async () => assert.fail("fifo must be rejected before open"),
        },
      },
    }),
    /Bilateral funding failed safely\./u,
  );
});

test("openFundingWallet rejects malformed metadata and keystore content", async (t) => {
  const base = await createKeystore();
  const invalidMetadata = [
    { extra: true },
    { schemaVersion: 1, chainId: 1, fundingAddress: ADDRESS, keystoreSha256: "0".repeat(64), createdAt: "2026-07-28T07:11:27.911Z" },
    { schemaVersion: 1, chainId: CHAIN_ID, fundingAddress: ADDRESS.toUpperCase(), keystoreSha256: "0".repeat(64), createdAt: "2026-07-28T07:11:27.911Z" },
  ];
  for (const metadata of invalidMetadata) {
    await assertFails(t, async ({ metadataPath }) => {
      await writePrivateJson(metadataPath, metadata);
    });
  }

  const invalidKeystores = [
    { ...base, version: 2 },
    { ...base, crypto: { ...base.crypto, cipher: "aes-256-ctr" } },
    { ...base, crypto: { ...base.crypto, kdf: "pbkdf2" } },
    { ...base, crypto: { ...base.crypto, kdfparams: { ...base.crypto.kdfparams, dklen: 16 } } },
    { ...base, address: base.address.toUpperCase() },
    { ...base, crypto: { ...base.crypto, mac: "00".repeat(32) } },
  ];
  for (const keystore of invalidKeystores) {
    await assertFails(t, async ({ keystorePath, metadataPath }) => {
      await writePrivateJson(keystorePath, keystore);
      const bytes = await readFile(keystorePath);
      await writePrivateJson(metadataPath, {
        schemaVersion: 1,
        chainId: CHAIN_ID,
        fundingAddress: `0x${keystore.address}`.toLowerCase(),
        keystoreSha256: createHash("sha256").update(bytes).digest("hex"),
        createdAt: "2026-07-28T07:11:27.911Z",
      });
    });
  }

  await assertFails(t, async ({ keystorePath }) => {
    await writeFile(keystorePath, "{", { mode: 0o600 });
    await chmod(keystorePath, 0o600);
  });
  await assertFails(t, async ({ metadataPath }) => {
    await writeFile(metadataPath, "{", { mode: 0o600 });
    await chmod(metadataPath, 0o600);
  });
});

test("openFundingWallet rejects digest mismatch, empty password, and decrypted-address mismatch", async (t) => {
  await assertFails(t, async ({ metadataPath }) => {
    const metadata = JSON.parse(await readFile(metadataPath, "utf8"));
    await writePrivateJson(metadataPath, { ...metadata, keystoreSha256: "0".repeat(64) });
  });

  const fixture = await writeFixture(t);
  await assert.rejects(
    openFundingWallet({
      keystorePath: fixture.keystorePath,
      metadataPath: fixture.metadataPath,
      dependencies: passwordReader(""),
    }),
    /Bilateral funding failed safely\./u,
  );

  const otherPrivateKey =
    "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  await assertFails(t, async ({ keystorePath, metadataPath }) => {
    const keystore = await createKeystore({ privateKey: otherPrivateKey });
    await writePrivateJson(keystorePath, { ...keystore, address: ADDRESS.slice(2) });
    const bytes = await readFile(keystorePath);
    await writePrivateJson(metadataPath, {
      schemaVersion: 1,
      chainId: CHAIN_ID,
      fundingAddress: ADDRESS,
      keystoreSha256: createHash("sha256").update(bytes).digest("hex"),
      createdAt: "2026-07-28T07:11:27.911Z",
    });
  });
});

test("openFundingWallet reads the password from the private env-named file with bounded nofollow reads and without leaking canaries", async (t) => {
  const fixture = await writeFixture(t);
  const stdout = [];
  const stderr = [];
  const fsCalls = [];
  const passwordPath = join(fixture.root, "funding-password");
  await writeFile(passwordPath, `${PASSWORD_CANARY}\n`, { mode: 0o600 });
  const previousEnv = process.env[FUNDING_PASSWORD_FILE_ENV];
  process.env[FUNDING_PASSWORD_FILE_ENV] = passwordPath;
  t.after(() => {
    if (previousEnv === undefined) {
      delete process.env[FUNDING_PASSWORD_FILE_ENV];
    } else {
      process.env[FUNDING_PASSWORD_FILE_ENV] = previousEnv;
    }
  });

  const result = await openFundingWallet({
    keystorePath: fixture.keystorePath,
    metadataPath: fixture.metadataPath,
    dependencies: {
      stdout: { write: (value) => stdout.push(String(value)) },
      stderr: { write: (value) => stderr.push(String(value)) },
      fs: {
        lstat,
        open: async (path, flags) => {
          fsCalls.push({ flags, path });
          return open(path, flags);
        },
      },
    },
  });

  assert.equal(result.account.address.toLowerCase(), ADDRESS);
  assert.ok(
    fsCalls.every(
      ({ flags }) => (flags & constants.O_ACCMODE) === constants.O_RDONLY,
    ),
  );
  if (constants.O_NOFOLLOW !== undefined) {
    assert.ok(fsCalls.every(({ flags }) => (flags & constants.O_NOFOLLOW) !== 0));
  }
  if (constants.O_NONBLOCK !== undefined) {
    assert.ok(fsCalls.every(({ flags }) => (flags & constants.O_NONBLOCK) !== 0));
  }
  const serialized = [
    JSON.stringify(result),
    stdout.join(""),
    stderr.join(""),
  ].join("\n");
  for (const canary of [PASSWORD_CANARY, PRIVATE_KEY_CANARY, RPC_CANARY]) {
    assert.doesNotMatch(serialized, new RegExp(canary.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"));
  }

  const failure = await openFundingWallet({
    keystorePath: fixture.keystorePath,
    metadataPath: fixture.metadataPath,
    dependencies: passwordReader("wrong-password-canary"),
  }).then(
    () => assert.fail("wrong password must fail"),
    (error) => error,
  );
  assert.equal(failure.message, "Bilateral funding failed safely.");
  assert.doesNotMatch(failure.message, /wrong-password-canary/u);
  assert.doesNotMatch(failure.message, new RegExp(PRIVATE_KEY_CANARY.slice(2), "u"));
});

test("openFundingWallet fails closed when no password source is configured", async (t) => {
  const fixture = await writeFixture(t);
  const previousEnv = process.env[FUNDING_PASSWORD_FILE_ENV];
  delete process.env[FUNDING_PASSWORD_FILE_ENV];
  t.after(() => {
    if (previousEnv === undefined) {
      delete process.env[FUNDING_PASSWORD_FILE_ENV];
    } else {
      process.env[FUNDING_PASSWORD_FILE_ENV] = previousEnv;
    }
  });

  await assert.rejects(
    openFundingWallet({
      keystorePath: fixture.keystorePath,
      metadataPath: fixture.metadataPath,
      dependencies: {},
    }),
    /Bilateral funding failed safely\./u,
  );
});
