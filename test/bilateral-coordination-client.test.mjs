import assert from "node:assert/strict";
import {
  chmod,
  link,
  lstat,
  mkdtemp,
  mkdir,
  open,
  readFile,
  rename,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import {
  constants as fsConstants,
} from "node:fs";
import {
  execFile as execFileCallback,
} from "node:child_process";
import {
  X509Certificate,
  constants as cryptoConstants,
  createHash,
  createPrivateKey,
  generateKeyPairSync,
  sign,
  verify,
} from "node:crypto";
import https from "node:https";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";

import {
  privateKeyToAccount,
} from "viem/accounts";
import { toHex } from "viem";

import {
  canonicalizeReceiptEventValue,
} from "../src/canonical.mjs";
import {
  canonicalBytes,
} from "../src/bilateral/canonical.mjs";
import {
  BILATERAL_PROTOCOL,
  createSignedEnvelope,
} from "../src/bilateral/descriptor.mjs";
import {
  coordinationEnrollmentSignaturePreimage,
  invitationProofPreimage,
} from "../src/bilateral/coordination/enrollment.mjs";
import {
  createCoordinationEnvelope,
} from "../src/bilateral/coordination/envelope.mjs";
import {
  MAX_RELAY_WAIT_MS,
} from "../src/bilateral/coordination/relay.mjs";
import {
  CLIENT_BODY_TIMEOUT_MS,
  CLIENT_CONNECT_TIMEOUT_MS,
  CLIENT_HEADER_TIMEOUT_MS,
  CLIENT_TOTAL_TIMEOUT_MS,
  MAX_CLIENT_JSON_RESPONSE_BYTES,
  CoordinationClientError,
  createCoordinationClient,
  createPinnedHttpsTransport,
  createResumedCoordinationClient,
} from "../src/bilateral/coordination/client.mjs";
import {
  COORDINATION_RECEIPT_SCHEMA,
  createCoordinationReceipt,
  createReceiptVerifierFromCertificate,
  verifyCoordinationReceipt,
} from "../src/bilateral/coordination/receipt.mjs";
import {
  ACTIVE_LAUNCH_STATE_SIGNATURE_DOMAIN,
  ACTIVE_LAUNCH_STATE_SCHEMA,
  LAUNCH_MANIFEST_SCHEMA,
  UNUSED_CAPABILITY_LIFETIME_MS,
  createActiveLaunchState,
  createLaunchManifest,
  readLaunchManifest,
  validateActiveLaunchState,
  validateLaunchManifest,
  writeLaunchManifest,
} from "../src/bilateral/coordination/manifest.mjs";

const execFile = promisify(execFileCallback);
const NOW_MS = 1_785_120_000_000;
const REPOSITORY_SHA = "f".repeat(40);
const RELEASE_ID = "release-a";
const SESSION_ID =
  "8f953393-86d0-4f99-9d6a-102f525fbecd";
const OPERATOR_KEY_ID = "clockchain-demo-2026";
const FIXED_CAPABILITY = Buffer.alloc(32, 0x41);
const INVITATION_KEYS = Object.freeze({
  rehearsal: `0x${"1".repeat(64)}`,
  stakeholder: `0x${"2".repeat(64)}`,
});
const PEER_INVITATION_KEYS = Object.freeze({
  rehearsal: `0x${"3".repeat(64)}`,
  stakeholder: `0x${"4".repeat(64)}`,
});

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function stableBytes(value) {
  return Buffer.from(
    JSON.stringify(canonicalizeReceiptEventValue(value)),
    "utf8",
  );
}

function rawPublicKey(pair) {
  return pair.publicKey
    .export({ format: "der", type: "spki" })
    .subarray(-32)
    .toString("base64");
}

function privateKeyPem(pair) {
  return pair.privateKey.export({
    format: "pem",
    type: "pkcs8",
  });
}

async function privateRoot(t) {
  const root = await mkdtemp(
    join(tmpdir(), "handshake-client-"),
  );
  await chmod(root, 0o700);
  t.after(() => rm(root, { force: true, recursive: true }));
  return root;
}

async function availablePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const { port } = server.address();
  await new Promise((resolve, reject) => {
    server.close((error) =>
      error === undefined ? resolve() : reject(error),
    );
  });
  return port;
}

async function tlsFixture(
  t,
  commonName = "127.0.0.1",
  algorithm = "ed25519",
) {
  const root = await privateRoot(t);
  const certificatePath = join(root, "tls-cert.pem");
  const privateKeyPath = join(root, "tls-key.pem");
  const subjectAlternativeName =
    commonName === "localhost"
      ? "DNS:localhost"
      : `IP:${commonName}`;
  const keyArguments = {
    "ecdsa-sha256": [
      "ec",
      "-pkeyopt",
      "ec_paramgen_curve:P-256",
    ],
    ed25519: ["ed25519"],
    "rsa-pss-sha256": ["rsa:2048"],
  }[algorithm];
  await execFile("openssl", [
    "req",
    "-x509",
    "-newkey",
    ...keyArguments,
    "-keyout",
    privateKeyPath,
    "-out",
    certificatePath,
    "-nodes",
    "-days",
    "1",
    "-subj",
    `/CN=${commonName}`,
    "-addext",
    `subjectAltName=${subjectAlternativeName}`,
  ]);
  await chmod(privateKeyPath, 0o600);
  const certificate = await readFile(certificatePath);
  const privateKey = await readFile(privateKeyPath);
  const parsed = new X509Certificate(certificate);
  return {
    certificate,
    certificateDer: Buffer.from(parsed.raw),
    expectedFingerprint: sha256(parsed.raw),
    privateKey,
    privateKeyObject: createPrivateKey(privateKey),
    signatureAlgorithm: algorithm,
    root,
  };
}

async function startHttpsServer(t, tls, handler) {
  const sockets = new Set();
  const server = https.createServer(
    {
      cert: tls.certificate,
      key: tls.privateKey,
    },
    handler,
  );
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  const port = await availablePort();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", resolve);
  });
  t.after(async () => {
    for (const socket of sockets) {
      socket.destroy();
    }
    await new Promise((resolve) => {
      server.close(() => resolve());
    });
  });
  return {
    port,
    relayUrl: `https://127.0.0.1:${port}`,
    server,
  };
}

function sendExact(
  response,
  body,
  {
    contentType = "application/json",
    statusCode = 200,
  } = {},
) {
  response.writeHead(statusCode, {
    "content-length": String(body.length),
    "content-type": contentType,
  });
  response.end(body);
}

function manifestInput(tls, overrides = {}) {
  return {
    expectedTlsFingerprint: tls.expectedFingerprint,
    nowMs: NOW_MS,
    operatorKeyId: OPERATOR_KEY_ID,
    randomBytes: () => Buffer.from(FIXED_CAPABILITY),
    relayUrl: "https://127.0.0.1:8443",
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    role: "payer",
    sessionId: SESSION_ID,
    tlsCertificatePem:
      tls.certificate.toString("utf8"),
    ...overrides,
  };
}

function manifestFixture(tls, overrides = {}) {
  return createLaunchManifest(
    manifestInput(tls, overrides),
  );
}

test("creates the exact private launch manifest and public capability registration", async (t) => {
  const tls = await tlsFixture(t);
  const { capabilityDigest, manifest } =
    manifestFixture(tls);
  assert.deepEqual(Object.keys(manifest).sort(), [
    "bootstrapCapability",
    "expectedTlsFingerprint",
    "expiresAtMs",
    "issuedAtMs",
    "operatorKeyId",
    "protocol",
    "relayUrl",
    "releaseId",
    "repositorySha",
    "role",
    "schema",
    "sessionId",
    "tlsCertificatePem",
  ]);
  assert.equal(
    manifest.schema,
    LAUNCH_MANIFEST_SCHEMA,
  );
  assert.equal(manifest.protocol, BILATERAL_PROTOCOL);
  assert.equal(manifest.bootstrapCapability.length, 64);
  assert.equal(
    manifest.bootstrapCapability,
    FIXED_CAPABILITY.toString("hex"),
  );
  assert.equal(
    capabilityDigest,
    sha256(
      Buffer.from(manifest.bootstrapCapability, "hex"),
    ),
  );
  assert.equal(manifest.issuedAtMs, String(NOW_MS));
  assert.equal(
    manifest.expiresAtMs,
    String(NOW_MS + UNUSED_CAPABILITY_LIFETIME_MS),
  );
  assert.equal(
    Object.isFrozen(manifest),
    true,
  );
});

test("creates distinct role-scoped 256-bit capabilities for one shared coordination session", async (t) => {
  const tls = await tlsFixture(t);
  const payer = manifestFixture(tls, {
    randomBytes: () => Buffer.alloc(32, 0x41),
    role: "payer",
  });
  const payee = manifestFixture(tls, {
    randomBytes: () => Buffer.alloc(32, 0x42),
    role: "payee",
  });
  assert.notEqual(
    payer.manifest.bootstrapCapability,
    payee.manifest.bootstrapCapability,
  );
  assert.notEqual(
    payer.capabilityDigest,
    payee.capabilityDigest,
  );
  assert.equal(
    payer.manifest.sessionId,
    payee.manifest.sessionId,
  );
  assert.equal(payer.manifest.role, "payer");
  assert.equal(payee.manifest.role, "payee");
});

test("launch manifest creation rejects every non-exact or noncanonical field without invoking getters", async (t) => {
  const tls = await tlsFixture(t);
  const exact = manifestInput(tls);
  for (const candidate of [
    { ...exact, extra: true },
    Object.assign(
      Object.create({ inherited: true }),
      exact,
    ),
    { ...exact, role: "operator" },
    { ...exact, repositorySha: "F".repeat(40) },
    { ...exact, sessionId: "not-a-session" },
    { ...exact, relayUrl: "http://relay.example.test:8443" },
    {
      ...exact,
      relayUrl: "https://relay.example.test:8443",
    },
    {
      ...exact,
      relayUrl: "https://127.0.0.1",
    },
    {
      ...exact,
      relayUrl:
        "https://127.0.0.1:8443/path",
    },
    {
      ...exact,
      relayUrl: "https://127.0.0.1:08443",
    },
    {
      ...exact,
      relayUrl: "https://127.000.000.001:8443",
    },
    {
      ...exact,
      relayUrl: "https://0.0.0.0:8443",
    },
    {
      ...exact,
      relayUrl: "https://[::]:8443",
    },
    {
      ...exact,
      relayUrl: "https://127.0.0.1:443",
    },
    {
      ...exact,
      expectedTlsFingerprint:
        exact.expectedTlsFingerprint.toUpperCase(),
    },
    {
      ...exact,
      expectedTlsFingerprint: "b".repeat(64),
    },
    {
      ...exact,
      tlsCertificatePem:
        "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n",
    },
    {
      ...exact,
      randomBytes: () => Buffer.alloc(31),
    },
    {
      ...exact,
      nowMs: BigInt(NOW_MS),
    },
  ]) {
    assert.throws(
      () => createLaunchManifest(candidate),
      {
        code: "LAUNCH_MANIFEST_INVALID",
        message: "Launch manifest processing failed safely.",
      },
    );
  }

  const canary = "manifest-getter-secret-canary";
  let invoked = false;
  const hostile = { ...exact };
  Object.defineProperty(hostile, "releaseId", {
    enumerable: true,
    get() {
      invoked = true;
      throw new Error(canary);
    },
  });
  assert.throws(
    () => createLaunchManifest(hostile),
    (error) => {
      assert.equal(invoked, false);
      assert.equal(error.code, "LAUNCH_MANIFEST_INVALID");
      assert.doesNotMatch(
        `${error.message}\n${error.stack}`,
        new RegExp(canary),
      );
      return true;
    },
  );
});

test("isolates every alternate raw capability encoding from non-capability manifest fields", async (t) => {
  const tls = await tlsFixture(t);
  const capability = Buffer.alloc(32, 0xab);
  const lowerHex = capability.toString("hex");
  const upperHex = lowerHex.toUpperCase();
  const mixedHex = [...lowerHex]
    .map((character, index) =>
      index % 2 === 0
        ? character.toUpperCase()
        : character,
    )
    .join("");
  const base64 = capability.toString("base64");
  const base64url = capability.toString("base64url");
  const { manifest } = manifestFixture(tls, {
    randomBytes: () => Buffer.from(capability),
  });
  const mutations = [
    { operatorKeyId: lowerHex },
    { releaseId: upperHex },
    { releaseId: mixedHex },
    { releaseId: base64 },
    { releaseId: base64url },
  ];
  for (const mutation of mutations) {
    assert.throws(
      () =>
        createLaunchManifest({
          ...manifestInput(tls, {
            randomBytes: () =>
              Buffer.from(capability),
          }),
          ...mutation,
        }),
      { code: "LAUNCH_MANIFEST_INVALID" },
    );
    assert.throws(
      () =>
        validateLaunchManifest({
          ...manifest,
          ...mutation,
        }),
      { code: "LAUNCH_MANIFEST_INVALID" },
    );
  }

  let transportCalls = 0;
  const fixture = await clientFixture(
    t,
    async () => {
      transportCalls += 1;
      throw new Error("must not send");
    },
    { capability },
  );
  assert.throws(
    () =>
      createCoordinationClient({
        coordinationIdentity: {
          keyId: "payer-coordination",
          privateKeyPem:
            privateKeyPem(fixture.coordination),
          publicKey:
            rawPublicKey(fixture.coordination),
        },
        manifest: {
          ...fixture.manifest,
          operatorKeyId: lowerHex,
        },
        transport: fixture.transport,
      }),
    { code: "COORDINATION_CLIENT_INVALID" },
  );
  assert.equal(transportCalls, 0);
});

test("writes canonical mode-0600 manifests exclusively and returns no raw capability", async (t) => {
  const tls = await tlsFixture(t);
  const root = await privateRoot(t);
  const path = join(root, "payer-launch.json");
  const { capabilityDigest, manifest } =
    manifestFixture(tls);
  const publicRegistration = await writeLaunchManifest(
    path,
    manifest,
  );
  assert.deepEqual(publicRegistration, {
    capabilityDigest,
    expiresAtMs: manifest.expiresAtMs,
    releaseId: RELEASE_ID,
    role: "payer",
    sessionId: SESSION_ID,
  });
  assert.equal(
    JSON.stringify(publicRegistration).includes(
      manifest.bootstrapCapability,
    ),
    false,
  );
  assert.equal((await stat(path)).mode & 0o777, 0o600);
  assert.deepEqual(
    await readFile(path),
    stableBytes(manifest),
  );
  assert.deepEqual(
    await readLaunchManifest(path),
    manifest,
  );
  await assert.rejects(
    writeLaunchManifest(path, manifest),
    { code: "LAUNCH_MANIFEST_INVALID" },
  );
});

test("fsyncs and closes both the exact manifest inode and pinned parent directory", async (t) => {
  const tls = await tlsFixture(t);
  const root = await privateRoot(t);
  const path = join(root, "durable-launch.json");
  const { manifest } = manifestFixture(tls);
  let closes = 0;
  let reads = 0;
  let syncs = 0;
  const fileSystem = {
    lstat,
    async open(candidate, flags, mode) {
      const handle = await open(candidate, flags, mode);
      return {
        async close() {
          closes += 1;
          await handle.close();
        },
        async read(...arguments_) {
          if (candidate === path) {
            reads += 1;
          }
          return handle.read(...arguments_);
        },
        stat: handle.stat.bind(handle),
        async sync() {
          syncs += 1;
          await handle.sync();
        },
        write: handle.write.bind(handle),
      };
    },
  };
  await writeLaunchManifest(path, manifest, {
    fileSystem,
  });
  assert.equal(closes, 2);
  assert.ok(reads >= 1);
  assert.equal(syncs, 2);
  assert.deepEqual(
    await readLaunchManifest(path),
    manifest,
  );
});

test("validates the exact one-hour lifetime without a client-side freshness dependency", async (t) => {
  const tls = await tlsFixture(t);
  const root = await privateRoot(t);
  const path = join(root, "launch.json");
  const { manifest } = manifestFixture(tls);
  await writeLaunchManifest(path, manifest);
  assert.equal(
    (await readLaunchManifest(path)).expiresAtMs,
    manifest.expiresAtMs,
  );
  await assert.rejects(
    readLaunchManifest(path, {
      now: () => Number(manifest.expiresAtMs) + 1,
    }),
    { code: "LAUNCH_MANIFEST_INVALID" },
  );
});

test("manifest reads reject symlink, FIFO, device, hard-link, mode, and pathname replacement attacks", async (t) => {
  const tls = await tlsFixture(t);
  const root = await privateRoot(t);
  const { manifest } = manifestFixture(tls);
  const exactPath = join(root, "exact.json");
  await writeLaunchManifest(exactPath, manifest);

  const symlinkPath = join(root, "symlink.json");
  await symlink(exactPath, symlinkPath);
  await assert.rejects(
    readLaunchManifest(symlinkPath),
    { code: "LAUNCH_MANIFEST_INVALID" },
  );

  const fifoPath = join(root, "manifest.fifo");
  await execFile("mkfifo", [fifoPath]);
  await assert.rejects(
    Promise.race([
      readLaunchManifest(fifoPath),
      new Promise((_, reject) => {
        setTimeout(
          () => reject(new Error("FIFO read blocked")),
          500,
        );
      }),
    ]),
    { code: "LAUNCH_MANIFEST_INVALID" },
  );

  await assert.rejects(
    readLaunchManifest("/dev/null"),
    { code: "LAUNCH_MANIFEST_INVALID" },
  );

  const modePath = join(root, "wrong-mode.json");
  await writeFile(modePath, stableBytes(manifest), {
    mode: 0o600,
  });
  await chmod(modePath, 0o644);
  await assert.rejects(
    readLaunchManifest(modePath),
    { code: "LAUNCH_MANIFEST_INVALID" },
  );

  const linkedPath = join(root, "linked.json");
  await link(exactPath, linkedPath);
  await assert.rejects(
    readLaunchManifest(exactPath),
    { code: "LAUNCH_MANIFEST_INVALID" },
  );
  await rm(linkedPath);

  const replacement = join(root, "replacement.json");
  const original = join(root, "original.json");
  await writeLaunchManifest(replacement, manifestFixture(tls, {
    randomBytes: () => Buffer.alloc(32, 0x42),
  }).manifest);
  await writeLaunchManifest(original, manifest);
  let replaced = false;
  const fileSystem = {
    async lstat(path) {
      const metadata = await lstat(path);
      if (path === original && !replaced) {
        replaced = true;
        await rename(original, `${original}.old`);
        await rename(replacement, original);
      }
      return metadata;
    },
    open,
  };
  await assert.rejects(
    readLaunchManifest(original, {
      fileSystem,
    }),
    { code: "LAUNCH_MANIFEST_INVALID" },
  );
});

test("pins a private parent directory and verifies exact persisted manifest bytes before success", async (t) => {
  const tls = await tlsFixture(t);
  const root = await privateRoot(t);
  const { manifest } = manifestFixture(tls);

  const publicParent = join(root, "public-parent");
  await mkdir(publicParent, { mode: 0o700 });
  await chmod(publicParent, 0o755);
  await assert.rejects(
    writeLaunchManifest(
      join(publicParent, "launch.json"),
      manifest,
    ),
    { code: "LAUNCH_MANIFEST_INVALID" },
  );

  const privateParent = join(root, "private-parent");
  await mkdir(privateParent, { mode: 0o700 });
  const exactPath = join(privateParent, "launch.json");
  await writeLaunchManifest(exactPath, manifest);
  await chmod(privateParent, 0o755);
  await assert.rejects(
    readLaunchManifest(exactPath),
    { code: "LAUNCH_MANIFEST_INVALID" },
  );
  await chmod(privateParent, 0o700);

  const linkedParent = join(root, "linked-parent");
  await symlink(privateParent, linkedParent);
  await assert.rejects(
    readLaunchManifest(
      join(linkedParent, "launch.json"),
    ),
    { code: "LAUNCH_MANIFEST_INVALID" },
  );

  const corruptedPath = join(
    privateParent,
    "corrupted.json",
  );
  const corruptingFileSystem = {
    lstat,
    async open(path, flags, mode) {
      const handle = await open(path, flags, mode);
      if (
        path !== corruptedPath ||
        (flags & fsConstants.O_CREAT) === 0
      ) {
        return handle;
      }
      return {
        close: handle.close.bind(handle),
        read: handle.read.bind(handle),
        stat: handle.stat.bind(handle),
        sync: handle.sync.bind(handle),
        write(buffer, offset, length, position) {
          const corrupted = Buffer.from(buffer);
          corrupted[0] =
            corrupted[0] === 0x7b ? 0x5b : 0x7b;
          return handle.write(
            corrupted,
            offset,
            length,
            position,
          );
        },
      };
    },
  };
  await assert.rejects(
    writeLaunchManifest(
      corruptedPath,
      manifest,
      { fileSystem: corruptingFileSystem },
    ),
    { code: "LAUNCH_MANIFEST_INVALID" },
  );
});

test("rejects parent pathname replacement and never deletes an attacker replacement during cleanup", async (t) => {
  const tls = await tlsFixture(t);
  const root = await privateRoot(t);
  const { manifest } = manifestFixture(tls);
  const parent = join(root, "launch-parent");
  const attackerParent = join(root, "attacker-parent");
  await mkdir(parent, { mode: 0o700 });
  await mkdir(attackerParent, { mode: 0o700 });
  const path = join(parent, "launch.json");
  let swapped = false;
  const swappingFileSystem = {
    async lstat(candidate) {
      const metadata = await lstat(candidate);
      if (candidate === parent && !swapped) {
        swapped = true;
        await rename(parent, `${parent}.old`);
        await rename(attackerParent, parent);
      }
      return metadata;
    },
    open,
  };
  await assert.rejects(
    writeLaunchManifest(path, manifest, {
      fileSystem: swappingFileSystem,
    }),
    { code: "LAUNCH_MANIFEST_INVALID" },
  );

  const cleanupParent = join(root, "cleanup-parent");
  await mkdir(cleanupParent, { mode: 0o700 });
  const cleanupPath = join(
    cleanupParent,
    "launch.json",
  );
  const attackerBytes = Buffer.from(
    "attacker replacement",
  );
  let replacementMade = false;
  const replacementFileSystem = {
    lstat,
    async open(candidate, flags, mode) {
      const handle = await open(candidate, flags, mode);
      if (
        candidate !== cleanupPath ||
        (flags & fsConstants.O_CREAT) === 0
      ) {
        return handle;
      }
      return {
        close: handle.close.bind(handle),
        read: handle.read.bind(handle),
        stat: handle.stat.bind(handle),
        write: handle.write.bind(handle),
        async sync() {
          await handle.sync();
          if (!replacementMade) {
            replacementMade = true;
            await rename(
              cleanupPath,
              `${cleanupPath}.created`,
            );
            await writeFile(
              cleanupPath,
              attackerBytes,
              { mode: 0o600 },
            );
          }
          throw new Error("injected sync failure");
        },
      };
    },
  };
  await assert.rejects(
    writeLaunchManifest(cleanupPath, manifest, {
      fileSystem: replacementFileSystem,
    }),
    { code: "LAUNCH_MANIFEST_INVALID" },
  );
  assert.deepEqual(
    await readFile(cleanupPath),
    attackerBytes,
  );
});

test("pins immutable HTTPS deadlines beyond the relay long-poll bound and rejects transport escape hatches", async (t) => {
  assert.equal(CLIENT_CONNECT_TIMEOUT_MS, 5_000);
  assert.equal(CLIENT_HEADER_TIMEOUT_MS, 5_000);
  assert.equal(CLIENT_BODY_TIMEOUT_MS, 5_000);
  assert.equal(CLIENT_TOTAL_TIMEOUT_MS, 45_000);
  assert.ok(
    CLIENT_TOTAL_TIMEOUT_MS >= MAX_RELAY_WAIT_MS + 5_000,
  );
  assert.equal(MAX_CLIENT_JSON_RESPONSE_BYTES, 3_145_728);

  const tls = await tlsFixture(t);
  const exact = {
    expectedFingerprint: tls.expectedFingerprint,
    relayUrl: "https://127.0.0.1:8443",
    tlsCertificatePem:
      tls.certificate.toString("utf8"),
  };
  assert.deepEqual(
    Object.keys(
      createPinnedHttpsTransport(exact),
    ).sort(),
    ["request", "verifyReceipt"],
  );
  for (const candidate of [
    {
      ...exact,
      relayUrl: exact.relayUrl.replace(
        "https:",
        "http:",
      ),
    },
    {
      ...exact,
      relayUrl: `${exact.relayUrl}/path`,
    },
    {
      ...exact,
      relayUrl: "https://relay.example.test:8443",
    },
    {
      ...exact,
      relayUrl: "https://127.0.0.1",
    },
    {
      ...exact,
      ca: exact.tlsCertificatePem,
    },
    {
      ...exact,
      rejectUnauthorized: false,
    },
    {
      ...exact,
      agent: new https.Agent(),
    },
    {
      ...exact,
      proxy: "http://127.0.0.1:9999",
    },
    {
      ...exact,
      expectedFingerprint:
        exact.expectedFingerprint.toUpperCase(),
    },
  ]) {
    assert.throws(
      () => createPinnedHttpsTransport(candidate),
      {
        code: "COORDINATION_CLIENT_INVALID",
        message: "Coordination client operation failed safely.",
      },
    );
  }
  assert.throws(
    () =>
      createPinnedHttpsTransport({
        ...exact,
        expectedFingerprint: "0".repeat(64),
      }),
    { code: "COORDINATION_CLIENT_INVALID" },
  );
});

test("uses normal TLS validation plus the canonical leaf fingerprint without proxy or Host ambiguity", async (t) => {
  const tls = await tlsFixture(t);
  let observed;
  const { port, relayUrl } = await startHttpsServer(
    t,
    tls,
    (request, response) => {
      observed = {
        host: request.headers.host,
        method: request.method,
        rawHeaders: request.rawHeaders,
        url: request.url,
      };
      sendExact(
        response,
        Buffer.from(
          '{"paymentMoved":false,"status":"ok"}',
          "utf8",
        ),
      );
    },
  );
  const transport = createPinnedHttpsTransport({
    expectedFingerprint: tls.expectedFingerprint,
    relayUrl,
    tlsCertificatePem: tls.certificate.toString("utf8"),
  });
  const originalProxy = process.env.HTTPS_PROXY;
  process.env.HTTPS_PROXY =
    "http://127.0.0.1:1";
  try {
    const result = await transport.request({
      body: null,
      method: "GET",
      path: `/v1/sessions/${SESSION_ID}/view`,
    });
    assert.deepEqual(
      JSON.parse(result.body.toString("utf8")),
      { paymentMoved: false, status: "ok" },
    );
    assert.equal(result.statusCode, 200);
    assert.equal(result.contentType, "application/json");
    assert.deepEqual(
      Object.keys(transport).sort(),
      ["request", "verifyReceipt"],
    );
    const expected = receiptExpected({
      capabilityDigest: "a".repeat(64),
      enrollmentDigest: "b".repeat(64),
    });
    assert.equal(
      (
        await transport.verifyReceipt(
          await receiptBytes({
            ...expected,
            tls,
          }),
          expected,
        )
      ).certificateSha256,
      tls.expectedFingerprint,
    );
  } finally {
    if (originalProxy === undefined) {
      delete process.env.HTTPS_PROXY;
    } else {
      process.env.HTTPS_PROXY = originalProxy;
    }
  }
  assert.equal(observed.method, "GET");
  assert.equal(observed.url, `/v1/sessions/${SESSION_ID}/view`);
  assert.equal(observed.host, `127.0.0.1:${port}`);
  assert.equal(
    observed.rawHeaders.filter(
      (value, index) =>
        index % 2 === 0 &&
        value.toLowerCase() === "host",
    ).length,
    1,
  );
});

test("rejects wrong fingerprints, alternate certificates, hostname mismatch, and redirects", async (t) => {
  const firstTls = await tlsFixture(t);
  const alternateTls = await tlsFixture(t);
  const wrongHostnameTls = await tlsFixture(
    t,
    "localhost",
  );
  const first = await startHttpsServer(
    t,
    firstTls,
    (_request, response) => {
      sendExact(response, Buffer.from("{}"));
    },
  );
  const alternate = await startHttpsServer(
    t,
    alternateTls,
    (_request, response) => {
      sendExact(response, Buffer.from("{}"));
    },
  );
  const wrongHostname = await startHttpsServer(
    t,
    wrongHostnameTls,
    (_request, response) => {
      sendExact(response, Buffer.from("{}"));
    },
  );
  const path = `/v1/sessions/${SESSION_ID}/view`;

  const wrongFingerprint =
    `${firstTls.expectedFingerprint[0] === "0" ? "1" : "0"}` +
    firstTls.expectedFingerprint.slice(1);
  assert.throws(
    () => createPinnedHttpsTransport({
      expectedFingerprint: wrongFingerprint,
      relayUrl: first.relayUrl,
      tlsCertificatePem:
        firstTls.certificate.toString("utf8"),
    }),
    { code: "COORDINATION_CLIENT_INVALID" },
  );

  assert.throws(
    () => createPinnedHttpsTransport({
      expectedFingerprint:
        alternateTls.expectedFingerprint,
      relayUrl: alternate.relayUrl,
      tlsCertificatePem:
        firstTls.certificate.toString("utf8"),
    }),
    { code: "COORDINATION_CLIENT_INVALID" },
  );

  await assert.rejects(
    createPinnedHttpsTransport({
      expectedFingerprint:
        wrongHostnameTls.expectedFingerprint,
      relayUrl: wrongHostname.relayUrl,
      tlsCertificatePem:
        wrongHostnameTls.certificate.toString("utf8"),
    }).request({
      body: null,
      method: "GET",
      path,
    }),
    { code: "COORDINATION_CLIENT_INVALID" },
  );

  const redirect = await startHttpsServer(
    t,
    firstTls,
    (_request, response) => {
      response.writeHead(302, {
        location: alternate.relayUrl,
      });
      response.end();
    },
  );
  await assert.rejects(
    createPinnedHttpsTransport({
      expectedFingerprint:
        firstTls.expectedFingerprint,
      relayUrl: redirect.relayUrl,
      tlsCertificatePem:
        firstTls.certificate.toString("utf8"),
    }).request({
      body: null,
      method: "GET",
      path,
    }),
    { code: "COORDINATION_CLIENT_INVALID" },
  );
});

test("transport accepts only closed raw relay paths and method-specific bodies and headers", async (t) => {
  const tls = await tlsFixture(t);
  const observed = [];
  const { relayUrl } = await startHttpsServer(
    t,
    tls,
    (request, response) => {
      const chunks = [];
      request.on("data", (chunk) => chunks.push(chunk));
      request.on("end", () => {
        observed.push({
          body: Buffer.concat(chunks),
          contentLength:
            request.headers["content-length"],
          contentType: request.headers["content-type"],
          artifactType:
            request.headers[
              "x-clockchain-artifact-type"
            ],
          method: request.method,
          url: request.url,
        });
        sendExact(
          response,
          request.method === "GET" &&
            request.url.startsWith("/v1/artifacts/")
            ? Buffer.from("{}")
            : Buffer.from("{}"),
          {
            contentType:
              request.method === "GET" &&
              request.url.startsWith("/v1/artifacts/")
                ? "application/octet-stream"
                : "application/json",
          },
        );
      });
    },
  );
  const transport = createPinnedHttpsTransport({
    expectedFingerprint: tls.expectedFingerprint,
    relayUrl,
    tlsCertificatePem: tls.certificate.toString("utf8"),
  });
  const digest = "a".repeat(64);
  await transport.request({
    artifactType: "signed-descriptor",
    body: Buffer.from("{}"),
    method: "PUT",
    path: `/v1/artifacts/${digest}`,
  });
  assert.deepEqual(observed[0], {
    artifactType: "signed-descriptor",
    body: Buffer.from("{}"),
    contentLength: "2",
    contentType: "application/octet-stream",
    method: "PUT",
    url: `/v1/artifacts/${digest}`,
  });
  await transport.request({
    artifactType: "signed-descriptor",
    body: null,
    method: "GET",
    path: `/v1/artifacts/${digest}`,
  });
  assert.equal(observed[1].artifactType, undefined);
  assert.equal(observed[1].contentType, undefined);
  await transport.request({
    body: null,
    method: "GET",
    path: `/v1/sessions/${SESSION_ID}/enrollments`,
  });
  assert.equal(observed[2].body.length, 0);
  assert.equal(observed[2].method, "GET");
  assert.equal(
    observed[2].url,
    `/v1/sessions/${SESSION_ID}/enrollments`,
  );

  for (const request of [
    {
      body: null,
      method: "GET",
      path: `//localhost/v1/sessions/${SESSION_ID}/view`,
    },
    {
      body: null,
      method: "GET",
      path: `/v1/junk/../sessions/${SESSION_ID}/view`,
    },
    {
      body: null,
      method: "GET",
      path: `/v1/sessions/${SESSION_ID}/%76iew`,
    },
    {
      body: Buffer.from("{}"),
      method: "GET",
      path: `/v1/sessions/${SESSION_ID}/view`,
    },
    {
      body: null,
      method: "GET",
      path:
        `/v1/sessions/${SESSION_ID}/enrollments?` +
        "advisoryStatus=ready",
    },
    {
      body: null,
      method: "POST",
      path: "/v1/bootstrap",
    },
    {
      body: Buffer.from("{}"),
      method: "PUT",
      path: `/v1/artifacts/${digest}`,
    },
    {
      artifactType: "signed-descriptor",
      body: Buffer.from("{}"),
      method: "POST",
      path: "/v1/events",
    },
    {
      body: null,
      method: "GET",
      path:
        `/v1/sessions/${SESSION_ID}/events` +
        "?waitMs=30001",
    },
    {
      body: null,
      method: "GET",
      path: `/v1/sessions/${SESSION_ID}/view`,
      signal: Object.create(
        new AbortController().signal,
      ),
    },
  ]) {
    await assert.rejects(
      transport.request(request),
      { code: "COORDINATION_CLIENT_INVALID" },
    );
  }
});

test("bounds artifact downloads by the declared exact artifact policy", async (t) => {
  const tls = await tlsFixture(t);
  const digest = "a".repeat(64);
  const { relayUrl } = await startHttpsServer(
    t,
    tls,
    (_request, response) => {
      sendExact(
        response,
        Buffer.alloc(1_048_577),
        { contentType: "application/octet-stream" },
      );
    },
  );
  const transport = createPinnedHttpsTransport({
    expectedFingerprint: tls.expectedFingerprint,
    relayUrl,
    tlsCertificatePem:
      tls.certificate.toString("utf8"),
  });
  await assert.rejects(
    transport.request({
      artifactType: "signed-descriptor",
      body: null,
      method: "GET",
      path: `/v1/artifacts/${digest}`,
    }),
    { code: "COORDINATION_CLIENT_INVALID" },
  );
});

test("rejects duplicate or wrong response metadata and oversized bodies terminally", async (t) => {
  const tls = await tlsFixture(t);
  const cases = [
    (response) => {
      response.writeHead(200, [
        "content-length",
        "2",
        "content-length",
        "2",
        "content-type",
        "application/json",
      ]);
      response.end("{}");
    },
    (response) => {
      response.writeHead(200, [
        "content-length",
        "2",
        "content-type",
        "application/json",
        "content-type",
        "application/json",
      ]);
      response.end("{}");
    },
    (response) => {
      sendExact(response, Buffer.from("{}"), {
        contentType: "text/plain",
      });
    },
    (response) => {
      response.writeHead(200, {
        "content-encoding": "gzip",
        "content-length": "2",
        "content-type": "application/json",
      });
      response.end("{}");
    },
    (response) => {
      response.writeHead(200, {
        "content-length": "2",
        "content-type": "application/json",
        "transfer-encoding": "chunked",
      });
      response.end("{}");
    },
    (response) => {
      sendExact(response, Buffer.from("{}"), {
        statusCode: 201,
      });
    },
    (response) => {
      const body = Buffer.alloc(
        MAX_CLIENT_JSON_RESPONSE_BYTES + 1,
        0x20,
      );
      sendExact(response, body);
    },
  ];
  for (const respond of cases) {
    const { relayUrl } = await startHttpsServer(
      t,
      tls,
      (_request, response) => respond(response),
    );
    const transport = createPinnedHttpsTransport({
      expectedFingerprint:
        tls.expectedFingerprint,
      relayUrl,
      tlsCertificatePem:
        tls.certificate.toString("utf8"),
    });
    await assert.rejects(
      transport.request({
        body: null,
        method: "GET",
        path: `/v1/sessions/${SESSION_ID}/view`,
      }),
      { code: "COORDINATION_CLIENT_INVALID" },
    );
  }
});

test("classifies post-header truncation as ambiguous and retries one byte-identical committed append", async (t) => {
  const tls = await tlsFixture(t);
  const bodies = [];
  const { relayUrl } = await startHttpsServer(
    t,
    tls,
    (request, response) => {
      const chunks = [];
      request.on("data", (chunk) =>
        chunks.push(Buffer.from(chunk)),
      );
      request.on("end", () => {
        const body = Buffer.concat(chunks);
        bodies.push(body);
        if (bodies.length === 1) {
          response.writeHead(200, {
            "content-length": String(body.length + 5),
            "content-type": "application/json",
          });
          response.end(body);
          return;
        }
        sendExact(response, body);
      });
    },
  );
  const pinned = createPinnedHttpsTransport({
    expectedFingerprint: tls.expectedFingerprint,
    relayUrl,
    tlsCertificatePem:
      tls.certificate.toString("utf8"),
  });
  const fixture = await resumedClientFixture(
    t,
    (input) => pinned.request(input),
  );
  const event = await fixture.client.appendEvent({
    artifactDigest: null,
    kind: "ENROLLMENT_CONFIRMED",
    subjectRun: "release",
  });
  assert.equal(event.sequence, "0");
  assert.equal(bodies.length, 2);
  assert.deepEqual(bodies[0], bodies[1]);
});

test("bounds slow headers and cleans external AbortSignal listeners for later requests", async (t) => {
  const tls = await tlsFixture(t);
  let requests = 0;
  const { relayUrl } = await startHttpsServer(
    t,
    tls,
    (_request, response) => {
      requests += 1;
      if (requests === 1 || requests === 2) {
        return;
      }
      if (requests === 3) {
        setTimeout(
          () => sendExact(response, Buffer.from("[]")),
          CLIENT_HEADER_TIMEOUT_MS + 100,
        );
        return;
      }
      sendExact(response, Buffer.from("{}"));
    },
  );
  const transport = createPinnedHttpsTransport({
    expectedFingerprint: tls.expectedFingerprint,
    relayUrl,
    tlsCertificatePem: tls.certificate.toString("utf8"),
  });
  const path = `/v1/sessions/${SESSION_ID}/view`;
  const started = Date.now();
  await assert.rejects(
    transport.request({
      body: null,
      method: "GET",
      path,
    }),
    { code: "COORDINATION_TRANSPORT_AMBIGUOUS" },
  );
  assert.ok(
    Date.now() - started >=
      CLIENT_HEADER_TIMEOUT_MS - 250,
  );

  const controller = new AbortController();
  const aborted = transport.request({
    body: null,
    method: "GET",
    path,
    signal: controller.signal,
  });
  setTimeout(() => controller.abort(), 25);
  await assert.rejects(
    aborted,
    { code: "COORDINATION_CLIENT_ABORTED" },
  );

  const longPoll = await transport.request({
    body: null,
    method: "GET",
    path:
      `/v1/sessions/${SESSION_ID}/events` +
      "?waitMs=500",
  });
  assert.deepEqual(longPoll.body, Buffer.from("[]"));

  const response = await transport.request({
    body: null,
    method: "GET",
    path,
  });
  assert.deepEqual(response.body, Buffer.from("{}"));
});

test("bounds a response body that stalls after exact headers", async (t) => {
  const tls = await tlsFixture(t);
  const { relayUrl } = await startHttpsServer(
    t,
    tls,
    (_request, response) => {
      response.writeHead(200, {
        "content-length": "2",
        "content-type": "application/json",
      });
      response.write("{");
    },
  );
  const transport = createPinnedHttpsTransport({
    expectedFingerprint: tls.expectedFingerprint,
    relayUrl,
    tlsCertificatePem:
      tls.certificate.toString("utf8"),
  });
  const started = Date.now();
  await assert.rejects(
    transport.request({
      body: null,
      method: "GET",
      path: `/v1/sessions/${SESSION_ID}/view`,
    }),
    { code: "COORDINATION_TRANSPORT_AMBIGUOUS" },
  );
  assert.ok(
    Date.now() - started >= CLIENT_BODY_TIMEOUT_MS - 250,
  );
});

async function enrollmentFixture({
  capability,
  coordination,
  invitationKeys = INVITATION_KEYS,
  preflight,
  preflightPublicKey = rawPublicKey(preflight),
  role = "payer",
  coordinationKeyId = `${role}-coordination`,
  preflightKeyId = `${role}-preflight`,
  releaseId = RELEASE_ID,
}) {
  const accounts = {
    rehearsal: privateKeyToAccount(
      invitationKeys.rehearsal,
    ),
    stakeholder: privateKeyToAccount(
      invitationKeys.stakeholder,
    ),
  };
  const capabilityDigest = sha256(capability);
  const invitations = {};
  for (const run of ["rehearsal", "stakeholder"]) {
    const address = accounts[run].address.toLowerCase();
    invitations[run] = {
      address,
      algorithm: "eip191",
      signature: await accounts[run].signMessage({
        message: {
          raw: toHex(
            invitationProofPreimage({
              address,
              capabilityDigest,
              releaseId,
              repositorySha: REPOSITORY_SHA,
              role,
              run,
              sessionId: SESSION_ID,
            }),
          ),
        },
      }),
    };
  }
  const unsigned = {
    capabilityDigest,
    coordinationKey: {
      algorithm: "ed25519",
      keyId: coordinationKeyId,
      publicKey: rawPublicKey(coordination),
    },
    invitations,
    paymentMoved: false,
    preflightKey: {
      algorithm: "ed25519",
      keyId: preflightKeyId,
      publicKey: preflightPublicKey,
    },
    releaseId,
    repositorySha: REPOSITORY_SHA,
    role,
    schema:
      "clockchain.bilateral-coordination-enrollment/v1",
    sessionId: SESSION_ID,
  };
  return {
    ...unsigned,
    signature: sign(
      null,
      coordinationEnrollmentSignaturePreimage(unsigned),
      coordination.privateKey,
    ).toString("base64"),
  };
}

function receiptSigner(tls) {
  const algorithm =
    tls.signatureAlgorithm === "ed25519"
      ? null
      : "sha256";
  const keyOptions =
    tls.signatureAlgorithm === "rsa-pss-sha256"
      ? {
          key: tls.privateKeyObject,
          padding:
            cryptoConstants.RSA_PKCS1_PSS_PADDING,
          saltLength:
            cryptoConstants.RSA_PSS_SALTLEN_DIGEST,
        }
      : tls.privateKeyObject;
  const verifyOptions =
    tls.signatureAlgorithm === "rsa-pss-sha256"
      ? {
          key: new X509Certificate(
            tls.certificate,
          ).publicKey,
          padding:
            cryptoConstants.RSA_PKCS1_PSS_PADDING,
          saltLength:
            cryptoConstants.RSA_PSS_SALTLEN_DIGEST,
        }
      : new X509Certificate(tls.certificate).publicKey;
  return Object.freeze({
    certificateSha256: tls.expectedFingerprint,
    sign(preimage) {
      return sign(algorithm, preimage, keyOptions);
    },
    signatureAlgorithm: tls.signatureAlgorithm,
    verify(preimage, signature) {
      return verify(
        algorithm,
        preimage,
        verifyOptions,
        signature,
      );
    },
  });
}

async function receiptBytes({
  capabilityDigest,
  enrollmentDigest,
  role = "payer",
  tls,
}) {
  return createCoordinationReceipt({
    context: {
      capabilityDigest,
      enrollmentDigest,
      releaseId: RELEASE_ID,
      repositorySha: REPOSITORY_SHA,
      role,
      sessionId: SESSION_ID,
    },
    signer: receiptSigner(tls),
  });
}

function receiptExpected({
  capabilityDigest,
  enrollmentDigest,
  role = "payer",
}) {
  return Object.freeze({
    capabilityDigest,
    enrollmentDigest,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    role,
    sessionId: SESSION_ID,
  });
}

test("shared receipt contract creates and verifies exact Ed25519, ECDSA, and RSA-PSS bootstrap receipts", async (t) => {
  const capabilityDigest = "a".repeat(64);
  const enrollmentDigest = "b".repeat(64);
  const expected = receiptExpected({
    capabilityDigest,
    enrollmentDigest,
  });
  for (const algorithm of [
    "ed25519",
    "ecdsa-sha256",
    "rsa-pss-sha256",
  ]) {
    const tls = await tlsFixture(
      t,
      "127.0.0.1",
      algorithm,
    );
    const bytes = await receiptBytes({
      capabilityDigest,
      enrollmentDigest,
      tls,
    });
    const verifier =
      createReceiptVerifierFromCertificate({
        tlsCertificatePem:
          tls.certificate.toString("utf8"),
      });
    const receipt = await verifyCoordinationReceipt({
      bytes,
      expected,
      verifier,
    });
    assert.equal(
      receipt.schema,
      COORDINATION_RECEIPT_SCHEMA,
    );
    assert.equal(
      receipt.signatureAlgorithm,
      algorithm,
    );
    assert.equal(receipt.paymentMoved, false);
    await assert.rejects(
      verifyCoordinationReceipt({
        bytes: bytes.toString("utf8"),
        expected,
        verifier,
      }),
      { code: "COORDINATION_RECEIPT_INVALID" },
    );
    await assert.rejects(
      verifyCoordinationReceipt({
        bytes: Buffer.from(
          bytes.toString("utf8").replace(
            enrollmentDigest,
            "c".repeat(64),
          ),
        ),
        expected,
        verifier,
      }),
      { code: "COORDINATION_RECEIPT_INVALID" },
    );
  }
});

function injectedResponse({
  body,
  contentType = "application/json",
  statusCode = 200,
}) {
  return {
    body: Buffer.from(body),
    contentType,
    statusCode,
  };
}

async function clientFixture(
  t,
  request,
  {
    capability = FIXED_CAPABILITY,
    coordination = generateKeyPairSync("ed25519"),
    releaseId = RELEASE_ID,
    role = "payer",
    tlsAlgorithm = "ed25519",
    verifyReceipt: verifyReceiptOverride,
  } = {},
) {
  const tls = await tlsFixture(
    t,
    "127.0.0.1",
    tlsAlgorithm,
  );
  const preflight = generateKeyPairSync("ed25519");
  const { manifest } = manifestFixture(tls, {
    randomBytes: () => Buffer.from(capability),
    releaseId,
    role,
  });
  const enrollment = await enrollmentFixture({
    capability,
    coordination,
    preflight,
    releaseId,
    role,
  });
  const verifier = createReceiptVerifierFromCertificate({
    tlsCertificatePem:
      tls.certificate.toString("utf8"),
  });
  const transport = Object.freeze({
    request,
    verifyReceipt(bytes, expected) {
      if (verifyReceiptOverride !== undefined) {
        return verifyReceiptOverride(
          Buffer.from(bytes),
          { ...expected },
          verifier,
        );
      }
      return verifyCoordinationReceipt({
        bytes,
        expected,
        verifier,
      });
    },
  });
  const client = createCoordinationClient({
    coordinationIdentity: {
      keyId: `${role}-coordination`,
      privateKeyPem: privateKeyPem(coordination),
      publicKey: rawPublicKey(coordination),
    },
    manifest,
    transport,
  });
  return {
    capability,
    client,
    coordination,
    enrollment,
    manifest,
    preflight,
    tls,
    transport,
  };
}

async function resumedClientFixture(
  t,
  request,
  {
    capability = FIXED_CAPABILITY,
    coordination = generateKeyPairSync("ed25519"),
    nowMs = NOW_MS,
    role = "payer",
    senderState = {
      previousEventDigest: null,
      sequence: "0",
    },
    tlsAlgorithm = "ed25519",
    verifyReceipt: verifyReceiptOverride,
  } = {},
) {
  const tls = await tlsFixture(
    t,
    "127.0.0.1",
    tlsAlgorithm,
  );
  const preflight = generateKeyPairSync("ed25519");
  const { manifest } = manifestFixture(tls, {
    nowMs,
    randomBytes: () => Buffer.from(capability),
    role,
  });
  const enrollment = await enrollmentFixture({
    capability,
    coordination,
    preflight,
    role,
  });
  const enrollmentDigest = sha256(
    canonicalBytes(enrollment),
  );
  const receiptBytesValue = await receiptBytes({
    capabilityDigest: sha256(capability),
    enrollmentDigest,
    role,
    tls,
  });
  const activeLaunchState = await createActiveLaunchState({
    coordinationIdentity: {
      keyId: `${role}-coordination`,
      privateKeyPem: privateKeyPem(coordination),
      publicKey: rawPublicKey(coordination),
    },
    enrollment,
    manifest,
    receiptBytes: receiptBytesValue,
  });
  const verifier = createReceiptVerifierFromCertificate({
    tlsCertificatePem:
      tls.certificate.toString("utf8"),
  });
  const transport = Object.freeze({
    request,
    verifyReceipt(bytes, expected) {
      if (verifyReceiptOverride !== undefined) {
        return verifyReceiptOverride(
          Buffer.from(bytes),
          { ...expected },
          verifier,
        );
      }
      return verifyCoordinationReceipt({
        bytes,
        expected,
        verifier,
      });
    },
  });
  const client = await createResumedCoordinationClient({
    activeLaunchState,
    coordinationIdentity: {
      keyId: `${role}-coordination`,
      privateKeyPem: privateKeyPem(coordination),
      publicKey: rawPublicKey(coordination),
    },
    senderState,
    transport,
  });
  return {
    activeLaunchState,
    capability,
    client,
    coordination,
    enrollment,
    manifest,
    preflight,
    receiptBytes: receiptBytesValue,
    tls,
    transport,
  };
}

test("role clients expose only scoped commercial-intent methods", async (t) => {
  const fixture = await resumedClientFixture(t, async () => injectedResponse({ body: Buffer.from("null", "utf8") }));
  assert.equal(typeof fixture.client.publishPayerMandate, "function");
  assert.equal(typeof fixture.client.submitPaymentRequest, "function");
  assert.equal(typeof fixture.client.readPayerMandate, "function");
  assert.equal(typeof fixture.client.readPaymentRequest, "function");
});

async function enrollmentSetFixture({
  activeLaunchState,
  tls,
}) {
  const activeRole = activeLaunchState.role;
  const peerRole =
    activeRole === "payer" ? "payee" : "payer";
  const peerCapability = Buffer.alloc(32, 0x52);
  const peerCoordination =
    generateKeyPairSync("ed25519");
  const peerPreflight =
    generateKeyPairSync("ed25519");
  const peerEnrollment = await enrollmentFixture({
    capability: peerCapability,
    coordination: peerCoordination,
    invitationKeys: PEER_INVITATION_KEYS,
    preflight: peerPreflight,
    role: peerRole,
  });
  const peerEnrollmentBytes =
    canonicalBytes(peerEnrollment);
  const peerReceipt = await receiptBytes({
    capabilityDigest: sha256(peerCapability),
    enrollmentDigest: sha256(peerEnrollmentBytes),
    role: peerRole,
    tls,
  });
  const activeEntry = {
    enrollmentBase64:
      activeLaunchState.enrollmentBase64,
    enrollmentDigest:
      activeLaunchState.enrollmentDigest,
    receiptBase64:
      activeLaunchState.receiptBase64,
  };
  const peerEntry = {
    enrollmentBase64:
      peerEnrollmentBytes.toString("base64"),
    enrollmentDigest: sha256(peerEnrollmentBytes),
    receiptBase64: peerReceipt.toString("base64"),
  };
  return {
    enrollments: {
      payee:
        activeRole === "payee"
          ? activeEntry
          : peerEntry,
      payer:
        activeRole === "payer"
          ? activeEntry
          : peerEntry,
    },
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    schema:
      "clockchain.bilateral-coordination-enrollment-set/v1",
    sessionId: SESSION_ID,
  };
}

test("gates enrollment-set authority until bootstrap and returns one exact verified frozen set afterward", async (t) => {
  const requests = [];
  const receiptVerifications = [];
  let fixture;
  let setBytes;
  const request = async (input) => {
    requests.push({
      ...input,
      body:
        input.body === null
          ? null
          : Buffer.from(input.body),
    });
    if (input.path === "/v1/bootstrap") {
      const wrapper = JSON.parse(
        input.body.toString("utf8"),
      );
      return injectedResponse({
        body: await receiptBytes({
          capabilityDigest:
            wrapper.enrollment.capabilityDigest,
          enrollmentDigest: sha256(
            canonicalBytes(wrapper.enrollment),
          ),
          tls: fixture.tls,
        }),
      });
    }
    return injectedResponse({ body: setBytes });
  };
  fixture = await clientFixture(t, request, {
    async verifyReceipt(bytes, expected, verifier) {
      receiptVerifications.push({
        bytes: Buffer.from(bytes),
        expected: { ...expected },
      });
      return verifyCoordinationReceipt({
        bytes,
        expected,
        verifier,
      });
    },
  });
  await assert.rejects(
    () => fixture.client.readEnrollmentSet(),
    { code: "COORDINATION_CLIENT_INVALID" },
  );
  assert.equal(requests.length, 0);
  const bootstrap = await fixture.client.bootstrap({
    enrollment: fixture.enrollment,
  });
  const exact = await enrollmentSetFixture({
    activeLaunchState: bootstrap.activeLaunchState,
    tls: fixture.tls,
  });
  setBytes = stableBytes(exact);
  receiptVerifications.length = 0;
  const set = await fixture.client.readEnrollmentSet();
  assert.deepEqual(set, exact);
  assert.equal(Object.isFrozen(set), true);
  assert.equal(Object.isFrozen(set.enrollments), true);
  assert.deepEqual(
    requests.at(-1),
    {
      body: null,
      method: "GET",
      path: `/v1/sessions/${SESSION_ID}/enrollments`,
    },
  );
  assert.deepEqual(
    receiptVerifications.map(
      ({ expected }) => expected.role,
    ),
    ["payee", "payer"],
  );
  assert.deepEqual(
    Object.keys(fixture.client).sort(),
    [
      "appendEvent",
      "bootstrap",
      "getArtifact",
      "publishPayerMandate",
      "putArtifact",
      "readEnrollmentSet",
      "readEvents",
      "readPayerMandate",
      "readPaymentRequest",
      "readSessionView",
      "readVerifierPublication",
      "submitPaymentRequest",
    ],
  );
});

test("resumed clients are immediately ready to read the exact authenticated enrollment set", async (t) => {
  for (const role of ["payer", "payee"]) {
    const requests = [];
    const receiptRoles = [];
    let setBytes;
    const fixture = await resumedClientFixture(
      t,
      async (input) => {
        requests.push({ ...input });
        return injectedResponse({ body: setBytes });
      },
      {
        role,
        async verifyReceipt(
          bytes,
          expected,
          verifier,
        ) {
          receiptRoles.push(expected.role);
          return verifyCoordinationReceipt({
            bytes,
            expected,
            verifier,
          });
        },
      },
    );
    const exact = await enrollmentSetFixture({
      activeLaunchState: fixture.activeLaunchState,
      tls: fixture.tls,
    });
    setBytes = stableBytes(exact);
    const set =
      await fixture.client.readEnrollmentSet();
    assert.deepEqual(set, exact, role);
    assert.deepEqual(
      receiptRoles,
      ["payee", "payer"],
      role,
    );
    assert.deepEqual(
      requests,
      [
        {
          body: null,
          method: "GET",
          path:
            `/v1/sessions/${SESSION_ID}/enrollments`,
        },
      ],
      role,
    );
  }
});

test("rejects hostile enrollment-set JSON, receipt bindings, certificates, and own-record substitutions", async (t) => {
  let responseBytes;
  const fixture = await resumedClientFixture(
    t,
    async () =>
      injectedResponse({ body: responseBytes }),
    { tlsAlgorithm: "ecdsa-sha256" },
  );
  const exact = await enrollmentSetFixture({
    activeLaunchState: fixture.activeLaunchState,
    tls: fixture.tls,
  });
  const alternateCoordination =
    generateKeyPairSync("ed25519");
  const alternatePreflight =
    generateKeyPairSync("ed25519");
  const alternateEnrollment = await enrollmentFixture({
    capability: fixture.capability,
    coordination: alternateCoordination,
    preflight: alternatePreflight,
    role: "payer",
  });
  const alternateEnrollmentBytes =
    canonicalBytes(alternateEnrollment);
  const alternateReceipt = await receiptBytes({
    capabilityDigest: sha256(fixture.capability),
    enrollmentDigest: sha256(
      alternateEnrollmentBytes,
    ),
    tls: fixture.tls,
  });
  const secondExactReceipt = await receiptBytes({
    capabilityDigest:
      fixture.activeLaunchState.capabilityDigest,
    enrollmentDigest:
      fixture.activeLaunchState.enrollmentDigest,
    tls: fixture.tls,
  });
  assert.notDeepEqual(
    secondExactReceipt,
    Buffer.from(
      fixture.activeLaunchState.receiptBase64,
      "base64",
    ),
  );

  const parsedOwnReceipt = JSON.parse(
    Buffer.from(
      exact.enrollments.payer.receiptBase64,
      "base64",
    ).toString("utf8"),
  );
  const cases = [
    {
      label: "missing top-level field",
      value: (() => {
        const candidate = structuredClone(exact);
        delete candidate.paymentMoved;
        return candidate;
      })(),
    },
    {
      label: "extra enrollment field",
      value: {
        ...exact,
        enrollments: {
          ...exact.enrollments,
          payer: {
            ...exact.enrollments.payer,
            advisoryStatus: "ready",
          },
        },
      },
    },
    {
      label: "digest mismatch",
      value: {
        ...exact,
        enrollments: {
          ...exact.enrollments,
          payer: {
            ...exact.enrollments.payer,
            enrollmentDigest: "0".repeat(64),
          },
        },
      },
    },
    {
      label: "receipt signature",
      value: {
        ...exact,
        enrollments: {
          ...exact.enrollments,
          payer: {
            ...exact.enrollments.payer,
            receiptBase64: stableBytes({
              ...parsedOwnReceipt,
              signature:
                Buffer.alloc(64).toString("base64"),
            }).toString("base64"),
          },
        },
      },
    },
    {
      label: "receipt certificate",
      value: {
        ...exact,
        enrollments: {
          ...exact.enrollments,
          payer: {
            ...exact.enrollments.payer,
            receiptBase64: stableBytes({
              ...parsedOwnReceipt,
              certificateSha256: "0".repeat(64),
            }).toString("base64"),
          },
        },
      },
    },
    {
      label: "cross-role receipt substitution",
      value: {
        ...exact,
        enrollments: {
          ...exact.enrollments,
          payer: {
            ...exact.enrollments.payer,
            receiptBase64:
              exact.enrollments.payee.receiptBase64,
          },
        },
      },
    },
    {
      label: "own enrollment substitution",
      value: {
        ...exact,
        enrollments: {
          ...exact.enrollments,
          payer: {
            enrollmentBase64:
              alternateEnrollmentBytes.toString("base64"),
            enrollmentDigest:
              sha256(alternateEnrollmentBytes),
            receiptBase64:
              alternateReceipt.toString("base64"),
          },
        },
      },
    },
    {
      label: "own receipt byte substitution",
      value: {
        ...exact,
        enrollments: {
          ...exact.enrollments,
          payer: {
            ...exact.enrollments.payer,
            receiptBase64:
              secondExactReceipt.toString("base64"),
          },
        },
      },
    },
  ];
  for (const { label, value } of cases) {
    responseBytes = stableBytes(value);
    await assert.rejects(
      () => fixture.client.readEnrollmentSet(),
      { code: "COORDINATION_CLIENT_INVALID" },
      label,
    );
  }
  responseBytes = Buffer.from(
    `${stableBytes(exact).toString("utf8")} `,
  );
  await assert.rejects(
    () => fixture.client.readEnrollmentSet(),
    { code: "COORDINATION_CLIENT_INVALID" },
    "noncanonical response",
  );
  responseBytes = Buffer.from(
    stableBytes(exact)
      .toString("utf8")
      .replace(
        '"paymentMoved":false,',
        '"paymentMoved":false,"paymentMoved":false,',
      ),
  );
  await assert.rejects(
    () => fixture.client.readEnrollmentSet(),
    { code: "COORDINATION_CLIENT_INVALID" },
    "duplicate response key",
  );
});

test("bootstraps with one raw capability, retries only identical bytes, verifies the TLS receipt, and exposes no capability state", async (t) => {
  const requests = [];
  let fixture;
  const request = async (input) => {
    requests.push({
      ...input,
      body:
        input.body === null
          ? null
          : Buffer.from(input.body),
    });
    if (requests.length === 1) {
      input.body.fill(0);
      throw new CoordinationClientError(
        "COORDINATION_TRANSPORT_AMBIGUOUS",
      );
    }
    const wrapper = JSON.parse(
      input.body.toString("utf8"),
    );
    const enrollmentBytes = canonicalBytes(
      wrapper.enrollment,
    );
    return injectedResponse({
      body: await receiptBytes({
        capabilityDigest:
          wrapper.enrollment.capabilityDigest,
        enrollmentDigest: sha256(enrollmentBytes),
        tls: fixture.tls,
      }),
    });
  };
  fixture = await clientFixture(t, request);
  const bootstrap = await fixture.client.bootstrap({
    enrollment: fixture.enrollment,
  });
  const { activeLaunchState, receipt } = bootstrap;

  assert.equal(requests.length, 2);
  assert.deepEqual(requests[0].body, requests[1].body);
  assert.equal(requests[0].method, "POST");
  assert.equal(requests[0].path, "/v1/bootstrap");
  assert.equal(receipt.paymentMoved, false);
  assert.equal(
    receipt.capabilityDigest,
    sha256(fixture.capability),
  );
  assert.equal(
    activeLaunchState.schema,
    ACTIVE_LAUNCH_STATE_SCHEMA,
  );
  assert.deepEqual(
    Object.keys(activeLaunchState).sort(),
    [
      "capabilityDigest",
      "enrollmentBase64",
      "enrollmentDigest",
      "expectedTlsFingerprint",
      "expiresAtMs",
      "issuedAtMs",
      "operatorKeyId",
      "paymentMoved",
      "protocol",
      "receiptBase64",
      "relayUrl",
      "releaseId",
      "repositorySha",
      "role",
      "schema",
      "sessionId",
      "signature",
      "tlsCertificatePem",
    ],
  );
  assert.equal(
    Object.isFrozen(activeLaunchState),
    true,
  );
  assert.deepEqual(
    Buffer.from(
      activeLaunchState.enrollmentBase64,
      "base64",
    ),
    canonicalBytes(fixture.enrollment),
  );
  assert.equal(Object.isFrozen(bootstrap), true);
  assert.equal(
    JSON.stringify(bootstrap).includes(
      fixture.capability.toString("hex"),
    ),
    false,
  );
  assert.deepEqual(
    Object.keys(fixture.client).sort(),
    [
      "appendEvent",
      "bootstrap",
      "getArtifact",
      "publishPayerMandate",
      "putArtifact",
      "readEnrollmentSet",
      "readEvents",
      "readPayerMandate",
      "readPaymentRequest",
      "readSessionView",
      "readVerifierPublication",
      "submitPaymentRequest",
    ],
  );
  assert.equal(
    JSON.stringify(fixture.client).includes(
      fixture.capability.toString("hex"),
    ),
    false,
  );
  await assert.rejects(
    fixture.client.bootstrap({
      enrollment: fixture.enrollment,
    }),
    { code: "COORDINATION_CLIENT_INVALID" },
  );
});

test("bootstrap rejects wrong receipt fields, signatures, certificate binding, and enrollment scope without leaking the capability", async (t) => {
  const cases = [
    (receipt) => ({ ...receipt, extra: true }),
    (receipt) => ({
      ...receipt,
      paymentMoved: true,
    }),
    (receipt) => ({
      ...receipt,
      repositorySha: "e".repeat(40),
    }),
    (receipt) => ({
      ...receipt,
      signature: Buffer.alloc(64).toString("base64"),
    }),
  ];
  for (const mutate of cases) {
    let fixture;
    let calls = 0;
    const request = async (input) => {
      calls += 1;
      const wrapper = JSON.parse(
        input.body.toString("utf8"),
      );
      const receipt = JSON.parse(
        (
          await receiptBytes({
            capabilityDigest:
              wrapper.enrollment.capabilityDigest,
            enrollmentDigest: sha256(
              canonicalBytes(wrapper.enrollment),
            ),
            tls: fixture.tls,
          })
        ).toString("utf8"),
      );
      return injectedResponse({
        body: canonicalBytes(mutate(receipt)),
      });
    };
    fixture = await clientFixture(t, request);
    await assert.rejects(
      fixture.client.bootstrap({
        enrollment: fixture.enrollment,
      }),
      (error) => {
        assert.equal(
          error.code,
          "COORDINATION_CLIENT_INVALID",
        );
        assert.doesNotMatch(
          `${error.message}\n${error.stack}`,
          new RegExp(
            fixture.capability.toString("hex"),
          ),
        );
        return true;
      },
    );
    assert.equal(calls, 1);
  }

  const fixture = await clientFixture(
    t,
    async () => {
      throw new Error("must not send");
    },
  );
  await assert.rejects(
    fixture.client.bootstrap({
      enrollment: {
        ...fixture.enrollment,
        role: "payee",
      },
    }),
    { code: "COORDINATION_CLIENT_INVALID" },
  );

  const maliciousTransport = Object.freeze({
    request: async () =>
      injectedResponse({ body: Buffer.from("{}") }),
    verifyReceipt: async () => ({
      certificateSha256: "0".repeat(64),
      paymentMoved: false,
    }),
  });
  const maliciousClient = createCoordinationClient({
    coordinationIdentity: {
      keyId: "payer-coordination",
      privateKeyPem:
        privateKeyPem(fixture.coordination),
      publicKey: rawPublicKey(fixture.coordination),
    },
    manifest: fixture.manifest,
    transport: maliciousTransport,
  });
  await assert.rejects(
    maliciousClient.bootstrap({
      enrollment: fixture.enrollment,
    }),
    { code: "COORDINATION_CLIENT_INVALID" },
  );
});

test("creates and independently validates an exact capability-free active launch state", async (t) => {
  const fixture = await resumedClientFixture(
    t,
    async () => {
      throw new Error("must not send");
    },
    {
      capability: Buffer.alloc(32, 0xab),
    },
  );
  const exact = fixture.activeLaunchState;
  assert.deepEqual(
    await validateActiveLaunchState(exact),
    exact,
  );
  assert.equal(
    JSON.stringify(exact).includes(
      fixture.capability.toString("hex"),
    ),
    false,
  );
  assert.doesNotMatch(
    JSON.stringify(exact),
    /bootstrapCapability|privateKey|token/i,
  );
  const serializedState = JSON.stringify(exact);
  for (const representation of [
    fixture.capability.toString("hex"),
    fixture.capability.toString("hex").toUpperCase(),
    fixture.capability.toString("base64"),
    fixture.capability.toString("base64url"),
  ]) {
    assert.equal(
      serializedState.includes(representation),
      false,
    );
  }
  assert.deepEqual(
    Buffer.from(exact.enrollmentBase64, "base64"),
    canonicalBytes(fixture.enrollment),
  );
  const unsigned = { ...exact };
  delete unsigned.signature;
  assert.equal(
    ACTIVE_LAUNCH_STATE_SIGNATURE_DOMAIN,
    "clockchain.bilateral-active-launch-state-signature/v1\n",
  );
  assert.equal(
    verify(
      null,
      Buffer.concat([
        Buffer.from(
          ACTIVE_LAUNCH_STATE_SIGNATURE_DOMAIN,
          "ascii",
        ),
        Buffer.from(
          sha256(stableBytes(unsigned)),
          "ascii",
        ),
      ]),
      fixture.coordination.publicKey,
      Buffer.from(exact.signature, "base64"),
    ),
    true,
  );

  const receipt = JSON.parse(
    Buffer.from(
      exact.receiptBase64,
      "base64",
    ).toString("utf8"),
  );
  const cases = [
    { ...exact, extra: true },
    { ...exact, paymentMoved: true },
    {
      ...exact,
      capabilityDigest: "0".repeat(64),
    },
    {
      ...exact,
      enrollmentBase64: "not-base64",
    },
    {
      ...exact,
      enrollmentBase64: Buffer.from(
        `${canonicalBytes(fixture.enrollment).toString("utf8")} `,
      ).toString("base64"),
    },
    {
      ...exact,
      enrollmentDigest: "1".repeat(64),
    },
    { ...exact, role: "payee" },
    {
      ...exact,
      expectedTlsFingerprint: "2".repeat(64),
    },
    {
      ...exact,
      receiptBase64: "not-base64",
    },
    {
      ...exact,
      receiptBase64: Buffer.from(
        `${JSON.stringify(receipt)} `,
      ).toString("base64"),
    },
    {
      ...exact,
      receiptBase64: canonicalBytes({
        ...receipt,
        role: "payee",
      }).toString("base64"),
    },
  ];
  const alternateTls = await tlsFixture(t);
  const authenticatedMutations = {
    capabilityDigest: "0".repeat(64),
    enrollmentBase64:
      Buffer.from("{}").toString("base64"),
    enrollmentDigest: "1".repeat(64),
    expectedTlsFingerprint: "2".repeat(64),
    expiresAtMs: String(Number(exact.expiresAtMs) + 1),
    issuedAtMs: String(Number(exact.issuedAtMs) + 1),
    operatorKeyId: "clockchain-demo-2027",
    paymentMoved: true,
    protocol: "clockchain-bilateral/v2",
    receiptBase64:
      Buffer.from("{}").toString("base64"),
    relayUrl: "https://127.0.0.2:8443",
    releaseId: "release-b",
    repositorySha: "e".repeat(40),
    role: "payee",
    schema:
      "clockchain.bilateral-active-launch-state/v2",
    sessionId:
      "01234567-89ab-4def-8123-456789abcdef",
    tlsCertificatePem:
      alternateTls.certificate.toString("utf8"),
  };
  assert.deepEqual(
    Object.keys(authenticatedMutations).sort(),
    Object.keys(exact)
      .filter((key) => key !== "signature")
      .sort(),
  );
  for (const [field, replacement] of Object.entries(
    authenticatedMutations,
  )) {
    assert.notDeepEqual(replacement, exact[field]);
    cases.push({
      ...exact,
      [field]: replacement,
    });
  }
  cases.push(
    {
      ...exact,
      signature: "AA==",
    },
    {
      ...exact,
      signature:
        Buffer.alloc(64).toString("base64"),
    },
  );
  cases.push({
    ...exact,
    tlsCertificatePem:
      alternateTls.certificate.toString("utf8"),
  });
  for (const enrollmentOverrides of [
    {
      capability: Buffer.alloc(32, 0x5a),
    },
    {
      coordination: generateKeyPairSync("ed25519"),
      role: "payee",
    },
    {
      coordination: generateKeyPairSync("ed25519"),
      coordinationKeyId: "alternate-coordination",
    },
  ]) {
    const enrollment = await enrollmentFixture({
      capability: fixture.capability,
      coordination: fixture.coordination,
      preflight: fixture.preflight,
      ...enrollmentOverrides,
    });
    const enrollmentBytes = canonicalBytes(enrollment);
    const enrollmentDigest = sha256(enrollmentBytes);
    cases.push({
      ...exact,
      enrollmentBase64:
        enrollmentBytes.toString("base64"),
      enrollmentDigest,
      receiptBase64: (
        await receiptBytes({
          capabilityDigest: exact.capabilityDigest,
          enrollmentDigest,
          tls: fixture.tls,
        })
      ).toString("base64"),
    });
  }
  for (const candidate of cases) {
    await assert.rejects(
      validateActiveLaunchState(candidate),
      { code: "LAUNCH_MANIFEST_INVALID" },
    );
  }

  let invoked = false;
  const accessor = { ...exact };
  Object.defineProperty(accessor, "receiptBase64", {
    enumerable: true,
    get() {
      invoked = true;
      throw new Error("active-state-secret-canary");
    },
  });
  await assert.rejects(
    validateActiveLaunchState(accessor),
    { code: "LAUNCH_MANIFEST_INVALID" },
  );
  assert.equal(invoked, false);

  await assert.rejects(
    createActiveLaunchState({
      coordinationIdentity: {
        keyId: "payer-coordination",
        privateKeyPem:
          privateKeyPem(fixture.coordination),
        publicKey:
          rawPublicKey(fixture.coordination),
      },
      enrollment: {
        ...fixture.enrollment,
        role: "payee",
      },
      manifest: fixture.manifest,
      receiptBytes: fixture.receiptBytes,
    }),
    { code: "LAUNCH_MANIFEST_INVALID" },
  );
  const wrongIdentity = generateKeyPairSync("ed25519");
  await assert.rejects(
    createActiveLaunchState({
      coordinationIdentity: {
        keyId: "payer-coordination",
        privateKeyPem: privateKeyPem(wrongIdentity),
        publicKey: rawPublicKey(wrongIdentity),
      },
      enrollment: fixture.enrollment,
      manifest: fixture.manifest,
      receiptBytes: fixture.receiptBytes,
    }),
    { code: "LAUNCH_MANIFEST_INVALID" },
  );
  await assert.rejects(
    createActiveLaunchState({
      coordinationIdentity: {
        keyId: "payer-coordination",
        privateKeyPem:
          privateKeyPem(fixture.coordination),
        publicKey:
          rawPublicKey(fixture.coordination),
      },
      enrollment: fixture.enrollment,
      manifest: {
        ...fixture.manifest,
        operatorKeyId:
          fixture.capability.toString("hex"),
      },
      receiptBytes: fixture.receiptBytes,
    }),
    { code: "LAUNCH_MANIFEST_INVALID" },
  );
});

test("locally verifies immutable bootstrap evidence before exposing detached copies to a hostile transport verifier", async (t) => {
  const base = await clientFixture(
    t,
    async () => {
      throw new Error("replaced below");
    },
  );
  const enrollmentDigest = sha256(
    canonicalBytes(base.enrollment),
  );
  const expected = receiptExpected({
    capabilityDigest: sha256(base.capability),
    enrollmentDigest,
  });
  const payerReceipt = await receiptBytes({
    ...expected,
    tls: base.tls,
  });
  const payeeReceipt = await receiptBytes({
    ...expected,
    role: "payee",
    tls: base.tls,
  });
  const verifier = createReceiptVerifierFromCertificate({
    tlsCertificatePem:
      base.tls.certificate.toString("utf8"),
  });
  const identity = {
    keyId: "payer-coordination",
    privateKeyPem: privateKeyPem(base.coordination),
    publicKey: rawPublicKey(base.coordination),
  };

  const mutationSafe = createCoordinationClient({
    coordinationIdentity: identity,
    manifest: base.manifest,
    transport: Object.freeze({
      request: async () =>
        injectedResponse({ body: payerReceipt }),
      async verifyReceipt(bytes, suppliedExpected) {
        const preserved = Buffer.from(bytes);
        bytes.fill(0x78);
        suppliedExpected.role = "payee";
        return verifyCoordinationReceipt({
          bytes: preserved,
          expected,
          verifier,
        });
      },
    }),
  });
  const bootstrap = await mutationSafe.bootstrap({
    enrollment: base.enrollment,
  });
  assert.equal(
    bootstrap.receipt.role,
    "payer",
  );

  const crossScope = createCoordinationClient({
    coordinationIdentity: identity,
    manifest: base.manifest,
    transport: Object.freeze({
      request: async () =>
        injectedResponse({ body: payerReceipt }),
      async verifyReceipt(bytes, suppliedExpected) {
        payeeReceipt.copy(
          bytes,
          0,
          0,
          Math.min(bytes.length, payeeReceipt.length),
        );
        suppliedExpected.role = "payee";
        return verifyCoordinationReceipt({
          bytes: payeeReceipt,
          expected: {
            ...expected,
            role: "payee",
          },
          verifier,
        });
      },
    }),
  });
  await assert.rejects(
    crossScope.bootstrap({
      enrollment: base.enrollment,
    }),
    { code: "COORDINATION_CLIENT_INVALID" },
  );
});

test("resumes after manifest expiry from public active state only and permanently disables bootstrap", async (t) => {
  let calls = 0;
  let observed;
  const fixture = await resumedClientFixture(
    t,
    async (input) => {
      calls += 1;
      observed = JSON.parse(input.body.toString("utf8"));
      return injectedResponse({ body: input.body });
    },
    {
      nowMs: 0,
      senderState: {
        previousEventDigest: "a".repeat(64),
        sequence: "7",
      },
    },
  );
  assert.equal(
    Number(fixture.activeLaunchState.expiresAtMs) <
      Date.now(),
    true,
  );
  let bootstrapError;
  try {
    await fixture.client.bootstrap({
      enrollment: fixture.enrollment,
    });
  } catch (error) {
    bootstrapError = error;
  }
  assert.equal(
    bootstrapError.code,
    "COORDINATION_CLIENT_INVALID",
  );
  assert.equal(calls, 0);
  const event = await fixture.client.appendEvent({
    artifactDigest: null,
    kind: "FUNDING_INPUTS_READY",
    subjectRun: "release",
  });
  assert.equal(event.sequence, "7");
  assert.equal(
    observed.previousEventDigest,
    "a".repeat(64),
  );
  const scan = JSON.stringify({
    activeLaunchState: fixture.activeLaunchState,
    client: fixture.client,
    error: {
      code: bootstrapError.code,
      message: bootstrapError.message,
    },
  });
  assert.equal(
    scan.includes(fixture.capability.toString("hex")),
    false,
  );
});

test("resumed clients bind the local identity to the signed active enrollment before transport", async (t) => {
  let transportCalls = 0;
  const fixture = await resumedClientFixture(
    t,
    async () => {
      transportCalls += 1;
      throw new Error("must not send");
    },
  );
  const wrongIdentity = generateKeyPairSync("ed25519");
  await assert.rejects(
    createResumedCoordinationClient({
      activeLaunchState: fixture.activeLaunchState,
      coordinationIdentity: {
        keyId: "payer-coordination",
        privateKeyPem: privateKeyPem(wrongIdentity),
        publicKey: rawPublicKey(wrongIdentity),
      },
      senderState: {
        previousEventDigest: null,
        sequence: "0",
      },
      transport: fixture.transport,
    }),
    { code: "COORDINATION_CLIENT_INVALID" },
  );
  assert.equal(transportCalls, 0);
});

test("owns sender sequence and predecessor state and rejects a mutated or mismatched event response", async (t) => {
  const eventRequests = [];
  let eventAttempts = 0;
  const fixture = await clientFixture(
    t,
    async (input) => {
      if (input.path === "/v1/bootstrap") {
        const wrapper = JSON.parse(
          input.body.toString("utf8"),
        );
        return injectedResponse({
          body: await receiptBytes({
            capabilityDigest:
              wrapper.enrollment.capabilityDigest,
            enrollmentDigest: sha256(
              canonicalBytes(wrapper.enrollment),
            ),
            tls: fixture.tls,
          }),
        });
      }
      eventAttempts += 1;
      eventRequests.push(Buffer.from(input.body));
      if (eventAttempts === 1) {
        input.body.fill(0x78);
        throw new CoordinationClientError(
          "COORDINATION_TRANSPORT_AMBIGUOUS",
        );
      }
      return injectedResponse({
        body: input.body,
      });
    },
  );
  await fixture.client.bootstrap({
    enrollment: fixture.enrollment,
  });
  const first = await fixture.client.appendEvent({
    artifactDigest: null,
    kind: "ENROLLMENT_CONFIRMED",
    subjectRun: "release",
  });
  assert.equal(first.sequence, "0");
  assert.equal(first.previousEventDigest, null);
  assert.deepEqual(eventRequests[0], eventRequests[1]);

  const second = await fixture.client.appendEvent({
    artifactDigest: null,
    kind: "FUNDING_INPUTS_READY",
    subjectRun: "release",
  });
  assert.equal(second.sequence, "1");
  assert.equal(
    second.previousEventDigest,
    first.eventDigest,
  );

  const hostile = await resumedClientFixture(
    t,
    async (input) => {
      const event = JSON.parse(
        input.body.toString("utf8"),
      );
      return injectedResponse({
        body: canonicalBytes({
          ...event,
          sequence: "9",
        }),
      });
    },
  );
  await assert.rejects(
    hostile.client.appendEvent({
      artifactDigest: null,
      kind: "ENROLLMENT_CONFIRMED",
      subjectRun: "release",
    }),
    { code: "COORDINATION_CLIENT_INVALID" },
  );
});

test("fresh clients reject sender state while resumed clients require exact authenticated restart state and identity", async (t) => {
  const previousEventDigest = "a".repeat(64);
  let observed;
  const fixture = await resumedClientFixture(
    t,
    async (input) => {
      observed = JSON.parse(input.body.toString("utf8"));
      return injectedResponse({ body: input.body });
    },
    {
      senderState: {
        previousEventDigest,
        sequence: "7",
      },
    },
  );
  await fixture.client.appendEvent({
    artifactDigest: null,
    kind: "FUNDING_INPUTS_READY",
    subjectRun: "release",
  });
  assert.equal(observed.sequence, "7");
  assert.equal(
    observed.previousEventDigest,
    previousEventDigest,
  );

  const input = {
    coordinationIdentity: {
      keyId: "payer-coordination",
      privateKeyPem:
        privateKeyPem(fixture.coordination),
      publicKey: rawPublicKey(fixture.coordination),
    },
    manifest: fixture.manifest,
    transport: fixture.transport,
  };
  for (const candidate of [
    {
      ...input,
      coordinationIdentity: {
        ...input.coordinationIdentity,
        extra: true,
      },
    },
    {
      ...input,
      coordinationIdentity: {
        ...input.coordinationIdentity,
        publicKey: rawPublicKey(
          generateKeyPairSync("ed25519"),
        ),
      },
    },
    {
      ...input,
      senderState: {
        previousEventDigest: null,
        sequence: "0",
      },
    },
    {
      ...input,
      manifest: {
        ...input.manifest,
        bootstrapCapability: null,
      },
    },
    {
      ...input,
      manifest: fixture.activeLaunchState,
    },
  ]) {
    assert.throws(
      () => createCoordinationClient(candidate),
      { code: "COORDINATION_CLIENT_INVALID" },
    );
  }

  for (const senderState of [
    {
      previousEventDigest: null,
      sequence: "00",
    },
    {
      previousEventDigest: null,
      sequence: "0",
      trustedGlobalHistory: true,
    },
  ]) {
    await assert.rejects(
      createResumedCoordinationClient({
        activeLaunchState:
          fixture.activeLaunchState,
        coordinationIdentity:
          input.coordinationIdentity,
        senderState,
        transport: fixture.transport,
      }),
      { code: "COORDINATION_CLIENT_INVALID" },
    );
  }

  let overflowCalls = 0;
  const overflow = await resumedClientFixture(
    t,
    async () => {
      overflowCalls += 1;
      throw new Error("must not send");
    },
    {
      senderState: {
        previousEventDigest: "b".repeat(64),
        sequence: String(Number.MAX_SAFE_INTEGER),
      },
    },
  );
  await assert.rejects(
    overflow.client.appendEvent({
      artifactDigest: null,
      kind: "FUNDING_INPUTS_READY",
      subjectRun: "release",
    }),
    { code: "COORDINATION_CLIENT_INVALID" },
  );
  assert.equal(overflowCalls, 0);
});

test("snapshots queued append input before caller mutation", async (t) => {
  let releaseFirst;
  const firstBlocked = new Promise((resolve) => {
    releaseFirst = resolve;
  });
  const observed = [];
  let calls = 0;
  const fixture = await resumedClientFixture(
    t,
    async (input) => {
      calls += 1;
      observed.push(
        JSON.parse(input.body.toString("utf8")),
      );
      if (calls === 1) {
        await firstBlocked;
      }
      return injectedResponse({ body: input.body });
    },
  );
  const first = fixture.client.appendEvent({
    artifactDigest: null,
    kind: "ENROLLMENT_CONFIRMED",
    subjectRun: "release",
  });
  const secondInput = {
    artifactDigest: null,
    kind: "FUNDING_INPUTS_READY",
    subjectRun: "release",
  };
  const second =
    fixture.client.appendEvent(secondInput);
  secondInput.kind = "TERMINAL_FAILURE";
  secondInput.subjectRun = "stakeholder";
  releaseFirst();
  await first;
  await second;
  assert.equal(
    observed[1].kind,
    "FUNDING_INPUTS_READY",
  );
  assert.equal(observed[1].subjectRun, "release");
});

test("rejects event publication before bootstrap without calling transport", async (t) => {
  let calls = 0;
  const fixture = await clientFixture(
    t,
    async (input) => {
      calls += 1;
      return injectedResponse({ body: input.body });
    },
  );
  await assert.rejects(
    fixture.client.appendEvent({
      artifactDigest: null,
      kind: "ENROLLMENT_CONFIRMED",
      subjectRun: "release",
    }),
    { code: "COORDINATION_CLIENT_INVALID" },
  );
  assert.equal(calls, 0);
});

test("rejects a live capability artifact publication path before bootstrap", async (t) => {
  let calls = 0;
  const fixture = await clientFixture(
    t,
    async (input) => {
      calls += 1;
      return injectedResponse({
        body: canonicalBytes({
          artifactType: input.artifactType,
          byteLength: String(input.body.length),
          digest: sha256(input.body),
        }),
      });
    },
  );
  const rawCapability =
    fixture.capability.toString("hex");
  const leakingEnrollment =
    await enrollmentFixture({
      capability: fixture.capability,
      coordination: fixture.coordination,
      preflight: fixture.preflight,
      preflightKeyId: rawCapability,
    });
  const bytes = canonicalBytes(leakingEnrollment);
  assert.equal(
    bytes.includes(Buffer.from(rawCapability)),
    true,
  );
  await assert.rejects(
    fixture.client.putArtifact({
      artifactType: "coordination-enrollment",
      bytes,
      expectedDigest: sha256(bytes),
    }),
    { code: "COORDINATION_CLIENT_INVALID" },
  );
  assert.equal(calls, 0);
});

test("rejects a live capability hidden in signed bootstrap enrollment before transport", async (t) => {
  let calls = 0;
  const fixture = await clientFixture(
    t,
    async () => {
      calls += 1;
      throw new Error("must not send");
    },
  );
  const rawCapability =
    fixture.capability.toString("hex");
  const leakingEnrollment =
    await enrollmentFixture({
      capability: fixture.capability,
      coordination: fixture.coordination,
      preflight: fixture.preflight,
      preflightKeyId: rawCapability,
    });
  assert.equal(
    canonicalBytes(leakingEnrollment).includes(
      Buffer.from(rawCapability),
    ),
    true,
  );
  await assert.rejects(
    fixture.client.bootstrap({
      enrollment: leakingEnrollment,
    }),
    { code: "COORDINATION_CLIENT_INVALID" },
  );
  assert.equal(calls, 0);
});

test("rejects live capability bytes used as an enrolled public key before transport", async (t) => {
  let calls = 0;
  const capability = Buffer.alloc(32, 0xab);
  const fixture = await clientFixture(
    t,
    async () => {
      calls += 1;
      throw new Error("must not send");
    },
    { capability },
  );
  const enrollment = await enrollmentFixture({
    capability,
    coordination: fixture.coordination,
    preflight: fixture.preflight,
    preflightPublicKey:
      capability.toString("base64"),
  });
  await assert.rejects(
    fixture.client.bootstrap({ enrollment }),
    { code: "COORDINATION_CLIENT_INVALID" },
  );
  assert.equal(calls, 0);
});

test("rejects an uppercase live capability in launch context before transport", async (t) => {
  let calls = 0;
  const capability = Buffer.alloc(32, 0xab);
  const releaseId =
    capability.toString("hex").toUpperCase();
  await assert.rejects(
    clientFixture(
      t,
      async () => {
        calls += 1;
        throw new Error("must not send");
      },
      {
        capability,
        releaseId,
      },
    ),
    { code: "LAUNCH_MANIFEST_INVALID" },
  );
  assert.equal(calls, 0);
});

test("validates content-addressed artifacts and exact relay metadata on put and get", async (t) => {
  const operator = generateKeyPairSync("ed25519");
  const descriptorBytes = canonicalBytes(
    createSignedEnvelope(
      {
      amountOptions: [
        { currency: "USD", value: "100" },
      ],
      chainId: "11155111",
      expirySeconds: "600",
      mandateDigest: "b".repeat(64),
      namespace: "cbv1",
      payee: {
        address:
          "0xffeeddccbbaa99887766554433221100ffeeddcc",
        agentId: "8678",
        displayName: "Iris",
        role: "payee",
      },
      payer: {
        address:
          "0x00112233445566778899aabbccddeeff00112233",
        agentId: "8677",
        displayName: "Billy",
        role: "payer",
      },
      paymentMoved: false,
      promptSha256: "a".repeat(64),
      protocol: BILATERAL_PROTOCOL,
      protocolVersion: "1",
      registry:
        "0x8004a818bfb912233c491871b3d84c89a494bd9e",
      repositorySha: REPOSITORY_SHA,
      requestDigest: "c".repeat(64),
      schema:
        "clockchain.bilateral-session-descriptor/v2",
      sessionId: "00112233445566778899aabbccddeeff",
      settlement: "not-executed",
      },
      {
        keyId: OPERATOR_KEY_ID,
        privateKeyPem: privateKeyPem(operator),
      },
    ),
  );
  const digest = sha256(descriptorBytes);
  const fixture = await resumedClientFixture(
    t,
    async (input) => {
      if (input.method === "PUT") {
        return injectedResponse({
          body: canonicalBytes({
            artifactType: input.artifactType,
            byteLength: String(input.body.length),
            digest,
          }),
        });
      }
      assert.equal(
        input.artifactType,
        "signed-descriptor",
      );
      return injectedResponse({
        body: descriptorBytes,
        contentType: "application/octet-stream",
      });
    },
  );
  const metadata = await fixture.client.putArtifact({
    artifactType: "signed-descriptor",
    bytes: descriptorBytes,
    expectedDigest: digest,
  });
  assert.deepEqual(metadata, {
    artifactType: "signed-descriptor",
    byteLength: String(descriptorBytes.length),
    digest,
  });
  assert.deepEqual(
    await fixture.client.getArtifact({
      artifactType: "signed-descriptor",
      digest,
    }),
    descriptorBytes,
  );
});

test("fails unsupported reserved artifacts and mismatched acknowledgments locally", async (t) => {
  let calls = 0;
  const fixture = await resumedClientFixture(
    t,
    async (input) => {
      calls += 1;
      return injectedResponse({
        body: canonicalBytes({
          artifactType: input.artifactType,
          byteLength: String(input.body.length),
          digest: "f".repeat(64),
        }),
      });
    },
  );
  const unsupported = canonicalBytes({
    paymentMoved: false,
    schema: "clockchain.bilateral-token-commitment/v1",
  });
  await assert.rejects(
    fixture.client.putArtifact({
      artifactType: "coordination-receipt",
      bytes: unsupported,
      expectedDigest: sha256(unsupported),
    }),
    { code: "COORDINATION_CLIENT_INVALID" },
  );
  assert.equal(calls, 0);

  const enrollmentBytes = canonicalBytes(
    fixture.enrollment,
  );
  await assert.rejects(
    fixture.client.putArtifact({
      artifactType: "coordination-enrollment",
      bytes: enrollmentBytes,
      expectedDigest: sha256(enrollmentBytes),
    }),
    { code: "COORDINATION_CLIENT_INVALID" },
  );
  assert.equal(calls, 1);

  let getCalls = 0;
  const getFixture = await clientFixture(
    t,
    async () => {
      getCalls += 1;
      throw new Error("must not send");
    },
  );
  await assert.rejects(
    getFixture.client.getArtifact({
      artifactType: "coordination-receipt",
      digest: sha256(unsupported),
    }),
    { code: "COORDINATION_CLIENT_INVALID" },
  );
  assert.equal(getCalls, 0);
});

test("readEvents returns bounded structurally consistent raw history without claiming embedded-key authority", async (t) => {
  const coordination = generateKeyPairSync("ed25519");
  const events = [];
  const fixture = await clientFixture(
    t,
    async (input) => {
      assert.equal(input.method, "GET");
      return injectedResponse({
        body: Buffer.from(JSON.stringify(events)),
      });
    },
    { coordination },
  );
  const event0 = createCoordinationEnvelope({
    artifactDigest: null,
    kind: "ENROLLMENT_CONFIRMED",
    paymentMoved: false,
    previousEventDigest: null,
    privateKeyPem: privateKeyPem(coordination),
    publicKey: rawPublicKey(coordination),
    publicKeyId: "payer-coordination",
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    role: "payer",
    schema:
      "clockchain.bilateral-coordination-event/v1",
    sequence: "0",
    sessionId: SESSION_ID,
    subjectRun: "release",
  });
  const advisoryEvent = {
    ...event0,
    signature: {
      ...event0.signature,
      value: Buffer.alloc(64).toString("base64"),
    },
  };
  const payee = generateKeyPairSync("ed25519");
  const operator = generateKeyPairSync("ed25519");
  const payeeEvent = createCoordinationEnvelope({
    artifactDigest: null,
    kind: "ENROLLMENT_CONFIRMED",
    paymentMoved: false,
    previousEventDigest: null,
    privateKeyPem: privateKeyPem(payee),
    publicKey: rawPublicKey(payee),
    publicKeyId: "payee-coordination",
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    role: "payee",
    schema:
      "clockchain.bilateral-coordination-event/v1",
    sequence: "0",
    sessionId: SESSION_ID,
    subjectRun: "release",
  });
  const operatorEvent = createCoordinationEnvelope({
    artifactDigest: null,
    kind: "WAIT_FOR_FUNDING",
    paymentMoved: false,
    previousEventDigest: null,
    privateKeyPem: privateKeyPem(operator),
    publicKey: rawPublicKey(operator),
    publicKeyId: "operator-coordination",
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    role: "operator",
    schema:
      "clockchain.bilateral-coordination-event/v1",
    sequence: "0",
    sessionId: SESSION_ID,
    subjectRun: "release",
  });
  events.push(advisoryEvent, payeeEvent, operatorEvent);
  const advisory = await fixture.client.readEvents({
      after: null,
      waitMs: 0,
    });
  assert.deepEqual(advisory, [
    advisoryEvent,
    payeeEvent,
    operatorEvent,
  ]);
  assert.equal(Object.isFrozen(advisory), true);
  assert.equal(Object.isFrozen(advisory[0]), true);
  assert.equal(
    Object.isFrozen(advisory[0].signature),
    true,
  );

  events.length = 0;
  events.push({
    ...advisoryEvent,
    previousEventDigest: "a".repeat(64),
    sequence: "2",
  });
  await assert.rejects(
    fixture.client.readEvents({
      after: advisoryEvent.eventDigest,
      waitMs: 0,
    }),
    { code: "COORDINATION_CLIENT_INVALID" },
  );
});

test("readSessionView returns only a canonical context-bound advisory lifecycle view", async (t) => {
  const view = {
    facts: {
      descriptorAccepted: {
        rehearsal: { payee: false, payer: false },
        stakeholder: { payee: false, payer: false },
      },
      enrollmentConfirmed: {
        payee: false,
        payer: false,
      },
      enrollmentReceipt: false,
      fundingInputsReady: { payee: false, payer: false },
      identityPackageReady: {
        rehearsal: { payee: false, payer: false },
        stakeholder: { payee: false, payer: false },
      },
      payerMandateReady: { rehearsal: false, stakeholder: false },
      paymentRequestReady: { rehearsal: false, stakeholder: false },
      paymentRequestMatched: { rehearsal: false, stakeholder: false },
      preflightParticipantReady: {
        payee: false,
        payer: false,
      },
      preflightPlanReady: false,
      recoveryAuthorized: {
        rehearsal: { payee: null, payer: null },
        release: { payee: null, payer: null },
        stakeholder: { payee: null, payer: null },
      },
      recoveryRequired: {
        rehearsal: { payee: null, payer: null },
        release: { payee: null, payer: null },
        stakeholder: { payee: null, payer: null },
      },
      registered: {
        rehearsal: false,
        stakeholder: false,
      },
      releaseCompleted: false,
      rolePackageReady: {
        rehearsal: { payee: false, payer: false },
        stakeholder: { payee: false, payer: false },
      },
      roleStarted: {
        rehearsal: { payee: false, payer: false },
        stakeholder: { payee: false, payer: false },
      },
      runDescriptorReady: {
        rehearsal: false,
        stakeholder: false,
      },
      runStarted: {
        rehearsal: false,
        stakeholder: false,
      },
      tokenReady: { payee: false, payer: false },
      verifierPublicationVerified: {
        rehearsal: false,
        stakeholder: false,
      },
      verificationPassed: {
        rehearsal: false,
        stakeholder: false,
      },
      waitForFunding: false,
    },
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
    state: "BOOTSTRAPPING",
  };
  let responseView = view;
  const fixture = await clientFixture(
    t,
    async () =>
      injectedResponse({
        body: canonicalBytes(responseView),
      }),
  );
  const controller = new AbortController();
  assert.deepEqual(
    await fixture.client.readSessionView({
      signal: controller.signal,
    }),
    view,
  );
  responseView = {
    ...view,
    paymentMoved: true,
  };
  await assert.rejects(
    fixture.client.readSessionView(),
    { code: "COORDINATION_CLIENT_INVALID" },
  );
});

test("readVerifierPublication returns a context-bound durable claim or null", async (t) => {
  const requests = [];
  const claim = {
    paymentMoved: false,
    publicationDigest: "d".repeat(64),
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    schema: "clockchain.bilateral-verifier-publication/v1",
    sessionId: SESSION_ID,
    status: "VERIFICATION_PASSED",
    subjectRun: "rehearsal",
  };
  let body = canonicalBytes(claim);
  const fixture = await resumedClientFixture(t, async (input) => {
    requests.push({ ...input });
    return injectedResponse({ body });
  });
  const controller = new AbortController();
  const result = await fixture.client.readVerifierPublication({
    signal: controller.signal,
    subjectRun: "rehearsal",
  });
  assert.deepEqual({ ...result }, claim);
  assert.equal(Object.isFrozen(result), true);
  assert.deepEqual(requests, [{
    body: null,
    method: "GET",
    path: `/v1/sessions/${SESSION_ID}/verifier-publications/rehearsal`,
    signal: controller.signal,
  }]);
  body = Buffer.from("null", "utf8");
  assert.equal(
    await fixture.client.readVerifierPublication({ subjectRun: "rehearsal" }),
    null,
  );
});

test("readVerifierPublication rejects hostile response and caller-context substitutions", async (t) => {
  const claim = {
    paymentMoved: false,
    publicationDigest: "d".repeat(64),
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    schema: "clockchain.bilateral-verifier-publication/v1",
    sessionId: SESSION_ID,
    status: "VERIFICATION_PASSED",
    subjectRun: "rehearsal",
  };
  let response = claim;
  const fixture = await resumedClientFixture(t, async () =>
    injectedResponse({ body: canonicalBytes(response) }),
  );
  for (const mutation of [
    { paymentMoved: true },
    { publicationDigest: "invalid" },
    { releaseId: "release-other" },
    { repositorySha: "e".repeat(40) },
    { sessionId: "9f953393-86d0-4f99-9d6a-102f525fbecd" },
    { subjectRun: "stakeholder" },
    { status: "AUTHORIZED" },
    { extra: true },
  ]) {
    response = { ...claim, ...mutation };
    await assert.rejects(
      fixture.client.readVerifierPublication({ subjectRun: "rehearsal" }),
      { code: "COORDINATION_CLIENT_INVALID" },
    );
  }
  await assert.rejects(
    fixture.client.readVerifierPublication({ sessionId: SESSION_ID, subjectRun: "rehearsal" }),
    { code: "COORDINATION_CLIENT_INVALID" },
  );
  await assert.rejects(
    fixture.client.readVerifierPublication({ subjectRun: "release" }),
    { code: "COORDINATION_CLIENT_INVALID" },
  );
});
