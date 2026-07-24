import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { constants as fsConstants } from "node:fs";
import {
  chmod,
  mkdtemp,
  readdir,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  decryptInvitation,
  encryptInvitation,
  readSecretInvitation,
} from "../src/invitation.mjs";

const PRIVATE_KEY = `0x${"11".repeat(32)}`;
const PAYLOAD = {
  privateKey: PRIVATE_KEY,
  address: "0x1111111111111111111111111111111111111111",
  displayName: "Billy",
};

async function captureRejection(operation) {
  let rejection;

  try {
    await operation();
  } catch (error) {
    rejection = error;
  }

  assert.ok(rejection instanceof Error, "expected operation to reject");
  return rejection;
}

function assertErrorOmits(error, ...values) {
  const diagnostic = `${error.message}\n${error.stack ?? ""}`;

  for (const value of values) {
    assert.equal(
      diagnostic.includes(value),
      false,
      "error diagnostic must not echo sensitive input",
    );
  }
}

function alterHex(hex) {
  return `${hex[0] === "0" ? "1" : "0"}${hex.slice(1)}`;
}

function readInvitationInChild(invitationPath, timeoutMilliseconds = 750) {
  const invitationModuleUrl = new URL(
    "../src/invitation.mjs",
    import.meta.url,
  ).href;
  const script = `
    const { readSecretInvitation } = await import(process.argv[1]);
    try {
      await readSecretInvitation(process.argv[2]);
      process.stdout.write(JSON.stringify({ rejected: false }));
      process.exitCode = 2;
    } catch (error) {
      process.stdout.write(JSON.stringify({
        rejected: true,
        message: error.message,
      }));
    }
  `;

  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [
        "--input-type=module",
        "--eval",
        script,
        invitationModuleUrl,
        invitationPath,
      ],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });

    const timeout = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeoutMilliseconds);

    child.once("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
    child.once("close", (code, signal) => {
      clearTimeout(timeout);
      resolve({ code, signal, stderr, stdout, timedOut });
    });
  });
}

test("round-trips a validated invitation with a public-only bundle", async () => {
  const code = "correct-horse-battery-staple";
  const bundle = await encryptInvitation(PAYLOAD, code);

  assert.deepEqual(await decryptInvitation(bundle, code), PAYLOAD);
  assert.deepEqual(Object.keys(bundle).sort(), [
    "address",
    "crypto",
    "displayName",
    "schema",
    "version",
  ]);
  assert.equal(bundle.schema, "clockchain.handshake-invitation/v1");
  assert.equal(bundle.version, 1);
  assert.equal(bundle.address, PAYLOAD.address);
  assert.equal(bundle.displayName, PAYLOAD.displayName);
  assert.deepEqual(bundle.crypto.kdf, {
    name: "scrypt",
    N: 16_384,
    r: 8,
    p: 1,
    keyLength: 32,
  });
  assert.deepEqual(bundle.crypto.cipher, {
    name: "aes-256-gcm",
    ivLength: 12,
    tagLength: 16,
  });
  assert.equal(bundle.crypto.encoding, "hex");
  assert.match(bundle.crypto.salt, /^[0-9a-f]{64}$/);
  assert.match(bundle.crypto.iv, /^[0-9a-f]{24}$/);
  assert.match(bundle.crypto.ciphertext, /^(?:[0-9a-f]{2})+$/);
  assert.match(bundle.crypto.tag, /^[0-9a-f]{32}$/);

  const serialized = JSON.stringify(bundle);
  assert.equal(serialized.includes(PRIVATE_KEY), false);
  assert.equal(serialized.includes(code), false);
  assert.equal(Object.hasOwn(bundle, "privateKey"), false);
  assert.equal(Object.hasOwn(bundle, "code"), false);
});

test("rejects modified ciphertext with an authentication error", async () => {
  const code = "ciphertext-tamper-code";
  const bundle = await encryptInvitation(PAYLOAD, code);
  const modified = structuredClone(bundle);
  modified.crypto.ciphertext = alterHex(modified.crypto.ciphertext);

  const error = await captureRejection(() =>
    decryptInvitation(modified, code),
  );

  assert.match(error.message, /authentication/i);
  assertErrorOmits(error, code, PRIVATE_KEY);
});

test("rejects a wrong invitation code without echoing it", async () => {
  const correctCode = "correct-code-never-echo";
  const wrongCode = "wrong-code-never-echo";
  const bundle = await encryptInvitation(PAYLOAD, correctCode);

  const error = await captureRejection(() =>
    decryptInvitation(bundle, wrongCode),
  );

  assert.match(error.message, /authentication/i);
  assertErrorOmits(error, correctCode, wrongCode, PRIVATE_KEY);
});

test("rejects invitation codes larger than 1024 UTF-8 bytes before scrypt", async () => {
  const validCode = "bounded-code";
  const oversizedCode = "é".repeat(513);
  const bundle = await encryptInvitation(PAYLOAD, validCode);

  const encryptError = await captureRejection(() =>
    encryptInvitation(PAYLOAD, oversizedCode),
  );
  assert.match(encryptError.message, /too large/i);
  assertErrorOmits(encryptError, oversizedCode, PRIVATE_KEY);

  const decryptError = await captureRejection(() =>
    decryptInvitation(bundle, oversizedCode),
  );
  assert.match(decryptError.message, /too large/i);
  assert.doesNotMatch(decryptError.message, /authentication/i);
  assertErrorOmits(decryptError, oversizedCode, PRIVATE_KEY);
});

test("rejects malformed schema, KDF, and cipher metadata before decryption", async () => {
  const code = "metadata-validation-code";
  const bundle = await encryptInvitation(PAYLOAD, code);
  const malformedBundles = [
    Object.assign(structuredClone(bundle), {
      schema: "clockchain.handshake-invitation/v2",
    }),
    Object.assign(structuredClone(bundle), { version: 2 }),
    (() => {
      const malformed = structuredClone(bundle);
      malformed.crypto.kdf.N = 32_768;
      return malformed;
    })(),
    (() => {
      const malformed = structuredClone(bundle);
      malformed.crypto.cipher.name = "aes-128-gcm";
      return malformed;
    })(),
    (() => {
      const malformed = structuredClone(bundle);
      malformed.crypto.encoding = "base64";
      return malformed;
    })(),
  ];

  for (const malformed of malformedBundles) {
    const error = await captureRejection(() =>
      decryptInvitation(malformed, code),
    );
    assert.match(error.message, /invalid or unsupported/i);
    assert.doesNotMatch(error.message, /authentication/i);
    assertErrorOmits(error, code, PRIVATE_KEY);
  }
});

test("rejects canonical ciphertext larger than 4096 bytes before scrypt", async () => {
  const code = "oversized-ciphertext-code";
  const bundle = await encryptInvitation(PAYLOAD, code);
  const oversized = structuredClone(bundle);
  oversized.crypto.ciphertext = "ab".repeat(4_097);

  const error = await captureRejection(() =>
    decryptInvitation(oversized, code),
  );

  assert.match(error.message, /invalid or unsupported/i);
  assert.doesNotMatch(error.message, /authentication/i);
  assertErrorOmits(error, code, PRIVATE_KEY);
});

test("authenticates the public invitation header as AES-GCM AAD", async () => {
  const code = "header-aad-code";
  const bundle = await encryptInvitation(PAYLOAD, code);
  const modified = structuredClone(bundle);
  modified.displayName = "Mallory";

  const error = await captureRejection(() =>
    decryptInvitation(modified, code),
  );

  assert.match(error.message, /authentication/i);
  assertErrorOmits(error, code, PRIVATE_KEY);
});

test("readSecretInvitation accepts only an owner-readable regular file", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "clockchain-invitation-"));
  t.after(() => rm(directory, { recursive: true, force: true }));

  const code = "file-code-never-echo";
  const bundle = await encryptInvitation(PAYLOAD, code);
  const invitationPath = join(directory, "invitation.json");
  await writeFile(
    invitationPath,
    JSON.stringify({ bundle, code }),
    { encoding: "utf8", mode: 0o600 },
  );
  await chmod(invitationPath, 0o600);

  assert.deepEqual(await readSecretInvitation(invitationPath), { bundle, code });

  const extraFieldPath = join(directory, "extra-field.json");
  await writeFile(
    extraFieldPath,
    JSON.stringify({ bundle, code, privateKey: PRIVATE_KEY }),
    { encoding: "utf8", mode: 0o600 },
  );
  await chmod(extraFieldPath, 0o600);
  const extraFieldError = await captureRejection(() =>
    readSecretInvitation(extraFieldPath),
  );
  assert.match(extraFieldError.message, /invalid/i);
  assertErrorOmits(extraFieldError, code, PRIVATE_KEY);

  const emptyCodePath = join(directory, "empty-code.json");
  await writeFile(
    emptyCodePath,
    JSON.stringify({ bundle, code: "" }),
    { encoding: "utf8", mode: 0o600 },
  );
  await chmod(emptyCodePath, 0o600);
  const emptyCodeError = await captureRejection(() =>
    readSecretInvitation(emptyCodePath),
  );
  assert.match(emptyCodeError.message, /invalid/i);
  assertErrorOmits(emptyCodeError, PRIVATE_KEY);

  const symlinkPath = join(directory, `${code}.json`);
  await symlink(invitationPath, symlinkPath);
  const symlinkError = await captureRejection(() =>
    readSecretInvitation(symlinkPath),
  );
  assert.match(symlinkError.message, /regular file/i);
  assertErrorOmits(symlinkError, code, PRIVATE_KEY);

  if (process.platform !== "win32") {
    await chmod(invitationPath, 0o640);
    const permissionError = await captureRejection(() =>
      readSecretInvitation(invitationPath),
    );
    assert.match(permissionError.message, /permissions/i);
    assertErrorOmits(permissionError, code, PRIVATE_KEY);
  }
});

test("closes the secret file descriptor after parse and validation failures", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "clockchain-invalid-invitation-"));
  t.after(() => rm(directory, { recursive: true, force: true }));

  const malformedPath = join(directory, "malformed.json");
  const invalidPath = join(directory, "invalid.json");
  await writeFile(malformedPath, "{", { encoding: "utf8", mode: 0o600 });
  await writeFile(invalidPath, JSON.stringify({ bundle: {}, code: "invalid" }), {
    encoding: "utf8",
    mode: 0o600,
  });
  await chmod(malformedPath, 0o600);
  await chmod(invalidPath, 0o600);

  let descriptorsBefore;
  try {
    descriptorsBefore = (await readdir("/dev/fd")).length;
  } catch {
    descriptorsBefore = undefined;
  }

  for (let attempt = 0; attempt < 4; attempt += 1) {
    await captureRejection(() => readSecretInvitation(malformedPath));
    await captureRejection(() => readSecretInvitation(invalidPath));
  }

  if (descriptorsBefore !== undefined) {
    const descriptorsAfter = (await readdir("/dev/fd")).length;
    assert.ok(
      descriptorsAfter <= descriptorsBefore + 1,
      "secret invitation failures must not leak file descriptors",
    );
  }

  const movedPath = join(directory, "moved-after-rejection.json");
  await rename(malformedPath, movedPath);
  await rm(movedPath);
});

test("rejects a POSIX FIFO without blocking before fstat", async (t) => {
  if (
    process.platform === "win32" ||
    typeof fsConstants.O_NONBLOCK !== "number" ||
    fsConstants.O_NONBLOCK === 0
  ) {
    t.skip("POSIX O_NONBLOCK is unavailable");
    return;
  }

  const directory = await mkdtemp(join(tmpdir(), "clockchain-fifo-invitation-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const fifoPath = join(directory, "invitation.fifo");
  const mkfifo = spawnSync("mkfifo", [fifoPath], { stdio: "ignore" });

  if (mkfifo.error?.code === "ENOENT" || mkfifo.status !== 0) {
    t.skip("mkfifo is unavailable");
    return;
  }

  const child = await readInvitationInChild(fifoPath);

  assert.equal(
    child.timedOut,
    false,
    "child timed out because opening the FIFO blocked before fstat",
  );
  assert.equal(child.signal, null);
  assert.equal(child.code, 0, child.stderr);
  const report = JSON.parse(child.stdout);
  assert.equal(report.rejected, true);
  assert.match(report.message, /regular file/i);
});

test("rejects a mode-0600 secret invitation larger than 16384 bytes before reading", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "clockchain-large-invitation-"));
  t.after(() => rm(directory, { recursive: true, force: true }));

  const code = "oversized-file-code-never-echo";
  const bundle = await encryptInvitation(PAYLOAD, code);
  const serialized = JSON.stringify({ bundle, code });
  const oversized = serialized.padEnd(16_385, " ");
  assert.equal(Buffer.byteLength(oversized, "utf8"), 16_385);

  const invitationPath = join(directory, "oversized.json");
  await writeFile(invitationPath, oversized, {
    encoding: "utf8",
    mode: 0o600,
  });
  await chmod(invitationPath, 0o600);

  const error = await captureRejection(() =>
    readSecretInvitation(invitationPath),
  );
  assert.match(error.message, /too large/i);
  assertErrorOmits(error, code, PRIVATE_KEY);
});
