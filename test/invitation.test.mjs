import assert from "node:assert/strict";
import { chmod, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
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

  const symlinkPath = join(directory, "invitation-link.json");
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
