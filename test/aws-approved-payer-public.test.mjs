import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  createHash,
  generateKeyPairSync,
  X509Certificate,
} from "node:crypto";
import {
  chmod,
  link,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  createApprovedPayerPublicProjection,
  readApprovedPayerPublicProjection,
  writeApprovedPayerPublicProjection,
} from "../src/bilateral/aws/approved-payer-public.mjs";
import {
  createPayerBootstrapKey,
  payerBootstrapClaimFingerprint,
  sshEd25519Fingerprint,
} from "../src/bilateral/local-mcp/payer-bootstrap-envelope.mjs";

const RELEASE_ID = "release-aws-bootstrap";
const REPOSITORY_SHA = "abcdef0123456789abcdef0123456789abcdef01";
const SESSION_ID = "22222222-2222-4222-8222-222222222222";

function sshString(value) {
  const bytes = Buffer.from(value);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

function openSshPublicKey(pair) {
  const raw = pair.publicKey
    .export({ format: "der", type: "spki" })
    .subarray(-32);
  return `ssh-ed25519 ${Buffer.concat([
    sshString("ssh-ed25519"),
    sshString(raw),
  ]).toString("base64")}`;
}

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), "approved-payer-public-"));
  await chmod(root, 0o700);
  t.after(() => rm(root, { recursive: true, force: true }));
  const certificatePath = join(root, "payer.crt");
  const privateKeyPath = join(root, "payer.key");
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "ed25519",
    "-keyout", privateKeyPath,
    "-out", certificatePath,
    "-nodes", "-days", "1",
    "-subj", "/CN=payer.clockchain.network",
    "-addext", "subjectAltName=DNS:payer.clockchain.network",
  ], { stdio: "ignore" });
  const certificatePem = await readFile(certificatePath, "utf8");
  const bootstrap = createPayerBootstrapKey();
  const ssh = generateKeyPairSync("ed25519");
  const sshPublicKey = openSshPublicKey(ssh);
  const claim = {
    claimNonce: "11111111-1111-4111-8111-111111111111",
    mcpTlsCertificatePem: certificatePem,
    mcpTlsFingerprint: createHash("sha256")
      .update(new X509Certificate(certificatePem).raw)
      .digest("hex"),
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    role: "payer",
    schema: "clockchain.payer-bootstrap-claim/v1",
    sessionId: SESSION_ID,
    sshPublicKey,
    sshPublicKeyFingerprint: sshEd25519Fingerprint(sshPublicKey),
    x25519PublicKey: bootstrap.publicKey,
  };
  return { claim, root, path: join(root, "approved-payer.json") };
}

test("projects and persists only approved public Payer certificate bindings", async (t) => {
  const { claim, path } = await fixture(t);
  const claimFingerprint = payerBootstrapClaimFingerprint(claim);
  const projection = createApprovedPayerPublicProjection({
    claim,
    claimFingerprint,
    expiresAtMs: "2000000600000",
    nowMs: 2_000_000_000_000,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
  });
  assert.deepEqual(projection, {
    certificateFingerprint: claim.mcpTlsFingerprint,
    certificatePem: claim.mcpTlsCertificatePem,
    claimFingerprint,
    expiresAtMs: "2000000600000",
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    schema: "clockchain.aws-approved-payer-public/v1",
    sessionId: SESSION_ID,
    status: "APPROVED",
  });
  await writeApprovedPayerPublicProjection(path, projection);
  assert.deepEqual(JSON.parse(await readFile(path, "utf8")), projection);
  const serialized = await readFile(path, "utf8");
  for (const forbidden of [
    "sshPublicKey",
    "x25519PublicKey",
    "claimNonce",
    "PRIVATE KEY",
  ]) {
    assert.equal(serialized.includes(forbidden), false);
  }
});

test("rejects changed scope, fingerprint, expiry, and unsafe destination replacement", async (t) => {
  const { claim, path } = await fixture(t);
  const input = {
    claim,
    claimFingerprint: payerBootstrapClaimFingerprint(claim),
    expiresAtMs: "2000000600000",
    nowMs: 2_000_000_000_000,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
  };
  assert.throws(() => createApprovedPayerPublicProjection({
    ...input,
    claimFingerprint: "f".repeat(64),
  }));
  assert.throws(() => createApprovedPayerPublicProjection({
    ...input,
    expiresAtMs: "1999999999999",
  }));
  const projection = createApprovedPayerPublicProjection(input);
  await writeApprovedPayerPublicProjection(path, projection);
  await assert.rejects(writeApprovedPayerPublicProjection("relative.json", projection));
});

test("reads a missing approved Payer public projection as polling null and fails closed on unsafe files", async (t) => {
  const { claim, path, root } = await fixture(t);
  const projection = createApprovedPayerPublicProjection({
    claim,
    claimFingerprint: payerBootstrapClaimFingerprint(claim),
    expiresAtMs: "2000000600000",
    nowMs: 2_000_000_000_000,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
  });

  assert.equal(await readApprovedPayerPublicProjection(path), null);
  await writeApprovedPayerPublicProjection(path, projection);
  assert.deepEqual(
    await readApprovedPayerPublicProjection(path),
    projection,
  );

  await chmod(path, 0o644);
  await assert.rejects(
    readApprovedPayerPublicProjection(path),
    /Approved Payer public projection failed safely/,
  );

  const body = `${JSON.stringify(projection)}\n`;
  const target = join(root, "target.json");
  const hardlink = join(root, "hardlink.json");
  const symlinkPath = join(root, "symlink.json");
  const oversized = join(root, "oversized.json");
  const noncanonical = join(root, "noncanonical.json");
  await writeFile(target, body, { mode: 0o600 });
  await link(target, hardlink);
  await symlink(target, symlinkPath);
  await writeFile(oversized, `${"x".repeat(131_073)}`, { mode: 0o600 });
  await writeFile(noncanonical, JSON.stringify({
    schema: projection.schema,
    certificateFingerprint: projection.certificateFingerprint,
    certificatePem: projection.certificatePem,
    claimFingerprint: projection.claimFingerprint,
    expiresAtMs: projection.expiresAtMs,
    paymentMoved: false,
    releaseId: projection.releaseId,
    repositorySha: projection.repositorySha,
    sessionId: projection.sessionId,
    status: projection.status,
  }), { mode: 0o600 });

  for (const unsafe of [
    hardlink,
    symlinkPath,
    oversized,
    noncanonical,
  ]) {
    await assert.rejects(
      readApprovedPayerPublicProjection(unsafe),
      /Approved Payer public projection failed safely/,
      unsafe,
    );
  }
});
