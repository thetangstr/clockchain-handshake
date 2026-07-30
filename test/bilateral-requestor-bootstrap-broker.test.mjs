import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, X509Certificate } from "node:crypto";
import { chmod, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { canonicalBytes } from "../src/bilateral/canonical.mjs";
import {
  createLaunchManifest,
  writeLaunchManifest,
} from "../src/bilateral/coordination/manifest.mjs";
import { createRequestorBootstrapKey } from "../src/bilateral/local-mcp/bootstrap-envelope.mjs";
import {
  approveBootstrapClaim,
  bootstrapClaimFingerprint,
  createBootstrapBroker,
} from "../src/bilateral/local-mcp/bootstrap-broker.mjs";

const REPOSITORY_SHA = "abcdef0123456789abcdef0123456789abcdef01";
const SESSION_ID = "11111111-2222-4333-8444-555555555555";
const RELEASE_ID = "release-remote-requestor";
const CLAIM_NONCE = "22222222-3333-4444-8555-666666666666";
const CAPABILITY = "cd".repeat(32);
const PRIVATE_CANARY = "requestor-live-manifest-canary";

async function privateRoot(t, prefix = "bootstrap-broker-") {
  const root = await mkdtemp(join(tmpdir(), prefix));
  await chmod(root, 0o700);
  t.after(() => rm(root, { force: true, recursive: true }));
  return root;
}

async function tlsFixture(t) {
  const root = await privateRoot(t, "bootstrap-broker-tls-");
  const certificatePath = join(root, "cert.pem");
  const privateKeyPath = join(root, "key.pem");
  execFileSync("openssl", [
    "req",
    "-x509",
    "-newkey",
    "ed25519",
    "-keyout",
    privateKeyPath,
    "-out",
    certificatePath,
    "-nodes",
    "-days",
    "1",
    "-subj",
    "/CN=127.0.0.1",
    "-addext",
    "subjectAltName=IP:127.0.0.1",
  ], { stdio: "ignore" });
  await chmod(privateKeyPath, 0o600);
  const tlsCertificatePem = await readFile(certificatePath, "utf8");
  return {
    expectedTlsFingerprint: createHash("sha256")
      .update(new X509Certificate(tlsCertificatePem).raw)
      .digest("hex"),
    tlsCertificatePem,
  };
}

async function manifestFixture(t, root, overrides = {}) {
  const tls = await tlsFixture(t);
  const manifest = createLaunchManifest({
    expectedTlsFingerprint: tls.expectedTlsFingerprint,
    nowMs: 1_785_120_000_000,
    operatorKeyId: "operator-demo",
    payerMcpIntakeCapability: "ab".repeat(32),
    randomBytes: () => Buffer.from(PRIVATE_CANARY.padEnd(32, "x").slice(0, 32)),
    relayUrl: "https://127.0.0.1:8443",
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    role: "payee",
    sessionId: SESSION_ID,
    tlsCertificatePem: tls.tlsCertificatePem,
    ...overrides,
  }).manifest;
  const manifestPath = join(root, "payee.launch.json");
  await writeLaunchManifest(manifestPath, manifest);
  return { manifest, manifestPath };
}

async function writeCapability(root, value = CAPABILITY) {
  const capabilityFile = join(root, "broker.capability");
  await writeFile(capabilityFile, `${value}\n`, { mode: 0o600 });
  return capabilityFile;
}

function claim(requestorPublicKey, overrides = {}) {
  return {
    claimNonce: CLAIM_NONCE,
    paymentMoved: false,
    repositorySha: REPOSITORY_SHA,
    requestorPublicKey,
    ...overrides,
  };
}

async function postJson(url, body, capability = CAPABILITY) {
  const response = await fetch(`${url}/claim`, {
    body: Buffer.isBuffer(body) ? body : canonicalBytes(body),
    headers: {
      authorization: `Bearer ${capability}`,
      "content-type": "application/json",
    },
    method: "POST",
  });
  return {
    body: await response.text(),
    status: response.status,
  };
}

test("broker keeps public claims pending until exact fingerprint approval then returns byte-identical sealed retries", async (t) => {
  const root = await privateRoot(t);
  const stateRoot = join(root, "state");
  await writeFile(join(root, "placeholder"), "", { mode: 0o600 });
  await chmod(root, 0o700);
  const capabilityFile = await writeCapability(root);
  const { manifestPath } = await manifestFixture(t, root);
  const requestor = createRequestorBootstrapKey();
  const broker = createBootstrapBroker({
    capabilityFile,
    host: "127.0.0.1",
    manifestPath,
    port: 0,
    repositorySha: REPOSITORY_SHA,
    stateRoot,
  });
  const listening = await broker.start();
  t.after(() => broker.stop());

  const exactClaim = claim(requestor.publicKey);
  const pending = await postJson(listening.url, exactClaim);
  assert.equal(pending.status, 202);
  const pendingBody = JSON.parse(pending.body);
  assert.deepEqual(Object.keys(pendingBody), [
    "claimFingerprint",
    "paymentMoved",
    "repositorySha",
    "schema",
    "status",
  ]);
  assert.equal(pendingBody.status, "PENDING_APPROVAL");
  assert.equal(pendingBody.paymentMoved, false);
  assert.equal(pendingBody.claimFingerprint, bootstrapClaimFingerprint(exactClaim));
  assert.doesNotMatch(pending.body, new RegExp(PRIVATE_CANARY));
  assert.doesNotMatch(pending.body, new RegExp(CAPABILITY));

  await approveBootstrapClaim({
    claimFingerprint: pendingBody.claimFingerprint,
    stateRoot,
  });

  const sealed = await postJson(listening.url, exactClaim);
  assert.equal(sealed.status, 200);
  const retry = await postJson(listening.url, exactClaim);
  assert.equal(retry.status, 200);
  assert.equal(retry.body, sealed.body);
  const sealedBody = JSON.parse(sealed.body);
  assert.equal(sealedBody.status, "SEALED");
  assert.equal(sealedBody.paymentMoved, false);
  assert.equal(sealedBody.context.claimNonce, CLAIM_NONCE);
  assert.equal(sealedBody.context.repositorySha, REPOSITORY_SHA);
  assert.equal(sealedBody.context.sessionId, SESSION_ID);
  assert.equal(sealedBody.context.releaseId, RELEASE_ID);
  assert.equal(sealedBody.envelope.paymentMoved, false);
  assert.doesNotMatch(sealed.body, new RegExp(PRIVATE_CANARY));
  assert.doesNotMatch(sealed.body, new RegExp(CAPABILITY));

  const journalBytes = await readFile(join(stateRoot, "bootstrap-broker-journal.json"), "utf8");
  assert.doesNotMatch(journalBytes, new RegExp(PRIVATE_CANARY));
  assert.doesNotMatch(journalBytes, new RegExp(CAPABILITY));
});

test("broker fails closed on alternate key, malformed claim, wrong SHA, auth failure, duplicate JSON key, and unsafe manifest path", async (t) => {
  const root = await privateRoot(t);
  const stateRoot = join(root, "state");
  const capabilityFile = await writeCapability(root);
  const { manifestPath } = await manifestFixture(t, root);
  const requestor = createRequestorBootstrapKey();
  const broker = createBootstrapBroker({
    capabilityFile,
    host: "127.0.0.1",
    manifestPath,
    port: 0,
    repositorySha: REPOSITORY_SHA,
    stateRoot,
  });
  const listening = await broker.start();
  t.after(() => broker.stop());

  const exactClaim = claim(requestor.publicKey);
  const pending = await postJson(listening.url, exactClaim);
  const { claimFingerprint } = JSON.parse(pending.body);
  await approveBootstrapClaim({ claimFingerprint, stateRoot });
  assert.equal((await postJson(listening.url, exactClaim, "00".repeat(32))).status, 401);
  assert.equal((await postJson(listening.url, claim(requestor.publicKey, { repositorySha: "b".repeat(40) }))).status, 400);
  assert.equal((await postJson(listening.url, claim(createRequestorBootstrapKey().publicKey))).status, 409);
  assert.equal((await postJson(listening.url, { ...exactClaim, extra: true })).status, 400);
  assert.equal((await postJson(listening.url, Buffer.from(`{"claimNonce":"${CLAIM_NONCE}","claimNonce":"${CLAIM_NONCE}","paymentMoved":false,"repositorySha":"${REPOSITORY_SHA}","requestorPublicKey":"${requestor.publicKey}"}`))).status, 400);

  const symlinkRoot = await privateRoot(t, "bootstrap-broker-symlink-");
  const symlinkState = join(symlinkRoot, "state");
  const symlinkCapability = await writeCapability(symlinkRoot);
  const linkPath = join(symlinkRoot, "manifest-link.json");
  await symlink(manifestPath, linkPath);
  const unsafeBroker = createBootstrapBroker({
    capabilityFile: symlinkCapability,
    host: "127.0.0.1",
    manifestPath: linkPath,
    port: 0,
    repositorySha: REPOSITORY_SHA,
    stateRoot: symlinkState,
  });
  await assert.rejects(unsafeBroker.start(), {
    code: "REQUESTOR_BOOTSTRAP_BROKER_INVALID",
  });
});
