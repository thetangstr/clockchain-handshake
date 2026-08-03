import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  createHash,
  generateKeyPairSync,
  verify,
  X509Certificate,
} from "node:crypto";
import { chmod, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { canonicalBytes } from "../src/bilateral/canonical.mjs";
import { canonicalizeReceiptEventValue } from "../src/canonical.mjs";
import {
  createLaunchManifest,
  writeLaunchManifest,
} from "../src/bilateral/coordination/manifest.mjs";
import {
  createRequestorBootstrapKey,
  openRequestorBootstrapEnvelope,
} from "../src/bilateral/local-mcp/bootstrap-envelope.mjs";
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
const OPERATOR_KEY_ID = "operator-demo";

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
  const role = overrides.role ?? "payee";
  const roleCapability = role === "payee"
    ? { payerMcpIntakeCapability: "ab".repeat(32) }
    : { payerMcpIntakeCapabilityDigest: "ef".repeat(32) };
  const manifest = createLaunchManifest({
    expectedTlsFingerprint: tls.expectedTlsFingerprint,
    nowMs: Date.now(),
    operatorKeyId: OPERATOR_KEY_ID,
    randomBytes: () => Buffer.from(PRIVATE_CANARY.padEnd(32, "x").slice(0, 32)),
    relayUrl: "https://8.8.8.8:8443",
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    role,
    sessionId: SESSION_ID,
    tlsCertificatePem: tls.tlsCertificatePem,
    ...roleCapability,
    ...overrides,
  }, { allowTestAddresses: true }).manifest;
  const manifestPath = join(root, "payee.launch.json");
  await writeLaunchManifest(manifestPath, manifest);
  return { manifest, manifestPath };
}

async function operatorFixture(root) {
  const pair = generateKeyPairSync("ed25519");
  const privateKeyPem = pair.privateKey.export({
    format: "pem",
    type: "pkcs8",
  });
  const operatorPrivateKeyPath = join(root, "operator.ed25519.pem");
  await writeFile(operatorPrivateKeyPath, privateKeyPem, { mode: 0o600 });
  return {
    operatorPrivateKeyPath,
    publicKey: pair.publicKey,
  };
}

async function writeCapability(root, value = CAPABILITY) {
  const capabilityFile = join(root, "broker.capability");
  await writeFile(capabilityFile, `${value}\n`, { mode: 0o600 });
  return capabilityFile;
}

function signaturePreimage(response) {
  const { signature: _signature, ...unsigned } = response;
  return Buffer.from(JSON.stringify(canonicalizeReceiptEventValue(unsigned)), "utf8");
}

function assertOperatorSignature(response, publicKey) {
  assert.deepEqual(Object.keys(response.signature), [
    "algorithm",
    "keyId",
    "value",
  ]);
  assert.equal(response.signature.algorithm, "ed25519");
  assert.equal(response.signature.keyId, OPERATOR_KEY_ID);
  const signature = Buffer.from(response.signature.value, "base64");
  assert.equal(signature.length, 64);
  assert.equal(
    verify(null, signaturePreimage(response), publicKey, signature),
    true,
  );
  assert.equal(
    verify(
      null,
      signaturePreimage({
        ...response,
        context: { ...response.context, releaseId: "tampered-release" },
      }),
      publicKey,
      signature,
    ),
    false,
  );
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
  const operator = await operatorFixture(root);
  const { manifestPath } = await manifestFixture(t, root);
  const requestor = createRequestorBootstrapKey();
  const broker = createBootstrapBroker({
    capabilityFile,
    host: "127.0.0.1",
    manifestPath,
    operatorKeyId: OPERATOR_KEY_ID,
    operatorPrivateKeyPath: operator.operatorPrivateKeyPath,
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
  assertOperatorSignature(sealedBody, operator.publicKey);
  assert.deepEqual(
    openRequestorBootstrapEnvelope({
      context: sealedBody.context,
      envelope: sealedBody.envelope,
      requestorPrivateKey: requestor.privateKey,
    }),
    await readFile(manifestPath),
  );
  assert.doesNotMatch(sealed.body, new RegExp(PRIVATE_CANARY));
  assert.doesNotMatch(sealed.body, new RegExp(CAPABILITY));

  const journalBytes = await readFile(join(stateRoot, "bootstrap-broker-journal.json"), "utf8");
  const journal = JSON.parse(journalBytes);
  assert.deepEqual(
    journal.claims[pendingBody.claimFingerprint].sealedResponse,
    sealedBody,
  );
  assert.doesNotMatch(journalBytes, new RegExp(PRIVATE_CANARY));
  assert.doesNotMatch(journalBytes, new RegExp(CAPABILITY));
});

test("broker serializes concurrent approved claims to one byte-identical sealed response", async (t) => {
  const root = await privateRoot(t);
  const stateRoot = join(root, "state");
  const capabilityFile = await writeCapability(root);
  const operator = await operatorFixture(root);
  const { manifestPath } = await manifestFixture(t, root);
  const requestor = createRequestorBootstrapKey();
  const broker = createBootstrapBroker({
    capabilityFile,
    host: "127.0.0.1",
    manifestPath,
    operatorKeyId: OPERATOR_KEY_ID,
    operatorPrivateKeyPath: operator.operatorPrivateKeyPath,
    port: 0,
    repositorySha: REPOSITORY_SHA,
    stateRoot,
  });
  const listening = await broker.start();
  t.after(() => broker.stop());

  const exactClaim = claim(requestor.publicKey);
  const pending = await postJson(listening.url, exactClaim);
  assert.equal(pending.status, 202);
  await approveBootstrapClaim({
    claimFingerprint: JSON.parse(pending.body).claimFingerprint,
    stateRoot,
  });

  const responses = await Promise.all(
    Array.from({ length: 30 }, () => postJson(listening.url, exactClaim)),
  );
  assert.deepEqual(
    responses.map((response) => response.status),
    Array.from({ length: 30 }, () => 200),
  );
  assert.equal(new Set(responses.map((response) => response.body)).size, 1);
  assertOperatorSignature(JSON.parse(responses[0].body), operator.publicKey);
});

test("broker fails closed on alternate key, malformed claim, wrong SHA, auth failure, duplicate JSON key, and unsafe manifest path", async (t) => {
  const root = await privateRoot(t);
  const stateRoot = join(root, "state");
  const capabilityFile = await writeCapability(root);
  const operator = await operatorFixture(root);
  const { manifestPath } = await manifestFixture(t, root);
  const requestor = createRequestorBootstrapKey();
  const broker = createBootstrapBroker({
    capabilityFile,
    host: "127.0.0.1",
    manifestPath,
    operatorKeyId: OPERATOR_KEY_ID,
    operatorPrivateKeyPath: operator.operatorPrivateKeyPath,
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
  await assert.rejects(
    approveBootstrapClaim({
      claimFingerprint: "f".repeat(64),
      stateRoot,
    }),
    { code: "REQUESTOR_BOOTSTRAP_BROKER_INVALID" },
  );
  assert.equal((await postJson(listening.url, exactClaim, "00".repeat(32))).status, 401);
  assert.equal((await postJson(listening.url, claim(requestor.publicKey, { repositorySha: "b".repeat(40) }))).status, 400);
  assert.equal((await postJson(listening.url, claim(createRequestorBootstrapKey().publicKey))).status, 409);
  assert.equal((await postJson(listening.url, claim(requestor.publicKey, { claimNonce: "33333333-4444-4555-8666-777777777777" }))).status, 409);
  assert.equal((await postJson(listening.url, { ...exactClaim, extra: true })).status, 400);
  assert.equal((await postJson(listening.url, Buffer.from(`{"claimNonce":"${CLAIM_NONCE}","claimNonce":"${CLAIM_NONCE}","paymentMoved":false,"repositorySha":"${REPOSITORY_SHA}","requestorPublicKey":"${requestor.publicKey}"}`))).status, 400);

  const symlinkRoot = await privateRoot(t, "bootstrap-broker-symlink-");
  const symlinkState = join(symlinkRoot, "state");
  const symlinkCapability = await writeCapability(symlinkRoot);
  const symlinkOperator = await operatorFixture(symlinkRoot);
  const linkPath = join(symlinkRoot, "manifest-link.json");
  await symlink(manifestPath, linkPath);
  const unsafeBroker = createBootstrapBroker({
    capabilityFile: symlinkCapability,
    host: "127.0.0.1",
    manifestPath: linkPath,
    operatorKeyId: OPERATOR_KEY_ID,
    operatorPrivateKeyPath: symlinkOperator.operatorPrivateKeyPath,
    port: 0,
    repositorySha: REPOSITORY_SHA,
    stateRoot: symlinkState,
  });
  await assert.rejects(unsafeBroker.start(), {
    code: "REQUESTOR_BOOTSTRAP_BROKER_INVALID",
  });

  assert.throws(
    () => createBootstrapBroker({
      capabilityFile,
      host: "0.0.0.0",
      manifestPath,
      operatorKeyId: OPERATOR_KEY_ID,
      operatorPrivateKeyPath: operator.operatorPrivateKeyPath,
      port: 0,
      repositorySha: REPOSITORY_SHA,
      stateRoot: join(root, "non-loopback-state"),
    }),
    { code: "REQUESTOR_BOOTSTRAP_BROKER_INVALID" },
  );
});

test("broker rejects expired, wrong-role, wrong-SHA, wrong-mode, changed, and wrong-operator manifest material", async (t) => {
  const root = await privateRoot(t);
  const capabilityFile = await writeCapability(root);
  const operator = await operatorFixture(root);

  for (const [name, manifestOverrides, configOverrides = {}, mutate] of [
    ["expired", { nowMs: Date.now() - 7_200_000 }],
    ["wrong role", { role: "payer" }],
    ["wrong SHA", { repositorySha: "b".repeat(40) }],
    ["wrong operator", { operatorKeyId: "operator-other" }],
  ]) {
    const caseRoot = await privateRoot(t, `bootstrap-broker-${name.replaceAll(" ", "-")}-`);
    const stateRoot = join(caseRoot, "state");
    const caseCapability = await writeCapability(caseRoot);
    const caseOperator = await operatorFixture(caseRoot);
    const { manifestPath } = await manifestFixture(t, caseRoot, manifestOverrides);
    if (mutate !== undefined) await mutate(manifestPath);
    const broker = createBootstrapBroker({
      capabilityFile: caseCapability,
      host: "127.0.0.1",
      manifestPath,
      operatorKeyId: OPERATOR_KEY_ID,
      operatorPrivateKeyPath: caseOperator.operatorPrivateKeyPath,
      port: 0,
      repositorySha: REPOSITORY_SHA,
      stateRoot,
      ...configOverrides,
    });
    await assert.rejects(broker.start(), {
      code: "REQUESTOR_BOOTSTRAP_BROKER_INVALID",
    });
  }

  const modeRoot = await privateRoot(t, "bootstrap-broker-mode-");
  const { manifestPath: modeManifest } = await manifestFixture(t, modeRoot);
  await chmod(modeManifest, 0o644);
  await assert.rejects(
    createBootstrapBroker({
      capabilityFile,
      host: "127.0.0.1",
      manifestPath: modeManifest,
      operatorKeyId: OPERATOR_KEY_ID,
      operatorPrivateKeyPath: operator.operatorPrivateKeyPath,
      port: 0,
      repositorySha: REPOSITORY_SHA,
      stateRoot: join(modeRoot, "state"),
    }).start(),
    { code: "REQUESTOR_BOOTSTRAP_BROKER_INVALID" },
  );

  const keyModeRoot = await privateRoot(t, "bootstrap-broker-key-mode-");
  const keyModeCapability = await writeCapability(keyModeRoot);
  const keyModeOperator = await operatorFixture(keyModeRoot);
  const { manifestPath: keyModeManifest } = await manifestFixture(t, keyModeRoot);
  await chmod(keyModeOperator.operatorPrivateKeyPath, 0o644);
  await assert.rejects(
    createBootstrapBroker({
      capabilityFile: keyModeCapability,
      host: "127.0.0.1",
      manifestPath: keyModeManifest,
      operatorKeyId: OPERATOR_KEY_ID,
      operatorPrivateKeyPath: keyModeOperator.operatorPrivateKeyPath,
      port: 0,
      repositorySha: REPOSITORY_SHA,
      stateRoot: join(keyModeRoot, "state"),
    }).start(),
    { code: "REQUESTOR_BOOTSTRAP_BROKER_INVALID" },
  );

  const changedRoot = await privateRoot(t, "bootstrap-broker-changed-");
  const changedCapability = await writeCapability(changedRoot);
  const changedOperator = await operatorFixture(changedRoot);
  const { manifestPath: changedManifest } = await manifestFixture(t, changedRoot);
  const requestor = createRequestorBootstrapKey();
  const changedBroker = createBootstrapBroker({
    capabilityFile: changedCapability,
    host: "127.0.0.1",
    manifestPath: changedManifest,
    operatorKeyId: OPERATOR_KEY_ID,
    operatorPrivateKeyPath: changedOperator.operatorPrivateKeyPath,
    port: 0,
    repositorySha: REPOSITORY_SHA,
    stateRoot: join(changedRoot, "state"),
  });
  const changedListening = await changedBroker.start();
  t.after(() => changedBroker.stop());
  const pending = await postJson(changedListening.url, claim(requestor.publicKey));
  const { claimFingerprint } = JSON.parse(pending.body);
  await approveBootstrapClaim({
    claimFingerprint,
    stateRoot: join(changedRoot, "state"),
  });
  await writeFile(changedManifest, await readFile(changedManifest), { mode: 0o600 });
  assert.equal((await postJson(changedListening.url, claim(requestor.publicKey))).status, 400);
});

test("broker rejects corrupted journal claims, digests, sealed responses, and signatures before serving", async (t) => {
  const root = await privateRoot(t);
  const stateRoot = join(root, "state");
  const capabilityFile = await writeCapability(root);
  const operator = await operatorFixture(root);
  const { manifestPath } = await manifestFixture(t, root);
  const requestor = createRequestorBootstrapKey();
  const exactClaim = claim(requestor.publicKey);

  async function readyBroker(prefix) {
    const caseRoot = await privateRoot(t, prefix);
    const caseState = join(caseRoot, "state");
    const caseCapability = await writeCapability(caseRoot);
    const caseOperator = await operatorFixture(caseRoot);
    const { manifestPath: caseManifest } = await manifestFixture(t, caseRoot);
    const caseBroker = createBootstrapBroker({
      capabilityFile: caseCapability,
      host: "127.0.0.1",
      manifestPath: caseManifest,
      operatorKeyId: OPERATOR_KEY_ID,
      operatorPrivateKeyPath: caseOperator.operatorPrivateKeyPath,
      port: 0,
      repositorySha: REPOSITORY_SHA,
      stateRoot: caseState,
    });
    const listening = await caseBroker.start();
    t.after(() => caseBroker.stop());
    const pending = await postJson(listening.url, exactClaim);
    const { claimFingerprint } = JSON.parse(pending.body);
    await approveBootstrapClaim({ claimFingerprint, stateRoot: caseState });
    const sealed = await postJson(listening.url, exactClaim);
    assert.equal(sealed.status, 200);
    return {
      claimFingerprint,
      journalPath: join(caseState, "bootstrap-broker-journal.json"),
      listening,
    };
  }

  for (const [name, mutate] of [
    ["claim digest", (journal, fingerprint) => {
      journal.claims[fingerprint].claimDigest = "0".repeat(64);
    }],
    ["sealed digest", (journal, fingerprint) => {
      journal.claims[fingerprint].sealedResponseDigest = "1".repeat(64);
    }],
    ["signature", (journal, fingerprint) => {
      journal.claims[fingerprint].sealedResponse.signature.value =
        Buffer.alloc(64, 7).toString("base64");
    }],
    ["context", (journal, fingerprint) => {
      journal.claims[fingerprint].sealedResponse.context.releaseId = "tampered";
    }],
    ["status", (journal, fingerprint) => {
      journal.claims[fingerprint].status = "APPROVED";
    }],
  ]) {
    const fixture = await readyBroker(`bootstrap-broker-journal-${name.replaceAll(" ", "-")}-`);
    const journal = JSON.parse(await readFile(fixture.journalPath, "utf8"));
    mutate(journal, fixture.claimFingerprint);
    await writeFile(
      fixture.journalPath,
      Buffer.from(JSON.stringify(canonicalizeReceiptEventValue(journal)), "utf8"),
      { mode: 0o600 },
    );
    assert.equal(
      (await postJson(fixture.listening.url, exactClaim)).status,
      400,
      name,
    );
  }

  const broker = createBootstrapBroker({
    capabilityFile,
    host: "127.0.0.1",
    manifestPath,
    operatorKeyId: OPERATOR_KEY_ID,
    operatorPrivateKeyPath: operator.operatorPrivateKeyPath,
    port: 0,
    repositorySha: REPOSITORY_SHA,
    stateRoot,
  });
  const listening = await broker.start();
  t.after(() => broker.stop());
  const pending = await postJson(listening.url, exactClaim);
  const { claimFingerprint } = JSON.parse(pending.body);
  const journalPath = join(stateRoot, "bootstrap-broker-journal.json");
  const journal = JSON.parse(await readFile(journalPath, "utf8"));
  delete journal.claims[claimFingerprint].claim;
  await writeFile(
    journalPath,
    Buffer.from(JSON.stringify(canonicalizeReceiptEventValue(journal)), "utf8"),
    { mode: 0o600 },
  );
  await assert.rejects(
    approveBootstrapClaim({ claimFingerprint, stateRoot }),
    { code: "REQUESTOR_BOOTSTRAP_BROKER_INVALID" },
  );
});
