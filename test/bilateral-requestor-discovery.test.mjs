import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, generateKeyPairSync, sign, X509Certificate } from "node:crypto";
import { chmod, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  createSignedRequestorDiscovery,
  parseRequestorDiscoveryWire,
  publishRequestorDiscovery,
  verifySignedRequestorDiscovery,
} from "../scripts/publish-requestor-discovery.mjs";
import { canonicalBytes } from "../src/bilateral/canonical.mjs";

const REPOSITORY_SHA = "abcdef0123456789abcdef0123456789abcdef01";
const RELEASE_ID = "release-requestor-bootstrap";
const SESSION_ID = "22222222-2222-4222-8222-222222222222";
const OPERATOR_KEY_ID = "operator";

function rawEd25519PublicKey(pair) {
  return pair.publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64");
}

async function certificateFixture(t) {
  const root = await mkdtemp(join(tmpdir(), "requestor-discovery-"));
  await chmod(root, 0o700);
  t.after(() => rm(root, { force: true, recursive: true }));
  const certificatePath = join(root, "payer-mcp.crt");
  const privateKeyPath = join(root, "payer-mcp.key");
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
  const certificatePem = await readFile(certificatePath, "utf8");
  return {
    certificateFingerprint: createHash("sha256").update(new X509Certificate(certificatePem).raw).digest("hex"),
    certificatePath,
    certificatePem,
    privateKeyPath,
    root,
  };
}

test("creates and verifies exact signed Requestor discovery without private fields", async (t) => {
  const cert = await certificateFixture(t);
  const operator = generateKeyPairSync("ed25519");
  const discovery = createSignedRequestorDiscovery({
    certificateFingerprint: cert.certificateFingerprint,
    certificateUrl: "https://payer.example.test/payer-mcp.crt",
    expiresAtMs: String(Date.now() + 60_000),
    operatorKeyId: OPERATOR_KEY_ID,
    operatorPrivateKey: operator.privateKey,
    publicUrl: "https://127.0.0.1:9443/mcp",
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
  });

  assert.deepEqual(Object.keys(discovery), [
    "certificateFingerprint",
    "certificateUrl",
    "expiresAtMs",
    "operatorKeyId",
    "publicUrl",
    "releaseId",
    "repositorySha",
    "sessionId",
    "signature",
  ]);
  assert.equal(JSON.stringify(discovery).includes("PRIVATE KEY"), false);
  assert.deepEqual(
    verifySignedRequestorDiscovery({
      discovery,
      nowMs: Date.now(),
      operatorPublicKey: rawEd25519PublicKey(operator),
      repositorySha: REPOSITORY_SHA,
    }),
    discovery,
  );

  const { signature: _signature, ...unsigned } = discovery;
  assert.equal(
    sign(null, canonicalBytes(unsigned), operator.privateKey).toString("base64"),
    discovery.signature.value,
  );
});

test("publisher uploads public certificate and signed discovery without opening TLS private key", async (t) => {
  const cert = await certificateFixture(t);
  const operator = generateKeyPairSync("ed25519");
  const operatorPrivateKeyPath = join(cert.root, "operator.ed25519.pem");
  await writeFile(operatorPrivateKeyPath, operator.privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
  const uploaded = [];
  const result = await publishRequestorDiscovery({
    bucket: "clockchain-demo",
    certificateKey: "payer-mcp.crt",
    certificatePath: cert.certificatePath,
    certificateUrl: "https://payer.example.test/payer-mcp.crt",
    discoveryKey: "discovery.json",
    expiresAtMs: String(Date.now() + 60_000),
    operatorKeyId: OPERATOR_KEY_ID,
    operatorPrivateKeyPath,
    publicUrl: "https://127.0.0.1:9443/mcp",
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
    putObject: async (input) => uploaded.push(input),
  });
  assert.equal(result.paymentMoved, false);
  assert.deepEqual(uploaded.map((entry) => entry.key), ["payer-mcp.crt", "discovery.json"]);
  assert.equal(uploaded[0].body, cert.certificatePem);
  assert.equal(JSON.stringify(uploaded).includes(cert.privateKeyPath), false);
  assert.equal(JSON.stringify(uploaded).includes("PRIVATE KEY"), false);
});

test("publisher rejects unsafe object keys and private file substitutions before upload", async (t) => {
  const cert = await certificateFixture(t);
  const operator = generateKeyPairSync("ed25519");
  const operatorPrivateKeyPath = join(cert.root, "operator.ed25519.pem");
  await writeFile(operatorPrivateKeyPath, operator.privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
  await chmod(operatorPrivateKeyPath, 0o600);
  const symlinkedCertificatePath = join(cert.root, "payer-mcp-symlink.crt");
  await symlink(cert.certificatePath, symlinkedCertificatePath);
  const base = Object.freeze({
    bucket: "clockchain-demo",
    certificateKey: "payer-mcp.crt",
    certificatePath: cert.certificatePath,
    certificateUrl: "https://payer.example.test/payer-mcp.crt",
    discoveryKey: "discovery.json",
    expiresAtMs: String(Date.now() + 60_000),
    operatorKeyId: OPERATOR_KEY_ID,
    operatorPrivateKeyPath,
    publicUrl: "https://127.0.0.1:9443/mcp",
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
  });

  for (const override of [
    { certificateKey: "" },
    { certificateKey: "/payer-mcp.crt" },
    { discoveryKey: "nested/../discovery.json" },
    { certificateKey: "same", discoveryKey: "same" },
    { discoveryKey: "bad\u0001key" },
    { certificatePath: operatorPrivateKeyPath, operatorPrivateKeyPath },
    { certificatePath: symlinkedCertificatePath },
  ]) {
    const uploaded = [];
    await assert.rejects(
      publishRequestorDiscovery({
        ...base,
        ...override,
        putObject: async (input) => uploaded.push(input),
      }),
      /Requestor discovery failed safely/,
    );
    assert.deepEqual(uploaded, []);
  }

  await chmod(operatorPrivateKeyPath, 0o644);
  const uploaded = [];
  await assert.rejects(
    publishRequestorDiscovery({
      ...base,
      putObject: async (input) => uploaded.push(input),
    }),
    /Requestor discovery failed safely/,
  );
  assert.deepEqual(uploaded, []);
});

test("discovery verification rejects stale, wrong SHA, HTTP URLs, redirects, and forged signatures", async (t) => {
  const cert = await certificateFixture(t);
  const operator = generateKeyPairSync("ed25519");
  const valid = createSignedRequestorDiscovery({
    certificateFingerprint: cert.certificateFingerprint,
    certificateUrl: "https://payer.example.test/payer-mcp.crt",
    expiresAtMs: String(Date.now() + 60_000),
    operatorKeyId: OPERATOR_KEY_ID,
    operatorPrivateKey: operator.privateKey,
    publicUrl: "https://127.0.0.1:9443/mcp",
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
  });
  for (const discovery of [
    { ...valid, expiresAtMs: "1" },
    { ...valid, repositorySha: "b".repeat(40) },
    { ...valid, certificateUrl: "http://payer.example.test/payer-mcp.crt" },
    { ...valid, publicUrl: "https://127.0.0.1:9443/other" },
    { ...valid, redirectUrl: "https://evil.example.test/discovery.json" },
    { ...valid, signature: { ...valid.signature, value: Buffer.alloc(64).toString("base64") } },
  ]) {
    assert.throws(
      () => verifySignedRequestorDiscovery({
        discovery,
        nowMs: Date.now(),
        operatorPublicKey: rawEd25519PublicKey(operator),
        repositorySha: REPOSITORY_SHA,
      }),
      /Requestor discovery failed safely/,
    );
  }
});

test("discovery wire parser rejects duplicate keys and reordered noncanonical text", async (t) => {
  const cert = await certificateFixture(t);
  const operator = generateKeyPairSync("ed25519");
  const discovery = createSignedRequestorDiscovery({
    certificateFingerprint: cert.certificateFingerprint,
    certificateUrl: "https://payer.example.test/payer-mcp.crt",
    expiresAtMs: String(Date.now() + 60_000),
    operatorKeyId: OPERATOR_KEY_ID,
    operatorPrivateKey: operator.privateKey,
    publicUrl: "https://127.0.0.1:9443/mcp",
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
  });
  const canonical = `${JSON.stringify(discovery)}\n`;
  assert.deepEqual(parseRequestorDiscoveryWire(canonical), discovery);
  for (const text of [
    canonical.replace("\"certificateUrl\"", "\"certificateFingerprint\":\"x\",\"certificateUrl\""),
    JSON.stringify({
      signature: discovery.signature,
      sessionId: discovery.sessionId,
      repositorySha: discovery.repositorySha,
      releaseId: discovery.releaseId,
      publicUrl: discovery.publicUrl,
      operatorKeyId: discovery.operatorKeyId,
      expiresAtMs: discovery.expiresAtMs,
      certificateUrl: discovery.certificateUrl,
      certificateFingerprint: discovery.certificateFingerprint,
    }),
  ]) {
    assert.throws(() => parseRequestorDiscoveryWire(text), /Requestor discovery failed safely/);
  }
});
