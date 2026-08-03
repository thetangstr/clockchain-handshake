import assert from "node:assert/strict";
import { execFile, execFileSync } from "node:child_process";
import { createHash, generateKeyPairSync, sign, X509Certificate } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";

import {
  createSignedRequestorDiscovery,
  parseRequestorDiscoveryWire,
  publishRequestorDiscovery,
  verifySignedRequestorDiscovery,
} from "../scripts/publish-requestor-discovery.mjs";
import { canonicalBytes } from "../src/bilateral/canonical.mjs";

const execFileAsync = promisify(execFile);
const REPOSITORY_SHA = "abcdef0123456789abcdef0123456789abcdef01";
const RELEASE_ID = "release-requestor-bootstrap";
const SESSION_ID = "22222222-2222-4222-8222-222222222222";
const OPERATOR_KEY_ID = "operator";
const IMAGE_DIGEST =
  `123456789012.dkr.ecr.us-west-2.amazonaws.com/clockchain@sha256:${"a".repeat(64)}`;

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

test("creates and verifies exact v3 signed Requestor discovery with run mode and without private fields", async (t) => {
  const cert = await certificateFixture(t);
  const operator = generateKeyPairSync("ed25519");
  const discovery = createSignedRequestorDiscovery({
    schema: "clockchain.requestor-discovery/v3",
    paymentMoved: false,
    imageDigest: IMAGE_DIGEST,
    releaseId: RELEASE_ID,
    sessionId: SESSION_ID,
    repositorySha: REPOSITORY_SHA,
    operatorPrivateKey: operator.privateKey,
    publicUrl: "https://127.0.0.1:9443/mcp",
    certificateUrl: "https://payer.example.test/payer-mcp.crt",
    certificateFingerprint: cert.certificateFingerprint,
    operatorKeyId: OPERATOR_KEY_ID,
    runMode: "local-two-run",
    expiresAtMs: String(Date.now() + 60_000),
  });

  assert.deepEqual(Object.keys(discovery), [
    "schema",
    "paymentMoved",
    "imageDigest",
    "releaseId",
    "sessionId",
    "repositorySha",
    "publicUrl",
    "certificateUrl",
    "certificateFingerprint",
    "operatorKeyId",
    "runMode",
    "expiresAtMs",
    "signature",
  ]);
  assert.equal(discovery.runMode, "local-two-run");
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

test("verifier accepts legacy v2 discovery as aws-stakeholder-only without changing signed bytes", async (t) => {
  const cert = await certificateFixture(t);
  const operator = generateKeyPairSync("ed25519");
  const discovery = createSignedRequestorDiscovery({
    schema: "clockchain.requestor-discovery/v2",
    paymentMoved: false,
    imageDigest: IMAGE_DIGEST,
    releaseId: RELEASE_ID,
    sessionId: SESSION_ID,
    repositorySha: REPOSITORY_SHA,
    operatorPrivateKey: operator.privateKey,
    publicUrl: "https://127.0.0.1:9443/mcp",
    certificateUrl: "https://payer.example.test/payer-mcp.crt",
    certificateFingerprint: cert.certificateFingerprint,
    operatorKeyId: OPERATOR_KEY_ID,
    expiresAtMs: String(Date.now() + 60_000),
  });

  assert.equal(Object.hasOwn(discovery, "runMode"), false);
  const verified = verifySignedRequestorDiscovery({
    discovery,
    nowMs: Date.now(),
    operatorPublicKey: rawEd25519PublicKey(operator),
    repositorySha: REPOSITORY_SHA,
  });
  assert.equal(verified.runMode, "aws-stakeholder-only");
  assert.equal(Object.hasOwn(verified, "runMode"), true);
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
    imageDigest: IMAGE_DIGEST,
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

test("publisher CLI uploads certificate and discovery through aws stdin and prints one secret-free line", async (t) => {
  const cert = await certificateFixture(t);
  const operator = generateKeyPairSync("ed25519");
  const operatorPrivateKeyPath = join(cert.root, "operator.ed25519.pem");
  await writeFile(operatorPrivateKeyPath, operator.privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
  const fakeBin = join(cert.root, "bin");
  const uploadLog = join(cert.root, "aws-uploads.ndjson");
  await mkdir(fakeBin, { mode: 0o700 });
  await writeFile(join(fakeBin, "aws"), `#!/usr/bin/env node
const fs = require("node:fs");
const chunks = [];
process.stdin.on("data", (chunk) => chunks.push(chunk));
process.stdin.on("end", () => {
  fs.appendFileSync(process.env.AWS_UPLOAD_LOG, JSON.stringify({
    argv: process.argv.slice(2),
    body: Buffer.concat(chunks).toString("utf8"),
  }) + "\\n");
});
`, { mode: 0o700 });

  const { stdout, stderr } = await execFileAsync(
    process.execPath,
    [
      "scripts/publish-requestor-discovery.mjs",
      "--bucket", "clockchain-demo",
      "--region", "us-west-2",
      "--certificate-key", "demo/payer-mcp.crt",
      "--discovery-key", "demo/requestor-discovery.json",
      "--certificate-path", cert.certificatePath,
      "--operator-key-id", OPERATOR_KEY_ID,
      "--operator-private-key", operatorPrivateKeyPath,
      "--public-url", "https://32.186.198.119:9443/mcp",
      "--release-id", RELEASE_ID,
      "--repository-sha", REPOSITORY_SHA,
      "--session-id", SESSION_ID,
      "--expires-at-ms", String(Date.now() + 60_000),
      "--image-digest", IMAGE_DIGEST,
    ],
    {
      cwd: new URL("../", import.meta.url).pathname,
      encoding: "utf8",
      env: {
        ...process.env,
        AWS_UPLOAD_LOG: uploadLog,
        PATH: `${fakeBin}:${process.env.PATH}`,
      },
    },
  );
  assert.equal(stderr, "");
  const lines = stdout.trimEnd().split("\n");
  assert.equal(lines.length, 1);
  const published = JSON.parse(lines[0]);
  assert.equal(published.status, "REQUESTOR_DISCOVERY_PUBLISHED");
  assert.equal(published.paymentMoved, false);
  assert.equal(published.repositorySha, REPOSITORY_SHA);
  assert.equal(published.releaseId, RELEASE_ID);
  assert.equal(published.sessionId, SESSION_ID);
  assert.equal(published.operatorKeyId, OPERATOR_KEY_ID);
  assert.equal(published.certificateFingerprint, cert.certificateFingerprint);
  assert.equal(published.discoveryUrl, "https://clockchain-demo.s3.us-west-2.amazonaws.com/demo/requestor-discovery.json");
  assert.equal(lines[0].includes(operatorPrivateKeyPath), false);
  assert.equal(lines[0].includes(cert.privateKeyPath), false);
  assert.equal(lines[0].includes("PRIVATE KEY"), false);

  const uploads = (await readFile(uploadLog, "utf8")).trimEnd().split("\n").map((line) => JSON.parse(line));
  assert.equal(uploads.length, 2);
  assert.deepEqual(uploads.map((upload) => upload.argv), [
    [
      "s3", "cp", "-", "s3://clockchain-demo/demo/payer-mcp.crt",
      "--region", "us-west-2",
      "--content-type", "application/x-pem-file",
      "--cache-control", "no-store,max-age=0",
      "--only-show-errors",
    ],
    [
      "s3", "cp", "-", "s3://clockchain-demo/demo/requestor-discovery.json",
      "--region", "us-west-2",
      "--content-type", "application/json",
      "--cache-control", "no-store,max-age=0",
      "--only-show-errors",
    ],
  ]);
  assert.equal(uploads[0].body, cert.certificatePem);
  const discovery = JSON.parse(uploads[1].body);
  assert.equal(discovery.certificateUrl, "https://clockchain-demo.s3.us-west-2.amazonaws.com/demo/payer-mcp.crt");
  assert.equal(discovery.publicUrl, "https://32.186.198.119:9443/mcp");
  assert.equal(discovery.schema, "clockchain.requestor-discovery/v3");
  assert.equal(discovery.runMode, "aws-stakeholder-only");
});

test("publisher CLI rejects bad bucket region object keys and duplicate flags before upload", async (t) => {
  const cert = await certificateFixture(t);
  const operator = generateKeyPairSync("ed25519");
  const operatorPrivateKeyPath = join(cert.root, "operator.ed25519.pem");
  await writeFile(operatorPrivateKeyPath, operator.privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
  const fakeBin = join(cert.root, "bad-bin");
  const uploadLog = join(cert.root, "bad-aws-uploads.ndjson");
  await mkdir(fakeBin, { mode: 0o700 });
  await writeFile(join(fakeBin, "aws"), `#!/usr/bin/env node
require("node:fs").appendFileSync(process.env.AWS_UPLOAD_LOG, "called\\n");
`, { mode: 0o700 });
  const baseArgs = [
    "--bucket", "clockchain-demo",
    "--region", "us-west-2",
    "--certificate-key", "demo/payer-mcp.crt",
    "--discovery-key", "demo/requestor-discovery.json",
    "--certificate-path", cert.certificatePath,
    "--operator-key-id", OPERATOR_KEY_ID,
    "--operator-private-key", operatorPrivateKeyPath,
    "--public-url", "https://32.186.198.119:9443/mcp",
    "--release-id", RELEASE_ID,
    "--repository-sha", REPOSITORY_SHA,
    "--session-id", SESSION_ID,
    "--expires-at-ms", String(Date.now() + 60_000),
    "--image-digest", IMAGE_DIGEST,
  ];
  for (const mutate of [
    (args) => ["--bucket", "bad..bucket", ...args.slice(2)],
    (args) => ["--bucket", "192.168.0.1", ...args.slice(2)],
    (args) => [...args.slice(0, 2), "--region", "us-west-2-extra", ...args.slice(4)],
    (args) => [...args.slice(0, 4), "--certificate-key", "demo/../payer-mcp.crt", ...args.slice(6)],
    (args) => [...args, "--run-mode", "aws"],
    (args) => [...args, "--bucket", "clockchain-demo"],
  ]) {
    const { stdout, stderr } = await execFileAsync(
      process.execPath,
      ["scripts/publish-requestor-discovery.mjs", ...mutate([...baseArgs])],
      {
        cwd: new URL("../", import.meta.url).pathname,
        encoding: "utf8",
        env: {
          ...process.env,
          AWS_UPLOAD_LOG: uploadLog,
          PATH: `${fakeBin}:${process.env.PATH}`,
        },
      },
    ).then(
      () => assert.fail("unsafe publisher arguments unexpectedly succeeded"),
      (error) => error,
    );
    assert.equal(stdout, "");
    assert.equal(stderr, "REQUESTOR_DISCOVERY_FAILED\n");
    assert.equal(stderr.includes(operatorPrivateKeyPath), false);
    await assert.rejects(readFile(uploadLog, "utf8"), { code: "ENOENT" });
  }
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
    imageDigest: IMAGE_DIGEST,
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
    schema: "clockchain.requestor-discovery/v2",
    paymentMoved: false,
    imageDigest: IMAGE_DIGEST,
    releaseId: RELEASE_ID,
    sessionId: SESSION_ID,
    repositorySha: REPOSITORY_SHA,
    operatorPrivateKey: operator.privateKey,
    publicUrl: "https://127.0.0.1:9443/mcp",
    certificateUrl: "https://payer.example.test/payer-mcp.crt",
    certificateFingerprint: cert.certificateFingerprint,
    operatorKeyId: OPERATOR_KEY_ID,
    expiresAtMs: String(Date.now() + 60_000),
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
    schema: "clockchain.requestor-discovery/v2",
    paymentMoved: false,
    imageDigest: IMAGE_DIGEST,
    releaseId: RELEASE_ID,
    sessionId: SESSION_ID,
    repositorySha: REPOSITORY_SHA,
    operatorPrivateKey: operator.privateKey,
    publicUrl: "https://127.0.0.1:9443/mcp",
    certificateUrl: "https://payer.example.test/payer-mcp.crt",
    certificateFingerprint: cert.certificateFingerprint,
    operatorKeyId: OPERATOR_KEY_ID,
    expiresAtMs: String(Date.now() + 60_000),
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
