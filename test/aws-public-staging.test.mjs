import assert from "node:assert/strict";
import {
  createHash,
  generateKeyPairSync,
  sign,
  X509Certificate,
} from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  chmod,
  link,
  lstat,
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
  createAwsPublicStager,
} from "../src/bilateral/aws/public-staging.mjs";
import {
  sshEd25519Fingerprint,
  verifySignedPayerBootstrapDiscovery,
} from "../scripts/publish-payer-bootstrap-discovery.mjs";
import {
  verifySignedRequestorDiscovery,
} from "../scripts/publish-requestor-discovery.mjs";

const REPOSITORY_SHA = "a".repeat(40);
const SESSION_ID = "11111111-2222-4333-8444-555555555555";
const RELEASE_ID =
  `release-${createHash("sha256").update(SESSION_ID, "utf8").digest("hex").slice(0, 16)}`;
const IMAGE_DIGEST =
  `570035913370.dkr.ecr.us-west-2.amazonaws.com/clockchain-handshake-control-plane@sha256:${"b".repeat(64)}`;
const PUBLIC_BASE_URL = "https://monitor.example.com/";
const PUBLIC_HOST = "payer.example.com";

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

function rawEd25519PublicKey(pair) {
  return pair.publicKey
    .export({ format: "der", type: "spki" })
    .subarray(-32)
    .toString("base64");
}

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), "aws-public-staging-"));
  await chmod(root, 0o700);
  t.after(() => rm(root, { recursive: true, force: true }));
  const certificatePath = join(root, "source.crt");
  const privateKeyPath = join(root, "source.key");
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
    `/CN=${PUBLIC_HOST}`,
    "-addext",
    `subjectAltName=DNS:${PUBLIC_HOST}`,
  ], { stdio: "ignore" });
  const certificatePem = await readFile(certificatePath, "utf8");
  const certificateFingerprint = createHash("sha256")
    .update(new X509Certificate(certificatePem).raw)
    .digest("hex");
  const operator = generateKeyPairSync("ed25519");
  const tunnel = generateKeyPairSync("ed25519");
  const tunnelHostPublicKey = openSshPublicKey(tunnel);
  const paths = {
    certificate: join(root, "payer-mcp.crt"),
    gate: join(root, "publication-gate.json"),
    input: join(root, "publisher-input.json"),
    payer: join(root, "payer.json"),
    requestor: join(root, "requestor.json"),
  };
  const stager = createAwsPublicStager({
    imageDigest: IMAGE_DIGEST,
    operatorKeyId: "clockchain-demo-2026",
    operatorPrivateKey: operator.privateKey,
    paths,
    payerClaimUrl: "https://bootstrap.example.com/v1/payer-claims",
    publicBaseUrl: PUBLIC_BASE_URL,
    publicMcpHostname: PUBLIC_HOST,
    publicMcpUrl: `https://${PUBLIC_HOST}:9443/mcp`,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
    tunnelHost: "tunnel.example.com",
    tunnelHostPublicKey,
    tunnelHostKeyFingerprint:
      sshEd25519Fingerprint(tunnelHostPublicKey),
  });
  t.after(() => stager.close());
  return {
    certificateFingerprint,
    certificatePem,
    operator,
    paths,
    root,
    stager,
    tunnelHostPublicKey,
  };
}

function waitingSnapshot(publishedAtMs = 1_785_000_000_000) {
  return {
    anchors: [],
    currentStep: "Waiting for the Payer and Requestor to join the run.",
    funding: { status: "NOT_STARTED" },
    mcp: { status: "WAITING" },
    paymentMoved: false,
    payer: { status: "WAITING" },
    publishedAtMs: String(publishedAtMs),
    relay: { status: "WAITING" },
    requestor: { status: "WAITING" },
    runId: `run-${RELEASE_ID.slice("release-".length)}`,
    runStatus: "WAITING",
    schema: "clockchain.bilateral-public-monitor/v3",
    staleAfterMs: 10_000,
    verifier: { status: "NOT_STARTED" },
  };
}

async function json(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

test("stages signed Payer discovery, a closed initial gate, and publisher input last", async (t) => {
  const value = await fixture(t);
  await value.stager.stageStart({
    expiresAtMs: "1785003600000",
    nowMs: 1_785_000_000_000,
    snapshot: waitingSnapshot(),
  });

  const payer = await json(value.paths.payer);
  assert.deepEqual(
    verifySignedPayerBootstrapDiscovery({
      discovery: payer,
      expectedImageDigest: IMAGE_DIGEST,
      expectedPublicMcpHostname: PUBLIC_HOST,
      nowMs: 1_785_000_000_000,
      operatorPublicKey: rawEd25519PublicKey(value.operator),
      repositorySha: REPOSITORY_SHA,
    }),
    payer,
  );
  assert.deepEqual(await json(value.paths.gate), {
    payerClaimApproved: false,
    payerDiscoveryReady: true,
    payerMcpReady: false,
    requestorDiscoveryReady: false,
    runStarted: true,
    tunnelTlsHealthy: false,
  });
  const input = await json(value.paths.input);
  assert.equal(input.certificateFingerprint, null);
  assert.deepEqual(input.secretCanaries, []);
  assert.deepEqual(input.snapshot, waitingSnapshot());
  for (const path of [value.paths.payer, value.paths.gate, value.paths.input]) {
    assert.equal((await lstat(path)).mode & 0o777, 0o600);
  }
  assert.equal((await lstat(value.paths.input)).mtimeMs >= (await lstat(value.paths.gate)).mtimeMs, true);
});

test("publishes Requestor discovery only from matching approved Payer and pinned TLS health", async (t) => {
  const value = await fixture(t);
  await value.stager.stageStart({
    expiresAtMs: "1785003600000",
    nowMs: 1_785_000_000_000,
    snapshot: waitingSnapshot(),
  });
  const approvedPayer = {
    certificateFingerprint: value.certificateFingerprint,
    certificatePem: value.certificatePem,
    claimFingerprint: "c".repeat(64),
    expiresAtMs: "1785003600000",
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    schema: "clockchain.aws-approved-payer-public/v1",
    sessionId: SESSION_ID,
    status: "APPROVED",
  };
  const health = {
    schema: "clockchain.payer-tunnel-health/v1",
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
    claimFingerprint: "c".repeat(64),
    mcpTlsFingerprint: value.certificateFingerprint,
    observedAtMs: "1785000001000",
    expiresAtMs: "1785003600000",
    paymentMoved: false,
    status: "READY",
  };

  await assert.rejects(
    value.stager.stagePayerReady({
      approvedPayer,
      nowMs: 1_785_000_002_000,
      tunnelHealth: { ...health, claimFingerprint: "d".repeat(64) },
    }),
  );
  await assert.rejects(readFile(value.paths.requestor));

  await value.stager.stagePayerReady({
    approvedPayer,
    nowMs: 1_785_000_002_000,
    tunnelHealth: health,
  });
  assert.equal(await readFile(value.paths.certificate, "utf8"), value.certificatePem);
  const requestor = await json(value.paths.requestor);
  assert.deepEqual(
    verifySignedRequestorDiscovery({
      discovery: requestor,
      nowMs: 1_785_000_002_000,
      operatorPublicKey: rawEd25519PublicKey(value.operator),
      repositorySha: REPOSITORY_SHA,
    }),
    requestor,
  );
  assert.deepEqual(await json(value.paths.gate), {
    payerClaimApproved: true,
    payerDiscoveryReady: true,
    payerMcpReady: true,
    requestorDiscoveryReady: true,
    runStarted: true,
    tunnelTlsHealthy: true,
  });
  const input = await json(value.paths.input);
  assert.equal(input.certificateFingerprint, value.certificateFingerprint);
  assert.equal(input.completedAtMs, null);
  assert.equal(input.verifierPublicationValidated, false);
  assert.deepEqual(input.snapshot, {
    ...waitingSnapshot(1_785_000_002_000),
    currentStep:
      "Payer MCP is ready. Requestor may connect to the published MCP endpoint.",
    mcp: { status: "READY" },
    payer: { status: "READY" },
  });
});

test("publishes late Payer readiness from a fresh WAITING snapshot instead of carrying stale expiration forward", async (t) => {
  const value = await fixture(t);
  await value.stager.stageStart({
    expiresAtMs: "1785003600000",
    nowMs: 1_785_000_000_000,
    snapshot: waitingSnapshot(),
  });
  const approvedPayer = {
    certificateFingerprint: value.certificateFingerprint,
    certificatePem: value.certificatePem,
    claimFingerprint: "c".repeat(64),
    expiresAtMs: "1785003600000",
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    schema: "clockchain.aws-approved-payer-public/v1",
    sessionId: SESSION_ID,
    status: "APPROVED",
  };
  const tunnelHealth = {
    schema: "clockchain.payer-tunnel-health/v1",
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
    claimFingerprint: "c".repeat(64),
    mcpTlsFingerprint: value.certificateFingerprint,
    observedAtMs: "1785000060000",
    expiresAtMs: "1785003600000",
    paymentMoved: false,
    status: "READY",
  };

  await value.stager.stagePayerReady({
    approvedPayer,
    nowMs: 1_785_000_061_000,
    tunnelHealth,
  });

  const input = await json(value.paths.input);
  assert.equal(input.completedAtMs, null);
  assert.equal(input.verifierPublicationValidated, false);
  assert.deepEqual(input.snapshot, {
    ...waitingSnapshot(1_785_000_061_000),
    currentStep:
      "Payer MCP is ready. Requestor may connect to the published MCP endpoint.",
    mcp: { status: "READY" },
    payer: { status: "READY" },
  });
});

test("rejects malformed public snapshots and writes a validated update as the publisher trigger", async (t) => {
  const value = await fixture(t);
  await value.stager.stageStart({
    expiresAtMs: "1785003600000",
    nowMs: 1_785_000_000_000,
    snapshot: waitingSnapshot(),
  });
  await assert.rejects(value.stager.stageSnapshot({
    completedAtMs: null,
    nowMs: 1_785_000_001_000,
    snapshot: { ...waitingSnapshot(), paymentMoved: true },
    verifierPublicationValidated: false,
  }));
  const running = {
    ...waitingSnapshot(1_785_000_001_000),
    currentStep: "The Requestor is evaluating the Payer proposal under the signed mandate.",
    funding: { status: "READY" },
    runStatus: "RUNNING",
  };
  await value.stager.stageSnapshot({
    completedAtMs: null,
    nowMs: 1_785_000_001_000,
    snapshot: running,
    verifierPublicationValidated: false,
  });
  assert.deepEqual((await json(value.paths.input)).snapshot, running);
});

test("rejects unsafe publisher input files before staging snapshot updates", async (t) => {
  const cases = [
    async ({ paths }) => {
      await chmod(paths.input, 0o644);
    },
    async ({ paths, root }) => {
      await link(paths.input, join(root, "input-hardlink.json"));
    },
    async ({ paths, root }) => {
      const body = await readFile(paths.input, "utf8");
      const target = join(root, "input-target.json");
      await writeFile(target, body, { mode: 0o600 });
      await rm(paths.input);
      await symlink(target, paths.input);
    },
    async ({ paths }) => {
      await writeFile(paths.input, "x".repeat(262_145), { mode: 0o600 });
    },
    async ({ paths }) => {
      await writeFile(
        paths.input,
        JSON.stringify(await json(paths.input)),
        { mode: 0o600 },
      );
    },
  ];

  for (const mutate of cases) {
    const value = await fixture(t);
    await value.stager.stageStart({
      expiresAtMs: "1785003600000",
      nowMs: 1_785_000_000_000,
      snapshot: waitingSnapshot(),
    });
    await mutate(value);
    await assert.rejects(
      value.stager.stageSnapshot({
        completedAtMs: null,
        nowMs: 1_785_000_001_000,
        snapshot: {
          ...waitingSnapshot(1_785_000_001_000),
          currentStep:
            "The Requestor is evaluating the Payer proposal under the signed mandate.",
          funding: { status: "READY" },
          runStatus: "RUNNING",
        },
        verifierPublicationValidated: false,
      }),
      /AWS public staging failed safely/,
    );
  }
});

test("requires every staged public file to be distinct under the strict release root", async (t) => {
  const value = await fixture(t);
  await value.stager.close();
  const duplicatePaths = {
    ...value.paths,
    requestor: value.paths.payer,
  };
  assert.throws(() =>
    createAwsPublicStager({
      imageDigest: IMAGE_DIGEST,
      operatorKeyId: "clockchain-demo-2026",
      operatorPrivateKey: value.operator.privateKey,
      paths: duplicatePaths,
      payerClaimUrl: "https://bootstrap.example.com/v1/payer-claims",
      publicBaseUrl: PUBLIC_BASE_URL,
      publicMcpHostname: PUBLIC_HOST,
      publicMcpUrl: `https://${PUBLIC_HOST}:9443/mcp`,
      releaseId: RELEASE_ID,
      repositorySha: REPOSITORY_SHA,
      sessionId: SESSION_ID,
      tunnelHost: "tunnel.example.com",
      tunnelHostPublicKey: value.tunnelHostPublicKey,
      tunnelHostKeyFingerprint:
        sshEd25519Fingerprint(value.tunnelHostPublicKey),
    }),
    /AWS public staging failed safely/,
  );
});

test("stages terminal operational failure from only the validated previous public snapshot", async (t) => {
  const value = await fixture(t);
  await value.stager.stageStart({
    expiresAtMs: "1785003600000",
    nowMs: 1_785_000_000_000,
    snapshot: waitingSnapshot(),
  });

  await value.stager.stageTerminalFailure({
    nowMs: 1_785_000_003_000,
  });

  const input = await json(value.paths.input);
  assert.equal(input.certificateFingerprint, null);
  assert.equal(input.completedAtMs, 1_785_000_003_000);
  assert.equal(input.verifierPublicationValidated, false);
  assert.deepEqual(input.snapshot, {
    ...waitingSnapshot(1_785_000_003_000),
    currentStep:
      "The run stopped safely before completion because required evidence did not validate.",
    runStatus: "FAILED",
    verifier: { status: "FAILED" },
  });
  assert.equal(
    JSON.stringify(input).includes("AUTHORIZED"),
    false,
  );
});

test("terminal operational failure remains accurate after Requestor discovery opened", async (t) => {
  const value = await fixture(t);
  await value.stager.stageStart({
    expiresAtMs: "1785003600000",
    nowMs: 1_785_000_000_000,
    snapshot: waitingSnapshot(),
  });
  const approvedPayer = {
    certificateFingerprint: value.certificateFingerprint,
    certificatePem: value.certificatePem,
    claimFingerprint: "c".repeat(64),
    expiresAtMs: "1785003600000",
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    schema: "clockchain.aws-approved-payer-public/v1",
    sessionId: SESSION_ID,
    status: "APPROVED",
  };
  const tunnelHealth = {
    schema: "clockchain.payer-tunnel-health/v1",
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
    claimFingerprint: "c".repeat(64),
    mcpTlsFingerprint: value.certificateFingerprint,
    observedAtMs: "1785000001000",
    expiresAtMs: "1785003600000",
    paymentMoved: false,
    status: "READY",
  };
  await value.stager.stagePayerReady({
    approvedPayer,
    nowMs: 1_785_000_002_000,
    tunnelHealth,
  });

  await value.stager.stageTerminalFailure({
    nowMs: 1_785_000_003_000,
  });

  const input = await json(value.paths.input);
  assert.equal(input.completedAtMs, 1_785_000_003_000);
  assert.equal(
    input.snapshot.currentStep,
    "The run stopped safely before completion because required evidence did not validate.",
  );
  assert.equal(input.snapshot.runStatus, "FAILED");
  assert.deepEqual(input.snapshot.verifier, { status: "FAILED" });
  assert.doesNotMatch(
    JSON.stringify(input),
    /Requestor discovery had not opened|AUTHORIZED/,
  );
});
