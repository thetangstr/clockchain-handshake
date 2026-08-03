import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign, X509Certificate } from "node:crypto";
import { chmod, mkdtemp, readFile, readdir, rm, stat } from "node:fs/promises";
import { mkdir } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { SUPERVISOR_FUNDING_DEADLINE_MS, createFundingInputVerifier, createGitInspector, createPrivateRoot, createPrivateSupervisorStateStore, createProductionSupervisorDependencies, createSupervisorLauncher, createSupervisorStatusLine, createVerifierPublicationVerifier, scanSupervisorCheckpointDirectories } from "../src/bilateral/coordination/supervisor-runtime.mjs";
import { verifyRepositoryState } from "../src/bilateral/coordination/supervisor-runtime.mjs";
import { ensureToken } from "../src/bilateral/coordination/supervisor-runtime.mjs";
import { ensureInvitations } from "../src/bilateral/coordination/supervisor-runtime.mjs";
import { writeFile } from "node:fs/promises";
import { unlink } from "node:fs/promises";
import { recoverMessageAddress } from "viem";
import { coordinationEnrollmentSignaturePreimage, invitationProofPreimage } from "../src/bilateral/coordination/enrollment.mjs";
import { createProductionSepoliaRpc } from "../src/bilateral/coordination/supervisor-runtime.mjs";
import { canonicalBytes } from "../src/bilateral/canonical.mjs";
import { canonicalizeReceiptEventValue } from "../src/canonical.mjs";
import { createSignedEnvelope } from "../src/bilateral/descriptor.mjs";
import { createLaunchManifest, writeLaunchManifest } from "../src/bilateral/coordination/manifest.mjs";
import { createCoordinationReceipt } from "../src/bilateral/coordination/receipt.mjs";
import { buildPaymentIntakeToolResult } from "../src/bilateral/local-mcp/payment-intake.mjs";
import { PAYER_MCP_INTAKE_DIRECTORY_NAME } from "../src/bilateral/local-mcp/intake-store.mjs";
import { REQUESTOR_MCP_INTAKE_FILE_NAME } from "../src/bilateral/local-mcp/client.mjs";
import { main as supervisorMain } from "../bin/handshake-supervisor.mjs";
import { main as createInvitationFiles } from "../scripts/create-invitations.mjs";

const DESCRIPTOR_SESSION_DOMAIN =
  "clockchain.bilateral-descriptor-session/v1\n";

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
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

function expectedDescriptorSessionId({
  releaseId,
  repositorySha,
  sessionId,
  subjectRun,
}) {
  return createHash("sha256")
    .update(DESCRIPTOR_SESSION_DOMAIN, "ascii")
    .update(
      canonicalBytes({
        releaseId,
        repositorySha,
        sessionId,
        subjectRun,
      }),
    )
    .digest("hex")
    .slice(0, 32);
}

async function repositoryCommitWithOperatorKey(
  root,
  keyId,
  publicKey,
) {
  const git = (...arguments_) => execFileSync(
    "/usr/bin/git",
    arguments_,
    { cwd: root, encoding: "utf8" },
  );
  git("init");
  git("config", "user.email", "session-fixture@example.invalid");
  git("config", "user.name", "session fixture");
  await mkdir(join(root, "docs", "operator-keys"), {
    recursive: true,
  });
  await writeFile(
    join(root, "docs", "operator-keys", `${keyId}.pub`),
    `${publicKey}\n`,
  );
  git("add", ".");
  git("commit", "-m", "session binding fixture");
  return git("rev-parse", "HEAD").trim();
}

function enrollmentFixture({
  addresses,
  releaseId,
  repositorySha,
  role,
  sessionId,
}) {
  const coordination = generateKeyPairSync("ed25519");
  const preflight = generateKeyPairSync("ed25519");
  const unsigned = {
    capabilityDigest: (role === "payer" ? "1" : "2").repeat(64),
    coordinationKey: {
      algorithm: "ed25519",
      keyId: `${role}-coordination`,
      publicKey: rawPublicKey(coordination),
    },
    invitations: {
      rehearsal: {
        address: addresses.rehearsal,
        algorithm: "eip191",
        signature: `0x${"1".repeat(130)}`,
      },
      stakeholder: {
        address: addresses.stakeholder,
        algorithm: "eip191",
        signature: `0x${"2".repeat(130)}`,
      },
    },
    paymentMoved: false,
    preflightKey: {
      algorithm: "ed25519",
      keyId: `${role}-preflight`,
      publicKey: rawPublicKey(preflight),
    },
    releaseId,
    repositorySha,
    role,
    schema: "clockchain.bilateral-coordination-enrollment/v1",
    sessionId,
  };
  return {
    ...unsigned,
    signature: sign(
      null,
      coordinationEnrollmentSignaturePreimage(unsigned),
      privateKeyPem(coordination),
    ).toString("base64"),
  };
}

function enrollmentEntry(enrollment, receipt) {
  const bytes = canonicalBytes(enrollment);
  return {
    enrollmentBase64: bytes.toString("base64"),
    enrollmentDigest: sha256(bytes),
    receiptBase64: receipt.toString("base64"),
  };
}

test("creates private state and round-trips a canonical checkpoint", async () => {
  const root = await mkdtemp(join(tmpdir(), "supervisor-runtime-"));
  const dependencies = await createPrivateSupervisorStateStore({ stateRoot: root });
  await dependencies.writeState({ phase: "EMPTY", paymentMoved: false });
  assert.deepEqual(await dependencies.readState(), { paymentMoved: false, phase: "EMPTY" });
  assert.equal((await stat(root)).mode & 0o777, 0o700);
});

test("coordination process child helper imports under generic role runners", async () => {
  const child = await import("./helpers/bilateral-coordination-child.mjs");
  assert.equal(typeof child.main, "function");
});

test("reads verifier publication through the context-bound client route", async () => {
  const verify = createVerifierPublicationVerifier();
  const context = { event: { artifactDigest: "a".repeat(64), kind: "VERIFICATION_PASSED", role: "operator", subjectRun: "rehearsal" }, releaseId: "release-a", repositorySha: "a".repeat(40), sessionId: "session-a" };
  let request;
  await assert.doesNotReject(verify(context, { async readVerifierPublication(value) {
    request = value;
    assert.deepEqual(value, { subjectRun: "rehearsal" });
    return { paymentMoved: false, publicationDigest: context.event.artifactDigest, releaseId: context.releaseId, repositorySha: context.repositorySha, schema: "clockchain.bilateral-verifier-publication/v1", sessionId: context.sessionId, status: "VERIFICATION_PASSED", subjectRun: "rehearsal" };
  } }));
  assert.deepEqual(request, { subjectRun: "rehearsal" });
});

test("projects supervisor status lines through an exact secret-free allowlist", () => {
  assert.equal(
    createSupervisorStatusLine({ paymentMoved: false, privateKeyPem: "secret", role: "payer", status: "WAITING_FOR_PEER" }),
    '{"paymentMoved":false,"role":"payer","status":"WAITING_FOR_PEER"}\n',
  );
  assert.equal(
    createSupervisorStatusLine({ code: "COORDINATION_SUPERVISOR_FAILED", message: "/private/path", paymentMoved: false, stack: "secret" }),
    '{"code":"COORDINATION_SUPERVISOR_FAILED","paymentMoved":false}\n',
  );
  assert.equal(
    createSupervisorStatusLine({ paymentMoved: false, privateKeyPem: "secret", role: "payer", status: "PAYER_MCP_READY", url: "https://127.0.0.1:9443/mcp" }),
    '{"paymentMoved":false,"role":"payer","status":"PAYER_MCP_READY","url":"https://127.0.0.1:9443/mcp"}\n',
  );
  assert.equal(
    createSupervisorStatusLine({ paymentMoved: false, role: "payer", state: "ACKNOWLEDGED", status: "PARTY_COMPLETE" }),
    '{"paymentMoved":false,"role":"payer","state":"ACKNOWLEDGED","status":"PARTY_COMPLETE"}\n',
  );
  assert.equal(
    createSupervisorStatusLine({ paymentMoved: false, role: "payer", state: "PROPOSED", status: "PARTY_PROGRESS" }),
    '{"paymentMoved":false,"role":"payer","state":"PROPOSED","status":"PARTY_PROGRESS"}\n',
  );
  assert.equal(
    createSupervisorStatusLine({ paymentMoved: false, role: "payee", state: "ACCEPTED", status: "PARTY_COMPLETE" }),
    '{"paymentMoved":false,"role":"payee","state":"ACCEPTED","status":"PARTY_COMPLETE"}\n',
  );
  let proxyGetCount = 0;
  const proxiedPartyComplete = new Proxy(
    { paymentMoved: false, role: "payer", state: "ACKNOWLEDGED", status: "PARTY_COMPLETE" },
    {
      get(target, property, receiver) {
        proxyGetCount += 1;
        return Reflect.get(target, property, receiver);
      },
    },
  );
  assert.equal(
    createSupervisorStatusLine(proxiedPartyComplete),
    '{"paymentMoved":false,"role":"payer","state":"ACKNOWLEDGED","status":"PARTY_COMPLETE"}\n',
  );
  assert.equal(proxyGetCount, 0);
  assert.throws(() => createSupervisorStatusLine({ paymentMoved: true, role: "payer", status: "WAITING_FOR_PEER" }));
  assert.throws(() => createSupervisorStatusLine({ paymentMoved: false, role: "payee", state: "PROPOSED", status: "PARTY_PROGRESS" }));
  assert.throws(() => createSupervisorStatusLine({ paymentMoved: false, role: "payer", state: "ACKNOWLEDGED", status: "PARTY_PROGRESS" }));
  assert.throws(() => createSupervisorStatusLine({ paymentMoved: false, role: "payer", state: "ACCEPTED", status: "PARTY_COMPLETE" }));
  assert.throws(() => createSupervisorStatusLine({ paymentMoved: false, role: "payee", state: "ACKNOWLEDGED", status: "PARTY_COMPLETE" }));
  assert.throws(() => createSupervisorStatusLine({ paymentMoved: false, role: "payer", state: "AUTHORIZED", status: "PARTY_COMPLETE" }));
  assert.throws(() => createSupervisorStatusLine({ paymentMoved: false, role: "operator", state: "ACKNOWLEDGED", status: "PARTY_COMPLETE" }));
  assert.throws(() => createSupervisorStatusLine({ paymentMoved: false, privateKeyPem: "secret", role: "payer", state: "ACKNOWLEDGED", status: "PARTY_COMPLETE" }));
  const hiddenPartyCompleteSecret = { paymentMoved: false, role: "payer", state: "ACKNOWLEDGED", status: "PARTY_COMPLETE" };
  Object.defineProperty(hiddenPartyCompleteSecret, "privateKeyPem", { value: "secret" });
  assert.throws(() => createSupervisorStatusLine(hiddenPartyCompleteSecret));
  const symbolPartyCompleteSecret = { paymentMoved: false, role: "payer", state: "ACKNOWLEDGED", status: "PARTY_COMPLETE" };
  symbolPartyCompleteSecret[Symbol("privateKeyPem")] = "secret";
  assert.throws(() => createSupervisorStatusLine(symbolPartyCompleteSecret));
  const accessorPartyCompleteState = { paymentMoved: false, role: "payer", status: "PARTY_COMPLETE" };
  Object.defineProperty(accessorPartyCompleteState, "state", { enumerable: true, get: () => "ACKNOWLEDGED" });
  assert.throws(() => createSupervisorStatusLine(accessorPartyCompleteState));
  let statusGetterInvoked = false;
  const accessorPartyCompleteStatus = { paymentMoved: false, role: "payer", state: "ACKNOWLEDGED" };
  Object.defineProperty(accessorPartyCompleteStatus, "status", {
    enumerable: true,
    get: () => {
      statusGetterInvoked = true;
      return "PARTY_COMPLETE";
    },
  });
  assert.throws(() => createSupervisorStatusLine(accessorPartyCompleteStatus));
  assert.equal(statusGetterInvoked, false);
});

test("supervisor CLI emits only the generic coordination failure line", () => {
  assert.throws(
    () => execFileSync(process.execPath, ["bin/handshake-supervisor.mjs"], {
      cwd: process.cwd(),
      encoding: "utf8",
    }),
    (error) => {
      assert.equal(error.status, 1);
      assert.equal(error.stdout, '{"code":"COORDINATION_SUPERVISOR_FAILED","paymentMoved":false}\n');
      assert.equal(error.stderr, "");
      return true;
    },
  );
});

test("supervisor CLI keeps legacy default run mode unless exact explicit mode is supplied", async () => {
  const baseArguments = [
    "--launch-manifest",
    "/private/launch.json",
    "--state",
    "/private/state",
  ];
  const calls = [];
  await supervisorMain(baseArguments, {
    async runSupervisor(input) {
      calls.push(input);
      return { paymentMoved: false };
    },
  });
  assert.equal(Object.hasOwn(calls[0], "runMode"), false);

  await supervisorMain([
    ...baseArguments,
    "--run-mode",
    "aws-stakeholder-only",
  ], {
    async runSupervisor(input) {
      calls.push(input);
      return { paymentMoved: false };
    },
  });
  assert.equal(calls[1].runMode, "aws-stakeholder-only");

  await supervisorMain([
    ...baseArguments,
    "--run-mode",
    "local-two-run",
  ], {
    async runSupervisor(input) {
      calls.push(input);
      return { paymentMoved: false };
    },
  });
  assert.equal(calls[2].runMode, "local-two-run");
});

test("supervisor CLI rejects unsupported or duplicate run mode before production setup", async () => {
  for (const arguments_ of [
    [
      "--launch-manifest",
      "/private/launch.json",
      "--state",
      "/private/state",
      "--run-mode",
      "aws",
    ],
    [
      "--launch-manifest",
      "/private/launch.json",
      "--state",
      "/private/state",
      "--run-mode",
      "aws-stakeholder-only",
      "--run-mode",
      "aws-stakeholder-only",
    ],
  ]) {
    await assert.rejects(
      supervisorMain(arguments_, {
        async createProductionSupervisorDependencies() {
          assert.fail("invalid run mode reached production setup");
        },
        async runSupervisor() {
          assert.fail("invalid run mode reached supervisor launch");
        },
      }),
      /Supervisor startup failed safely/,
    );
  }
});

test("production supervisor verifies valid enrollment receipts and binds each descriptor to its derived run session", async (t) => {
  const stateRoot = await mkdtemp(join(tmpdir(), "supervisor-session-state-"));
  const manifestRoot = await mkdtemp(join(tmpdir(), "supervisor-session-manifest-"));
  t.after(() => Promise.all([
    rm(stateRoot, { force: true, recursive: true }),
    rm(manifestRoot, { force: true, recursive: true }),
  ]));
  await Promise.all([chmod(stateRoot, 0o700), chmod(manifestRoot, 0o700)]);

  const operator = generateKeyPairSync("ed25519");
  const operatorKeyId = "session-fixture";
  const repositorySha = await repositoryCommitWithOperatorKey(
    manifestRoot,
    operatorKeyId,
    rawPublicKey(operator),
  );
  const releaseId = "release-session-binding";
  const coordinationSessionId =
    "8f953393-86d0-4f99-9d6a-102f525fbecd";
  const subjectRun = "rehearsal";
  const payerAddresses = {
    rehearsal: `0x${"1".repeat(40)}`,
    stakeholder: `0x${"2".repeat(40)}`,
  };
  const payeeAddresses = {
    rehearsal: `0x${"3".repeat(40)}`,
    stakeholder: `0x${"4".repeat(40)}`,
  };

  const certificatePath = join(manifestRoot, "tls-cert.pem");
  const privateKeyPath = join(manifestRoot, "tls-key.pem");
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
  const tlsCertificatePem = await readFile(certificatePath, "utf8");
  const tlsPrivateKeyPem = await readFile(privateKeyPath, "utf8");
  const expectedTlsFingerprint = sha256(
    new X509Certificate(tlsCertificatePem).raw,
  );
  const manifestPath = join(manifestRoot, "launch-manifest.json");
  const { manifest } = createLaunchManifest({
    expectedTlsFingerprint,
    nowMs: 0,
    operatorKeyId,
    randomBytes: () => Buffer.alloc(32, 7),
    relayUrl: "https://8.8.8.8:8443",
    releaseId,
    repositorySha,
    role: "payer",
    sessionId: coordinationSessionId,
    tlsCertificatePem,
    payerMcpIntakeCapabilityDigest: "0".repeat(64),
  });
  await writeLaunchManifest(manifestPath, manifest);
  const dependencies = await createProductionSupervisorDependencies({
    launchManifestPath: manifestPath,
    repositoryRoot: manifestRoot,
    sepoliaRpc: async () => "0x0",
    stateRoot,
  });
  const rehearsalRequestId = dependencies.requestId({ subjectRun: "rehearsal" });
  const stakeholderRequestId = dependencies.requestId({ subjectRun: "stakeholder" });
  assert.match(rehearsalRequestId, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.match(stakeholderRequestId, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.notEqual(rehearsalRequestId, stakeholderRequestId);
  const mandatePath = join(stateRoot, "rehearsal", "payer-mandate.json");
  const originalMandateBytes = canonicalBytes({ paymentMoved: false, schema: "test-intent-artifact/v1", value: "original" });
  await dependencies.writeArtifactFile({ bytes: originalMandateBytes, path: mandatePath });
  await dependencies.writeArtifactFile({ bytes: originalMandateBytes, path: mandatePath });
  await assert.rejects(
    dependencies.writeArtifactFile({
      bytes: canonicalBytes({ paymentMoved: false, schema: "test-intent-artifact/v1", value: "changed" }),
      path: mandatePath,
    }),
  );
  assert.deepEqual(await readFile(mandatePath), originalMandateBytes);
  for (const run of ["rehearsal", "stakeholder"]) {
    const info = await stat(join(stateRoot, run));
    assert.equal(info.isDirectory(), true);
    assert.equal(info.isSymbolicLink(), false);
    assert.equal(info.mode & 0o777, 0o700);
  }

  const payer = enrollmentFixture({
    addresses: payerAddresses,
    releaseId,
    repositorySha,
    role: "payer",
    sessionId: coordinationSessionId,
  });
  const payee = enrollmentFixture({
    addresses: payeeAddresses,
    releaseId,
    repositorySha,
    role: "payee",
    sessionId: coordinationSessionId,
  });
  const receiptSigner = {
    certificateSha256: expectedTlsFingerprint,
    sign(preimage) {
      return sign(null, preimage, tlsPrivateKeyPem);
    },
    signatureAlgorithm: "ed25519",
    verify() {
      return true;
    },
  };
  const payerBytes = canonicalBytes(payer);
  const payeeBytes = canonicalBytes(payee);
  const receiptFor = async (enrollment, enrollmentBytes) =>
    createCoordinationReceipt({
      context: {
        capabilityDigest: enrollment.capabilityDigest,
        enrollmentDigest: sha256(enrollmentBytes),
        releaseId,
        repositorySha,
        role: enrollment.role,
        sessionId: coordinationSessionId,
      },
      signer: receiptSigner,
    });
  const enrollmentSet = {
    enrollments: {
      payee: enrollmentEntry(payee, await receiptFor(payee, payeeBytes)),
      payer: enrollmentEntry(payer, await receiptFor(payer, payerBytes)),
    },
    paymentMoved: false,
    releaseId,
    repositorySha,
    schema: "clockchain.bilateral-coordination-enrollment-set/v1",
    sessionId: coordinationSessionId,
  };
  const context = {
    enrollmentSet,
    releaseId,
    repositorySha,
    sessionId: coordinationSessionId,
    subjectRun,
  };
  await assert.doesNotReject(
    dependencies.verifyEnrollmentSet({
      enrollmentBytes: Buffer.from(
        JSON.stringify(canonicalizeReceiptEventValue(enrollmentSet)),
        "utf8",
      ),
      enrollmentSet: structuredClone(enrollmentSet),
      releaseId,
      repositorySha,
      sessionId: coordinationSessionId,
    }),
  );
  const signedDescriptor = (sessionId) => canonicalBytes(
    createSignedEnvelope({
      amountOptions: [
        { currency: "USD", value: "100" },
        { currency: "USD", value: "250" },
      ],
      chainId: "11155111",
      expirySeconds: "600",
      mandateDigest: "b".repeat(64),
      namespace: "cbv1",
      payee: {
        address: payeeAddresses.rehearsal,
        agentId: "8678",
        displayName: "Requestor",
        role: "payee",
      },
      payer: {
        address: payerAddresses.rehearsal,
        agentId: "8677",
        displayName: "Payer",
        role: "payer",
      },
      paymentMoved: false,
      promptSha256: "5".repeat(64),
      protocol: "clockchain.bilateral-authorization/v1",
      protocolVersion: "1",
      registry: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
      repositorySha,
      requestDigest: "c".repeat(64),
      schema: "clockchain.bilateral-session-descriptor/v2",
      sessionId,
      settlement: "not-executed",
    }, {
      keyId: operatorKeyId,
      privateKeyPem: privateKeyPem(operator),
    }),
  );
  const expectedSessionId = expectedDescriptorSessionId({
    releaseId,
    repositorySha,
    sessionId: coordinationSessionId,
    subjectRun,
  });

  await assert.doesNotReject(
    dependencies.verifyDescriptor(
      signedDescriptor(expectedSessionId),
      context,
    ),
  );

  for (const mismatchedSessionId of [
    expectedDescriptorSessionId({
      releaseId: "release-other",
      repositorySha,
      sessionId: coordinationSessionId,
      subjectRun,
    }),
    expectedDescriptorSessionId({
      releaseId,
      repositorySha: "b".repeat(40),
      sessionId: coordinationSessionId,
      subjectRun,
    }),
    expectedDescriptorSessionId({
      releaseId,
      repositorySha,
      sessionId: "9f953393-86d0-4f99-9d6a-102f525fbecd",
      subjectRun,
    }),
    expectedDescriptorSessionId({
      releaseId,
      repositorySha,
      sessionId: coordinationSessionId,
      subjectRun: "stakeholder",
    }),
  ]) {
    assert.notEqual(mismatchedSessionId, expectedSessionId);
    await assert.rejects(
      dependencies.verifyDescriptor(
        signedDescriptor(mismatchedSessionId),
        context,
      ),
    );
  }
});

test("rejects every stale supervisor temporary file and noncanonical checkpoints", async () => {
  const root = await mkdtemp(join(tmpdir(), "supervisor-runtime-"));
  for (const name of [
    ".supervisor-state-abandoned.tmp",
    ".retired-launch-manifest-abandoned.tmp",
    ".supervisor-artifact-abandoned.tmp",
    ".coordination-identity-abandoned.tmp",
  ]) {
    await writeFile(join(root, name), "stale", { mode: 0o600 });
    await assert.rejects(createPrivateSupervisorStateStore({ stateRoot: root }));
    await unlink(join(root, name));
  }
  const store = await createPrivateSupervisorStateStore({ stateRoot: root });
  await writeFile(join(root, "supervisor-state.json"), '{"phase":"EMPTY", "paymentMoved":false}\n', { mode: 0o600 });
  await assert.rejects(store.readState());
});

test("rejects supervisor artifact leftovers in every private artifact directory", async () => {
  const root = await mkdtemp(join(tmpdir(), "supervisor-runtime-"));
  for (const directory of [
    root,
    join(root, "preflight"),
    join(root, "rehearsal"),
    join(root, "stakeholder"),
    join(root, "rehearsal", "identity"),
    join(root, "stakeholder", "result"),
  ]) {
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const temporary = join(directory, ".supervisor-artifact-abandoned.tmp");
    await writeFile(temporary, "stale", { mode: 0o600 });
    await assert.rejects(createPrivateRoot(directory));
    await unlink(temporary);
    const pinned = await createPrivateRoot(directory);
    await pinned.handle.close();
  }
});

test("scans every checkpoint-derived private directory before a resumed client can exist", async () => {
  const root = await mkdtemp(join(tmpdir(), "supervisor-runtime-"));
  const rehearsal = join(root, "rehearsal"), stakeholder = join(root, "stakeholder");
  for (const directory of [join(root, "preflight"), rehearsal, stakeholder, join(rehearsal, "identity"), join(rehearsal, "result"), join(stakeholder, "identity"), join(stakeholder, "result")]) await mkdir(directory, { recursive: true, mode: 0o700 });
  const checkpoint = {
    stateRoot: root,
    preflight: { planPath: join(root, "preflight", "plan.json"), outputPath: join(root, "preflight", "report.json"), privateKeyPath: join(root, "preflight", "key.pem"), publicArtifactPath: join(root, "preflight", "public.json") },
    rehearsal: { descriptorPath: join(rehearsal, "descriptor.json"), identityDirectory: join(rehearsal, "identity"), resultDirectory: join(rehearsal, "result") },
    stakeholder: { descriptorPath: join(stakeholder, "descriptor.json"), identityDirectory: join(stakeholder, "identity"), resultDirectory: join(stakeholder, "result") },
  };
  await scanSupervisorCheckpointDirectories({ checkpoint, stateRoot: root });
  const stale = join(stakeholder, "result", ".supervisor-artifact-abandoned.tmp");
  await writeFile(stale, "stale", { mode: 0o600 });
  await assert.rejects(scanSupervisorCheckpointDirectories({ checkpoint, stateRoot: root }));
  await unlink(stale);
  await mkdir(join(rehearsal, "identity", "unexpected"), { mode: 0o700 });
  await assert.rejects(scanSupervisorCheckpointDirectories({ checkpoint, stateRoot: root }));
});

test("checkpoint scanning accepts one valid Payer intake directory and rejects tampering", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "supervisor-runtime-intake-"));
  const manifestRoot = await mkdtemp(join(tmpdir(), "supervisor-runtime-intake-manifest-"));
  t.after(() => Promise.all([
    rm(root, { force: true, recursive: true }),
    rm(manifestRoot, { force: true, recursive: true }),
  ]));
  const rehearsal = join(root, "rehearsal"), stakeholder = join(root, "stakeholder");
  for (const directory of [join(root, "preflight"), rehearsal, stakeholder, join(rehearsal, "identity"), join(rehearsal, "result"), join(stakeholder, "identity"), join(stakeholder, "result")]) await mkdir(directory, { recursive: true, mode: 0o700 });
  await chmod(manifestRoot, 0o700);
  const certificatePath = join(manifestRoot, "tls-cert.pem");
  const privateKeyPath = join(manifestRoot, "tls-key.pem");
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
  const tlsCertificatePem = await readFile(certificatePath, "utf8");
  const manifestPath = join(manifestRoot, "launch-manifest.json");
  const { manifest } = createLaunchManifest({
    expectedTlsFingerprint: sha256(new X509Certificate(tlsCertificatePem).raw),
    nowMs: 0,
    operatorKeyId: "operator",
    randomBytes: () => Buffer.alloc(32, 7),
    relayUrl: "https://8.8.8.8:8443",
    releaseId: "release-intake",
    repositorySha: "a".repeat(40),
    role: "payer",
    sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd",
    tlsCertificatePem,
    payerMcpIntakeCapabilityDigest: "0".repeat(64),
  });
  await writeLaunchManifest(manifestPath, manifest);
  const checkpoint = {
    repositorySha: "a".repeat(40),
    role: "payer",
    stateRoot: root,
    preflight: { planPath: join(root, "preflight", "plan.json"), outputPath: join(root, "preflight", "report.json"), privateKeyPath: join(root, "preflight", "key.pem"), publicArtifactPath: join(root, "preflight", "public.json") },
    rehearsal: { descriptorPath: join(rehearsal, "descriptor.json"), identityDirectory: join(rehearsal, "identity"), resultDirectory: join(rehearsal, "result") },
    stakeholder: { descriptorPath: join(stakeholder, "descriptor.json"), identityDirectory: join(stakeholder, "identity"), resultDirectory: join(stakeholder, "result") },
  };
  const dependencies = await createProductionSupervisorDependencies({
    launchManifestPath: manifestPath,
    probe: async () => ({ clean: true, head: checkpoint.repositorySha }),
    stateRoot: root,
  });
  assert.equal(typeof dependencies.writePayerMcpIntake, "function");
  assert.equal(typeof dependencies.readPayerMcpIntake, "function");
  assert.equal(typeof dependencies.readStoredPayerMcpIntake, "function");
  const request = {
    amount: { currency: "USD", value: "100" },
    intakeRequestId: "00000000-0000-4000-8000-000000000000",
    invoiceReference: "invoice-001",
    paymentMoved: false,
    purpose: "Handshake demo",
    schema: "clockchain.payer-mcp-payment-intake/v1",
  };
  const response = buildPaymentIntakeToolResult({ repositorySha: checkpoint.repositorySha, toolInput: request });
  await dependencies.writePayerMcpIntake({ request, response });
  await scanSupervisorCheckpointDirectories({ checkpoint, stateRoot: root });

  await writeFile(join(root, PAYER_MCP_INTAKE_DIRECTORY_NAME, "unexpected.json"), "{}", { mode: 0o600 });
  await assert.rejects(scanSupervisorCheckpointDirectories({ checkpoint, stateRoot: root }));
});

test("Requestor production dependencies do not expose Payer intake methods and reject intake checkpoint state", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "supervisor-runtime-payee-intake-"));
  const manifestRoot = await mkdtemp(join(tmpdir(), "supervisor-runtime-payee-intake-manifest-"));
  t.after(() => Promise.all([
    rm(root, { force: true, recursive: true }),
    rm(manifestRoot, { force: true, recursive: true }),
  ]));
  await chmod(manifestRoot, 0o700);
  const certificatePath = join(manifestRoot, "tls-cert.pem");
  const privateKeyPath = join(manifestRoot, "tls-key.pem");
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
  const tlsCertificatePem = await readFile(certificatePath, "utf8");
  const manifestPath = join(manifestRoot, "launch-manifest.json");
  const repositorySha = "a".repeat(40);
  const { manifest } = createLaunchManifest({
    expectedTlsFingerprint: sha256(new X509Certificate(tlsCertificatePem).raw),
    nowMs: 0,
    operatorKeyId: "operator",
    randomBytes: () => Buffer.alloc(32, 7),
    relayUrl: "https://8.8.8.8:8443",
    releaseId: "release-payee-intake",
    repositorySha,
    role: "payee",
    sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd",
    tlsCertificatePem,
    payerMcpIntakeCapability: "1".repeat(64),
  });
  await writeLaunchManifest(manifestPath, manifest);
  const dependencies = await createProductionSupervisorDependencies({
    launchManifestPath: manifestPath,
    probe: async () => ({ clean: true, head: repositorySha }),
    stateRoot: root,
  });
  assert.equal(Object.hasOwn(dependencies, "writePayerMcpIntake"), false);
  assert.equal(Object.hasOwn(dependencies, "readPayerMcpIntake"), false);
  assert.equal(Object.hasOwn(dependencies, "readStoredPayerMcpIntake"), false);
  assert.equal(typeof dependencies.readRequestorMcpIntake, "function");
  const result = buildPaymentIntakeToolResult({
    repositorySha,
    toolInput: {
      amount: { currency: "USD", value: "100" },
      intakeRequestId: "00000000-0000-4000-8000-000000000000",
      invoiceReference: "invoice-001",
      paymentMoved: false,
      purpose: "Handshake demo",
      schema: "clockchain.payer-mcp-payment-intake/v1",
    },
  }).structuredContent;
  await writeFile(join(root, REQUESTOR_MCP_INTAKE_FILE_NAME), canonicalBytes(result), { mode: 0o600 });
  assert.deepEqual(await dependencies.readRequestorMcpIntake(), result);

  const rehearsal = join(root, "rehearsal"), stakeholder = join(root, "stakeholder");
  for (const directory of [join(root, "preflight"), rehearsal, stakeholder, join(rehearsal, "identity"), join(rehearsal, "result"), join(stakeholder, "identity"), join(stakeholder, "result"), join(root, PAYER_MCP_INTAKE_DIRECTORY_NAME)]) await mkdir(directory, { recursive: true, mode: 0o700 });
  const checkpoint = {
    repositorySha,
    role: "payee",
    stateRoot: root,
    preflight: { planPath: join(root, "preflight", "plan.json"), outputPath: join(root, "preflight", "report.json"), privateKeyPath: join(root, "preflight", "key.pem"), publicArtifactPath: join(root, "preflight", "public.json") },
    rehearsal: { descriptorPath: join(rehearsal, "descriptor.json"), identityDirectory: join(rehearsal, "identity"), resultDirectory: join(rehearsal, "result") },
    stakeholder: { descriptorPath: join(stakeholder, "descriptor.json"), identityDirectory: join(stakeholder, "identity"), resultDirectory: join(stakeholder, "result") },
  };
  await assert.rejects(scanSupervisorCheckpointDirectories({ checkpoint, stateRoot: root }));
});

test("production dependencies construct the local MCP server only for the Payer role", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "supervisor-runtime-mcp-server-"));
  const manifestRoot = await mkdtemp(join(tmpdir(), "supervisor-runtime-mcp-server-manifest-"));
  t.after(() => Promise.all([
    rm(root, { force: true, recursive: true }),
    rm(manifestRoot, { force: true, recursive: true }),
  ]));
  await chmod(manifestRoot, 0o700);
  const certificatePath = join(manifestRoot, "tls-cert.pem");
  const privateKeyPath = join(manifestRoot, "tls-key.pem");
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
  const tlsCertificatePem = await readFile(certificatePath, "utf8");
  const tlsPrivateKeyPem = await readFile(privateKeyPath, "utf8");
  const repositorySha = "a".repeat(40);
  const payerMcpIntakeCapabilityDigest = "3".repeat(64);
  const manifestPath = join(manifestRoot, "launch-manifest.json");
  const { manifest } = createLaunchManifest({
    expectedTlsFingerprint: sha256(new X509Certificate(tlsCertificatePem).raw),
    nowMs: 0,
    operatorKeyId: "operator",
    randomBytes: () => Buffer.alloc(32, 7),
    relayUrl: "https://8.8.8.8:8443",
    releaseId: "release-mcp-server",
    repositorySha,
    role: "payer",
    sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd",
    tlsCertificatePem,
    payerMcpIntakeCapabilityDigest,
  });
  await writeLaunchManifest(manifestPath, manifest);
  const calls = [];
  const fundingAddresses = {
    rehearsal: `0x${"7".repeat(40)}`,
    stakeholder: `0x${"8".repeat(40)}`,
  };
  let fundingCalls = 0;
  let fundingNow = 0;
  const fundingSleeps = [];
  const dependencies = await createProductionSupervisorDependencies({
    createPayerMcpServer: (input) => {
      calls.push(input);
      return {
        start: async () => ({ host: input.host, port: input.port, url: `https://${input.host}:${input.port}/mcp` }),
        stop: async () => undefined,
      };
    },
    launchManifestPath: manifestPath,
    now: () => fundingNow,
    payerMcpServerOptions: {
      host: "127.0.0.1",
      port: 9443,
      publicUrl: "https://203.0.113.10:19443/mcp",
      tlsCertificatePem,
      tlsPrivateKeyPem,
    },
    probe: async () => ({ clean: true, head: repositorySha }),
    sepoliaRpc: async ({ method }) => {
      const round = Math.floor(fundingCalls / 4);
      fundingCalls += 1;
      const value = method === "eth_getBalance" && round > 0
        ? 10_000_000_000_000_000n
        : 0n;
      return `0x${value.toString(16)}`;
    },
    sleeper: async (milliseconds) => {
      fundingSleeps.push(milliseconds);
      fundingNow += milliseconds;
    },
    stateRoot: root,
  });
  assert.equal(typeof dependencies.startPayerMcpServer, "function");
  assert.equal(typeof dependencies.stopPayerMcpServer, "function");
  assert.deepEqual(await dependencies.startPayerMcpServer(), { host: "127.0.0.1", port: 9443, url: "https://127.0.0.1:9443/mcp" });
  await dependencies.stopPayerMcpServer();
  assert.equal(calls.length, 1);
  assert.equal(calls[0].capabilityDigest, payerMcpIntakeCapabilityDigest);
  assert.equal(calls[0].repositorySha, repositorySha);
  assert.equal(calls[0].publicUrl, "https://203.0.113.10:19443/mcp");
  assert.equal(typeof calls[0].intakeStore.writeIntake, "function");
  assert.equal(Object.hasOwn(calls[0], "bootstrapCapability"), false);
  assert.equal(Object.hasOwn(calls[0], "payerMcpIntakeCapability"), false);
  const fundingEnrollment = enrollmentFixture({
    addresses: fundingAddresses,
    releaseId: "release-mcp-server",
    repositorySha,
    role: "payer",
    sessionId: manifest.sessionId,
  });
  assert.deepEqual(await dependencies.verifyFundingInputs({
    addresses: [
      fundingAddresses.rehearsal,
      fundingAddresses.stakeholder,
    ],
    enrollmentSet: {
      enrollments: {
        payer: {
          enrollmentBase64: canonicalBytes(fundingEnrollment).toString("base64"),
        },
      },
      repositorySha,
      sessionId: manifest.sessionId,
    },
    repositorySha,
    role: "payer",
    sessionId: manifest.sessionId,
  }), { paymentMoved: false });
  assert.deepEqual(fundingSleeps, [5_000]);

  const payeeManifestPath = join(manifestRoot, "payee-launch-manifest.json");
  const { manifest: payeeManifest } = createLaunchManifest({
    expectedTlsFingerprint: sha256(new X509Certificate(tlsCertificatePem).raw),
    nowMs: 0,
    operatorKeyId: "operator",
    randomBytes: () => Buffer.alloc(32, 8),
    relayUrl: "https://8.8.8.8:8443",
    releaseId: "release-mcp-server",
    repositorySha,
    role: "payee",
    sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd",
    tlsCertificatePem,
    payerMcpIntakeCapability: "4".repeat(64),
  });
  await writeLaunchManifest(payeeManifestPath, payeeManifest);
  await assert.rejects(createProductionSupervisorDependencies({
    launchManifestPath: payeeManifestPath,
    payerMcpServerOptions: {
      host: "127.0.0.1",
      port: 9443,
      tlsCertificatePem,
      tlsPrivateKeyPem,
    },
    probe: async () => ({ clean: true, head: repositorySha }),
    stateRoot: join(root, "payee"),
  }));

});

test("supervisor CLI accepts four Payer MCP path options plus an optional public URL and production pins TLS files", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "supervisor-runtime-mcp-cli-"));
  const manifestRoot = await mkdtemp(join(tmpdir(), "supervisor-runtime-mcp-cli-manifest-"));
  t.after(() => Promise.all([
    rm(root, { force: true, recursive: true }),
    rm(manifestRoot, { force: true, recursive: true }),
  ]));
  await chmod(manifestRoot, 0o700);
  const certificatePath = join(manifestRoot, "tls-cert.pem");
  const privateKeyPath = join(manifestRoot, "tls-key.pem");
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
  await chmod(certificatePath, 0o600);
  await chmod(privateKeyPath, 0o600);
  const tlsCertificatePem = await readFile(certificatePath, "utf8");
  const tlsPrivateKeyPem = await readFile(privateKeyPath, "utf8");
  const repositorySha = "a".repeat(40);
  const payerManifestPath = join(manifestRoot, "payer-launch-manifest.json");
  const { manifest: payerManifest } = createLaunchManifest({
    expectedTlsFingerprint: sha256(new X509Certificate(tlsCertificatePem).raw),
    nowMs: 0,
    operatorKeyId: "operator",
    randomBytes: () => Buffer.alloc(32, 9),
    relayUrl: "https://8.8.8.8:8443",
    releaseId: "release-mcp-cli",
    repositorySha,
    role: "payer",
    sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd",
    tlsCertificatePem,
    payerMcpIntakeCapabilityDigest: "5".repeat(64),
  });
  await writeLaunchManifest(payerManifestPath, payerManifest);
  const constructed = [];
  const dependencies = await createProductionSupervisorDependencies({
    createPayerMcpServer(input) {
      constructed.push(input);
      return { start: async () => ({ host: input.host, port: input.port, url: `https://${input.host}:${input.port}/mcp` }), stop: async () => undefined };
    },
    launchManifestPath: payerManifestPath,
    payerMcpServerOptions: {
      host: "127.0.0.1",
      port: 9443,
      tlsCertificatePath: certificatePath,
      tlsPrivateKeyPath: privateKeyPath,
    },
    probe: async () => ({ clean: true, head: repositorySha }),
    stateRoot: root,
  });
  assert.equal(typeof dependencies.startPayerMcpServer, "function");
  assert.equal(constructed[0].tlsCertificatePem, tlsCertificatePem);
  assert.equal(constructed[0].tlsPrivateKeyPem, tlsPrivateKeyPem);

  const seen = [];
  await supervisorMain([
    "--launch-manifest", payerManifestPath,
    "--state", root,
    "--payer-mcp-host", "127.0.0.1",
    "--payer-mcp-port", "9443",
    "--payer-mcp-tls-certificate", certificatePath,
    "--payer-mcp-tls-private-key", privateKeyPath,
  ], {
    async createProductionSupervisorDependencies(input) {
      seen.push(input);
      return {
        runSupervisor: async () => ({ paymentMoved: false }),
      };
    },
  });
  assert.equal(seen[0].payerMcpServerOptions.host, "127.0.0.1");
  assert.equal(seen[0].payerMcpServerOptions.port, 9443);
  assert.equal(seen[0].payerMcpServerOptions.tlsCertificatePath, certificatePath);
  assert.equal(seen[0].payerMcpServerOptions.tlsPrivateKeyPath, privateKeyPath);
  const externalSeen = [];
  await supervisorMain([
    "--launch-manifest", payerManifestPath,
    "--state", root,
    "--payer-mcp-host", "127.0.0.1",
    "--payer-mcp-port", "9443",
    "--payer-mcp-public-url", "https://203.0.113.10:19443/mcp",
    "--payer-mcp-tls-certificate", certificatePath,
    "--payer-mcp-tls-private-key", privateKeyPath,
  ], {
    async createProductionSupervisorDependencies(input) {
      externalSeen.push(input);
      return {
        runSupervisor: async () => ({ paymentMoved: false }),
      };
    },
  });
  assert.equal(externalSeen[0].payerMcpServerOptions.publicUrl, "https://203.0.113.10:19443/mcp");
  const brokerCapabilityPath = join(root, "bootstrap-broker.capability");
  await writeFile(brokerCapabilityPath, `${"12".repeat(32)}\n`, { mode: 0o600 });
  await chmod(brokerCapabilityPath, 0o600);
  const bootstrapSeen = [];
  await supervisorMain([
    "--launch-manifest", payerManifestPath,
    "--state", root,
    "--payer-mcp-host", "127.0.0.1",
    "--payer-mcp-port", "9443",
    "--payer-mcp-public-url", "https://203.0.113.10:19443/mcp",
    "--payer-mcp-tls-certificate", certificatePath,
    "--payer-mcp-tls-private-key", privateKeyPath,
    "--payer-mcp-bootstrap-broker-url", "http://127.0.0.1:9555",
    "--payer-mcp-bootstrap-broker-capability-file", brokerCapabilityPath,
  ], {
    async createProductionSupervisorDependencies(input) {
      bootstrapSeen.push(input);
      return {
        runSupervisor: async () => ({ paymentMoved: false }),
      };
    },
  });
  assert.equal(bootstrapSeen[0].payerMcpServerOptions.bootstrapBrokerUrl, "http://127.0.0.1:9555");
  assert.equal(bootstrapSeen[0].payerMcpServerOptions.bootstrapBrokerCapabilityFile, brokerCapabilityPath);
  const constructedWithBroker = [];
  await createProductionSupervisorDependencies({
    createPayerMcpServer(input) {
      constructedWithBroker.push(input);
      return { start: async () => ({ host: input.host, port: input.port, url: `https://${input.host}:${input.port}/mcp` }), stop: async () => undefined };
    },
    launchManifestPath: payerManifestPath,
    payerMcpServerOptions: {
      bootstrapBrokerCapabilityFile: brokerCapabilityPath,
      bootstrapBrokerUrl: "http://127.0.0.1:9555",
      host: "127.0.0.1",
      port: 9443,
      tlsCertificatePath: certificatePath,
      tlsPrivateKeyPath: privateKeyPath,
    },
    probe: async () => ({ clean: true, head: repositorySha }),
    stateRoot: join(root, "broker-runtime"),
  });
  assert.equal(typeof constructedWithBroker[0].claimRequestorBootstrap, "function");
  assert.equal(Object.hasOwn(constructedWithBroker[0], "bootstrapBrokerCapability"), false);
  assert.equal(Object.hasOwn(constructedWithBroker[0], "bootstrapBrokerCapabilityFile"), false);
  const publicBrokerClients = [];
  const loopbackBrokerClients = [];
  const constructedWithPublicBroker = [];
  await createProductionSupervisorDependencies({
    createAwsRequestorBootstrapBrokerClient(input) {
      publicBrokerClients.push(input);
      return {
        claimRequestorBootstrap: async () => ({
          paymentMoved: false,
        }),
      };
    },
    createPayerMcpServer(input) {
      constructedWithPublicBroker.push(input);
      return {
        start: async () => ({
          host: input.host,
          port: input.port,
          url: `https://${input.host}:${input.port}/mcp`,
        }),
        stop: async () => undefined,
      };
    },
    createRequestorBootstrapBrokerClient(input) {
      loopbackBrokerClients.push(input);
      return {
        claimRequestorBootstrap: async () => ({
          paymentMoved: false,
        }),
      };
    },
    launchManifestPath: payerManifestPath,
    payerMcpServerOptions: {
      bootstrapBrokerCapabilityFile: brokerCapabilityPath,
      bootstrapBrokerUrl:
        "https://bootstrap.example.net/v1/requestor-claims",
      host: "127.0.0.1",
      port: 9443,
      tlsCertificatePath: certificatePath,
      tlsPrivateKeyPath: privateKeyPath,
    },
    probe: async () => ({ clean: true, head: repositorySha }),
    stateRoot: join(root, "public-broker-runtime"),
  });
  assert.equal(publicBrokerClients.length, 1);
  assert.equal(loopbackBrokerClients.length, 0);
  assert.equal(
    publicBrokerClients[0].brokerUrl,
    "https://bootstrap.example.net/v1/requestor-claims",
  );
  assert.equal(
    typeof constructedWithPublicBroker[0]
      .claimRequestorBootstrap,
    "function",
  );
  let brokerHalfFactoryCalled = false;
  await assert.rejects(supervisorMain([
    "--launch-manifest", payerManifestPath,
    "--state", root,
    "--payer-mcp-host", "127.0.0.1",
    "--payer-mcp-port", "9443",
    "--payer-mcp-tls-certificate", certificatePath,
    "--payer-mcp-tls-private-key", privateKeyPath,
    "--payer-mcp-bootstrap-broker-url", "http://127.0.0.1:9555",
  ], {
    async createProductionSupervisorDependencies() {
      brokerHalfFactoryCalled = true;
      return {};
    },
  }));
  assert.equal(brokerHalfFactoryCalled, false);
  let publicOnlyFactoryCalled = false;
  await assert.rejects(supervisorMain([
    "--launch-manifest", payerManifestPath,
    "--state", root,
    "--payer-mcp-public-url", "https://203.0.113.10:19443/mcp",
  ], {
    async createProductionSupervisorDependencies() {
      publicOnlyFactoryCalled = true;
      return {};
    },
  }));
  assert.equal(publicOnlyFactoryCalled, false);
  let portZeroFactoryCalled = false;
  await assert.rejects(supervisorMain([
    "--launch-manifest", payerManifestPath,
    "--state", root,
    "--payer-mcp-host", "127.0.0.1",
    "--payer-mcp-port", "0",
    "--payer-mcp-tls-certificate", certificatePath,
    "--payer-mcp-tls-private-key", privateKeyPath,
  ], {
    async createProductionSupervisorDependencies() {
      portZeroFactoryCalled = true;
      return {};
    },
  }));
  assert.equal(portZeroFactoryCalled, false);

  const payeeManifestPath = join(manifestRoot, "payee-launch-manifest.json");
  const { manifest: payeeManifest } = createLaunchManifest({
    expectedTlsFingerprint: sha256(new X509Certificate(tlsCertificatePem).raw),
    nowMs: 0,
    operatorKeyId: "operator",
    randomBytes: () => Buffer.alloc(32, 10),
    relayUrl: "https://8.8.8.8:8443",
    releaseId: "release-mcp-cli",
    repositorySha,
    role: "payee",
    sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd",
    tlsCertificatePem,
    payerMcpIntakeCapability: "6".repeat(64),
  });
  await writeLaunchManifest(payeeManifestPath, payeeManifest);
  await assert.rejects(createProductionSupervisorDependencies({
    launchManifestPath: payeeManifestPath,
    payerMcpServerOptions: {
      host: "127.0.0.1",
      port: 9443,
      tlsCertificatePath: certificatePath,
      tlsPrivateKeyPath: privateKeyPath,
    },
    probe: async () => ({ clean: true, head: repositorySha }),
    stateRoot: join(root, "payee"),
  }));

  await chmod(privateKeyPath, 0o644);
  await assert.rejects(createProductionSupervisorDependencies({
    createPayerMcpServer() {
      throw new Error("must reject before constructing MCP server");
    },
    launchManifestPath: payerManifestPath,
    payerMcpServerOptions: {
      host: "127.0.0.1",
      port: 9443,
      tlsCertificatePath: certificatePath,
      tlsPrivateKeyPath: privateKeyPath,
    },
    probe: async () => ({ clean: true, head: repositorySha }),
    stateRoot: join(root, "bad-key-mode"),
  }));
});

test("production TLS option reader rejects growth and same-size drift before constructing MCP server", async (t) => {
  for (const candidate of ["growth", "same-size"]) {
    const root = await mkdtemp(join(tmpdir(), `supervisor-runtime-mcp-${candidate}-state-`));
    const manifestRoot = await mkdtemp(join(tmpdir(), `supervisor-runtime-mcp-${candidate}-manifest-`));
    t.after(() => Promise.all([
      rm(root, { force: true, recursive: true }),
      rm(manifestRoot, { force: true, recursive: true }),
    ]));
    await chmod(manifestRoot, 0o700);
    const certificatePath = join(manifestRoot, "tls-cert.pem");
    const privateKeyPath = join(manifestRoot, "tls-key.pem");
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
    await chmod(certificatePath, 0o600);
    await chmod(privateKeyPath, 0o600);
    const tlsCertificatePem = await readFile(certificatePath, "utf8");
    const repositorySha = "a".repeat(40);
    const manifestPath = join(manifestRoot, "payer-launch-manifest.json");
    const { manifest } = createLaunchManifest({
      expectedTlsFingerprint: sha256(new X509Certificate(tlsCertificatePem).raw),
      nowMs: 0,
      operatorKeyId: "operator",
      randomBytes: () => Buffer.alloc(32, 11),
      relayUrl: "https://8.8.8.8:8443",
      releaseId: `release-mcp-${candidate}`,
      repositorySha,
      role: "payer",
      sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd",
      tlsCertificatePem,
      payerMcpIntakeCapabilityDigest: "7".repeat(64),
    });
    await writeLaunchManifest(manifestPath, manifest);
    let hookCalled = false;
    await assert.rejects(createProductionSupervisorDependencies({
      createPayerMcpServer() {
        assert.fail("drifted TLS file must fail before MCP server construction");
      },
      launchManifestPath: manifestPath,
      payerMcpServerOptions: {
        host: "127.0.0.1",
        port: 9443,
        tlsCertificatePath: certificatePath,
        tlsPrivateKeyPath: privateKeyPath,
        async afterPinnedTextFirstRead({ path }) {
          if (path !== certificatePath || hookCalled) return;
          hookCalled = true;
          const current = await readFile(path);
          if (candidate === "growth") {
            await writeFile(path, Buffer.concat([current, Buffer.from("x")]));
          } else {
            const drifted = Buffer.from(current);
            drifted[0] = drifted[0] === 0x2d ? 0x20 : 0x2d;
            await writeFile(path, drifted);
          }
          await chmod(path, 0o600);
        },
      },
      probe: async () => ({ clean: true, head: repositorySha }),
      stateRoot: root,
    }));
    assert.equal(hookCalled, true);
  }
});

test("securely unlinks a launch manifest without retaining bootstrap capability in active state", async () => {
  const stateRoot = await mkdtemp(join(tmpdir(), "supervisor-state-"));
  const manifestRoot = await mkdtemp(join(tmpdir(), "supervisor-manifest-"));
  const manifestPath = join(manifestRoot, "launch-manifest.json");
  const rawManifest = `${JSON.stringify({ bootstrapCapability: "11".repeat(32) })}\n`;
  await writeFile(manifestPath, rawManifest, { mode: 0o600 });
  const store = await createPrivateSupervisorStateStore({ stateRoot });

  await store.retireLaunchManifest(manifestPath);
  await store.retireLaunchManifest(manifestPath);

  await assert.rejects(stat(manifestPath));
  assert.deepEqual(await readdir(stateRoot), []);
  await assert.rejects(store.retireLaunchManifest(join(stateRoot, "preflight", "launch-manifest.json")));
});

test("mints once then reuses the private token path", async () => {
  const root = await mkdtemp(join(tmpdir(), "supervisor-token-")); let calls = 0;
  const mint = async ({ tokenPath }) => { calls += 1; await writeFile(tokenPath, "token-value", { mode: 0o600 }); };
  await ensureToken({ role: "payer", repositorySha: "a".repeat(40), stateRoot: root, mint });
  await ensureToken({ role: "payer", repositorySha: "a".repeat(40), stateRoot: root, mint });
  assert.equal(calls, 1);
});

test("accepts only a clean exact repository probe", async () => {
  const sha = "a".repeat(40);
  await assert.doesNotReject(verifyRepositoryState({ repositorySha: sha, probe: async () => ({ head: sha, clean: true }) }));
  for (const probe of [async () => ({ head: "b".repeat(40), clean: true }), async () => ({ head: sha, clean: false })]) await assert.rejects(verifyRepositoryState({ repositorySha: sha, probe }));
});

test("builds the production Sepolia funding RPC seam without an injected RPC function", async () => {
  const calls = [];
  const rpc = createProductionSepoliaRpc({
    createClient({ chain, transport }) {
      assert.equal(chain.id, 11155111);
      assert.equal(typeof transport, "function");
      return {
        async getBalance(input) { calls.push(["balance", input]); return 5_000_000_000_000_000n; },
        async getTransactionCount(input) { calls.push(["nonce", input]); return 0n; },
      };
    },
  });
  assert.equal(await rpc({ method: "eth_getBalance", params: [`0x${"1".repeat(40)}`, "latest"] }), "0x11c37937e08000");
  assert.equal(await rpc({ method: "eth_getTransactionCount", params: [`0x${"1".repeat(40)}`, "latest"] }), "0x0");
  assert.deepEqual(calls, [["balance", { address: `0x${"1".repeat(40)}` }], ["nonce", { address: `0x${"1".repeat(40)}`, blockTag: "latest" }]]);
});

test("waits through zero and partial balances until both enrollment-bound addresses are ready", async () => {
  const repositorySha = "a".repeat(40);
  const sessionId = "8f953393-86d0-4f99-9d6a-102f525fbecd";
  const addresses = {
    rehearsal: `0x${"1".repeat(40)}`,
    stakeholder: `0x${"2".repeat(40)}`,
  };
  const enrollment = enrollmentFixture({
    addresses,
    releaseId: "release-funding-wait",
    repositorySha,
    role: "payer",
    sessionId,
  });
  const enrollmentSet = {
    enrollments: {
      payer: {
        enrollmentBase64: canonicalBytes(enrollment).toString("base64"),
      },
    },
    repositorySha,
    sessionId,
  };
  const observations = [
    {
      balances: [0n, 0n],
      nonces: [0n, 0n],
    },
    {
      balances: [10_000_000_000_000_000n, 0n],
      nonces: [0n, 0n],
    },
    {
      balances: [
        10_000_000_000_000_000n,
        10_000_000_000_000_000n,
      ],
      nonces: [0n, 0n],
    },
  ];
  const calls = [];
  let nowMs = 0;
  const sleeps = [];
  const sepoliaRpc = async ({ method, params }) => {
    const addressIndex = params[0] === addresses.rehearsal ? 0 : 1;
    const round = Math.floor(calls.length / 4);
    calls.push([method, params[0]]);
    const observation = observations[Math.min(round, observations.length - 1)];
    const value = method === "eth_getBalance"
      ? observation.balances[addressIndex]
      : observation.nonces[addressIndex];
    return `0x${value.toString(16)}`;
  };
  const verify = createFundingInputVerifier({
    intervalMs: 5_000,
    now: () => nowMs,
    sepoliaRpc,
    sleeper: async (milliseconds) => {
      sleeps.push(milliseconds);
      nowMs += milliseconds;
    },
  });

  assert.deepEqual(await verify({
    addresses: [addresses.rehearsal, addresses.stakeholder],
    enrollmentSet,
    repositorySha,
    role: "payer",
    sessionId,
  }), { paymentMoved: false });
  assert.deepEqual(sleeps, [5_000, 5_000]);
  assert.equal(calls.length, 12);
});

test("fails closed immediately for invalid funding and at the bounded underfunding deadline", async () => {
  const repositorySha = "b".repeat(40);
  const sessionId = "29ba5f3a-46b4-420a-b807-6346eb7a42b2";
  const addresses = {
    rehearsal: `0x${"3".repeat(40)}`,
    stakeholder: `0x${"4".repeat(40)}`,
  };
  const enrollment = enrollmentFixture({
    addresses,
    releaseId: "release-funding-failure",
    repositorySha,
    role: "payee",
    sessionId,
  });
  const input = {
    addresses: [addresses.rehearsal, addresses.stakeholder],
    enrollmentSet: {
      enrollments: {
        payee: {
          enrollmentBase64: canonicalBytes(enrollment).toString("base64"),
        },
      },
      repositorySha,
      sessionId,
    },
    repositorySha,
    role: "payee",
    sessionId,
  };

  for (const values of [
    { balance: 20_000_000_000_000_001n, nonce: 0n },
    { balance: 10_000_000_000_000_000n, nonce: 1n },
    { balance: "malformed", nonce: 0n },
  ]) {
    let sleeps = 0;
    const verify = createFundingInputVerifier({
      now: () => 0,
      sepoliaRpc: async ({ method }) => {
        const value = method === "eth_getBalance" ? values.balance : values.nonce;
        return typeof value === "bigint" ? `0x${value.toString(16)}` : value;
      },
      sleeper: async () => {
        sleeps += 1;
      },
    });
    await assert.rejects(verify(input));
    assert.equal(sleeps, 0);
  }

  let mismatchedRpcCalls = 0;
  await assert.rejects(createFundingInputVerifier({
    now: () => 0,
    sepoliaRpc: async () => {
      mismatchedRpcCalls += 1;
      return "0x0";
    },
    sleeper: async () => {},
  })({
    ...input,
    addresses: [...input.addresses].reverse(),
  }));
  assert.equal(mismatchedRpcCalls, 0);

  let nowMs = 0;
  const sleeps = [];
  const deadlineVerifier = createFundingInputVerifier({
    intervalMs: 300_000,
    now: () => nowMs,
    sepoliaRpc: async () => "0x0",
    sleeper: async (milliseconds) => {
      sleeps.push(milliseconds);
      nowMs += milliseconds;
    },
  });
  await assert.rejects(deadlineVerifier(input));
  // The run must stop exactly at the bounded deadline: every sleep respects
  // the poll interval and the cumulative wait equals the deadline.
  assert.ok(sleeps.length > 1);
  assert.ok(sleeps.every((milliseconds) => milliseconds <= 300_000));
  assert.equal(sleeps.reduce((total, milliseconds) => total + milliseconds, 0), SUPERVISOR_FUNDING_DEADLINE_MS);
});

test("pins Git inspection to a clean frozen repository object despite poisoned environment", async () => {
  const root = await mkdtemp(join(tmpdir(), "supervisor-git-"));
  const git = (...arguments_) => execFileSync("/usr/bin/git", arguments_, { cwd: root, encoding: "utf8" });
  git("init"); git("config", "user.email", "test@example.invalid"); git("config", "user.name", "test");
  await mkdir(join(root, "docs", "operator-keys"), { recursive: true });
  const frozenKey = Buffer.alloc(32, 7).toString("base64");
  await writeFile(join(root, "docs", "operator-keys", "operator.pub"), `${frozenKey}\n`);
  git("add", "."); git("commit", "-m", "fixture");
  const sha = git("rev-parse", "HEAD").trim(); const inspector = createGitInspector(root);
  const originalGitDir = process.env.GIT_DIR, originalPath = process.env.PATH;
  process.env.GIT_DIR = "/not/a/repository"; process.env.PATH = "/not/a/bin";
  try {
    assert.deepEqual(await inspector.probe(), { clean: true, head: sha });
    assert.equal(await inspector.operatorKey(sha, "operator"), frozenKey);
    await writeFile(join(root, "docs", "operator-keys", "operator.pub"), `${Buffer.alloc(32, 8).toString("base64")}\n`);
    assert.equal(await inspector.operatorKey(sha, "operator"), frozenKey);
    await assert.rejects(inspector.operatorKey("b".repeat(40), "operator"));
    await assert.rejects(inspector.probe());
  } finally {
    if (originalGitDir === undefined) delete process.env.GIT_DIR; else process.env.GIT_DIR = originalGitDir;
    if (originalPath === undefined) delete process.env.PATH; else process.env.PATH = originalPath;
  }
});

test("creates invitation proofs once and rejects partial secrets", async () => {
  const root = await mkdtemp(join(tmpdir(), "supervisor-invitations-"));
  const input = { capabilityDigest: "1".repeat(64), releaseId: "release-a", repositorySha: "a".repeat(40), role: "payer", sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd", stateRoot: root };
  const proofs = await ensureInvitations(input);
  assert.equal(proofs.length, 2);
  assert.notEqual(proofs[0].address, proofs[1].address);
  for (const proof of proofs) assert.equal((await recoverMessageAddress({ message: { raw: invitationProofPreimage({ address: proof.address, capabilityDigest: input.capabilityDigest, releaseId: input.releaseId, repositorySha: input.repositorySha, role: input.role, run: proof.subjectRun, sessionId: input.sessionId }) }, signature: proof.signature })).toLowerCase(), proof.address);
  await assert.doesNotReject(ensureInvitations({ ...input, create: async () => { throw new Error("recreated"); } }));
  await unlink(proofs[0].secretPath);
  await assert.rejects(ensureInvitations(input));
});

test("creates canonical Payer and Requestor invitation personas", async () => {
  for (const [role, displayName] of [["payer", "Payer"], ["payee", "Requestor"]]) {
    const root = await mkdtemp(join(tmpdir(), `supervisor-${role}-persona-`));
    let creationArguments;
    const input = {
      capabilityDigest: "1".repeat(64),
      releaseId: "release-a",
      repositorySha: "a".repeat(40),
      role,
      sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd",
      stateRoot: root,
      create: async (arguments_) => {
        creationArguments = arguments_;
        await createInvitationFiles(arguments_);
      },
    };
    const proofs = await ensureInvitations(input);
    assert.equal(proofs.length, 2);
    assert.deepEqual(
      creationArguments.slice(creationArguments.indexOf("--names"), creationArguments.indexOf("--names") + 2),
      ["--names", `${displayName},${displayName}`],
    );
  }
});

test("rejects incomplete child argv before any process can be considered ready", async () => {
  const launcher = createSupervisorLauncher({ repositoryRoot: process.cwd() });
  await assert.rejects(launcher({ command: "scripts/probe-bilateral-rendezvous.mjs", args: [] }));
  await assert.rejects(launcher({ command: "sh", args: ["-c", "true"] }));
  await assert.rejects(launcher({ command: "bin/handshake-propose.mjs", args: ["--output", "relative"] }));
  await assert.rejects(launcher({ command: "bin/handshake-propose.mjs", args: ["--clockchain-token-file", "/token", "--descriptor", "/descriptor", "--invitation", "/invitation", "--output", "/result", "--i-understand-this-writes-to-clockchain", "extra"] }));
});

test("announces a role child only after its exact authenticated readiness line", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "supervisor-ready-"));
  await mkdir(join(root, "bin"));
  await writeFile(join(root, "package.json"), '{"type":"module"}\n');
  const script = join(root, "bin", "handshake-propose.mjs");
  t.after(() => unlink(script).catch(() => {}));
  await writeFile(script, [
    "import { closeSync, writeSync } from 'node:fs';",
    "const fd = Number.parseInt(process.env.CLOCKCHAIN_BILATERAL_ROLE_READY_FD, 10);",
    "writeSync(fd, `${JSON.stringify({ nonce: process.env.CLOCKCHAIN_BILATERAL_ROLE_READY_NONCE, role: 'payer', schema: process.env.CLOCKCHAIN_BILATERAL_ROLE_READY_SCHEMA })}\\n`);",
    "closeSync(fd);",
    "setTimeout(() => process.exit(0), 100);",
  ].join("\n"));
  const launcher = createSupervisorLauncher({ repositoryRoot: root });
  const result = await launcher({
    command: "bin/handshake-propose.mjs",
    args: ["--clockchain-token-file", "/token", "--descriptor", "/descriptor", "--invitation", "/invitation", "--output", "/result", "--i-understand-this-writes-to-clockchain"],
  });
  assert.equal(result.started, true);
  assert.deepEqual(await result.completion, { ambiguous: false, exitCode: 0 });
});

test("requires readiness EOF after the exact line and rejects a delayed duplicate", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "supervisor-ready-eof-"));
  await mkdir(join(root, "bin"));
  await writeFile(join(root, "package.json"), '{"type":"module"}\n');
  const script = join(root, "bin", "handshake-propose.mjs");
  t.after(() => unlink(script).catch(() => {}));
  const line = "`${JSON.stringify({ nonce: process.env.CLOCKCHAIN_BILATERAL_ROLE_READY_NONCE, role: 'payer', schema: process.env.CLOCKCHAIN_BILATERAL_ROLE_READY_SCHEMA })}\\n`";
  await writeFile(script, [
    "import { writeSync } from 'node:fs';",
    `const line = ${line};`,
    "writeSync(3, line);",
    "setTimeout(() => { writeSync(3, line); process.exit(0); }, 25);",
  ].join("\n"));
  const launcher = createSupervisorLauncher({ readinessDeadlineMs: 100, repositoryRoot: root });
  const args = ["--clockchain-token-file", "/token", "--descriptor", "/descriptor", "--invitation", "/invitation", "--output", "/result", "--i-understand-this-writes-to-clockchain"];
  await assert.rejects(launcher({ command: "bin/handshake-propose.mjs", args }));
});

test("passes only the sanitized environment plus readiness values to role children", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "supervisor-ready-env-"));
  const output = join(root, "environment.json");
  await mkdir(join(root, "bin"));
  await writeFile(join(root, "package.json"), '{"type":"module"}\n');
  const script = join(root, "bin", "handshake-propose.mjs");
  t.after(() => unlink(script).catch(() => {}));
  await writeFile(script, [
    "import { closeSync, writeFile, writeSync } from 'node:fs';",
    "writeFile(process.argv[process.argv.indexOf('--output') + 1], JSON.stringify(Object.keys(process.env).sort()), () => {});",
    "writeSync(3, `${JSON.stringify({ nonce: process.env.CLOCKCHAIN_BILATERAL_ROLE_READY_NONCE, role: 'payer', schema: process.env.CLOCKCHAIN_BILATERAL_ROLE_READY_SCHEMA })}\\n`);",
    "closeSync(3);",
    "setTimeout(() => process.exit(0), 20);",
  ].join("\n"));
  const launcher = createSupervisorLauncher({ repositoryRoot: root });
  const args = ["--clockchain-token-file", "/token", "--descriptor", "/descriptor", "--invitation", "/invitation", "--output", output, "--i-understand-this-writes-to-clockchain"];
  const result = await launcher({ command: "bin/handshake-propose.mjs", args });
  await result.completion;
  const keys = JSON.parse(await (await import("node:fs/promises")).readFile(output, "utf8"));
  assert.deepEqual(keys.filter((key) => key !== "__CF_USER_TEXT_ENCODING"), ["CLOCKCHAIN_BILATERAL_ROLE_READY_FD", "CLOCKCHAIN_BILATERAL_ROLE_READY_NONCE", "CLOCKCHAIN_BILATERAL_ROLE_READY_SCHEMA", "LANG", "LC_ALL", "PATH"]);
});

test("rejects malformed, wrong-role, and duplicate role readiness before start", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "supervisor-ready-"));
  await mkdir(join(root, "bin"));
  await writeFile(join(root, "package.json"), '{"type":"module"}\n');
  const script = join(root, "bin", "handshake-propose.mjs");
  const launcher = createSupervisorLauncher({ repositoryRoot: root });
  const args = ["--clockchain-token-file", "/token", "--descriptor", "/descriptor", "--invitation", "/invitation", "--output", "/result", "--i-understand-this-writes-to-clockchain"];
  for (const body of [
    "import { writeSync } from 'node:fs'; writeSync(3, 'not-json\\n');",
    "import { writeSync } from 'node:fs'; writeSync(3, `${JSON.stringify({ nonce: '0'.repeat(64), role: 'payer', schema: process.env.CLOCKCHAIN_BILATERAL_ROLE_READY_SCHEMA })}\\n`);",
    "import { writeSync } from 'node:fs'; writeSync(3, `${JSON.stringify({ nonce: process.env.CLOCKCHAIN_BILATERAL_ROLE_READY_NONCE, role: 'payee', schema: process.env.CLOCKCHAIN_BILATERAL_ROLE_READY_SCHEMA })}\\n`);",
    "import { writeSync } from 'node:fs'; const line = `${JSON.stringify({ nonce: process.env.CLOCKCHAIN_BILATERAL_ROLE_READY_NONCE, role: 'payer', schema: process.env.CLOCKCHAIN_BILATERAL_ROLE_READY_SCHEMA })}\\n`; writeSync(3, line + line);",
  ]) {
    await writeFile(script, body);
    await assert.rejects(launcher({ command: "bin/handshake-propose.mjs", args }));
  }
});
