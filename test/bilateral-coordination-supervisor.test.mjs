import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { test } from "node:test";
import { mkdtemp, mkdir, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { privateKeyToAccount } from "viem/accounts";
import { canonicalBytes } from "../src/bilateral/canonical.mjs";
import { canonicalizeReceiptEventValue } from "../src/canonical.mjs";
import { createCoordinationEnvelope } from "../src/bilateral/coordination/envelope.mjs";
import { coordinationEnrollmentSignaturePreimage, verifyCoordinationEnrollment } from "../src/bilateral/coordination/enrollment.mjs";
import { parseCoordinationEnrollmentSet } from "../src/bilateral/coordination/enrollment.mjs";
import { payerMandateDigest, signPayerMandate } from "../src/bilateral/payer-mandate.mjs";
import { paymentRequestDigest, signPaymentRequest } from "../src/bilateral/payment-request.mjs";

import {
  SUPERVISOR_COMMAND_POLICY,
  SUPERVISOR_STATE_SCHEMA,
  buildSupervisorCommand,
  authenticateSupervisorReplay,
  createRoleSupervisor,
  executeSupervisorTransition,
  runSupervisor,
} from "../src/bilateral/coordination/supervisor.mjs";
import { createSupervisorLauncher } from "../src/bilateral/coordination/supervisor-runtime.mjs";

const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const raw = (pair) => pair.publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64");
const pem = (pair) => pair.privateKey.export({ format: "pem", type: "pkcs8" });
const independentlyVerifiedEnrollmentSet = async ({ enrollmentSet }) => enrollmentSet;
function replayFixture({ payerInvitationAddress = `0x${"1".repeat(40)}`, payeeInvitationAddress = `0x${"3".repeat(40)}` } = {}) {
  const payer = generateKeyPairSync("ed25519"), payee = generateKeyPairSync("ed25519"), operator = generateKeyPairSync("ed25519");
  const repo = "a".repeat(40), session = "8f953393-86d0-4f99-9d6a-102f525fbecd", release = "release-a";
  const enrollment = (role, pair, address) => { const value = { capabilityDigest: sha256(role), coordinationKey: { algorithm: "ed25519", keyId: `${role}-coordination`, publicKey: raw(pair) }, invitations: { rehearsal: { address, algorithm: "eip191", signature: `0x${"0".repeat(130)}` }, stakeholder: { address: `0x${(role === "payer" ? "2" : "4").repeat(40)}`, algorithm: "eip191", signature: `0x${"0".repeat(130)}` } }, paymentMoved: false, preflightKey: { algorithm: "ed25519", keyId: `${role}-preflight`, publicKey: raw(generateKeyPairSync("ed25519")) }, releaseId: release, repositorySha: repo, role, schema: "clockchain.bilateral-coordination-enrollment/v1", sessionId: session }; return { ...value, signature: sign(null, coordinationEnrollmentSignaturePreimage(value), pair.privateKey).toString("base64") }; };
  const payerEnrollment = enrollment("payer", payer, payerInvitationAddress), payeeEnrollment = enrollment("payee", payee, payeeInvitationAddress);
  const entry = (value) => { const bytes = canonicalBytes(value); return { enrollmentBase64: bytes.toString("base64"), enrollmentDigest: sha256(bytes), receiptBase64: Buffer.from("{}").toString("base64") }; };
  const set = Buffer.from(JSON.stringify(canonicalizeReceiptEventValue({ enrollments: { payer: entry(payerEnrollment), payee: entry(payeeEnrollment) }, paymentMoved: false, releaseId: release, repositorySha: repo, schema: "clockchain.bilateral-coordination-enrollment-set/v1", sessionId: session })), "utf8");
  const event = (role, kind, pair) => createCoordinationEnvelope({ artifactDigest: null, kind, paymentMoved: false, previousEventDigest: null, privateKeyPem: pem(pair), publicKey: raw(pair), publicKeyId: role === "operator" ? "operator" : `${role}-coordination`, releaseId: release, repositorySha: repo, role, schema: "clockchain.bilateral-coordination-event/v1", sequence: "0", sessionId: session, subjectRun: "release" });
  return { events: [event("payer", "ENROLLMENT_CONFIRMED", payer), event("payee", "ENROLLMENT_CONFIRMED", payee), event("operator", "ENROLLMENT_RECEIPT", operator)], operator, payee, payer, release, repo, session, set };
}

function replayThroughDescriptor(fixture) {
  const events = [...fixture.events];
  const append = (role, pair, kind, artifactDigest = null, subjectRun = "release") => {
    const prior = events.filter((event) => event.role === role);
    const event = createCoordinationEnvelope({
      artifactDigest,
      kind,
      paymentMoved: false,
      previousEventDigest: prior.at(-1)?.eventDigest ?? null,
      privateKeyPem: pem(pair),
      publicKey: raw(pair),
      publicKeyId: role === "operator" ? "operator" : `${role}-coordination`,
      releaseId: fixture.release,
      repositorySha: fixture.repo,
      role,
      schema: "clockchain.bilateral-coordination-event/v1",
      sequence: String(prior.length),
      sessionId: fixture.session,
      subjectRun,
    });
    events.push(event);
    return event;
  };
  append("operator", fixture.operator, "WAIT_FOR_FUNDING");
  append("payer", fixture.payer, "FUNDING_INPUTS_READY");
  append("payee", fixture.payee, "FUNDING_INPUTS_READY");
  append("payer", fixture.payer, "TOKEN_READY", "1".repeat(64));
  append("payee", fixture.payee, "TOKEN_READY", "2".repeat(64));
  append("operator", fixture.operator, "PREFLIGHT_PLAN_READY", "3".repeat(64));
  append("payer", fixture.payer, "PREFLIGHT_PARTICIPANT_READY", "4".repeat(64));
  append("payee", fixture.payee, "PREFLIGHT_PARTICIPANT_READY", "5".repeat(64));
  append("operator", fixture.operator, "REGISTER_REHEARSAL", "6".repeat(64), "rehearsal");
  append("payer", fixture.payer, "IDENTITY_PACKAGE_READY", "7".repeat(64), "rehearsal");
  append("payee", fixture.payee, "IDENTITY_PACKAGE_READY", "8".repeat(64), "rehearsal");
  append("payer", fixture.payer, "PAYER_MANDATE_READY", "9".repeat(64), "rehearsal");
  append("payee", fixture.payee, "PAYMENT_REQUEST_READY", "a".repeat(64), "rehearsal");
  append("payer", fixture.payer, "PAYMENT_REQUEST_MATCHED", null, "rehearsal");
  const descriptorBytes = Buffer.from("descriptor");
  const descriptor = append("operator", fixture.operator, "REHEARSAL_DESCRIPTOR_READY", sha256(descriptorBytes), "rehearsal");
  return { append, descriptor, descriptorBytes, events };
}

function identityPackage({ address, agentId, displayName, repositorySha }) {
  return canonicalBytes({
    address,
    agentId,
    chainId: "11155111",
    displayName,
    identityReference: `eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:${agentId}`,
    metadata: { roleplay: true },
    paymentMoved: false,
    register: { status: "confirmed" },
    registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
    repositorySha,
    schema: "clockchain.bilateral-identity-package/v1",
  });
}

function replayThroughIdentities(fixture) {
  const events = [...fixture.events];
  const artifacts = new Map();
  const append = (role, pair, kind, artifactDigest = null, subjectRun = "release") => {
    const prior = events.filter((event) => event.role === role);
    const event = createCoordinationEnvelope({
      artifactDigest,
      kind,
      paymentMoved: false,
      previousEventDigest: prior.at(-1)?.eventDigest ?? null,
      privateKeyPem: pem(pair),
      publicKey: raw(pair),
      publicKeyId: role === "operator" ? "operator" : `${role}-coordination`,
      releaseId: fixture.release,
      repositorySha: fixture.repo,
      role,
      schema: "clockchain.bilateral-coordination-event/v1",
      sequence: String(prior.length),
      sessionId: fixture.session,
      subjectRun,
    });
    events.push(event);
    return event;
  };
  append("operator", fixture.operator, "WAIT_FOR_FUNDING");
  append("payer", fixture.payer, "FUNDING_INPUTS_READY");
  append("payee", fixture.payee, "FUNDING_INPUTS_READY");
  append("payer", fixture.payer, "TOKEN_READY", "1".repeat(64));
  append("payee", fixture.payee, "TOKEN_READY", "2".repeat(64));
  append("operator", fixture.operator, "PREFLIGHT_PLAN_READY", "3".repeat(64));
  append("payer", fixture.payer, "PREFLIGHT_PARTICIPANT_READY", "4".repeat(64));
  append("payee", fixture.payee, "PREFLIGHT_PARTICIPANT_READY", "5".repeat(64));
  append("operator", fixture.operator, "REGISTER_REHEARSAL", "6".repeat(64), "rehearsal");
  const payerIdentity = identityPackage({
    address: parseCoordinationEnrollmentSet(fixture.set).enrollments.payer
      ? verifyCoordinationEnrollment(JSON.parse(Buffer.from(parseCoordinationEnrollmentSet(fixture.set).enrollments.payer.enrollmentBase64, "base64").toString("utf8"))).invitations.rehearsal.address
      : `0x${"1".repeat(40)}`,
    agentId: "8677",
    displayName: "Iris",
    repositorySha: fixture.repo,
  });
  const payeeIdentity = identityPackage({
    address: parseCoordinationEnrollmentSet(fixture.set).enrollments.payee
      ? verifyCoordinationEnrollment(JSON.parse(Buffer.from(parseCoordinationEnrollmentSet(fixture.set).enrollments.payee.enrollmentBase64, "base64").toString("utf8"))).invitations.rehearsal.address
      : `0x${"3".repeat(40)}`,
    agentId: "8678",
    displayName: "Billie",
    repositorySha: fixture.repo,
  });
  artifacts.set(sha256(payerIdentity), payerIdentity);
  artifacts.set(sha256(payeeIdentity), payeeIdentity);
  append("payer", fixture.payer, "IDENTITY_PACKAGE_READY", sha256(payerIdentity), "rehearsal");
  append("payee", fixture.payee, "IDENTITY_PACKAGE_READY", sha256(payeeIdentity), "rehearsal");
  return { append, artifacts, events, payerIdentity, payeeIdentity };
}

const payerIntentAccount = privateKeyToAccount(`0x${"5".repeat(64)}`);
const payeeIntentAccount = privateKeyToAccount(`0x${"6".repeat(64)}`);

test("pins the supervisor schema and closed role-run command policy", () => {
  assert.equal(SUPERVISOR_STATE_SCHEMA, "clockchain.bilateral-supervisor-state/v1");
  assert.deepEqual(SUPERVISOR_COMMAND_POLICY, {
    PREFLIGHT_PLAN_READY: "preflight-participant",
    REGISTER_REHEARSAL: "register-identity",
    REHEARSAL_DESCRIPTOR_READY: "accept-descriptor",
    START_REHEARSAL: "run-role",
    REGISTER_STAKEHOLDER: "register-identity",
    STAKEHOLDER_DESCRIPTOR_READY: "accept-descriptor",
    START_STAKEHOLDER: "run-role",
    EXACT_RECOVERY_AUTHORIZATION: "recover-exact-command",
    TERMINAL_ABORT: "abort",
  });
  assert.deepEqual(buildSupervisorCommand({
    event: { kind: "START_REHEARSAL", repositorySha: "a".repeat(40), role: "operator", subjectRun: "rehearsal" },
    localState: { repositorySha: "a".repeat(40), role: "payer", tokenPath: "/state/token", rehearsal: { descriptorPath: "/state/rehearsal/descriptor", invitationPath: "/state/rehearsal/invitation", resultDirectory: "/state/rehearsal/result" } },
  }), { args: ["--clockchain-token-file", "/state/token", "--descriptor", "/state/rehearsal/descriptor", "--invitation", "/state/rehearsal/invitation", "--output", "/state/rehearsal/result", "--i-understand-this-writes-to-clockchain"], command: "bin/handshake-propose.mjs" });
});

test("bootstraps only through the pinned dependency contract", async () => {
  const writes = [];
  const supervisor = await createRoleSupervisor({
    launchManifestPath: "/private/launch.json",
    stateRoot: "/private/state",
    dependencies: {
      async readLaunchManifest() { return { bootstrapCapability: "11".repeat(32), releaseId: "release-a", repositorySha: "a".repeat(40), role: "payer", sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd" }; },
      async verifyRepositoryState() { return true; },
      async createCoordinationIdentity() { const key = generateKeyPairSync("ed25519"); return { keyId: "payer-coordination", privateKeyPem: pem(key), publicKey: raw(key) }; },
      async createLocalPreflightEnrollment() { const key = generateKeyPairSync("ed25519"); return { privateKeyPath: "/state/preflight", publicArtifact: { paymentMoved: false, publicKey: raw(key), repositorySha: "a".repeat(40), role: "payer" } }; },
      async createInvitations() { return [{ subjectRun: "rehearsal", address: `0x${"1".repeat(40)}`, algorithm: "eip191", signature: `0x${"0".repeat(130)}`, secretPath: "/a" }, { subjectRun: "stakeholder", address: `0x${"2".repeat(40)}`, algorithm: "eip191", signature: `0x${"0".repeat(130)}`, secretPath: "/b" }]; },
      async createTransport() { return {}; },
      createCoordinationClient() { return { async bootstrap() { return { activeLaunchState: { paymentMoved: false, releaseId: "release-a", repositorySha: "a".repeat(40), role: "payer", sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd" }, receipt: {} }; } }; },
      async writeState(value) { writes.push(value); },
      async readState() { return writes.at(-1); },
      async validateActiveLaunchState(value) { return value; },
      async retireLaunchManifest() {},
    },
  });
  const state = await supervisor.bootstrap();
  assert.equal(state.paymentMoved, false);
  assert.equal(state.role, "payer");
  assert.equal(writes.length, 2);
});

test("builds only exact preflight and registration commands", () => {
  const state = { repositorySha: "a".repeat(40), role: "payer", tokenPath: "/state/token", preflight: { planPath: "/state/plan", privateKeyPath: "/state/preflight", outputPath: "/state/preflight/report" }, rehearsal: { invitationPath: "/state/rehearsal/invitation", identityDirectory: "/state/rehearsal/identity" } };
  assert.deepEqual(buildSupervisorCommand({ event: { kind: "PREFLIGHT_PLAN_READY", repositorySha: "a".repeat(40), role: "operator", subjectRun: "release" }, localState: state }), { command: "scripts/probe-bilateral-rendezvous.mjs", args: ["participant", "--role", "payer", "--plan", "/state/plan", "--token-file", "/state/token", "--participant-private-key", "/state/preflight", "--output", "/state/preflight"] });
  assert.deepEqual(buildSupervisorCommand({ event: { kind: "REGISTER_REHEARSAL", repositorySha: "a".repeat(40), role: "operator", subjectRun: "rehearsal" }, localState: state }), { command: "scripts/register-bilateral-identity.mjs", args: ["--invitation", "/state/rehearsal/invitation", "--output", "/state/rehearsal/identity", "--repository-sha", "a".repeat(40), "--i-understand-this-writes-to-sepolia"] });
});

test("authenticates a two-pass signed replay and derives local sender state", async () => {
  const fixture = replayFixture();
  const replay = await authenticateSupervisorReplay({ events: fixture.events, enrollmentSet: fixture.set, operatorPublicKey: raw(fixture.operator), releaseId: fixture.release, repositorySha: fixture.repo, sessionId: fixture.session, localRole: "payer", verifyEnrollmentSet: independentlyVerifiedEnrollmentSet });
  assert.equal(replay.senderState.sequence, "1");
  assert.equal(replay.senderState.previousEventDigest, fixture.events[0].eventDigest);
  assert.equal(replay.view.state, "ADDRESSES_READY");
  assert.equal(Object.isFrozen(replay), true);
});

test("returns detached frozen replay events", async () => {
  const fixture = replayFixture();
  const events = structuredClone(fixture.events);
  const replay = await authenticateSupervisorReplay({ events, enrollmentSet: fixture.set, operatorPublicKey: raw(fixture.operator), releaseId: fixture.release, repositorySha: fixture.repo, sessionId: fixture.session, localRole: "payer", verifyEnrollmentSet: independentlyVerifiedEnrollmentSet });
  const digest = replay.events[0].eventDigest;
  events[0].eventDigest = "f".repeat(64);
  events[0].signature.publicKey = "mutated";
  assert.equal(replay.events[0].eventDigest, digest);
  assert.equal(Object.isFrozen(replay.events[0]), true);
});

test("durably aborts only an event from the authenticated replay snapshot", async () => {
  const event = Object.freeze({ kind: "TERMINAL_ABORT", eventDigest: "a".repeat(64) });
  const writes = [];
  await executeSupervisorTransition({ client: {}, event, localState: { authenticatedEvents: Object.freeze([event]), repositorySha: "a".repeat(40), tokenPath: "/private/token" }, dependencies: { async writeState(value) { writes.push(value); } } });
  assert.deepEqual(writes, [{ authenticatedEvents: [event], phase: "ABORTED", paymentMoved: false, repositorySha: "a".repeat(40), tokenPath: "/private/token" }]);
  await assert.rejects(executeSupervisorTransition({ client: {}, event: { ...event }, localState: { authenticatedEvents: Object.freeze([event]) }, dependencies: { async writeState() {} } }));
});

test("accepts an authenticated descriptor only after durable readback", async () => {
  const digest = sha256(Buffer.from("descriptor"));
  const event = Object.freeze({ artifactDigest: digest, kind: "REHEARSAL_DESCRIPTOR_READY", subjectRun: "rehearsal" });
  const writes = [];
  const state = { authenticatedEvents: Object.freeze([event]), releaseId: "release-123", repositorySha: "a".repeat(40), role: "payer", sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd", rehearsal: { descriptorPath: "/state/rehearsal/descriptor" } };
  await executeSupervisorTransition({ client: { async getArtifact(value) { assert.deepEqual(value, { artifactType: "signed-descriptor", digest }); return Buffer.from("descriptor"); }, async appendEvent(value) { assert.deepEqual(value, { artifactDigest: digest, kind: "DESCRIPTOR_ACCEPTED", subjectRun: "rehearsal" }); } }, event, localState: state, dependencies: { async verifyDescriptor(bytes, context) { assert.equal(bytes.toString(), "descriptor"); assert.equal(context.repositorySha, state.repositorySha); assert.equal(context.releaseId, state.releaseId); assert.equal(context.sessionId, state.sessionId); assert.equal(context.subjectRun, "rehearsal"); }, async writeArtifactFile(value) { assert.equal(value.path, state.rehearsal.descriptorPath); }, async writeState(value) { writes.push(value); }, async readState() { return writes.at(-1); } } });
  assert.equal(writes.at(-1).phase, "DESCRIPTOR_ACCEPTED");
});

test("adopts an EVENT_APPENDED descriptor journal without rewriting or appending", async () => {
  const digest = sha256(Buffer.from("descriptor"));
  const event = Object.freeze({ artifactDigest: digest, eventDigest: "b".repeat(64), kind: "REHEARSAL_DESCRIPTOR_READY", subjectRun: "rehearsal" });
  let reads = 0;
  const result = await executeSupervisorTransition({ client: { async getArtifact() { reads += 1; return Buffer.from("descriptor"); }, async appendEvent() { assert.fail("must not append"); } }, event, localState: { authenticatedEvents: Object.freeze([event]), descriptorJournal: { artifactDigest: digest, eventDigest: event.eventDigest, stage: "EVENT_APPENDED", subjectRun: "rehearsal" }, repositorySha: "a".repeat(40), role: "payer", rehearsal: { descriptorPath: "/state/rehearsal/descriptor" } }, dependencies: { async verifyDescriptor() { assert.fail("must not verify"); }, async writeArtifactFile() { assert.fail("must not write"); }, async writeState() { assert.fail("must not write state"); }, async readState() { assert.fail("must not read state"); } } });
  assert.equal(result.kind, "DESCRIPTOR_ACCEPTED");
  assert.equal(reads, 0);
});

test("the long-lived supervisor accepts a descriptor without treating it as a child command", async () => {
  const fixture = replayFixture();
  const events = [...fixture.events];
  const append = (role, pair, kind, artifactDigest = null, subjectRun = "release") => {
    const prior = events.filter((event) => event.role === role);
    const event = createCoordinationEnvelope({
      artifactDigest,
      kind,
      paymentMoved: false,
      previousEventDigest: prior.at(-1)?.eventDigest ?? null,
      privateKeyPem: pem(pair),
      publicKey: raw(pair),
      publicKeyId: role === "operator" ? "operator" : `${role}-coordination`,
      releaseId: fixture.release,
      repositorySha: fixture.repo,
      role,
      schema: "clockchain.bilateral-coordination-event/v1",
      sequence: String(prior.length),
      sessionId: fixture.session,
      subjectRun,
    });
    events.push(event);
    return event;
  };
  append("operator", fixture.operator, "WAIT_FOR_FUNDING");
  append("payer", fixture.payer, "FUNDING_INPUTS_READY");
  append("payee", fixture.payee, "FUNDING_INPUTS_READY");
  append("payer", fixture.payer, "TOKEN_READY", "1".repeat(64));
  append("payee", fixture.payee, "TOKEN_READY", "2".repeat(64));
  append("operator", fixture.operator, "PREFLIGHT_PLAN_READY", "3".repeat(64));
  append("payer", fixture.payer, "PREFLIGHT_PARTICIPANT_READY", "4".repeat(64));
  append("payee", fixture.payee, "PREFLIGHT_PARTICIPANT_READY", "5".repeat(64));
  append("operator", fixture.operator, "REGISTER_REHEARSAL", "6".repeat(64), "rehearsal");
  append("payer", fixture.payer, "IDENTITY_PACKAGE_READY", "7".repeat(64), "rehearsal");
  append("payee", fixture.payee, "IDENTITY_PACKAGE_READY", "8".repeat(64), "rehearsal");
  append("payer", fixture.payer, "PAYER_MANDATE_READY", "9".repeat(64), "rehearsal");
  append("payee", fixture.payee, "PAYMENT_REQUEST_READY", "a".repeat(64), "rehearsal");
  append("payer", fixture.payer, "PAYMENT_REQUEST_MATCHED", null, "rehearsal");
  const descriptorBytes = Buffer.from("descriptor");
  const descriptor = append("operator", fixture.operator, "REHEARSAL_DESCRIPTOR_READY", sha256(descriptorBytes), "rehearsal");
  const processedEventDigests = events
    .filter((event) => event.role === "operator" && event.eventDigest !== descriptor.eventDigest)
    .map((event) => event.eventDigest);
  let appended = null;
  let persisted = null;
  let writtenPath = null;
  const result = await runSupervisor({
    client: {
      async appendEvent(value) { appended = value; },
      async getArtifact(value) {
        assert.deepEqual(value, { artifactType: "signed-descriptor", digest: descriptor.artifactDigest });
        return descriptorBytes;
      },
      async readEnrollmentSet() { return parseCoordinationEnrollmentSet(fixture.set); },
      async readEvents() { return structuredClone(events); },
    },
    dependencies: {
      async readState() { return persisted; },
      shouldContinue() { return false; },
      async verifyDescriptor(bytes) { assert.deepEqual(bytes, descriptorBytes); },
      verifyEnrollmentSet: independentlyVerifiedEnrollmentSet,
      async writeArtifactFile({ path }) { writtenPath = path; },
      async writeState(value) { persisted = value; },
    },
    localState: {
      operatorPublicKey: raw(fixture.operator),
      processedEventDigests,
      rehearsal: { descriptorPath: "/state/rehearsal/descriptor.json" },
      releaseId: fixture.release,
      repositorySha: fixture.repo,
      role: "payer",
      sessionId: fixture.session,
    },
  });
  assert.deepEqual(appended, {
    artifactDigest: descriptor.artifactDigest,
    kind: "DESCRIPTOR_ACCEPTED",
    subjectRun: "rehearsal",
  });
  assert.equal(writtenPath, "/state/rehearsal/descriptor.json");
  assert.ok(result.processedEventDigests.includes(descriptor.eventDigest));
});

test("the payer supervisor waits for authenticated payee readiness instead of failing the session", async () => {
  const fixture = replayFixture();
  const { append, descriptor, events } = replayThroughDescriptor(fixture);
  append("payer", fixture.payer, "DESCRIPTOR_ACCEPTED", descriptor.artifactDigest, "rehearsal");
  append("payee", fixture.payee, "DESCRIPTOR_ACCEPTED", descriptor.artifactDigest, "rehearsal");
  const start = append("operator", fixture.operator, "START_REHEARSAL", null, "rehearsal");
  const processedEventDigests = events
    .filter((event) => event.role === "operator" && event.eventDigest !== start.eventDigest)
    .map((event) => event.eventDigest);
  const result = await runSupervisor({
    client: {
      async readEnrollmentSet() { return parseCoordinationEnrollmentSet(fixture.set); },
      async readEvents() { return structuredClone(events); },
    },
    dependencies: {
      shouldContinue() { return false; },
      verifyEnrollmentSet: independentlyVerifiedEnrollmentSet,
      async writeState() {},
    },
    localState: {
      coordinationIdentity: { privateKeyPem: "private", publicKey: "public" },
      operatorPublicKey: raw(fixture.operator),
      processedEventDigests,
      rehearsal: {
        descriptorPath: "/state/rehearsal/descriptor.json",
        invitationPath: "/state/rehearsal/invitation.json",
        resultDirectory: "/state/rehearsal/result",
      },
      releaseId: fixture.release,
      repositorySha: fixture.repo,
      role: "payer",
      sessionId: fixture.session,
      tokenCommitment: {
        paymentMoved: false,
        repositorySha: fixture.repo,
        role: "payer",
        tokenSha256: "1".repeat(64),
      },
      tokenPath: "/state/token",
    },
  });
  assert.equal(result.processedEventDigests.includes(start.eventDigest), false);
});

test("payer publishes one signed mandate from identity-bound parties before descriptor or role start", async () => {
  const fixture = replayFixture({
    payerInvitationAddress: payerIntentAccount.address.toLowerCase(),
    payeeInvitationAddress: payeeIntentAccount.address.toLowerCase(),
  });
  const { artifacts, events, payerIdentity, payeeIdentity } = replayThroughIdentities(fixture);
  const processedEventDigests = events
    .filter((event) => event.role === "operator")
    .map((event) => event.eventDigest);
  const writes = [];
  const publications = [];
  const stored = [];
  let launches = 0;
  await runSupervisor({
    client: {
      async getArtifact({ digest, artifactType }) {
        assert.equal(artifactType, "identity-package");
        return artifacts.get(digest);
      },
      async publishPayerMandate(value) {
        publications.push(value);
        return { artifactType: "payer-mandate", byteLength: String(value.bytes.length), digest: sha256(value.bytes) };
      },
      async readEnrollmentSet() { return parseCoordinationEnrollmentSet(fixture.set); },
      async readEvents() { return structuredClone(events); },
    },
    dependencies: {
      async launcher() { launches += 1; return { ambiguous: false, exitCode: 0 }; },
      nowMs() { return 1785294300000; },
      async signPayerMandate({ mandate }) {
        return signPayerMandate({
          mandate,
          signMessage: (bytes) => payerIntentAccount.signMessage({ message: { raw: bytes } }),
        });
      },
      shouldContinue() { return false; },
      async validateRelayArtifactWithFacts({ artifactType, bytes, expectedDigest }) {
        assert.equal(artifactType, "identity-package");
        assert.equal(sha256(bytes), expectedDigest);
        return { facts: { identity: JSON.parse(bytes.toString("utf8")) } };
      },
      verifyEnrollmentSet: independentlyVerifiedEnrollmentSet,
      async writeArtifactFile({ bytes, path }) {
        assert.equal(path, "/state/rehearsal/payer-mandate.json");
        stored.push(bytes);
      },
      async writeState(value) { writes.push(value); },
    },
    localState: {
      operatorPublicKey: raw(fixture.operator),
      processedEventDigests,
      rehearsal: {
        descriptorPath: "/state/rehearsal/descriptor.json",
        identityDirectory: "/state/rehearsal/identity",
        invitationPath: "/secret/rehearsal",
        mandatePath: "/state/rehearsal/payer-mandate.json",
        resultDirectory: "/state/rehearsal/result",
      },
      releaseId: fixture.release,
      repositorySha: fixture.repo,
      role: "payer",
      sessionId: fixture.session,
    },
  });
  assert.equal(launches, 0);
  assert.equal(stored.length, 1);
  assert.equal(publications.length, 1);
  assert.deepEqual(publications[0].bytes, stored[0]);
  const envelope = JSON.parse(publications[0].bytes.toString("utf8"));
  const payer = JSON.parse(payerIdentity.toString("utf8"));
  const payee = JSON.parse(payeeIdentity.toString("utf8"));
  assert.equal(envelope.mandate.payer.address, payer.address);
  assert.equal(envelope.mandate.payer.agentId, payer.agentId);
  assert.equal(envelope.mandate.payee.address, payee.address);
  assert.equal(envelope.mandate.payee.agentId, payee.agentId);
  assert.equal(envelope.mandate.paymentMoved, false);
  assert.equal(writes.at(-1).intentJournal.mandateDigest, payerMandateDigest(envelope));
  assert.equal(writes.at(-1).intentJournal.mandateRawDigest, sha256(publications[0].bytes));
});

test("payee verifies Iris mandate and submits one Billie-signed payment request", async () => {
  const fixture = replayFixture({
    payerInvitationAddress: payerIntentAccount.address.toLowerCase(),
    payeeInvitationAddress: payeeIntentAccount.address.toLowerCase(),
  });
  const { append, artifacts, events, payerIdentity, payeeIdentity } = replayThroughIdentities(fixture);
  const payer = JSON.parse(payerIdentity.toString("utf8"));
  const payee = JSON.parse(payeeIdentity.toString("utf8"));
  const mandateEnvelope = await signPayerMandate({
    mandate: {
      amount: { currency: "USD", value: "100" },
      expiresAtMs: "1785297900000",
      invoiceReferencePrefix: "invoice-",
      issuedAtMs: "1785294299999",
      payee: { address: payee.address, agentId: payee.agentId },
      payer: { address: payer.address, agentId: payer.agentId },
      paymentMoved: false,
      protocol: "clockchain.bilateral-authorization/v1",
      purpose: "Handshake demo",
      releaseId: fixture.release,
      repositorySha: fixture.repo,
      requestEndpoint: `/v1/sessions/${fixture.session}/payment-requests`,
      schema: "clockchain.bilateral-payer-mandate/v1",
      sessionId: fixture.session,
      subjectRun: "rehearsal",
    },
    signMessage: (bytes) => payerIntentAccount.signMessage({ message: { raw: bytes } }),
  });
  const mandateBytes = canonicalBytes(mandateEnvelope);
  append("payer", fixture.payer, "PAYER_MANDATE_READY", sha256(mandateBytes), "rehearsal");
  const writes = [];
  const submitted = [];
  const stored = [];
  await runSupervisor({
    client: {
      async getArtifact({ digest, artifactType }) {
        assert.equal(artifactType, "identity-package");
        return artifacts.get(digest);
      },
      async readEnrollmentSet() { return parseCoordinationEnrollmentSet(fixture.set); },
      async readEvents() { return structuredClone(events); },
      async readPayerMandate(value) {
        assert.deepEqual(value, {
          payer: { address: payer.address, agentId: payer.agentId },
          payee: { address: payee.address, agentId: payee.agentId },
          subjectRun: "rehearsal",
        });
        return mandateBytes;
      },
      async submitPaymentRequest(value) {
        submitted.push(value);
        const envelope = JSON.parse(value.bytes.toString("utf8"));
        return { paymentMoved: false, paymentRequestDigest: paymentRequestDigest(envelope), rawEnvelopeDigest: sha256(value.bytes), requestId: envelope.request.requestId, sessionId: fixture.session, subjectRun: "rehearsal" };
      },
    },
    dependencies: {
      nowMs() { return 1785294300000; },
      requestId() { return "9f953393-86d0-4f99-9d6a-102f525fbecd"; },
      async signPaymentRequest({ request }) {
        return signPaymentRequest({
          request,
          signMessage: (bytes) => payeeIntentAccount.signMessage({ message: { raw: bytes } }),
        });
      },
      shouldContinue() { return false; },
      async validateRelayArtifactWithFacts({ artifactType, bytes, expectedDigest }) {
        assert.equal(artifactType, "identity-package");
        assert.equal(sha256(bytes), expectedDigest);
        return { facts: { identity: JSON.parse(bytes.toString("utf8")) } };
      },
      verifyEnrollmentSet: independentlyVerifiedEnrollmentSet,
      async writeArtifactFile({ bytes, path }) {
        assert.equal(path, "/state/rehearsal/payment-request.json");
        stored.push(bytes);
      },
      async writeState(value) { writes.push(value); },
    },
    localState: {
      operatorPublicKey: raw(fixture.operator),
      processedEventDigests: events.filter((event) => event.role === "operator").map((event) => event.eventDigest),
      rehearsal: {
        descriptorPath: "/state/rehearsal/descriptor.json",
        identityDirectory: "/state/rehearsal/identity",
        invitationPath: "/secret/rehearsal",
        requestPath: "/state/rehearsal/payment-request.json",
        resultDirectory: "/state/rehearsal/result",
      },
      releaseId: fixture.release,
      repositorySha: fixture.repo,
      role: "payee",
      sessionId: fixture.session,
    },
  });
  assert.equal(stored.length, 1);
  assert.equal(submitted.length, 1);
  assert.deepEqual(submitted[0].bytes, stored[0]);
  const envelope = JSON.parse(submitted[0].bytes.toString("utf8"));
  assert.equal(envelope.request.mandateDigest, payerMandateDigest(mandateEnvelope));
  assert.equal(envelope.request.paymentMoved, false);
  assert.equal(writes.at(-1).intentJournal.mandateRawDigest, sha256(mandateBytes));
  assert.equal(writes.at(-1).intentJournal.requestDigest, paymentRequestDigest(envelope));
  assert.equal(writes.at(-1).intentJournal.requestRawDigest, sha256(submitted[0].bytes));
});

test("payer verifies the exact Billie request before appending PAYMENT_REQUEST_MATCHED", async () => {
  const fixture = replayFixture({
    payerInvitationAddress: payerIntentAccount.address.toLowerCase(),
    payeeInvitationAddress: payeeIntentAccount.address.toLowerCase(),
  });
  const { append, artifacts, events, payerIdentity, payeeIdentity } = replayThroughIdentities(fixture);
  const payer = JSON.parse(payerIdentity.toString("utf8"));
  const payee = JSON.parse(payeeIdentity.toString("utf8"));
  const mandateEnvelope = await signPayerMandate({
    mandate: {
      amount: { currency: "USD", value: "100" },
      expiresAtMs: "1785297900000",
      invoiceReferencePrefix: "invoice-",
      issuedAtMs: "1785294299999",
      payee: { address: payee.address, agentId: payee.agentId },
      payer: { address: payer.address, agentId: payer.agentId },
      paymentMoved: false,
      protocol: "clockchain.bilateral-authorization/v1",
      purpose: "Handshake demo",
      releaseId: fixture.release,
      repositorySha: fixture.repo,
      requestEndpoint: `/v1/sessions/${fixture.session}/payment-requests`,
      schema: "clockchain.bilateral-payer-mandate/v1",
      sessionId: fixture.session,
      subjectRun: "rehearsal",
    },
    signMessage: (bytes) => payerIntentAccount.signMessage({ message: { raw: bytes } }),
  });
  const requestEnvelope = await signPaymentRequest({
    request: {
      amount: { currency: "USD", value: "100" },
      createdAtMs: "1785294300000",
      expiresAtMs: "1785297600000",
      invoiceReference: "invoice-001",
      mandateDigest: payerMandateDigest(mandateEnvelope),
      payee: { address: payee.address, agentId: payee.agentId },
      payer: { address: payer.address, agentId: payer.agentId },
      paymentMoved: false,
      protocol: "clockchain.bilateral-authorization/v1",
      purpose: "Handshake demo",
      releaseId: fixture.release,
      repositorySha: fixture.repo,
      requestId: "9f953393-86d0-4f99-9d6a-102f525fbecd",
      schema: "clockchain.bilateral-payment-request/v1",
      sessionId: fixture.session,
      subjectRun: "rehearsal",
    },
    signMessage: (bytes) => payeeIntentAccount.signMessage({ message: { raw: bytes } }),
  });
  const mandateBytes = canonicalBytes(mandateEnvelope);
  const requestBytes = canonicalBytes(requestEnvelope);
  append("payer", fixture.payer, "PAYER_MANDATE_READY", sha256(mandateBytes), "rehearsal");
  append("payee", fixture.payee, "PAYMENT_REQUEST_READY", sha256(requestBytes), "rehearsal");
  const appended = [];
  const writes = [];
  await runSupervisor({
    client: {
      async appendEvent(value) { appended.push(value); },
      async getArtifact({ digest, artifactType }) {
        if (artifactType === "payment-request") {
          assert.equal(digest, sha256(requestBytes));
          return requestBytes;
        }
        assert.equal(artifactType, "identity-package");
        return artifacts.get(digest);
      },
      async readEnrollmentSet() { return parseCoordinationEnrollmentSet(fixture.set); },
      async readEvents() { return structuredClone(events); },
      async readPayerMandate() { return mandateBytes; },
      async readPaymentRequest(value) {
        assert.equal(value.requestId, "9f953393-86d0-4f99-9d6a-102f525fbecd");
        return requestBytes;
      },
    },
    dependencies: {
      nowMs() { return 1785294300000; },
      shouldContinue() { return false; },
      async validateRelayArtifactWithFacts({ artifactType, bytes, expectedDigest }) {
        assert.equal(artifactType, "identity-package");
        assert.equal(sha256(bytes), expectedDigest);
        return { facts: { identity: JSON.parse(bytes.toString("utf8")) } };
      },
      verifyEnrollmentSet: independentlyVerifiedEnrollmentSet,
      async writeState(value) { writes.push(value); },
    },
    localState: {
      operatorPublicKey: raw(fixture.operator),
      processedEventDigests: events.filter((event) => event.role === "operator").map((event) => event.eventDigest),
      rehearsal: {
        descriptorPath: "/state/rehearsal/descriptor.json",
        identityDirectory: "/state/rehearsal/identity",
        invitationPath: "/secret/rehearsal",
        mandatePath: "/state/rehearsal/payer-mandate.json",
        requestId: "9f953393-86d0-4f99-9d6a-102f525fbecd",
        resultDirectory: "/state/rehearsal/result",
      },
      releaseId: fixture.release,
      repositorySha: fixture.repo,
      role: "payer",
      sessionId: fixture.session,
    },
  });
  assert.deepEqual(appended, [{ artifactDigest: null, kind: "PAYMENT_REQUEST_MATCHED", subjectRun: "rehearsal" }]);
  assert.equal(writes.at(-1).intentJournal.mandateRawDigest, sha256(mandateBytes));
  assert.equal(writes.at(-1).intentJournal.requestRawDigest, sha256(requestBytes));
});

test("payer discovers Billie's unpredictable requestId from the authenticated payment-request artifact", async () => {
  const fixture = replayFixture({
    payerInvitationAddress: payerIntentAccount.address.toLowerCase(),
    payeeInvitationAddress: payeeIntentAccount.address.toLowerCase(),
  });
  const { append, artifacts, events, payerIdentity, payeeIdentity } = replayThroughIdentities(fixture);
  const payer = JSON.parse(payerIdentity.toString("utf8"));
  const payee = JSON.parse(payeeIdentity.toString("utf8"));
  const requestId = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
  const mandateEnvelope = await signPayerMandate({
    mandate: {
      amount: { currency: "USD", value: "100" },
      expiresAtMs: "1785297900000",
      invoiceReferencePrefix: "invoice-",
      issuedAtMs: "1785294299999",
      payee: { address: payee.address, agentId: payee.agentId },
      payer: { address: payer.address, agentId: payer.agentId },
      paymentMoved: false,
      protocol: "clockchain.bilateral-authorization/v1",
      purpose: "Handshake demo",
      releaseId: fixture.release,
      repositorySha: fixture.repo,
      requestEndpoint: `/v1/sessions/${fixture.session}/payment-requests`,
      schema: "clockchain.bilateral-payer-mandate/v1",
      sessionId: fixture.session,
      subjectRun: "rehearsal",
    },
    signMessage: (bytes) => payerIntentAccount.signMessage({ message: { raw: bytes } }),
  });
  const requestEnvelope = await signPaymentRequest({
    request: {
      amount: { currency: "USD", value: "100" },
      createdAtMs: "1785294300000",
      expiresAtMs: "1785297600000",
      invoiceReference: "invoice-001",
      mandateDigest: payerMandateDigest(mandateEnvelope),
      payee: { address: payee.address, agentId: payee.agentId },
      payer: { address: payer.address, agentId: payer.agentId },
      paymentMoved: false,
      protocol: "clockchain.bilateral-authorization/v1",
      purpose: "Handshake demo",
      releaseId: fixture.release,
      repositorySha: fixture.repo,
      requestId,
      schema: "clockchain.bilateral-payment-request/v1",
      sessionId: fixture.session,
      subjectRun: "rehearsal",
    },
    signMessage: (bytes) => payeeIntentAccount.signMessage({ message: { raw: bytes } }),
  });
  const mandateBytes = canonicalBytes(mandateEnvelope);
  const requestBytes = canonicalBytes(requestEnvelope);
  append("payer", fixture.payer, "PAYER_MANDATE_READY", sha256(mandateBytes), "rehearsal");
  append("payee", fixture.payee, "PAYMENT_REQUEST_READY", sha256(requestBytes), "rehearsal");
  const appended = [];
  const routeReads = [];
  await runSupervisor({
    client: {
      async appendEvent(value) { appended.push(value); },
      async getArtifact({ digest, artifactType }) {
        if (artifactType === "identity-package") return artifacts.get(digest);
        assert.equal(artifactType, "payment-request");
        assert.equal(digest, sha256(requestBytes));
        return requestBytes;
      },
      async readEnrollmentSet() { return parseCoordinationEnrollmentSet(fixture.set); },
      async readEvents() { return structuredClone(events); },
      async readPayerMandate() { return mandateBytes; },
      async readPaymentRequest(value) {
        routeReads.push(value);
        assert.equal(value.requestId, requestId);
        return requestBytes;
      },
    },
    dependencies: {
      nowMs() { return 1785294300000; },
      shouldContinue() { return false; },
      async validateRelayArtifactWithFacts({ artifactType, bytes, expectedDigest }) {
        assert.equal(sha256(bytes), expectedDigest);
        return { facts: { identity: JSON.parse(bytes.toString("utf8")) }, artifactType };
      },
      verifyEnrollmentSet: independentlyVerifiedEnrollmentSet,
      async writeState() {},
    },
    localState: {
      operatorPublicKey: raw(fixture.operator),
      processedEventDigests: events.filter((event) => event.role === "operator").map((event) => event.eventDigest),
      rehearsal: {
        descriptorPath: "/state/rehearsal/descriptor.json",
        invitationPath: "/secret/rehearsal",
        mandatePath: "/state/rehearsal/payer-mandate.json",
        resultDirectory: "/state/rehearsal/result",
      },
      releaseId: fixture.release,
      repositorySha: fixture.repo,
      role: "payer",
      sessionId: fixture.session,
    },
  });
  assert.deepEqual(routeReads.map((value) => value.requestId), [requestId]);
  assert.deepEqual(appended, [{ artifactDigest: null, kind: "PAYMENT_REQUEST_MATCHED", subjectRun: "rehearsal" }]);
});

test("payer rejects payment-request route bytes that differ from the authenticated ready artifact", async () => {
  const fixture = replayFixture({
    payerInvitationAddress: payerIntentAccount.address.toLowerCase(),
    payeeInvitationAddress: payeeIntentAccount.address.toLowerCase(),
  });
  const { append, artifacts, events, payerIdentity, payeeIdentity } = replayThroughIdentities(fixture);
  const payer = JSON.parse(payerIdentity.toString("utf8"));
  const payee = JSON.parse(payeeIdentity.toString("utf8"));
  const mandateEnvelope = await signPayerMandate({
    mandate: {
      amount: { currency: "USD", value: "100" },
      expiresAtMs: "1785297900000",
      invoiceReferencePrefix: "invoice-",
      issuedAtMs: "1785294299999",
      payee: { address: payee.address, agentId: payee.agentId },
      payer: { address: payer.address, agentId: payer.agentId },
      paymentMoved: false,
      protocol: "clockchain.bilateral-authorization/v1",
      purpose: "Handshake demo",
      releaseId: fixture.release,
      repositorySha: fixture.repo,
      requestEndpoint: `/v1/sessions/${fixture.session}/payment-requests`,
      schema: "clockchain.bilateral-payer-mandate/v1",
      sessionId: fixture.session,
      subjectRun: "rehearsal",
    },
    signMessage: (bytes) => payerIntentAccount.signMessage({ message: { raw: bytes } }),
  });
  const request = {
    amount: { currency: "USD", value: "100" },
    createdAtMs: "1785294300000",
    expiresAtMs: "1785297600000",
    invoiceReference: "invoice-001",
    mandateDigest: payerMandateDigest(mandateEnvelope),
    payee: { address: payee.address, agentId: payee.agentId },
    payer: { address: payer.address, agentId: payer.agentId },
    paymentMoved: false,
    protocol: "clockchain.bilateral-authorization/v1",
    purpose: "Handshake demo",
    releaseId: fixture.release,
    repositorySha: fixture.repo,
    requestId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    schema: "clockchain.bilateral-payment-request/v1",
    sessionId: fixture.session,
    subjectRun: "rehearsal",
  };
  const requestEnvelope = await signPaymentRequest({
    request,
    signMessage: (bytes) => payeeIntentAccount.signMessage({ message: { raw: bytes } }),
  });
  const changedEnvelope = await signPaymentRequest({
    request: { ...request, requestId: "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff" },
    signMessage: (bytes) => payeeIntentAccount.signMessage({ message: { raw: bytes } }),
  });
  const mandateBytes = canonicalBytes(mandateEnvelope);
  const requestBytes = canonicalBytes(requestEnvelope);
  const changedBytes = canonicalBytes(changedEnvelope);
  append("payer", fixture.payer, "PAYER_MANDATE_READY", sha256(mandateBytes), "rehearsal");
  append("payee", fixture.payee, "PAYMENT_REQUEST_READY", sha256(requestBytes), "rehearsal");
  let appended = 0;
  await assert.rejects(runSupervisor({
    client: {
      async appendEvent() { appended += 1; },
      async getArtifact({ digest, artifactType }) {
        if (artifactType === "identity-package") return artifacts.get(digest);
        assert.equal(artifactType, "payment-request");
        assert.equal(digest, sha256(requestBytes));
        return requestBytes;
      },
      async readEnrollmentSet() { return parseCoordinationEnrollmentSet(fixture.set); },
      async readEvents() { return structuredClone(events); },
      async readPayerMandate() { return mandateBytes; },
      async readPaymentRequest(value) {
        assert.equal(value.requestId, request.requestId);
        return changedBytes;
      },
    },
    dependencies: {
      nowMs() { return 1785294300000; },
      shouldContinue() { return false; },
      async validateRelayArtifactWithFacts({ artifactType, bytes, expectedDigest }) {
        assert.equal(sha256(bytes), expectedDigest);
        return { facts: { identity: JSON.parse(bytes.toString("utf8")) }, artifactType };
      },
      verifyEnrollmentSet: independentlyVerifiedEnrollmentSet,
      async writeState() {},
    },
    localState: {
      operatorPublicKey: raw(fixture.operator),
      processedEventDigests: events.filter((event) => event.role === "operator").map((event) => event.eventDigest),
      rehearsal: {
        descriptorPath: "/state/rehearsal/descriptor.json",
        invitationPath: "/secret/rehearsal",
        mandatePath: "/state/rehearsal/payer-mandate.json",
        resultDirectory: "/state/rehearsal/result",
      },
      releaseId: fixture.release,
      repositorySha: fixture.repo,
      role: "payer",
      sessionId: fixture.session,
    },
  }));
  assert.equal(appended, 0);
});

test("retries payer mandate publication from durable bytes without re-signing", async () => {
  const fixture = replayFixture({
    payerInvitationAddress: payerIntentAccount.address.toLowerCase(),
    payeeInvitationAddress: payeeIntentAccount.address.toLowerCase(),
  });
  const { artifacts, events, payerIdentity, payeeIdentity } = replayThroughIdentities(fixture);
  const payer = JSON.parse(payerIdentity.toString("utf8"));
  const payee = JSON.parse(payeeIdentity.toString("utf8"));
  const mandateEnvelope = await signPayerMandate({
    mandate: {
      amount: { currency: "USD", value: "100" },
      expiresAtMs: "1785297900000",
      invoiceReferencePrefix: "invoice-",
      issuedAtMs: "1785294299999",
      payee: { address: payee.address, agentId: payee.agentId },
      payer: { address: payer.address, agentId: payer.agentId },
      paymentMoved: false,
      protocol: "clockchain.bilateral-authorization/v1",
      purpose: "Handshake demo",
      releaseId: fixture.release,
      repositorySha: fixture.repo,
      requestEndpoint: `/v1/sessions/${fixture.session}/payment-requests`,
      schema: "clockchain.bilateral-payer-mandate/v1",
      sessionId: fixture.session,
      subjectRun: "rehearsal",
    },
    signMessage: (bytes) => payerIntentAccount.signMessage({ message: { raw: bytes } }),
  });
  const mandateBytes = canonicalBytes(mandateEnvelope);
  const published = [];
  await runSupervisor({
    client: {
      async getArtifact({ digest }) { return artifacts.get(digest); },
      async publishPayerMandate(value) {
        published.push(value);
        return { artifactType: "payer-mandate", byteLength: String(value.bytes.length), digest: sha256(value.bytes) };
      },
      async readEnrollmentSet() { return parseCoordinationEnrollmentSet(fixture.set); },
      async readEvents() { return structuredClone(events); },
    },
    dependencies: {
      async readArtifactFile({ path }) {
        assert.equal(path, "/state/rehearsal/payer-mandate.json");
        return mandateBytes;
      },
      async signPayerMandate() { assert.fail("restart retry must not re-sign mandate bytes"); },
      shouldContinue() { return false; },
      async validateRelayArtifactWithFacts({ bytes }) { return { facts: { identity: JSON.parse(bytes.toString("utf8")) } }; },
      verifyEnrollmentSet: independentlyVerifiedEnrollmentSet,
      async writeState() {},
    },
    localState: {
      intentJournal: {
        mandateDigest: payerMandateDigest(mandateEnvelope),
        mandateRawDigest: sha256(mandateBytes),
        stage: "PAYER_MANDATE_READY_TO_PUBLISH",
        subjectRun: "rehearsal",
      },
      operatorPublicKey: raw(fixture.operator),
      processedEventDigests: events.filter((event) => event.role === "operator").map((event) => event.eventDigest),
      rehearsal: {
        descriptorPath: "/state/rehearsal/descriptor.json",
        invitationPath: "/secret/rehearsal",
        mandatePath: "/state/rehearsal/payer-mandate.json",
        resultDirectory: "/state/rehearsal/result",
      },
      releaseId: fixture.release,
      repositorySha: fixture.repo,
      role: "payer",
      sessionId: fixture.session,
    },
  });
  assert.deepEqual(published, [{ bytes: mandateBytes, subjectRun: "rehearsal" }]);
});

test("fails closed when durable mandate retry bytes differ from the journal", async () => {
  const fixture = replayFixture({
    payerInvitationAddress: payerIntentAccount.address.toLowerCase(),
    payeeInvitationAddress: payeeIntentAccount.address.toLowerCase(),
  });
  const { events } = replayThroughIdentities(fixture);
  const original = Buffer.from("{}");
  let published = 0;
  await assert.rejects(runSupervisor({
    client: {
      async publishPayerMandate() { published += 1; },
      async readEnrollmentSet() { return parseCoordinationEnrollmentSet(fixture.set); },
      async readEvents() { return structuredClone(events); },
    },
    dependencies: {
      async readArtifactFile() { return Buffer.from("{\"changed\":true}"); },
      async signPayerMandate() { assert.fail("changed retry bytes must not re-sign"); },
      shouldContinue() { return false; },
      verifyEnrollmentSet: independentlyVerifiedEnrollmentSet,
      async writeState() {},
    },
    localState: {
      intentJournal: {
        mandateDigest: "b".repeat(64),
        mandateRawDigest: sha256(original),
        stage: "PAYER_MANDATE_READY_TO_PUBLISH",
        subjectRun: "rehearsal",
      },
      operatorPublicKey: raw(fixture.operator),
      processedEventDigests: events.filter((event) => event.role === "operator").map((event) => event.eventDigest),
      rehearsal: { descriptorPath: "/state/rehearsal/descriptor.json", mandatePath: "/state/rehearsal/payer-mandate.json" },
      releaseId: fixture.release,
      repositorySha: fixture.repo,
      role: "payer",
      sessionId: fixture.session,
    },
  }));
  assert.equal(published, 0);
});

test("retries payment-request submission from durable bytes without re-signing or changing requestId", async () => {
  const fixture = replayFixture({
    payerInvitationAddress: payerIntentAccount.address.toLowerCase(),
    payeeInvitationAddress: payeeIntentAccount.address.toLowerCase(),
  });
  const { append, events, payerIdentity, payeeIdentity } = replayThroughIdentities(fixture);
  const payer = JSON.parse(payerIdentity.toString("utf8"));
  const payee = JSON.parse(payeeIdentity.toString("utf8"));
  const mandateEnvelope = await signPayerMandate({
    mandate: {
      amount: { currency: "USD", value: "100" },
      expiresAtMs: "1785297900000",
      invoiceReferencePrefix: "invoice-",
      issuedAtMs: "1785294299999",
      payee: { address: payee.address, agentId: payee.agentId },
      payer: { address: payer.address, agentId: payer.agentId },
      paymentMoved: false,
      protocol: "clockchain.bilateral-authorization/v1",
      purpose: "Handshake demo",
      releaseId: fixture.release,
      repositorySha: fixture.repo,
      requestEndpoint: `/v1/sessions/${fixture.session}/payment-requests`,
      schema: "clockchain.bilateral-payer-mandate/v1",
      sessionId: fixture.session,
      subjectRun: "rehearsal",
    },
    signMessage: (bytes) => payerIntentAccount.signMessage({ message: { raw: bytes } }),
  });
  const mandateBytes = canonicalBytes(mandateEnvelope);
  const requestEnvelope = await signPaymentRequest({
    request: {
      amount: { currency: "USD", value: "100" },
      createdAtMs: "1785294300000",
      expiresAtMs: "1785297600000",
      invoiceReference: "invoice-001",
      mandateDigest: payerMandateDigest(mandateEnvelope),
      payee: { address: payee.address, agentId: payee.agentId },
      payer: { address: payer.address, agentId: payer.agentId },
      paymentMoved: false,
      protocol: "clockchain.bilateral-authorization/v1",
      purpose: "Handshake demo",
      releaseId: fixture.release,
      repositorySha: fixture.repo,
      requestId: "9f953393-86d0-4f99-9d6a-102f525fbecd",
      schema: "clockchain.bilateral-payment-request/v1",
      sessionId: fixture.session,
      subjectRun: "rehearsal",
    },
    signMessage: (bytes) => payeeIntentAccount.signMessage({ message: { raw: bytes } }),
  });
  const requestBytes = canonicalBytes(requestEnvelope);
  append("payer", fixture.payer, "PAYER_MANDATE_READY", sha256(mandateBytes), "rehearsal");
  const submitted = [];
  await runSupervisor({
    client: {
      async readEnrollmentSet() { return parseCoordinationEnrollmentSet(fixture.set); },
      async readEvents() { return structuredClone(events); },
      async submitPaymentRequest(value) {
        submitted.push(value);
        return { paymentMoved: false, paymentRequestDigest: paymentRequestDigest(requestEnvelope), rawEnvelopeDigest: sha256(value.bytes), requestId: "9f953393-86d0-4f99-9d6a-102f525fbecd", sessionId: fixture.session, subjectRun: "rehearsal" };
      },
    },
    dependencies: {
      async readArtifactFile({ path }) {
        assert.equal(path, "/state/rehearsal/payment-request.json");
        return requestBytes;
      },
      async signPaymentRequest() { assert.fail("restart retry must not re-sign request bytes"); },
      shouldContinue() { return false; },
      verifyEnrollmentSet: independentlyVerifiedEnrollmentSet,
      async writeState() {},
    },
    localState: {
      intentJournal: {
        mandateDigest: payerMandateDigest(mandateEnvelope),
        mandateRawDigest: sha256(mandateBytes),
        requestDigest: paymentRequestDigest(requestEnvelope),
        requestId: "9f953393-86d0-4f99-9d6a-102f525fbecd",
        requestRawDigest: sha256(requestBytes),
        stage: "PAYMENT_REQUEST_READY_TO_SUBMIT",
        subjectRun: "rehearsal",
      },
      operatorPublicKey: raw(fixture.operator),
      processedEventDigests: events.filter((event) => event.role === "operator").map((event) => event.eventDigest),
      rehearsal: { descriptorPath: "/state/rehearsal/descriptor.json", requestPath: "/state/rehearsal/payment-request.json" },
      releaseId: fixture.release,
      repositorySha: fixture.repo,
      role: "payee",
      sessionId: fixture.session,
    },
  });
  assert.deepEqual(submitted, [{ bytes: requestBytes }]);
});

test("fails closed when durable payment-request retry bytes differ from the journal", async () => {
  const fixture = replayFixture({
    payerInvitationAddress: payerIntentAccount.address.toLowerCase(),
    payeeInvitationAddress: payeeIntentAccount.address.toLowerCase(),
  });
  const { events } = replayThroughIdentities(fixture);
  let submitted = 0;
  await assert.rejects(runSupervisor({
    client: {
      async readEnrollmentSet() { return parseCoordinationEnrollmentSet(fixture.set); },
      async readEvents() { return structuredClone(events); },
      async submitPaymentRequest() { submitted += 1; },
    },
    dependencies: {
      async readArtifactFile() { return Buffer.from("{\"changed\":true}"); },
      async signPaymentRequest() { assert.fail("changed retry bytes must not re-sign"); },
      shouldContinue() { return false; },
      verifyEnrollmentSet: independentlyVerifiedEnrollmentSet,
      async writeState() {},
    },
    localState: {
      intentJournal: {
        mandateDigest: "b".repeat(64),
        mandateRawDigest: "c".repeat(64),
        requestDigest: "d".repeat(64),
        requestId: "9f953393-86d0-4f99-9d6a-102f525fbecd",
        requestRawDigest: sha256(Buffer.from("{}")),
        stage: "PAYMENT_REQUEST_READY_TO_SUBMIT",
        subjectRun: "rehearsal",
      },
      operatorPublicKey: raw(fixture.operator),
      processedEventDigests: events.filter((event) => event.role === "operator").map((event) => event.eventDigest),
      rehearsal: { descriptorPath: "/state/rehearsal/descriptor.json", requestPath: "/state/rehearsal/payment-request.json" },
      releaseId: fixture.release,
      repositorySha: fixture.repo,
      role: "payee",
      sessionId: fixture.session,
    },
  }));
  assert.equal(submitted, 0);
});

test("does not let payer start before authenticated payee ROLE_STARTED", async () => {
  const event = Object.freeze({ kind: "START_REHEARSAL", repositorySha: "a".repeat(40), role: "operator", subjectRun: "rehearsal" });
  await assert.rejects(executeSupervisorTransition({ client: {}, event, localState: { authenticatedEvents: Object.freeze([event]), repositorySha: event.repositorySha, role: "payer", rehearsal: {} }, dependencies: { async writeState() {} } }));
});

test("recommits the pinned token before a role command", async () => {
  const event = Object.freeze({ eventDigest: "e".repeat(64), kind: "START_REHEARSAL", repositorySha: "a".repeat(40), role: "operator", subjectRun: "rehearsal" });
  const payeeStarted = Object.freeze({ kind: "ROLE_STARTED", role: "payee", subjectRun: "rehearsal" });
  const commitment = Object.freeze({ paymentMoved: false, repositorySha: event.repositorySha, role: "payer", tokenSha256: "1".repeat(64) });
  const writes = [];
  let recommits = 0;
  await executeSupervisorTransition({
    client: { async putArtifact({ artifactType, bytes }) { return { artifactType, byteLength: String(bytes.length), digest: sha256(bytes) }; }, async appendEvent() {} },
    event,
    localState: { authenticatedEvents: Object.freeze([event, payeeStarted]), coordinationIdentity: { privateKeyPem: "private", publicKey: "public" }, rehearsal: { descriptorPath: "/state/descriptor", invitationPath: "/state/invitation", resultDirectory: "/state/result" }, releaseId: "release-a", repositorySha: event.repositorySha, role: "payer", sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd", tokenCommitment: commitment, tokenPath: "/state/token" },
    dependencies: { async readAndSignTokenCommitment() { recommits += 1; return commitment; }, async launcher() { return { ambiguous: false, completion: Promise.resolve({ ambiguous: false, exitCode: 0 }), started: true }; }, async readArtifactPackage() { return Buffer.from("package"); }, async validateRelayArtifact() {}, async writeState(value) { writes.push(value); } },
  });
  assert.equal(recommits, 1);
  assert.equal(writes.at(-1).phase, "TRANSITION_COMPLETE");
});

test("publishes ROLE_STARTED after real launcher readiness and awaits role completion", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "supervisor-transition-"));
  await mkdir(join(root, "bin"));
  await writeFile(join(root, "package.json"), '{"type":"module"}\n');
  const script = join(root, "bin", "handshake-propose.mjs");
  t.after(() => unlink(script).catch(() => {}));
  await writeFile(script, [
    "import { closeSync, writeSync } from 'node:fs';",
    "writeSync(3, `${JSON.stringify({ nonce: process.env.CLOCKCHAIN_BILATERAL_ROLE_READY_NONCE, role: 'payer', schema: process.env.CLOCKCHAIN_BILATERAL_ROLE_READY_SCHEMA })}\\n`);",
    "closeSync(3);",
    "setTimeout(() => process.exit(0), 25);",
  ].join("\n"));
  const event = Object.freeze({ eventDigest: "d".repeat(64), kind: "START_REHEARSAL", repositorySha: "a".repeat(40), role: "operator", subjectRun: "rehearsal" });
  const payeeStarted = Object.freeze({ kind: "ROLE_STARTED", role: "payee", subjectRun: "rehearsal" });
  const commitment = Object.freeze({ paymentMoved: false, repositorySha: event.repositorySha, role: "payer", tokenSha256: "1".repeat(64) });
  const calls = [];
  await executeSupervisorTransition({
    client: {
      async appendEvent(value) { calls.push(value.kind); },
      async putArtifact({ artifactType, bytes, expectedDigest }) { return { artifactType, byteLength: String(bytes.length), digest: expectedDigest }; },
    },
    event,
    localState: { authenticatedEvents: Object.freeze([event, payeeStarted]), coordinationIdentity: { privateKeyPem: "private", publicKey: "public" }, rehearsal: { descriptorPath: "/state/descriptor", invitationPath: "/state/invitation", resultDirectory: "/state/result" }, releaseId: "release-a", repositorySha: event.repositorySha, role: "payer", sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd", tokenCommitment: commitment, tokenPath: "/state/token" },
    dependencies: {
      launcher: createSupervisorLauncher({ repositoryRoot: root }),
      async readAndSignTokenCommitment() { return commitment; },
      async readArtifactPackage() { return Buffer.from("package"); },
      async validateRelayArtifact() {},
      async writeState() {},
    },
  });
  assert.deepEqual(calls, ["ROLE_STARTED", "ROLE_PACKAGE_READY"]);
});

test("resumes a CHILD_COMPLETE role journal without launching a second child", async () => {
  const event = Object.freeze({ eventDigest: "c".repeat(64), kind: "START_REHEARSAL", repositorySha: "a".repeat(40), role: "operator", subjectRun: "rehearsal" });
  const payeeStarted = Object.freeze({ kind: "ROLE_STARTED", role: "payee", subjectRun: "rehearsal" });
  const commitment = Object.freeze({ paymentMoved: false, repositorySha: event.repositorySha, role: "payer", tokenSha256: "1".repeat(64) });
  let launches = 0;
  const writes = [];
  await executeSupervisorTransition({
    client: { async appendEvent() {}, async putArtifact({ artifactType, bytes, expectedDigest }) { return { artifactType, byteLength: String(bytes.length), digest: expectedDigest }; } },
    event,
    localState: { authenticatedEvents: Object.freeze([event, payeeStarted]), childJournal: { command: "bin/handshake-propose.mjs", commandDigest: sha256(canonicalBytes({ args: ["--clockchain-token-file", "/state/token", "--descriptor", "/state/descriptor", "--invitation", "/state/invitation", "--output", "/state/result", "--i-understand-this-writes-to-clockchain"], command: "bin/handshake-propose.mjs", eventDigest: event.eventDigest, repositorySha: event.repositorySha, role: event.role, sessionId: "", subjectRun: "rehearsal" })), eventDigest: event.eventDigest, status: "CHILD_COMPLETE", subjectRun: "rehearsal" }, coordinationIdentity: { privateKeyPem: "private", publicKey: "public" }, rehearsal: { descriptorPath: "/state/descriptor", invitationPath: "/state/invitation", resultDirectory: "/state/result" }, releaseId: "release-a", repositorySha: event.repositorySha, role: "payer", sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd", tokenCommitment: commitment, tokenPath: "/state/token" },
    dependencies: { async launcher() { launches += 1; return { ambiguous: false, completion: Promise.resolve({ ambiguous: false, exitCode: 0 }), started: true }; }, async readAndSignTokenCommitment() { return commitment; }, async readArtifactPackage() { return Buffer.from("package"); }, async validateRelayArtifact() {}, async writeState(value) { writes.push(value); } },
  });
  assert.equal(launches, 0);
  assert.equal(writes.at(-1).childJournal.status, "EVENT_APPENDED");
});

test("records an exact recovery manifest for an ambiguous role command", async () => {
  const event = Object.freeze({ eventDigest: "f".repeat(64), kind: "START_REHEARSAL", repositorySha: "a".repeat(40), role: "operator", subjectRun: "rehearsal" });
  const payeeStarted = Object.freeze({ kind: "ROLE_STARTED", role: "payee", subjectRun: "rehearsal" });
  const commitment = Object.freeze({ paymentMoved: false, repositorySha: event.repositorySha, role: "payer", tokenSha256: "1".repeat(64) });
  const writes = [], appended = [];
  await assert.rejects(executeSupervisorTransition({
    client: { async putArtifact({ artifactType, bytes }) { return { artifactType, byteLength: String(bytes.length), digest: sha256(bytes) }; }, async appendEvent(value) { appended.push(value); } },
    event,
    localState: { authenticatedEvents: Object.freeze([event, payeeStarted]), coordinationIdentity: { privateKeyPem: "private", publicKey: "public" }, rehearsal: { descriptorPath: "/state/descriptor", invitationPath: "/state/invitation", resultDirectory: "/state/result" }, releaseId: "release-a", repositorySha: event.repositorySha, role: "payer", sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd", tokenCommitment: commitment, tokenPath: "/state/token" },
    dependencies: { async readAndSignTokenCommitment() { return commitment; }, async launcher() { return { ambiguous: false, completion: Promise.resolve({ ambiguous: true, exitCode: 1 }), started: true }; }, async readArtifactPackage() { return Buffer.from("unused"); }, async validateRelayArtifact() {}, async writeState(value) { writes.push(value); } },
  }));
  assert.equal(writes.at(-1).phase, "RECOVERY_REQUIRED");
  assert.deepEqual(writes.map((value) => value.phase), ["BEFORE_CHILD", "RECOVERY_REQUIRED", "RECOVERY_REQUIRED", "RECOVERY_REQUIRED"]);
  assert.deepEqual(writes.slice(-3).map((value) => value.recovery.stage), ["MANIFEST_STORED", "EVENT_APPEND_ATTEMPTED", "EVENT_APPENDED"]);
  assert.equal(appended.length, 2);
  assert.equal(appended.filter((value) => value.kind === "RECOVERY_REQUIRED").length, 1);
  assert.equal(appended.at(-1)?.kind, "RECOVERY_REQUIRED");
  assert.match(appended.at(-1)?.artifactDigest ?? "", /^[0-9a-f]{64}$/);
});

test("rejects a substituted exact recovery authorization", async () => {
  const event = Object.freeze({ artifactDigest: "c".repeat(64), eventDigest: "d".repeat(64), kind: "EXACT_RECOVERY_AUTHORIZATION", subjectRun: "rehearsal" });
  const commandEvent = Object.freeze({ eventDigest: "e".repeat(64), kind: "START_REHEARSAL", repositorySha: "a".repeat(40), role: "operator", subjectRun: "rehearsal" });
  await assert.rejects(executeSupervisorTransition({
    client: {}, event,
    localState: { authenticatedEvents: Object.freeze([event]), recovery: { authorizationUsed: false, commandEvent, manifestBytes: Buffer.from("manifest").toString("base64"), manifestDigest: "b".repeat(64), subjectRun: "rehearsal" }, repositorySha: commandEvent.repositorySha, role: "payer" },
    dependencies: { async writeState() {} },
  }));
});

test("rejects recovery authorization when its stored manifest is not the exact command", async () => {
  const commandEvent = Object.freeze({ eventDigest: "e".repeat(64), kind: "REGISTER_REHEARSAL", repositorySha: "a".repeat(40), role: "operator", subjectRun: "rehearsal" });
  const manifestBytes = Buffer.from("not the canonical recovery command");
  const event = Object.freeze({ artifactDigest: sha256(manifestBytes), eventDigest: "d".repeat(64), kind: "EXACT_RECOVERY_AUTHORIZATION", subjectRun: "rehearsal" });
  let launches = 0;
  await assert.rejects(executeSupervisorTransition({
    client: {
      async getArtifact() { return manifestBytes; },
      async putArtifact({ artifactType, bytes, expectedDigest }) { return { artifactType, byteLength: String(bytes.length), digest: expectedDigest }; },
      async appendEvent() {},
    },
    event,
    localState: {
      authenticatedEvents: Object.freeze([commandEvent, event]),
      recovery: { authorizationUsed: false, commandEvent, manifestBytes: manifestBytes.toString("base64"), manifestDigest: event.artifactDigest, subjectRun: "rehearsal" },
      rehearsal: { identityDirectory: "/state/identity", invitationPath: "/state/invitation" },
      releaseId: "release-a", repositorySha: commandEvent.repositorySha, role: "payer", sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd",
    },
    dependencies: {
      async launcher() { launches += 1; return { ambiguous: false, exitCode: 0 }; },
      async readArtifactPackage() { return Buffer.from("identity"); },
      async validateRelayArtifact() {},
      async verifyIdentityPackage() {},
      async writeState() {},
    },
  }));
  assert.equal(launches, 0);
});

test("does not relaunch an ambiguous command before exact recovery authorization", async () => {
  const commandEvent = Object.freeze({ eventDigest: "e".repeat(64), kind: "REGISTER_REHEARSAL", repositorySha: "a".repeat(40), role: "operator", subjectRun: "rehearsal" });
  const command = buildSupervisorCommand({ event: commandEvent, localState: { repositorySha: commandEvent.repositorySha, role: "payer", rehearsal: { identityDirectory: "/state/identity", invitationPath: "/state/invitation" } } });
  const manifestBytes = canonicalBytes({ arguments: command.args, command: command.command, paymentMoved: false, reasonCode: "AMBIGUOUS_WRITE", releaseId: "release-a", repositorySha: commandEvent.repositorySha, role: "payer", schema: "clockchain.bilateral-recovery-command-manifest/v1", sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd", subjectRun: "rehearsal" });
  let launches = 0;
  await assert.rejects(executeSupervisorTransition({
    client: {}, event: commandEvent,
    localState: {
      authenticatedEvents: Object.freeze([commandEvent]),
      recovery: { authorizationUsed: false, commandEvent, manifestBytes: manifestBytes.toString("base64"), manifestDigest: sha256(manifestBytes), stage: "EVENT_APPEND_ATTEMPTED", subjectRun: "rehearsal" },
      rehearsal: { identityDirectory: "/state/identity", invitationPath: "/state/invitation" },
      releaseId: "release-a", repositorySha: commandEvent.repositorySha, role: "payer", sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd",
    },
    dependencies: { async launcher() { launches += 1; return { ambiguous: false, exitCode: 0 }; }, async readArtifactPackage() { return Buffer.from("identity"); }, async validateRelayArtifact() {}, async verifyIdentityPackage() {}, async writeState() {} },
  }));
  assert.equal(launches, 0);
});

test("consumes exact recovery before every durable child checkpoint", async () => {
  const commandEvent = Object.freeze({ eventDigest: "e".repeat(64), kind: "REGISTER_REHEARSAL", repositorySha: "a".repeat(40), role: "operator", subjectRun: "rehearsal" });
  const state = { rehearsal: { identityDirectory: "/state/identity", invitationPath: "/state/invitation" }, releaseId: "release-a", repositorySha: commandEvent.repositorySha, role: "payer", sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd" };
  const command = buildSupervisorCommand({ event: commandEvent, localState: state });
  const manifest = canonicalBytes({ arguments: command.args, command: command.command, paymentMoved: false, reasonCode: "AMBIGUOUS_WRITE", releaseId: state.releaseId, repositorySha: state.repositorySha, role: state.role, schema: "clockchain.bilateral-recovery-command-manifest/v1", sessionId: state.sessionId, subjectRun: "rehearsal" });
  const authorization = Object.freeze({ artifactDigest: sha256(manifest), eventDigest: "d".repeat(64), kind: "EXACT_RECOVERY_AUTHORIZATION", subjectRun: "rehearsal" });
  const recovery = { authorizationUsed: false, commandEvent, manifestBytes: manifest.toString("base64"), manifestDigest: authorization.artifactDigest, stage: "EVENT_APPENDED", subjectRun: "rehearsal" };
  const writes = [];
  await executeSupervisorTransition({
    client: { async getArtifact() { return manifest; }, async putArtifact({ artifactType, bytes }) { return { artifactType, byteLength: String(bytes.length), digest: sha256(bytes) }; }, async appendEvent() {} },
    event: authorization,
    localState: { ...state, authenticatedEvents: Object.freeze([commandEvent, authorization]), recovery },
    dependencies: { async launcher() { return { ambiguous: false, exitCode: 0 }; }, async readArtifactPackage() { return Buffer.from("identity"); }, async validateRelayArtifact() {}, async verifyIdentityPackage() {}, async writeState(value) { writes.push(value); } },
  });
  assert.ok(writes.some((value) => value.phase === "BEFORE_CHILD"));
  assert.ok(writes.some((value) => value.phase === "CHILD_COMPLETE"));
  assert.ok(writes.some((value) => value.phase === "TRANSITION_COMPLETE"));
  assert.ok(writes.every((value) => value.recovery === undefined));
});

test("adopts an exact replayed recovery request after an append response is lost", async () => {
  const event = Object.freeze({ eventDigest: "f".repeat(64), kind: "START_REHEARSAL", repositorySha: "a".repeat(40), role: "operator", subjectRun: "rehearsal" });
  const payeeStarted = Object.freeze({ kind: "ROLE_STARTED", role: "payee", subjectRun: "rehearsal" });
  const command = buildSupervisorCommand({ event, localState: { repositorySha: event.repositorySha, role: "payer", tokenPath: "/state/token", rehearsal: { descriptorPath: "/state/descriptor", invitationPath: "/state/invitation", resultDirectory: "/state/result" } } });
  const manifest = canonicalBytes({ arguments: command.args, command: command.command, paymentMoved: false, reasonCode: "AMBIGUOUS_WRITE", releaseId: "release-a", repositorySha: event.repositorySha, role: "payer", schema: "clockchain.bilateral-recovery-command-manifest/v1", sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd", subjectRun: "rehearsal" });
  const digest = sha256(manifest);
  const existing = Object.freeze({ artifactDigest: digest, kind: "RECOVERY_REQUIRED", role: "payer", subjectRun: "rehearsal" });
  const commitment = Object.freeze({ paymentMoved: false, repositorySha: event.repositorySha, role: "payer", tokenSha256: "1".repeat(64) });
  const appended = [], writes = [];
  await assert.rejects(executeSupervisorTransition({
    client: {
      async putArtifact({ artifactType, bytes, expectedDigest }) { return { artifactType, byteLength: String(bytes.length), digest: expectedDigest }; },
      async appendEvent(value) { appended.push(value); },
    },
    event,
    localState: { authenticatedEvents: Object.freeze([event, payeeStarted, existing]), coordinationIdentity: { privateKeyPem: "private", publicKey: "public" }, rehearsal: { descriptorPath: "/state/descriptor", invitationPath: "/state/invitation", resultDirectory: "/state/result" }, releaseId: "release-a", repositorySha: event.repositorySha, role: "payer", sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd", tokenCommitment: commitment, tokenPath: "/state/token" },
    dependencies: { async readAndSignTokenCommitment() { return commitment; }, async launcher() { return { ambiguous: false, completion: Promise.resolve({ ambiguous: true, exitCode: 1 }), started: true }; }, async readArtifactPackage() { return Buffer.from("unused"); }, async validateRelayArtifact() {}, async writeState(value) { writes.push(value); } },
  }));
  assert.equal(appended.filter((entry) => entry.kind === "RECOVERY_REQUIRED").length, 0);
  assert.equal(writes.at(-1).recovery.stage, "EVENT_APPENDED");
});

test("requires an exact authenticated preflight plan before the durable child boundary", async () => {
  const plan = Buffer.from("pinned plan"), digest = sha256(plan);
  const event = Object.freeze({ artifactDigest: digest, eventDigest: "b".repeat(64), kind: "PREFLIGHT_PLAN_READY", repositorySha: "a".repeat(40), role: "operator", subjectRun: "release" });
  const writes = [];
  const state = { authenticatedEvents: Object.freeze([event]), coordinationIdentity: { privateKeyPem: "private", publicKey: "public" }, paymentMoved: false, preflight: { planPath: "/state/plan", privateKeyPath: "/state/preflight", outputPath: "/state/report" }, repositorySha: "a".repeat(40), role: "payer", tokenCommitment: { paymentMoved: false, repositorySha: "a".repeat(40), role: "payer" }, tokenPath: "/state/token" };
  await executeSupervisorTransition({
    client: { async getArtifact() { return plan; }, async putArtifact({ artifactType, bytes }) { assert.equal(artifactType, "preflight-participant-report"); return { artifactType, byteLength: String(bytes.length), digest: sha256(bytes) }; }, async appendEvent(value) { assert.deepEqual(value, { artifactDigest: sha256(Buffer.from("report")), kind: "PREFLIGHT_PARTICIPANT_READY", subjectRun: "release" }); } },
    event,
    localState: state,
    dependencies: { async verifyPreflightPlan(bytes, context) { assert.deepEqual(bytes, plan); assert.equal(context.artifactDigest, digest); }, async writeArtifactFile({ path }) { assert.equal(path, "/state/plan"); }, async readAndSignTokenCommitment() { return state.tokenCommitment; }, async launcher({ command }) { assert.equal(command, "scripts/probe-bilateral-rendezvous.mjs"); return { ambiguous: false, exitCode: 0 }; }, async readArtifactPackage() { return Buffer.from("report"); }, async validateRelayArtifact() {}, async writeState(value) { writes.push(value); } },
  });
  assert.equal(writes[0].phase, "BEFORE_CHILD");
  for (const checkpoint of writes) assert.equal(checkpoint.repositorySha, state.repositorySha);
});

test("rejects a substituted preflight plan and an identity package that does not bind its invitation", async () => {
  const plan = Buffer.from("pinned plan"), event = Object.freeze({ artifactDigest: sha256(plan), eventDigest: "c".repeat(64), kind: "PREFLIGHT_PLAN_READY", repositorySha: "a".repeat(40), role: "operator", subjectRun: "release" });
  const state = { authenticatedEvents: Object.freeze([event]), preflight: { planPath: "/state/plan", privateKeyPath: "/state/preflight", outputPath: "/state/report" }, repositorySha: "a".repeat(40), role: "payer", tokenCommitment: {}, tokenPath: "/state/token" };
  await assert.rejects(executeSupervisorTransition({ client: { async getArtifact() { return Buffer.from("substituted"); } }, event, localState: state, dependencies: { async writeState() {}, async writeArtifactFile() {}, async readAndSignTokenCommitment() { return {}; }, async launcher() {}, async readArtifactPackage() {}, async validateRelayArtifact() {} } }));
  const identityEvent = Object.freeze({ eventDigest: "d".repeat(64), kind: "REGISTER_REHEARSAL", repositorySha: "a".repeat(40), role: "operator", subjectRun: "rehearsal" });
  await assert.rejects(executeSupervisorTransition({ client: { async putArtifact() { return { artifactType: "identity-package", byteLength: "8", digest: sha256(Buffer.from("identity")) }; }, async appendEvent() {} }, event: identityEvent, localState: { authenticatedEvents: Object.freeze([identityEvent]), rehearsal: { identityDirectory: "/state/identity", invitationPath: "/state/invitation" }, repositorySha: "a".repeat(40), role: "payer" }, dependencies: { async launcher() { return { ambiguous: false, exitCode: 0 }; }, async readArtifactPackage() { return Buffer.from("identity"); }, async validateRelayArtifact() {}, async verifyIdentityPackage() { throw new Error("wrong invitation"); }, async writeState() {} } }));
});

test("refreshes only complete authenticated event snapshots", async () => {
  const fixture = replayFixture();
  let enrollments = 0, events = 0;
  const parsedEnrollmentSet = parseCoordinationEnrollmentSet(fixture.set);
  const result = await runSupervisor({ client: { async readEnrollmentSet() { enrollments += 1; return parsedEnrollmentSet; }, async readEvents(value) { events += 1; assert.deepEqual(value, { after: null, waitMs: 30000 }); return []; } }, localState: { operatorPublicKey: raw(fixture.operator), releaseId: fixture.release, repositorySha: fixture.repo, sessionId: fixture.session, role: "payer" }, dependencies: { shouldContinue() { return false; }, verifyEnrollmentSet: independentlyVerifiedEnrollmentSet } });
  assert.equal(enrollments, 1);
  assert.equal(events, 1);
  assert.equal(result.view.state, "BOOTSTRAPPING");
});

test("drives the authenticated startup through a token commitment without replacing its checkpoint", async () => {
  const fixture = replayFixture();
  const payer = generateKeyPairSync("ed25519");
  const payee = generateKeyPairSync("ed25519");
  const operator = fixture.operator;
  const enrollment = (role, pair, address) => {
    const value = { capabilityDigest: sha256(role), coordinationKey: { algorithm: "ed25519", keyId: `${role}-coordination`, publicKey: raw(pair) }, invitations: { rehearsal: { address, algorithm: "eip191", signature: `0x${"0".repeat(130)}` }, stakeholder: { address: `0x${(role === "payer" ? "2" : "4").repeat(40)}`, algorithm: "eip191", signature: `0x${"0".repeat(130)}` } }, paymentMoved: false, preflightKey: { algorithm: "ed25519", keyId: `${role}-preflight`, publicKey: raw(generateKeyPairSync("ed25519")) }, releaseId: fixture.release, repositorySha: fixture.repo, role, schema: "clockchain.bilateral-coordination-enrollment/v1", sessionId: fixture.session };
    return { ...value, signature: sign(null, coordinationEnrollmentSignaturePreimage(value), pair.privateKey).toString("base64") };
  };
  const payerEnrollment = enrollment("payer", payer, `0x${"1".repeat(40)}`);
  const payeeEnrollment = enrollment("payee", payee, `0x${"3".repeat(40)}`);
  const entry = (value) => { const bytes = canonicalBytes(value); return { enrollmentBase64: bytes.toString("base64"), enrollmentDigest: sha256(bytes), receiptBase64: Buffer.from("{}").toString("base64") }; };
  const enrollmentSet = Buffer.from(JSON.stringify(canonicalizeReceiptEventValue({ enrollments: { payer: entry(payerEnrollment), payee: entry(payeeEnrollment) }, paymentMoved: false, releaseId: fixture.release, repositorySha: fixture.repo, schema: "clockchain.bilateral-coordination-enrollment-set/v1", sessionId: fixture.session })), "utf8");
  const events = [];
  const appendSigned = (role, pair, kind, artifactDigest = null) => {
    const prior = events.filter((event) => event.role === role);
    events.push(createCoordinationEnvelope({ artifactDigest, kind, paymentMoved: false, previousEventDigest: prior.at(-1)?.eventDigest ?? null, privateKeyPem: pem(pair), publicKey: raw(pair), publicKeyId: role === "operator" ? "operator" : `${role}-coordination`, releaseId: fixture.release, repositorySha: fixture.repo, role, schema: "clockchain.bilateral-coordination-event/v1", sequence: String(prior.length), sessionId: fixture.session, subjectRun: "release" }));
  };
  appendSigned("payer", payer, "ENROLLMENT_CONFIRMED");
  appendSigned("payee", payee, "ENROLLMENT_CONFIRMED");
  appendSigned("operator", operator, "ENROLLMENT_RECEIPT");
  appendSigned("operator", operator, "WAIT_FOR_FUNDING");
  appendSigned("payee", payee, "FUNDING_INPUTS_READY");
  const writes = [];
  let loops = 0;
  const result = await runSupervisor({
    client: {
      async readEnrollmentSet() { return parseCoordinationEnrollmentSet(enrollmentSet); },
      async readEvents() { return structuredClone(events); },
      async putArtifact({ artifactType, bytes }) { assert.equal(artifactType, "token-commitment"); return { artifactType, byteLength: String(bytes.length), digest: sha256(bytes) }; },
      async appendEvent({ artifactDigest, kind, subjectRun }) { assert.equal(subjectRun, "release"); appendSigned("payer", payer, kind, artifactDigest); },
    },
    localState: { coordinationIdentity: { keyId: "payer-coordination", privateKeyPem: pem(payer), publicKey: raw(payer) }, invitations: [{ address: payerEnrollment.invitations.rehearsal.address }, { address: payerEnrollment.invitations.stakeholder.address }], operatorPublicKey: raw(operator), paymentMoved: false, phase: "BOOTSTRAPPED_ACTIVE", releaseId: fixture.release, repositorySha: fixture.repo, role: "payer", sessionId: fixture.session, tokenPath: "/state/token" },
    dependencies: {
      async ensureToken() { return { tokenPath: "/state/token" }; },
      async verifyFundingInputs(input) { assert.deepEqual(input.addresses, [payerEnrollment.invitations.rehearsal.address, payerEnrollment.invitations.stakeholder.address]); },
      async readAndSignTokenCommitment(input) { assert.equal(input.coordinationPrivateKeyPem, pem(payer)); assert.equal(input.coordinationPublicKey, raw(payer)); assert.equal(input.repositorySha, fixture.repo); assert.equal(input.role, "payer"); assert.equal(input.tokenPath, "/state/token"); return { paymentMoved: false, repositorySha: fixture.repo, role: "payer", tokenSha256: "1".repeat(64) }; },
      async writeState(value) { writes.push(value); },
      shouldContinue() { return loops++ < 2; },
      verifyEnrollmentSet: independentlyVerifiedEnrollmentSet,
    },
  });
  assert.equal(result.view.facts.tokenReady.payer, true);
  assert.deepEqual(events.filter((event) => event.role === "payer").map((event) => event.kind), ["ENROLLMENT_CONFIRMED", "FUNDING_INPUTS_READY", "TOKEN_READY"]);
  assert.ok(writes.length >= 2);
  for (const checkpoint of writes) assert.equal(checkpoint.coordinationIdentity.keyId, "payer-coordination");
});

test("fails closed on replay ordering and authority substitutions", async () => {
  const fixture = replayFixture();
  const input = (events) => ({ events, enrollmentSet: fixture.set, operatorPublicKey: raw(fixture.operator), releaseId: fixture.release, repositorySha: fixture.repo, sessionId: fixture.session, localRole: "payer", verifyEnrollmentSet: independentlyVerifiedEnrollmentSet });
  for (const events of [
    [...fixture.events, fixture.events[0]],
    [{ ...fixture.events[0], previousEventDigest: "a".repeat(64) }, fixture.events[1], fixture.events[2]],
    [{ ...fixture.events[0], signature: { ...fixture.events[0].signature, publicKey: raw(fixture.operator) } }, fixture.events[1], fixture.events[2]],
  ]) await assert.rejects(authenticateSupervisorReplay(input(events)));
});

test("resumes only through a replay-derived resumed coordination client", async () => {
  const fixture = replayFixture();
  let resumed = 0;
  const payerEnrollment = parseCoordinationEnrollmentSet(fixture.set).enrollments.payer;
  const payer = verifyCoordinationEnrollment(JSON.parse(Buffer.from(payerEnrollment.enrollmentBase64, "base64").toString("utf8")));
  let checkpoint = { activeLaunchState: { capabilityDigest: payer.capabilityDigest, paymentMoved: false, releaseId: fixture.release, repositorySha: fixture.repo, role: "payer", sessionId: fixture.session }, coordinationIdentity: { keyId: "payer-coordination", privateKeyPem: pem(fixture.payer), publicKey: raw(fixture.payer) }, enrollmentBase64: payerEnrollment.enrollmentBase64, invitations: [{ address: payer.invitations.rehearsal.address, algorithm: "eip191", secretPath: "/secret/rehearsal", signature: payer.invitations.rehearsal.signature, subjectRun: "rehearsal" }, { address: payer.invitations.stakeholder.address, algorithm: "eip191", secretPath: "/secret/stakeholder", signature: payer.invitations.stakeholder.signature, subjectRun: "stakeholder" }], paymentMoved: false, phase: "BOOTSTRAPPED_ACTIVE", preflight: { outputPath: "/state/preflight/report.json", planPath: "/state/preflight/plan.json", privateKeyPath: "/state/preflight/preflight.ed25519.pem", publicArtifact: { paymentMoved: false, publicKey: payer.preflightKey.publicKey, repositorySha: fixture.repo, role: "payer" }, publicArtifactPath: "/state/preflight/preflight-key-enrollment.json" }, receipt: {}, rehearsal: { descriptorPath: "/state/rehearsal/descriptor.json", identityDirectory: "/state/rehearsal/identity", invitationPath: "/secret/rehearsal", resultDirectory: "/state/rehearsal/result" }, repositorySha: fixture.repo, role: "payer", schema: SUPERVISOR_STATE_SCHEMA, sessionId: fixture.session, stateRoot: "/state", stakeholder: { descriptorPath: "/state/stakeholder/descriptor.json", identityDirectory: "/state/stakeholder/identity", invitationPath: "/secret/stakeholder", resultDirectory: "/state/stakeholder/result" } };
  const retirements = [], scans = [];
  const supervisor = await createRoleSupervisor({ launchManifestPath: "/retired", stateRoot: "/state", dependencies: {
    async readState() { return checkpoint; },
    async validateActiveLaunchState(value) { return value; },
    async createTransport() { return {}; },
    async resolveOperatorPublicKey() { return raw(fixture.operator); },
    createCoordinationClient() { throw new Error("fresh client forbidden"); },
    createResumedCoordinationClient(input) { resumed += 1; assert.equal(input.senderState.sequence, "0"); return {}; },
    async retireLaunchManifest(path) { retirements.push(path); },
    async scanCheckpointDirectories({ checkpoint: value }) { scans.push(value.phase); },
    verifyEnrollmentSet: independentlyVerifiedEnrollmentSet,
  } });
  const state = await supervisor.bootstrap();
  assert.equal(resumed, 1);
  assert.equal(state.phase, "BOOTSTRAPPED_ACTIVE");
  assert.equal(Buffer.isBuffer(state.enrollmentSet), false);
  checkpoint = state;
  for (const mutation of [
    (value) => { value.phase = "BEFORE_CHILD"; },
    (value) => { value.phase = "DESCRIPTOR_WRITING"; },
    (value) => { value.phase = "TOKEN_READY"; },
    (value) => { value.phase = "RECOVERY_REQUIRED"; },
    (value) => { value.processedEventDigests = ["f".repeat(64)]; },
    (value) => { value.childJournal = { command: "bin/handshake-propose.mjs", commandDigest: "f".repeat(64), eventDigest: "f".repeat(64), status: "CHILD_COMPLETE", subjectRun: "rehearsal" }; },
  ]) {
    const hostile = structuredClone(checkpoint);
    mutation(hostile);
    await assert.rejects(createRoleSupervisor({ launchManifestPath: "/retired", stateRoot: "/state", dependencies: {
      async readState() { return hostile; },
      async validateActiveLaunchState(value) { return value; },
      async createTransport() { assert.fail("hostile restart must not create transport"); },
      async resolveOperatorPublicKey() { assert.fail("hostile restart must not resolve authority"); },
      createResumedCoordinationClient() { assert.fail("hostile restart must not create client"); },
      async retireLaunchManifest() { assert.fail("hostile restart must not retire manifest"); },
    } }));
  }
  const restarted = await createRoleSupervisor({ launchManifestPath: "/retired", stateRoot: "/state", dependencies: {
    async readState() { return checkpoint; },
    async validateActiveLaunchState(value) { return value; },
    async createTransport() { return {}; },
    async resolveOperatorPublicKey() { return raw(fixture.operator); },
    createCoordinationClient() { throw new Error("fresh client forbidden"); },
    createResumedCoordinationClient(input) { resumed += 1; assert.equal(input.senderState.sequence, "0"); return {}; },
    async retireLaunchManifest(path) { retirements.push(path); },
    async scanCheckpointDirectories({ checkpoint: value }) { scans.push(value.phase); },
    verifyEnrollmentSet: independentlyVerifiedEnrollmentSet,
  } });
  await restarted.bootstrap();
  assert.equal(resumed, 2);
  assert.deepEqual(retirements, ["/retired", "/retired"]);
  assert.deepEqual(scans, ["BOOTSTRAPPED_ACTIVE", "BOOTSTRAPPED_ACTIVE"]);
});

test("passes a durable enrollment to fresh client bootstrap", async () => {
  let enrollment, state;
  const supervisor = await createRoleSupervisor({ launchManifestPath: "/launch", stateRoot: "/state", dependencies: {
    async readLaunchManifest() { return { bootstrapCapability: "11".repeat(32), releaseId: "release-a", repositorySha: "a".repeat(40), role: "payer", sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd" }; },
    async verifyRepositoryState() { return true; }, async createCoordinationIdentity() { const key = generateKeyPairSync("ed25519"); return { keyId: "payer-coordination", privateKeyPem: pem(key), publicKey: raw(key) }; }, async createLocalPreflightEnrollment() { const key = generateKeyPairSync("ed25519"); return { privateKeyPath: "/state/preflight", publicArtifact: { paymentMoved: false, publicKey: raw(key), repositorySha: "a".repeat(40), role: "payer" } }; }, async createInvitations() { return [{ subjectRun: "rehearsal", address: `0x${"1".repeat(40)}`, algorithm: "eip191", signature: `0x${"0".repeat(130)}`, secretPath: "/a" }, { subjectRun: "stakeholder", address: `0x${"2".repeat(40)}`, algorithm: "eip191", signature: `0x${"0".repeat(130)}`, secretPath: "/b" }]; }, async createTransport() { return {}; }, createCoordinationClient() { return { async bootstrap(input) { enrollment = input.enrollment; return { activeLaunchState: { paymentMoved: false, releaseId: "release-a", repositorySha: "a".repeat(40), role: "payer", sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd" }, receipt: {} }; } }; }, async writeState(value) { state = value; }, async readState() { return state; }, async validateActiveLaunchState(value) { return value; }, async retireLaunchManifest() {},
  } });
  await supervisor.bootstrap();
  assert.equal(verifyCoordinationEnrollment(enrollment).role, "payer");
});

test("rejects hostile enrollment factories before bootstrap transport", async () => {
  const coordination = generateKeyPairSync("ed25519"), preflight = generateKeyPairSync("ed25519");
  const validIdentity = { keyId: "payer-coordination", privateKeyPem: pem(coordination), publicKey: raw(coordination) };
  const validPreflight = { privateKeyPath: "/state/preflight", publicArtifact: { paymentMoved: false, publicKey: raw(preflight), repositorySha: "a".repeat(40), role: "payer" } };
  const validInvitations = [{ subjectRun: "rehearsal", address: `0x${"1".repeat(40)}`, algorithm: "eip191", signature: `0x${"0".repeat(130)}`, secretPath: "/a" }, { subjectRun: "stakeholder", address: `0x${"2".repeat(40)}`, algorithm: "eip191", signature: `0x${"0".repeat(130)}`, secretPath: "/b" }];
  const cases = [
    ["coordination key id", { identity: { ...validIdentity, keyId: "other" } }],
    ["preflight payment", { preflight: { ...validPreflight, publicArtifact: { ...validPreflight.publicArtifact, paymentMoved: true } } }],
    ["preflight role", { preflight: { ...validPreflight, publicArtifact: { ...validPreflight.publicArtifact, role: "payee" } } }],
    ["duplicate invitations", { invitations: [validInvitations[0], { ...validInvitations[0], secretPath: "/b" }] }],
    ["bad invitation signature", { invitations: [{ ...validInvitations[0], signature: "bad" }, validInvitations[1]] }],
  ];
  for (const [, mutation] of cases) {
    let calls = 0;
    const supervisor = await createRoleSupervisor({ launchManifestPath: "/launch", stateRoot: "/state", dependencies: {
      async readLaunchManifest() { return { bootstrapCapability: "11".repeat(32), releaseId: "release-a", repositorySha: "a".repeat(40), role: "payer", sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd" }; }, async verifyRepositoryState() { return true; }, async createCoordinationIdentity() { return mutation.identity ?? validIdentity; }, async createLocalPreflightEnrollment() { return mutation.preflight ?? validPreflight; }, async createInvitations() { return mutation.invitations ?? validInvitations; }, async createTransport() { return {}; }, createCoordinationClient() { calls += 1; return { bootstrap() {} }; }, async writeState() {},
    } });
    await assert.rejects(supervisor.bootstrap());
    assert.equal(calls, 0);
  }
});

test("persists local secrets before bootstrap transport", async () => {
  const writes = [];
  const key = generateKeyPairSync("ed25519"), preflight = generateKeyPairSync("ed25519");
  const supervisor = await createRoleSupervisor({ launchManifestPath: "/launch", stateRoot: "/state", dependencies: {
    async readLaunchManifest() { return { bootstrapCapability: "11".repeat(32), releaseId: "release-a", repositorySha: "a".repeat(40), role: "payer", sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd" }; }, async verifyRepositoryState() { return true; }, async createCoordinationIdentity() { return { keyId: "payer-coordination", privateKeyPem: pem(key), publicKey: raw(key) }; }, async createLocalPreflightEnrollment() { return { privateKeyPath: "/p", publicArtifact: { paymentMoved: false, publicKey: raw(preflight), repositorySha: "a".repeat(40), role: "payer" } }; }, async createInvitations() { return [{ subjectRun: "rehearsal", address: `0x${"1".repeat(40)}`, algorithm: "eip191", signature: `0x${"0".repeat(130)}`, secretPath: "/a" }, { subjectRun: "stakeholder", address: `0x${"2".repeat(40)}`, algorithm: "eip191", signature: `0x${"0".repeat(130)}`, secretPath: "/b" }]; }, async createTransport() { assert.equal(writes[0]?.phase, "LOCAL_SECRETS_READY"); return {}; }, createCoordinationClient() { return { async bootstrap() { return { activeLaunchState: { paymentMoved: false, releaseId: "release-a", repositorySha: "a".repeat(40), role: "payer", sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd" }, receipt: {} }; } }; }, async writeState(value) { writes.push(value); }, async readState() { return writes.at(-1); }, async validateActiveLaunchState(value) { return value; }, async retireLaunchManifest() {},
  } });
  await supervisor.bootstrap();
  assert.equal(writes[0].phase, "LOCAL_SECRETS_READY");
});

test("reuses a verified local checkpoint and retires the manifest only after active-state readback", async () => {
  const writes = [], calls = [];
  const coordination = generateKeyPairSync("ed25519"), preflight = generateKeyPairSync("ed25519");
  const manifest = { bootstrapCapability: "11".repeat(32), releaseId: "release-a", repositorySha: "a".repeat(40), role: "payer", sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd" };
  const activeLaunchState = Object.freeze({ paymentMoved: false, releaseId: manifest.releaseId, repositorySha: manifest.repositorySha, role: manifest.role, sessionId: manifest.sessionId });
  let persisted;
  const dependencies = {
    async readLaunchManifest() { return manifest; },
    async readState() { return persisted ?? null; },
    async verifyRepositoryState() { return true; },
    async createCoordinationIdentity() { return { keyId: "payer-coordination", privateKeyPem: pem(coordination), publicKey: raw(coordination) }; },
    async createLocalPreflightEnrollment() { return { privateKeyPath: "/state/preflight/preflight.ed25519.pem", publicArtifact: { paymentMoved: false, publicKey: raw(preflight), repositorySha: manifest.repositorySha, role: manifest.role }, publicArtifactPath: "/state/preflight/preflight-key-enrollment.json" }; },
    async createInvitations() { return [{ subjectRun: "rehearsal", address: `0x${"1".repeat(40)}`, algorithm: "eip191", signature: `0x${"0".repeat(130)}`, secretPath: "/secret/rehearsal" }, { subjectRun: "stakeholder", address: `0x${"2".repeat(40)}`, algorithm: "eip191", signature: `0x${"0".repeat(130)}`, secretPath: "/secret/stakeholder" }]; },
    async writeState(value) { calls.push(`write:${value.phase}`); persisted = value; writes.push(value); },
    async createTransport() { calls.push("transport"); return {}; },
    createCoordinationClient() { return { async bootstrap() { calls.push("bootstrap"); throw new Error("network interrupted"); } }; },
    async validateActiveLaunchState(value) { calls.push("validate"); assert.strictEqual(value, activeLaunchState); return value; },
    async retireLaunchManifest(path) { calls.push(`retire:${path}`); },
  };
  const first = await createRoleSupervisor({ launchManifestPath: "/private/launch", stateRoot: "/state", dependencies });
  await assert.rejects(first.run(), /network interrupted/);
  assert.equal(writes.length, 1);
  const storedEnrollment = writes[0].enrollmentBase64;
  assert.equal(writes[0].phase, "LOCAL_SECRETS_READY");

  dependencies.createCoordinationIdentity = () => { throw new Error("must reuse identity"); };
  dependencies.createLocalPreflightEnrollment = () => { throw new Error("must reuse preflight"); };
  dependencies.createInvitations = () => { throw new Error("must reuse invitations"); };
  dependencies.createCoordinationClient = () => ({ async bootstrap() { return { activeLaunchState, receipt: { id: "receipt" } }; } });
  const second = await createRoleSupervisor({ launchManifestPath: "/private/launch", stateRoot: "/state", dependencies });
  const state = await second.bootstrap();
  assert.equal(storedEnrollment, writes[0].enrollmentBase64);
  assert.deepEqual(calls.slice(-5), ["transport", "validate", "write:BOOTSTRAPPED_ACTIVE", "validate", "retire:/private/launch"]);
  assert.deepEqual(persisted.activeLaunchState, activeLaunchState);
  assert.equal(Object.hasOwn(state, "invitations"), false);
  assert.equal(JSON.stringify(state).includes(manifest.bootstrapCapability), false);
  assert.equal(JSON.stringify(state).includes("/secret/rehearsal"), false);
});

test("requires an independent enrollment-set verifier before replay trusts peer keys", async () => {
  const fixture = replayFixture();
  await assert.rejects(authenticateSupervisorReplay({
    events: fixture.events,
    enrollmentSet: fixture.set,
    operatorPublicKey: raw(fixture.operator),
    releaseId: fixture.release,
    repositorySha: fixture.repo,
    sessionId: fixture.session,
    localRole: "payer",
  }));
});

test("requires a fresh verifier-publication check for every verifier event", async () => {
  const fixture = replayFixture();
  const verification = createCoordinationEnvelope({ artifactDigest: "a".repeat(64), kind: "VERIFICATION_PASSED", paymentMoved: false, previousEventDigest: fixture.events.at(-1).eventDigest, privateKeyPem: pem(fixture.operator), publicKey: raw(fixture.operator), publicKeyId: "operator", releaseId: fixture.release, repositorySha: fixture.repo, role: "operator", schema: "clockchain.bilateral-coordination-event/v1", sequence: "1", sessionId: fixture.session, subjectRun: "rehearsal" });
  let checks = 0;
  await assert.rejects(authenticateSupervisorReplay({ events: [...fixture.events, verification], enrollmentSet: parseCoordinationEnrollmentSet(fixture.set), operatorPublicKey: raw(fixture.operator), releaseId: fixture.release, repositorySha: fixture.repo, sessionId: fixture.session, localRole: "payer", verifyEnrollmentSet: independentlyVerifiedEnrollmentSet }));
  await assert.rejects(authenticateSupervisorReplay({ events: [...fixture.events, verification], enrollmentSet: parseCoordinationEnrollmentSet(fixture.set), operatorPublicKey: raw(fixture.operator), releaseId: fixture.release, repositorySha: fixture.repo, sessionId: fixture.session, localRole: "payer", verifyEnrollmentSet: independentlyVerifiedEnrollmentSet, async verifyVerifierPublication() { checks += 1; return false; } }));
  assert.equal(checks, 1);
});

test("rejects a malformed spawned-child handle instead of announcing ROLE_STARTED", async () => {
  const event = Object.freeze({ eventDigest: "9".repeat(64), kind: "START_REHEARSAL", repositorySha: "a".repeat(40), role: "operator", subjectRun: "rehearsal" });
  const payeeStarted = Object.freeze({ kind: "ROLE_STARTED", role: "payee", subjectRun: "rehearsal" });
  const commitment = Object.freeze({ paymentMoved: false, repositorySha: event.repositorySha, role: "payer", tokenSha256: "1".repeat(64) });
  const calls = [];
  await assert.rejects(executeSupervisorTransition({
    client: {
      async putArtifact({ artifactType, bytes, expectedDigest }) { calls.push(["put", artifactType, expectedDigest]); return { artifactType, byteLength: String(bytes.length), digest: expectedDigest }; },
      async appendEvent(value) { calls.push(["event", value.kind]); },
    },
    event,
    localState: { authenticatedEvents: Object.freeze([event, payeeStarted]), coordinationIdentity: { privateKeyPem: "private", publicKey: "public" }, rehearsal: { descriptorPath: "/state/descriptor", invitationPath: "/state/invitation", resultDirectory: "/state/result" }, releaseId: "release-a", repositorySha: event.repositorySha, role: "payer", sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd", tokenCommitment: commitment, tokenPath: "/state/token" },
    dependencies: {
      async readAndSignTokenCommitment() { return commitment; },
      async launcher() { return { ambiguous: false, completion: Promise.resolve({ ambiguous: false, exitCode: 0 }), started: false }; },
      async readArtifactPackage() { return Buffer.from("package"); },
      async validateRelayArtifact() {},
      async writeState() {},
    },
  }));
  assert.deepEqual(calls, []);
});

test("persists a verified failure summary before publishing terminal failure", async () => {
  const event = Object.freeze({ eventDigest: "8".repeat(64), kind: "REGISTER_REHEARSAL", repositorySha: "a".repeat(40), role: "operator", subjectRun: "rehearsal" });
  const calls = [];
  await assert.rejects(executeSupervisorTransition({
    client: {
      async putArtifact({ artifactType, bytes, expectedDigest }) { calls.push(["put", artifactType, expectedDigest]); return { artifactType, byteLength: String(bytes.length), digest: expectedDigest }; },
      async appendEvent(value) { calls.push(["event", value.kind, value.artifactDigest]); },
    },
    event,
    localState: { authenticatedEvents: Object.freeze([event]), rehearsal: { identityDirectory: "/state/identity", invitationPath: "/state/invitation" }, releaseId: "release-a", repositorySha: event.repositorySha, role: "payer", sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd" },
    dependencies: {
      async launcher() { return { ambiguous: false, exitCode: 1 }; },
      async readArtifactPackage() { return Buffer.from("unused"); },
      async validateRelayArtifact({ artifactType, expectedDigest }) { assert.equal(artifactType, "failure-summary"); assert.match(expectedDigest, /^[0-9a-f]{64}$/); },
      async verifyIdentityPackage() {},
      async writeState(value) { calls.push(["state", value.phase]); },
    },
  }));
  assert.deepEqual(calls.map(([kind, value]) => [kind, value]), [["state", "BEFORE_CHILD"], ["put", "failure-summary"], ["state", "TERMINAL_FAILURE"], ["event", "TERMINAL_FAILURE"]]);
});
