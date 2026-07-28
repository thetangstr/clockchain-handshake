import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash, generateKeyPairSync, sign, X509Certificate } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { chmod, lstat, mkdir, mkdtemp, open, readFile, readdir, rename, rm, symlink, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";
import { privateKeyToAccount } from "viem/accounts";
import { toHex } from "viem";

import { canonicalizeReceiptEventValue } from "../src/canonical.mjs";
import { canonicalBytes } from "../src/bilateral/canonical.mjs";
import {
  COORDINATION_ENROLLMENT_SET_SCHEMA,
  coordinationEnrollmentSignaturePreimage,
  invitationProofPreimage,
} from "../src/bilateral/coordination/enrollment.mjs";

import {
  COORDINATOR_STATE_SCHEMA,
  createCoordinatorRelease,
  runCoordinator as runCoordinatorCore,
  validateVerifierChildResult,
} from "../src/bilateral/coordination/coordinator.mjs";
import { createCoordinationEnvelope } from "../src/bilateral/coordination/envelope.mjs";

const REPOSITORY_SHA = "a".repeat(40);
const SESSION_ID = "8f953393-86d0-4f99-9d6a-102f525fbecd";
const RELEASE_ID = "release-a";
const execFileAsync = promisify(execFile);

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

const TEST_RELEASE_ID = `release-${sha256(Buffer.from(SESSION_ID, "utf8")).slice(0, 16)}`;

function preparedRegistration(capabilities, repositorySha = REPOSITORY_SHA) {
  return {
    capabilities,
    operatorKeyId: "clockchain-demo-2026",
    paymentMoved: false,
    releaseId: TEST_RELEASE_ID,
    repositorySha,
    schema: "clockchain.bilateral-capability-registration/v1",
    sessionId: SESSION_ID,
    signature: { algorithm: "ed25519", keyId: "clockchain-demo-2026", value: "signature" },
  };
}

function capabilityReceipt(request) {
  const registration = request.registration;
  return {
    capabilities: registration.capabilities,
    paymentMoved: false,
    registrationDigest: "c".repeat(64),
    releaseId: registration.releaseId,
    repositorySha: registration.repositorySha,
    requestDigest: "d".repeat(64),
    schema: "clockchain.bilateral-capability-registration-receipt/v1",
    sessionId: registration.sessionId,
  };
}

function coordinationEvent({ artifactDigest = null, eventDigest, kind, role = "operator", subjectRun = "release" }) {
  return { artifactDigest, eventDigest, kind, paymentMoved: false, previousEventDigest: null, releaseId: RELEASE_ID, repositorySha: REPOSITORY_SHA, role, schema: "clockchain.bilateral-coordination-envelope/v1", sequence: "0", sessionId: SESSION_ID, signature: {}, subjectRun };
}

function fundingReplay() {
  return [
    coordinationEvent({ eventDigest: "1".repeat(64), kind: "ENROLLMENT_CONFIRMED", role: "payer" }),
    coordinationEvent({ eventDigest: "2".repeat(64), kind: "ENROLLMENT_CONFIRMED", role: "payee" }),
    coordinationEvent({ eventDigest: "3".repeat(64), kind: "FUNDING_INPUTS_READY", role: "payer" }),
    coordinationEvent({ eventDigest: "4".repeat(64), kind: "FUNDING_INPUTS_READY", role: "payee" }),
    coordinationEvent({ artifactDigest: "5".repeat(64), eventDigest: "5".repeat(64), kind: "TOKEN_READY", role: "payer" }),
    coordinationEvent({ artifactDigest: "6".repeat(64), eventDigest: "6".repeat(64), kind: "TOKEN_READY", role: "payee" }),
  ];
}

function stableBytes(value) {
  return Buffer.from(JSON.stringify(canonicalizeReceiptEventValue(value)), "utf8");
}

async function privateRoot(t) {
  const root = await mkdtemp(join(tmpdir(), "clockchain-coordinator-"));
  await chmod(root, 0o700);
  t.after(() => rm(root, { force: true, recursive: true }));
  return root;
}

async function tlsFixture(t) {
  const root = await privateRoot(t);
  const certificatePath = join(root, "tls-cert.pem");
  const privateKeyPath = join(root, "tls-key.pem");
  await execFileAsync("openssl", [
    "req", "-x509", "-newkey", "ed25519", "-keyout", privateKeyPath,
    "-out", certificatePath, "-nodes", "-days", "1", "-subj", "/CN=127.0.0.1",
    "-addext", "subjectAltName=IP:127.0.0.1",
  ]);
  const certificate = await readFile(certificatePath);
  return {
    certificate: certificate.toString("utf8"),
    fingerprint: sha256(new X509Certificate(certificate).raw),
  };
}

function stateWriterInput(root, overrides = {}) {
  return {
    dependencies: {
      createLaunchManifest: (input) => ({
        capabilityDigest: input.role === "payee" ? "a".repeat(64) : "b".repeat(64),
        manifest: {
          bootstrapCapability: input.role === "payee" ? "1".repeat(64) : "2".repeat(64),
          expectedTlsFingerprint: input.expectedTlsFingerprint,
          expiresAtMs: "20",
          operatorKeyId: input.operatorKeyId,
          releaseId: input.releaseId,
          repositorySha: input.repositorySha,
          role: input.role,
          sessionId: input.sessionId,
          tlsCertificatePem: input.tlsCertificatePem,
        },
      }),
      randomBytes: (size) => Buffer.alloc(size, 9),
      randomUUID: () => SESSION_ID,
      prepareCapabilityRegistration: async ({ capabilities }) => preparedRegistration(capabilities),
      registerCapabilitySet: async (request) => capabilityReceipt(request),
      writeLaunchManifest: async () => {},
      ...overrides,
    },
    operatorKeyId: "clockchain-demo-2026",
    relayUrl: "https://127.0.0.1:8443",
    releaseRoot: root,
    repositorySha: REPOSITORY_SHA,
    tlsCertificatePem: "test certificate",
    tlsFingerprint: "a".repeat(64),
  };
}

function rawPublicKey(pair) {
  return pair.publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64");
}

function privateKeyPem(pair) {
  return pair.privateKey.export({ format: "pem", type: "pkcs8" });
}

function signedReplayFixture(keys = Object.fromEntries(["operator", "payer", "payee"].map((role) => [role, generateKeyPairSync("ed25519")])) ) {
  const events = [];
  const append = ({ artifactDigest = null, key, kind, previousEventDigest, role, subjectRun = "release" }) => {
    if (["REHEARSAL_DESCRIPTOR_READY", "STAKEHOLDER_DESCRIPTOR_READY"].includes(kind)) {
      const has = (eventKind) => events.some((event) => event.kind === eventKind && event.subjectRun === subjectRun);
      const requestDigest = subjectRun === "rehearsal" ? "d".repeat(64) : "e".repeat(64);
      if (!has("PAYER_MANDATE_READY")) append({ artifactDigest: subjectRun === "rehearsal" ? "c".repeat(64) : "f".repeat(64), kind: "PAYER_MANDATE_READY", role: "payer", subjectRun });
      if (!has("PAYMENT_REQUEST_READY")) append({ artifactDigest: requestDigest, kind: "PAYMENT_REQUEST_READY", role: "payee", subjectRun });
      if (!has("PAYMENT_REQUEST_MATCHED")) append({ artifactDigest: null, kind: "PAYMENT_REQUEST_MATCHED", role: "payer", subjectRun });
    }
    key ??= keys[role];
    const previous = events.filter((event) => event.role === role).at(-1);
    events.push(createCoordinationEnvelope({
      artifactDigest,
      kind,
      paymentMoved: false,
      previousEventDigest: previousEventDigest ?? previous?.eventDigest ?? null,
      privateKeyPem: privateKeyPem(key),
      publicKey: rawPublicKey(key),
      publicKeyId: `${role}-key`,
      releaseId: RELEASE_ID,
      repositorySha: REPOSITORY_SHA,
      role,
      schema: "clockchain.bilateral-coordination-event/v1",
      sequence: String(events.filter((event) => event.role === role).length),
      sessionId: SESSION_ID,
      subjectRun,
    }));
    return events.at(-1);
  };
  return { append, events, keys };
}

async function signedFundingReplay() {
  const fixture = signedReplayFixture();
  const set = await enrollmentSetBytes({
    payee: await enrollment("payee", 1, fixture.keys.payee),
    payer: await enrollment("payer", 3, fixture.keys.payer),
  });
  fixture.append({ role: "payer", kind: "ENROLLMENT_CONFIRMED" });
  fixture.append({ role: "payee", kind: "ENROLLMENT_CONFIRMED" });
  fixture.append({ role: "operator", kind: "ENROLLMENT_RECEIPT" });
  fixture.append({ role: "operator", kind: "WAIT_FOR_FUNDING" });
  fixture.append({ role: "payer", kind: "FUNDING_INPUTS_READY" });
  fixture.append({ role: "payee", kind: "FUNDING_INPUTS_READY" });
  fixture.append({ artifactDigest: "1".repeat(64), role: "payer", kind: "TOKEN_READY" });
  fixture.append({ artifactDigest: "2".repeat(64), role: "payee", kind: "TOKEN_READY" });
  return { fixture, set };
}

function rawReplayDependencies({ fixture, set, verifierPublication = null }) {
  return {
    appendOperatorEvent: () => {}, createTransport: () => {}, displayAddresses: () => {}, launcher: () => {}, now: () => 0, putArtifact: () => {},
    readEnrollmentSet: async () => set, readEvents: async () => fixture.events, readSessionView: async () => ({ facts: { enrollmentConfirmed: { payee: true, payer: true } }, paymentMoved: false }), readState: async () => null,
    readVerifierPublication: async () => verifierPublication,
    resolveOperatorPublicKey: async () => rawPublicKey(fixture.keys.operator),
    sleeper: () => {}, verifyMarkerCompleteVerdict: () => {}, writeState: () => {}, waitForFunding: () => {},
  };
}

async function enrollment(role, seed, coordination = generateKeyPairSync("ed25519")) {
  const preflight = generateKeyPairSync("ed25519");
  const capabilityDigest = `${seed}`.repeat(64);
  const invitations = {};
  for (const [run, value] of [["rehearsal", seed], ["stakeholder", seed + 1]]) {
    const account = privateKeyToAccount(`0x${value.toString(16).padStart(2, "0").repeat(32)}`);
    const address = account.address.toLowerCase();
    invitations[run] = {
      address,
      algorithm: "eip191",
      signature: await account.signMessage({ message: { raw: toHex(invitationProofPreimage({ address, capabilityDigest, releaseId: RELEASE_ID, repositorySha: REPOSITORY_SHA, role, run, sessionId: SESSION_ID })) } }),
    };
  }
  const unsigned = { capabilityDigest, coordinationKey: { algorithm: "ed25519", keyId: `${role}-coordination`, publicKey: rawPublicKey(coordination) }, invitations, paymentMoved: false, preflightKey: { algorithm: "ed25519", keyId: `${role}-preflight`, publicKey: rawPublicKey(preflight) }, releaseId: RELEASE_ID, repositorySha: REPOSITORY_SHA, role, schema: "clockchain.bilateral-coordination-enrollment/v1", sessionId: SESSION_ID };
  return { ...unsigned, signature: sign(null, coordinationEnrollmentSignaturePreimage(unsigned), privateKeyPem(coordination)).toString("base64") };
}

async function enrollmentSetBytes(overrides = {}) {
  const payee = overrides.payee ?? await enrollment("payee", 1);
  const payer = overrides.payer ?? await enrollment("payer", 3);
  const entry = (value) => {
    const bytes = canonicalBytes(value);
    return { enrollmentBase64: bytes.toString("base64"), enrollmentDigest: sha256(bytes), receiptBase64: Buffer.from("receipt").toString("base64") };
  };
  return stableBytes({ enrollments: { payee: entry(payee), payer: entry(payer) }, paymentMoved: false, releaseId: RELEASE_ID, repositorySha: REPOSITORY_SHA, schema: COORDINATION_ENROLLMENT_SET_SCHEMA, sessionId: SESSION_ID });
}

// Legacy test descriptions supply only public event facts.  This adapter turns
// them into the same canonical, enrolled, signed raw relay surface used by the
// production coordinator.  The core never receives this seam.
async function runCoordinator(input) {
  const legacy = input?.dependencies?.legacyEvents;
  if (typeof legacy !== "function") return runCoordinatorCore(input);
  const fixture = signedReplayFixture();
  const set = await enrollmentSetBytes({
    payee: await enrollment("payee", 1, fixture.keys.payee),
    payer: await enrollment("payer", 3, fixture.keys.payer),
  });
  const appended = [];
  const raw = async () => {
    const legacyValues = await legacy();
    const values = [...legacyValues];
    if (
      values.some((value) => value.kind === "FUNDING_INPUTS_READY") &&
      !values.some((value) => value.kind === "ENROLLMENT_RECEIPT")
    ) {
      const afterEnrollment = values.findIndex((value) => value.kind === "FUNDING_INPUTS_READY");
      values.splice(afterEnrollment, 0,
        { artifactDigest: null, kind: "ENROLLMENT_RECEIPT", role: "operator", subjectRun: "release" },
        { artifactDigest: null, kind: "WAIT_FOR_FUNDING", role: "operator", subjectRun: "release" },
      );
    }
    values.push(...appended);
    const rebuilt = signedReplayFixture(fixture.keys);
    for (const value of values) {
      rebuilt.append({
        artifactDigest: value.artifactDigest,
        kind: value.kind,
        role: value.role,
        subjectRun: value.subjectRun,
      });
    }
    return rebuilt.events;
  };
  const dependencies = { ...input.dependencies };
  delete dependencies.legacyEvents;
  const originalAppend = dependencies.appendOperatorEvent;
  dependencies.appendOperatorEvent = async (value) => {
    appended.push({ ...value, role: "operator" });
    return originalAppend?.(value);
  };
  const originalVerifiedAppend = dependencies.appendVerifiedEvent;
  dependencies.appendVerifiedEvent = async ({ event, publication }) => {
    appended.push(event);
    return originalVerifiedAppend?.({ event, publication });
  };
  dependencies.readEnrollmentSet = async () => set;
  dependencies.readEvents = raw;
  dependencies.resolveOperatorPublicKey = async () => rawPublicKey(fixture.keys.operator);
  dependencies.readVerifierPublication ??= async () => null;
  const originalReadState = dependencies.readState;
  dependencies.readState = async (value) => {
    const state = await originalReadState(value);
    if (state === null) return null;
    const events = await raw();
    const kinds = {
      COMPLETE_RELEASE: "COMPLETE_RELEASE",
      ENROLLMENT_RECEIPT: "ENROLLMENT_RECEIPT",
      PAYEE_ROLE_START: "ROLE_STARTED",
      PAYER_ROLE_START: "ROLE_STARTED",
      PREFLIGHT_PLAN: "PREFLIGHT_PLAN_READY",
      REGISTER_REHEARSAL: "REGISTER_REHEARSAL",
      REGISTER_STAKEHOLDER: "REGISTER_STAKEHOLDER",
      REHEARSAL_DESCRIPTOR: "REHEARSAL_DESCRIPTOR_READY",
      REHEARSAL_VERDICT: "VERIFICATION_PASSED",
      ROLE_PACKAGE: "ROLE_PACKAGE_READY",
      ROLE_STARTED: "ROLE_STARTED",
      STAKEHOLDER_DESCRIPTOR: "STAKEHOLDER_DESCRIPTOR_READY",
      STAKEHOLDER_VERDICT: "VERIFICATION_PASSED",
      START_REHEARSAL: "START_REHEARSAL",
      START_STAKEHOLDER: "START_STAKEHOLDER",
      WAIT_FOR_FUNDING: "WAIT_FOR_FUNDING",
    };
    return {
      ...state,
      checkpoints: state.checkpoints.map((checkpoint) => {
        if (checkpoint.status !== "EVENT_APPENDED") return checkpoint;
        const event = events.find((candidate) =>
          candidate.kind === kinds[checkpoint.action] &&
          candidate.role === checkpoint.role &&
          candidate.subjectRun === checkpoint.subjectRun &&
          candidate.artifactDigest === checkpoint.artifactDigest,
        );
        return event === undefined ? checkpoint : { ...checkpoint, eventDigest: event.eventDigest };
      }),
    };
  };
  return runCoordinatorCore({ ...input, dependencies });
}

test("accepts only a complete lifecycle reconstructed from signed raw relay envelopes", async () => {
  const fixture = signedReplayFixture();
  const set = await enrollmentSetBytes({
    payee: await enrollment("payee", 1, fixture.keys.payee),
    payer: await enrollment("payer", 3, fixture.keys.payer),
  });
  const append = (role, kind, artifactDigest = null, subjectRun = "release") =>
    fixture.append({ artifactDigest, kind, role, subjectRun });
  append("payer", "ENROLLMENT_CONFIRMED"); append("payee", "ENROLLMENT_CONFIRMED");
  append("operator", "ENROLLMENT_RECEIPT"); append("operator", "WAIT_FOR_FUNDING");
  append("payer", "FUNDING_INPUTS_READY"); append("payee", "FUNDING_INPUTS_READY");
  append("payer", "TOKEN_READY", "a".repeat(64)); append("payee", "TOKEN_READY", "b".repeat(64));
  append("operator", "PREFLIGHT_PLAN_READY", "1".repeat(64));
  append("payer", "PREFLIGHT_PARTICIPANT_READY", "2".repeat(64)); append("payee", "PREFLIGHT_PARTICIPANT_READY", "3".repeat(64));
  const checkpoints = [];
  for (const subjectRun of ["rehearsal", "stakeholder"]) {
    const descriptor = subjectRun === "rehearsal" ? "4".repeat(64) : "a".repeat(64);
    append("operator", subjectRun === "rehearsal" ? "REGISTER_REHEARSAL" : "REGISTER_STAKEHOLDER", subjectRun === "rehearsal" ? "1".repeat(64) : null, subjectRun);
    append("payer", "IDENTITY_PACKAGE_READY", subjectRun === "rehearsal" ? "5".repeat(64) : "b".repeat(64), subjectRun);
    append("payee", "IDENTITY_PACKAGE_READY", subjectRun === "rehearsal" ? "6".repeat(64) : "c".repeat(64), subjectRun);
    append("operator", subjectRun === "rehearsal" ? "REHEARSAL_DESCRIPTOR_READY" : "STAKEHOLDER_DESCRIPTOR_READY", descriptor, subjectRun);
    append("payee", "DESCRIPTOR_ACCEPTED", descriptor, subjectRun); append("payer", "DESCRIPTOR_ACCEPTED", descriptor, subjectRun);
    append("operator", subjectRun === "rehearsal" ? "START_REHEARSAL" : "START_STAKEHOLDER", null, subjectRun);
    append("payee", "ROLE_STARTED", null, subjectRun); append("payer", "ROLE_STARTED", null, subjectRun);
    append("payee", "ROLE_PACKAGE_READY", subjectRun === "rehearsal" ? "7".repeat(64) : "d".repeat(64), subjectRun);
    append("payer", "ROLE_PACKAGE_READY", subjectRun === "rehearsal" ? "8".repeat(64) : "e".repeat(64), subjectRun);
    const verdict = append("operator", "VERIFICATION_PASSED", subjectRun === "rehearsal" ? "9".repeat(64) : "f".repeat(64), subjectRun);
    checkpoints.push({ action: subjectRun === "rehearsal" ? "REHEARSAL_VERDICT" : "STAKEHOLDER_VERDICT", artifactDigest: verdict.artifactDigest, eventDigest: verdict.eventDigest, role: "operator", status: "EVENT_APPENDED", subjectRun });
  }
  const complete = append("operator", "COMPLETE_RELEASE");
  checkpoints.push({ action: "COMPLETE_RELEASE", artifactDigest: null, eventDigest: complete.eventDigest, role: "operator", status: "EVENT_APPENDED", subjectRun: "release" });
  const release = { capabilityDigests: ["a".repeat(64), "b".repeat(64)], paymentMoved: false, releaseId: RELEASE_ID, repositorySha: REPOSITORY_SHA, schema: COORDINATOR_STATE_SCHEMA, sessionId: SESSION_ID };
  const publications = new Map([["rehearsal", "9".repeat(64)], ["stakeholder", "f".repeat(64)]]);
  const dependencies = rawReplayDependencies({ fixture, set });
  dependencies.readState = async () => ({ ...release, checkpoints, state: "COMPLETE" });
  dependencies.readVerifierPublication = async ({ subjectRun }) => ({ paymentMoved: false, publicationDigest: publications.get(subjectRun), releaseId: RELEASE_ID, repositorySha: REPOSITORY_SHA, schema: "clockchain.bilateral-verifier-publication/v1", sessionId: SESSION_ID, status: "VERIFICATION_PASSED", subjectRun });
  const result = await runCoordinatorCore({ dependencies, release, releaseRoot: "/private/release" });
  assert.equal(result.state, "COMPLETE");
});

test("accepts only a fresh successful verifier publication without child output", () => {
  const publicationDigest = "a".repeat(64);
  assert.equal(
    COORDINATOR_STATE_SCHEMA,
    "clockchain.bilateral-coordinator-state/v1",
  );
  assert.deepEqual(
    validateVerifierChildResult({
      exitCode: 0,
      publicationDigest,
      status: "VERIFICATION_PASSED",
      stderr: "",
      stdout: "",
    }),
    {
      publicationDigest,
      status: "VERIFICATION_PASSED",
    },
  );
  assert.throws(
    () =>
      validateVerifierChildResult({
        exitCode: 0,
        publicationDigest,
        status: "VERIFICATION_PASSED",
        stderr: "",
        stdout: "AUTHORIZED",
      }),
  );
});

test("publishes the exact release-bound verifier claim with its authenticated event", async () => {
  const fixture = signedReplayFixture();
  const set = await enrollmentSetBytes({
    payee: await enrollment("payee", 1, fixture.keys.payee),
    payer: await enrollment("payer", 3, fixture.keys.payer),
  });
  const append = (role, kind, artifactDigest = null, subjectRun = "release") =>
    fixture.append({ artifactDigest, kind, role, subjectRun });
  append("payer", "ENROLLMENT_CONFIRMED");
  append("payee", "ENROLLMENT_CONFIRMED");
  const enrollmentReceipt = append("operator", "ENROLLMENT_RECEIPT");
  const funding = append("operator", "WAIT_FOR_FUNDING");
  append("payer", "FUNDING_INPUTS_READY");
  append("payee", "FUNDING_INPUTS_READY");
  append("payer", "TOKEN_READY", "a".repeat(64));
  append("payee", "TOKEN_READY", "b".repeat(64));
  const plan = append("operator", "PREFLIGHT_PLAN_READY", "1".repeat(64));
  append("payer", "PREFLIGHT_PARTICIPANT_READY", "2".repeat(64));
  append("payee", "PREFLIGHT_PARTICIPANT_READY", "3".repeat(64));
  const registration = append("operator", "REGISTER_REHEARSAL", "4".repeat(64), "rehearsal");
  const payerIdentity = append("payer", "IDENTITY_PACKAGE_READY", "5".repeat(64), "rehearsal");
  const payeeIdentity = append("payee", "IDENTITY_PACKAGE_READY", "6".repeat(64), "rehearsal");
  append("payer", "PAYER_MANDATE_READY", "c".repeat(64), "rehearsal");
  append("payee", "PAYMENT_REQUEST_READY", "d".repeat(64), "rehearsal");
  append("payer", "PAYMENT_REQUEST_MATCHED", null, "rehearsal");
  const descriptor = append("operator", "REHEARSAL_DESCRIPTOR_READY", "7".repeat(64), "rehearsal");
  append("payer", "DESCRIPTOR_ACCEPTED", descriptor.artifactDigest, "rehearsal");
  append("payee", "DESCRIPTOR_ACCEPTED", descriptor.artifactDigest, "rehearsal");
  const start = append("operator", "START_REHEARSAL", null, "rehearsal");
  const payeeStarted = append("payee", "ROLE_STARTED", null, "rehearsal");
  const payerStarted = append("payer", "ROLE_STARTED", null, "rehearsal");
  const payeePackage = append("payee", "ROLE_PACKAGE_READY", "8".repeat(64), "rehearsal");
  const payerPackage = append("payer", "ROLE_PACKAGE_READY", "9".repeat(64), "rehearsal");
  const release = {
    capabilityDigests: ["a".repeat(64), "b".repeat(64)],
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    schema: COORDINATOR_STATE_SCHEMA,
    sessionId: SESSION_ID,
  };
  const eventCheckpoint = (action, event, role, subjectRun, artifactDigest = event.artifactDigest) => ({
    action,
    artifactDigest,
    eventDigest: event.eventDigest,
    role,
    status: "EVENT_APPENDED",
    subjectRun,
  });
  const persisted = {
    ...release,
    checkpoints: [
      eventCheckpoint("ENROLLMENT_RECEIPT", enrollmentReceipt, "operator", "release"),
      eventCheckpoint("WAIT_FOR_FUNDING", funding, "operator", "release"),
      eventCheckpoint("PREFLIGHT_PLAN", plan, "operator", "release"),
      eventCheckpoint("REGISTER_REHEARSAL", registration, "operator", "rehearsal"),
      eventCheckpoint("IDENTITY_PACKAGE", payerIdentity, "payer", "rehearsal"),
      eventCheckpoint("IDENTITY_PACKAGE", payeeIdentity, "payee", "rehearsal"),
      eventCheckpoint("REHEARSAL_DESCRIPTOR", descriptor, "operator", "rehearsal"),
      eventCheckpoint("START_REHEARSAL", start, "operator", "rehearsal", descriptor.artifactDigest),
      eventCheckpoint("ROLE_STARTED", payeeStarted, "payee", "rehearsal", descriptor.artifactDigest),
      eventCheckpoint("ROLE_STARTED", payerStarted, "payer", "rehearsal", descriptor.artifactDigest),
      eventCheckpoint("ROLE_PACKAGE", payeePackage, "payee", "rehearsal"),
      eventCheckpoint("ROLE_PACKAGE", payerPackage, "payer", "rehearsal"),
    ],
    state: "REHEARSAL_PACKAGES_READY",
  };
  const publication = {
    paymentMoved: false,
    publicationDigest: "c".repeat(64),
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    schema: "clockchain.bilateral-verifier-publication/v1",
    sessionId: SESSION_ID,
    status: "VERIFICATION_PASSED",
    subjectRun: "rehearsal",
  };
  let appendedPublication;
  const result = await runCoordinatorCore({
    dependencies: {
      ...rawReplayDependencies({ fixture, set }),
      appendVerifiedEvent: async ({ event, publication: claim }) => {
        appendedPublication = claim;
        fixture.events.push(event);
      },
      createVerifiedEvent: async ({ artifactDigest, subjectRun }) => {
        const event = append("operator", "VERIFICATION_PASSED", artifactDigest, subjectRun);
        fixture.events.pop();
        return event;
      },
      launchVerifier: async ({ outputDirectory }) => ({
        outputDirectory,
        result: {
          exitCode: 0,
          publicationDigest: publication.publicationDigest,
          status: "VERIFICATION_PASSED",
          stderr: "",
          stdout: "",
        },
      }),
      readVerifierPublication: async () => publication,
      readState: async () => persisted,
      validatePublishedBilateralVerdict: async () => publication,
    },
    release,
    releaseRoot: "/private/release",
  });
  assert.equal(result.state, "REHEARSAL_VERIFIED");
  assert.deepEqual({ ...appendedPublication }, publication);
});

test("persists two private manifests only after one atomic two-role capability registration", async (t) => {
  const root = await privateRoot(t);
  const writes = [];
  const registrations = [];
  const states = [];
  const capability = Buffer.alloc(32, 7);
  const release = await createCoordinatorRelease({
    dependencies: {
      createLaunchManifest: (input) => ({
        capabilityDigest: input.role === "payee" ? "a".repeat(64) : "b".repeat(64),
        manifest: Object.freeze({
          bootstrapCapability: Buffer.alloc(32, input.role === "payee" ? 7 : 8).toString("hex"),
          expectedTlsFingerprint: input.expectedTlsFingerprint,
          expiresAtMs: "20",
          operatorKeyId: input.operatorKeyId,
          releaseId: input.releaseId,
          repositorySha: input.repositorySha,
          role: input.role,
          sessionId: input.sessionId,
          tlsCertificatePem: input.tlsCertificatePem,
        }),
      }),
      now: () => 10,
      prepareCapabilityRegistration: async ({ capabilities }) => preparedRegistration(capabilities, "2".repeat(40)),
      randomBytes: () => capability,
      randomUUID: () => "8f953393-86d0-4f99-9d6a-102f525fbecd",
      registerCapabilitySet: async (value) => {
        registrations.push(value);
        return capabilityReceipt(value);
      },
      writeLaunchManifest: async (path, manifest) => writes.push({ manifest, path }),
      writeState: async (value) => states.push(value),
    },
    operatorKeyId: "clockchain-demo-2026",
    relayUrl: "https://127.0.0.1:8443",
    releaseRoot: root,
    repositorySha: "2".repeat(40),
    tlsCertificatePem: "test certificate",
    tlsFingerprint: "a".repeat(64),
  });
  assert.equal(release.manifests.length, 2);
  assert.deepEqual(writes.map(({ path }) => path), [
    `${root}/payee.launch.json`,
    `${root}/payer.launch.json`,
  ]);
  assert.equal(registrations.length, 1);
  assert.deepEqual(Object.keys(registrations[0].registration.capabilities), ["payee", "payer"]);
  assert.equal(JSON.stringify(registrations).includes(capability.toString("hex")), false);
  assert.equal(JSON.stringify(states).includes(capability.toString("hex")), false);
});

test("composes the exact bound operator capability client calls", async (t) => {
  const root = await privateRoot(t);
  const calls = [];
  await createCoordinatorRelease({
    ...stateWriterInput(root),
    dependencies: {
      ...stateWriterInput(root).dependencies,
      prepareCapabilityRegistration: async (value) => {
        calls.push(["prepare", value]);
        return preparedRegistration(value.capabilities);
      },
      registerCapabilitySet: async (value) => {
        calls.push(["register", value]);
        return capabilityReceipt(value);
      },
      writeState: async () => {},
    },
  });
  assert.deepEqual(Object.keys(calls[0][1]), ["capabilities"]);
  assert.deepEqual(Object.keys(calls[1][1]), ["registration"]);
  assert.deepEqual(Object.keys(calls[0][1].capabilities), ["payee", "payer"]);
  assert.deepEqual(Object.keys(calls[1][1].registration), ["capabilities", "operatorKeyId", "paymentMoved", "releaseId", "repositorySha", "schema", "sessionId", "signature"]);
});

test("does not write either launch manifest when the atomic capability set is rejected", async () => {
  const writes = [];
  await assert.rejects(
    createCoordinatorRelease({
      ...stateWriterInput("/private/release"),
      dependencies: {
        ...stateWriterInput("/private/release").dependencies,
        registerCapabilitySet: async (value) => {
          assert.deepEqual(Object.keys(value.registration.capabilities), ["payee", "payer"]);
          throw new Error("relay rejected the whole set");
        },
        writeLaunchManifest: async (path) => writes.push(path),
      },
    }),
    { code: "COORDINATION_COORDINATOR_INVALID" },
  );
  assert.deepEqual(writes, []);
});

test("reuses one durable private capability registration after a lost post response", async (t) => {
  const root = await privateRoot(t);
  const registrations = [];
  let generated = 0;
  const input = stateWriterInput(root, {
    createLaunchManifest: (value) => {
      generated += 1;
      return {
        capabilityDigest: value.role === "payee" ? "a".repeat(64) : "b".repeat(64),
        manifest: {
          bootstrapCapability: value.role === "payee" ? "1".repeat(64) : "2".repeat(64),
          expectedTlsFingerprint: value.expectedTlsFingerprint,
          expiresAtMs: "20", operatorKeyId: value.operatorKeyId,
          releaseId: value.releaseId, repositorySha: value.repositorySha,
          role: value.role, sessionId: value.sessionId,
          tlsCertificatePem: value.tlsCertificatePem,
        },
      };
    },
    registerCapabilitySet: async (value) => {
      registrations.push(value.registration);
      return capabilityReceipt(value);
    },
    writeLaunchManifest: async () => { throw new Error("lost response after durable relay post"); },
  });
  await assert.rejects(createCoordinatorRelease(input), /lost response after durable relay post/);
  assert.equal(registrations.length, 1);
  await createCoordinatorRelease({
    ...input,
    dependencies: { ...input.dependencies, writeLaunchManifest: async () => {}, writeState: async () => {} },
  });
  assert.equal(registrations.length, 1);
  assert.equal(generated, 2);
  await assert.rejects(lstat(join(root, "capability-registration.pending.json")), { code: "ENOENT" });
});

test("rejects a stale or tampered private capability registration journal", async (t) => {
  const root = await privateRoot(t);
  const stale = join(root, ".capability-registration.pending.json.deadbeef.tmp");
  await writeFile(stale, "{}", { mode: 0o600 });
  await assert.rejects(createCoordinatorRelease(stateWriterInput(root)), { code: "COORDINATION_COORDINATOR_INVALID" });
  await unlink(stale);
  const input = stateWriterInput(root, { writeLaunchManifest: async () => { throw new Error("interrupt"); } });
  await assert.rejects(createCoordinatorRelease(input), /interrupt/);
  const pending = join(root, "capability-registration.pending.json");
  await writeFile(pending, "{}", { mode: 0o600 });
  await assert.rejects(createCoordinatorRelease(input), { code: "COORDINATION_COORDINATOR_INVALID" });
});

test("writes canonical secret-free coordinator state in a preexisting private root", async (t) => {
  const root = await privateRoot(t);
  const tls = await tlsFixture(t);
  const registrations = [];
  let randomCall = 0;
  const release = await createCoordinatorRelease({
    dependencies: {
      now: () => 10,
      prepareCapabilityRegistration: async ({ capabilities }) => preparedRegistration(capabilities),
      randomBytes: (size) => Buffer.alloc(size, ++randomCall),
      randomUUID: () => "8f953393-86d0-4f99-9d6a-102f525fbecd",
      registerCapabilitySet: async (value) => {
        registrations.push(value);
        return capabilityReceipt(value);
      },
    },
    operatorKeyId: "clockchain-demo-2026",
    relayUrl: "https://127.0.0.1:8443",
    releaseRoot: root,
    repositorySha: REPOSITORY_SHA,
    tlsCertificatePem: tls.certificate,
    tlsFingerprint: tls.fingerprint,
  });
  const statePath = join(root, "coordinator-state.json");
  const stateBytes = await readFile(statePath);
  assert.equal((await lstat(statePath)).mode & 0o777, 0o600);
  assert.equal((await lstat(join(root, "payee.launch.json"))).mode & 0o777, 0o600);
  assert.equal((await lstat(join(root, "payer.launch.json"))).mode & 0o777, 0o600);
  assert.deepEqual(stateBytes, Buffer.from(`${JSON.stringify(canonicalizeReceiptEventValue({
    capabilityDigests: release.capabilityDigests,
    checkpoints: [],
    paymentMoved: false,
    releaseId: release.releaseId,
    repositorySha: REPOSITORY_SHA,
    schema: COORDINATOR_STATE_SCHEMA,
    sessionId: release.sessionId,
    state: "BOOTSTRAPPING",
  }))}\n`, "utf8"));
  assert.equal(stateBytes.includes(Buffer.from("07".repeat(32), "utf8")), false);
  assert.equal(registrations.length, 1);
});

test("recovers after durable BOOTSTRAPPING state before pending-journal retirement", async (t) => {
  const root = await privateRoot(t);
  const tls = await tlsFixture(t);
  let registrations = 0;
  let failPendingUnlink = true;
  const first = {
    lstat,
    open,
    rename,
    unlink: async (path) => {
      if (failPendingUnlink && path.endsWith("capability-registration.pending.json")) {
        failPendingUnlink = false;
        throw new Error("crash after public state");
      }
      return unlink(path);
    },
  };
  let randomCall = 0;
  const common = {
    now: () => 10,
    prepareCapabilityRegistration: async ({ capabilities }) => preparedRegistration(capabilities),
    randomBytes: (size) => Buffer.alloc(size, ++randomCall),
    randomUUID: () => SESSION_ID,
    registerCapabilitySet: async (value) => { registrations += 1; return capabilityReceipt(value); },
  };
  const args = { operatorKeyId: "clockchain-demo-2026", relayUrl: "https://127.0.0.1:8443", releaseRoot: root, repositorySha: REPOSITORY_SHA, tlsCertificatePem: tls.certificate, tlsFingerprint: tls.fingerprint };
  await assert.rejects(createCoordinatorRelease({ ...args, dependencies: { ...common, fileSystem: first } }), /crash after public state/);
  assert.equal(registrations, 1);
  const state = await readFile(join(root, "coordinator-state.json"));
  assert.ok(state.length > 0);
  await createCoordinatorRelease({ ...args, dependencies: common });
  assert.equal(registrations, 1);
  await assert.rejects(lstat(join(root, "capability-registration.pending.json")), { code: "ENOENT" });
});

test("rejects permissive, symlinked, and unexpected coordinator state targets", async (t) => {
  const permissive = await mkdtemp(join(tmpdir(), "clockchain-coordinator-"));
  t.after(() => rm(permissive, { force: true, recursive: true }));
  await chmod(permissive, 0o755);
  await assert.rejects(createCoordinatorRelease(stateWriterInput(permissive)), { code: "COORDINATION_COORDINATOR_INVALID" });

  const root = await privateRoot(t);
  const linkedRoot = join(root, "linked-root");
  await symlink(root, linkedRoot);
  await assert.rejects(createCoordinatorRelease(stateWriterInput(linkedRoot)), { code: "COORDINATION_COORDINATOR_INVALID" });
  await symlink("/dev/null", join(root, "coordinator-state.json"));
  await assert.rejects(createCoordinatorRelease(stateWriterInput(root)), { code: "COORDINATION_COORDINATOR_INVALID" });
  await unlink(join(root, "coordinator-state.json"));
  await writeFile(join(root, "coordinator-state.json"), "{}\n", { mode: 0o600 });
  await assert.rejects(createCoordinatorRelease(stateWriterInput(root)), { code: "COORDINATION_COORDINATOR_INVALID" });
});

test("rejects release-root replacement after the directory is pinned", async (t) => {
  const parent = await privateRoot(t);
  const root = join(parent, "release");
  const replacement = join(parent, "replaced-release");
  await mkdir(root, { mode: 0o700 });
  let rootLookups = 0;
  const fileSystem = {
    lstat: async (path) => {
      if (path === root && ++rootLookups === 2) {
        await rename(root, replacement);
        await mkdir(root, { mode: 0o700 });
      }
      return lstat(path);
    },
    open,
    rename,
    unlink,
  };
  await assert.rejects(
    createCoordinatorRelease(stateWriterInput(root, { fileSystem })),
    { code: "COORDINATION_COORDINATOR_INVALID" },
  );
  assert.deepEqual(await readdir(root), []);
});

test("cleans public-state temporary files after write, sync, or rename failure", async (t) => {
  for (const failure of ["write", "sync", "rename"]) {
    const root = await privateRoot(t);
    const fileSystem = {
      lstat,
      open: async (path, flags, mode) => {
        const handle = await open(path, flags, mode);
        if ((flags & fsConstants.O_CREAT) === 0) return handle;
        return {
          close: (...args) => handle.close(...args),
          read: (...args) => handle.read(...args),
          stat: (...args) => handle.stat(...args),
          sync: failure === "sync" ? async () => { throw new Error("sync"); } : (...args) => handle.sync(...args),
          write: failure === "write" ? async () => ({ bytesWritten: 0 }) : (...args) => handle.write(...args),
        };
      },
      rename: failure === "rename" ? async () => { throw new Error("rename"); } : rename,
      unlink,
    };
    await assert.rejects(
      createCoordinatorRelease(stateWriterInput(root, { fileSystem })),
      { code: "COORDINATION_COORDINATOR_INVALID" },
    );
    assert.deepEqual((await readdir(root)).filter((name) => name.startsWith(".")), []);
    await assert.rejects(lstat(join(root, "coordinator-state.json")), { code: "ENOENT" });
  }
});

test("rejects arbitrary step injection instead of treating it as coordination", async () => {
  await assert.rejects(
    runCoordinator({
      release: {
        paymentMoved: false,
        releaseId: "release-a",
        repositorySha: "a".repeat(40),
        schema: COORDINATOR_STATE_SCHEMA,
        sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd",
      },
      steps: [],
    }),
    { code: "COORDINATION_COORDINATOR_INVALID" },
  );
});

test("derives stable funding addresses from a signed canonical enrollment set", async () => {
  const calls = [];
  const payee = await enrollment("payee", 1);
  const payer = await enrollment("payer", 3);
  const set = await enrollmentSetBytes({ payee, payer });
  const release = {
    capabilityDigests: ["a".repeat(64), "b".repeat(64)],
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    schema: COORDINATOR_STATE_SCHEMA,
    sessionId: SESSION_ID,
  };
  const dependency = () => {};
  await runCoordinator({
    dependencies: {
      appendOperatorEvent: async ({ kind }) => coordinationEvent({ eventDigest: kind === "ENROLLMENT_RECEIPT" ? "a".repeat(64) : "b".repeat(64), kind }),
      createTransport: dependency,
      displayAddresses: async (addresses) => calls.push(["display", addresses]),
      launcher: dependency,
      now: () => 0,
      putArtifact: dependency,
      readEnrollmentSet: async () => set,
      readEvents: async () => [],
      readSessionView: async () => ({ facts: { enrollmentConfirmed: { payee: true, payer: true } }, paymentMoved: false }),
      legacyEvents: async () => fundingReplay(),
      readState: async () => null,
      sleeper: dependency,
      verifyMarkerCompleteVerdict: dependency,
      waitForFunding: async (addresses) => {
        calls.push(["fund", addresses]);
        return addresses.map((address) => ({ address, balanceWei: "5000000000000000", nonce: "0", paymentMoved: false }));
      },
      writeState: async ({ state }) => calls.push(["state", state.state]),
    },
    release,
    releaseRoot: "/private/release",
  });
  assert.equal(calls[0][0], "display");
  assert.deepEqual(calls[0][1], [
    payer.invitations.rehearsal.address,
    payee.invitations.rehearsal.address,
    payer.invitations.stakeholder.address,
    payee.invitations.stakeholder.address,
  ]);
});

test("waits for advisory enrollment readiness before reading the authoritative enrollment set", async () => {
  const fixture = signedReplayFixture();
  const payee = await enrollment("payee", 1, fixture.keys.payee);
  const payer = await enrollment("payer", 3, fixture.keys.payer);
  const set = await enrollmentSetBytes({ payee, payer });
  const release = { capabilityDigests: ["a".repeat(64), "b".repeat(64)], paymentMoved: false, releaseId: RELEASE_ID, repositorySha: REPOSITORY_SHA, schema: COORDINATOR_STATE_SCHEMA, sessionId: SESSION_ID };
  let views = 0;
  let enrollmentReads = 0;
  let sleeps = 0;
  const result = await runCoordinatorCore({
    dependencies: {
      ...rawReplayDependencies({ fixture, set }),
      appendOperatorEvent: async ({ artifactDigest, kind, subjectRun }) => fixture.append({ artifactDigest, kind, role: "operator", subjectRun }),
      readEnrollmentSet: async () => {
        enrollmentReads += 1;
        assert.equal(views, 3);
        fixture.append({ role: "payer", kind: "ENROLLMENT_CONFIRMED" });
        fixture.append({ role: "payee", kind: "ENROLLMENT_CONFIRMED" });
        return set;
      },
      readEvents: async () => fixture.events,
      readSessionView: async () => {
        views += 1;
        if (views === 1) return { facts: { enrollmentConfirmed: { payee: false, payer: false } }, paymentMoved: false };
        if (views === 2) return { facts: { enrollmentConfirmed: { payee: false, payer: true } }, paymentMoved: false };
        return { facts: { enrollmentConfirmed: { payee: true, payer: true } }, paymentMoved: false };
      },
      sleeper: async () => { sleeps += 1; },
      waitForFunding: async (addresses) => {
        fixture.append({ kind: "FUNDING_INPUTS_READY", role: "payer" });
        fixture.append({ kind: "FUNDING_INPUTS_READY", role: "payee" });
        fixture.append({ artifactDigest: "1".repeat(64), kind: "TOKEN_READY", role: "payer" });
        fixture.append({ artifactDigest: "2".repeat(64), kind: "TOKEN_READY", role: "payee" });
        return addresses.map((address) => ({ address, balanceWei: "5000000000000000", nonce: "0", paymentMoved: false }));
      },
    },
    release,
    releaseRoot: "/private/release",
  });
  assert.equal(result.state, "FUNDING_READY");
  assert.equal(enrollmentReads, 1);
  assert.equal(sleeps, 2);
});

test("retries advisory enrollment readiness only for a missing session view", async () => {
  const fixture = signedReplayFixture();
  const payee = await enrollment("payee", 1, fixture.keys.payee);
  const payer = await enrollment("payer", 3, fixture.keys.payer);
  const set = await enrollmentSetBytes({ payee, payer });
  const release = { capabilityDigests: ["a".repeat(64), "b".repeat(64)], paymentMoved: false, releaseId: RELEASE_ID, repositorySha: REPOSITORY_SHA, schema: COORDINATOR_STATE_SCHEMA, sessionId: SESSION_ID };
  let views = 0;
  let enrollmentReads = 0;
  let sleeps = 0;
  const missing = new Error("session view not created yet");
  missing.code = "COORDINATION_SESSION_NOT_FOUND";

  const result = await runCoordinatorCore({
    dependencies: {
      ...rawReplayDependencies({ fixture, set }),
      appendOperatorEvent: async ({ artifactDigest, kind, subjectRun }) => fixture.append({ artifactDigest, kind, role: "operator", subjectRun }),
      readEnrollmentSet: async () => {
        enrollmentReads += 1;
        fixture.append({ role: "payer", kind: "ENROLLMENT_CONFIRMED" });
        fixture.append({ role: "payee", kind: "ENROLLMENT_CONFIRMED" });
        return set;
      },
      readEvents: async () => fixture.events,
      readSessionView: async () => {
        views += 1;
        if (views < 3) throw missing;
        return { facts: { enrollmentConfirmed: { payee: true, payer: true } }, paymentMoved: false };
      },
      sleeper: async () => { sleeps += 1; },
      waitForFunding: async (addresses) => {
        fixture.append({ kind: "FUNDING_INPUTS_READY", role: "payer" });
        fixture.append({ kind: "FUNDING_INPUTS_READY", role: "payee" });
        fixture.append({ artifactDigest: "1".repeat(64), kind: "TOKEN_READY", role: "payer" });
        fixture.append({ artifactDigest: "2".repeat(64), kind: "TOKEN_READY", role: "payee" });
        return addresses.map((address) => ({ address, balanceWei: "5000000000000000", nonce: "0", paymentMoved: false }));
      },
    },
    release,
    releaseRoot: "/private/release",
  });

  assert.equal(result.state, "FUNDING_READY");
  assert.equal(views, 3);
  assert.equal(sleeps, 2);
  assert.equal(enrollmentReads, 1);
});

test("does not retry unexpected advisory enrollment readiness errors", async () => {
  const release = { capabilityDigests: ["a".repeat(64), "b".repeat(64)], paymentMoved: false, releaseId: RELEASE_ID, repositorySha: REPOSITORY_SHA, schema: COORDINATOR_STATE_SCHEMA, sessionId: SESSION_ID };
  const set = await enrollmentSetBytes();

  for (const error of [
    Object.assign(new Error("malformed response"), { code: "COORDINATION_OPERATOR_CLIENT_INVALID" }),
    Object.assign(new Error("lost authenticated transport"), { code: "COORDINATION_TRANSPORT_AMBIGUOUS" }),
    new Error("unexpected implementation failure"),
  ]) {
    let views = 0;
    let enrollmentReads = 0;
    let sleeps = 0;
    await assert.rejects(
      runCoordinatorCore({
        dependencies: {
          ...rawReplayDependencies({ fixture: signedReplayFixture(), set }),
          readEnrollmentSet: async () => { enrollmentReads += 1; return set; },
          readSessionView: async () => {
            views += 1;
            throw error;
          },
          sleeper: async () => { sleeps += 1; },
        },
        release,
        releaseRoot: "/private/release",
      }),
      error,
    );
    assert.equal(views, 1);
    assert.equal(enrollmentReads, 0);
    assert.equal(sleeps, 0);
  }
});

test("rejects advisory enrollment readiness when the authoritative set disagrees with signed relay state", async () => {
  const fixture = signedReplayFixture();
  fixture.append({ role: "payer", kind: "ENROLLMENT_CONFIRMED" });
  fixture.append({ role: "payee", kind: "ENROLLMENT_CONFIRMED" });
  const mismatchedSet = await enrollmentSetBytes({
    payee: await enrollment("payee", 1),
    payer: await enrollment("payer", 3),
  });
  const release = { capabilityDigests: ["a".repeat(64), "b".repeat(64)], paymentMoved: false, releaseId: RELEASE_ID, repositorySha: REPOSITORY_SHA, schema: COORDINATOR_STATE_SCHEMA, sessionId: SESSION_ID };

  await assert.rejects(runCoordinatorCore({
    dependencies: {
      ...rawReplayDependencies({ fixture, set: mismatchedSet }),
      readEvents: async () => fixture.events,
      readSessionView: async () => ({ facts: { enrollmentConfirmed: { payee: true, payer: true } }, paymentMoved: false }),
    },
    release,
    releaseRoot: "/private/release",
  }), { code: "COORDINATION_COORDINATOR_INVALID" });
});

test("fails closed when advisory enrollment readiness is malformed, regresses, or times out", async () => {
  const release = { capabilityDigests: ["a".repeat(64), "b".repeat(64)], paymentMoved: false, releaseId: RELEASE_ID, repositorySha: REPOSITORY_SHA, schema: COORDINATOR_STATE_SCHEMA, sessionId: SESSION_ID };
  const set = await enrollmentSetBytes();
  const makeInput = (views, now = (() => 0)) => {
    let viewIndex = 0;
    let enrollmentReads = 0;
    return {
      input: {
        dependencies: {
          ...rawReplayDependencies({ fixture: signedReplayFixture(), set }),
          now,
          readEnrollmentSet: async () => { enrollmentReads += 1; return set; },
          readSessionView: async () => views[Math.min(viewIndex++, views.length - 1)],
          sleeper: async () => {},
        },
        release,
        releaseRoot: "/private/release",
      },
      enrollmentReads: () => enrollmentReads,
    };
  };
  for (const { input, enrollmentReads } of [
    makeInput([{ paymentMoved: false }]),
    makeInput([{ facts: { enrollmentConfirmed: { payee: true, payer: "yes" } }, paymentMoved: false }]),
    makeInput([{ facts: { enrollmentConfirmed: { payee: false, payer: false } }, paymentMoved: false }], (() => { const values = [10, 9]; return () => values.shift() ?? 9; })()),
    makeInput([{ facts: { enrollmentConfirmed: { payee: false, payer: false } }, paymentMoved: false }], (() => { let value = 0; return () => { value += 480001; return value; }; })()),
  ]) {
    await assert.rejects(runCoordinatorCore(input), { code: "COORDINATION_COORDINATOR_INVALID" });
    assert.equal(enrollmentReads(), 0);
  }
});

test("derives funding readiness from fresh signed raw replay without trusting an authenticated-event shortcut", async () => {
  const fixture = signedReplayFixture();
  const set = await enrollmentSetBytes({
    payee: await enrollment("payee", 1, fixture.keys.payee),
    payer: await enrollment("payer", 3, fixture.keys.payer),
  });
  fixture.append({ role: "payer", kind: "ENROLLMENT_CONFIRMED" });
  fixture.append({ role: "payee", kind: "ENROLLMENT_CONFIRMED" });
  fixture.append({ role: "operator", kind: "ENROLLMENT_RECEIPT" });
  fixture.append({ role: "operator", kind: "WAIT_FOR_FUNDING" });
  fixture.append({ role: "payer", kind: "FUNDING_INPUTS_READY" });
  fixture.append({ role: "payee", kind: "FUNDING_INPUTS_READY" });
  fixture.append({ artifactDigest: "1".repeat(64), role: "payer", kind: "TOKEN_READY" });
  fixture.append({ artifactDigest: "2".repeat(64), role: "payee", kind: "TOKEN_READY" });
  const release = { capabilityDigests: ["a".repeat(64), "b".repeat(64)], paymentMoved: false, releaseId: RELEASE_ID, repositorySha: REPOSITORY_SHA, schema: COORDINATOR_STATE_SCHEMA, sessionId: SESSION_ID };
  const result = await runCoordinator({
    dependencies: {
      appendOperatorEvent: async ({ kind }) => coordinationEvent({ eventDigest: kind === "ENROLLMENT_RECEIPT" ? "a".repeat(64) : "b".repeat(64), kind }),
      createTransport: () => {}, displayAddresses: () => {}, launcher: () => {}, now: () => 0, putArtifact: () => {},
      readEnrollmentSet: async () => set, readEvents: async () => fixture.events, readSessionView: async () => ({ facts: { enrollmentConfirmed: { payee: true, payer: true } }, paymentMoved: false }), readState: async () => null,
      readVerifierPublication: async () => null,
      resolveOperatorPublicKey: async () => rawPublicKey(fixture.keys.operator),
      sleeper: () => {}, verifyMarkerCompleteVerdict: () => {}, writeState: () => {},
      waitForFunding: async (addresses) => addresses.map((address) => ({ address, balanceWei: "5000000000000000", nonce: "0", paymentMoved: false })),
    },
    release,
    releaseRoot: "/private/release",
  });
  assert.equal(result.state, "FUNDING_READY");
});

test("waits for authenticated role funding readiness that arrives after the funding check", async () => {
  const fixture = signedReplayFixture();
  const set = await enrollmentSetBytes({
    payee: await enrollment("payee", 1, fixture.keys.payee),
    payer: await enrollment("payer", 3, fixture.keys.payer),
  });
  fixture.append({ role: "payer", kind: "ENROLLMENT_CONFIRMED" });
  fixture.append({ role: "payee", kind: "ENROLLMENT_CONFIRMED" });
  const release = { capabilityDigests: ["a".repeat(64), "b".repeat(64)], paymentMoved: false, releaseId: RELEASE_ID, repositorySha: REPOSITORY_SHA, schema: COORDINATOR_STATE_SCHEMA, sessionId: SESSION_ID };
  let fundingObserved = false;
  let fundingReplayReads = 0;
  let sleeps = 0;
  const result = await runCoordinatorCore({
    dependencies: {
      ...rawReplayDependencies({ fixture, set }),
      appendOperatorEvent: async ({ artifactDigest, kind, subjectRun }) => fixture.append({ artifactDigest, kind, role: "operator", subjectRun }),
      now: () => 0,
      readEvents: async () => {
        if (fundingObserved) fundingReplayReads += 1;
        return fixture.events;
      },
      sleeper: async () => {
        sleeps += 1;
        assert.ok(fundingReplayReads >= 1);
        fixture.append({ artifactDigest: "1".repeat(64), kind: "TOKEN_READY", role: "payer" });
        fixture.append({ artifactDigest: "2".repeat(64), kind: "TOKEN_READY", role: "payee" });
      },
      waitForFunding: async (addresses) => {
        fundingObserved = true;
        fixture.append({ kind: "FUNDING_INPUTS_READY", role: "payer" });
        fixture.append({ kind: "FUNDING_INPUTS_READY", role: "payee" });
        return addresses.map((address) => ({ address, balanceWei: "5000000000000000", nonce: "0", paymentMoved: false }));
      },
    },
    release,
    releaseRoot: "/private/release",
  });
  assert.equal(result.state, "FUNDING_READY");
  assert.equal(sleeps, 1);
  assert.ok(fundingReplayReads >= 2);
});

test("fails closed for hostile signed raw replay keys, chains, digests, and verifier publications", async () => {
  const release = { capabilityDigests: ["a".repeat(64), "b".repeat(64)], paymentMoved: false, releaseId: RELEASE_ID, repositorySha: REPOSITORY_SHA, schema: COORDINATOR_STATE_SCHEMA, sessionId: SESSION_ID };
  const hostile = {
    "wrong role key": async ({ fixture }) => {
      const original = fixture.events[0];
      fixture.events[0] = createCoordinationEnvelope({ artifactDigest: original.artifactDigest, kind: original.kind, paymentMoved: original.paymentMoved, previousEventDigest: original.previousEventDigest, privateKeyPem: privateKeyPem(fixture.keys.operator), publicKey: rawPublicKey(fixture.keys.operator), publicKeyId: "operator-key", releaseId: original.releaseId, repositorySha: original.repositorySha, role: original.role, schema: original.schema, sequence: original.sequence, sessionId: original.sessionId, subjectRun: original.subjectRun });
    },
    "broken sender chain": async ({ fixture }) => fixture.append({ role: "payer", kind: "TOKEN_READY", previousEventDigest: null }),
    "missing payer token": async ({ fixture }) => { fixture.events.splice(fixture.events.findIndex((event) => event.kind === "TOKEN_READY" && event.role === "payer"), 1); },
    "duplicate global digest": async ({ fixture }) => fixture.events.push(fixture.events[0]),
    "verifier publication mismatch": async ({ fixture }) => fixture.append({ artifactDigest: "a".repeat(64), role: "operator", kind: "VERIFICATION_PASSED", subjectRun: "rehearsal" }),
  };
  for (const [label, mutate] of Object.entries(hostile)) {
    const replay = await signedFundingReplay();
    await mutate(replay);
    const verifierPublication = label === "verifier publication mismatch"
      ? { paymentMoved: false, publicationDigest: "b".repeat(64), releaseId: RELEASE_ID, repositorySha: REPOSITORY_SHA, schema: "clockchain.bilateral-verifier-publication/v1", sessionId: SESSION_ID, status: "VERIFICATION_PASSED", subjectRun: "rehearsal" }
      : null;
    await assert.rejects(
      runCoordinator({ dependencies: rawReplayDependencies({ ...replay, verifierPublication }), release, releaseRoot: "/private/release" }),
      { code: "COORDINATION_COORDINATOR_INVALID" },
      label,
    );
  }
});

test("adopts replayed operator funding gates after a lost append response", async () => {
  const replay = await signedFundingReplay();
  const release = { capabilityDigests: ["a".repeat(64), "b".repeat(64)], paymentMoved: false, releaseId: RELEASE_ID, repositorySha: REPOSITORY_SHA, schema: COORDINATOR_STATE_SCHEMA, sessionId: SESSION_ID };
  let appends = 0;
  const result = await runCoordinator({
    dependencies: {
      ...rawReplayDependencies(replay),
      appendOperatorEvent: async () => { appends += 1; throw new Error("lost response must be adopted"); },
      readState: async () => ({ ...release, checkpoints: [], state: "ADDRESSES_READY" }),
      waitForFunding: async (addresses) => addresses.map((address) => ({ address, balanceWei: "5000000000000000", nonce: "0", paymentMoved: false })),
    },
    release,
    releaseRoot: "/private/release",
  });
  assert.equal(result.state, "FUNDING_READY");
  assert.equal(appends, 0);
});

test("polls fresh signed identity packages after persisting a new registration", async () => {
  const fixture = signedReplayFixture();
  const payee = await enrollment("payee", 1, fixture.keys.payee);
  const payer = await enrollment("payer", 3, fixture.keys.payer);
  const set = await enrollmentSetBytes({ payee, payer });
  const append = (role, kind, artifactDigest = null, subjectRun = "release") => fixture.append({ artifactDigest, kind, role, subjectRun });
  append("payer", "ENROLLMENT_CONFIRMED"); append("payee", "ENROLLMENT_CONFIRMED"); append("operator", "ENROLLMENT_RECEIPT"); append("operator", "WAIT_FOR_FUNDING"); append("payer", "FUNDING_INPUTS_READY"); append("payee", "FUNDING_INPUTS_READY"); append("payer", "TOKEN_READY", "a".repeat(64)); append("payee", "TOKEN_READY", "b".repeat(64));
  const plan = append("operator", "PREFLIGHT_PLAN_READY", "1".repeat(64)); append("payer", "PREFLIGHT_PARTICIPANT_READY", "2".repeat(64)); append("payee", "PREFLIGHT_PARTICIPANT_READY", "3".repeat(64));
  const release = { capabilityDigests: ["a".repeat(64), "b".repeat(64)], paymentMoved: false, releaseId: RELEASE_ID, repositorySha: REPOSITORY_SHA, schema: COORDINATOR_STATE_SCHEMA, sessionId: SESSION_ID };
  const aggregate = "4".repeat(64); let registrations = 0; let waits = 0; const states = [];
  const result = await runCoordinatorCore({ dependencies: {
    ...rawReplayDependencies({ fixture, set }),
    appendOperatorEvent: async ({ kind, subjectRun, artifactDigest }) => { registrations += 1; return append("operator", kind, artifactDigest, subjectRun); },
    getArtifact: async ({ digest }) => Buffer.from(digest),
    validateArtifact: async ({ expectedDigest }) => ({ digest: expectedDigest, facts: { identity: { address: expectedDigest === "5".repeat(64) ? payer.invitations.rehearsal.address : payee.invitations.rehearsal.address, repositorySha: REPOSITORY_SHA } } }),
    readState: async () => ({ ...release, checkpoints: [
      { action: "ENROLLMENT_RECEIPT", artifactDigest: null, eventDigest: fixture.events.find((event) => event.kind === "ENROLLMENT_RECEIPT").eventDigest, role: "operator", status: "EVENT_APPENDED", subjectRun: "release" },
      { action: "WAIT_FOR_FUNDING", artifactDigest: null, eventDigest: fixture.events.find((event) => event.kind === "WAIT_FOR_FUNDING").eventDigest, role: "operator", status: "EVENT_APPENDED", subjectRun: "release" },
      { action: "PREFLIGHT_PLAN", artifactDigest: plan.artifactDigest, eventDigest: plan.eventDigest, role: "operator", status: "EVENT_APPENDED", subjectRun: "release" },
      { action: "PREFLIGHT_AGGREGATE", artifactDigest: aggregate, eventDigest: null, role: "operator", status: "ARTIFACT_STORED", subjectRun: "release" },
    ], state: "PREFLIGHT_PASSED" }),
    waitForIdentityPackage: async () => { waits += 1; append("payer", "IDENTITY_PACKAGE_READY", "5".repeat(64), "rehearsal"); append("payee", "IDENTITY_PACKAGE_READY", "6".repeat(64), "rehearsal"); },
    writeState: async ({ state }) => states.push(state),
  }, release, releaseRoot: "/private/release" });
  assert.equal(registrations, 1); assert.equal(waits, 1); assert.equal(result.state, "REHEARSAL_IDENTITIES_READY");
  assert.equal(states.at(-1).checkpoints.filter((item) => item.action === "IDENTITY_PACKAGE").length, 2);
});

test("recreates a completed descriptor locally before its first relay upload", async () => {
  const fixture = signedReplayFixture();
  const set = await enrollmentSetBytes({
    payee: await enrollment("payee", 1, fixture.keys.payee),
    payer: await enrollment("payer", 3, fixture.keys.payer),
  });
  const append = (role, kind, artifactDigest = null, subjectRun = "release") =>
    fixture.append({ artifactDigest, kind, role, subjectRun });
  append("payer", "ENROLLMENT_CONFIRMED");
  append("payee", "ENROLLMENT_CONFIRMED");
  const enrollmentReceipt = append("operator", "ENROLLMENT_RECEIPT");
  const funding = append("operator", "WAIT_FOR_FUNDING");
  append("payer", "FUNDING_INPUTS_READY");
  append("payee", "FUNDING_INPUTS_READY");
  append("payer", "TOKEN_READY", "a".repeat(64));
  append("payee", "TOKEN_READY", "b".repeat(64));
  const plan = append("operator", "PREFLIGHT_PLAN_READY", "1".repeat(64));
  append("payer", "PREFLIGHT_PARTICIPANT_READY", "2".repeat(64));
  append("payee", "PREFLIGHT_PARTICIPANT_READY", "3".repeat(64));
  const registration = append("operator", "REGISTER_REHEARSAL", "4".repeat(64), "rehearsal");
  const payerIdentity = append("payer", "IDENTITY_PACKAGE_READY", "5".repeat(64), "rehearsal");
  const payeeIdentity = append("payee", "IDENTITY_PACKAGE_READY", "6".repeat(64), "rehearsal");
  append("payer", "PAYER_MANDATE_READY", "c".repeat(64), "rehearsal");
  append("payee", "PAYMENT_REQUEST_READY", "d".repeat(64), "rehearsal");
  append("payer", "PAYMENT_REQUEST_MATCHED", null, "rehearsal");
  const descriptorBytes = stableBytes({ descriptor: "recreated" });
  const descriptorDigest = sha256(descriptorBytes);
  const release = {
    capabilityDigests: ["a".repeat(64), "b".repeat(64)],
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    schema: COORDINATOR_STATE_SCHEMA,
    sessionId: SESSION_ID,
  };
  const persisted = {
    ...release,
    checkpoints: [
      { action: "ENROLLMENT_RECEIPT", artifactDigest: null, eventDigest: enrollmentReceipt.eventDigest, role: "operator", status: "EVENT_APPENDED", subjectRun: "release" },
      { action: "WAIT_FOR_FUNDING", artifactDigest: null, eventDigest: funding.eventDigest, role: "operator", status: "EVENT_APPENDED", subjectRun: "release" },
      { action: "PREFLIGHT_PLAN", artifactDigest: plan.artifactDigest, eventDigest: plan.eventDigest, role: "operator", status: "EVENT_APPENDED", subjectRun: "release" },
      { action: "REGISTER_REHEARSAL", artifactDigest: registration.artifactDigest, eventDigest: registration.eventDigest, role: "operator", status: "EVENT_APPENDED", subjectRun: "rehearsal" },
      { action: "IDENTITY_PACKAGE", artifactDigest: payerIdentity.artifactDigest, eventDigest: payerIdentity.eventDigest, role: "payer", status: "EVENT_APPENDED", subjectRun: "rehearsal" },
      { action: "IDENTITY_PACKAGE", artifactDigest: payeeIdentity.artifactDigest, eventDigest: payeeIdentity.eventDigest, role: "payee", status: "EVENT_APPENDED", subjectRun: "rehearsal" },
      { action: "REHEARSAL_DESCRIPTOR", artifactDigest: descriptorDigest, eventDigest: null, role: "operator", status: "CHILD_COMPLETE", subjectRun: "rehearsal" },
    ],
    state: "REHEARSAL_IDENTITIES_READY",
  };
  let descriptorCreates = 0;
  let relayReads = 0;
  let uploaded = null;
  const result = await runCoordinatorCore({
    dependencies: {
      ...rawReplayDependencies({ fixture, set }),
      appendOperatorEvent: async ({ artifactDigest, kind, subjectRun }) => {
        const ready = append("operator", kind, artifactDigest, subjectRun);
        append("payer", "DESCRIPTOR_ACCEPTED", artifactDigest, subjectRun);
        append("payee", "DESCRIPTOR_ACCEPTED", artifactDigest, subjectRun);
        return ready;
      },
      appendVerifiedEvent: async () => {},
      createDescriptor: async () => {
        descriptorCreates += 1;
        return descriptorBytes;
      },
      createVerifiedEvent: async () => {},
      getArtifact: async () => {
        relayReads += 1;
        assert.fail("a completed local descriptor must not be read from the relay before upload");
      },
      launchVerifier: async () => {},
      putArtifact: async ({ bytes, expectedDigest }) => {
        uploaded = Buffer.from(bytes);
        return { digest: expectedDigest };
      },
      readState: async () => persisted,
      startRole: async () => {},
      startWatcher: async () => {},
      validateArtifact: async ({ expectedDigest }) => ({
        digest: expectedDigest,
        facts: {
          descriptor: {
            paymentMoved: false,
            repositorySha: REPOSITORY_SHA,
            sessionId: "0".repeat(32),
          },
        },
      }),
      validatePublishedBilateralVerdict: async () => {},
      validateRehearsalPackage: async () => {},
      waitForDescriptorAcceptance: async () => {},
      waitForRolePackage: async () => {},
      waitForRoleStarted: async () => {},
    },
    release,
    releaseRoot: "/private/release",
  });
  assert.equal(result.state, "REHEARSAL_DESCRIPTOR_READY");
  assert.equal(descriptorCreates, 1);
  assert.equal(relayReads, 0);
  assert.deepEqual(uploaded, descriptorBytes);
});

test("adopts signed replayed role starts before a coordinator can launch either role again", async () => {
  const fixture = signedReplayFixture();
  const set = await enrollmentSetBytes({ payee: await enrollment("payee", 1, fixture.keys.payee), payer: await enrollment("payer", 3, fixture.keys.payer) });
  const append = (role, kind, artifactDigest = null, subjectRun = "release") => fixture.append({ artifactDigest, kind, role, subjectRun });
  append("payer", "ENROLLMENT_CONFIRMED"); append("payee", "ENROLLMENT_CONFIRMED");
  append("operator", "ENROLLMENT_RECEIPT"); append("operator", "WAIT_FOR_FUNDING");
  append("payer", "FUNDING_INPUTS_READY"); append("payee", "FUNDING_INPUTS_READY");
  append("payer", "TOKEN_READY", "a".repeat(64)); append("payee", "TOKEN_READY", "b".repeat(64));
  append("operator", "PREFLIGHT_PLAN_READY", "1".repeat(64));
  append("payer", "PREFLIGHT_PARTICIPANT_READY", "2".repeat(64)); append("payee", "PREFLIGHT_PARTICIPANT_READY", "3".repeat(64));
  append("operator", "REGISTER_REHEARSAL", "4".repeat(64), "rehearsal");
  append("payer", "IDENTITY_PACKAGE_READY", "5".repeat(64), "rehearsal"); append("payee", "IDENTITY_PACKAGE_READY", "6".repeat(64), "rehearsal");
  const descriptor = append("operator", "REHEARSAL_DESCRIPTOR_READY", "7".repeat(64), "rehearsal");
  append("payer", "DESCRIPTOR_ACCEPTED", "7".repeat(64), "rehearsal"); append("payee", "DESCRIPTOR_ACCEPTED", "7".repeat(64), "rehearsal");
  append("operator", "START_REHEARSAL", null, "rehearsal");
  append("payee", "ROLE_STARTED", null, "rehearsal"); append("payer", "ROLE_STARTED", null, "rehearsal");
  const release = { capabilityDigests: ["a".repeat(64), "b".repeat(64)], paymentMoved: false, releaseId: RELEASE_ID, repositorySha: REPOSITORY_SHA, schema: COORDINATOR_STATE_SCHEMA, sessionId: SESSION_ID };
  let starts = 0;
  const result = await runCoordinatorCore({
    dependencies: {
      ...rawReplayDependencies({ fixture, set }),
      readState: async () => ({ ...release, checkpoints: [{ action: "REHEARSAL_DESCRIPTOR", artifactDigest: descriptor.artifactDigest, eventDigest: descriptor.eventDigest, role: "operator", status: "EVENT_APPENDED", subjectRun: "rehearsal" }], state: "REHEARSAL_DESCRIPTOR_READY" }),
      startRole: async () => { starts += 1; },
    }, release, releaseRoot: "/private/release",
  });
  assert.equal(starts, 0);
  assert.equal(result.state, "REHEARSAL_DESCRIPTOR_READY");
  assert.ok(result.checkpoints.some((item) => item.action === "PAYEE_ROLE_START" && item.status === "CHILD_COMPLETE"));
  assert.ok(result.checkpoints.some((item) => item.action === "PAYER_ROLE_START" && item.status === "CHILD_COMPLETE"));
  assert.ok(result.checkpoints.filter((item) => item.action === "ROLE_STARTED" && item.status === "EVENT_APPENDED").length === 2);
});

test("replay adoption descriptor-binds starts and resumes the rehearsal on a second pass", async () => {
  const fixture = signedReplayFixture();
  const set = await enrollmentSetBytes({ payee: await enrollment("payee", 1, fixture.keys.payee), payer: await enrollment("payer", 3, fixture.keys.payer) });
  const append = (role, kind, artifactDigest = null, subjectRun = "release") => fixture.append({ artifactDigest, kind, role, subjectRun });
  append("payer", "ENROLLMENT_CONFIRMED"); append("payee", "ENROLLMENT_CONFIRMED");
  append("operator", "ENROLLMENT_RECEIPT"); append("operator", "WAIT_FOR_FUNDING");
  append("payer", "FUNDING_INPUTS_READY"); append("payee", "FUNDING_INPUTS_READY");
  append("payer", "TOKEN_READY", "a".repeat(64)); append("payee", "TOKEN_READY", "b".repeat(64));
  append("operator", "PREFLIGHT_PLAN_READY", "1".repeat(64));
  append("payer", "PREFLIGHT_PARTICIPANT_READY", "2".repeat(64)); append("payee", "PREFLIGHT_PARTICIPANT_READY", "3".repeat(64));
  append("operator", "REGISTER_REHEARSAL", "4".repeat(64), "rehearsal");
  append("payer", "IDENTITY_PACKAGE_READY", "5".repeat(64), "rehearsal"); append("payee", "IDENTITY_PACKAGE_READY", "6".repeat(64), "rehearsal");
  const descriptor = append("operator", "REHEARSAL_DESCRIPTOR_READY", "7".repeat(64), "rehearsal");
  append("payer", "DESCRIPTOR_ACCEPTED", descriptor.artifactDigest, "rehearsal"); append("payee", "DESCRIPTOR_ACCEPTED", descriptor.artifactDigest, "rehearsal");
  append("operator", "START_REHEARSAL", null, "rehearsal");
  append("payee", "ROLE_STARTED", null, "rehearsal"); append("payer", "ROLE_STARTED", null, "rehearsal");
  const release = { capabilityDigests: ["a".repeat(64), "b".repeat(64)], paymentMoved: false, releaseId: RELEASE_ID, repositorySha: REPOSITORY_SHA, schema: COORDINATOR_STATE_SCHEMA, sessionId: SESSION_ID };
  let persisted = { ...release, checkpoints: [{ action: "REHEARSAL_DESCRIPTOR", artifactDigest: descriptor.artifactDigest, eventDigest: descriptor.eventDigest, role: "operator", status: "EVENT_APPENDED", subjectRun: "rehearsal" }], state: "REHEARSAL_DESCRIPTOR_READY" };
  let starts = 0;
  const dependencies = {
    ...rawReplayDependencies({ fixture, set }),
    appendVerifiedEvent: async () => {}, createDescriptor: async () => {}, createVerifiedEvent: async () => {}, launchVerifier: async () => {}, startWatcher: async () => {}, validatePublishedBilateralVerdict: async () => {}, waitForDescriptorAcceptance: async () => {}, waitForRoleStarted: async () => {},
    getArtifact: async ({ digest }) => Buffer.from(digest),
    readState: async () => persisted,
    startRole: async () => { starts += 1; },
    validateArtifact: async ({ expectedDigest }) => ({ digest: expectedDigest, facts: { partyResult: { paymentMoved: false, repositorySha: REPOSITORY_SHA, role: expectedDigest === "8".repeat(64) ? "payee" : "payer", sessionDigest: "9".repeat(64) } } }),
    validateRehearsalPackage: async () => true,
    waitForRolePackage: async ({ role }) => append(role, "ROLE_PACKAGE_READY", role === "payee" ? "8".repeat(64) : "9".repeat(64), "rehearsal"),
    writeState: async ({ state }) => { persisted = state; },
  };
  const adopted = await runCoordinatorCore({ dependencies, release, releaseRoot: "/private/release" });
  assert.equal(adopted.checkpoints.find((item) => item.action === "START_REHEARSAL").artifactDigest, descriptor.artifactDigest);
  assert.deepEqual(adopted.checkpoints.filter((item) => item.action === "ROLE_STARTED").map((item) => item.artifactDigest), [descriptor.artifactDigest, descriptor.artifactDigest]);
  const resumed = await runCoordinatorCore({ dependencies, release, releaseRoot: "/private/release" });
  assert.equal(resumed.state, "REHEARSAL_PACKAGES_READY");
  assert.equal(starts, 0);
});

test("rejects EVENT_APPENDED checkpoints that disagree with canonical replay bindings", async () => {
  const fixture = signedReplayFixture();
  const set = await enrollmentSetBytes({ payee: await enrollment("payee", 1, fixture.keys.payee), payer: await enrollment("payer", 3, fixture.keys.payer) });
  const append = (role, kind, artifactDigest = null, subjectRun = "release") => fixture.append({ artifactDigest, kind, role, subjectRun });
  append("payer", "ENROLLMENT_CONFIRMED"); append("payee", "ENROLLMENT_CONFIRMED"); append("operator", "ENROLLMENT_RECEIPT"); append("operator", "WAIT_FOR_FUNDING"); append("payer", "FUNDING_INPUTS_READY"); append("payee", "FUNDING_INPUTS_READY"); append("payer", "TOKEN_READY", "a".repeat(64)); append("payee", "TOKEN_READY", "b".repeat(64)); append("operator", "PREFLIGHT_PLAN_READY", "1".repeat(64)); append("payer", "PREFLIGHT_PARTICIPANT_READY", "2".repeat(64)); append("payee", "PREFLIGHT_PARTICIPANT_READY", "3".repeat(64)); append("operator", "REGISTER_REHEARSAL", "4".repeat(64), "rehearsal"); append("payer", "IDENTITY_PACKAGE_READY", "5".repeat(64), "rehearsal"); append("payee", "IDENTITY_PACKAGE_READY", "6".repeat(64), "rehearsal");
  const descriptor = append("operator", "REHEARSAL_DESCRIPTOR_READY", "7".repeat(64), "rehearsal"); append("payer", "DESCRIPTOR_ACCEPTED", descriptor.artifactDigest, "rehearsal"); append("payee", "DESCRIPTOR_ACCEPTED", descriptor.artifactDigest, "rehearsal"); const start = append("operator", "START_REHEARSAL", null, "rehearsal"); const roleStarted = append("payee", "ROLE_STARTED", null, "rehearsal");
  const release = { capabilityDigests: ["a".repeat(64), "b".repeat(64)], paymentMoved: false, releaseId: RELEASE_ID, repositorySha: REPOSITORY_SHA, schema: COORDINATOR_STATE_SCHEMA, sessionId: SESSION_ID };
  const descriptorCheckpoint = { action: "REHEARSAL_DESCRIPTOR", artifactDigest: descriptor.artifactDigest, eventDigest: descriptor.eventDigest, role: "operator", status: "EVENT_APPENDED", subjectRun: "rehearsal" };
  for (const forged of [
    { action: "START_REHEARSAL", artifactDigest: descriptor.artifactDigest, eventDigest: descriptor.eventDigest, role: "operator", status: "EVENT_APPENDED", subjectRun: "rehearsal" },
    { action: "START_REHEARSAL", artifactDigest: null, eventDigest: start.eventDigest, role: "operator", status: "EVENT_APPENDED", subjectRun: "rehearsal" },
    { action: "ROLE_STARTED", artifactDigest: null, eventDigest: roleStarted.eventDigest, role: "payee", status: "EVENT_APPENDED", subjectRun: "rehearsal" },
  ]) {
    await assert.rejects(runCoordinatorCore({ dependencies: { ...rawReplayDependencies({ fixture, set }), readState: async () => ({ ...release, checkpoints: [descriptorCheckpoint, forged], state: "REHEARSAL_DESCRIPTOR_READY" }) }, release, releaseRoot: "/private/release" }), { code: "COORDINATION_COORDINATOR_INVALID" });
  }
});

test("reconciles persisted payee and payer launch intents before invoking either child", async () => {
  const fixture = signedReplayFixture();
  const set = await enrollmentSetBytes({ payee: await enrollment("payee", 1, fixture.keys.payee), payer: await enrollment("payer", 3, fixture.keys.payer) });
  const append = (role, kind, artifactDigest = null, subjectRun = "release") => fixture.append({ artifactDigest, kind, role, subjectRun });
  append("payer", "ENROLLMENT_CONFIRMED"); append("payee", "ENROLLMENT_CONFIRMED"); append("operator", "ENROLLMENT_RECEIPT"); append("operator", "WAIT_FOR_FUNDING"); append("payer", "FUNDING_INPUTS_READY"); append("payee", "FUNDING_INPUTS_READY"); append("payer", "TOKEN_READY"); append("payee", "TOKEN_READY"); append("operator", "PREFLIGHT_PLAN_READY", "1".repeat(64)); append("payer", "PREFLIGHT_PARTICIPANT_READY", "2".repeat(64)); append("payee", "PREFLIGHT_PARTICIPANT_READY", "3".repeat(64)); append("operator", "REGISTER_REHEARSAL", "4".repeat(64), "rehearsal"); append("payer", "IDENTITY_PACKAGE_READY", "5".repeat(64), "rehearsal"); append("payee", "IDENTITY_PACKAGE_READY", "6".repeat(64), "rehearsal");
  const descriptor = append("operator", "REHEARSAL_DESCRIPTOR_READY", "7".repeat(64), "rehearsal"); append("payer", "DESCRIPTOR_ACCEPTED", "7".repeat(64), "rehearsal"); append("payee", "DESCRIPTOR_ACCEPTED", "7".repeat(64), "rehearsal"); const beforeRoles = [...fixture.events]; const start = append("operator", "START_REHEARSAL", null, "rehearsal"); append("payee", "ROLE_STARTED", null, "rehearsal"); append("payer", "ROLE_STARTED", null, "rehearsal");
  const release = { capabilityDigests: ["a".repeat(64), "b".repeat(64)], paymentMoved: false, releaseId: RELEASE_ID, repositorySha: REPOSITORY_SHA, schema: COORDINATOR_STATE_SCHEMA, sessionId: SESSION_ID };
  const checkpoint = (action, role, subjectRun, kind) => {
    const event = beforeRoles.find((item) => item.kind === kind && item.role === role && item.subjectRun === subjectRun);
    return { action, artifactDigest: event.artifactDigest, eventDigest: event.eventDigest, role, status: "EVENT_APPENDED", subjectRun };
  };
  const persistedCheckpoints = [
    checkpoint("ENROLLMENT_RECEIPT", "operator", "release", "ENROLLMENT_RECEIPT"),
    checkpoint("WAIT_FOR_FUNDING", "operator", "release", "WAIT_FOR_FUNDING"),
    checkpoint("PREFLIGHT_PLAN", "operator", "release", "PREFLIGHT_PLAN_READY"),
    checkpoint("REGISTER_REHEARSAL", "operator", "rehearsal", "REGISTER_REHEARSAL"),
    checkpoint("IDENTITY_PACKAGE", "payer", "rehearsal", "IDENTITY_PACKAGE_READY"),
    checkpoint("IDENTITY_PACKAGE", "payee", "rehearsal", "IDENTITY_PACKAGE_READY"),
    { action: "REHEARSAL_DESCRIPTOR", artifactDigest: descriptor.artifactDigest, eventDigest: descriptor.eventDigest, role: "operator", status: "EVENT_APPENDED", subjectRun: "rehearsal" },
    { action: "PAYEE_ROLE_START", artifactDigest: descriptor.artifactDigest, eventDigest: null, role: "payee", status: "BEFORE_CHILD", subjectRun: "rehearsal" },
    { action: "PAYER_ROLE_START", artifactDigest: descriptor.artifactDigest, eventDigest: null, role: "payer", status: "BEFORE_CHILD", subjectRun: "rehearsal" },
  ];
  let reads = 0; let starts = 0; const states = [];
  await assert.rejects(runCoordinatorCore({ dependencies: {
    ...rawReplayDependencies({ fixture, set }),
    appendVerifiedEvent: async () => {}, createDescriptor: async () => {}, createVerifiedEvent: async () => {},
    launchVerifier: async () => {}, startWatcher: async () => {}, validatePublishedBilateralVerdict: async () => {},
    waitForDescriptorAcceptance: async () => {}, waitForRoleStarted: async () => {},
    readEvents: async () => (++reads === 1 ? beforeRoles : fixture.events),
    readState: async () => ({ ...release, checkpoints: persistedCheckpoints, state: "REHEARSAL_DESCRIPTOR_READY" }),
    startRole: async () => { starts += 1; },
    waitForRolePackage: async () => { throw new Error("packages intentionally absent"); },
    writeState: async ({ state }) => states.push(state),
  }, release, releaseRoot: "/private/release" }), /packages intentionally absent/);
  assert.equal(starts, 0);
  const adopted = states.at(-1);
  assert.equal(adopted.checkpoints.filter((item) => item.action === "ROLE_STARTED" && item.status === "EVENT_APPENDED").length, 2);
  assert.equal(adopted.checkpoints.filter((item) => /ROLE_START$/.test(item.action) && item.status === "CHILD_COMPLETE").length, 2);
});

test("rejects raw-mode local state that is ahead of or divergent from replay", async () => {
  const replay = await signedFundingReplay();
  const release = { capabilityDigests: ["a".repeat(64), "b".repeat(64)], paymentMoved: false, releaseId: RELEASE_ID, repositorySha: REPOSITORY_SHA, schema: COORDINATOR_STATE_SCHEMA, sessionId: SESSION_ID };
  for (const persisted of [
    { ...release, checkpoints: [], state: "PREFLIGHT_PASSED" },
    { ...release, checkpoints: [{ action: "ENROLLMENT_RECEIPT", artifactDigest: null, eventDigest: "f".repeat(64), role: "operator", status: "EVENT_APPENDED", subjectRun: "release" }], state: "ADDRESSES_READY" },
  ]) {
    await assert.rejects(runCoordinator({
      dependencies: { ...rawReplayDependencies(replay), readState: async () => persisted },
      release,
      releaseRoot: "/private/release",
    }), { code: "COORDINATION_COORDINATOR_INVALID" });
  }
});

test("rejects every malformed funding result before FUNDING_READY", async () => {
  const set = await enrollmentSetBytes();
  const addresses = ["0x1", "0x2", "0x3", "0x4"];
  const makeInput = (funding, states) => ({
    dependencies: {
      appendOperatorEvent: async ({ kind }) => coordinationEvent({ eventDigest: kind === "ENROLLMENT_RECEIPT" ? "a".repeat(64) : "b".repeat(64), kind }), createTransport: () => {}, displayAddresses: () => {}, launcher: () => {}, now: () => 0, putArtifact: () => {},
      readEnrollmentSet: async () => set, readEvents: async () => [], readSessionView: async () => ({ facts: { enrollmentConfirmed: { payee: true, payer: true } }, paymentMoved: false }), readState: async () => null,
      legacyEvents: async () => fundingReplay(),
      sleeper: () => {}, verifyMarkerCompleteVerdict: () => {}, waitForFunding: async (actual) => funding(actual), writeState: async ({ state }) => states.push(state.state),
    },
    release: { capabilityDigests: ["a".repeat(64), "b".repeat(64)], paymentMoved: false, releaseId: RELEASE_ID, repositorySha: REPOSITORY_SHA, schema: COORDINATOR_STATE_SCHEMA, sessionId: SESSION_ID }, releaseRoot: "/private/release",
  });
  const valid = (actual) => actual.map((address) => ({ address, balanceWei: "5000000000000000", nonce: "0", paymentMoved: false }));
  const hostile = [
    (rows) => rows.slice(0, 3),
    (rows) => [...rows, rows[0]],
    (rows) => rows.map((row, index) => index === 0 ? { ...row, balanceWei: "4999999999999999" } : row),
    (rows) => rows.map((row, index) => index === 0 ? { ...row, balanceWei: "20000000000000001" } : row),
    (rows) => rows.map((row, index) => index === 0 ? { ...row, balanceWei: 5000000000000000 } : row),
    (rows) => rows.map((row, index) => index === 0 ? { ...row, nonce: "1" } : row),
    (rows) => rows.map((row, index) => index === 0 ? { ...row, nonce: 0 } : row),
    (rows) => rows.map((row, index) => index === 0 ? { ...row, address: rows[1].address } : row),
    (rows) => rows.map((row, index) => index === 0 ? { balanceWei: row.balanceWei, nonce: row.nonce, paymentMoved: row.paymentMoved } : row),
    (rows) => rows.map((row, index) => index === 0 ? { ...row, extra: false } : row),
    (rows) => rows.map((row, index) => index === 0 ? { ...row, paymentMoved: true } : row),
  ];
  for (const mutate of hostile) {
    const states = [];
    await assert.rejects(runCoordinator(makeInput((actual) => mutate(valid(actual)), states)), { code: "COORDINATION_COORDINATOR_INVALID" });
    assert.equal(states.includes("FUNDING_READY"), false);
  }
});
