import { readLaunchManifest } from "./manifest.mjs";
import { createHash, createPublicKey, sign } from "node:crypto";
import { dirname } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { verifyCoordinationEnvelope } from "./envelope.mjs";
import { coordinationEnrollmentSignaturePreimage, parseCoordinationEnrollment, parseCoordinationEnrollmentSet, verifyCoordinationEnrollment } from "./enrollment.mjs";
import { initialReleaseView, reduceReleaseEvent } from "./lifecycle.mjs";
import { canonicalBytes } from "../canonical.mjs";
import { canonicalizeReceiptEventValue } from "../../canonical.mjs";
import { validateRelayArtifact as defaultValidateRelayArtifact } from "./artifact.mjs";
import { validateRelayArtifactWithFacts as defaultValidateRelayArtifactWithFacts } from "./artifact.mjs";
import { readAndSignTokenCommitment as defaultReadAndSignTokenCommitment, verifyTokenCommitment } from "./preflight.mjs";
import { payerMandateDigest, verifyPayerMandate } from "../payer-mandate.mjs";
import { paymentRequestDigest, verifyPaymentRequest } from "../payment-request.mjs";

export const SUPERVISOR_STATE_SCHEMA = "clockchain.bilateral-supervisor-state/v1";
export const SUPERVISOR_COMMAND_POLICY = Object.freeze({
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
const FULL_CHECKPOINT_PHASES = new Set(["BOOTSTRAPPED_ACTIVE", "ENROLLMENT_CONFIRMING", "VERIFYING_FUNDING_INPUTS", "TOKEN_COMMITMENT_PREPARING", "TOKEN_READY", "DESCRIPTOR_WRITING", "DESCRIPTOR_ACCEPTED", "BEFORE_CHILD", "CHILD_COMPLETE", "ARTIFACT_STORED", "EVENT_APPENDED", "RECOVERY_REQUIRED", "TERMINAL_FAILURE", "EVENT_PROCESSED", "TRANSITION_COMPLETE", "ABORTED"]);
const DURABLE_CHECKPOINT_KEYS = new Set(["activeLaunchState", "authenticatedEvents", "childJournal", "coordinationIdentity", "descriptorJournal", "enrollmentBase64", "enrollmentSet", "events", "eventDigest", "failureSummaryDigest", "intentJournal", "invitations", "operatorPublicKey", "paymentMoved", "phase", "preflight", "processedEventDigests", "receipt", "recovery", "rehearsal", "releaseId", "repositorySha", "role", "schema", "senderState", "sessionId", "stateRoot", "stakeholder", "tokenCommitment", "tokenPath", "view"]);
const CHILD_JOURNAL_PHASES = new Set(["BEFORE_CHILD", "CHILD_COMPLETE", "ARTIFACT_STORED", "EVENT_APPENDED", "TRANSITION_COMPLETE"]);
const TOKEN_BOUND_PHASES = new Set(["TOKEN_READY", "DESCRIPTOR_WRITING", "DESCRIPTOR_ACCEPTED", "BEFORE_CHILD", "CHILD_COMPLETE", "ARTIFACT_STORED", "EVENT_APPENDED", "RECOVERY_REQUIRED", "TRANSITION_COMPLETE"]);
const ENROLLMENT_READINESS_SCHEMA = "clockchain.bilateral-enrollment-readiness/v1";

function invalid() { throw new Error("Coordination supervisor operation failed safely."); }
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const same = (left, right) => isDeepStrictEqual(left, right);
function exact(value, keys) { return value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key)); }
function dataExact(value, keys) { return exact(value, keys) && keys.every((key) => { const descriptor = Object.getOwnPropertyDescriptor(value, key); return descriptor?.enumerable === true && Object.hasOwn(descriptor, "value"); }); }
function assertEnrollmentReadiness(value, localState) {
  if (!dataExact(value, ["paymentMoved", "ready", "releaseId", "repositorySha", "schema", "sessionId"]) || value.schema !== ENROLLMENT_READINESS_SCHEMA || value.paymentMoved !== false || typeof value.ready !== "boolean" || value.releaseId !== localState.releaseId || value.repositorySha !== localState.repositorySha || value.sessionId !== localState.sessionId) invalid();
  return value.ready;
}
function publicState({ activeLaunchState, coordinationIdentity, enrollmentBase64, invitations, phase, preflight, receipt, rehearsal, stateRoot, stakeholder, ...base }) { return Object.freeze({ ...base, activeLaunchState, phase, receipt }); }
function safePrivateRoot(stateRoot) {
  if (typeof stateRoot !== "string" || !/^\/(?:[^/]+\/)*[^/]+$/.test(stateRoot) || stateRoot.includes("/../") || stateRoot.endsWith("/..")) invalid();
  return stateRoot;
}
function fixedRoleArtifacts(stateRoot, invitations) {
  const root = safePrivateRoot(stateRoot);
  const byRun = Object.fromEntries(invitations.map((invitation) => [invitation.subjectRun, invitation]));
  return Object.freeze(Object.fromEntries(["rehearsal", "stakeholder"].map((run) => {
    const invitation = byRun[run];
    if (!invitation || typeof invitation.secretPath !== "string" || !/^\/(?:[^/]+\/)*[^/]+$/.test(invitation.secretPath) || invitation.secretPath.includes("/../") || invitation.secretPath.endsWith("/..")) invalid();
    return [run, Object.freeze({ descriptorPath: `${root}/${run}/descriptor.json`, identityDirectory: `${root}/${run}/identity`, invitationPath: invitation.secretPath, resultDirectory: `${root}/${run}/result` })];
  })));
}
function matchingCoordinationIdentity(identity, enrollment) {
  try {
    return exact(identity, ["keyId", "privateKeyPem", "publicKey"])
      && identity.keyId === enrollment.coordinationKey.keyId
      && identity.publicKey === enrollment.coordinationKey.publicKey
      && createPublicKey(identity.privateKeyPem).export({ format: "der", type: "spki" }).subarray(-32).toString("base64") === identity.publicKey;
  } catch { return false; }
}
function recoveryManifest({ command, localState, subjectRun }) {
  return Object.freeze({ arguments: Object.freeze([...command.args]), command: command.command, paymentMoved: false, reasonCode: "AMBIGUOUS_WRITE", releaseId: localState.releaseId, repositorySha: localState.repositorySha, role: localState.role, schema: "clockchain.bilateral-recovery-command-manifest/v1", sessionId: localState.sessionId, subjectRun });
}
function failureSummary({ localState, subjectRun }) {
  return Object.freeze({ eventKind: "TERMINAL_FAILURE", paymentMoved: false, releaseId: localState.releaseId, repositorySha: localState.repositorySha, role: localState.role, schema: "clockchain.bilateral-failure-summary/v1", sessionId: localState.sessionId, subjectRun, terminalCode: "FAILED" });
}
function childJournal({ command, event, status, artifactDigest = undefined, artifactType = undefined }) {
  const commandDigest = sha256(canonicalBytes({ args: command.args, command: command.command, eventDigest: event.eventDigest, repositorySha: event.repositorySha ?? "", role: event.role ?? "", sessionId: event.sessionId ?? "", subjectRun: event.subjectRun }));
  const value = { command: command.command, commandDigest, eventDigest: event.eventDigest, status, subjectRun: event.subjectRun };
  if (artifactDigest !== undefined) value.artifactDigest = artifactDigest;
  if (artifactType !== undefined) value.artifactType = artifactType;
  return Object.freeze(value);
}
function sameJournal(value, { command, event, status }) {
  const commandDigest = sha256(canonicalBytes({ args: command.args, command: command.command, eventDigest: event.eventDigest, repositorySha: event.repositorySha ?? "", role: event.role ?? "", sessionId: event.sessionId ?? "", subjectRun: event.subjectRun }));
  return value && value.command === command.command && value.commandDigest === commandDigest && value.eventDigest === event.eventDigest && value.status === status && value.subjectRun === event.subjectRun;
}
function descriptorJournal({ event, stage }) {
  return Object.freeze({ artifactDigest: event.artifactDigest, eventDigest: event.eventDigest, stage, subjectRun: event.subjectRun });
}
function sameDescriptorJournal(value, event, stage) {
  return value && value.artifactDigest === event.artifactDigest && value.eventDigest === event.eventDigest && value.stage === stage && value.subjectRun === event.subjectRun;
}
const DEMO_INTENT_POLICY = Object.freeze({
  amount: Object.freeze({ currency: "USD", value: "100" }),
  invoiceReferencePrefix: "invoice-",
  purpose: "Handshake demo",
});
function partyFromIdentity(identity) {
  if (!identity || typeof identity.address !== "string" || typeof identity.agentId !== "string") invalid();
  return Object.freeze({ address: identity.address, agentId: identity.agentId });
}
function runArtifactPath(runState, fileName) {
  if (!runState || typeof runState.descriptorPath !== "string") invalid();
  return `${dirname(runState.descriptorPath)}/${fileName}`;
}
function requestIdForRun(localState, dependencies, subjectRun) {
  const journal = localState.intentJournal;
  if (journal?.subjectRun === subjectRun && typeof journal.requestId === "string") return journal.requestId;
  const configured = localState[subjectRun]?.requestId;
  if (configured !== undefined) return configured;
  if (typeof dependencies.requestId === "function") return dependencies.requestId({ localState, subjectRun });
  const digest = sha256(Buffer.from(`${localState.sessionId}:${subjectRun}`, "utf8"));
  return `${digest.slice(0, 8)}-${digest.slice(8, 12)}-4${digest.slice(13, 16)}-8${digest.slice(17, 20)}-${digest.slice(20, 32)}`;
}
function eventFor(events, role, kind, subjectRun) {
  return events.find((event) => event?.role === role && event.kind === kind && event.subjectRun === subjectRun);
}
async function resolveRunParties({ client, dependencies, enrollmentSet, events, localState, subjectRun }) {
  if (typeof client?.getArtifact !== "function" || !enrollmentSet?.enrollments || !Array.isArray(events)) invalid();
  const validate = dependencies.validateRelayArtifactWithFacts ?? defaultValidateRelayArtifactWithFacts;
  if (typeof validate !== "function") invalid();
  const parties = Object.create(null);
  for (const role of ["payer", "payee"]) {
    const event = eventFor(events, role, "IDENTITY_PACKAGE_READY", subjectRun);
    const entry = enrollmentSet.enrollments[role];
    if (!event || !/^[0-9a-f]{64}$/.test(event.artifactDigest) || !entry?.enrollmentBase64) invalid();
    const bytes = await client.getArtifact({ artifactType: "identity-package", digest: event.artifactDigest });
    if (!Buffer.isBuffer(bytes) || sha256(bytes) !== event.artifactDigest) invalid();
    const checked = await validate({ artifactType: "identity-package", bytes, expectedDigest: event.artifactDigest, secretCanaries: [] });
    const identity = checked?.facts?.identity ?? checked?.parsed;
    const enrollment = parseCoordinationEnrollment(Buffer.from(entry.enrollmentBase64, "base64"));
    if (!identity || identity.repositorySha !== localState.repositorySha || identity.paymentMoved !== false || identity.address !== enrollment.invitations[subjectRun]?.address) invalid();
    parties[role] = partyFromIdentity(identity);
  }
  return Object.freeze({ payer: parties.payer, payee: parties.payee });
}
function intentPolicy(localState, subjectRun) {
  const override = localState[subjectRun]?.intentPolicy;
  if (override === undefined) return DEMO_INTENT_POLICY;
  if (!dataExact(override, ["amount", "invoiceReferencePrefix", "purpose"])) invalid();
  return Object.freeze({ amount: Object.freeze({ ...override.amount }), invoiceReferencePrefix: override.invoiceReferencePrefix, purpose: override.purpose });
}
function nowMs(dependencies) {
  const value = typeof dependencies.nowMs === "function" ? dependencies.nowMs() : Date.now();
  if (!Number.isSafeInteger(value) || value < 0) invalid();
  return value;
}
function mandateFor({ localState, parties, policy, subjectRun, timeMs }) {
  return Object.freeze({
    amount: policy.amount,
    expiresAtMs: String(timeMs + 3_600_000),
    invoiceReferencePrefix: policy.invoiceReferencePrefix,
    issuedAtMs: String(Math.max(0, timeMs - 1)),
    payee: parties.payee,
    payer: parties.payer,
    paymentMoved: false,
    protocol: "clockchain.bilateral-authorization/v1",
    purpose: policy.purpose,
    releaseId: localState.releaseId,
    repositorySha: localState.repositorySha,
    requestEndpoint: `/v1/sessions/${localState.sessionId}/payment-requests`,
    schema: "clockchain.bilateral-payer-mandate/v1",
    sessionId: localState.sessionId,
    subjectRun,
  });
}
function requestFor({ localState, mandateEnvelope, parties, policy, requestId, subjectRun, timeMs }) {
  return Object.freeze({
    amount: policy.amount,
    createdAtMs: String(timeMs),
    expiresAtMs: String(timeMs + 1_800_000),
    invoiceReference: `${policy.invoiceReferencePrefix}001`,
    mandateDigest: payerMandateDigest(mandateEnvelope),
    payee: parties.payee,
    payer: parties.payer,
    paymentMoved: false,
    protocol: "clockchain.bilateral-authorization/v1",
    purpose: policy.purpose,
    releaseId: localState.releaseId,
    repositorySha: localState.repositorySha,
    requestId,
    schema: "clockchain.bilateral-payment-request/v1",
    sessionId: localState.sessionId,
    subjectRun,
  });
}
function exactIntentJournal({ mandateBytes, mandateEnvelope, requestBytes = undefined, requestEnvelope = undefined, requestId = undefined, stage, subjectRun }) {
  const value = { mandateDigest: payerMandateDigest(mandateEnvelope), mandateRawDigest: sha256(mandateBytes), stage, subjectRun };
  if (requestBytes !== undefined && requestEnvelope !== undefined) {
    value.requestDigest = paymentRequestDigest(requestEnvelope);
    value.requestRawDigest = sha256(requestBytes);
  }
  if (requestId !== undefined) value.requestId = requestId;
  return Object.freeze(value);
}
function parseCanonicalEnvelope(bytes, expectedRawDigest) {
  if (!Buffer.isBuffer(bytes) || sha256(bytes) !== expectedRawDigest) invalid();
  let parsed;
  try { parsed = JSON.parse(bytes.toString("utf8")); } catch { invalid(); }
  if (!canonicalBytes(parsed).equals(bytes)) invalid();
  return parsed;
}
async function writeIntentEnvelope({ bytes, dependencies, localState, path }) {
  if (typeof dependencies.writeArtifactFile !== "function") invalid();
  await dependencies.writeArtifactFile({ bytes, path });
  return Object.freeze({ path });
}
async function retryPayerMandatePublication({ client, dependencies, localState, subjectRun }) {
  if (typeof client?.publishPayerMandate !== "function" || typeof dependencies.readArtifactFile !== "function") invalid();
  const path = localState[subjectRun]?.mandatePath ?? runArtifactPath(localState[subjectRun], "payer-mandate.json");
  const bytes = await dependencies.readArtifactFile({ path });
  const envelope = parseCanonicalEnvelope(bytes, localState.intentJournal.mandateRawDigest);
  if (payerMandateDigest(envelope) !== localState.intentJournal.mandateDigest) invalid();
  const acknowledgement = await client.publishPayerMandate({ bytes, subjectRun });
  if (!acknowledgement || acknowledgement.digest !== localState.intentJournal.mandateRawDigest) invalid();
  return Object.freeze({ ...localState, intentJournal: Object.freeze({ ...localState.intentJournal, stage: "PAYER_MANDATE_PUBLISHED" }), paymentMoved: false, phase: "EVENT_PROCESSED" });
}
async function retryPaymentRequestSubmission({ client, dependencies, localState, subjectRun }) {
  if (typeof client?.submitPaymentRequest !== "function" || typeof dependencies.readArtifactFile !== "function") invalid();
  const path = localState[subjectRun]?.requestPath ?? runArtifactPath(localState[subjectRun], "payment-request.json");
  const bytes = await dependencies.readArtifactFile({ path });
  const envelope = parseCanonicalEnvelope(bytes, localState.intentJournal.requestRawDigest);
  if (paymentRequestDigest(envelope) !== localState.intentJournal.requestDigest || envelope.request.requestId !== localState.intentJournal.requestId) invalid();
  const receipt = await client.submitPaymentRequest({ bytes });
  if (!receipt || receipt.paymentMoved !== false || receipt.rawEnvelopeDigest !== localState.intentJournal.requestRawDigest || receipt.paymentRequestDigest !== localState.intentJournal.requestDigest || receipt.requestId !== localState.intentJournal.requestId || receipt.sessionId !== localState.sessionId || receipt.subjectRun !== subjectRun) invalid();
  return Object.freeze({ ...localState, intentJournal: Object.freeze({ ...localState.intentJournal, stage: "PAYMENT_REQUEST_SUBMITTED" }), paymentMoved: false, phase: "EVENT_PROCESSED" });
}
async function publishPayerMandatePhase({ client, dependencies, localState, replay, subjectRun }) {
  if (typeof client?.publishPayerMandate !== "function" || typeof dependencies.signPayerMandate !== "function") invalid();
  const parties = await resolveRunParties({ client, dependencies, enrollmentSet: replay.enrollmentSet, events: replay.events, localState, subjectRun });
  const timeMs = nowMs(dependencies);
  const mandate = mandateFor({ localState, parties, policy: intentPolicy(localState, subjectRun), subjectRun, timeMs });
  const envelope = await dependencies.signPayerMandate({ invitationPath: localState[subjectRun]?.invitationPath, localState, mandate, subjectRun });
  const bytes = canonicalBytes(envelope);
  const readyJournal = exactIntentJournal({ mandateBytes: bytes, mandateEnvelope: envelope, stage: "PAYER_MANDATE_READY_TO_PUBLISH", subjectRun });
  await writeIntentEnvelope({ bytes, dependencies, localState, path: localState[subjectRun]?.mandatePath ?? runArtifactPath(localState[subjectRun], "payer-mandate.json") });
  if (typeof dependencies.writeState === "function") await dependencies.writeState(Object.freeze({ ...localState, intentJournal: readyJournal, paymentMoved: false, phase: "EVENT_PROCESSED" }));
  const acknowledgement = await client.publishPayerMandate({ bytes, subjectRun });
  if (!acknowledgement || acknowledgement.digest !== readyJournal.mandateRawDigest) invalid();
  const state = Object.freeze({ ...localState, intentJournal: Object.freeze({ ...readyJournal, stage: "PAYER_MANDATE_PUBLISHED" }), paymentMoved: false, phase: "EVENT_PROCESSED" });
  if (typeof dependencies.writeState === "function") await dependencies.writeState(state);
  return state;
}
async function submitPaymentRequestPhase({ client, dependencies, localState, replay, subjectRun }) {
  if (typeof client?.readPayerMandate !== "function" || typeof client?.submitPaymentRequest !== "function" || typeof dependencies.signPaymentRequest !== "function") invalid();
  const parties = await resolveRunParties({ client, dependencies, enrollmentSet: replay.enrollmentSet, events: replay.events, localState, subjectRun });
  const timeMs = nowMs(dependencies);
  const policy = intentPolicy(localState, subjectRun);
  const mandateBytes = await client.readPayerMandate({ payer: parties.payer, payee: parties.payee, subjectRun });
  if (!Buffer.isBuffer(mandateBytes)) invalid();
  const mandateEvent = eventFor(replay.events, "payer", "PAYER_MANDATE_READY", subjectRun);
  const mandateEnvelope = await verifyPayerMandate({ envelope: parseCanonicalEnvelope(mandateBytes, mandateEvent.artifactDigest), expected: { ...policy, payer: parties.payer, payee: parties.payee, releaseId: localState.releaseId, repositorySha: localState.repositorySha, requestEndpoint: `/v1/sessions/${localState.sessionId}/payment-requests`, sessionId: localState.sessionId, subjectRun }, nowMs: timeMs });
  const requestId = requestIdForRun(localState, dependencies, subjectRun);
  const request = requestFor({ localState, mandateEnvelope, parties, policy, requestId, subjectRun, timeMs });
  const envelope = await dependencies.signPaymentRequest({ invitationPath: localState[subjectRun]?.invitationPath, localState, request, subjectRun });
  const bytes = canonicalBytes(envelope);
  const readyJournal = exactIntentJournal({ mandateBytes, mandateEnvelope, requestBytes: bytes, requestEnvelope: envelope, requestId, stage: "PAYMENT_REQUEST_READY_TO_SUBMIT", subjectRun });
  await writeIntentEnvelope({ bytes, dependencies, localState, path: localState[subjectRun]?.requestPath ?? runArtifactPath(localState[subjectRun], "payment-request.json") });
  if (typeof dependencies.writeState === "function") await dependencies.writeState(Object.freeze({ ...localState, intentJournal: readyJournal, paymentMoved: false, phase: "EVENT_PROCESSED" }));
  const receipt = await client.submitPaymentRequest({ bytes });
  if (!receipt || receipt.paymentMoved !== false || receipt.rawEnvelopeDigest !== readyJournal.requestRawDigest || receipt.paymentRequestDigest !== readyJournal.requestDigest || receipt.requestId !== requestId || receipt.sessionId !== localState.sessionId || receipt.subjectRun !== subjectRun) invalid();
  const state = Object.freeze({ ...localState, intentJournal: Object.freeze({ ...readyJournal, stage: "PAYMENT_REQUEST_SUBMITTED" }), paymentMoved: false, phase: "EVENT_PROCESSED" });
  if (typeof dependencies.writeState === "function") await dependencies.writeState(state);
  return state;
}
async function matchPaymentRequestPhase({ client, dependencies, localState, replay, subjectRun }) {
  if (typeof client?.getArtifact !== "function" || typeof client?.readPayerMandate !== "function" || typeof client?.readPaymentRequest !== "function" || typeof client?.appendEvent !== "function") invalid();
  const parties = await resolveRunParties({ client, dependencies, enrollmentSet: replay.enrollmentSet, events: replay.events, localState, subjectRun });
  const timeMs = nowMs(dependencies);
  const policy = intentPolicy(localState, subjectRun);
  const mandateBytes = await client.readPayerMandate({ payer: parties.payer, payee: parties.payee, subjectRun });
  if (!Buffer.isBuffer(mandateBytes)) invalid();
  const mandateEvent = eventFor(replay.events, "payer", "PAYER_MANDATE_READY", subjectRun);
  const requestEvent = eventFor(replay.events, "payee", "PAYMENT_REQUEST_READY", subjectRun);
  if (!requestEvent || !/^[0-9a-f]{64}$/.test(requestEvent.artifactDigest)) invalid();
  const requestBytes = await client.getArtifact({ artifactType: "payment-request", digest: requestEvent.artifactDigest });
  if (!Buffer.isBuffer(requestBytes)) invalid();
  const mandateEnvelope = parseCanonicalEnvelope(mandateBytes, mandateEvent.artifactDigest);
  const requestEnvelope = await verifyPaymentRequest({ envelope: parseCanonicalEnvelope(requestBytes, requestEvent.artifactDigest), mandateEnvelope, expected: { ...policy, payer: parties.payer, payee: parties.payee, releaseId: localState.releaseId, repositorySha: localState.repositorySha, sessionId: localState.sessionId, subjectRun }, nowMs: timeMs });
  const requestId = requestEnvelope.request.requestId;
  const routedBytes = await client.readPaymentRequest({ payer: parties.payer, payee: parties.payee, requestId, subjectRun });
  if (!Buffer.isBuffer(routedBytes) || !routedBytes.equals(requestBytes)) invalid();
  const journal = exactIntentJournal({ mandateBytes, mandateEnvelope, requestBytes, requestEnvelope, requestId, stage: "PAYMENT_REQUEST_MATCHED", subjectRun });
  await client.appendEvent({ artifactDigest: null, kind: "PAYMENT_REQUEST_MATCHED", subjectRun });
  const state = Object.freeze({ ...localState, intentJournal: journal, paymentMoved: false, phase: "EVENT_PROCESSED" });
  if (typeof dependencies.writeState === "function") await dependencies.writeState(state);
  return state;
}
async function runCommercialIntentPhase({ client, dependencies, localState, replay }) {
  const journal = localState.intentJournal;
  if (journal?.stage === "PAYER_MANDATE_READY_TO_PUBLISH") {
    if (localState.role !== "payer" || eventFor(replay.events, "payer", "PAYER_MANDATE_READY", journal.subjectRun)) return null;
    return retryPayerMandatePublication({ client, dependencies, localState, subjectRun: journal.subjectRun });
  }
  if (journal?.stage === "PAYMENT_REQUEST_READY_TO_SUBMIT") {
    if (localState.role !== "payee" || eventFor(replay.events, "payee", "PAYMENT_REQUEST_READY", journal.subjectRun)) return null;
    return retryPaymentRequestSubmission({ client, dependencies, localState, subjectRun: journal.subjectRun });
  }
  for (const subjectRun of ["rehearsal", "stakeholder"]) {
    const identityReady = ["payer", "payee"].every((role) => eventFor(replay.events, role, "IDENTITY_PACKAGE_READY", subjectRun));
    if (!identityReady) continue;
    const mandateReady = eventFor(replay.events, "payer", "PAYER_MANDATE_READY", subjectRun);
    const requestReady = eventFor(replay.events, "payee", "PAYMENT_REQUEST_READY", subjectRun);
    const requestMatched = eventFor(replay.events, "payer", "PAYMENT_REQUEST_MATCHED", subjectRun);
    if (localState.role === "payer" && !mandateReady) return publishPayerMandatePhase({ client, dependencies, localState, replay, subjectRun });
    if (localState.role === "payee" && mandateReady && !requestReady) return submitPaymentRequestPhase({ client, dependencies, localState, replay, subjectRun });
    if (localState.role === "payer" && mandateReady && requestReady && !requestMatched) return matchPaymentRequestPhase({ client, dependencies, localState, replay, subjectRun });
  }
  return null;
}
async function publishRecoveryRequired({ client, command, dependencies, event, localState }) {
  const bytes = canonicalBytes(recoveryManifest({ command, localState, subjectRun: event.subjectRun }));
  const digest = sha256(bytes);
  await (dependencies.validateRelayArtifact ?? defaultValidateRelayArtifact)({ artifactType: "recovery-command-manifest", bytes, expectedDigest: digest, secretCanaries: [] });
  if (typeof client?.putArtifact !== "function" || typeof client?.appendEvent !== "function" || typeof dependencies.writeState !== "function") invalid();
  const acknowledgement = await client.putArtifact({ artifactType: "recovery-command-manifest", bytes, expectedDigest: digest });
  if (!exact(acknowledgement, ["artifactType", "byteLength", "digest"]) || acknowledgement.artifactType !== "recovery-command-manifest" || acknowledgement.byteLength !== String(bytes.length) || acknowledgement.digest !== digest) invalid();
  const recovery = Object.freeze({ authorizationUsed: false, commandEvent: structuredClone(event), manifestBytes: bytes.toString("base64"), manifestDigest: digest, stage: "MANIFEST_STORED", subjectRun: event.subjectRun });
  await dependencies.writeState(Object.freeze({ ...localState, phase: "RECOVERY_REQUIRED", paymentMoved: false, eventDigest: event.eventDigest, recovery }));
  const published = localState.authenticatedEvents?.filter((entry) => entry?.role === localState.role && entry.kind === "RECOVERY_REQUIRED" && entry.subjectRun === event.subjectRun) ?? [];
  if (published.length > 1 || published.length === 1 && published[0].artifactDigest !== digest) invalid();
  if (published.length === 1) {
    const adopted = Object.freeze({ ...recovery, stage: "EVENT_APPENDED" });
    await dependencies.writeState(Object.freeze({ ...localState, phase: "RECOVERY_REQUIRED", paymentMoved: false, eventDigest: event.eventDigest, recovery: adopted }));
    return adopted;
  }
  const appendAttempt = Object.freeze({ ...recovery, stage: "EVENT_APPEND_ATTEMPTED" });
  await dependencies.writeState(Object.freeze({ ...localState, phase: "RECOVERY_REQUIRED", paymentMoved: false, eventDigest: event.eventDigest, recovery: appendAttempt }));
  await client.appendEvent({ artifactDigest: digest, kind: "RECOVERY_REQUIRED", subjectRun: event.subjectRun });
  const appended = Object.freeze({ ...recovery, stage: "EVENT_APPENDED" });
  await dependencies.writeState(Object.freeze({ ...localState, phase: "RECOVERY_REQUIRED", paymentMoved: false, eventDigest: event.eventDigest, recovery: appended }));
  return appended;
}
function canonicalEnrollmentSetBytes(value) {
  return Buffer.from(JSON.stringify(canonicalizeReceiptEventValue(value)), "utf8");
}
async function rereadTokenCommitment(localState, dependencies) {
  if (!localState.coordinationIdentity || !localState.tokenCommitment || typeof (dependencies.readAndSignTokenCommitment ?? defaultReadAndSignTokenCommitment) !== "function") invalid();
  const commitment = await (dependencies.readAndSignTokenCommitment ?? defaultReadAndSignTokenCommitment)({ coordinationPrivateKeyPem: localState.coordinationIdentity.privateKeyPem, coordinationPublicKey: localState.coordinationIdentity.publicKey, repositorySha: localState.repositorySha, role: localState.role, tokenPath: localState.tokenPath });
  if (!same(commitment, localState.tokenCommitment)) invalid();
}
function validateLocalCheckpoint(checkpoint, scope) {
  if (!dataExact(checkpoint.preflight, ["outputPath", "planPath", "privateKeyPath", "publicArtifact", "publicArtifactPath"]) || !dataExact(checkpoint.preflight.publicArtifact, ["paymentMoved", "publicKey", "repositorySha", "role"]) || !Array.isArray(checkpoint.invitations) || checkpoint.invitations.length !== 2 || checkpoint.preflight.planPath !== `${safePrivateRoot(checkpoint.stateRoot)}/preflight/plan.json` || checkpoint.preflight.outputPath !== `${safePrivateRoot(checkpoint.stateRoot)}/preflight/report.json` || checkpoint.preflight.privateKeyPath !== `${checkpoint.stateRoot}/preflight/preflight.ed25519.pem` || checkpoint.preflight.publicArtifactPath !== `${checkpoint.stateRoot}/preflight/preflight-key-enrollment.json`) invalid();
  const enrollment = verifyCoordinationEnrollment(JSON.parse(Buffer.from(checkpoint.enrollmentBase64, "base64").toString("utf8")));
  if (!Buffer.from(checkpoint.enrollmentBase64, "base64").equals(canonicalBytes(enrollment)) || !matchingCoordinationIdentity(checkpoint.coordinationIdentity, enrollment) || (scope.capabilityDigest !== undefined && enrollment.capabilityDigest !== scope.capabilityDigest) || enrollment.releaseId !== scope.releaseId || enrollment.repositorySha !== scope.repositorySha || enrollment.role !== scope.role || enrollment.sessionId !== scope.sessionId) invalid();
  const artifact = checkpoint.preflight.publicArtifact;
  if (artifact.paymentMoved !== false || artifact.publicKey !== enrollment.preflightKey.publicKey || artifact.repositorySha !== enrollment.repositorySha || artifact.role !== enrollment.role) invalid();
  for (const [index, run] of ["rehearsal", "stakeholder"].entries()) {
    const invitation = checkpoint.invitations[index];
    if (!dataExact(invitation, ["address", "algorithm", "secretPath", "signature", "subjectRun"]) || invitation.subjectRun !== run || invitation.address !== enrollment.invitations[run].address || invitation.algorithm !== enrollment.invitations[run].algorithm || invitation.signature !== enrollment.invitations[run].signature || typeof invitation.secretPath !== "string") invalid();
  }
  if (checkpoint.invitations[0].address === checkpoint.invitations[1].address || checkpoint.invitations[0].secretPath === checkpoint.invitations[1].secretPath) invalid();
  const expectedArtifacts = fixedRoleArtifacts(checkpoint.stateRoot, checkpoint.invitations);
  for (const run of ["rehearsal", "stakeholder"]) if (!dataExact(checkpoint[run], ["descriptorPath", "identityDirectory", "invitationPath", "resultDirectory"]) || !same(checkpoint[run], expectedArtifacts[run])) invalid();
  return enrollment;
}
function validateDurableCheckpointShape(checkpoint, activeLaunchState, stateRoot) {
  if (checkpoint.schema !== SUPERVISOR_STATE_SCHEMA || checkpoint.stateRoot !== safePrivateRoot(stateRoot) || checkpoint.paymentMoved !== false || !FULL_CHECKPOINT_PHASES.has(checkpoint.phase)) invalid();
  if (Reflect.ownKeys(checkpoint).some((key) => typeof key !== "string" || !DURABLE_CHECKPOINT_KEYS.has(key)) || ["bootstrapCapability", "token", "tokenValue", "rawCapability"].some((key) => Object.hasOwn(checkpoint, key))) invalid();
  const pairedReplay = checkpoint.events !== undefined || checkpoint.enrollmentSet !== undefined;
  if (pairedReplay !== (checkpoint.events !== undefined && checkpoint.enrollmentSet !== undefined) || (checkpoint.events !== undefined && !Array.isArray(checkpoint.events)) || (checkpoint.processedEventDigests !== undefined && (!Array.isArray(checkpoint.processedEventDigests) || checkpoint.processedEventDigests.some((digest) => !/^[0-9a-f]{64}$/.test(digest)) || new Set(checkpoint.processedEventDigests).size !== checkpoint.processedEventDigests.length))) invalid();
  if (checkpoint.processedEventDigests && (!checkpoint.events || checkpoint.processedEventDigests.some((digest) => !checkpoint.events.some((event) => event?.eventDigest === digest)))) invalid();
  if (checkpoint.eventDigest !== undefined && !/^[0-9a-f]{64}$/.test(checkpoint.eventDigest)) invalid();
  if (checkpoint.senderState !== undefined && (!dataExact(checkpoint.senderState, ["previousEventDigest", "sequence"]) || (checkpoint.senderState.previousEventDigest !== null && !/^[0-9a-f]{64}$/.test(checkpoint.senderState.previousEventDigest)) || !/^(?:0|[1-9][0-9]*)$/.test(checkpoint.senderState.sequence))) invalid();
  const child = checkpoint.childJournal;
  if (child !== undefined) {
    if (!CHILD_JOURNAL_PHASES.has(checkpoint.phase) || !dataExact(child, child.status === "ARTIFACT_STORED" || child.status === "EVENT_APPENDED" ? ["artifactDigest", "artifactType", "command", "commandDigest", "eventDigest", "status", "subjectRun"] : ["command", "commandDigest", "eventDigest", "status", "subjectRun"]) || !["BEFORE_CHILD", "CHILD_COMPLETE", "ARTIFACT_STORED", "EVENT_APPENDED"].includes(child.status) || !["scripts/probe-bilateral-rendezvous.mjs", "scripts/register-bilateral-identity.mjs", "bin/handshake-propose.mjs", "bin/handshake-accept.mjs"].includes(child.command) || !/^[0-9a-f]{64}$/.test(child.commandDigest) || !/^[0-9a-f]{64}$/.test(child.eventDigest) || !["release", "rehearsal", "stakeholder"].includes(child.subjectRun) || checkpoint.eventDigest !== child.eventDigest || (child.artifactDigest !== undefined && !/^[0-9a-f]{64}$/.test(child.artifactDigest)) || (child.artifactType !== undefined && !["preflight-participant-report", "identity-package", "party-result-package"].includes(child.artifactType))) invalid();
    if (["BEFORE_CHILD", "CHILD_COMPLETE", "ARTIFACT_STORED", "EVENT_APPENDED"].includes(checkpoint.phase) && child.status !== checkpoint.phase) invalid();
    const event = checkpoint.events?.find((entry) => entry?.eventDigest === child.eventDigest && entry.role === "operator");
    if (!event || !sameJournal(child, { command: buildSupervisorCommand({ event, localState: checkpoint }), event, status: child.status })) invalid();
  } else if (CHILD_JOURNAL_PHASES.has(checkpoint.phase)) invalid();
  const descriptor = checkpoint.descriptorJournal;
  if (descriptor !== undefined) {
    if (!dataExact(descriptor, ["artifactDigest", "eventDigest", "stage", "subjectRun"]) || !/^[0-9a-f]{64}$/.test(descriptor.artifactDigest) || !/^[0-9a-f]{64}$/.test(descriptor.eventDigest) || !["FILE_WRITING", "ACCEPTED_STORED", "APPEND_ATTEMPTED", "EVENT_APPENDED"].includes(descriptor.stage) || !["rehearsal", "stakeholder"].includes(descriptor.subjectRun) || checkpoint.eventDigest !== descriptor.eventDigest) invalid();
    if (checkpoint.phase === "DESCRIPTOR_WRITING" && descriptor.stage !== "FILE_WRITING") invalid();
    if (checkpoint.phase === "DESCRIPTOR_ACCEPTED" && !["ACCEPTED_STORED", "APPEND_ATTEMPTED", "EVENT_APPENDED"].includes(descriptor.stage)) invalid();
    const event = checkpoint.events?.find((entry) => entry?.eventDigest === descriptor.eventDigest && entry.role === "operator");
    if (!event || !sameDescriptorJournal(descriptor, event, descriptor.stage)) invalid();
  } else if (["DESCRIPTOR_WRITING", "DESCRIPTOR_ACCEPTED"].includes(checkpoint.phase)) invalid();
  const intent = checkpoint.intentJournal;
  if (intent !== undefined) {
    const keys = intent.requestDigest === undefined
      ? ["mandateDigest", "mandateRawDigest", "stage", "subjectRun"]
      : ["mandateDigest", "mandateRawDigest", "requestDigest", "requestId", "requestRawDigest", "stage", "subjectRun"];
    if (!dataExact(intent, keys) || !/^[0-9a-f]{64}$/.test(intent.mandateDigest) || !/^[0-9a-f]{64}$/.test(intent.mandateRawDigest) || !["PAYER_MANDATE_READY_TO_PUBLISH", "PAYER_MANDATE_PUBLISHED", "PAYMENT_REQUEST_READY_TO_SUBMIT", "PAYMENT_REQUEST_SUBMITTED", "PAYMENT_REQUEST_MATCHED"].includes(intent.stage) || !["rehearsal", "stakeholder"].includes(intent.subjectRun)) invalid();
    if (intent.requestDigest !== undefined && (!/^[0-9a-f]{64}$/.test(intent.requestDigest) || !/^[0-9a-f]{64}$/.test(intent.requestRawDigest) || typeof intent.requestId !== "string")) invalid();
  }
  if (checkpoint.recovery !== undefined) {
    const recovery = checkpoint.recovery;
    if (checkpoint.phase !== "RECOVERY_REQUIRED" || !dataExact(recovery, ["authorizationUsed", "commandEvent", "manifestBytes", "manifestDigest", "stage", "subjectRun"]) || typeof recovery.authorizationUsed !== "boolean" || !["MANIFEST_STORED", "EVENT_APPEND_ATTEMPTED", "EVENT_APPENDED"].includes(recovery.stage) || !/^[0-9a-f]{64}$/.test(recovery.manifestDigest) || !["release", "rehearsal", "stakeholder"].includes(recovery.subjectRun) || typeof recovery.manifestBytes !== "string") invalid();
    const command = buildSupervisorCommand({ event: recovery.commandEvent, localState: checkpoint });
    const bytes = Buffer.from(recovery.manifestBytes, "base64");
    if (!bytes.equals(canonicalBytes(recoveryManifest({ command, localState: checkpoint, subjectRun: recovery.subjectRun }))) || sha256(bytes) !== recovery.manifestDigest) invalid();
  } else if (checkpoint.phase === "RECOVERY_REQUIRED") invalid();
  if (TOKEN_BOUND_PHASES.has(checkpoint.phase)) {
    if (!checkpoint.tokenCommitment || typeof checkpoint.tokenPath !== "string" || !/^\/(?:[^/]+\/)*[^/]+$/.test(checkpoint.tokenPath) || checkpoint.tokenPath.includes("/../") || checkpoint.tokenPath.endsWith("/..")) invalid();
    try { verifyTokenCommitment(checkpoint.tokenCommitment, { coordinationPublicKey: checkpoint.coordinationIdentity?.publicKey, repositorySha: checkpoint.repositorySha, role: checkpoint.role }); } catch { invalid(); }
  }
}

async function finalizeBootstrap({ bootstrapResult, checkpoint, dependencies, launchManifestPath, manifest, stateRoot }) {
  if (!exact(bootstrapResult, ["activeLaunchState", "receipt"]) || !dependencies.validateActiveLaunchState || !dependencies.writeState || !dependencies.readState || !dependencies.retireLaunchManifest) invalid();
  const activeLaunchState = await dependencies.validateActiveLaunchState(bootstrapResult.activeLaunchState);
  if (!same(activeLaunchState, bootstrapResult.activeLaunchState) || activeLaunchState.paymentMoved !== false || activeLaunchState.role !== manifest.role || activeLaunchState.repositorySha !== manifest.repositorySha || activeLaunchState.sessionId !== manifest.sessionId || activeLaunchState.releaseId !== manifest.releaseId) invalid();
  const persisted = Object.freeze({ ...checkpoint, activeLaunchState, phase: "BOOTSTRAPPED_ACTIVE", receipt: bootstrapResult.receipt });
  await dependencies.writeState(persisted);
  const readback = await dependencies.readState(stateRoot);
  if (!same(readback, persisted)) invalid();
  const verifiedReadback = await dependencies.validateActiveLaunchState(readback.activeLaunchState);
  if (!same(verifiedReadback, activeLaunchState)) invalid();
  await dependencies.retireLaunchManifest(launchManifestPath);
  return publicState(persisted);
}

export async function authenticateSupervisorReplay({ events, enrollmentSet, operatorPublicKey, releaseId, repositorySha, sessionId, localRole, verifyEnrollmentSet, verifyVerifierPublication }) {
  try {
    if (!Array.isArray(events) || !["payer", "payee"].includes(localRole) || typeof operatorPublicKey !== "string" || typeof verifyEnrollmentSet !== "function") invalid();
    const suppliedBytes = Buffer.isBuffer(enrollmentSet) ? Buffer.from(enrollmentSet) : canonicalEnrollmentSetBytes(enrollmentSet);
    const set = parseCoordinationEnrollmentSet(suppliedBytes);
    const enrollmentBytes = canonicalEnrollmentSetBytes(set);
    const verifiedSet = await verifyEnrollmentSet(Object.freeze({ enrollmentBytes: Buffer.from(enrollmentBytes), enrollmentSet: structuredClone(set), releaseId, repositorySha, sessionId }));
    if (!same(verifiedSet, set)) invalid();
    if (set.releaseId !== releaseId || set.repositorySha !== repositorySha || set.sessionId !== sessionId) invalid();
    const payer = parseCoordinationEnrollment(Buffer.from(set.enrollments.payer.enrollmentBase64, "base64"));
    const payee = parseCoordinationEnrollment(Buffer.from(set.enrollments.payee.enrollmentBase64, "base64"));
    const keys = { operator: operatorPublicKey, payer: payer.coordinationKey.publicKey, payee: payee.coordinationKey.publicKey };
    const sender = { operator: { previousEventDigest: null, sequence: 0 }, payer: { previousEventDigest: null, sequence: 0 }, payee: { previousEventDigest: null, sequence: 0 } };
    const digests = new Set();
    let view = initialReleaseView({ releaseId, repositorySha, sessionId });
    for (const event of events) {
      const role = event?.role;
      if (!Object.hasOwn(keys, role) || digests.has(event.eventDigest)) invalid();
      const state = sender[role];
      if (event.signature?.publicKey !== keys[role]) invalid();
      verifyCoordinationEnvelope(event, { expectedPublicKey: keys[role], expectedReleaseId: releaseId, expectedRepositorySha: repositorySha, expectedRole: role, expectedSessionId: sessionId });
      if (event.sequence !== String(state.sequence) || event.previousEventDigest !== state.previousEventDigest) invalid();
      const options = event.kind === "VERIFICATION_PASSED"
        ? { expectedPublicKey: keys[role], verifierPublicationVerified: typeof verifyVerifierPublication === "function" && await verifyVerifierPublication(Object.freeze({ event: structuredClone(event), enrollmentSet: structuredClone(set), releaseId, repositorySha, sessionId })) === true }
        : { expectedPublicKey: keys[role] };
      view = reduceReleaseEvent(view, event, options);
      digests.add(event.eventDigest); state.previousEventDigest = event.eventDigest; state.sequence += 1;
    }
    return Object.freeze({ enrollmentSet: Object.freeze(structuredClone(set)), events: Object.freeze(events.map((event) => Object.freeze(structuredClone(event)))), senderState: Object.freeze({ previousEventDigest: sender[localRole].previousEventDigest, sequence: String(sender[localRole].sequence) }), view: Object.freeze(view) });
  } catch { invalid(); }
}

export function buildSupervisorCommand({ event, localState }) {
  if (!event || !localState || event.repositorySha !== localState.repositorySha || event.role !== "operator") invalid();
  if (event.kind === "PREFLIGHT_PLAN_READY" && event.subjectRun === "release" && localState.preflight?.outputPath) return Object.freeze({ command: "scripts/probe-bilateral-rendezvous.mjs", args: Object.freeze(["participant", "--role", localState.role, "--plan", localState.preflight.planPath, "--token-file", localState.tokenPath, "--participant-private-key", localState.preflight.privateKeyPath, "--output", dirname(localState.preflight.outputPath)]) });
  if (["REGISTER_REHEARSAL", "REGISTER_STAKEHOLDER"].includes(event.kind)) {
    const run = event.kind === "REGISTER_REHEARSAL" ? "rehearsal" : "stakeholder";
    const state = localState[run];
    if (!state || event.subjectRun !== run) invalid();
    return Object.freeze({ command: "scripts/register-bilateral-identity.mjs", args: Object.freeze(["--invitation", state.invitationPath, "--output", state.identityDirectory, "--repository-sha", localState.repositorySha, "--i-understand-this-writes-to-sepolia"]) });
  }
  if (!["START_REHEARSAL", "START_STAKEHOLDER"].includes(event.kind)) invalid();
  const run = event.subjectRun;
  if ((event.kind === "START_REHEARSAL" && run !== "rehearsal") || (event.kind === "START_STAKEHOLDER" && run !== "stakeholder")) invalid();
  const state = localState[run];
  if (!state || localState.role !== "payer" && localState.role !== "payee") invalid();
  return Object.freeze({ args: Object.freeze(["--clockchain-token-file", localState.tokenPath, "--descriptor", state.descriptorPath, "--invitation", state.invitationPath, "--output", state.resultDirectory, "--i-understand-this-writes-to-clockchain"]), command: localState.role === "payer" ? "bin/handshake-propose.mjs" : "bin/handshake-accept.mjs" });
}

export async function executeSupervisorTransition({ client, event, localState, dependencies = {} }) {
  if (!localState || !Array.isArray(localState.authenticatedEvents) || !localState.authenticatedEvents.includes(event) || !event || typeof event.kind !== "string") invalid();
  const writeState = dependencies.writeState;
  if (typeof writeState !== "function") invalid();
  if (event.kind === "TERMINAL_ABORT") {
    await writeState(Object.freeze({ ...localState, phase: "ABORTED", paymentMoved: false }));
    return Object.freeze({ phase: "ABORTED" });
  }
  if (["REHEARSAL_DESCRIPTOR_READY", "STAKEHOLDER_DESCRIPTOR_READY"].includes(event.kind)) {
    const run = event.kind === "REHEARSAL_DESCRIPTOR_READY" ? "rehearsal" : "stakeholder";
    if (event.subjectRun !== run || typeof client?.getArtifact !== "function" || typeof client?.appendEvent !== "function" || typeof dependencies.verifyDescriptor !== "function" || typeof dependencies.writeArtifactFile !== "function" || typeof dependencies.readState !== "function" || !localState[run]?.descriptorPath) invalid();
    const done = sameDescriptorJournal(localState.descriptorJournal, event, "EVENT_APPENDED");
    if (done) return Object.freeze({ artifactDigest: event.artifactDigest, kind: "DESCRIPTOR_ACCEPTED" });
    const bytes = await client.getArtifact({ digest: event.artifactDigest, artifactType: "signed-descriptor" });
    if (!Buffer.isBuffer(bytes) || sha256(bytes) !== event.artifactDigest) invalid();
    await dependencies.verifyDescriptor(bytes, Object.freeze({ enrollmentSet: localState.enrollmentSet, releaseId: localState.releaseId, repositorySha: localState.repositorySha, role: localState.role, sessionId: localState.sessionId, subjectRun: run }));
    if (!sameDescriptorJournal(localState.descriptorJournal, event, "ACCEPTED_STORED") && !sameDescriptorJournal(localState.descriptorJournal, event, "APPEND_ATTEMPTED")) {
      const pending = Object.freeze({ ...localState, descriptorJournal: descriptorJournal({ event, stage: "FILE_WRITING" }), phase: "DESCRIPTOR_WRITING", paymentMoved: false, eventDigest: event.eventDigest });
      await writeState(pending);
      await dependencies.writeArtifactFile({ bytes, path: localState[run].descriptorPath });
      const accepted = Object.freeze({ ...localState, descriptorJournal: descriptorJournal({ event, stage: "ACCEPTED_STORED" }), phase: "DESCRIPTOR_ACCEPTED", paymentMoved: false, eventDigest: event.eventDigest });
      await writeState(accepted);
      if (!same(await dependencies.readState(), accepted)) invalid();
    }
    const attempted = Object.freeze({ ...localState, descriptorJournal: descriptorJournal({ event, stage: "APPEND_ATTEMPTED" }), phase: "DESCRIPTOR_ACCEPTED", paymentMoved: false, eventDigest: event.eventDigest });
    await writeState(attempted);
    await client.appendEvent({ artifactDigest: event.artifactDigest, kind: "DESCRIPTOR_ACCEPTED", subjectRun: run });
    await writeState(Object.freeze({ ...localState, descriptorJournal: descriptorJournal({ event, stage: "EVENT_APPENDED" }), phase: "DESCRIPTOR_ACCEPTED", paymentMoved: false, eventDigest: event.eventDigest }));
    return Object.freeze({ artifactDigest: event.artifactDigest, kind: "DESCRIPTOR_ACCEPTED" });
  }
  if (!Object.hasOwn(SUPERVISOR_COMMAND_POLICY, event.kind)) invalid();
  if (event.kind !== "EXACT_RECOVERY_AUTHORIZATION" && localState.recovery?.commandEvent?.eventDigest === event.eventDigest) invalid();
  let effectiveEvent = event;
  if (event.kind === "EXACT_RECOVERY_AUTHORIZATION") {
    const recovery = localState.recovery;
    if (!recovery || recovery.authorizationUsed === true || recovery.manifestDigest !== event.artifactDigest || recovery.subjectRun !== event.subjectRun || !recovery.commandEvent || !recovery.manifestBytes || typeof client?.getArtifact !== "function") invalid();
    const bytes = await client.getArtifact({ digest: event.artifactDigest, artifactType: "recovery-command-manifest" });
    if (!Buffer.isBuffer(bytes) || sha256(bytes) !== event.artifactDigest || !same(bytes, Buffer.from(recovery.manifestBytes, "base64"))) invalid();
    await (dependencies.validateRelayArtifact ?? defaultValidateRelayArtifact)({ artifactType: "recovery-command-manifest", bytes, expectedDigest: event.artifactDigest, secretCanaries: [] });
    const expectedBytes = canonicalBytes(recoveryManifest({ command: buildSupervisorCommand({ event: recovery.commandEvent, localState }), localState, subjectRun: event.subjectRun }));
    if (!same(bytes, expectedBytes)) invalid();
    effectiveEvent = recovery.commandEvent;
    const { recovery: consumedRecovery, ...withoutRecovery } = localState;
    localState = Object.freeze(withoutRecovery);
  }
  if (!["PREFLIGHT_PLAN_READY", "REGISTER_REHEARSAL", "REGISTER_STAKEHOLDER", "START_REHEARSAL", "START_STAKEHOLDER"].includes(effectiveEvent.kind)) invalid();
  if (effectiveEvent.kind.startsWith("START_") && localState.role === "payer" && !localState.authenticatedEvents.some((entry) => entry?.role === "payee" && entry.kind === "ROLE_STARTED" && entry.subjectRun === effectiveEvent.subjectRun)) invalid();
  const command = buildSupervisorCommand({ event: effectiveEvent, localState });
  if (typeof dependencies.launcher !== "function" || typeof dependencies.readArtifactPackage !== "function" || typeof dependencies.validateRelayArtifact !== "function" && defaultValidateRelayArtifact === undefined) invalid();
  if (effectiveEvent.kind === "PREFLIGHT_PLAN_READY") {
    if (typeof client?.getArtifact !== "function" || typeof dependencies.verifyPreflightPlan !== "function" || typeof dependencies.writeArtifactFile !== "function" || typeof (dependencies.readAndSignTokenCommitment ?? defaultReadAndSignTokenCommitment) !== "function" || !localState.coordinationIdentity) invalid();
    const plan = await client.getArtifact({ digest: event.artifactDigest, artifactType: "preflight-plan" });
    if (!Buffer.isBuffer(plan) || sha256(plan) !== event.artifactDigest) invalid();
    await dependencies.verifyPreflightPlan(plan, Object.freeze({ artifactDigest: event.artifactDigest, coordinationIdentity: localState.coordinationIdentity, preflight: localState.preflight, repositorySha: localState.repositorySha, role: localState.role, tokenCommitment: localState.tokenCommitment }));
    await dependencies.writeArtifactFile({ bytes: plan, path: localState.preflight.planPath });
    const commitment = await (dependencies.readAndSignTokenCommitment ?? defaultReadAndSignTokenCommitment)({ coordinationPrivateKeyPem: localState.coordinationIdentity.privateKeyPem, coordinationPublicKey: localState.coordinationIdentity.publicKey, repositorySha: localState.repositorySha, role: localState.role, tokenPath: localState.tokenPath });
    if (!same(commitment, localState.tokenCommitment)) invalid();
  }
  if (effectiveEvent.kind.startsWith("REGISTER_")) {
    const run = effectiveEvent.kind === "REGISTER_REHEARSAL" ? "rehearsal" : "stakeholder";
    if (effectiveEvent.subjectRun !== run || typeof dependencies.verifyIdentityPackage !== "function" || !localState[run]?.invitationPath || !localState[run]?.identityDirectory) invalid();
  }
  if (effectiveEvent.kind.startsWith("START_")) await rereadTokenCommitment(localState, dependencies);
  const resumeAfterChild = ["CHILD_COMPLETE", "ARTIFACT_STORED"].some((status) => sameJournal(localState.childJournal, { command, event: effectiveEvent, status }));
  if (sameJournal(localState.childJournal, { command, event: effectiveEvent, status: "EVENT_APPENDED" })) invalid();
  let outcome;
  if (resumeAfterChild) {
    outcome = Object.freeze({ ambiguous: false, exitCode: 0 });
  } else {
    await writeState(Object.freeze({ ...localState, childJournal: childJournal({ command, event: effectiveEvent, status: "BEFORE_CHILD" }), phase: "BEFORE_CHILD", paymentMoved: false, eventDigest: effectiveEvent.eventDigest }));
    outcome = await dependencies.launcher(Object.freeze({ args: command.args, command: command.command }));
  }
  if (!resumeAfterChild && effectiveEvent.kind.startsWith("START_")) {
    if (!exact(outcome, ["ambiguous", "completion", "started"]) || outcome.ambiguous !== false || outcome.started !== true || typeof outcome.completion?.then !== "function" || typeof client?.appendEvent !== "function") invalid();
    // The launcher resolves only after the role has written and closed its
    // authenticated readiness pipe.  The child remains owned here until its
    // terminal result determines whether a package can be published.
    await client.appendEvent({ artifactDigest: null, kind: "ROLE_STARTED", subjectRun: effectiveEvent.subjectRun });
    outcome = await outcome.completion;
  }
  if (!exact(outcome, ["ambiguous", "exitCode"])) invalid();
  if (outcome.ambiguous || outcome.exitCode !== 0) {
    if (outcome.ambiguous) {
      await publishRecoveryRequired({ client, command, dependencies, event: effectiveEvent, localState });
    } else {
      if (typeof client?.putArtifact !== "function" || typeof client?.appendEvent !== "function") invalid();
      const summaryBytes = canonicalBytes(failureSummary({ localState, subjectRun: effectiveEvent.subjectRun }));
      const summaryDigest = sha256(summaryBytes);
      await (dependencies.validateRelayArtifact ?? defaultValidateRelayArtifact)({ artifactType: "failure-summary", bytes: summaryBytes, expectedDigest: summaryDigest, secretCanaries: [] });
      const acknowledgement = await client.putArtifact({ artifactType: "failure-summary", bytes: summaryBytes, expectedDigest: summaryDigest });
      if (!exact(acknowledgement, ["artifactType", "byteLength", "digest"]) || acknowledgement.artifactType !== "failure-summary" || acknowledgement.byteLength !== String(summaryBytes.length) || acknowledgement.digest !== summaryDigest) invalid();
      await writeState(Object.freeze({ ...localState, failureSummaryDigest: summaryDigest, phase: "TERMINAL_FAILURE", paymentMoved: false, eventDigest: effectiveEvent.eventDigest }));
      await client.appendEvent({ artifactDigest: summaryDigest, kind: "TERMINAL_FAILURE", subjectRun: effectiveEvent.subjectRun });
    }
    invalid();
  }
  if (!resumeAfterChild) await writeState(Object.freeze({ ...localState, childJournal: childJournal({ command, event: effectiveEvent, status: "CHILD_COMPLETE" }), phase: "CHILD_COMPLETE", paymentMoved: false, eventDigest: effectiveEvent.eventDigest }));
  const artifactType = effectiveEvent.kind === "PREFLIGHT_PLAN_READY" ? "preflight-participant-report" : effectiveEvent.kind.startsWith("REGISTER_") ? "identity-package" : "party-result-package";
  const packageBytes = await dependencies.readArtifactPackage({ artifactType, event: effectiveEvent, localState });
  if (!Buffer.isBuffer(packageBytes)) invalid();
  if (effectiveEvent.kind.startsWith("REGISTER_")) {
    const run = effectiveEvent.kind === "REGISTER_REHEARSAL" ? "rehearsal" : "stakeholder";
    await dependencies.verifyIdentityPackage(packageBytes, Object.freeze({ enrollmentSet: localState.enrollmentSet, invitationPath: localState[run].invitationPath, repositorySha: localState.repositorySha, role: localState.role, subjectRun: run }));
  }
  const digest = sha256(packageBytes);
  await (dependencies.validateRelayArtifact ?? defaultValidateRelayArtifact)({ artifactType, bytes: packageBytes, expectedDigest: digest, secretCanaries: [] });
  if (typeof client?.putArtifact !== "function" || typeof client?.appendEvent !== "function") invalid();
  if (!sameJournal(localState.childJournal, { command, event: effectiveEvent, status: "ARTIFACT_STORED" })) {
    const acknowledgement = await client.putArtifact({ artifactType, bytes: packageBytes, expectedDigest: digest });
    if (!exact(acknowledgement, ["artifactType", "byteLength", "digest"]) || acknowledgement.artifactType !== artifactType || acknowledgement.byteLength !== String(packageBytes.length) || acknowledgement.digest !== digest) invalid();
    await writeState(Object.freeze({ ...localState, childJournal: childJournal({ artifactDigest: digest, artifactType, command, event: effectiveEvent, status: "ARTIFACT_STORED" }), phase: "ARTIFACT_STORED", paymentMoved: false, eventDigest: effectiveEvent.eventDigest }));
  } else if (localState.childJournal.artifactDigest !== digest || localState.childJournal.artifactType !== artifactType) invalid();
  const kind = effectiveEvent.kind === "PREFLIGHT_PLAN_READY" ? "PREFLIGHT_PARTICIPANT_READY" : effectiveEvent.kind.startsWith("REGISTER_") ? "IDENTITY_PACKAGE_READY" : "ROLE_PACKAGE_READY";
  await client.appendEvent({ artifactDigest: digest, kind, subjectRun: effectiveEvent.subjectRun });
  await writeState(Object.freeze({ ...localState, childJournal: childJournal({ artifactDigest: digest, artifactType, command, event: effectiveEvent, status: "EVENT_APPENDED" }), phase: "EVENT_APPENDED", paymentMoved: false, eventDigest: effectiveEvent.eventDigest }));
  const completed = Object.freeze({ ...localState, childJournal: childJournal({ artifactDigest: digest, artifactType, command, event: effectiveEvent, status: "EVENT_APPENDED" }), phase: "TRANSITION_COMPLETE", paymentMoved: false, eventDigest: effectiveEvent.eventDigest });
  await writeState(completed);
  return Object.freeze({ artifactDigest: digest, kind, state: completed });
}

export async function createRoleSupervisor({ launchManifestPath, stateRoot, dependencies = {} }) {
  if (typeof launchManifestPath !== "string" || typeof stateRoot !== "string") invalid();
  if (dependencies.readState) {
    const checkpoint = await dependencies.readState(stateRoot);
    if (checkpoint !== null && checkpoint !== undefined) {
      if (checkpoint.phase === "LOCAL_SECRETS_READY") {
        const reader = dependencies.readLaunchManifest ?? readLaunchManifest;
        const manifest = await reader(launchManifestPath, dependencies.fileSystem);
        if (!dataExact(checkpoint, ["coordinationIdentity", "enrollmentBase64", "invitations", "paymentMoved", "phase", "preflight", "rehearsal", "releaseId", "repositorySha", "role", "schema", "sessionId", "stateRoot", "stakeholder"]) || checkpoint.schema !== SUPERVISOR_STATE_SCHEMA || checkpoint.paymentMoved !== false || checkpoint.releaseId !== manifest.releaseId || checkpoint.role !== manifest.role || checkpoint.repositorySha !== manifest.repositorySha || checkpoint.sessionId !== manifest.sessionId || checkpoint.stateRoot !== stateRoot || !/^[0-9a-f]{64}$/.test(manifest.bootstrapCapability)) invalid();
        const enrollment = validateLocalCheckpoint(checkpoint, { capabilityDigest: sha256(Buffer.from(manifest.bootstrapCapability, "hex")), releaseId: manifest.releaseId, repositorySha: manifest.repositorySha, role: manifest.role, sessionId: manifest.sessionId });
        if (!dependencies.createTransport || !dependencies.createCoordinationClient) invalid();
        const client = dependencies.createCoordinationClient({ coordinationIdentity: checkpoint.coordinationIdentity, manifest, transport: await dependencies.createTransport(manifest) });
        const result = await client.bootstrap({ enrollment });
        const state = await finalizeBootstrap({ bootstrapResult: result, checkpoint, dependencies, launchManifestPath, manifest, stateRoot });
        const localState = Object.freeze({ ...checkpoint, activeLaunchState: result.activeLaunchState, receipt: result.receipt, operatorPublicKey: await dependencies.resolveOperatorPublicKey?.(result.activeLaunchState) });
        return Object.freeze({ async bootstrap() { return state; }, async run() { if (typeof client.readEnrollmentSet !== "function" || typeof client.readEvents !== "function" || typeof localState.operatorPublicKey !== "string") invalid(); return runSupervisor({ client, dependencies, localState }); }, state });
      }
      if (checkpoint.schema !== SUPERVISOR_STATE_SCHEMA || !FULL_CHECKPOINT_PHASES.has(checkpoint.phase) || checkpoint.paymentMoved !== false || checkpoint.role !== "payer" && checkpoint.role !== "payee") invalid();
      if (!dependencies.validateActiveLaunchState || !dependencies.createTransport || !dependencies.resolveOperatorPublicKey || !dependencies.createResumedCoordinationClient) invalid();
      const activeLaunchState = await dependencies.validateActiveLaunchState(checkpoint.activeLaunchState);
      if (activeLaunchState.paymentMoved !== false || activeLaunchState.role !== checkpoint.role || activeLaunchState.repositorySha !== checkpoint.repositorySha || activeLaunchState.sessionId !== checkpoint.sessionId) invalid();
      validateDurableCheckpointShape(checkpoint, activeLaunchState, stateRoot);
      validateLocalCheckpoint(checkpoint, { capabilityDigest: activeLaunchState.capabilityDigest, releaseId: activeLaunchState.releaseId, repositorySha: checkpoint.repositorySha, role: checkpoint.role, sessionId: checkpoint.sessionId });
      if (typeof dependencies.scanCheckpointDirectories === "function") await dependencies.scanCheckpointDirectories({ checkpoint, stateRoot });
      if (typeof dependencies.retireLaunchManifest === "function") await dependencies.retireLaunchManifest(launchManifestPath);
      const earlyCheckpoint = checkpoint.events === undefined && checkpoint.enrollmentSet === undefined;
      if (!earlyCheckpoint && ((checkpoint.events === undefined) !== (checkpoint.enrollmentSet === undefined))) invalid();
      const replay = earlyCheckpoint ? Object.freeze({ senderState: Object.freeze({ previousEventDigest: null, sequence: "0" }) }) : await authenticateSupervisorReplay({ events: checkpoint.events, enrollmentSet: checkpoint.enrollmentSet, operatorPublicKey: await dependencies.resolveOperatorPublicKey(activeLaunchState), releaseId: activeLaunchState.releaseId, repositorySha: checkpoint.repositorySha, sessionId: checkpoint.sessionId, localRole: checkpoint.role, verifyEnrollmentSet: dependencies.verifyEnrollmentSet, verifyVerifierPublication: dependencies.verifyVerifierPublication });
      const transport = await dependencies.createTransport(activeLaunchState);
      const client = await dependencies.createResumedCoordinationClient({ activeLaunchState, coordinationIdentity: checkpoint.coordinationIdentity, senderState: replay.senderState, transport });
      const state = Object.freeze({ ...checkpoint, ...(earlyCheckpoint ? {} : { enrollmentSet: replay.enrollmentSet, events: replay.events, view: replay.view }), senderState: replay.senderState });
      const operatorPublicKey = await dependencies.resolveOperatorPublicKey(activeLaunchState);
      const localState = Object.freeze({ ...state, operatorPublicKey });
      return Object.freeze({ async bootstrap() { return state; }, async run() { if (typeof client?.readEnrollmentSet !== "function" || typeof client?.readEvents !== "function") invalid(); return runSupervisor({ client, dependencies, localState }); }, state });
    }
  }
  const reader = dependencies.readLaunchManifest ?? readLaunchManifest;
  const manifest = await reader(launchManifestPath, dependencies.fileSystem);
  safePrivateRoot(stateRoot);
  const base = { paymentMoved: false, releaseId: manifest.releaseId, repositorySha: manifest.repositorySha, role: manifest.role, schema: SUPERVISOR_STATE_SCHEMA, sessionId: manifest.sessionId, stateRoot };
  let activeClient, activeState;
  async function bootstrap() {
    if (!dependencies.verifyRepositoryState || !dependencies.createCoordinationIdentity || !dependencies.createLocalPreflightEnrollment || !dependencies.createInvitations || !dependencies.createTransport || !dependencies.createCoordinationClient || !dependencies.writeState) invalid();
    if (await dependencies.verifyRepositoryState(manifest.repositorySha) !== true) invalid();
    const coordinationIdentity = await dependencies.createCoordinationIdentity({ role: manifest.role });
    const preflight = await dependencies.createLocalPreflightEnrollment({ role: manifest.role });
    const invitations = await dependencies.createInvitations({ role: manifest.role });
    if (!Array.isArray(invitations) || invitations.length !== 2 || invitations[0].subjectRun !== "rehearsal" || invitations[1].subjectRun !== "stakeholder") invalid();
    if (!/^[0-9a-f]{64}$/.test(manifest.bootstrapCapability) || coordinationIdentity?.keyId !== `${manifest.role}-coordination` || typeof coordinationIdentity.privateKeyPem !== "string" || typeof coordinationIdentity.publicKey !== "string" || preflight?.publicArtifact?.paymentMoved !== false || preflight.publicArtifact.publicKey === undefined || preflight.publicArtifact.repositorySha !== manifest.repositorySha || preflight.publicArtifact.role !== manifest.role) invalid();
    const invitationMap = Object.fromEntries(invitations.map((invitation) => [invitation.subjectRun, invitation]));
    for (const run of ["rehearsal", "stakeholder"]) if (!invitationMap[run] || !/^0x[0-9a-f]{40}$/.test(invitationMap[run].address) || invitationMap[run].algorithm !== "eip191" || !/^0x[0-9a-f]{130}$/.test(invitationMap[run].signature) || typeof invitationMap[run].secretPath !== "string") invalid();
    if (invitationMap.rehearsal.address === invitationMap.stakeholder.address) invalid();
    const unsignedEnrollment = { capabilityDigest: sha256(Buffer.from(manifest.bootstrapCapability, "hex")), coordinationKey: { algorithm: "ed25519", keyId: coordinationIdentity.keyId, publicKey: coordinationIdentity.publicKey }, invitations: { rehearsal: { address: invitationMap.rehearsal.address, algorithm: "eip191", signature: invitationMap.rehearsal.signature }, stakeholder: { address: invitationMap.stakeholder.address, algorithm: "eip191", signature: invitationMap.stakeholder.signature } }, paymentMoved: false, preflightKey: { algorithm: "ed25519", keyId: `${manifest.role}-preflight`, publicKey: preflight.publicArtifact.publicKey }, releaseId: manifest.releaseId, repositorySha: manifest.repositorySha, role: manifest.role, schema: "clockchain.bilateral-coordination-enrollment/v1", sessionId: manifest.sessionId };
    const enrollment = verifyCoordinationEnrollment({ ...unsignedEnrollment, signature: sign(null, coordinationEnrollmentSignaturePreimage(unsignedEnrollment), coordinationIdentity.privateKeyPem).toString("base64") });
    if (typeof preflight.privateKeyPath !== "string" || (preflight.publicArtifactPath !== undefined && preflight.publicArtifactPath !== `${stateRoot}/preflight/preflight-key-enrollment.json`)) invalid();
    const localPreflight = Object.freeze({ outputPath: `${stateRoot}/preflight/report.json`, planPath: `${stateRoot}/preflight/plan.json`, privateKeyPath: `${stateRoot}/preflight/preflight.ed25519.pem`, publicArtifact: preflight.publicArtifact, publicArtifactPath: `${stateRoot}/preflight/preflight-key-enrollment.json` });
    const roleArtifacts = fixedRoleArtifacts(stateRoot, invitations);
    const checkpoint = Object.freeze({ ...base, coordinationIdentity, enrollmentBase64: canonicalBytes(enrollment).toString("base64"), invitations: Object.freeze([...invitations]), phase: "LOCAL_SECRETS_READY", preflight: localPreflight, rehearsal: roleArtifacts.rehearsal, stakeholder: roleArtifacts.stakeholder });
    await dependencies.writeState(checkpoint);
    const transport = await dependencies.createTransport(manifest);
    const client = dependencies.createCoordinationClient({ coordinationIdentity, manifest, transport });
    const bootstrapResult = await client.bootstrap({ enrollment });
    const result = await finalizeBootstrap({ bootstrapResult, checkpoint, dependencies, launchManifestPath, manifest, stateRoot });
    activeClient = client;
    activeState = Object.freeze({ ...checkpoint, activeLaunchState: bootstrapResult.activeLaunchState, receipt: bootstrapResult.receipt, operatorPublicKey: await dependencies.resolveOperatorPublicKey?.(bootstrapResult.activeLaunchState) });
    return result;
  }
  const state = Object.freeze({ ...base, phase: "EMPTY" });
  return Object.freeze({ bootstrap, async run() { if (!activeState) await bootstrap(); if (typeof activeClient?.readEnrollmentSet !== "function" || typeof activeClient?.readEvents !== "function" || typeof activeState?.operatorPublicKey !== "string") invalid(); return runSupervisor({ client: activeClient, dependencies, localState: activeState }); }, state });
}

export async function runSupervisor(input) {
  if (input?.client) {
    const { client, dependencies = {} } = input;
    let localState = input.localState;
    if (!localState || typeof client.readEnrollmentSet !== "function" || typeof client.readEvents !== "function" || typeof localState.operatorPublicKey !== "string" || typeof localState.releaseId !== "string" || typeof localState.repositorySha !== "string" || typeof localState.sessionId !== "string" || !["payer", "payee"].includes(localState.role)) invalid();
    if (typeof client.readEnrollmentReadiness === "function") {
      let waitingReported = false;
      let readyReported = false;
      for (;;) {
        const ready = assertEnrollmentReadiness(await client.readEnrollmentReadiness({ waitMs: 30000 }), localState);
        if (ready) {
          if (!readyReported && typeof dependencies.writeStatus === "function") {
            dependencies.writeStatus(Object.freeze({ paymentMoved: false, role: localState.role, status: "PEER_READY" }));
            readyReported = true;
          }
          break;
        }
        if (!waitingReported && typeof dependencies.writeStatus === "function") {
          dependencies.writeStatus(Object.freeze({ paymentMoved: false, role: localState.role, status: "WAITING_FOR_PEER" }));
          waitingReported = true;
        }
      }
    }
    let enrollmentSet = await client.readEnrollmentSet();
    const processed = new Set(localState.processedEventDigests ?? []);
    let previous = null, replay;
    do {
      const events = await client.readEvents({ after: null, waitMs: 30000 });
      if (!Array.isArray(events) || previous && (events.length < previous.length || previous.some((event, index) => events[index]?.eventDigest !== event.eventDigest))) invalid();
      replay = await authenticateSupervisorReplay({ events, enrollmentSet, operatorPublicKey: localState.operatorPublicKey, releaseId: localState.releaseId, repositorySha: localState.repositorySha, sessionId: localState.sessionId, localRole: localState.role, verifyEnrollmentSet: dependencies.verifyEnrollmentSet, verifyVerifierPublication: typeof dependencies.verifyVerifierPublication === "function" ? (input) => dependencies.verifyVerifierPublication(input, client) : undefined });
      enrollmentSet = replay.enrollmentSet;
      previous = replay.events;
      const checkpoint = (phase) => Object.freeze({
        ...localState,
        authenticatedEvents: replay.events,
        enrollmentSet,
        events: replay.events,
        paymentMoved: false,
        phase,
        processedEventDigests: Object.freeze([...processed]),
        senderState: replay.senderState,
        view: replay.view,
      });
      const persist = async (phase) => {
        if (typeof dependencies.writeState === "function") await dependencies.writeState(checkpoint(phase));
      };
      if (["COMPLETE", "ABORTED"].includes(replay.view.state)) return Object.freeze({ ...replay, processedEventDigests: Object.freeze([...processed]) });
      const own = (kind) => replay.events.some((entry) => entry.role === localState.role && entry.kind === kind && entry.subjectRun === "release");
      if (!own("ENROLLMENT_CONFIRMED") && typeof client.appendEvent === "function") {
        await persist("ENROLLMENT_CONFIRMING");
        await client.appendEvent({ artifactDigest: null, kind: "ENROLLMENT_CONFIRMED", subjectRun: "release" });
        continue;
      }
      if (replay.view.facts.enrollmentReceipt && replay.view.facts.waitForFunding && !own("FUNDING_INPUTS_READY")) {
        if (typeof dependencies.verifyFundingInputs !== "function" || typeof client.appendEvent !== "function" || !Array.isArray(localState.invitations) || localState.invitations.length !== 2) invalid();
        const addresses = localState.invitations.map((invitation) => invitation?.address);
        if (addresses.some((address) => typeof address !== "string")) invalid();
        await persist("VERIFYING_FUNDING_INPUTS");
        await dependencies.verifyFundingInputs(Object.freeze({ addresses: Object.freeze(addresses), enrollmentSet, repositorySha: localState.repositorySha, role: localState.role, sessionId: localState.sessionId }));
        await client.appendEvent({ artifactDigest: null, kind: "FUNDING_INPUTS_READY", subjectRun: "release" });
        continue;
      }
      if (replay.view.facts.fundingInputsReady.payer && replay.view.facts.fundingInputsReady.payee && !own("TOKEN_READY")) {
        if (typeof dependencies.ensureToken !== "function" || typeof client.putArtifact !== "function" || typeof client.appendEvent !== "function" || !localState.coordinationIdentity) invalid();
        const token = await dependencies.ensureToken({ repositorySha: localState.repositorySha, role: localState.role });
        const tokenPath = token?.tokenPath ?? localState.tokenPath;
        if (typeof tokenPath !== "string") invalid();
        await persist("TOKEN_COMMITMENT_PREPARING");
        const commitment = await (dependencies.readAndSignTokenCommitment ?? defaultReadAndSignTokenCommitment)({ coordinationPrivateKeyPem: localState.coordinationIdentity.privateKeyPem, coordinationPublicKey: localState.coordinationIdentity.publicKey, repositorySha: localState.repositorySha, role: localState.role, tokenPath });
        if (!commitment || commitment.paymentMoved !== false || commitment.repositorySha !== localState.repositorySha || commitment.role !== localState.role) invalid();
        const bytes = canonicalBytes(commitment);
        const digest = sha256(bytes);
        const acknowledgement = await client.putArtifact({ artifactType: "token-commitment", bytes, expectedDigest: digest });
        if (!exact(acknowledgement, ["artifactType", "byteLength", "digest"]) || acknowledgement.artifactType !== "token-commitment" || acknowledgement.byteLength !== String(bytes.length) || acknowledgement.digest !== digest) invalid();
        localState = Object.freeze({ ...localState, tokenCommitment: commitment, tokenPath });
        await persist("TOKEN_READY");
        await client.appendEvent({ artifactDigest: digest, kind: "TOKEN_READY", subjectRun: "release" });
        continue;
      }
      if (localState.recovery) {
        const recovery = localState.recovery;
        if (!exact(recovery, ["authorizationUsed", "commandEvent", "manifestBytes", "manifestDigest", "stage", "subjectRun"]) || typeof recovery.authorizationUsed !== "boolean" || !["MANIFEST_STORED", "EVENT_APPEND_ATTEMPTED", "EVENT_APPENDED"].includes(recovery.stage) || typeof recovery.manifestBytes !== "string" || !/^[0-9a-f]{64}$/.test(recovery.manifestDigest) || !["rehearsal", "stakeholder", "release"].includes(recovery.subjectRun)) invalid();
        const command = buildSupervisorCommand({ event: recovery.commandEvent, localState });
        const manifestBytes = Buffer.from(recovery.manifestBytes, "base64");
        if (!manifestBytes.equals(canonicalBytes(recoveryManifest({ command, localState, subjectRun: recovery.subjectRun }))) || sha256(manifestBytes) !== recovery.manifestDigest) invalid();
        const published = replay.events.filter((entry) => entry.role === localState.role && entry.kind === "RECOVERY_REQUIRED" && entry.subjectRun === recovery.subjectRun);
        if (published.length > 1 || published.length === 1 && published[0].artifactDigest !== recovery.manifestDigest) invalid();
        if (published.length === 0) {
          if (typeof client.appendEvent !== "function") invalid();
          if (recovery.stage !== "EVENT_APPEND_ATTEMPTED") {
            localState = Object.freeze({ ...localState, phase: "RECOVERY_REQUIRED", recovery: Object.freeze({ ...recovery, stage: "EVENT_APPEND_ATTEMPTED" }) });
            await persist("RECOVERY_REQUIRED");
          }
          await client.appendEvent({ artifactDigest: recovery.manifestDigest, kind: "RECOVERY_REQUIRED", subjectRun: recovery.subjectRun });
          localState = Object.freeze({ ...localState, phase: "RECOVERY_REQUIRED", recovery: Object.freeze({ ...recovery, stage: "EVENT_APPENDED" }) });
          await persist("RECOVERY_REQUIRED");
          continue;
        }
        if (recovery.stage !== "EVENT_APPENDED") {
          localState = Object.freeze({ ...localState, phase: "RECOVERY_REQUIRED", recovery: Object.freeze({ ...recovery, stage: "EVENT_APPENDED" }) });
          await persist("RECOVERY_REQUIRED");
          continue;
        }
      }
      const intentState = await runCommercialIntentPhase({ client, dependencies, localState: checkpoint(localState.phase), replay });
      if (intentState) {
        localState = intentState;
        continue;
      }
      const completionKind = Object.freeze({ PREFLIGHT_PLAN_READY: "PREFLIGHT_PARTICIPANT_READY", REGISTER_REHEARSAL: "IDENTITY_PACKAGE_READY", REGISTER_STAKEHOLDER: "IDENTITY_PACKAGE_READY", REHEARSAL_DESCRIPTOR_READY: "DESCRIPTOR_ACCEPTED", STAKEHOLDER_DESCRIPTOR_READY: "DESCRIPTOR_ACCEPTED", START_REHEARSAL: "ROLE_PACKAGE_READY", START_STAKEHOLDER: "ROLE_PACKAGE_READY" });
      const completionFor = (entry) => completionKind[entry.kind] && replay.events.some((candidate) => candidate.role === localState.role && candidate.kind === completionKind[entry.kind] && candidate.subjectRun === entry.subjectRun);
      const journalCommand = localState.childJournal && replay.events.find((entry) => entry.role === "operator" && entry.eventDigest === localState.childJournal.eventDigest);
      if (journalCommand && completionFor(journalCommand) && !processed.has(journalCommand.eventDigest)) {
        processed.add(journalCommand.eventDigest);
        const { childJournal, descriptorJournal, eventDigest, recovery, ...stable } = localState;
        localState = Object.freeze({ ...stable, phase: "EVENT_PROCESSED" });
        await persist("EVENT_PROCESSED");
        continue;
      }
      const startOrderSatisfied = (entry) =>
        localState.role !== "payer" ||
        !["START_REHEARSAL", "START_STAKEHOLDER"].includes(entry.kind) ||
        replay.events.some((candidate) =>
          candidate.role === "payee" &&
          candidate.kind === "ROLE_STARTED" &&
          candidate.subjectRun === entry.subjectRun);
      const event = replay.events.find((entry) => entry.role === "operator" && Object.hasOwn(SUPERVISOR_COMMAND_POLICY, entry.kind) && !processed.has(entry.eventDigest) && localState.recovery?.commandEvent?.eventDigest !== entry.eventDigest && (!completionKind[entry.kind] || !completionFor(entry)) && startOrderSatisfied(entry));
      if (event) {
        const command = ["PREFLIGHT_PLAN_READY", "REGISTER_REHEARSAL", "REGISTER_STAKEHOLDER", "START_REHEARSAL", "START_STAKEHOLDER"].includes(event.kind)
          ? buildSupervisorCommand({ event, localState })
          : undefined;
        if (command !== undefined && localState.phase === "BEFORE_CHILD" && sameJournal(localState.childJournal, { command, event, status: "BEFORE_CHILD" })) {
          const recovery = await publishRecoveryRequired({ client, command, dependencies, event, localState: checkpoint(localState.phase) });
          localState = Object.freeze({ ...localState, phase: "RECOVERY_REQUIRED", recovery });
          continue;
        }
        const result = await executeSupervisorTransition({ client, event, localState: checkpoint(localState.phase), dependencies });
        if (result?.state) {
          localState = result.state;
          if (result.state.childJournal?.eventDigest) processed.add(result.state.childJournal.eventDigest);
        }
        processed.add(event.eventDigest);
        const { childJournal, descriptorJournal, eventDigest, recovery, ...stable } = localState;
        localState = Object.freeze({ ...stable, phase: "EVENT_PROCESSED" });
        await persist("EVENT_PROCESSED");
      }
    } while (dependencies.shouldContinue?.() !== false);
    return Object.freeze({ ...replay, processedEventDigests: Object.freeze([...processed]) });
  }
  const supervisor = await createRoleSupervisor(input);
  return supervisor.run();
}
