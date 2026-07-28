import {
  createHash,
  createPrivateKey,
  createPublicKey,
  timingSafeEqual,
  X509Certificate,
} from "node:crypto";
import https from "node:https";
import { isIP } from "node:net";
import { checkServerIdentity } from "node:tls";

import { canonicalizeReceiptEventValue } from "../../canonical.mjs";
import { canonicalBytes } from "../canonical.mjs";
import { KEY_ID_PATTERN } from "../descriptor.mjs";
import { validateRelayArtifact } from "./artifact.mjs";
import {
  createCapabilityRegistration,
  verifyCapabilityRegistration,
} from "./capability-registration.mjs";
import { CoordinationClientError } from "./client.mjs";
import {
  COORDINATION_ENVELOPE_SCHEMA,
  createCoordinationEnvelope,
  eventDigest,
  verifyCoordinationEnvelope,
} from "./envelope.mjs";
import {
  parseCoordinationEnrollment,
  parseCoordinationEnrollmentSet,
} from "./enrollment.mjs";
import {
  COORDINATION_EVENT_KINDS,
  initialReleaseView,
  RELEASE_STATES,
} from "./lifecycle.mjs";
import {
  CAPABILITY_REGISTRATION_RECEIPT_SCHEMA,
  VERIFIER_PUBLICATION_SCHEMA,
  VERIFIED_EVENT_SCHEMA,
} from "./relay.mjs";

export const OPERATOR_CLIENT_MAX_RESPONSE_BYTES = 3_145_728;
export const OPERATOR_CLIENT_CONNECT_TIMEOUT_MS = 5_000;
export const OPERATOR_CLIENT_HEADER_TIMEOUT_MS = 5_000;
export const OPERATOR_CLIENT_BODY_TIMEOUT_MS = 5_000;
export const OPERATOR_CLIENT_TOTAL_TIMEOUT_MS = 45_000;

const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const REPOSITORY_SHA_PATTERN = /^[0-9a-f]{40}$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const ARTIFACT_TYPE_PATTERN = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const EVENT_KINDS = new Set(COORDINATION_EVENT_KINDS);
const ARTIFACT_TYPES = new Set([
  "coordination-enrollment", "failure-summary", "identity-package", "party-result-package",
  "preflight-aggregate-report", "preflight-participant-report", "preflight-plan",
  "preflight-public-key", "recovery-command-manifest", "signed-descriptor", "token-commitment",
]);
const PUBLICATION_KEYS = Object.freeze([
  "paymentMoved", "publicationDigest", "releaseId", "repositorySha", "schema", "sessionId", "status", "subjectRun",
]);
const VIEW_KEYS = Object.freeze(["facts", "paymentMoved", "releaseId", "repositorySha", "sessionId", "state"]);
const CAPABILITY_RECEIPT_KEYS = Object.freeze([
  "capabilities", "paymentMoved", "registrationDigest", "releaseId", "repositorySha", "requestDigest", "schema", "sessionId",
]);

export class OperatorRelayClientError extends CoordinationClientError {
  constructor(code = "COORDINATION_OPERATOR_CLIENT_INVALID") {
    super(code);
    this.name = new.target.name;
    this.code = /^COORDINATION_[A-Z_]+$/.test(code) ? code : "COORDINATION_OPERATOR_CLIENT_INVALID";
  }
}

function invalid() { throw new OperatorRelayClientError(); }
function isPlainObject(value) {
  if (value === null || typeof value !== "object") return false;
  try { const p = Object.getPrototypeOf(value); return p === Object.prototype || p === null; } catch { return false; }
}
function exact(value, keys) {
  if (!isPlainObject(value)) invalid();
  let own;
  try { own = Reflect.ownKeys(value); } catch { invalid(); }
  if (own.length !== keys.length || own.some((key) => typeof key !== "string" || !keys.includes(key))) invalid();
  const result = Object.create(null);
  for (const key of keys) {
    let descriptor;
    try { descriptor = Object.getOwnPropertyDescriptor(value, key); } catch { invalid(); }
    if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, "value")) invalid();
    result[key] = descriptor.value;
  }
  return result;
}
function canonicalJson(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > OPERATOR_CLIENT_MAX_RESPONSE_BYTES) invalid();
  let value;
  try { value = JSON.parse(bytes.toString("utf8")); } catch { invalid(); }
  let expected;
  try { expected = Buffer.from(JSON.stringify(canonicalizeReceiptEventValue(value)), "utf8"); } catch { invalid(); }
  if (!expected.equals(bytes)) invalid();
  return value;
}
function sha256(bytes) { return createHash("sha256").update(bytes).digest("hex"); }
function rawHeaderValues(headers, name) {
  const values = [];
  for (let index = 0; index < headers.length; index += 2) {
    if (headers[index].toLowerCase() === name) values.push(headers[index + 1]);
  }
  return values;
}
function assertContext(value) {
  const data = exact(value, ["releaseId", "repositorySha", "sessionId"]);
  if (typeof data.releaseId !== "string" || data.releaseId.length === 0 || data.releaseId.length > 256 || data.releaseId.trim() !== data.releaseId || !/^[ -~]+$/.test(data.releaseId) || typeof data.repositorySha !== "string" || !REPOSITORY_SHA_PATTERN.test(data.repositorySha) || typeof data.sessionId !== "string" || !UUID_PATTERN.test(data.sessionId)) invalid();
  return Object.freeze(data);
}
function assertIdentity(value) {
  const data = exact(value, ["keyId", "privateKeyPem", "publicKey"]);
  if (typeof data.keyId !== "string" || !KEY_ID_PATTERN.test(data.keyId) || typeof data.publicKey !== "string" || typeof data.privateKeyPem !== "string" || data.privateKeyPem.length === 0 || Buffer.byteLength(data.privateKeyPem) > 1024) invalid();
  let privateKey; let raw;
  try {
    privateKey = createPrivateKey(data.privateKeyPem);
    if (privateKey.asymmetricKeyType !== "ed25519" || privateKey.export({ format: "pem", type: "pkcs8" }) !== data.privateKeyPem) invalid();
    const der = createPublicKey(privateKey).export({ format: "der", type: "spki" });
    if (der.length !== ED25519_SPKI_PREFIX.length + 32 || !der.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX)) invalid();
    raw = der.subarray(ED25519_SPKI_PREFIX.length);
  } catch { invalid(); }
  const supplied = Buffer.from(data.publicKey, "base64");
  if (supplied.length !== 32 || supplied.toString("base64") !== data.publicKey || !timingSafeEqual(supplied, raw)) invalid();
  return Object.freeze({ keyId: data.keyId, privateKeyPem: data.privateKeyPem, publicKey: data.publicKey });
}
function assertSignal(value) { if (!(value instanceof AbortSignal)) invalid(); return value; }
function frozen(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) { for (const child of Object.values(value)) frozen(child); Object.freeze(value); }
  return value;
}
function exactResponse(value, type) {
  const response = exact(value, ["body", "contentType", "statusCode"]);
  if (response.statusCode !== 200 || response.contentType !== type || !Buffer.isBuffer(response.body)) invalid();
  const body = Buffer.from(response.body);
  if (body.length > OPERATOR_CLIENT_MAX_RESPONSE_BYTES || (type === "application/json" && body.length === 0)) invalid();
  if (type === "application/json") canonicalJson(body);
  return body;
}
function capabilityInput(value) {
  const capabilities = exact(value, ["payee", "payer"]);
  const output = Object.create(null);
  for (const role of ["payee", "payer"]) {
    const entry = exact(capabilities[role], ["capabilityDigest", "expiresAtMs"]);
    if (typeof entry.capabilityDigest !== "string" || !SHA256_PATTERN.test(entry.capabilityDigest) || typeof entry.expiresAtMs !== "string" || !DECIMAL_PATTERN.test(entry.expiresAtMs)) invalid();
    output[role] = Object.freeze({ capabilityDigest: entry.capabilityDigest, expiresAtMs: entry.expiresAtMs });
  }
  if (output.payee.capabilityDigest === output.payer.capabilityDigest) invalid();
  return Object.freeze(output);
}
function validatePublication(value, context, subjectRun) {
  const claim = exact(value, PUBLICATION_KEYS);
  if (claim.schema !== VERIFIER_PUBLICATION_SCHEMA || claim.paymentMoved !== false || typeof claim.publicationDigest !== "string" || !SHA256_PATTERN.test(claim.publicationDigest) || claim.releaseId !== context.releaseId || claim.repositorySha !== context.repositorySha || claim.sessionId !== context.sessionId || claim.subjectRun !== subjectRun || !["rehearsal", "stakeholder"].includes(claim.subjectRun) || claim.status !== "VERIFICATION_PASSED") invalid();
  return frozen({ ...claim });
}
function validateEnrollmentBytes(bytes, context) {
  let set;
  try { set = parseCoordinationEnrollmentSet(bytes); } catch { invalid(); }
  if (set.paymentMoved !== false || set.releaseId !== context.releaseId || set.repositorySha !== context.repositorySha || set.sessionId !== context.sessionId) invalid();
  const keys = Object.create(null);
  for (const role of ["payee", "payer"]) {
    const entry = set.enrollments?.[role];
    if (!isPlainObject(entry) || typeof entry.enrollmentBase64 !== "string") invalid();
    let enrollment;
    try { enrollment = parseCoordinationEnrollment(Buffer.from(entry.enrollmentBase64, "base64")); } catch { invalid(); }
    if (enrollment.role !== role || enrollment.releaseId !== context.releaseId || enrollment.repositorySha !== context.repositorySha || enrollment.sessionId !== context.sessionId || enrollment.paymentMoved !== false) invalid();
    keys[role] = enrollment.coordinationKey.publicKey;
  }
  return Object.freeze(keys);
}
function expectedEventKey(event, identity, roleKeys) {
  if (event.role === "operator") return identity.publicKey;
  if (!["payer", "payee"].includes(event.role)) invalid();
  return roleKeys[event.role];
}
function validateEvent(event, context, identity, roleKeys) {
  const expectedPublicKey = expectedEventKey(event, identity, roleKeys);
  let verified;
  try { verified = verifyCoordinationEnvelope(event, { expectedPublicKey, expectedReleaseId: context.releaseId, expectedRepositorySha: context.repositorySha, expectedRole: event.role, expectedSessionId: context.sessionId, expectedSubjectRun: event.subjectRun }); } catch { invalid(); }
  if (!EVENT_KINDS.has(verified.kind) || verified.paymentMoved !== false || eventDigest(verified) !== verified.eventDigest || (verified.role === "operator" && verified.signature.keyId !== identity.keyId)) invalid();
  return frozen(verified);
}
function operatorSenderState(events) {
  let previousEventDigest = null;
  let sequence = "0";
  for (const event of events) {
    if (event.role !== "operator") continue;
    if (event.sequence !== sequence || event.previousEventDigest !== previousEventDigest) invalid();
    previousEventDigest = event.eventDigest;
    if (Number(sequence) === Number.MAX_SAFE_INTEGER) invalid();
    sequence = String(Number(sequence) + 1);
  }
  return Object.freeze({ previousEventDigest, sequence });
}
function validateSenderChains(events) {
  const states = Object.create(null);
  for (const event of events) {
    const state = states[event.role] ?? { previousEventDigest: null, sequence: "0" };
    if (event.sequence !== state.sequence || event.previousEventDigest !== state.previousEventDigest) invalid();
    states[event.role] = { previousEventDigest: event.eventDigest, sequence: String(Number(state.sequence) + 1) };
  }
  return Object.freeze(states);
}
function validateFacts(value, template) {
  if (template === null) {
    if (value !== null && (typeof value !== "string" || !SHA256_PATTERN.test(value))) invalid();
    return value;
  }
  if (typeof template === "boolean") {
    if (typeof value !== "boolean") invalid();
    return value;
  }
  const keys = Object.keys(template);
  const data = exact(value, keys);
  const output = Object.create(null);
  for (const key of keys) output[key] = validateFacts(data[key], template[key]);
  return frozen(output);
}

function assertOperatorRoute(request) {
  if (!isPlainObject(request)) invalid();
  const keys = Reflect.ownKeys(request);
  const allowed = new Set(["artifactType", "body", "method", "path", "signal"]);
  if (!keys.includes("body") || !keys.includes("method") || !keys.includes("path") || keys.some((key) => typeof key !== "string" || !allowed.has(key))) invalid();
  const data = exact(request, keys);
  if (data.signal !== undefined) assertSignal(data.signal);
  if (typeof data.path !== "string" || data.path.includes("%") || data.path.includes("#") || data.path.includes("..") || data.path.startsWith("//")) invalid();
  const artifact = /^\/v1\/artifacts\/[0-9a-f]{64}$/.test(data.path);
  const events = new RegExp(`^/v1/sessions/${UUID_PATTERN.source.slice(1, -1)}/events\\?(?:after=[0-9a-f]{64}&)?waitMs=(?:0|[1-9][0-9]*)$`).test(data.path);
  const view = new RegExp(`^/v1/sessions/${UUID_PATTERN.source.slice(1, -1)}/view$`).test(data.path);
  const enrollments = new RegExp(`^/v1/sessions/${UUID_PATTERN.source.slice(1, -1)}/enrollments$`).test(data.path);
  const publication = new RegExp(`^/v1/sessions/${UUID_PATTERN.source.slice(1, -1)}/verifier-publications/(?:rehearsal|stakeholder)$`).test(data.path);
  const post = new Set(["/v1/capabilities", "/v1/events", "/v1/verified-events"]);
  if (data.method === "POST") {
    if (!post.has(data.path) || !Buffer.isBuffer(data.body) || data.body.length === 0 || data.body.length > 65_536 || data.artifactType !== undefined) invalid();
  } else if (data.method === "PUT") {
    if (!artifact || typeof data.artifactType !== "string" || !ARTIFACT_TYPE_PATTERN.test(data.artifactType) || !ARTIFACT_TYPES.has(data.artifactType) || !Buffer.isBuffer(data.body) || data.body.length === 0 || data.body.length > OPERATOR_CLIENT_MAX_RESPONSE_BYTES) invalid();
  } else if (data.method === "GET") {
    if ((!artifact && !events && !view && !enrollments && !publication) || data.body !== null || (artifact && (!ARTIFACT_TYPES.has(data.artifactType) || typeof data.artifactType !== "string"))) invalid();
  } else invalid();
  return Object.freeze({ artifactType: data.artifactType, body: data.body === null ? null : Buffer.from(data.body), method: data.method, path: data.path, signal: data.signal });
}

function assertRequestTiming(value) {
  const data = exact(value, ["bodyMs", "connectMs", "headerMs", "totalMs"]);
  for (const key of ["bodyMs", "connectMs", "headerMs", "totalMs"]) {
    if (!Number.isSafeInteger(data[key]) || data[key] <= 0 || data[key] > 60_000) invalid();
  }
  return Object.freeze(data);
}

function createPinnedOperatorHttpsTransportInternal(input, timing) {
  const data = exact(input, ["expectedFingerprint", "relayUrl", "tlsCertificatePem"]);
  if (typeof data.expectedFingerprint !== "string" || !SHA256_PATTERN.test(data.expectedFingerprint) || typeof data.tlsCertificatePem !== "string" || data.tlsCertificatePem.length === 0) invalid();
  let endpoint;
  try { endpoint = new URL(data.relayUrl); } catch { invalid(); }
  if (endpoint.protocol !== "https:" || endpoint.username !== "" || endpoint.password !== "" || endpoint.pathname !== "/" || endpoint.search !== "" || endpoint.hash !== "" || !isIP(endpoint.hostname) || endpoint.port === "" || Number(endpoint.port) > 65_535 || endpoint.origin !== data.relayUrl) invalid();
  const expected = Buffer.from(data.expectedFingerprint, "hex");
  try {
    const certificateFingerprint = createHash("sha256").update(new X509Certificate(data.tlsCertificatePem).raw).digest();
    if (!timingSafeEqual(certificateFingerprint, expected)) invalid();
  } catch { invalid(); }
  return Object.freeze({
    async request(value) {
      const request = assertOperatorRoute(value);
      if (request.signal?.aborted) throw new OperatorRelayClientError("COORDINATION_CLIENT_ABORTED");
      return new Promise((resolve, reject) => {
        let settled = false; let secure = false; let response; let connectTimer; let headerTimer; let bodyTimer; let totalTimer; let handle;
        const clearTimers = () => { clearTimeout(connectTimer); clearTimeout(headerTimer); clearTimeout(bodyTimer); clearTimeout(totalTimer); };
        const fail = (error) => { if (settled) return; settled = true; clearTimers(); response?.destroy(); handle?.destroy(); reject(error); };
        const finish = (answer) => { if (settled) return; settled = true; clearTimers(); resolve(answer); };
        const headers = { host: endpoint.host };
        if (request.body !== null) { headers["content-length"] = String(request.body.length); headers["content-type"] = request.method === "PUT" ? "application/octet-stream" : "application/json"; }
        if (request.method === "PUT") headers["x-clockchain-artifact-type"] = request.artifactType;
        totalTimer = setTimeout(() => fail(new OperatorRelayClientError("COORDINATION_TRANSPORT_AMBIGUOUS")), timing.totalMs);
        connectTimer = setTimeout(() => fail(new OperatorRelayClientError("COORDINATION_TRANSPORT_AMBIGUOUS")), timing.connectMs);
        handle = https.request({ agent: false, ca: data.tlsCertificatePem, checkServerIdentity(host, certificate) {
          const normal = checkServerIdentity(host, certificate);
          if (normal !== undefined || !Buffer.isBuffer(certificate?.raw)) return new Error("Pinned TLS identity verification failed.");
          const actual = createHash("sha256").update(certificate.raw).digest();
          return actual.length === expected.length && timingSafeEqual(actual, expected) ? undefined : new Error("Pinned TLS identity verification failed.");
        }, headers, hostname: endpoint.hostname, method: request.method, path: request.path, port: Number(endpoint.port), rejectUnauthorized: true }, (incoming) => {
          response = incoming;
          clearTimeout(headerTimer);
          const contentLengths = rawHeaderValues(incoming.rawHeaders, "content-length");
          const contentTypes = rawHeaderValues(incoming.rawHeaders, "content-type");
          const artifact = request.method === "GET" && /^\/v1\/artifacts\//.test(request.path);
          const sessionView = request.method === "GET" && /^\/v1\/sessions\/[0-9a-f-]{36}\/view$/.test(request.path);
          const expectedType = artifact ? "application/octet-stream" : "application/json";
          if (incoming.statusCode === 404 && sessionView) return fail(new OperatorRelayClientError("COORDINATION_SESSION_NOT_FOUND"));
          if (incoming.statusCode !== 200 || contentLengths.length !== 1 || contentTypes.length !== 1 || contentTypes[0] !== expectedType || !DECIMAL_PATTERN.test(contentLengths[0]) || Number(contentLengths[0]) > OPERATOR_CLIENT_MAX_RESPONSE_BYTES || ["content-encoding", "location", "transfer-encoding", "upgrade"].some((name) => rawHeaderValues(incoming.rawHeaders, name).length !== 0)) return fail(new OperatorRelayClientError());
          const chunks = []; let length = 0;
          bodyTimer = setTimeout(() => fail(new OperatorRelayClientError("COORDINATION_TRANSPORT_AMBIGUOUS")), timing.bodyMs);
          incoming.on("data", (chunk) => { clearTimeout(bodyTimer); bodyTimer = setTimeout(() => fail(new OperatorRelayClientError("COORDINATION_TRANSPORT_AMBIGUOUS")), timing.bodyMs); length += chunk.length; if (length > Number(contentLengths[0]) || length > OPERATOR_CLIENT_MAX_RESPONSE_BYTES) fail(new OperatorRelayClientError()); else chunks.push(Buffer.from(chunk)); });
          incoming.once("aborted", () => fail(new OperatorRelayClientError("COORDINATION_TRANSPORT_AMBIGUOUS")));
          incoming.once("error", () => fail(new OperatorRelayClientError("COORDINATION_TRANSPORT_AMBIGUOUS")));
          incoming.once("end", () => { const body = Buffer.concat(chunks); if (body.length !== Number(contentLengths[0]) || incoming.complete !== true) return fail(new OperatorRelayClientError("COORDINATION_TRANSPORT_AMBIGUOUS")); try { if (expectedType === "application/json") canonicalJson(body); } catch (error) { return fail(error); } finish(Object.freeze({ body, contentType: expectedType, statusCode: 200 })); });
        });
        handle.once("socket", (socket) => socket.once("secureConnect", () => { secure = true; clearTimeout(connectTimer); headerTimer = setTimeout(() => fail(new OperatorRelayClientError("COORDINATION_TRANSPORT_AMBIGUOUS")), timing.headerMs); }));
        handle.once("error", () => fail(new OperatorRelayClientError(secure ? "COORDINATION_TRANSPORT_AMBIGUOUS" : "COORDINATION_OPERATOR_CLIENT_INVALID")));
        request.signal?.addEventListener("abort", () => fail(new OperatorRelayClientError("COORDINATION_CLIENT_ABORTED")), { once: true });
        handle.end(request.body ?? undefined);
      });
    },
  });
}

export function createPinnedOperatorHttpsTransport(input) {
  return createPinnedOperatorHttpsTransportInternal(input, Object.freeze({
    bodyMs: OPERATOR_CLIENT_BODY_TIMEOUT_MS,
    connectMs: OPERATOR_CLIENT_CONNECT_TIMEOUT_MS,
    headerMs: OPERATOR_CLIENT_HEADER_TIMEOUT_MS,
    totalMs: OPERATOR_CLIENT_TOTAL_TIMEOUT_MS,
  }));
}

export function createPinnedOperatorHttpsTransportForTesting(input) {
  const data = exact(input, ["expectedFingerprint", "relayUrl", "requestTiming", "tlsCertificatePem"]);
  return createPinnedOperatorHttpsTransportInternal({ expectedFingerprint: data.expectedFingerprint, relayUrl: data.relayUrl, tlsCertificatePem: data.tlsCertificatePem }, assertRequestTiming(data.requestTiming));
}

export function createOperatorRelayClient(input) {
  const data = exact(input, ["operatorIdentity", "releaseId", "repositorySha", "sessionId", "transport"]);
  const context = assertContext({ releaseId: data.releaseId, repositorySha: data.repositorySha, sessionId: data.sessionId });
  const identity = assertIdentity(data.operatorIdentity);
  const transport = exact(data.transport, ["request"]);
  if (typeof transport.request !== "function") invalid();
  let appendQueue = Promise.resolve();
  const request = async (value, contentType) => {
    const canonical = assertOperatorRoute(value);
    let response;
    try { response = await transport.request(canonical); } catch (error) { if (error instanceof CoordinationClientError) throw error; invalid(); }
    return exactResponse(response, contentType);
  };
  const readEvents = async (value) => {
    const inputValue = exact(value, ["after", "waitMs"]);
    if (inputValue.after !== null || !Number.isSafeInteger(inputValue.waitMs) || inputValue.waitMs < 0 || inputValue.waitMs > 30_000) invalid();
    const enrollmentBytes = await request({ body: null, method: "GET", path: `/v1/sessions/${context.sessionId}/enrollments` }, "application/json");
    const roleKeys = validateEnrollmentBytes(enrollmentBytes, context);
    const parsed = canonicalJson(await request({ body: null, method: "GET", path: `/v1/sessions/${context.sessionId}/events?waitMs=${inputValue.waitMs}` }, "application/json"));
    if (!Array.isArray(parsed) || parsed.length > 4096 || Reflect.ownKeys(parsed).length !== parsed.length + 1) invalid();
    const events = parsed.map((event) => validateEvent(event, context, identity, roleKeys));
    validateSenderChains(events);
    return Object.freeze(events);
  };
  const createEvent = async (value) => {
    const prepared = exact(value, ["artifactDigest", "kind", "subjectRun"]);
    if ((prepared.artifactDigest !== null && (typeof prepared.artifactDigest !== "string" || !SHA256_PATTERN.test(prepared.artifactDigest))) || !EVENT_KINDS.has(prepared.kind) || !["release", "rehearsal", "stakeholder"].includes(prepared.subjectRun)) invalid();
    const state = operatorSenderState(await readEvents({ after: null, waitMs: 0 }));
    return createCoordinationEnvelope({ artifactDigest: prepared.artifactDigest, kind: prepared.kind, paymentMoved: false, previousEventDigest: state.previousEventDigest, privateKeyPem: identity.privateKeyPem, publicKey: identity.publicKey, publicKeyId: identity.keyId, releaseId: context.releaseId, repositorySha: context.repositorySha, role: "operator", schema: COORDINATION_ENVELOPE_SCHEMA, sequence: state.sequence, sessionId: context.sessionId, subjectRun: prepared.subjectRun });
  };
  const append = (value) => {
    const run = async () => {
      const event = await createEvent(value);
      const bytes = canonicalBytes(event);
      const echoed = canonicalJson(await request({ body: bytes, method: "POST", path: "/v1/events" }, "application/json"));
      const accepted = validateEvent(echoed, context, identity, Object.create(null));
      if (!canonicalBytes(accepted).equals(bytes)) invalid();
      return accepted;
    };
    const result = appendQueue.then(run, run); appendQueue = result.catch(() => {}); return result;
  };
  return Object.freeze({
    appendOperatorEvent: append,
    createVerifiedEvent: async (value) => {
      const prepared = exact(value, ["artifactDigest", "releaseId", "repositorySha", "sessionId", "subjectRun"]);
      if (prepared.releaseId !== context.releaseId || prepared.repositorySha !== context.repositorySha || prepared.sessionId !== context.sessionId) invalid();
      return createEvent({ artifactDigest: prepared.artifactDigest, kind: "VERIFICATION_PASSED", subjectRun: prepared.subjectRun });
    },
    appendVerifiedEvent(value) {
      const run = async () => {
      const dataValue = exact(value, ["event", "publication"]);
      const event = validateEvent(dataValue.event, context, identity, Object.create(null));
      const publication = validatePublication(dataValue.publication, context, event.subjectRun);
      if (event.kind !== "VERIFICATION_PASSED" || event.role !== "operator" || event.artifactDigest !== publication.publicationDigest) invalid();
      const expected = await createEvent({ artifactDigest: event.artifactDigest, kind: "VERIFICATION_PASSED", subjectRun: event.subjectRun });
      if (!canonicalBytes(expected).equals(canonicalBytes(event))) invalid();
      const body = canonicalBytes({ event, paymentMoved: false, publication, schema: VERIFIED_EVENT_SCHEMA });
      const echoed = validateEvent(canonicalJson(await request({ body, method: "POST", path: "/v1/verified-events" }, "application/json")), context, identity, Object.create(null));
      if (!canonicalBytes(echoed).equals(canonicalBytes(event))) invalid();
      return echoed;
      };
      const result = appendQueue.then(run, run); appendQueue = result.catch(() => {}); return result;
    },
    async getArtifact(value) {
      const inputValue = exact(value, ["artifactType", "digest"]);
      if (!ARTIFACT_TYPES.has(inputValue.artifactType) || typeof inputValue.digest !== "string" || !SHA256_PATTERN.test(inputValue.digest)) invalid();
      const bytes = await request({ artifactType: inputValue.artifactType, body: null, method: "GET", path: `/v1/artifacts/${inputValue.digest}` }, "application/octet-stream");
      try { await validateRelayArtifact({ artifactType: inputValue.artifactType, bytes, expectedDigest: inputValue.digest, secretCanaries: [] }); } catch { invalid(); }
      return Buffer.from(bytes);
    },
    async putArtifact(value) {
      const inputValue = exact(value, ["artifactType", "bytes", "expectedDigest"]);
      if (!ARTIFACT_TYPES.has(inputValue.artifactType) || !Buffer.isBuffer(inputValue.bytes) || typeof inputValue.expectedDigest !== "string" || !SHA256_PATTERN.test(inputValue.expectedDigest)) invalid();
      let metadata;
      try { metadata = await validateRelayArtifact({ artifactType: inputValue.artifactType, bytes: inputValue.bytes, expectedDigest: inputValue.expectedDigest, secretCanaries: [] }); } catch { invalid(); }
      const ack = exact(canonicalJson(await request({ artifactType: inputValue.artifactType, body: Buffer.from(inputValue.bytes), method: "PUT", path: `/v1/artifacts/${metadata.digest}` }, "application/json")), ["artifactType", "byteLength", "digest"]);
      if (ack.artifactType !== metadata.artifactType || ack.byteLength !== metadata.byteLength || ack.digest !== metadata.digest) invalid();
      return frozen({ ...ack });
    },
    async readEnrollmentSet(value) {
      if (value !== undefined) invalid();
      const bytes = await request({ body: null, method: "GET", path: `/v1/sessions/${context.sessionId}/enrollments` }, "application/json");
      validateEnrollmentBytes(bytes, context);
      return Buffer.from(bytes);
    },
    readEvents,
    async readSessionView(value) {
      if (value !== undefined) invalid();
      const view = exact(canonicalJson(await request({ body: null, method: "GET", path: `/v1/sessions/${context.sessionId}/view` }, "application/json")), VIEW_KEYS);
      if (view.paymentMoved !== false || view.releaseId !== context.releaseId || view.repositorySha !== context.repositorySha || view.sessionId !== context.sessionId || !RELEASE_STATES.includes(view.state)) invalid();
      const template = initialReleaseView(context);
      // The view is advisory, but still must be a closed, non-secret shape.
      return frozen({ ...view, facts: validateFacts(view.facts, template.facts) });
    },
    async readVerifierPublication(value) {
      const inputValue = exact(value, ["subjectRun"]);
      if (!["rehearsal", "stakeholder"].includes(inputValue.subjectRun)) invalid();
      const parsed = canonicalJson(await request({ body: null, method: "GET", path: `/v1/sessions/${context.sessionId}/verifier-publications/${inputValue.subjectRun}` }, "application/json"));
      return parsed === null ? null : validatePublication(parsed, context, inputValue.subjectRun);
    },
    prepareCapabilityRegistration(value) {
      const inputValue = exact(value, ["capabilities"]);
      const capabilities = capabilityInput(inputValue.capabilities);
      return frozen(createCapabilityRegistration({ capabilities, operatorKeyId: identity.keyId, paymentMoved: false, privateKeyPem: identity.privateKeyPem, releaseId: context.releaseId, repositorySha: context.repositorySha, sessionId: context.sessionId }));
    },
    async registerCapabilitySet(value) {
      const inputValue = exact(value, ["registration"]);
      let registration;
      try {
        registration = verifyCapabilityRegistration(inputValue.registration, {
          expectedOperatorKeyId: identity.keyId,
          expectedOperatorPublicKey: identity.publicKey,
          expectedRepositorySha: context.repositorySha,
        });
      } catch { invalid(); }
      if (registration.releaseId !== context.releaseId || registration.sessionId !== context.sessionId || registration.paymentMoved !== false) invalid();
      const capabilities = registration.capabilities;
      const body = canonicalBytes(registration);
      const receipt = exact(canonicalJson(await request({ body, method: "POST", path: "/v1/capabilities" }, "application/json")), CAPABILITY_RECEIPT_KEYS);
      if (receipt.schema !== CAPABILITY_REGISTRATION_RECEIPT_SCHEMA || receipt.paymentMoved !== false || receipt.releaseId !== context.releaseId || receipt.repositorySha !== context.repositorySha || receipt.sessionId !== context.sessionId || !SHA256_PATTERN.test(receipt.registrationDigest) || receipt.requestDigest !== sha256(body) || !canonicalBytes(receipt.capabilities).equals(canonicalBytes(capabilities))) invalid();
      return frozen({ ...receipt });
    },
  });
}
