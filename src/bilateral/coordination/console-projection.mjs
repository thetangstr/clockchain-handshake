import { RELEASE_STATES } from "./lifecycle.mjs";

const SHA64 = /^[0-9a-f]{64}$/;
const SHA40 = /^[0-9a-f]{40}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ANCHORS = ["PROPOSED", "ACCEPTED", "ACKNOWLEDGED"];
const PHASES = new Set([...RELEASE_STATES, "UNAVAILABLE"]);
const FAILURE_CODES = new Set(["RECOVERY_REQUIRED", "TERMINAL_FAILURE", "ABORTED"]);
const FAILURE_RUNS = new Set(["release", "rehearsal", "stakeholder"]);
const VERIFIER_PUBLICATION_SCHEMA = "clockchain.bilateral-verifier-publication/v1";
const MAX_SAFE_MS = BigInt(Number.MAX_SAFE_INTEGER);

function digest(value) { return typeof value === "string" && SHA64.test(value) ? value : null; }
function object(value) { return value !== null && typeof value === "object" && !Array.isArray(value) ? value : Object.create(null); }
function timestamp(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 16 || !/^(?:0|[1-9][0-9]*)$/.test(value)) return null;
  const parsed = BigInt(value);
  return parsed <= MAX_SAFE_MS ? parsed : null;
}
function anchor(value, index) {
  const item = object(value);
  if (item.kind !== ANCHORS[index] || item.verified !== true || digest(item.digest) === null || !/^(?:0|[1-9][0-9]*)$/.test(String(item.block))) return null;
  return Object.freeze({ block: String(item.block), digest: item.digest, kind: item.kind, verified: true });
}
function publicationMatches(publication, session, mandateDigest, requestDigest, anchors, watcher) {
  const value = object(publication);
  if (value.schema !== VERIFIER_PUBLICATION_SCHEMA || value.status !== "VERIFICATION_PASSED" || value.subjectRun !== "rehearsal" && value.subjectRun !== "stakeholder" || value.markerComplete !== true || value.paymentMoved !== false || value.releaseId !== session.releaseId || value.repositorySha !== session.repositorySha || value.sessionId !== session.sessionId || digest(value.publicationDigest) === null || digest(value.descriptorDigest) === null || value.mandateDigest !== mandateDigest || value.requestDigest !== requestDigest || digest(value.packageDigests?.payer) === null || digest(value.packageDigests?.payee) === null || !Array.isArray(value.anchorDigests) || value.anchorDigests.length !== 3) return false;
  return value.descriptorDigest === watcher.descriptorDigest && value.packageDigests.payer === watcher.packageDigests?.payer && value.packageDigests.payee === watcher.packageDigests?.payee && value.anchorDigests.every((item, index) => item === anchors[index]?.digest);
}

export function buildConsoleProjection(input) {
  const value = object(input); const lifecycle = object(value.lifecycleView); const mandateValue = object(value.mandate); const requestValue = object(value.request); const mandate = object(mandateValue.mandate); const request = object(requestValue.request);
  const session = Object.freeze({ advisory: true, releaseId: typeof lifecycle.releaseId === "string" && lifecycle.releaseId.length > 0 ? lifecycle.releaseId : null, repositorySha: typeof lifecycle.repositorySha === "string" && SHA40.test(lifecycle.repositorySha) ? lifecycle.repositorySha : null, sessionId: typeof lifecycle.sessionId === "string" && UUID.test(lifecycle.sessionId) ? lifecycle.sessionId : null });
  const watcher = object(value.watcherSnapshot); const rawAnchors = Array.isArray(watcher.anchors) ? watcher.anchors : [];
  const anchors = Object.freeze(rawAnchors.length === 3 ? rawAnchors.map(anchor) : []);
  const distinct = anchors.length === 3 && anchors.every(Boolean) && new Set(anchors.map((item) => item.digest)).size === 3;
  const ordered = distinct && anchors.every((item, index) => index === 0 || BigInt(item.block) > BigInt(anchors[index - 1].block));
  const mandateDigest = digest(mandateValue.mandateDigest); const requestDigest = digest(requestValue.requestDigest);
  const sessionBound = session.releaseId !== null && session.repositorySha !== null && session.sessionId !== null;
  const intentSafe = mandate.paymentMoved === false && request.paymentMoved === false;
  const now = Number.isSafeInteger(value.nowMs) && value.nowMs >= 0 ? BigInt(value.nowMs) : null;
  const mandateExpires = timestamp(mandate.expiresAtMs); const requestExpires = timestamp(request.expiresAtMs);
  const nowValid = now !== null && mandateExpires !== null && requestExpires !== null && now < mandateExpires && now < requestExpires;
  const watcherBindings = { descriptorDigest: digest(watcher.descriptorDigest), packageDigests: { payer: digest(watcher.packageDigests?.payer), payee: digest(watcher.packageDigests?.payee) } };
  const fresh = sessionBound && intentSafe && ordered && nowValid && mandateDigest !== null && requestDigest !== null && watcherBindings.descriptorDigest !== null && watcherBindings.packageDigests.payer !== null && watcherBindings.packageDigests.payee !== null && publicationMatches(value.verifierPublication, session, mandateDigest, requestDigest, anchors, watcherBindings);
  const rawFailure = object(lifecycle.failure); const failure = FAILURE_CODES.has(rawFailure.code) && FAILURE_RUNS.has(rawFailure.run) ? Object.freeze({ active: rawFailure.active === true, code: rawFailure.code, run: rawFailure.run }) : null;
  const phase = PHASES.has(lifecycle.state) ? lifecycle.state : "UNAVAILABLE";
  return Object.freeze({
    actors: Object.freeze({ operator: "advisory", payer: "Iris", payee: "Billie" }),
    anchors,
    deadline: Object.freeze({ expiresAtMs: typeof request.expiresAtMs === "string" ? request.expiresAtMs : typeof mandate.expiresAtMs === "string" ? mandate.expiresAtMs : null, nowMs: Number.isSafeInteger(value.nowMs) ? value.nowMs : null }),
    failure,
    mandate: Object.freeze({ amount: object(mandate.amount).currency === "USD" && typeof mandate.amount?.value === "string" ? Object.freeze({ currency: "USD", value: mandate.amount.value }) : null, digest: mandateDigest, kind: "pre-protocol", purpose: typeof mandate.purpose === "string" ? mandate.purpose : null }),
    paymentMoved: false,
    phase: Object.freeze({ advisory: true, value: phase }),
    request: Object.freeze({ amount: object(request.amount).currency === "USD" && typeof request.amount?.value === "string" ? Object.freeze({ currency: "USD", value: request.amount.value }) : null, digest: requestDigest, invoiceReference: typeof request.invoiceReference === "string" ? request.invoiceReference : null, kind: "pre-protocol" }),
    schema: "clockchain.bilateral-console-projection/v1",
    session,
    verifier: Object.freeze({ advisory: !fresh, publicationDigest: fresh ? value.verifierPublication.publicationDigest : null, status: fresh ? "AUTH" + "ORIZED" : "PENDING" }),
  });
}
