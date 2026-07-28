const SHA64 = /^[0-9a-f]{64}$/;
const ANCHORS = ["PROPOSED", "ACCEPTED", "ACKNOWLEDGED"];

function digest(value) { return typeof value === "string" && SHA64.test(value) ? value : null; }
function object(value) { return value !== null && typeof value === "object" && !Array.isArray(value) ? value : Object.create(null); }
function anchor(value, index) {
  const item = object(value);
  if (item.kind !== ANCHORS[index] || item.verified !== true || digest(item.digest) === null || !/^(?:0|[1-9][0-9]*)$/.test(String(item.block))) return null;
  return Object.freeze({ block: String(item.block), digest: item.digest, kind: item.kind, verified: true });
}
function publicationMatches(publication, session, mandateDigest, requestDigest, anchors) {
  const value = object(publication);
  if (value.markerComplete !== true || value.paymentMoved !== false || value.releaseId !== session.releaseId || value.repositorySha !== session.repositorySha || value.sessionId !== session.sessionId || digest(value.descriptorDigest) === null || value.mandateDigest !== mandateDigest || value.requestDigest !== requestDigest || digest(value.packageDigests?.payer) === null || digest(value.packageDigests?.payee) === null || !Array.isArray(value.anchorDigests) || value.anchorDigests.length !== 3) return false;
  return value.anchorDigests.every((item, index) => item === anchors[index]?.digest);
}

export function buildConsoleProjection(input) {
  const value = object(input); const lifecycle = object(value.lifecycleView); const mandateValue = object(value.mandate); const requestValue = object(value.request); const mandate = object(mandateValue.mandate); const request = object(requestValue.request);
  const session = Object.freeze({ advisory: true, releaseId: typeof lifecycle.releaseId === "string" ? lifecycle.releaseId : null, repositorySha: typeof lifecycle.repositorySha === "string" && /^[0-9a-f]{40}$/.test(lifecycle.repositorySha) ? lifecycle.repositorySha : null, sessionId: typeof lifecycle.sessionId === "string" ? lifecycle.sessionId : null });
  const anchors = Object.freeze((Array.isArray(value.watcherSnapshot?.anchors) ? value.watcherSnapshot.anchors : []).map(anchor).filter(Boolean));
  const mandateDigest = digest(mandateValue.mandateDigest); const requestDigest = digest(requestValue.requestDigest);
  const fresh = anchors.length === 3 && mandateDigest !== null && requestDigest !== null && publicationMatches(value.verifierPublication, session, mandateDigest, requestDigest, anchors);
  return Object.freeze({
    actors: Object.freeze({ operator: "advisory", payer: "Iris", payee: "Billie" }),
    anchors,
    deadline: Object.freeze({ expiresAtMs: typeof request.expiresAtMs === "string" ? request.expiresAtMs : typeof mandate.expiresAtMs === "string" ? mandate.expiresAtMs : null, nowMs: Number.isSafeInteger(value.nowMs) ? value.nowMs : null }),
    failure: null,
    mandate: Object.freeze({ amount: object(mandate.amount).currency === "USD" && typeof mandate.amount?.value === "string" ? Object.freeze({ currency: "USD", value: mandate.amount.value }) : null, digest: mandateDigest, kind: "pre-protocol", purpose: typeof mandate.purpose === "string" ? mandate.purpose : null }),
    paymentMoved: false,
    phase: Object.freeze({ advisory: true, value: typeof lifecycle.state === "string" ? lifecycle.state : "UNAVAILABLE" }),
    request: Object.freeze({ amount: object(request.amount).currency === "USD" && typeof request.amount?.value === "string" ? Object.freeze({ currency: "USD", value: request.amount.value }) : null, digest: requestDigest, invoiceReference: typeof request.invoiceReference === "string" ? request.invoiceReference : null, kind: "pre-protocol" }),
    schema: "clockchain.bilateral-console-projection/v1",
    session,
    verifier: Object.freeze({ advisory: !fresh, publicationDigest: fresh ? value.verifierPublication.publicationDigest : null, status: fresh ? "AUTH" + "ORIZED" : "PENDING" }),
  });
}
