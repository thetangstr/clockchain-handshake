const HEALTH = new Set(["READY", "WAITING", "FAILED", "UNAVAILABLE"]);
const ANCHORS = Object.freeze([
  Object.freeze({ actor: "Payer", state: "PROPOSED" }),
  Object.freeze({ actor: "Requestor", state: "ACCEPTED" }),
  Object.freeze({ actor: "Payer", state: "ACKNOWLEDGED" }),
]);
const VERIFIER = new Set(["PENDING", "VERIFICATION_PASSED"]);

function fail() {
  throw new Error("Public monitor projection failed safely.");
}

function object(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value
    : fail();
}

function health(value) {
  return typeof value === "string" && HEALTH.has(value) ? value : fail();
}

function boolean(value) {
  return typeof value === "boolean" ? value : fail();
}

function block(value) {
  if (value === null) return null;
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]*)$/.test(value)) fail();
  return value;
}

function timestamp(value) {
  if (
    typeof value !== "string" ||
    value.length > 32 ||
    !Number.isFinite(Date.parse(value))
  ) fail();
  return value;
}

function status({ anchors, markers, verifier }) {
  if (verifier === "VERIFICATION_PASSED") return "VERIFIED";
  if (anchors.every((item) => item.verified)) return "ANCHORED";
  if (markers.paymentRequestMatched) return "HANDSHAKE_RUNNING";
  if (markers.paymentRequestReady) return "REQUEST_RECEIVED";
  if (markers.payerMandateReady) return "MANDATE_READY";
  return "WAITING_FOR_PARTICIPANTS";
}

export function buildUnavailablePublicMonitorSnapshot({
  observedAt,
  payerMcpReady,
}) {
  if (typeof payerMcpReady !== "boolean") fail();
  return Object.freeze({
    schema: "clockchain.public-handshake-monitor/v1",
    observedAt: timestamp(observedAt),
    staleAfterMs: 10_000,
    status: "WAITING_FOR_PARTICIPANTS",
    paymentMoved: false,
    actors: Object.freeze({
      operator: "UNAVAILABLE",
      payer: "UNAVAILABLE",
      requestor: "UNAVAILABLE",
    }),
    services: Object.freeze({
      payerMcp: payerMcpReady ? "READY" : "UNAVAILABLE",
      watcher: "UNAVAILABLE",
    }),
    markers: Object.freeze({
      payerMandateReady: false,
      paymentRequestReady: false,
      paymentRequestMatched: false,
    }),
    anchors: Object.freeze(ANCHORS.map((anchor) => Object.freeze({
      actor: anchor.actor,
      state: anchor.state,
      verified: false,
      block: null,
    }))),
    verifier: Object.freeze({ status: "PENDING" }),
  });
}

export function buildPublicMonitorSnapshot(
  projection,
  { observedAt, payerMcpReady },
) {
  const value = object(projection);
  if (
    value.schema !== "clockchain.bilateral-console-projection/v1" ||
    value.paymentMoved !== false ||
    typeof payerMcpReady !== "boolean"
  ) fail();

  const actorsValue = object(value.actors);
  const session = object(value.session);
  const observations = object(session.observations);
  const mandate = object(value.mandate);
  const request = object(value.request);
  const verifierValue = object(value.verifier);
  if (!Array.isArray(value.anchors) || value.anchors.length !== ANCHORS.length) fail();

  const markers = Object.freeze({
    payerMandateReady: boolean(mandate.received),
    paymentRequestReady: boolean(request.received),
    paymentRequestMatched: boolean(mandate.matched),
  });
  const anchors = Object.freeze(value.anchors.map((raw, index) => {
    const item = object(raw);
    const expected = ANCHORS[index];
    if (
      item.actor !== expected.actor ||
      item.kind !== expected.state ||
      typeof item.verified !== "boolean"
    ) fail();
    const height = block(item.block);
    if (item.verified && height === null) fail();
    return Object.freeze({
      actor: expected.actor,
      state: expected.state,
      verified: item.verified,
      block: height,
    });
  }));
  const verifierStatus = verifierValue.status;
  if (typeof verifierStatus !== "string" || !VERIFIER.has(verifierStatus)) fail();

  return Object.freeze({
    schema: "clockchain.public-handshake-monitor/v1",
    observedAt: timestamp(observedAt),
    staleAfterMs: 10_000,
    status: status({ anchors, markers, verifier: verifierStatus }),
    paymentMoved: false,
    actors: Object.freeze({
      operator: health(object(actorsValue.operator).health),
      payer: health(object(actorsValue.payer).health),
      requestor: health(object(actorsValue.payee).health),
    }),
    services: Object.freeze({
      payerMcp: payerMcpReady ? "READY" : "UNAVAILABLE",
      watcher: health(object(observations.watcher).health),
    }),
    markers,
    anchors,
    verifier: Object.freeze({ status: verifierStatus }),
  });
}
