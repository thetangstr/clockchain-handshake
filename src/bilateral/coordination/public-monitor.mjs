const HEALTH = new Set(["READY", "WAITING", "FAILED", "UNAVAILABLE"]);
const SHA64 = /^[0-9a-f]{64}$/;
const ANCHORS = Object.freeze([
  Object.freeze({ actor: "Payer", sequence: 1, stage: "proposal", state: "PROPOSED" }),
  Object.freeze({ actor: "Requestor", sequence: 2, stage: "acceptance", state: "ACCEPTED" }),
  Object.freeze({ actor: "Payer", sequence: 3, stage: "acknowledgment", state: "ACKNOWLEDGED" }),
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

function closed(value, keys) {
  const result = object(value);
  const names = Object.keys(result);
  if (
    names.length !== keys.length ||
    !keys.every((key) => Object.hasOwn(result, key))
  ) fail();
  return result;
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
  const value = closed(projection, [
    "actors",
    "anchors",
    "deadline",
    "failure",
    "mandate",
    "paymentMoved",
    "phase",
    "request",
    "schema",
    "session",
    "verifier",
  ]);
  if (
    value.schema !== "clockchain.bilateral-console-projection/v1" ||
    value.paymentMoved !== false ||
    typeof payerMcpReady !== "boolean"
  ) fail();

  const actorsValue = closed(value.actors, ["operator", "payer", "payee"]);
  const operator = closed(actorsValue.operator, ["health", "label", "role"]);
  const payer = closed(actorsValue.payer, ["health", "label", "role"]);
  const payee = closed(actorsValue.payee, ["health", "label", "role"]);
  if (
    operator.label !== "Operator" ||
    operator.role !== "operator" ||
    payer.label !== "Payer" ||
    payer.role !== "payer" ||
    payee.label !== "Requestor" ||
    payee.role !== "payee"
  ) fail();
  const session = closed(value.session, [
    "advisory",
    "observations",
    "releaseId",
    "repositorySha",
    "sessionId",
  ]);
  const observations = closed(session.observations, ["relay", "watcher"]);
  const relay = closed(observations.relay, ["advisory", "health", "label"]);
  const watcher = closed(observations.watcher, ["advisory", "health", "label"]);
  if (
    session.advisory !== true ||
    relay.advisory !== true ||
    relay.label !== "relay advisory" ||
    watcher.advisory !== true ||
    watcher.label !== "watcher advisory"
  ) fail();
  closed(value.deadline, ["expiresAtMs", "freshness", "nowMs"]);
  if (value.failure !== null) {
    const failure = closed(value.failure, ["active", "code", "recovery", "run"]);
    closed(failure.recovery, ["label", "visible"]);
  }
  const phase = closed(value.phase, ["advisory", "value"]);
  if (phase.advisory !== true) fail();
  const mandate = closed(value.mandate, [
    "amount",
    "digest",
    "kind",
    "matched",
    "purpose",
    "received",
  ]);
  const request = closed(value.request, [
    "amount",
    "digest",
    "invoiceReference",
    "kind",
    "received",
  ]);
  if (mandate.amount !== null) closed(mandate.amount, ["currency", "value"]);
  if (request.amount !== null) closed(request.amount, ["currency", "value"]);
  if (mandate.kind !== "pre-protocol" || request.kind !== "pre-protocol") fail();
  const verifierValue = closed(value.verifier, [
    "advisory",
    "publicationDigest",
    "status",
  ]);
  if (!Array.isArray(value.anchors) || value.anchors.length !== ANCHORS.length) fail();

  const markers = Object.freeze({
    payerMandateReady: boolean(mandate.received),
    paymentRequestReady: boolean(request.received),
    paymentRequestMatched: boolean(mandate.matched),
  });
  const anchors = Object.freeze(value.anchors.map((raw, index) => {
    const item = closed(raw, [
      "actor",
      "block",
      "digest",
      "kind",
      "sequence",
      "stage",
      "verified",
    ]);
    const expected = ANCHORS[index];
    if (
      item.actor !== expected.actor ||
      item.kind !== expected.state ||
      item.sequence !== expected.sequence ||
      item.stage !== expected.stage ||
      typeof item.digest !== "string" ||
      !SHA64.test(item.digest) ||
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
      operator: health(operator.health),
      payer: health(payer.health),
      requestor: health(payee.health),
    }),
    services: Object.freeze({
      payerMcp: payerMcpReady ? "READY" : "UNAVAILABLE",
      watcher: health(watcher.health),
    }),
    markers,
    anchors,
    verifier: Object.freeze({ status: verifierStatus }),
  });
}
