import { isIP } from "node:net";
import { types } from "node:util";

export const PUBLIC_MONITOR_SCHEMA =
  "clockchain.bilateral-public-monitor/v2";

const SOURCE_HEALTH = new Set([
  "READY",
  "WAITING",
  "FAILED",
  "UNAVAILABLE",
]);
const SERVICE_STATUS = new Set([
  "READY",
  "WAITING",
  "FAILED",
  "UNAVAILABLE",
]);
const FUNDING_STATUS = new Set([
  "NOT_STARTED",
  "WAITING",
  "READY",
  "FAILED",
]);
const VERIFIER_STATUS = new Set([
  "NOT_STARTED",
  "RUNNING",
  "VERIFIED",
  "FAILED",
  "EXPIRED",
]);
const RUN_STATUS = new Set([
  "WAITING",
  "RUNNING",
  "VERIFIED",
  "FAILED",
  "EXPIRED",
]);
const SOURCE_ANCHORS = Object.freeze([
  Object.freeze({
    actor: "Payer",
    kind: "PROPOSED",
    sequence: 1,
    signerRole: "Payer",
    stage: "proposal",
  }),
  Object.freeze({
    actor: "Requestor",
    kind: "ACCEPTED",
    sequence: 2,
    signerRole: "Requestor",
    stage: "acceptance",
  }),
  Object.freeze({
    actor: "Payer",
    kind: "ACKNOWLEDGED",
    sequence: 3,
    signerRole: "Payer",
    stage: "acknowledgment",
  }),
]);
const PUBLIC_KEYS = Object.freeze([
  "anchors",
  "currentStep",
  "funding",
  "mcp",
  "paymentMoved",
  "payer",
  "publishedAtMs",
  "relay",
  "requestor",
  "runId",
  "runStatus",
  "schema",
  "staleAfterMs",
  "verifier",
]);
const PUBLIC_ANCHOR_KEYS = Object.freeze([
  "block",
  "explorerUrl",
  "kind",
  "signerRole",
]);
const SOURCE_KEYS = Object.freeze([
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
const AWS_WATCHER_KEYS = Object.freeze([
  "observedAtMs",
  "paymentMoved",
  "releaseId",
  "repositorySha",
  "schema",
  "sessionId",
  "state",
  "subjectRun",
  "terminal",
  "transitions",
]);
const AWS_WATCHER_TRANSITION_KEYS = Object.freeze([
  "blockHeight",
  "cardinality",
  "ledgerId",
  "slot",
  "verified",
]);
const AWS_WATCHER_STATES = Object.freeze([
  "UNSTARTED",
  "PROPOSED",
  "ACCEPTED",
  "ACKNOWLEDGED",
]);
const AWS_WATCHER_SLOTS = Object.freeze([
  "proposal",
  "acceptance",
  "acknowledgment",
]);
const SHA64 = /^[0-9a-f]{64}$/;
const SHA40 = /^[0-9a-f]{40}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const RUN_ID = /^run-[0-9a-f]{16}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const LEDGER_ID = /^[A-Za-z0-9._:-]{1,128}$/;

function fail() {
  throw new Error(
    "Public monitor projection failed safely.",
  );
}

function plain(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    !types.isProxy(value) &&
    Object.getPrototypeOf(value) ===
      Object.prototype
  );
}

function exact(value, keys) {
  if (!plain(value)) fail();
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== keys.length ||
    keys.some((key) => !ownKeys.includes(key))
  ) {
    fail();
  }
  for (const key of keys) {
    const descriptor =
      Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor?.enumerable !== true ||
      !Object.hasOwn(descriptor, "value")
    ) {
      fail();
    }
  }
  return value;
}

function exactOrdered(value, keys) {
  const object = exact(value, keys);
  const ownKeys = Reflect.ownKeys(object);
  for (let index = 0; index < keys.length; index += 1) {
    if (ownKeys[index] !== keys[index]) fail();
  }
  return object;
}

function safeInteger(value) {
  if (
    !Number.isSafeInteger(value) ||
    value < 0 ||
    Object.is(value, -0)
  ) {
    fail();
  }
  return value;
}

function decimal(value) {
  if (
    typeof value !== "string" ||
    !DECIMAL.test(value) ||
    BigInt(value) >
      BigInt(Number.MAX_SAFE_INTEGER)
  ) {
    fail();
  }
  return Number(value);
}

function positiveDecimal(value) {
  const number = decimal(value);
  if (number <= 0) fail();
  return number;
}

function boundedText(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 180 ||
    value.trim() !== value ||
    /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(
      value,
    )
  ) {
    fail();
  }
  return value;
}

function statusObject(value, allowed) {
  const object = exact(value, ["status"]);
  if (
    typeof object.status !== "string" ||
    !allowed.has(object.status)
  ) {
    fail();
  }
  return Object.freeze({
    status: object.status,
  });
}

function publicUrl(value) {
  if (typeof value !== "string") fail();
  let url;
  try {
    url = new URL(value);
  } catch {
    fail();
  }
  const ipVersion = isIP(url.hostname);
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== "" ||
    url.hostname === "localhost" ||
    url.hostname.endsWith(".local") ||
    (
      ipVersion === 4 &&
      (
        url.hostname.startsWith("10.") ||
        url.hostname.startsWith("127.") ||
        url.hostname.startsWith("169.254.") ||
        url.hostname.startsWith("192.168.") ||
        /^172\.(?:1[6-9]|2[0-9]|3[01])\./.test(
          url.hostname,
        )
      )
    ) ||
    (
      ipVersion === 6 &&
      (
        url.hostname === "::1" ||
        url.hostname.startsWith("fc") ||
        url.hostname.startsWith("fd") ||
        url.hostname.startsWith("fe80")
      )
    )
  ) {
    fail();
  }
  return value;
}

function validateSourceActors(value) {
  const actors = exact(value, [
    "operator",
    "payer",
    "payee",
  ]);
  for (const [
    key,
    label,
    role,
  ] of [
    ["operator", "Operator", "operator"],
    ["payer", "Payer", "payer"],
    ["payee", "Requestor", "payee"],
  ]) {
    const actor = exact(actors[key], [
      "health",
      "label",
      "role",
    ]);
    if (
      actor.label !== label ||
      actor.role !== role ||
      !SOURCE_HEALTH.has(actor.health)
    ) {
      fail();
    }
  }
  return actors;
}

function validateSourceSession(value) {
  const session = exact(value, [
    "advisory",
    "observations",
    "releaseId",
    "repositorySha",
    "sessionId",
  ]);
  const observations = exact(
    session.observations,
    ["relay", "watcher"],
  );
  const relay = exact(observations.relay, [
    "advisory",
    "health",
    "label",
  ]);
  const watcher = exact(
    observations.watcher,
    ["advisory", "health", "label"],
  );
  if (
    session.advisory !== true ||
    relay.advisory !== true ||
    relay.label !== "relay advisory" ||
    watcher.advisory !== true ||
    watcher.label !== "watcher advisory" ||
    !SOURCE_HEALTH.has(relay.health) ||
    !SOURCE_HEALTH.has(watcher.health)
  ) {
    fail();
  }
  return { relay, watcher };
}

function validateSourceIntent(value) {
  const mandate = exact(value.mandate, [
    "amount",
    "digest",
    "kind",
    "matched",
    "purpose",
    "received",
  ]);
  const request = exact(value.request, [
    "amount",
    "digest",
    "invoiceReference",
    "kind",
    "received",
  ]);
  if (
    mandate.kind !== "pre-protocol" ||
    request.kind !== "pre-protocol" ||
    typeof mandate.received !== "boolean" ||
    typeof mandate.matched !== "boolean" ||
    typeof request.received !== "boolean"
  ) {
    fail();
  }
  if (mandate.amount !== null) {
    exact(mandate.amount, [
      "currency",
      "value",
    ]);
  }
  if (request.amount !== null) {
    exact(request.amount, [
      "currency",
      "value",
    ]);
  }
  return { mandate, request };
}

function validateSourceAnchors(
  value,
  explorerUrls,
) {
  if (
    !Array.isArray(value) ||
    value.length !== SOURCE_ANCHORS.length ||
    !Array.isArray(explorerUrls) ||
    explorerUrls.length !==
      SOURCE_ANCHORS.length
  ) {
    fail();
  }
  const anchors = [];
  let sawUnverified = false;
  for (
    let index = 0;
    index < SOURCE_ANCHORS.length;
    index += 1
  ) {
    const expected = SOURCE_ANCHORS[index];
    const source = exact(value[index], [
      "actor",
      "block",
      "digest",
      "kind",
      "sequence",
      "stage",
      "verified",
    ]);
    if (
      source.actor !== expected.actor ||
      source.kind !== expected.kind ||
      source.sequence !==
        expected.sequence ||
      source.stage !== expected.stage ||
      typeof source.verified !== "boolean" ||
      !SHA64.test(source.digest)
    ) {
      fail();
    }
    if (!source.verified) {
      sawUnverified = true;
      if (
        source.block !== null ||
        explorerUrls[index] !== null
      ) {
        fail();
      }
      continue;
    }
    if (
      sawUnverified ||
      typeof source.block !== "string" ||
      !DECIMAL.test(source.block) ||
      typeof explorerUrls[index] !==
        "string"
    ) {
      fail();
    }
    anchors.push(Object.freeze({
      block: source.block,
      explorerUrl:
        publicUrl(explorerUrls[index]),
      kind: expected.kind,
      signerRole: expected.signerRole,
    }));
  }
  return Object.freeze(anchors);
}

function runState({
  anchors,
  deadline,
  failure,
  intent,
  verifier,
  verifierPublicationValidated,
}) {
  const deadlineValue = exact(deadline, [
    "expiresAtMs",
    "freshness",
    "nowMs",
  ]);
  decimal(deadlineValue.expiresAtMs);
  safeInteger(deadlineValue.nowMs);
  const failed =
    failure !== null &&
    exact(failure, [
      "active",
      "code",
      "recovery",
      "run",
    ]).active === true;
  if (failure !== null) {
    exact(failure.recovery, [
      "label",
      "visible",
    ]);
  }
  const verifierValue = exact(verifier, [
    "advisory",
    "publicationDigest",
    "status",
  ]);
  if (
    !["PENDING", "VERIFICATION_PASSED"].includes(
      verifierValue.status,
    )
  ) {
    fail();
  }
  if (failed) {
    return {
      runStatus: "FAILED",
      verifierStatus: "FAILED",
    };
  }
  if (deadlineValue.freshness !== "FRESH") {
    return {
      runStatus: "EXPIRED",
      verifierStatus: "EXPIRED",
    };
  }
  if (
    verifierValue.status ===
      "VERIFICATION_PASSED"
  ) {
    if (
      verifierPublicationValidated !== true ||
      anchors.length !== 3 ||
      !SHA64.test(
        verifierValue.publicationDigest,
      )
    ) {
      fail();
    }
    return {
      runStatus: "VERIFIED",
      verifierStatus: "VERIFIED",
    };
  }
  if (verifierPublicationValidated !== false) {
    fail();
  }
  const progress =
    anchors.length > 0 ||
    intent.mandate.received ||
    intent.request.received;
  return {
    runStatus:
      progress ? "RUNNING" : "WAITING",
    verifierStatus:
      anchors.length === 3
        ? "RUNNING"
        : "NOT_STARTED",
  };
}

function stepFor(
  runStatus,
  anchors,
  intent,
) {
  if (runStatus === "VERIFIED") {
    return "Fresh independent verification confirmed all three Clockchain anchors.";
  }
  if (runStatus === "FAILED") {
    return "The run stopped safely because required evidence did not validate.";
  }
  if (runStatus === "EXPIRED") {
    return "The run expired before fresh independent verification completed.";
  }
  if (anchors.length === 3) {
    return "All three anchors are present; fresh independent verification is running.";
  }
  if (anchors.length === 2) {
    return "The Payer is reviewing the Requestor acceptance before acknowledgment.";
  }
  if (anchors.length === 1) {
    return "The Requestor is evaluating the Payer proposal under the signed mandate.";
  }
  if (intent.request.received) {
    return "The payment request is matched and the Clockchain handshake is starting.";
  }
  if (intent.mandate.received) {
    return "The Payer mandate is ready and the Requestor may submit a matching request.";
  }
  return "Waiting for the Payer and Requestor to join the run.";
}

function createSnapshot({
  anchors,
  currentStep,
  fundingStatus,
  mcpStatus,
  payerStatus,
  publishedAtMs,
  relayStatus,
  requestorStatus,
  runId,
  runStatus,
  staleAfterMs,
  verifierStatus,
}) {
  const freshnessWindow =
    safeInteger(staleAfterMs);
  if (
    freshnessWindow < 1_000 ||
    freshnessWindow > 60_000
  ) {
    fail();
  }
  return Object.freeze({
    anchors,
    currentStep:
      boundedText(currentStep),
    funding: Object.freeze({
      status: fundingStatus,
    }),
    mcp: Object.freeze({
      status: mcpStatus,
    }),
    paymentMoved: false,
    payer: Object.freeze({
      status: payerStatus,
    }),
    publishedAtMs: String(
      safeInteger(publishedAtMs),
    ),
    relay: Object.freeze({
      status: relayStatus,
    }),
    requestor: Object.freeze({
      status: requestorStatus,
    }),
    runId,
    runStatus,
    schema: PUBLIC_MONITOR_SCHEMA,
    staleAfterMs: freshnessWindow,
    verifier: Object.freeze({
      status: verifierStatus,
    }),
  });
}

export function buildPublicMonitorSnapshot(
  projection,
  options,
) {
  const value = exact(
    projection,
    SOURCE_KEYS,
  );
  const input = exactOrdered(options, [
    "anchorExplorerUrls",
    "nowMs",
    "payerMcpReady",
    "publishedAtMs",
    "runId",
    "sourceObservedAtMs",
    "staleAfterMs",
    "verifierPublicationValidated",
  ]);
  if (
    value.schema !==
      "clockchain.bilateral-console-projection/v1" ||
    value.paymentMoved !== false ||
    typeof input.payerMcpReady !== "boolean" ||
    !RUN_ID.test(input.runId)
  ) {
    fail();
  }
  const nowMs = safeInteger(input.nowMs);
  const sourceObservedAtMs = safeInteger(
    input.sourceObservedAtMs,
  );
  const publishedAtMs = safeInteger(
    input.publishedAtMs,
  );
  const staleAfterMs = safeInteger(
    input.staleAfterMs,
  );
  if (
    staleAfterMs < 1_000 ||
    staleAfterMs > 60_000 ||
    publishedAtMs > nowMs ||
    sourceObservedAtMs > nowMs ||
    nowMs - sourceObservedAtMs >
      staleAfterMs
  ) {
    fail();
  }
  const actors =
    validateSourceActors(value.actors);
  const observations =
    validateSourceSession(value.session);
  const intent = validateSourceIntent(value);
  const phase = exact(value.phase, [
    "advisory",
    "value",
  ]);
  if (
    phase.advisory !== true ||
    typeof phase.value !== "string"
  ) {
    fail();
  }
  const anchors = validateSourceAnchors(
    value.anchors,
    input.anchorExplorerUrls,
  );
  const state = runState({
    anchors,
    deadline: value.deadline,
    failure: value.failure,
    intent,
    verifier: value.verifier,
    verifierPublicationValidated:
      input.verifierPublicationValidated,
  });
  const fundingStatus =
    state.runStatus === "FAILED"
      ? "FAILED"
      : (
          intent.mandate.received ||
          anchors.length > 0
        )
        ? "READY"
        : "WAITING";
  return createSnapshot({
    anchors,
    currentStep: stepFor(
      state.runStatus,
      anchors,
      intent,
    ),
    fundingStatus,
    mcpStatus: input.payerMcpReady
      ? "READY"
      : "WAITING",
    payerStatus:
      actors.payer.health,
    publishedAtMs,
    relayStatus:
      observations.relay.health,
    requestorStatus:
      actors.payee.health,
    runId: input.runId,
    runStatus: state.runStatus,
    staleAfterMs,
    verifierStatus:
      state.verifierStatus,
  });
}

function validateAwsWatcherTransitions(value) {
  if (!Array.isArray(value) || value.length !== SOURCE_ANCHORS.length) {
    fail();
  }
  const anchors = [];
  const blockHeights = new Set();
  const ledgerIds = new Set();
  let previousBlock = null;
  let sawUnverified = false;
  for (let index = 0; index < SOURCE_ANCHORS.length; index += 1) {
    const transition = exactOrdered(
      value[index],
      AWS_WATCHER_TRANSITION_KEYS,
    );
    const expected = SOURCE_ANCHORS[index];
    if (
      transition.slot !== AWS_WATCHER_SLOTS[index] ||
      typeof transition.verified !== "boolean"
    ) {
      fail();
    }
    if (transition.verified) {
      if (
        sawUnverified ||
        transition.cardinality !== "1" ||
        typeof transition.ledgerId !== "string" ||
        !LEDGER_ID.test(transition.ledgerId) ||
        typeof transition.blockHeight !== "string"
      ) {
        fail();
      }
      positiveDecimal(transition.blockHeight);
      const block = BigInt(transition.blockHeight);
      if (
        (previousBlock !== null && block <= previousBlock) ||
        blockHeights.has(transition.blockHeight) ||
        ledgerIds.has(transition.ledgerId)
      ) {
        fail();
      }
      previousBlock = block;
      blockHeights.add(transition.blockHeight);
      ledgerIds.add(transition.ledgerId);
      anchors.push(Object.freeze({
        block: transition.blockHeight,
        explorerUrl: `https://sepolia.etherscan.io/block/${transition.blockHeight}`,
        kind: expected.kind,
        signerRole: expected.signerRole,
      }));
      continue;
    }
    sawUnverified = true;
    if (
      transition.cardinality !== "0" ||
      transition.blockHeight !== null ||
      transition.ledgerId !== null
    ) {
      fail();
    }
  }
  return Object.freeze(anchors);
}

export function buildAwsWatcherPublicMonitorSnapshot(
  projection,
  options,
) {
  const value = exactOrdered(
    projection,
    AWS_WATCHER_KEYS,
  );
  const input = exactOrdered(options, [
    "nowMs",
    "publishedAtMs",
    "releaseId",
    "repositorySha",
    "runId",
    "sessionId",
    "staleAfterMs",
    "subjectRun",
  ]);
  if (
    value.schema !== "clockchain.aws-watcher-projection/v1" ||
    value.paymentMoved !== false ||
    value.subjectRun !== "stakeholder" ||
    value.terminal !== null ||
    !/^release-[0-9a-f]{16}$/.test(value.releaseId) ||
    !SHA40.test(value.repositorySha) ||
    !UUID.test(value.sessionId) ||
    !RUN_ID.test(input.runId) ||
    input.releaseId !== value.releaseId ||
    input.repositorySha !== value.repositorySha ||
    input.sessionId !== value.sessionId ||
    input.subjectRun !== value.subjectRun ||
    input.runId !== `run-${value.releaseId.slice("release-".length)}`
  ) {
    fail();
  }
  const nowMs = safeInteger(input.nowMs);
  const observedAtMs = decimal(value.observedAtMs);
  const publishedAtMs = safeInteger(input.publishedAtMs);
  const staleAfterMs = safeInteger(input.staleAfterMs);
  if (
    staleAfterMs < 1_000 ||
    staleAfterMs > 60_000 ||
    publishedAtMs > nowMs ||
    observedAtMs > nowMs ||
    nowMs - observedAtMs > staleAfterMs
  ) {
    fail();
  }
  const anchors = validateAwsWatcherTransitions(value.transitions);
  if (value.state !== AWS_WATCHER_STATES[anchors.length]) {
    fail();
  }
  const runStatus = anchors.length === 0 ? "WAITING" : "RUNNING";
  return createSnapshot({
    anchors,
    currentStep: stepFor(
      runStatus,
      anchors,
      {
        mandate: {
          received: true,
        },
        request: {
          received: anchors.length > 0,
        },
      },
    ),
    fundingStatus: anchors.length === 0 ? "WAITING" : "READY",
    mcpStatus: "READY",
    payerStatus: "READY",
    publishedAtMs,
    relayStatus: "READY",
    requestorStatus: "READY",
    runId: input.runId,
    runStatus,
    staleAfterMs,
    verifierStatus: anchors.length === 3 ? "RUNNING" : "NOT_STARTED",
  });
}

export function buildUnavailablePublicMonitorSnapshot({
  publishedAtMs,
  runId,
  staleAfterMs,
} = {}) {
  if (!RUN_ID.test(runId)) fail();
  return createSnapshot({
    anchors: Object.freeze([]),
    currentStep:
      "Waiting for the Payer and Requestor to join the run.",
    fundingStatus: "NOT_STARTED",
    mcpStatus: "WAITING",
    payerStatus: "WAITING",
    publishedAtMs,
    relayStatus: "WAITING",
    requestorStatus: "WAITING",
    runId,
    runStatus: "WAITING",
    staleAfterMs,
    verifierStatus: "NOT_STARTED",
  });
}

function validatePublicAnchor(value, index) {
  const anchor = exact(
    value,
    PUBLIC_ANCHOR_KEYS,
  );
  const expected = SOURCE_ANCHORS[index];
  if (
    anchor.kind !== expected.kind ||
    anchor.signerRole !==
      expected.signerRole ||
    typeof anchor.block !== "string" ||
    !DECIMAL.test(anchor.block)
  ) {
    fail();
  }
  publicUrl(anchor.explorerUrl);
  return Object.freeze({ ...anchor });
}

function validatePublicSnapshot(value) {
  const snapshot = exact(value, PUBLIC_KEYS);
  if (
    snapshot.schema !==
      PUBLIC_MONITOR_SCHEMA ||
    snapshot.paymentMoved !== false ||
    !RUN_ID.test(snapshot.runId) ||
    !RUN_STATUS.has(snapshot.runStatus) ||
    !Array.isArray(snapshot.anchors) ||
    snapshot.anchors.length > 3
  ) {
    fail();
  }
  const anchors = Object.freeze(
    snapshot.anchors.map(
      validatePublicAnchor,
    ),
  );
  const verifier = statusObject(
    snapshot.verifier,
    VERIFIER_STATUS,
  );
  if (
    (
      snapshot.runStatus === "VERIFIED" &&
      (
        verifier.status !== "VERIFIED" ||
        anchors.length !== 3
      )
    ) ||
    (
      verifier.status === "VERIFIED" &&
      snapshot.runStatus !== "VERIFIED"
    )
  ) {
    fail();
  }
  return {
    anchors,
    currentStep:
      boundedText(snapshot.currentStep),
    funding: statusObject(
      snapshot.funding,
      FUNDING_STATUS,
    ),
    mcp: statusObject(
      snapshot.mcp,
      SERVICE_STATUS,
    ),
    payer: statusObject(
      snapshot.payer,
      SERVICE_STATUS,
    ),
    publishedAtMs: decimal(
      snapshot.publishedAtMs,
    ),
    relay: statusObject(
      snapshot.relay,
      SERVICE_STATUS,
    ),
    requestor: statusObject(
      snapshot.requestor,
      SERVICE_STATUS,
    ),
    runId: snapshot.runId,
    runStatus: snapshot.runStatus,
    staleAfterMs: safeInteger(
      snapshot.staleAfterMs,
    ),
    verifier,
  };
}

export function observePublicMonitorSnapshot(
  value,
  { nowMs } = {},
) {
  const snapshot =
    validatePublicSnapshot(value);
  const observedAt = safeInteger(nowMs);
  if (
    observedAt <=
    snapshot.publishedAtMs +
      snapshot.staleAfterMs
  ) {
    return Object.freeze({
      ...value,
      anchors: snapshot.anchors,
    });
  }
  return createSnapshot({
    anchors: snapshot.anchors,
    currentStep:
      "This public update expired; wait for a fresh validated monitor snapshot.",
    fundingStatus:
      snapshot.funding.status,
    mcpStatus: snapshot.mcp.status,
    payerStatus:
      snapshot.payer.status,
    publishedAtMs:
      snapshot.publishedAtMs,
    relayStatus:
      snapshot.relay.status,
    requestorStatus:
      snapshot.requestor.status,
    runId: snapshot.runId,
    runStatus: "EXPIRED",
    staleAfterMs:
      snapshot.staleAfterMs,
    verifierStatus: "EXPIRED",
  });
}
