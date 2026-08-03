import { RELAY_KINDS } from "../roles/catalog.mjs";

// Monitor snapshot assembly. Read-only: the monitor never writes to
// the relay and never sees private material. Every rendered field is
// already public on the relay (signed envelopes, statuses, verdict).

export const MONITOR_SNAPSHOT_SCHEMA = "handshake-monitor-snapshot/v1";

// Message-map completeness contract: every relay message kind has
// exactly one monitor label and phase. The completeness test fails
// if a kind is added to the catalog without a monitor mapping.
export const MONITOR_MESSAGE_MAP = Object.freeze({
  [RELAY_KINDS.IDENTITY_ANNOUNCE]: Object.freeze({
    label: "Participant identified",
    phase: "participants",
  }),
  [RELAY_KINDS.FUNDING_CONFIRMED]: Object.freeze({
    label: "Requestor funded",
    phase: "funded",
  }),
  [RELAY_KINDS.PARTY_READY]: Object.freeze({
    label: "Participant registered",
    phase: "ready",
  }),
  [RELAY_KINDS.MANDATE_PUBLISHED]: Object.freeze({
    label: "Payer terms published",
    phase: "mandate",
  }),
  [RELAY_KINDS.HANDSHAKE_REQUIRED]: Object.freeze({
    label: "Handshake required by payer policy",
    phase: "mandate",
  }),
  [RELAY_KINDS.PAYMENT_REQUEST]: Object.freeze({
    label: "Payment request received",
    phase: "request",
  }),
  [RELAY_KINDS.PAYMENT_REQUEST_SIGNED]: Object.freeze({
    label: "Payment request signed",
    phase: "request",
  }),
  [RELAY_KINDS.DESCRIPTOR_PUBLISHED]: Object.freeze({
    label: "Session locked by operator",
    phase: "descriptor",
  }),
});

export const MONITOR_PHASES = Object.freeze([
  "opened",
  "participants",
  "funded",
  "ready",
  "mandate",
  "request",
  "descriptor",
  "anchored",
  "verified",
]);

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value)
  );
}

export function derivePhase({ messages, verdict }) {
  let phase = "opened";
  for (const message of messages) {
    const mapped = MONITOR_MESSAGE_MAP[message.kind];
    if (mapped === undefined) continue;
    if (
      MONITOR_PHASES.indexOf(mapped.phase) >
      MONITOR_PHASES.indexOf(phase)
    ) {
      phase = mapped.phase;
    }
  }
  if (isPlainObject(verdict)) {
    phase = "verified";
  }
  return phase;
}

export async function buildMonitorSnapshot({ relay, sessionId }) {
  const base = await relay.getSnapshot(sessionId);
  const polled = await relay.pollMessages({
    sessionId,
    after: 0,
    waitMs: 0,
  });
  const messages = [];
  for (const entry of polled.messages ?? []) {
    const envelope = isPlainObject(entry.envelope)
      ? entry.envelope
      : entry;
    if (typeof envelope.kind !== "string") continue;
    messages.push(Object.freeze({
      kind: envelope.kind,
      role: typeof envelope.role === "string" ? envelope.role : "?",
      seq: typeof entry.seq === "number" ? entry.seq : null,
    }));
  }
  messages.sort((a, b) => (a.seq ?? 0) - (b.seq ?? 0));
  const evidence = {};
  for (const role of ["payer", "payee"]) {
    try {
      await relay.getEvidence(sessionId, role);
      evidence[role] = true;
    } catch {
      evidence[role] = false;
    }
  }
  const verdict = (() => {
    if (!isPlainObject(base.verdict)) return null;
    // The relay stores the signed verdict document; tolerate both the
    // bare document and the event-wrapped shape.
    if (isPlainObject(base.verdict.verdict)) return base.verdict.verdict;
    if (
      isPlainObject(base.verdict.document) &&
      isPlainObject(base.verdict.document.verdict)
    ) {
      return base.verdict.document.verdict;
    }
    return null;
  })();
  const evidenceFrozen = Object.freeze(evidence);
  let phase = derivePhase({ messages, verdict });
  // Anchored-but-unverified: both parties folded their evidence, the
  // verdict document has not landed yet.
  if (
    verdict === null &&
    evidenceFrozen.payer === true &&
    evidenceFrozen.payee === true &&
    MONITOR_PHASES.indexOf(phase) < MONITOR_PHASES.indexOf("anchored")
  ) {
    phase = "anchored";
  }
  return Object.freeze({
    discoveryPublished: base.discoveryPublished === true,
    evidence: evidenceFrozen,
    messages: Object.freeze(messages),
    paymentMoved: false,
    phase,
    roles: Object.freeze(base.roles ?? {}),
    schema: MONITOR_SNAPSHOT_SCHEMA,
    sessionId: base.sessionId,
    subjectRun: base.subjectRun,
    verdict,
  });
}
