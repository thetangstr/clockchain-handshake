import {
  MONITOR_MESSAGE_MAP,
  MONITOR_PHASES,
} from "../snapshot.mjs";

// Stakeholder view: business-language rendering of a monitor
// snapshot. Framework-free, self-contained, every dynamic field
// HTML-escaped. The final-verdict word appears only when a signed
// verdict document is present on the relay — never before.

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

const PHASE_TITLES = Object.freeze({
  opened: "Session opened",
  participants: "Participants identified",
  funded: "Requestor funded",
  ready: "Identities registered",
  mandate: "Payer terms published",
  request: "Payment request signed",
  descriptor: "Session locked",
  anchored: "Evidence anchored",
  verified: "Independently verified",
});

const TRANSITION_TITLES = Object.freeze({
  proposal: "PROPOSED — payer publishes the mandate",
  acceptance: "ACCEPTED — requestor signs acceptance",
  acknowledgment: "ACKNOWLEDGED — payer acknowledges",
});

function timelineRows(snapshot) {
  const currentIndex = MONITOR_PHASES.indexOf(snapshot.phase);
  return MONITOR_PHASES.map((phase, index) => {
    const state =
      index < currentIndex
        ? "done"
        : index === currentIndex
          ? "current"
          : "pending";
    return `<li class="${state}"><span class="dot"></span>${escapeHtml(
      PHASE_TITLES[phase],
    )}</li>`;
  }).join("\n");
}

function anchorCards(snapshot) {
  if (snapshot.verdict === null) {
    return `<p class="muted">Anchor receipts appear here once the
      handshake completes and the evidence is anchored on Clockchain.</p>`;
  }
  const transitions = Array.isArray(snapshot.verdict.transitions)
    ? snapshot.verdict.transitions
    : [];
  return transitions
    .map((transition) => {
      const title =
        TRANSITION_TITLES[transition.kind] ?? transition.kind;
      return `<div class="card">
  <h3>${escapeHtml(title)}</h3>
  <dl>
    <dt>Clockchain block</dt><dd>${escapeHtml(transition.blockHeight)}</dd>
    <dt>Anchored hash</dt><dd class="mono">${escapeHtml(transition.anchoredHash)}</dd>
    <dt>Ledger</dt><dd class="mono">${escapeHtml(transition.ledgerId)}</dd>
  </dl>
</div>`;
    })
    .join("\n");
}

function verdictCard(snapshot) {
  if (snapshot.verdict === null) {
    return `<div class="card muted">
  <h3>Final verdict</h3>
  <p>Not yet published. Only the operator's fresh aggregate verifier
  can publish the final verdict; this page never asserts an outcome
  before that signed document exists.</p>
</div>`;
  }
  return `<div class="card verdict">
  <h3>Final verdict: ${escapeHtml(snapshot.verdict.outcome)}</h3>
  <dl>
    <dt>Payment moved</dt><dd>${snapshot.verdict.paymentMoved === false ? "no" : "UNKNOWN"}</dd>
    <dt>Session digest</dt><dd class="mono">${escapeHtml(snapshot.verdict.sessionDigest)}</dd>
    <dt>Mandate digest</dt><dd class="mono">${escapeHtml(snapshot.verdict.mandateDigest)}</dd>
    <dt>Request digest</dt><dd class="mono">${escapeHtml(snapshot.verdict.requestDigest)}</dd>
  </dl>
</div>`;
}

export function renderStakeholderPage(snapshot) {
  const seen = new Set();
  const activity = snapshot.messages
    .filter((message) => {
      const key = `${message.kind}:${message.role}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return MONITOR_MESSAGE_MAP[message.kind] !== undefined;
    })
    .map(
      (message) =>
        `<li>${escapeHtml(MONITOR_MESSAGE_MAP[message.kind].label)} <span class="muted">(${escapeHtml(message.role)})</span></li>`,
    )
    .join("\n");
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Clockchain Handshake — session ${escapeHtml(snapshot.sessionId)}</title>
<style>
body { font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 46rem; color: #17202a; }
h1 { font-size: 1.4rem; }
.mono { font-family: ui-monospace, monospace; font-size: 0.8em; word-break: break-all; }
.muted { color: #68727d; }
.card { border: 1px solid #d6dbe1; border-radius: 8px; padding: 1rem; margin: 0.75rem 0; }
.card.verdict { border-color: #1d7a3a; background: #f1f9f3; }
dl { display: grid; grid-template-columns: 9rem 1fr; gap: 0.25rem 0.75rem; margin: 0; }
dt { color: #68727d; } dd { margin: 0; }
ul.timeline { list-style: none; padding: 0; }
ul.timeline li { padding: 0.3rem 0; }
ul.timeline li.done { color: #1d7a3a; }
ul.timeline li.current { font-weight: 600; }
ul.timeline li.pending { color: #9aa4ae; }
.dot { display: inline-block; width: 0.6rem; height: 0.6rem; border-radius: 50%; background: currentColor; margin-right: 0.5rem; }
</style>
</head>
<body>
<h1>Bilateral payment authorization</h1>
<p class="muted">Session <span class="mono">${escapeHtml(snapshot.sessionId)}</span> · ${escapeHtml(snapshot.subjectRun)} · payment moved: <strong>no</strong></p>
<h2>Progress</h2>
<ul class="timeline">
${timelineRows(snapshot)}
</ul>
<h2>What has happened</h2>
<ul>
${activity}
</ul>
<h2>Clockchain anchor receipts</h2>
${anchorCards(snapshot)}
${verdictCard(snapshot)}
<p class="muted">Every fact on this page is read from signed relay
artifacts. Advisory fields are never treated as authority.</p>
</body>
</html>
`;
}
