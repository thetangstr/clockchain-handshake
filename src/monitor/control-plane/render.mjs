import { MONITOR_MESSAGE_MAP } from "../snapshot.mjs";

// Control-plane view: operator-facing rendering of the same monitor
// snapshot. Raw message table, role heartbeats, evidence presence,
// and the verdict document when it exists. Same rule as the
// stakeholder view: the final-verdict word never renders before a
// signed verdict document is present.

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function messageRows(snapshot) {
  if (snapshot.messages.length === 0) {
    return `<tr><td colspan="4" class="muted">no messages yet</td></tr>`;
  }
  return snapshot.messages
    .map((message) => {
      const mapped = MONITOR_MESSAGE_MAP[message.kind];
      return `<tr>
<td>${escapeHtml(message.seq ?? "")}</td>
<td>${escapeHtml(message.kind)}</td>
<td>${escapeHtml(message.role)}</td>
<td>${escapeHtml(mapped === undefined ? "UNMAPPED" : mapped.phase)}</td>
</tr>`;
    })
    .join("\n");
}

function roleRows(snapshot) {
  const entries = Object.entries(snapshot.roles);
  if (entries.length === 0) {
    return `<tr><td colspan="3" class="muted">no role heartbeats yet</td></tr>`;
  }
  return entries
    .map(([role, status]) => {
      const phase =
        status !== null && typeof status === "object"
          ? (status.phase ?? "")
          : "";
      const state =
        status !== null && typeof status === "object"
          ? (status.state ?? "")
          : "";
      return `<tr>
<td>${escapeHtml(role)}</td>
<td>${escapeHtml(phase)}</td>
<td>${escapeHtml(state)}</td>
</tr>`;
    })
    .join("\n");
}

function verdictPanel(snapshot) {
  if (snapshot.verdict === null) {
    return `<p class="muted">No verdict document published. The control
plane renders session evidence only; it never asserts an outcome.</p>`;
  }
  return `<h2>Verdict document</h2>
<pre class="verdict">${escapeHtml(JSON.stringify(snapshot.verdict, null, 2))}</pre>`;
}

export function renderControlPlanePage(snapshot) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Handshake control plane — ${escapeHtml(snapshot.sessionId)}</title>
<style>
body { font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 60rem; color: #17202a; }
h1 { font-size: 1.3rem; }
table { border-collapse: collapse; width: 100%; margin: 0.5rem 0 1.5rem; }
th, td { border: 1px solid #d6dbe1; padding: 0.3rem 0.6rem; text-align: left; font-size: 0.9rem; }
th { background: #f4f6f8; }
.mono, pre { font-family: ui-monospace, monospace; font-size: 0.8em; }
.muted { color: #68727d; }
pre.verdict { border: 1px solid #1d7a3a; background: #f1f9f3; padding: 1rem; border-radius: 8px; overflow-x: auto; }
</style>
</head>
<body>
<h1>Control plane</h1>
<p class="muted">Session <span class="mono">${escapeHtml(snapshot.sessionId)}</span> ·
sub-run ${escapeHtml(snapshot.subjectRun)} ·
phase ${escapeHtml(snapshot.phase)} ·
discovery published: ${snapshot.discoveryPublished ? "yes" : "no"} ·
payment moved: <strong>no</strong></p>
<h2>Messages</h2>
<table>
<tr><th>seq</th><th>kind</th><th>role</th><th>monitor phase</th></tr>
${messageRows(snapshot)}
</table>
<h2>Role heartbeats</h2>
<table>
<tr><th>role</th><th>phase</th><th>state</th></tr>
${roleRows(snapshot)}
</table>
<h2>Evidence</h2>
<table>
<tr><th>role</th><th>folded</th></tr>
<tr><td>payer</td><td>${snapshot.evidence.payer ? "yes" : "no"}</td></tr>
<tr><td>payee</td><td>${snapshot.evidence.payee ? "yes" : "no"}</td></tr>
</table>
${verdictPanel(snapshot)}
</body>
</html>
`;
}
