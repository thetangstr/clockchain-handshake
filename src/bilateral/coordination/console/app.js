const field = (id) => document.querySelector(`#${id}`);
const timeline = field("anchor-timeline");

function text(value) {
  return typeof value === "string" && value.length > 0 ? value : "unavailable";
}

function booleanStatus(value) {
  return value === true ? "yes" : "no";
}

function setField(id, value) {
  const target = field(id);
  if (target !== null) target.textContent = value;
}

function setTimeline(anchors) {
  if (timeline === null) return;
  timeline.textContent = "";
  if (!Array.isArray(anchors) || anchors.length === 0) {
    const item = document.createElement("li");
    item.textContent = "No verified anchors available";
    timeline.append(item);
    return;
  }
  for (const anchor of anchors) {
    const item = document.createElement("li");
    item.textContent = `${text(anchor.actor)} ${text(anchor.kind)} block ${text(anchor.block)} digest ${text(anchor.digest)}`;
    timeline.append(item);
  }
}

function render(projection) {
  setField("operator-health", `${text(projection.actors?.operator?.label)} ${text(projection.actors?.operator?.health)}`);
  setField("iris-health", `${text(projection.actors?.payer?.label)} ${text(projection.actors?.payer?.health)}`);
  setField("billie-health", `${text(projection.actors?.payee?.label)} ${text(projection.actors?.payee?.health)}`);
  setField("request-status", `received ${booleanStatus(projection.request?.received)} digest ${text(projection.request?.digest)}`);
  setField("mandate-status", `received ${booleanStatus(projection.mandate?.received)} matched ${booleanStatus(projection.mandate?.matched)} digest ${text(projection.mandate?.digest)}`);
  setField("deadline-freshness", `${text(projection.deadline?.freshness)} until ${text(projection.deadline?.expiresAtMs)}`);
  setField("verifier-state", `${text(projection.verifier?.status)} advisory ${booleanStatus(projection.verifier?.advisory)}`);
  setField("relay-advisory", `${text(projection.session?.observations?.relay?.label)} ${text(projection.session?.observations?.relay?.health)}`);
  setField("watcher-advisory", `${text(projection.session?.observations?.watcher?.label)} ${text(projection.session?.observations?.watcher?.health)}`);
  setField("failure-recovery", projection.failure?.active === true ? `${text(projection.failure.code)} ${text(projection.failure.recovery?.label)}` : "no active recovery");
  setTimeline(projection.anchors);
}

async function refresh() {
  try {
    const response = await fetch("/v1/console/session", { cache: "no-store" });
    if (!response.ok) throw new Error("unavailable");
    render(await response.json());
  } catch {
    for (const id of ["operator-health", "iris-health", "billie-health", "request-status", "mandate-status", "deadline-freshness", "verifier-state", "relay-advisory", "watcher-advisory", "failure-recovery"]) setField(id, "unavailable");
    setTimeline([]);
  }
}

refresh();
setInterval(refresh, 3000);
