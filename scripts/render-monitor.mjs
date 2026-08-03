import { writeFile } from "node:fs/promises";
import { parseArgs } from "node:util";

import { createRelayClient } from "../src/relay/client.mjs";
import { buildMonitorSnapshot } from "../src/monitor/snapshot.mjs";
import { renderStakeholderPage } from "../src/monitor/stakeholder/render.mjs";
import { renderControlPlanePage } from "../src/monitor/control-plane/render.mjs";

// Render the monitor views for one session from a relay.
// Read-only: this script never writes to the relay.

const { values } = parseArgs({
  options: {
    "relay-url": { type: "string" },
    "session-id": { type: "string" },
    out: { type: "string" },
    view: { type: "string", default: "both" },
  },
  strict: true,
});

if (
  typeof values["relay-url"] !== "string" ||
  typeof values["session-id"] !== "string" ||
  typeof values.out !== "string" ||
  !["stakeholder", "control", "both"].includes(values.view)
) {
  process.stderr.write(
    "usage: render-monitor.mjs --relay-url <url> --session-id <id> --out <file.html> [--view stakeholder|control|both]\n",
  );
  process.exit(1);
}

const relay = createRelayClient({ relayUrl: values["relay-url"] });
const snapshot = await buildMonitorSnapshot({
  relay,
  sessionId: values["session-id"],
});

const targets = [];
if (values.view === "stakeholder" || values.view === "both") {
  targets.push([
    values.view === "both" ? values.out.replace(/\.html$/, ".stakeholder.html") : values.out,
    renderStakeholderPage(snapshot),
  ]);
}
if (values.view === "control" || values.view === "both") {
  targets.push([
    values.view === "both" ? values.out.replace(/\.html$/, ".control.html") : values.out,
    renderControlPlanePage(snapshot),
  ]);
}
for (const [path, html] of targets) {
  await writeFile(path, html, { encoding: "utf8", mode: 0o644 });
  process.stdout.write(`wrote ${path}\n`);
}
process.stdout.write(
  `phase=${snapshot.phase} messages=${snapshot.messages.length} verdict=${snapshot.verdict === null ? "pending" : "published"}\n`,
);
