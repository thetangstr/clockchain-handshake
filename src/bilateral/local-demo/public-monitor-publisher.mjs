import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { observePublicMonitorSnapshot } from "../coordination/public-monitor.mjs";
import {
  appendPublicRunIndex,
  createImmutableRunSummary,
} from "../aws/public-history.mjs";

export const LOCAL_PUBLIC_MONITOR_SCHEMA =
  "clockchain.local-public-monitor-publisher/v1";

export class LocalPublicMonitorError extends Error {
  constructor() {
    super("The local public monitor input is invalid.");
    this.name = "LocalPublicMonitorError";
    this.code = "LOCAL_PUBLIC_MONITOR_INVALID";
  }
}

function fail() {
  throw new LocalPublicMonitorError();
}

function plain(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value)
  );
}

function decimalText(value) {
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]*)$/.test(value)) fail();
  return value;
}

function instant(value) {
  if (!Number.isSafeInteger(value) || value < 0) fail();
  return value;
}

function secretFree(bytes, canaries) {
  const text = Buffer.isBuffer(bytes) ? bytes.toString("utf8") : String(bytes);
  for (const canary of canaries) {
    if (typeof canary !== "string" || canary.length === 0) fail();
    if (text.includes(canary)) fail();
  }
}

const HEALTH = new Set(["READY", "WAITING", "FAILED", "UNAVAILABLE"]);

function health(value) {
  if (typeof value !== "string" || !HEALTH.has(value)) fail();
  return value;
}

const STATE_RANK = Object.freeze({
  BOOTSTRAPPING: 0,
  ADDRESSES_READY: 1,
  FUNDING_READY: 2,
  PREFLIGHT_PASSED: 3,
  REHEARSAL_IDENTITIES_READY: 4,
  REHEARSAL_DESCRIPTOR_READY: 5,
  REHEARSAL_PACKAGES_READY: 6,
  REHEARSAL_VERIFIED: 7,
  STAKEHOLDER_IDENTITIES_READY: 8,
  STAKEHOLDER_DESCRIPTOR_READY: 9,
  STAKEHOLDER_PACKAGES_READY: 10,
  STAKEHOLDER_VERIFIED: 11,
  COMPLETE: 12,
});

const SIGNER_FOR_KIND = Object.freeze({
  PROPOSED: "Payer",
  ACCEPTED: "Requestor",
  ACKNOWLEDGED: "Payer",
});

function stepText({ anchors, runStatus, verifierStatus, facts }) {
  if (runStatus === "VERIFIED") {
    return "The fresh verifier confirmed the full handshake: three ordered Clockchain receipts, no payment moved.";
  }
  if (verifierStatus === "RUNNING") {
    return "All three Clockchain receipts are anchored; the fresh verifier is checking them independently.";
  }
  if (anchors.length > 0) {
    return "The Clockchain handshake is anchoring on-chain receipts in order.";
  }
  if (facts?.paymentRequestMatched?.stakeholder === true) {
    return "The payment request is matched and the Clockchain handshake is starting.";
  }
  if (facts?.payerMandateReady?.stakeholder === true) {
    return "The Payer mandate is ready and the Requestor may submit a matching request.";
  }
  return "Waiting for the Payer and Requestor to join the run.";
}

// Maps the secret-free local console state onto the exact v3 public monitor
// snapshot the public run page consumes.  Pure and total: any deviation fails
// closed before a byte can reach the public bucket.
export function snapshotFromConsoleState(value, { nowMs, staleAfterMs = 60_000 } = {}) {
  if (!plain(value) || !plain(value.lifecycleView)) fail();
  const view = value.lifecycleView;
  const now = instant(nowMs);
  if (!Number.isSafeInteger(staleAfterMs) || staleAfterMs < 1_000 || staleAfterMs > 60_000) fail();
  if (typeof view.releaseId !== "string" || !view.releaseId.startsWith("release-")) fail();
  const runId = `run-${view.releaseId.slice("release-".length)}`;
  if (!/^run-[0-9a-f]{16}$/.test(runId)) fail();
  const state = view.state;
  if (typeof state !== "string" || !(state in STATE_RANK)) fail();
  const rank = STATE_RANK[state];
  const rawAnchors = value.watcherSnapshot === undefined ? [] : value.watcherSnapshot?.anchors;
  if (!Array.isArray(rawAnchors) || rawAnchors.length > 3) fail();
  const anchors = rawAnchors.map((anchor) => {
    if (!plain(anchor)) fail();
    const signerRole = SIGNER_FOR_KIND[anchor.kind];
    if (signerRole === undefined || anchor.verified !== true || anchor.cardinality !== "1") fail();
    const block = decimalText(anchor.block);
    if (BigInt(block) <= 0n) fail();
    if (typeof anchor.ledgerId !== "string" || anchor.ledgerId.length === 0 || anchor.ledgerId.length > 128) fail();
    return Object.freeze({
      block,
      cardinality: "1",
      explorerUrl: `https://sepolia.etherscan.io/block/${block}`,
      kind: anchor.kind,
      ledgerId: anchor.ledgerId,
      signerRole,
      verified: true,
    });
  });
  const publication = value.verifierPublication;
  const verifierStatus =
    publication !== undefined
      ? (plain(publication) && publication.status === "VERIFICATION_PASSED" && publication.paymentMoved === false
          ? "VERIFIED"
          : fail())
      : anchors.length === 3
        ? "RUNNING"
        : "NOT_STARTED";
  const runStatus =
    verifierStatus === "VERIFIED"
      ? "VERIFIED"
      : anchors.length > 0 || rank >= STATE_RANK.FUNDING_READY
        ? "RUNNING"
        : "WAITING";
  if (runStatus === "WAITING" && (anchors.length !== 0 || verifierStatus !== "NOT_STARTED")) fail();
  const actors = plain(view.health?.actors) ? view.health.actors : fail();
  const services = plain(view.health?.services) ? view.health.services : fail();
  const facts = plain(view.facts) ? view.facts : {};
  const fundingStatus =
    rank < STATE_RANK.ADDRESSES_READY
      ? "NOT_STARTED"
      : rank < STATE_RANK.FUNDING_READY
        ? "WAITING"
        : "READY";
  return Object.freeze({
    anchors: Object.freeze(anchors),
    currentStep: stepText({ anchors, runStatus, verifierStatus, facts }),
    funding: Object.freeze({ status: fundingStatus }),
    mcp: Object.freeze({ status: facts?.payerMandateReady?.stakeholder === true ? "READY" : "WAITING" }),
    paymentMoved: false,
    payer: Object.freeze({ status: health(actors.payer) }),
    publishedAtMs: String(now),
    relay: Object.freeze({ status: health(services.relay) }),
    requestor: Object.freeze({ status: health(actors.payee) }),
    runId,
    runStatus,
    schema: "clockchain.bilateral-public-monitor/v3",
    staleAfterMs,
    verifier: Object.freeze({ status: verifierStatus }),
  });
}

async function atomicWrite(path, bytes) {
  await mkdir(dirname(path), { recursive: true });
  const temporary = join(dirname(path), `.${Date.now()}-${process.pid}.tmp`);
  await writeFile(temporary, bytes);
  await rename(temporary, path);
}

// Read-only public monitor publisher for the hybrid local operator.  It never
// touches protocol state; every artifact passes the repository validator and
// a canary scan before one byte leaves the machine.
export function createLocalPublicMonitorPublisher({
  bucketPrefix,
  consoleStatePath,
  now = Date.now,
  pollMs = 15_000,
  publicBaseUrl,
  secretCanaries = [],
  sleeper = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  stageRoot,
  transport,
}) {
  if (
    typeof consoleStatePath !== "string" || consoleStatePath.length === 0 ||
    typeof stageRoot !== "string" || stageRoot.length === 0 ||
    typeof bucketPrefix !== "string" || !bucketPrefix.startsWith("s3://") ||
    typeof publicBaseUrl !== "string" || !publicBaseUrl.startsWith("https://") ||
    typeof transport !== "function" ||
    typeof now !== "function" || typeof sleeper !== "function" ||
    !Number.isSafeInteger(pollMs) || pollMs < 1_000 ||
    !Array.isArray(secretCanaries)
  ) fail();
  const history = { written: false };

  const publish = async (relativePath, object) => {
    const bytes = Buffer.from(JSON.stringify(object), "utf8");
    secretFree(bytes, secretCanaries);
    const localPath = join(stageRoot, relativePath);
    await atomicWrite(localPath, bytes);
    await transport(localPath, `${bucketPrefix}/${relativePath}`);
  };

  const readConsoleState = async () => {
    let raw;
    try {
      raw = await readFile(consoleStatePath);
    } catch {
      return null;
    }
    try {
      return JSON.parse(raw.toString("utf8"));
    } catch {
      fail();
    }
  };

  const readIndex = async () => {
    try {
      return JSON.parse((await readFile(join(stageRoot, "runs", "index.json"))).toString("utf8"));
    } catch {
      return null;
    }
  };

  async function publishOnce() {
    const consoleState = await readConsoleState();
    if (consoleState === null) return Object.freeze({ published: false, reason: "NO_CONSOLE_STATE" });
    const nowMs = instant(now());
    const snapshot = snapshotFromConsoleState(consoleState, { nowMs });
    const validated = observePublicMonitorSnapshot(snapshot, { nowMs });
    if (validated.runStatus !== snapshot.runStatus) fail();
    await publish("latest.json", validated);
    if (validated.runStatus === "VERIFIED" && !history.written) {
      const completedAtMs = instant(now());
      const summaryUrl = `${publicBaseUrl.replace(/\/$/, "")}/runs/${validated.runId}.json`;
      const summary = createImmutableRunSummary({
        completedAtMs,
        projection: validated,
        secretCanaries,
        summaryUrl,
        verifierPublicationValidated: true,
      });
      const index = appendPublicRunIndex({
        index: await readIndex(),
        summary,
        updatedAtMs: completedAtMs,
      });
      await publish(join("runs", `${validated.runId}.json`), summary);
      await publish(join("runs", "index.json"), index);
      history.written = true;
    }
    return Object.freeze({
      historyWritten: history.written,
      published: true,
      runId: validated.runId,
      runStatus: validated.runStatus,
    });
  }

  async function run({ graceMs = 1_800_000, maxMs = 7_200_000 } = {}) {
    if (!Number.isSafeInteger(graceMs) || graceMs < 0 || !Number.isSafeInteger(maxMs) || maxMs < pollMs) fail();
    const started = instant(now());
    let terminalAt = null;
    for (;;) {
      const result = await publishOnce();
      const current = instant(now());
      if (result.published && result.runStatus === "VERIFIED" && terminalAt === null) terminalAt = current;
      if (terminalAt !== null && current - terminalAt >= graceMs) {
        return Object.freeze({ exitCode: 0, outcome: "VERIFIED_GRACE_ELAPSED", runId: result.runId });
      }
      if (current - started >= maxMs) {
        return Object.freeze({ exitCode: 1, outcome: terminalAt === null ? "MAX_ELAPSED_WITHOUT_VERDICT" : "MAX_ELAPSED" });
      }
      await sleeper(pollMs);
    }
  }

  return Object.freeze({ publishOnce, run });
}
