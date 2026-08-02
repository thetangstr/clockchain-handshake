import { isIP } from "node:net";
import { types } from "node:util";

import {
  PUBLIC_MONITOR_SCHEMA,
  observePublicMonitorSnapshot,
} from "../coordination/public-monitor.mjs";

export const AWS_PUBLIC_RUN_SUMMARY_SCHEMA =
  "clockchain.aws-public-run-summary/v2";
export const AWS_PUBLIC_RUN_INDEX_SCHEMA =
  "clockchain.aws-public-run-index/v2";
const AWS_PUBLIC_RUN_INDEX_LEGACY_SCHEMA =
  "clockchain.aws-public-run-index/v1";

const SUMMARY_KEYS = Object.freeze([
  "anchors",
  "businessResult",
  "completedAtMs",
  "paymentMoved",
  "runId",
  "runStatus",
  "schema",
  "summaryUrl",
]);
const INDEX_KEYS = Object.freeze([
  "entries",
  "paymentMoved",
  "schema",
  "updatedAtMs",
]);
const ENTRY_KEYS = Object.freeze([
  "anchors",
  "businessResult",
  "completedAtMs",
  "runId",
  "runStatus",
  "summaryUrl",
]);
const RUN_ID = /^run-[0-9a-f]{16}$/;
const SHA64 = /^[0-9a-f]{64}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const TERMINAL = new Set([
  "VERIFIED",
  "FAILED",
  "EXPIRED",
]);

export class AwsPublicHistoryError extends Error {
  constructor() {
    super("AWS public history failed safely.");
    this.name = "AwsPublicHistoryError";
    this.code = "AWS_PUBLIC_HISTORY_FAILED";
    this.category = "verification";
  }
}

function fail() {
  throw new AwsPublicHistoryError();
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

function integer(value) {
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

function publicUrl(value) {
  if (typeof value !== "string") fail();
  let url;
  try {
    url = new URL(value);
  } catch {
    fail();
  }
  const ip = isIP(url.hostname);
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== "" ||
    url.hostname === "localhost" ||
    url.hostname.endsWith(".local") ||
    (
      ip === 4 &&
      (
        url.hostname.startsWith("10.") ||
        url.hostname.startsWith("127.") ||
        url.hostname.startsWith("192.168.") ||
        /^172\.(?:1[6-9]|2[0-9]|3[01])\./.test(
          url.hostname,
        )
      )
    )
  ) {
    fail();
  }
  return value;
}

function secretFree(value, canaries) {
  if (
    !Array.isArray(canaries) ||
    canaries.some(
      (canary) =>
        typeof canary !== "string" ||
        canary.length === 0,
    )
  ) {
    fail();
  }
  const serialized = JSON.stringify(value);
  if (
    canaries.some((canary) =>
      serialized.includes(canary))
  ) {
    fail();
  }
}

function businessResult(runStatus) {
  if (runStatus === "VERIFIED") {
    return "The Requestor followed the Payer mandate and all three Clockchain anchors were independently verified.";
  }
  if (runStatus === "FAILED") {
    return "The run stopped safely because the available evidence did not satisfy every required check.";
  }
  if (runStatus === "EXPIRED") {
    return "The run expired before fresh independent verification completed.";
  }
  fail();
}

function indexEntry(value) {
  const entry = exact(value, ENTRY_KEYS);
  if (
    !RUN_ID.test(entry.runId) ||
    !TERMINAL.has(entry.runStatus) ||
    entry.businessResult !== businessResult(entry.runStatus)
  ) {
    fail();
  }
  const completedAtMs = decimal(entry.completedAtMs);
  publicUrl(entry.summaryUrl);
  if (
    !Array.isArray(entry.anchors) ||
    entry.anchors.length > 3 ||
    (
      entry.runStatus === "VERIFIED" &&
      entry.anchors.length !== 3
    )
  ) {
    fail();
  }
  const observed = observePublicMonitorSnapshot(
    {
      anchors: entry.anchors,
      currentStep: entry.businessResult,
      funding: { status: "READY" },
      mcp: { status: "READY" },
      paymentMoved: false,
      payer: { status: "READY" },
      publishedAtMs: entry.completedAtMs,
      relay: { status: "READY" },
      requestor: { status: "READY" },
      runId: entry.runId,
      runStatus: entry.runStatus,
      schema: PUBLIC_MONITOR_SCHEMA,
      staleAfterMs: 60_000,
      verifier: { status: entry.runStatus },
    },
    { nowMs: completedAtMs },
  );
  return Object.freeze({
    ...entry,
    anchors: observed.anchors,
  });
}

function validateIndex(value) {
  const index = exact(value, INDEX_KEYS);
  if (
    ![
      AWS_PUBLIC_RUN_INDEX_SCHEMA,
      AWS_PUBLIC_RUN_INDEX_LEGACY_SCHEMA,
    ].includes(index.schema) ||
    index.paymentMoved !== false ||
    !Array.isArray(index.entries) ||
    index.entries.length > 25
  ) {
    fail();
  }
  decimal(index.updatedAtMs);
  const ids = new Set();
  let previous = Number.MAX_SAFE_INTEGER;
  const entries = index.entries.map(
    (candidate) => {
      const entry = indexEntry(candidate);
      const completedAtMs = decimal(
        entry.completedAtMs,
      );
      if (
        ids.has(entry.runId) ||
        completedAtMs > previous
      ) {
        fail();
      }
      ids.add(entry.runId);
      previous = completedAtMs;
      return Object.freeze({ ...entry });
    },
  );
  return {
    ...index,
    schema: AWS_PUBLIC_RUN_INDEX_SCHEMA,
    entries: Object.freeze(entries),
  };
}

export function createImmutableRunSummary({
  completedAtMs,
  projection,
  secretCanaries,
  summaryUrl,
  verifierPublicationValidated,
} = {}) {
  try {
    const completion = integer(
      completedAtMs,
    );
    secretFree(projection, secretCanaries);
    const publishedAtMs = decimal(
      projection?.publishedAtMs,
    );
    const validated =
      observePublicMonitorSnapshot(
        projection,
        { nowMs: publishedAtMs },
      );
    if (
      !TERMINAL.has(validated.runStatus) ||
      validated.paymentMoved !== false ||
      !RUN_ID.test(validated.runId) ||
      completion < publishedAtMs ||
      (
        validated.runStatus === "VERIFIED" &&
        (
          verifierPublicationValidated !== true ||
          validated.verifier.status !==
            "VERIFIED" ||
          validated.anchors.length !== 3
        )
      ) ||
      (
        validated.runStatus !== "VERIFIED" &&
        verifierPublicationValidated !== false
      )
    ) {
      fail();
    }
    const summary = Object.freeze({
      anchors: validated.anchors,
      businessResult: businessResult(
        validated.runStatus,
      ),
      completedAtMs: String(completion),
      paymentMoved: false,
      runId: validated.runId,
      runStatus: validated.runStatus,
      schema:
        AWS_PUBLIC_RUN_SUMMARY_SCHEMA,
      summaryUrl: publicUrl(summaryUrl),
    });
    secretFree(summary, secretCanaries);
    return summary;
  } catch (error) {
    if (
      error instanceof AwsPublicHistoryError
    ) {
      throw error;
    }
    fail();
  }
}

export function observeImmutableRunSummary(value) {
  try {
    const summary = exact(value, SUMMARY_KEYS);
    if (
      summary.schema !== AWS_PUBLIC_RUN_SUMMARY_SCHEMA ||
      summary.paymentMoved !== false
    ) {
      fail();
    }
    const checked = indexEntry({
      anchors: summary.anchors,
      businessResult: summary.businessResult,
      completedAtMs: summary.completedAtMs,
      runId: summary.runId,
      runStatus: summary.runStatus,
      summaryUrl: summary.summaryUrl,
    });
    if (
      checked.runStatus === "VERIFIED" &&
      checked.anchors.length !== 3
    ) {
      fail();
    }
    return Object.freeze({
      ...summary,
      anchors: checked.anchors,
    });
  } catch (error) {
    if (error instanceof AwsPublicHistoryError) {
      throw error;
    }
    fail();
  }
}

export function appendPublicRunIndex({
  index,
  summary,
  updatedAtMs,
} = {}) {
  try {
    const updateTime = integer(updatedAtMs);
    const source =
      index === null
        ? {
            entries: [],
            paymentMoved: false,
            schema:
              AWS_PUBLIC_RUN_INDEX_SCHEMA,
            updatedAtMs: "0",
          }
        : validateIndex(index);
    const candidate =
      observeImmutableRunSummary(summary);
    const entry = indexEntry({
      anchors: candidate.anchors,
      businessResult:
        candidate.businessResult,
      completedAtMs:
        candidate.completedAtMs,
      runId: candidate.runId,
      runStatus: candidate.runStatus,
      summaryUrl: candidate.summaryUrl,
    });
    if (
      source.entries.some(
        ({ runId }) =>
          runId === entry.runId,
      ) ||
      (
        source.entries.length > 0 &&
        decimal(entry.completedAtMs) <
          decimal(
            source.entries[0]
              .completedAtMs,
          )
      ) ||
      updateTime <
        decimal(entry.completedAtMs)
    ) {
      fail();
    }
    return Object.freeze({
      entries: Object.freeze(
        [
          Object.freeze({ ...entry }),
          ...source.entries,
        ].slice(0, 25),
      ),
      paymentMoved: false,
      schema: AWS_PUBLIC_RUN_INDEX_SCHEMA,
      updatedAtMs: String(updateTime),
    });
  } catch (error) {
    if (
      error instanceof AwsPublicHistoryError
    ) {
      throw error;
    }
    fail();
  }
}

export function publicArtifactKeys({
  certificateFingerprint,
  runId,
} = {}) {
  try {
    if (
      !RUN_ID.test(runId) ||
      typeof certificateFingerprint !==
        "string" ||
      !SHA64.test(
        certificateFingerprint,
      )
    ) {
      fail();
    }
    return Object.freeze({
      certificate:
        `certificates/${certificateFingerprint}.crt`,
      index: "runs/index.json",
      latest: "latest.json",
      payerDiscovery:
        "discoveries/payer.json",
      requestorDiscovery:
        "discoveries/requestor.json",
      summary: `runs/${runId}.json`,
    });
  } catch (error) {
    if (
      error instanceof AwsPublicHistoryError
    ) {
      throw error;
    }
    fail();
  }
}
