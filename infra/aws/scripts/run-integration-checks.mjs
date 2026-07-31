#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

const SHA40 = /^[0-9a-f]{40}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;

function fail(label) {
  throw new Error(
    `AWS live integration report failed: ${label}.`,
  );
}

function requireTrue(value, label) {
  if (value !== true) {
    fail(label);
  }
}

function requireChecks(value, label) {
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    value.some(
      (item) =>
        typeof item !== "string" ||
        item.length === 0,
    )
  ) {
    fail(label);
  }
}

export function validateIntegrationReport(report) {
  const serialized = JSON.stringify(report);
  if (
    /"(?:secret|secretValue|privateKey|password|token|capability|invitation)"\s*:/i.test(
      serialized,
    )
  ) {
    throw new Error(
      "AWS live integration report contains a forbidden secret field.",
    );
  }
  if (
    report?.schema !==
    "clockchain.aws-live-integration-report/v1"
  ) {
    fail("schema");
  }
  if (
    !SHA40.test(
      report?.images?.repositorySha ?? "",
    ) ||
    !DIGEST.test(
      report?.images?.controlPlaneDigest ??
        "",
    ) ||
    !DIGEST.test(
      report?.images?.tunnelDigest ?? "",
    )
  ) {
    fail("image/SHA binding");
  }
  for (const service of [
    "bootstrap",
    "operator",
    "publisher",
    "relay",
    "tunnel",
  ]) {
    if (
      report?.services?.[service] !==
      "STABLE"
    ) {
      fail(`${service} service stability`);
    }
  }
  requireChecks(
    report?.iam?.allowChecks,
    "IAM allow checks",
  );
  requireChecks(
    report?.iam?.denyChecks,
    "IAM deny checks",
  );
  requireChecks(
    report?.efs?.allowChecks,
    "EFS allow checks",
  );
  requireChecks(
    report?.efs?.denyChecks,
    "EFS deny checks",
  );
  for (const [group, keys] of [
    [
      "network",
      [
        "payerMcpClosedBeforeApproval",
        "rawTcpTlsPassThrough",
        "tunnelHostKeyPinned",
      ],
    ],
    [
      "restart",
      [
        "bootstrapRecovered",
        "publisherRecovered",
        "relayRecovered",
        "tunnelRecovered",
      ],
    ],
    [
      "funding",
      [
        "firstExecutionRecorded",
        "replayRejected",
      ],
    ],
    [
      "canaryScans",
      [
        "cloudWatchClean",
        "publicObjectsClean",
      ],
    ],
    [
      "monitor",
      [
        "staleStateObserved",
        "updatesAcrossTwoWindows",
      ],
    ],
  ]) {
    for (const key of keys) {
      requireTrue(
        report?.[group]?.[key],
        `${group}.${key}`,
      );
    }
  }
  return report;
}

async function main() {
  const reportPath =
    process.argv.find((argument) =>
      argument.startsWith("--report="),
    )?.slice("--report=".length) ??
    process.env.AWS_INTEGRATION_REPORT;
  if (!reportPath) {
    throw new Error(
      "A private integration report path is required.",
    );
  }
  const report = JSON.parse(
    await readFile(reportPath, "utf8"),
  );
  validateIntegrationReport(report);
  process.stdout.write(
    "AWS live integration report passed.\n",
  );
}

if (
  process.argv[1] !== undefined &&
  import.meta.url ===
    pathToFileURL(process.argv[1]).href
) {
  main().catch((error) => {
    process.stderr.write(
      `${error instanceof Error ? error.message : "AWS integration checks failed."}\n`,
    );
    process.exitCode = 1;
  });
}
