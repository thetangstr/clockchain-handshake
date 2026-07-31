import assert from "node:assert/strict";
import test from "node:test";

import {
  validateIntegrationReport,
} from "../scripts/run-integration-checks.mjs";

const SHA = "a".repeat(40);
const DIGEST = `sha256:${"b".repeat(64)}`;

function validReport() {
  return {
    canaryScans: {
      cloudWatchClean: true,
      publicObjectsClean: true,
    },
    efs: {
      allowChecks: ["operator-own-access-point"],
      denyChecks: ["operator-verifier-evidence"],
    },
    funding: {
      firstExecutionRecorded: true,
      replayRejected: true,
    },
    iam: {
      allowChecks: ["operator-run-approved-task"],
      denyChecks: ["publisher-read-secrets"],
    },
    images: {
      controlPlaneDigest: DIGEST,
      repositorySha: SHA,
      tunnelDigest: DIGEST,
    },
    monitor: {
      staleStateObserved: true,
      updatesAcrossTwoWindows: true,
    },
    network: {
      payerMcpClosedBeforeApproval: true,
      rawTcpTlsPassThrough: true,
      tunnelHostKeyPinned: true,
    },
    restart: {
      bootstrapRecovered: true,
      publisherRecovered: true,
      relayRecovered: true,
      tunnelRecovered: true,
    },
    schema: "clockchain.aws-live-integration-report/v1",
    services: {
      bootstrap: "STABLE",
      operator: "STABLE",
      publisher: "STABLE",
      relay: "STABLE",
      tunnel: "STABLE",
    },
  };
}

test("accepts the complete credentialed integration report contract", () => {
  assert.deepEqual(
    validateIntegrationReport(validReport()),
    validReport(),
  );
});

test("fails closed when allow/deny, restart, funding, network, or monitor evidence is missing", () => {
  const mutations = [
    (report) => {
      report.iam.denyChecks = [];
    },
    (report) => {
      report.efs.allowChecks = [];
    },
    (report) => {
      report.restart.relayRecovered = false;
    },
    (report) => {
      report.funding.replayRejected = false;
    },
    (report) => {
      report.network.rawTcpTlsPassThrough = false;
    },
    (report) => {
      report.monitor.updatesAcrossTwoWindows = false;
    },
  ];
  for (const mutate of mutations) {
    const report = validReport();
    mutate(report);
    assert.throws(
      () => validateIntegrationReport(report),
      /integration report failed/i,
    );
  }
});

test("rejects secrets in the report", () => {
  const report = validReport();
  report.secretValue = "canary-private-value";
  assert.throws(
    () => validateIntegrationReport(report),
    /secret/i,
  );
});
