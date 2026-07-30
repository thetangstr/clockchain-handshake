import assert from "node:assert/strict";
import test from "node:test";
import {
  buildPublicMonitorSnapshot,
  buildUnavailablePublicMonitorSnapshot,
} from "../src/bilateral/coordination/public-monitor.mjs";
import { parsePublicMonitorArguments } from "../scripts/publish-public-monitor.mjs";

function projection() {
  return {
    schema: "clockchain.bilateral-console-projection/v1",
    paymentMoved: false,
    actors: {
      operator: { health: "READY", label: "Operator", role: "operator" },
      payer: { health: "READY", label: "Payer", role: "payer" },
      payee: { health: "WAITING", label: "Requestor", role: "payee" },
    },
    session: {
      advisory: true,
      observations: {
        relay: { advisory: true, health: "READY", label: "relay advisory" },
        watcher: { advisory: true, health: "READY", label: "watcher advisory" },
      },
      releaseId: "private-release",
      repositorySha: "a".repeat(40),
      sessionId: "11111111-2222-4333-8444-555555555555",
    },
    mandate: {
      received: true,
      matched: true,
      kind: "pre-protocol",
      amount: { currency: "USD", value: "100" },
      purpose: "private-purpose",
      digest: "b".repeat(64),
    },
    request: {
      received: true,
      kind: "pre-protocol",
      amount: { currency: "USD", value: "100" },
      invoiceReference: "private-invoice",
      digest: "c".repeat(64),
    },
    anchors: [
      { actor: "Payer", kind: "PROPOSED", sequence: 1, stage: "proposal", verified: true, block: "101", digest: "d".repeat(64) },
      { actor: "Requestor", kind: "ACCEPTED", sequence: 2, stage: "acceptance", verified: true, block: "102", digest: "e".repeat(64) },
      { actor: "Payer", kind: "ACKNOWLEDGED", sequence: 3, stage: "acknowledgment", verified: true, block: "103", digest: "f".repeat(64) },
    ],
    deadline: {
      expiresAtMs: "1785297600000",
      freshness: "FRESH",
      nowMs: 1785294300000,
    },
    failure: null,
    phase: { advisory: true, value: "STAKEHOLDER_RUNNING" },
    verifier: {
      advisory: false,
      publicationDigest: "9".repeat(64),
      status: "VERIFICATION_PASSED",
    },
  };
}

test("builds one exact secret-free public monitor snapshot", () => {
  const value = buildPublicMonitorSnapshot(projection(), {
    observedAt: "2026-07-30T19:55:00.000Z",
    payerMcpReady: true,
  });

  assert.deepEqual(value, {
    schema: "clockchain.public-handshake-monitor/v1",
    observedAt: "2026-07-30T19:55:00.000Z",
    staleAfterMs: 10_000,
    status: "VERIFIED",
    paymentMoved: false,
    actors: {
      operator: "READY",
      payer: "READY",
      requestor: "WAITING",
    },
    services: {
      payerMcp: "READY",
      watcher: "READY",
    },
    markers: {
      payerMandateReady: true,
      paymentRequestReady: true,
      paymentRequestMatched: true,
    },
    anchors: [
      { actor: "Payer", state: "PROPOSED", verified: true, block: "101" },
      { actor: "Requestor", state: "ACCEPTED", verified: true, block: "102" },
      { actor: "Payer", state: "ACKNOWLEDGED", verified: true, block: "103" },
    ],
    verifier: { status: "VERIFICATION_PASSED" },
  });

  const serialized = JSON.stringify(value);
  for (const forbidden of [
    "private-release",
    "private-purpose",
    "private-invoice",
    "11111111-2222-4333-8444-555555555555",
    "bbbbbbbb",
    "cccccccc",
    "dddddddd",
  ]) {
    assert.doesNotMatch(serialized, new RegExp(forbidden));
  }
});

test("rejects malformed, moved-payment, and mismatched anchor input", () => {
  const cases = [
    { ...projection(), paymentMoved: true },
    { ...projection(), schema: "wrong" },
    { ...projection(), anchors: projection().anchors.slice(0, 2) },
    { ...projection(), anchors: projection().anchors.map((item, index) => index === 1 ? { ...item, kind: "ACKNOWLEDGED" } : item) },
    { ...projection(), actors: { ...projection().actors, payer: { health: "UNKNOWN" } } },
    { ...projection(), verifier: { status: "AUTHORIZED" } },
    { ...projection(), unexpectedTopLevel: "secret" },
    { ...projection(), mandate: { ...projection().mandate, secret: "secret" } },
    {
      ...projection(),
      session: {
        ...projection().session,
        observations: {
          ...projection().session.observations,
          watcher: {
            ...projection().session.observations.watcher,
            extra: "secret",
          },
        },
      },
    },
  ];

  for (const value of cases) {
    assert.throws(
      () => buildPublicMonitorSnapshot(value, {
        observedAt: "2026-07-30T19:55:00.000Z",
        payerMcpReady: false,
      }),
      /Public monitor projection failed safely/,
    );
  }
});

test("publisher defaults to the reviewed public bucket and loopback services", () => {
  assert.deepEqual(parsePublicMonitorArguments([]), {
    bucket: "clockchain-handshake-monitor-570035913370-us-west-2",
    consoleUrl: "http://127.0.0.1:8787/v1/console/session",
    intervalMs: 2_000,
    payerMcpHost: "127.0.0.1",
    payerMcpPort: 9_443,
    region: "us-west-2",
  });
  assert.throws(
    () => parsePublicMonitorArguments(["--console-url", "https://example.com"]),
    /Public monitor arguments failed safely/,
  );
});

test("publishes a fresh safe waiting snapshot before the private console starts", () => {
  assert.deepEqual(
    buildUnavailablePublicMonitorSnapshot({
      observedAt: "2026-07-30T20:00:00.000Z",
      payerMcpReady: false,
    }),
    {
      schema: "clockchain.public-handshake-monitor/v1",
      observedAt: "2026-07-30T20:00:00.000Z",
      staleAfterMs: 10_000,
      status: "WAITING_FOR_PARTICIPANTS",
      paymentMoved: false,
      actors: {
        operator: "UNAVAILABLE",
        payer: "UNAVAILABLE",
        requestor: "UNAVAILABLE",
      },
      services: {
        payerMcp: "UNAVAILABLE",
        watcher: "UNAVAILABLE",
      },
      markers: {
        payerMandateReady: false,
        paymentRequestReady: false,
        paymentRequestMatched: false,
      },
      anchors: [
        { actor: "Payer", state: "PROPOSED", verified: false, block: null },
        { actor: "Requestor", state: "ACCEPTED", verified: false, block: null },
        { actor: "Payer", state: "ACKNOWLEDGED", verified: false, block: null },
      ],
      verifier: { status: "PENDING" },
    },
  );
});
