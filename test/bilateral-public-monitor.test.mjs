import assert from "node:assert/strict";
import test from "node:test";
import { buildPublicMonitorSnapshot } from "../src/bilateral/coordination/public-monitor.mjs";
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
      amount: { currency: "USD", value: "100" },
      purpose: "private-purpose",
      digest: "b".repeat(64),
    },
    request: {
      received: true,
      amount: { currency: "USD", value: "100" },
      invoiceReference: "private-invoice",
      digest: "c".repeat(64),
    },
    anchors: [
      { actor: "Payer", kind: "PROPOSED", verified: true, block: "101", digest: "d".repeat(64) },
      { actor: "Requestor", kind: "ACCEPTED", verified: true, block: "102", digest: "e".repeat(64) },
      { actor: "Payer", kind: "ACKNOWLEDGED", verified: true, block: "103", digest: "f".repeat(64) },
    ],
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
