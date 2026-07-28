import assert from "node:assert/strict";
import test from "node:test";

import { buildConsoleProjection } from "../src/bilateral/coordination/console-projection.mjs";

const digest = (value) => value.repeat(64);
const base = () => ({
  lifecycleView: { releaseId: "release-a", repositorySha: "a".repeat(40), sessionId: "11111111-2222-4333-8444-555555555555", state: "STAKEHOLDER_RUNNING", facts: { payerMandateReady: { stakeholder: true }, paymentRequestReady: { stakeholder: true }, paymentRequestMatched: { stakeholder: true } }, token: "console-canary", invitations: { secret: "console-canary" } },
  mandate: { mandate: { amount: { currency: "USD", value: "100" }, expiresAtMs: "1785297600000", purpose: "freight-services", paymentMoved: false }, mandateDigest: digest("e"), privatePath: "console-canary" },
  request: { request: { amount: { currency: "USD", value: "100" }, expiresAtMs: "1785297000000", invoiceReference: "TREL-2026-0001", paymentMoved: false }, requestDigest: digest("f"), tls: "console-canary" },
  nowMs: 1785294300000,
  watcherSnapshot: { health: "ok", environment: "console-canary", anchors: [
    { digest: digest("1"), kind: "PROPOSED", block: "10", verified: true },
    { digest: digest("2"), kind: "ACCEPTED", block: "11", verified: true },
    { digest: digest("3"), kind: "ACKNOWLEDGED", block: "12", verified: true },
  ] },
  verifierPublication: { markerComplete: true, paymentMoved: false, publicationDigest: digest("a"), releaseId: "release-a", repositorySha: "a".repeat(40), sessionId: "11111111-2222-4333-8444-555555555555", descriptorDigest: digest("d"), mandateDigest: digest("e"), requestDigest: digest("f"), packageDigests: { payer: digest("b"), payee: digest("c") }, anchorDigests: [digest("1"), digest("2"), digest("3")] },
});

test("projection is closed, redacted, ordered, and labels pre-protocol evidence", () => {
  const value = buildConsoleProjection(base());
  assert.deepEqual(Object.keys(value), ["actors", "anchors", "deadline", "failure", "mandate", "paymentMoved", "phase", "request", "schema", "session", "verifier"]);
  assert.equal(JSON.stringify(value).includes("console-canary"), false);
  assert.equal(value.paymentMoved, false);
  assert.equal(value.mandate.kind, "pre-protocol");
  assert.equal(value.request.kind, "pre-protocol");
  assert.deepEqual(value.anchors.map((anchor) => anchor.kind), ["PROPOSED", "ACCEPTED", "ACKNOWLEDGED"]);
  assert.equal(value.verifier.status, "AUTH" + "ORIZED");
});

test("projection fails closed and never emits authorization from advisory or mismatched evidence", () => {
  for (const mutate of [
    (input) => { input.watcherSnapshot.anchors[1].kind = "ACKNOWLEDGED"; },
    (input) => { input.verifierPublication.anchorDigests[1] = digest("x"); },
    (input) => { input.verifierPublication.markerComplete = false; },
    (input) => { input.verifierPublication.paymentMoved = true; },
  ]) {
    const input = base(); mutate(input);
    const value = buildConsoleProjection(input);
    assert.notEqual(value.verifier.status, "AUTH" + "ORIZED");
  }
});
