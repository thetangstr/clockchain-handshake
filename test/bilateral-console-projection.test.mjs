import assert from "node:assert/strict";
import test from "node:test";

import { buildConsoleProjection } from "../src/bilateral/coordination/console-projection.mjs";
import { RELEASE_STATES } from "../src/bilateral/coordination/lifecycle.mjs";

const digest = (value) => value.repeat(64);
const base = () => ({
  lifecycleView: { releaseId: "release-a", repositorySha: "a".repeat(40), sessionId: "11111111-2222-4333-8444-555555555555", state: "STAKEHOLDER_RUNNING", facts: { payerMandateReady: { stakeholder: true }, paymentRequestReady: { stakeholder: true }, paymentRequestMatched: { stakeholder: true } }, token: "console-canary", invitations: { secret: "console-canary" } },
  mandate: { mandate: { amount: { currency: "USD", value: "100" }, expiresAtMs: "1785297600000", purpose: "freight-services", paymentMoved: false }, mandateDigest: digest("e"), privatePath: "console-canary" },
  request: { request: { amount: { currency: "USD", value: "100" }, expiresAtMs: "1785297000000", invoiceReference: "TREL-2026-0001", paymentMoved: false }, requestDigest: digest("f"), tls: "console-canary" },
  nowMs: 1785294300000,
  watcherSnapshot: { descriptorDigest: digest("d"), packageDigests: { payer: digest("b"), payee: digest("c") }, health: "ok", environment: "console-canary", anchors: [
    { digest: digest("1"), kind: "PROPOSED", block: "10", verified: true },
    { digest: digest("2"), kind: "ACCEPTED", block: "11", verified: true },
    { digest: digest("3"), kind: "ACKNOWLEDGED", block: "12", verified: true },
  ] },
  verifierPublication: { markerComplete: true, paymentMoved: false, publicationDigest: digest("a"), releaseId: "release-a", repositorySha: "a".repeat(40), schema: "clockchain.bilateral-verifier-publication/v1", sessionId: "11111111-2222-4333-8444-555555555555", status: "VERIFICATION_PASSED", subjectRun: "stakeholder", descriptorDigest: digest("d"), mandateDigest: digest("e"), requestDigest: digest("f"), packageDigests: { payer: digest("b"), payee: digest("c") }, anchorDigests: [digest("1"), digest("2"), digest("3")] },
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
    (input) => { input.lifecycleView.releaseId = null; },
    (input) => { input.lifecycleView.repositorySha = null; },
    (input) => { input.lifecycleView.sessionId = null; },
    (input) => { input.lifecycleView.sessionId = "not-a-uuid"; },
    (input) => { input.mandate.mandate.paymentMoved = true; },
    (input) => { input.request.request.paymentMoved = true; },
    (input) => { input.verifierPublication.schema = "clockchain.bilateral-verifier-publication/v2"; },
    (input) => { input.verifierPublication.status = "PENDING"; },
    (input) => { delete input.verifierPublication.schema; },
    (input) => { delete input.verifierPublication.status; },
    (input) => { input.watcherSnapshot.anchors[1].kind = "ACKNOWLEDGED"; },
    (input) => { input.verifierPublication.anchorDigests[1] = digest("x"); },
    (input) => { input.verifierPublication.markerComplete = false; },
    (input) => { input.verifierPublication.paymentMoved = true; },
    (input) => { input.watcherSnapshot.descriptorDigest = digest("9"); },
    (input) => { input.watcherSnapshot.packageDigests.payer = digest("9"); },
    (input) => { input.watcherSnapshot.packageDigests.payee = digest("9"); },
    (input) => { input.nowMs = 1785298000000; },
    (input) => { input.watcherSnapshot.anchors.push({ digest: digest("4"), kind: "ACKNOWLEDGED", block: "13", verified: true }); },
    (input) => { input.watcherSnapshot.anchors[1].block = "10"; },
  ]) {
    const input = base(); mutate(input);
    const value = buildConsoleProjection(input);
    assert.notEqual(value.verifier.status, "AUTH" + "ORIZED");
  }
});

test("projection supports every real lifecycle state and rejects unknown canaries", () => {
  for (const state of RELEASE_STATES) {
    const input = base();
    input.lifecycleView.state = state;
    assert.equal(buildConsoleProjection(input).phase.value, state);
  }
  const input = base();
  input.lifecycleView.state = "console-canary";
  assert.equal(buildConsoleProjection(input).phase.value, "UNAVAILABLE");
});

test("projection exposes only closed failure summary", () => {
  const input = base(); input.lifecycleView.failure = { active: true, code: "RECOVERY_REQUIRED", run: "stakeholder", cause: { path: "console-canary" }, message: "console-canary" };
  const value = buildConsoleProjection(input); assert.deepEqual(value.failure, { active: true, code: "RECOVERY_REQUIRED", run: "stakeholder" }); assert.equal(JSON.stringify(value).includes("console-canary"), false);
});

test("projection allowlists phase and failure values instead of direct lifecycle strings", () => {
  const input = base();
  input.lifecycleView.state = "console-canary";
  input.lifecycleView.failure = { active: true, code: "console-canary", run: "console-canary" };
  const value = buildConsoleProjection(input);
  assert.equal(JSON.stringify(value).includes("console-canary"), false);
  assert.deepEqual(value.phase, { advisory: true, value: "UNAVAILABLE" });
  assert.equal(value.failure, null);
});

test("projection requires three distinct anchor digests", () => {
  const input = base();
  input.watcherSnapshot.anchors[1].digest = input.watcherSnapshot.anchors[0].digest;
  input.verifierPublication.anchorDigests[1] = input.watcherSnapshot.anchors[0].digest;
  const value = buildConsoleProjection(input);
  assert.deepEqual(value.anchors.map((anchor) => anchor.digest), [digest("1"), digest("1"), digest("3")]);
  assert.equal(value.verifier.status, "PENDING");
});
