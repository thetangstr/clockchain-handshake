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
    { cardinality: "1", digest: digest("1"), kind: "PROPOSED", block: "10", ledgerId: "00000000-0000-4000-8000-000000000001", verified: true },
    { cardinality: "1", digest: digest("2"), kind: "ACCEPTED", block: "11", ledgerId: "00000000-0000-4000-8000-000000000002", verified: true },
    { cardinality: "1", digest: digest("3"), kind: "ACKNOWLEDGED", block: "12", ledgerId: "00000000-0000-4000-8000-000000000003", verified: true },
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
  assert.deepEqual(
    value.anchors.map(({ cardinality, ledgerId, verified }) => ({ cardinality, ledgerId, verified })),
    [
      { cardinality: "1", ledgerId: "00000000-0000-4000-8000-000000000001", verified: true },
      { cardinality: "1", ledgerId: "00000000-0000-4000-8000-000000000002", verified: true },
      { cardinality: "1", ledgerId: "00000000-0000-4000-8000-000000000003", verified: true },
    ],
  );
  assert.equal(value.verifier.status, "VERIFICATION_PASSED");
  assert.equal(JSON.stringify(value).includes("AUTHORIZED"), false);
});

test("projection reads rehearsal facts for rehearsal publications", () => {
  const input = base();
  input.lifecycleView.state = "REHEARSAL_RUNNING";
  input.lifecycleView.facts.payerMandateReady = { rehearsal: true, stakeholder: false };
  input.lifecycleView.facts.paymentRequestReady = { rehearsal: true, stakeholder: false };
  input.lifecycleView.facts.paymentRequestMatched = { rehearsal: true, stakeholder: false };
  input.verifierPublication.subjectRun = "rehearsal";

  const value = buildConsoleProjection(input);

  assert.equal(value.request.received, true);
  assert.equal(value.mandate.received, true);
  assert.equal(value.mandate.matched, true);
  assert.equal(value.verifier.status, "VERIFICATION_PASSED");
});

test("projection reads stakeholder facts for stakeholder publications", () => {
  const input = base();
  input.lifecycleView.facts.payerMandateReady = { rehearsal: false, stakeholder: true };
  input.lifecycleView.facts.paymentRequestReady = { rehearsal: false, stakeholder: true };
  input.lifecycleView.facts.paymentRequestMatched = { rehearsal: false, stakeholder: true };

  const value = buildConsoleProjection(input);

  assert.equal(value.request.received, true);
  assert.equal(value.mandate.received, true);
  assert.equal(value.mandate.matched, true);
  assert.equal(value.verifier.status, "VERIFICATION_PASSED");
});

test("projection fails closed when active lifecycle run and verifier publication disagree", () => {
  const input = base();
  input.lifecycleView.state = "REHEARSAL_RUNNING";
  input.lifecycleView.facts.payerMandateReady = { rehearsal: true, stakeholder: true };
  input.lifecycleView.facts.paymentRequestReady = { rehearsal: true, stakeholder: true };
  input.lifecycleView.facts.paymentRequestMatched = { rehearsal: true, stakeholder: true };
  input.verifierPublication.subjectRun = "stakeholder";

  const value = buildConsoleProjection(input);

  assert.equal(value.verifier.status, "PENDING");
  assert.equal(value.verifier.publicationDigest, null);
  assert.equal(JSON.stringify(value.verifier).includes("AUTH" + "ORIZED"), false);
});

test("projection fails closed for unknown phase without emitting an auth literal", () => {
  const input = base();
  input.lifecycleView.state = "console-canary";

  const value = buildConsoleProjection(input);

  assert.equal(value.phase.value, "UNAVAILABLE");
  assert.equal(value.request.received, false);
  assert.equal(value.mandate.received, false);
  assert.equal(value.mandate.matched, false);
  assert.equal(value.verifier.status, "PENDING");
  assert.equal(JSON.stringify(value).includes("AUTH" + "ORIZED"), false);
});

test("projection conveys structured console status without widening top-level keys", () => {
  const input = base();
  input.lifecycleView.health = {
    schema: "clockchain.bilateral-console-health/v1",
    observedAtMs: "1785294299000",
    expiresAtMs: "1785297600000",
    actors: {
      operator: "READY",
      payer: "READY",
      payee: "READY",
    },
    services: {
      relay: "READY",
      watcher: "READY",
    },
  };
  input.lifecycleView.failure = {
    active: true,
    code: "RECOVERY_REQUIRED",
    run: "stakeholder",
    message: "console-canary",
  };

  const value = buildConsoleProjection(input);

  assert.deepEqual(Object.keys(value), ["actors", "anchors", "deadline", "failure", "mandate", "paymentMoved", "phase", "request", "schema", "session", "verifier"]);
  assert.deepEqual(value.actors.operator, {
    health: "READY",
    label: "Operator",
    role: "operator",
  });
  assert.deepEqual(value.actors.payer, {
    health: "READY",
    label: "Payer",
    role: "payer",
  });
  assert.deepEqual(value.actors.payee, {
    health: "READY",
    label: "Requestor",
    role: "payee",
  });
  assert.equal(value.request.received, true);
  assert.equal(value.mandate.received, true);
  assert.equal(value.mandate.matched, true);
  assert.deepEqual(
    value.anchors.map(({ actor, kind, sequence, stage }) => ({
      actor,
      kind,
      sequence,
      stage,
    })),
    [
      { actor: "Payer", kind: "PROPOSED", sequence: 1, stage: "proposal" },
      { actor: "Requestor", kind: "ACCEPTED", sequence: 2, stage: "acceptance" },
      { actor: "Payer", kind: "ACKNOWLEDGED", sequence: 3, stage: "acknowledgment" },
    ],
  );
  assert.equal(value.deadline.freshness, "FRESH");
  assert.deepEqual(value.failure, {
    active: true,
    code: "RECOVERY_REQUIRED",
    recovery: {
      label: "operator recovery required",
      visible: true,
    },
    run: "stakeholder",
  });
  assert.deepEqual(value.session.observations, {
    relay: { advisory: true, health: "READY", label: "relay advisory" },
    watcher: { advisory: true, health: "READY", label: "watcher advisory" },
  });
  assert.equal(value.verifier.advisory, false);
  assert.equal(value.verifier.status, "VERIFICATION_PASSED");
  assert.equal(JSON.stringify(value).includes("console-canary"), false);
});

test("projection does not fabricate ready health from intents, phase, or anchors", () => {
  const value = buildConsoleProjection(base());

  assert.equal(value.actors.operator.health, "UNAVAILABLE");
  assert.equal(value.actors.payer.health, "UNAVAILABLE");
  assert.equal(value.actors.payee.health, "UNAVAILABLE");
  assert.equal(value.session.observations.relay.health, "UNAVAILABLE");
  assert.equal(value.session.observations.watcher.health, "UNAVAILABLE");
});

test("projection accepts only exact fresh closed health input", () => {
  for (const mutate of [
    (input) => { input.lifecycleView.health.observedAtMs = "1785294299000 "; },
    (input) => { input.lifecycleView.health.expiresAtMs = "1e999"; },
    (input) => { input.lifecycleView.health.expiresAtMs = "1785294300000"; },
    (input) => { input.lifecycleView.health.actors.payer = "ok"; },
    (input) => { input.lifecycleView.health.services.watcher = "console-canary"; },
    (input) => { input.lifecycleView.health.extra = "console-canary"; },
    (input) => { input.lifecycleView.health.actors.extra = "console-canary"; },
    (input) => { delete input.lifecycleView.health.services; },
  ]) {
    const input = base();
    input.lifecycleView.health = {
      schema: "clockchain.bilateral-console-health/v1",
      observedAtMs: "1785294299000",
      expiresAtMs: "1785297600000",
      actors: {
        operator: "READY",
        payer: "READY",
        payee: "READY",
      },
      services: {
        relay: "READY",
        watcher: "READY",
      },
    };
    mutate(input);
    const value = buildConsoleProjection(input);
    assert.notEqual(value.actors.operator.health, "READY");
    assert.notEqual(value.actors.payer.health, "READY");
    assert.notEqual(value.actors.payee.health, "READY");
    assert.notEqual(value.session.observations.relay.health, "READY");
    assert.notEqual(value.session.observations.watcher.health, "READY");
    assert.equal(JSON.stringify(value).includes("console-canary"), false);
  }
});

test("projection fails closed and never emits the authorizing literal from advisory or mismatched evidence", () => {
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
    assert.equal(value.verifier.status, "PENDING");
    assert.equal(JSON.stringify(value).includes("AUTHORIZED"), false);
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
  const value = buildConsoleProjection(input); assert.deepEqual(value.failure, { active: true, code: "RECOVERY_REQUIRED", recovery: { label: "operator recovery required", visible: true }, run: "stakeholder" }); assert.equal(JSON.stringify(value).includes("console-canary"), false);
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

test("projection requires canonical string anchor blocks before authorization", () => {
  for (const [label, block] of [
    ["number", 10],
    ["exponent", "1e3"],
    ["object", { value: "10" }],
    ["unsafe", String(BigInt(Number.MAX_SAFE_INTEGER) + 1n)],
    ["leading zero", "010"],
  ]) {
    const input = base();
    input.watcherSnapshot.anchors[0].block = block;
    const value = buildConsoleProjection(input);
    assert.equal(value.verifier.status, "PENDING", label);
  }
});

test("projection requires bounded decimal expiration timestamps", () => {
  for (const [label, expiresAtMs] of [
    ["infinity exponent", "1e999"],
    ["signed", "+1785297600000"],
    ["negative", "-1785297600000"],
    ["whitespace", "1785297600000 "],
    ["decimal", "1785297600000.1"],
    ["empty", ""],
    ["overlarge", String(BigInt(Number.MAX_SAFE_INTEGER) + 1n)],
    ["too long", "1".repeat(17)],
    ["malformed", "not-a-time"],
    ["expired", "1785294300000"],
  ]) {
    const input = base();
    input.mandate.mandate.expiresAtMs = expiresAtMs;
    input.request.request.expiresAtMs = expiresAtMs;
    const value = buildConsoleProjection(input);
    assert.equal(value.verifier.status, "PENDING", label);
  }
});
