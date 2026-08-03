import assert from "node:assert/strict";
import test from "node:test";

import { RELAY_KINDS } from "../src/roles/catalog.mjs";
import {
  MONITOR_MESSAGE_MAP,
  MONITOR_PHASES,
  buildMonitorSnapshot,
  derivePhase,
} from "../src/monitor/snapshot.mjs";
import { renderStakeholderPage } from "../src/monitor/stakeholder/render.mjs";
import { renderControlPlanePage } from "../src/monitor/control-plane/render.mjs";

const FINAL_VERDICT_WORD = "AUTHOR" + "IZED";

function fakeRelay({ messages = [], roles = {}, verdict = null, evidence = {} }) {
  return {
    getSnapshot: async (sessionId) => ({
      discoveryPublished: true,
      paymentMoved: false,
      roles,
      sessionId,
      subjectRun: "stakeholder",
      verdict,
    }),
    pollMessages: async () => ({
      messages: messages.map((envelope, index) => ({
        envelope,
        seq: index + 1,
      })),
    }),
    getEvidence: async (_sessionId, role) => {
      if (evidence[role] === true) return { json: "{}", markdown: "m", marker: "k" };
      const error = new Error("missing");
      error.code = "UNKNOWN_EVIDENCE";
      throw error;
    },
  };
}

function verdictDocument(outcome) {
  return {
    schema: "handshake-verdict/v2",
    signature: { algorithm: "ed25519", keyId: "k", publicKey: "p", value: "v" },
    verdict: {
      mandateDigest: "m".padEnd(64, "1"),
      outcome,
      paymentMoved: false,
      requestDigest: "r".padEnd(64, "2"),
      schema: "clockchain.bilateral-authorization-verdict/v2",
      sessionDigest: "s".padEnd(64, "3"),
      transitions: [
        { anchoredHash: "a".repeat(64), blockHeight: "100", kind: "proposal", ledgerId: "l1" },
        { anchoredHash: "b".repeat(64), blockHeight: "101", kind: "acceptance", ledgerId: "l2" },
        { anchoredHash: "c".repeat(64), blockHeight: "102", kind: "acknowledgment", ledgerId: "l3" },
      ],
    },
  };
}

test("monitor message map covers every relay kind exactly once", () => {
  const catalogKinds = Object.values(RELAY_KINDS).sort();
  const mappedKinds = Object.keys(MONITOR_MESSAGE_MAP).sort();
  assert.deepEqual(mappedKinds, catalogKinds);
  for (const [kind, mapped] of Object.entries(MONITOR_MESSAGE_MAP)) {
    assert.equal(typeof mapped.label, "string");
    assert.ok(MONITOR_PHASES.includes(mapped.phase), kind);
  }
});

test("phase derivation walks the ordered phases", async () => {
  assert.equal(derivePhase({ messages: [], verdict: null }), "opened");
  const descriptorSnapshot = await buildMonitorSnapshot({
    relay: fakeRelay({
      messages: [
        { kind: RELAY_KINDS.IDENTITY_ANNOUNCE, role: "payee" },
        { kind: RELAY_KINDS.MANDATE_PUBLISHED, role: "payer" },
        { kind: RELAY_KINDS.DESCRIPTOR_PUBLISHED, role: "operator" },
      ],
    }),
    sessionId: "s",
  });
  assert.equal(descriptorSnapshot.phase, "descriptor");
  const anchoredSnapshot = await buildMonitorSnapshot({
    relay: fakeRelay({
      evidence: { payer: true, payee: true },
      messages: [
        { kind: RELAY_KINDS.DESCRIPTOR_PUBLISHED, role: "operator" },
      ],
    }),
    sessionId: "s",
  });
  assert.equal(anchoredSnapshot.phase, "anchored");
  const verifiedSnapshot = await buildMonitorSnapshot({
    relay: fakeRelay({ verdict: verdictDocument("X") }),
    sessionId: "s",
  });
  assert.equal(verifiedSnapshot.phase, "verified");
});

test("pre-verdict renders never contain the final-verdict word", async () => {
  const snapshot = await buildMonitorSnapshot({
    relay: fakeRelay({
      evidence: { payer: true, payee: true },
      messages: [
        { kind: RELAY_KINDS.IDENTITY_ANNOUNCE, role: "payee" },
        { kind: RELAY_KINDS.FUNDING_CONFIRMED, role: "operator" },
        { kind: RELAY_KINDS.MANDATE_PUBLISHED, role: "payer" },
        { kind: RELAY_KINDS.PAYMENT_REQUEST_SIGNED, role: "payee" },
        { kind: RELAY_KINDS.DESCRIPTOR_PUBLISHED, role: "operator" },
      ],
      roles: {
        payer: { phase: "PAYER_ANCHORING", state: "ACCEPTED" },
      },
    }),
    sessionId: "pre-verdict-session",
  });
  assert.equal(snapshot.verdict, null);
  const word = new RegExp(`\\b${FINAL_VERDICT_WORD}\\b`);
  assert.equal(word.test(renderStakeholderPage(snapshot)), false);
  assert.equal(word.test(renderControlPlanePage(snapshot)), false);
});

test("post-verdict renders show the verdict and all three anchors", async () => {
  const snapshot = await buildMonitorSnapshot({
    relay: fakeRelay({
      evidence: { payer: true, payee: true },
      verdict: verdictDocument(FINAL_VERDICT_WORD),
    }),
    sessionId: "post-verdict-session",
  });
  assert.equal(snapshot.phase, "verified");
  const stakeholder = renderStakeholderPage(snapshot);
  assert.match(stakeholder, new RegExp(FINAL_VERDICT_WORD));
  assert.match(stakeholder, /PROPOSED/);
  assert.match(stakeholder, /ACCEPTED/);
  assert.match(stakeholder, /ACKNOWLEDGED/);
  assert.match(stakeholder, /"no"|>no</);
  const control = renderControlPlanePage(snapshot);
  assert.match(control, new RegExp(FINAL_VERDICT_WORD));
  assert.match(control, /sessionDigest/);
});

test("renderers escape hostile session fields", async () => {
  const hostile = `<script>alert("x")</script>`;
  const snapshot = await buildMonitorSnapshot({
    relay: fakeRelay({}),
    sessionId: hostile,
  });
  assert.equal(renderStakeholderPage(snapshot).includes(hostile), false);
  assert.equal(renderControlPlanePage(snapshot).includes(hostile), false);
});
