import assert from "node:assert/strict";
import { test } from "node:test";

import {
  approveAndSealAwsBootstrapClaim,
} from "../infra/aws/runtime/operator-bootstrap-runtime.mjs";

const INPUT = Object.freeze({
  claimFingerprint: "a".repeat(64),
  paymentMoved: false,
  releaseId: "release-bd7662a5eeb41614",
  repositorySha:
    "abcdef0123456789abcdef0123456789abcdef01",
  role: "payer",
  sessionId:
    "11111111-1111-4111-8111-111111111111",
});

function state(status, revision) {
  return {
    claims: {
      [INPUT.claimFingerprint]: {
        claim: { paymentMoved: false },
        claimFingerprint:
          INPUT.claimFingerprint,
        expiresAtMs: "2000000600000",
        paymentMoved: false,
        releaseId: INPUT.releaseId,
        role: INPUT.role,
        sessionId: INPUT.sessionId,
        status,
      },
    },
    paymentMoved: false,
    releaseId: INPUT.releaseId,
    repositorySha:
      INPUT.repositorySha,
    revision,
    sessionId: INPUT.sessionId,
  };
}

test("approves, persists the exact Payer grant, and seals one bootstrap response in order", async () => {
  const calls = [];
  let current = state("PENDING", "0");
  const result =
    await approveAndSealAwsBootstrapClaim(
      INPUT,
      {
        buildSealedResponse: async () => {
          calls.push("build");
          return {
            response: {
              paymentMoved: false,
            },
            tunnelGrant: {
              paymentMoved: false,
            },
          };
        },
        openBootstrap: async () => ({
          async approveClaim() {
            calls.push("approve");
            current = state(
              "APPROVED",
              "1",
            );
            return current;
          },
          async readState() {
            return current;
          },
          async sealClaim() {
            calls.push("seal");
            current = state("SEALED", "2");
            return current;
          },
        }),
        persistTunnelGrant: async () => {
          calls.push("grant");
        },
        publishApprovedPayer: async ({
          claim,
          claimFingerprint,
          expiresAtMs,
        }) => {
          assert.deepEqual(claim, { paymentMoved: false });
          assert.equal(claimFingerprint, INPUT.claimFingerprint);
          assert.equal(expiresAtMs, "2000000600000");
          calls.push("public");
        },
      },
    );
  assert.deepEqual(result, {
    paymentMoved: false,
    status: "APPROVED",
  });
  assert.deepEqual(calls, [
    "approve",
    "build",
    "grant",
    "seal",
    "public",
  ]);
});

test("adopts a previously sealed claim without resealing or replacing its grant", async () => {
  let built = 0;
  const result =
    await approveAndSealAwsBootstrapClaim(
      INPUT,
      {
        assertTunnelGrant: async () => {},
        buildSealedResponse: async () => {
          built += 1;
        },
        openBootstrap: async () => ({
          async approveClaim() {},
          async readState() {
            return state("SEALED", "2");
          },
          async sealClaim() {},
        }),
        persistTunnelGrant: async () => {},
      },
    );
  assert.equal(built, 0);
  assert.equal(result.status, "APPROVED");
});

test("fails closed for a mismatched claim, role, run, or payment state", async () => {
  for (const overrides of [
    { claimFingerprint: "b".repeat(64) },
    { paymentMoved: true },
    { role: "operator" },
    {
      sessionId:
        "22222222-2222-4222-8222-222222222222",
    },
  ]) {
    await assert.rejects(
      approveAndSealAwsBootstrapClaim(
        { ...INPUT, ...overrides },
        {
          buildSealedResponse: async () => {},
          openBootstrap: async () => ({
            async readState() {
              return state("PENDING", "0");
            },
          }),
          persistTunnelGrant: async () => {},
        },
      ),
      /AWS operator bootstrap failed safely/,
    );
  }
});
