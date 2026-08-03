import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";

import {
  createReceiptEmailHandler,
  renderVerifiedReceiptEmail,
} from "../src/bilateral/aws/receipt-email.mjs";

const ALLOWED_ORIGIN =
  "https://clockchain-research.vercel.app";
const FROM_EMAIL = "receipts@clockchain.network";
const RUN_ID = "run-0123456789abcdef";

function digest(value) {
  return createHash("sha256")
    .update(value, "utf8")
    .digest("hex");
}

function verifiedSummary(overrides = {}) {
  return {
    anchors: [
      {
        block: "101",
        cardinality: "1",
        explorerUrl:
          "https://sepolia.etherscan.io/block/101",
        kind: "PROPOSED",
        ledgerId:
          "b5b34a59-4e10-482e-bb1a-e1b2b7374c20",
        signerRole: "Payer",
        verified: true,
      },
      {
        block: "102",
        cardinality: "1",
        explorerUrl:
          "https://sepolia.etherscan.io/block/102",
        kind: "ACCEPTED",
        ledgerId:
          "00000000-0000-4000-8000-000000000002",
        signerRole: "Requestor",
        verified: true,
      },
      {
        block: "103",
        cardinality: "1",
        explorerUrl:
          "https://sepolia.etherscan.io/block/103",
        kind: "ACKNOWLEDGED",
        ledgerId:
          "00000000-0000-4000-8000-000000000003",
        signerRole: "Payer",
        verified: true,
      },
    ],
    businessResult:
      "The Requestor followed the Payer mandate and all three Clockchain anchors were independently verified.",
    completedAtMs: "2000000000500",
    paymentMoved: false,
    runId: RUN_ID,
    runStatus: "VERIFIED",
    schema: "clockchain.aws-public-run-summary/v2",
    summaryUrl:
      `https://monitor.example/runs/${RUN_ID}.json`,
    ...overrides,
  };
}

function event(overrides = {}) {
  return {
    body: JSON.stringify({
      email: "Stakeholder@Example.com",
      runId: RUN_ID,
    }),
    headers: {
      "content-type": "application/json",
      origin: ALLOWED_ORIGIN,
    },
    httpMethod: "POST",
    path: "/receipt-email",
    ...overrides,
  };
}

function fixture(overrides = {}) {
  const calls = {
    claims: [],
    completed: [],
    failed: [],
    messages: [],
  };
  const handler = createReceiptEmailHandler({
    allowedOrigin: ALLOWED_ORIGIN,
    claimDelivery: async (value) => {
      calls.claims.push(value);
      return "CLAIMED";
    },
    completeDelivery: async (value) => {
      calls.completed.push(value);
    },
    failDelivery: async (value) => {
      calls.failed.push(value);
    },
    fromEmail: FROM_EMAIL,
    readSummary: async () => verifiedSummary(),
    sendEmail: async (message) => {
      calls.messages.push(message);
    },
    ...overrides,
  });
  return { calls, handler };
}

test("sends one verifier-confirmed HTML and text receipt", async () => {
  const { calls, handler } = fixture();
  const response = await handler(event());

  assert.deepEqual(response, {
    body: JSON.stringify({
      paymentMoved: false,
      status: "RECEIPT_EMAIL_ACCEPTED",
    }),
    headers: {
      "access-control-allow-origin": ALLOWED_ORIGIN,
      "content-type": "application/json",
    },
    statusCode: 202,
  });
  assert.equal(calls.messages.length, 1);
  assert.equal(
    calls.messages[0].toEmail,
    "stakeholder@example.com",
  );
  assert.match(
    calls.messages[0].html,
    /Clockchain Handshake Receipt/,
  );
  assert.match(
    calls.messages[0].html,
    /b5b34a59-4e10-482e-bb1a-e1b2b7374c20/,
  );
  assert.doesNotMatch(
    calls.messages[0].html,
    /AUTHORIZED/,
  );
  assert.match(
    calls.messages[0].text,
    /No represented payment moved/,
  );
  assert.deepEqual(calls.claims, [
    {
      deliveryId: digest(
        `${RUN_ID}\0stakeholder@example.com`,
      ),
      recipientDigest: digest(
        "stakeholder@example.com",
      ),
      runId: RUN_ID,
    },
  ]);
  assert.deepEqual(calls.completed, [
    { deliveryId: calls.claims[0].deliveryId },
  ]);
  assert.equal(
    JSON.stringify([
      calls.claims,
      calls.completed,
      calls.failed,
    ]).includes("stakeholder@example.com"),
    false,
  );
});

test("rejects malformed and cross-origin requests without dependencies", async () => {
  const invalid = [
    event({ httpMethod: "GET" }),
    event({ path: "/other" }),
    event({ headers: { ...event().headers, origin: "https://evil.example" } }),
    event({ headers: { ...event().headers, "content-type": "text/plain" } }),
    event({ body: "{" }),
    event({ body: JSON.stringify({ email: "bad", runId: RUN_ID }) }),
    event({ body: JSON.stringify({ email: "a@example.com", runId: "run-bad" }) }),
    event({ body: JSON.stringify({ email: "a@example.com", extra: true, runId: RUN_ID }) }),
    event({ body: JSON.stringify({ email: "a@example.com" }) }),
    event({ body: " ".repeat(2_049) }),
  ];
  for (const input of invalid) {
    const { calls, handler } = fixture();
    const response = await handler(input);
    assert.equal(response.statusCode, 400);
    assert.deepEqual(JSON.parse(response.body), {
      paymentMoved: false,
      status: "RECEIPT_EMAIL_INVALID",
    });
    assert.deepEqual(calls.claims, []);
    assert.deepEqual(calls.messages, []);
  }
});

test("withholds email unless immutable history is exactly verified", async () => {
  const malformed = [
    verifiedSummary({ runStatus: "FAILED" }),
    verifiedSummary({ runStatus: "EXPIRED" }),
    verifiedSummary({ anchors: verifiedSummary().anchors.slice(0, 2) }),
    verifiedSummary({ paymentMoved: true }),
    verifiedSummary({ schema: "clockchain.aws-public-run-summary/v1" }),
  ];
  for (const summary of malformed) {
    const { calls, handler } = fixture({
      readSummary: async () => summary,
    });
    const response = await handler(event());
    assert.equal(response.statusCode, 409);
    assert.deepEqual(JSON.parse(response.body), {
      paymentMoved: false,
      status: "RECEIPT_NOT_READY",
    });
    assert.deepEqual(calls.claims, []);
    assert.deepEqual(calls.messages, []);
  }
});

test("does not resend a completed or in-progress delivery", async () => {
  for (const claim of ["SENT", "IN_PROGRESS"]) {
    const { calls, handler } = fixture({
      claimDelivery: async (value) => {
        calls.claims.push(value);
        return claim;
      },
    });
    const response = await handler(event());
    assert.equal(response.statusCode, 202);
    assert.equal(calls.messages.length, 0);
    assert.equal(calls.completed.length, 0);
  }
});

test("marks a claimed delivery failed when the provider rejects it", async () => {
  const { calls, handler } = fixture({
    sendEmail: async () => {
      throw new Error("provider detail must not escape");
    },
  });
  const response = await handler(event());
  assert.equal(response.statusCode, 502);
  assert.deepEqual(JSON.parse(response.body), {
    paymentMoved: false,
    status: "RECEIPT_EMAIL_FAILED",
  });
  assert.deepEqual(calls.failed, [
    { deliveryId: calls.claims[0].deliveryId },
  ]);
  assert.equal(
    response.body.includes("provider detail"),
    false,
  );
});

test("escapes every public string placed in HTML", () => {
  const summary = verifiedSummary();
  summary.anchors[0] = {
    ...summary.anchors[0],
    explorerUrl:
      "https://sepolia.etherscan.io/block/<script>&value=\"quoted\"'",
  };
  const message = renderVerifiedReceiptEmail(summary);
  assert.doesNotMatch(message.html, /<script>/);
  assert.doesNotMatch(message.html, /&value=/);
  assert.match(message.html, /&amp;value=/);
  assert.match(message.html, /&quot;quoted&quot;/);
  assert.match(message.html, /&#39;/);
});

test("returns a bounded failure when delivery state cannot be claimed", async () => {
  const { handler } = fixture({
    claimDelivery: async () => {
      throw new Error("database internals");
    },
  });
  const response = await handler(event());
  assert.equal(response.statusCode, 502);
  assert.equal(response.body.includes("database internals"), false);
});
