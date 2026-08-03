import assert from "node:assert/strict";
import { test } from "node:test";

import {
  createReceiptEmailLambdaHandler,
} from "../lambda/receipt-email-handler.mjs";

const RUN_ID = "run-0123456789abcdef";
const EMAIL = "stakeholder@example.com";

function summary(overrides = {}) {
  return {
    anchors: [
      {
        block: "101",
        cardinality: "1",
        explorerUrl:
          "https://sepolia.etherscan.io/block/101",
        kind: "PROPOSED",
        ledgerId:
          "00000000-0000-4000-8000-000000000001",
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
    body: JSON.stringify({ email: EMAIL, runId: RUN_ID }),
    headers: {
      "content-type": "application/json",
      origin:
        "https://clockchain-research.vercel.app",
    },
    isBase64Encoded: false,
    rawPath: "/v1/receipt-email",
    requestContext: {
      http: { method: "POST" },
    },
    ...overrides,
  };
}

function fixture({
  ddbSend,
  s3Body = summary(),
  sesSend,
} = {}) {
  const calls = [];
  const logs = [];
  const record = (service, command) => {
    calls.push({
      command: command.constructor.name,
      input: command.input,
      service,
    });
  };
  const handler = createReceiptEmailLambdaHandler({
    allowedOrigin:
      "https://clockchain-research.vercel.app",
    ddb: {
      send: async (command) => {
        record("dynamodb", command);
        return ddbSend?.(command) ?? {};
      },
    },
    fromEmail: "receipts@clockchain.network",
    log: (value) => logs.push(value),
    now: () => 2_000_000_000_000,
    publicBucketName: "public-monitor-bucket",
    receiptDeliveryTableName:
      "receipt-delivery-table",
    s3: {
      send: async (command) => {
        record("s3", command);
        return {
          Body: {
            transformToString: async () =>
              JSON.stringify(s3Body),
          },
        };
      },
    },
    ses: {
      send: async (command) => {
        record("ses", command);
        return sesSend?.(command) ?? {
          MessageId: "message-id",
        };
      },
    },
  });
  return { calls, handler, logs };
}

test("reads immutable evidence, claims once, sends fixed content, and completes", async () => {
  const { calls, handler, logs } = fixture();
  const response = await handler(event());

  assert.equal(response.statusCode, 202);
  assert.deepEqual(
    calls.map(({ command }) => command),
    [
      "GetObjectCommand",
      "TransactWriteCommand",
      "SendEmailCommand",
      "UpdateCommand",
    ],
  );
  assert.deepEqual(calls[0].input, {
    Bucket: "public-monitor-bucket",
    Key: `runs/${RUN_ID}.json`,
  });
  assert.equal(
    JSON.stringify(calls).includes(EMAIL),
    true,
  );
  assert.equal(
    JSON.stringify(logs).includes(EMAIL),
    false,
  );
  const claim = calls[1].input;
  assert.match(
    JSON.stringify(claim),
    /recipientCount/,
  );
  assert.match(
    JSON.stringify(claim),
    /:five/,
  );
  assert.equal(
    JSON.stringify(claim).includes(EMAIL),
    false,
  );
  const send = calls[2].input;
  assert.equal(
    send.FromEmailAddress,
    "receipts@clockchain.network",
  );
  assert.deepEqual(send.Destination, {
    ToAddresses: [EMAIL],
  });
  assert.match(
    send.Content.Simple.Subject.Data,
    /Clockchain Handshake Receipt/,
  );
});

test("returns not-ready without claiming or sending for an unverified summary", async () => {
  const { calls, handler } = fixture({
    s3Body: summary({
      anchors: [],
      businessResult:
        "The run stopped safely because the available evidence did not satisfy every required check.",
      runStatus: "FAILED",
    }),
  });
  const response = await handler(event());
  assert.equal(response.statusCode, 409);
  assert.deepEqual(
    calls.map(({ command }) => command),
    ["GetObjectCommand"],
  );
});

test("treats an already-sent digest as an idempotent success", async () => {
  let first = true;
  const { calls, handler } = fixture({
    ddbSend: async (command) => {
      if (
        first &&
        command.constructor.name ===
          "TransactWriteCommand"
      ) {
        first = false;
        const error = new Error("conditional");
        error.name = "TransactionCanceledException";
        throw error;
      }
      if (command.constructor.name === "GetCommand") {
        return { Item: { attempts: 1, status: "SENT" } };
      }
      return {};
    },
  });
  const response = await handler(event());
  assert.equal(response.statusCode, 202);
  assert.deepEqual(
    calls.map(({ command }) => command),
    [
      "GetObjectCommand",
      "TransactWriteCommand",
      "GetCommand",
    ],
  );
});

test("records a bounded failed attempt when SES rejects the send", async () => {
  const { calls, handler } = fixture({
    sesSend: async () => {
      throw new Error("provider details");
    },
  });
  const response = await handler(event());
  assert.equal(response.statusCode, 502);
  assert.deepEqual(
    calls.map(({ command }) => command),
    [
      "GetObjectCommand",
      "TransactWriteCommand",
      "SendEmailCommand",
      "UpdateCommand",
    ],
  );
  assert.match(
    JSON.stringify(calls.at(-1)?.input),
    /FAILED/,
  );
  assert.equal(
    response.body.includes("provider details"),
    false,
  );
});

test("rejects encoded request bodies before any AWS call", async () => {
  const { calls, handler } = fixture();
  const response = await handler(
    event({ isBase64Encoded: true }),
  );
  assert.equal(response.statusCode, 400);
  assert.deepEqual(calls, []);
});
