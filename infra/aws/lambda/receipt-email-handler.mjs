import {
  GetObjectCommand,
  S3Client,
} from "@aws-sdk/client-s3";
import {
  SendEmailCommand,
  SESv2Client,
} from "@aws-sdk/client-sesv2";
import {
  DynamoDBClient,
} from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  GetCommand,
  TransactWriteCommand,
  UpdateCommand,
} from "@aws-sdk/lib-dynamodb";

import {
  createReceiptEmailHandler,
} from "../../../src/bilateral/aws/receipt-email.mjs";

const RUN_ID = /^run-[0-9a-f]{16}$/;
const NAME = /^[A-Za-z0-9._-]{3,255}$/;
const MAX_SUMMARY_BYTES = 65_536;
const DELIVERY_TTL_SECONDS = 30 * 24 * 60 * 60;

function required(value, pattern) {
  if (
    typeof value !== "string" ||
    !pattern.test(value)
  ) {
    throw new Error("Receipt email runtime is invalid.");
  }
  return value;
}

function deliveryKey(deliveryId) {
  return `DELIVERY#${deliveryId}`;
}

function createDeliveryState({
  ddb,
  now,
  tableName,
}) {
  const expiresAt = () =>
    Math.floor(now() / 1_000) +
    DELIVERY_TTL_SECONDS;
  return {
    claimDelivery: async ({
      deliveryId,
      recipientDigest,
      runId,
    }) => {
      const pk = deliveryKey(deliveryId);
      const ttl = expiresAt();
      try {
        await ddb.send(
          new TransactWriteCommand({
            TransactItems: [
              {
                Put: {
                  ConditionExpression:
                    "attribute_not_exists(pk)",
                  Item: {
                    attempts: 1,
                    pk,
                    recipientDigest,
                    runId,
                    status: "CLAIMED",
                    ttl,
                  },
                  TableName: tableName,
                },
              },
              {
                Update: {
                  ConditionExpression:
                    "attribute_not_exists(recipientCount) OR recipientCount < :five",
                  ExpressionAttributeValues: {
                    ":five": 5,
                    ":one": 1,
                    ":ttl": ttl,
                  },
                  Key: {
                    pk: `RUN#${runId}`,
                  },
                  TableName: tableName,
                  UpdateExpression:
                    "SET ttl = :ttl ADD recipientCount :one",
                },
              },
            ],
          }),
        );
        return "CLAIMED";
      } catch (error) {
        if (
          error?.name !==
          "TransactionCanceledException"
        ) {
          throw error;
        }
      }

      const existing = await ddb.send(
        new GetCommand({
          ConsistentRead: true,
          Key: { pk },
          TableName: tableName,
        }),
      );
      if (existing.Item?.status === "SENT") {
        return "SENT";
      }
      if (
        existing.Item?.status === "CLAIMED"
      ) {
        return "IN_PROGRESS";
      }
      if (
        existing.Item?.status !== "FAILED" ||
        !Number.isSafeInteger(
          existing.Item.attempts,
        ) ||
        existing.Item.attempts < 1 ||
        existing.Item.attempts >= 3
      ) {
        throw new Error(
          "Receipt delivery cannot be claimed.",
        );
      }
      const attempts = existing.Item.attempts;
      try {
        await ddb.send(
          new UpdateCommand({
            ConditionExpression:
              "#status = :failed AND attempts = :attempts AND attempts < :three",
            ExpressionAttributeNames: {
              "#status": "status",
            },
            ExpressionAttributeValues: {
              ":attempts": attempts,
              ":claimed": "CLAIMED",
              ":failed": "FAILED",
              ":one": 1,
              ":three": 3,
              ":ttl": expiresAt(),
            },
            Key: { pk },
            TableName: tableName,
            UpdateExpression:
              "SET #status = :claimed, ttl = :ttl ADD attempts :one",
          }),
        );
        return "CLAIMED";
      } catch (error) {
        if (
          error?.name ===
          "ConditionalCheckFailedException"
        ) {
          return "IN_PROGRESS";
        }
        throw error;
      }
    },
    completeDelivery: async ({ deliveryId }) => {
      await ddb.send(
        new UpdateCommand({
          ConditionExpression:
            "#status = :claimed",
          ExpressionAttributeNames: {
            "#status": "status",
          },
          ExpressionAttributeValues: {
            ":claimed": "CLAIMED",
            ":sent": "SENT",
            ":ttl": expiresAt(),
          },
          Key: {
            pk: deliveryKey(deliveryId),
          },
          TableName: tableName,
          UpdateExpression:
            "SET #status = :sent, ttl = :ttl",
        }),
      );
    },
    failDelivery: async ({ deliveryId }) => {
      await ddb.send(
        new UpdateCommand({
          ConditionExpression:
            "#status = :claimed",
          ExpressionAttributeNames: {
            "#status": "status",
          },
          ExpressionAttributeValues: {
            ":claimed": "CLAIMED",
            ":failed": "FAILED",
            ":ttl": expiresAt(),
          },
          Key: {
            pk: deliveryKey(deliveryId),
          },
          TableName: tableName,
          UpdateExpression:
            "SET #status = :failed, ttl = :ttl",
        }),
      );
    },
  };
}

function normalizeEvent(event) {
  const headers = Object.fromEntries(
    Object.entries(event?.headers ?? {}).map(
      ([key, value]) => [
        key.toLowerCase(),
        value,
      ],
    ),
  );
  return {
    body: event?.body,
    headers,
    httpMethod:
      event?.isBase64Encoded === true
        ? "INVALID"
        : event?.requestContext?.http
            ?.method,
    path:
      event?.rawPath ===
      "/v1/receipt-email"
        ? "/receipt-email"
        : event?.rawPath,
  };
}

export function createReceiptEmailLambdaHandler({
  allowedOrigin,
  ddb,
  fromEmail,
  log = () => {},
  now = Date.now,
  publicBucketName,
  receiptDeliveryTableName,
  s3,
  ses,
} = {}) {
  required(
    publicBucketName,
    NAME,
  );
  required(
    receiptDeliveryTableName,
    NAME,
  );
  if (
    typeof now !== "function" ||
    typeof log !== "function" ||
    typeof s3?.send !== "function" ||
    typeof ddb?.send !== "function" ||
    typeof ses?.send !== "function"
  ) {
    throw new Error(
      "Receipt email runtime is invalid.",
    );
  }
  const delivery = createDeliveryState({
    ddb,
    now,
    tableName: receiptDeliveryTableName,
  });
  const pure = createReceiptEmailHandler({
    allowedOrigin,
    ...delivery,
    fromEmail,
    readSummary: async (runId) => {
      if (!RUN_ID.test(runId)) {
        throw new Error("invalid run");
      }
      const result = await s3.send(
        new GetObjectCommand({
          Bucket: publicBucketName,
          Key: `runs/${runId}.json`,
        }),
      );
      if (
        typeof result.Body
          ?.transformToString !== "function"
      ) {
        throw new Error("invalid body");
      }
      const body =
        await result.Body.transformToString();
      if (
        typeof body !== "string" ||
        Buffer.byteLength(body, "utf8") >
          MAX_SUMMARY_BYTES
      ) {
        throw new Error("invalid body");
      }
      return JSON.parse(body);
    },
    sendEmail: async ({
      fromEmail: sender,
      html,
      subject,
      text,
      toEmail,
    }) => {
      await ses.send(
        new SendEmailCommand({
          Content: {
            Simple: {
              Body: {
                Html: {
                  Charset: "UTF-8",
                  Data: html,
                },
                Text: {
                  Charset: "UTF-8",
                  Data: text,
                },
              },
              Subject: {
                Charset: "UTF-8",
                Data: subject,
              },
            },
          },
          Destination: {
            ToAddresses: [toEmail],
          },
          FromEmailAddress: sender,
        }),
      );
    },
  });
  return async (event) => {
    const response = await pure(
      normalizeEvent(event),
    );
    let status = "RECEIPT_EMAIL_FAILED";
    try {
      status = JSON.parse(response.body).status;
    } catch {
      // The pure boundary always returns JSON; keep the bounded fallback.
    }
    log(Object.freeze({
      paymentMoved: false,
      status,
      statusCode: response.statusCode,
    }));
    return response;
  };
}

const s3 = new S3Client({});
const ddb = DynamoDBDocumentClient.from(
  new DynamoDBClient({}),
  {
    marshallOptions: {
      removeUndefinedValues: true,
    },
  },
);
const ses = new SESv2Client({});
let runtime;

export async function handler(event) {
  runtime ??= createReceiptEmailLambdaHandler({
    allowedOrigin: process.env.ALLOWED_ORIGIN,
    ddb,
    fromEmail:
      process.env.RECEIPT_SENDER_EMAIL,
    log: (value) =>
      console.info(JSON.stringify(value)),
    publicBucketName:
      process.env.PUBLIC_BUCKET_NAME,
    receiptDeliveryTableName:
      process.env
        .RECEIPT_DELIVERY_TABLE_NAME,
    s3,
    ses,
  });
  return runtime(event);
}
