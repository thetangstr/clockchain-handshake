import {
  DynamoDBClient,
} from "@aws-sdk/client-dynamodb";
import {
  SendMessageCommand,
  SQSClient,
} from "@aws-sdk/client-sqs";
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
} from "@aws-sdk/lib-dynamodb";

import {
  createControlApiHandler,
} from "./control-api.mjs";

function required(key) {
  const value = process.env[key];
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.trim() !== value
  ) {
    throw new Error(
      "AWS control API runtime configuration invalid.",
    );
  }
  return value;
}

const tableName = required("ACTION_TABLE_NAME");
const queueUrl = required("ACTION_QUEUE_URL");
const audience = required("COGNITO_AUDIENCE");
const issuer = required("COGNITO_ISSUER");
const allowedOrigin = required("ALLOWED_ORIGIN");
const operatorGroup = required("OPERATOR_GROUP");
const documentClient =
  DynamoDBDocumentClient.from(
    new DynamoDBClient({}),
  );
const sqs = new SQSClient({});

function groups(value) {
  if (Array.isArray(value)) return value;
  if (
    typeof value !== "string" ||
    value.length === 0
  ) {
    return [];
  }
  try {
    const parsed = JSON.parse(value);
    if (Array.isArray(parsed)) return parsed;
  } catch {
    // Cognito may serialize one group as a string.
  }
  return [value];
}

async function readSessionState({
  releaseId,
  sessionId,
}) {
  const actionId =
    sessionId === null
      ? `RELEASE#${releaseId}`
      : `SESSION#${releaseId}#${sessionId}`;
  const result = await documentClient.send(
    new GetCommand({
      ConsistentRead: true,
      Key: { actionId },
      TableName: tableName,
    }),
  );
  return result.Item?.controlContext;
}

async function putIdempotency({
  actionDigest,
  actionId,
}) {
  try {
    await documentClient.send(
      new PutCommand({
        ConditionExpression:
          "attribute_not_exists(actionId)",
        Item: {
          actionDigest,
          actionId,
          recordType: "IDEMPOTENCY",
        },
        TableName: tableName,
      }),
    );
    return "CREATED";
  } catch (error) {
    if (
      error?.name !==
      "ConditionalCheckFailedException"
    ) {
      throw error;
    }
  }
  const existing = await documentClient.send(
    new GetCommand({
      ConsistentRead: true,
      Key: { actionId },
      TableName: tableName,
    }),
  );
  return existing.Item?.actionDigest ===
    actionDigest
    ? "SAME"
    : "CONFLICT";
}

async function sendMessage({
  body,
  deduplicationId,
  groupId,
}) {
  await sqs.send(
    new SendMessageCommand({
      MessageBody: body.toString("utf8"),
      MessageDeduplicationId:
        deduplicationId,
      MessageGroupId: groupId,
      QueueUrl: queueUrl,
    }),
  );
}

export async function handler(event) {
  const jwt =
    event?.requestContext?.authorizer?.jwt
      ?.claims;
  const verifyJwt = async () => ({
    aud: jwt?.aud ?? jwt?.client_id,
    exp:
      typeof jwt?.exp === "string"
        ? Number(jwt.exp)
        : jwt?.exp,
    groups: groups(jwt?.["cognito:groups"]),
    iss: jwt?.iss,
    sub: jwt?.sub,
  });
  const runtime = createControlApiHandler({
    allowedOrigin,
    audience,
    issuer,
    operatorGroup,
    putIdempotency,
    readSessionState,
    sendMessage,
    verifyJwt,
  });
  return runtime({
    body: event?.body,
    headers: event?.headers,
    httpMethod:
      event?.requestContext?.http?.method,
    path:
      event?.rawPath === "/v1/actions"
        ? "/actions"
        : event?.rawPath,
  });
}
