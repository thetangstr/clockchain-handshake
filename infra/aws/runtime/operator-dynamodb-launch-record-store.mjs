import {
  GetCommand,
  PutCommand,
} from "@aws-sdk/lib-dynamodb";

const TABLE = /^[A-Za-z0-9_.-]{3,255}$/;

export class AwsOperatorLaunchRecordStoreError extends Error {
  constructor() {
    super(
      "AWS operator launch record store failed safely.",
    );
    this.name =
      "AwsOperatorLaunchRecordStoreError";
    this.code =
      "AWS_OPERATOR_LAUNCH_RECORD_STORE_INVALID";
    this.category = "verification";
  }
}

function fail() {
  throw new AwsOperatorLaunchRecordStoreError();
}

function validateKey(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 512 ||
    !value.startsWith("operator-launch#") ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    fail();
  }
  return value;
}

export function createDynamoOperatorLaunchRecordStore(
  value = {},
) {
  try {
    const { documentClient, tableName } = value;
    if (
      documentClient === null ||
      typeof documentClient !== "object" ||
      typeof documentClient.send !==
        "function" ||
      !TABLE.test(tableName)
    ) {
      fail();
    }
    return Object.freeze({
      async readRecord(key) {
        const result = await documentClient.send(
          new GetCommand({
            ConsistentRead: true,
            Key: {
              actionId: validateKey(key),
            },
            TableName: tableName,
          }),
        );
        return result.Item?.launchRecord ?? null;
      },
      async writeRecord(key, record) {
        if (
          record === null ||
          typeof record !== "object" ||
          Array.isArray(record) ||
          record.paymentMoved !== false
        ) {
          fail();
        }
        await documentClient.send(
          new PutCommand({
            ConditionExpression:
              "attribute_not_exists(actionId) OR (launchRecord.intentDigest = :intentDigest AND launchRecord.runtimeInputDigest = :runtimeInputDigest AND launchRecord.identity = :identity AND (attribute_not_exists(launchRecord.taskArn) OR launchRecord.taskArn = :nullTaskArn OR launchRecord.taskArn = :taskArn))",
            ExpressionAttributeValues: {
              ":identity": record.identity,
              ":intentDigest":
                record.intentDigest,
              ":nullTaskArn": null,
              ":runtimeInputDigest":
                record.runtimeInputDigest,
              ":taskArn": record.taskArn,
            },
            Item: {
              actionId: validateKey(key),
              launchRecord: record,
              paymentMoved: false,
              recordType:
                "OPERATOR_LAUNCH_RECORD",
            },
            TableName: tableName,
          }),
        );
      },
    });
  } catch (error) {
    if (
      error instanceof
      AwsOperatorLaunchRecordStoreError
    ) {
      throw error;
    }
    fail();
  }
}
