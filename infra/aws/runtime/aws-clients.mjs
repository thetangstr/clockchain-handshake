function required(value, label) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.trim() !== value
  ) {
    throw new Error(
      `AWS runtime configuration invalid: ${label}.`,
    );
  }
  return value;
}

export async function createAwsRuntimeClients({
  region = process.env.AWS_REGION,
} = {}) {
  const activeRegion = required(
    region,
    "AWS_REGION",
  );
  const [
    dynamodb,
    ecs,
    s3,
    secrets,
    sqs,
  ] = await Promise.all([
    import("@aws-sdk/client-dynamodb"),
    import("@aws-sdk/client-ecs"),
    import("@aws-sdk/client-s3"),
    import("@aws-sdk/client-secrets-manager"),
    import("@aws-sdk/client-sqs"),
  ]);
  return Object.freeze({
    dynamodb: new dynamodb.DynamoDBClient({
      region: activeRegion,
    }),
    ecs: new ecs.ECSClient({
      region: activeRegion,
    }),
    s3: new s3.S3Client({
      region: activeRegion,
    }),
    secrets: new secrets.SecretsManagerClient({
      region: activeRegion,
    }),
    sqs: new sqs.SQSClient({
      region: activeRegion,
    }),
  });
}
