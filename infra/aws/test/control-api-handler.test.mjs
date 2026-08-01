import assert from "node:assert/strict";
import { test } from "node:test";

const ORIGIN = "https://clockchain.example";
const ISSUER =
  "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_example";
const AUDIENCE = "clockchain-console-client";
const OPERATOR_GROUP = "clockchain-operators";

function configureEnvironment() {
  process.env.ACTION_QUEUE_URL =
    "https://sqs.us-west-2.amazonaws.com/123456789012/actions.fifo";
  process.env.ACTION_TABLE_NAME = "clockchain-actions";
  process.env.ALLOWED_ORIGIN = ORIGIN;
  process.env.COGNITO_AUDIENCE = AUDIENCE;
  process.env.COGNITO_ISSUER = ISSUER;
  process.env.OPERATOR_GROUP = OPERATOR_GROUP;
}

test("accepts API Gateway JWT-authorized events when authorization header is not forwarded", async () => {
  configureEnvironment();
  const { handler } = await import(
    `../lambda/handler.mjs?jwt-authorizer-event=${Date.now()}`
  );
  const response = await handler({
    body: "{",
    headers: {
      "content-type": "application/json",
      origin: ORIGIN,
    },
    rawPath: "/v1/actions",
    requestContext: {
      authorizer: {
        jwt: {
          claims: {
            "cognito:groups": OPERATOR_GROUP,
            client_id: AUDIENCE,
            exp: String(Math.floor(Date.now() / 1000) + 60),
            iss: ISSUER,
            sub: "operator-1",
          },
        },
      },
      http: {
        method: "POST",
      },
    },
  });
  assert.equal(response.statusCode, 400);
});
