#!/usr/bin/env node

import { App } from "aws-cdk-lib";

import {
  ClockchainHandshakeImagesStack,
  ClockchainHandshakeStack,
} from "../lib/clockchain-handshake-stack.js";

function required(
  value: unknown,
  label: string,
): string {
  if (
    typeof value !== "string" ||
    value.length === 0
  ) {
    throw new Error(
      `Missing required CDK context: ${label}.`,
    );
  }
  return value;
}

function optionalBoolean(
  value: unknown,
  label: string,
): boolean {
  if (value === undefined || value === "false") {
    return false;
  }
  if (value === "true") {
    return true;
  }
  throw new Error(
    `Invalid CDK context: ${label}.`,
  );
}

const app = new App();

new ClockchainHandshakeImagesStack(
  app,
  "ClockchainHandshakeImages",
  {
    env: {
      account: process.env.CDK_DEFAULT_ACCOUNT,
      region: process.env.CDK_DEFAULT_REGION,
    },
  },
);

const controlPlaneImage =
  app.node.tryGetContext(
    "controlPlaneImage",
  );
const repositorySha =
  app.node.tryGetContext("repositorySha");
const sessionId =
  app.node.tryGetContext("sessionId");
const bootstrapBrokerCapabilityDigest =
  app.node.tryGetContext(
    "bootstrapBrokerCapabilityDigest",
  );
const relayTlsCertificatePem =
  app.node.tryGetContext(
    "relayTlsCertificatePem",
  );
const relayPublicHostname =
  app.node.tryGetContext(
    "relayPublicHostname",
  );
const relayTlsFingerprint =
  app.node.tryGetContext(
    "relayTlsFingerprint",
  );
const relayTlsSecretArn =
  app.node.tryGetContext(
    "relayTlsSecretArn",
  );
const operatorPublicKey =
  app.node.tryGetContext("operatorPublicKey");
const sourceTreeSha256 =
  app.node.tryGetContext("sourceTreeSha256");
const tunnelImage =
  app.node.tryGetContext("tunnelImage");

if (
  controlPlaneImage !== undefined ||
  repositorySha !== undefined ||
  tunnelImage !== undefined
) {
  new ClockchainHandshakeStack(
    app,
    "ClockchainHandshake",
    {
      activateServices: optionalBoolean(
        app.node.tryGetContext(
          "activateServices",
        ),
        "activateServices",
      ),
      bootstrapBrokerCapabilityDigest:
        required(
          bootstrapBrokerCapabilityDigest,
          "bootstrapBrokerCapabilityDigest",
        ),
      controlPlaneImage: required(
        controlPlaneImage,
        "controlPlaneImage",
      ),
      env: {
        account: process.env.CDK_DEFAULT_ACCOUNT,
        region: process.env.CDK_DEFAULT_REGION,
      },
      repositorySha: required(
        repositorySha,
        "repositorySha",
      ),
      operatorPublicKey: required(
        operatorPublicKey,
        "operatorPublicKey",
      ),
      relayTlsCertificatePem: required(
        relayTlsCertificatePem,
        "relayTlsCertificatePem",
      ),
      relayPublicHostname: required(
        relayPublicHostname,
        "relayPublicHostname",
      ),
      relayTlsFingerprint: required(
        relayTlsFingerprint,
        "relayTlsFingerprint",
      ),
      relayTlsSecretArn: required(
        relayTlsSecretArn,
        "relayTlsSecretArn",
      ),
      sessionId: required(
        sessionId,
        "sessionId",
      ),
      sourceTreeSha256: required(
        sourceTreeSha256,
        "sourceTreeSha256",
      ),
      tunnelImage: required(
        tunnelImage,
        "tunnelImage",
      ),
    },
  );
}
