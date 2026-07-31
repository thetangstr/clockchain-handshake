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
      tunnelImage: required(
        tunnelImage,
        "tunnelImage",
      ),
    },
  );
}
