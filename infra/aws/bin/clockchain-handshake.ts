#!/usr/bin/env node

import { App } from "aws-cdk-lib";

import {
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

const app = new App();

new ClockchainHandshakeStack(
  app,
  "ClockchainHandshake",
  {
    controlPlaneImage: required(
      app.node.tryGetContext(
        "controlPlaneImage",
      ),
      "controlPlaneImage",
    ),
    env: {
      account: process.env.CDK_DEFAULT_ACCOUNT,
      region: process.env.CDK_DEFAULT_REGION,
    },
    tunnelImage: required(
      app.node.tryGetContext("tunnelImage"),
      "tunnelImage",
    ),
  },
);
