import assert from "node:assert/strict";
import { test } from "node:test";

import {
  launchPinnedTask,
  waitForPinnedTask,
} from "../infra/aws/runtime/ecs-task-runner.mjs";

const CONFIG = Object.freeze({
  clusterArn:
    "arn:aws:ecs:us-west-2:123456789012:cluster/clockchain",
  containerName: "coordinator",
  paymentMoved: false,
  securityGroupId: "sg-0123456789abcdef0",
  subnetIds: Object.freeze([
    "subnet-0123456789abcdef0",
    "subnet-11111111111111111",
  ]),
  taskDefinitionArn:
    "arn:aws:ecs:us-west-2:123456789012:task-definition/coordinator:7",
});
const CLIENT_TOKEN = Object.freeze({
  childTask: "coordinator",
  action: "request-payment",
  fingerprint: "0123456789abcdef",
});
const RUNTIME_INPUT = Object.freeze({
  paymentMoved: false,
  schema:
    "clockchain.aws-runtime-input/v1",
});

test("launches one immutable Fargate task with canonical runtime input and no command-line secret", async () => {
  const calls = [];
  const result = await launchPinnedTask(
    {
      clientToken: CLIENT_TOKEN,
      config: CONFIG,
      runtimeInput: RUNTIME_INPUT,
    },
    {
      ecs: {
        async send(command) {
          calls.push(command.input);
          return {
            failures: [],
            tasks: [
              {
                taskArn:
                  "arn:aws:ecs:us-west-2:123456789012:task/clockchain/11111111111111111111111111111111",
              },
            ],
          };
        },
      },
    },
  );
  assert.equal(
    result.taskArn.endsWith(
      "/11111111111111111111111111111111",
    ),
    true,
  );
  assert.deepEqual(calls[0], {
    clientToken:
      "cc-coordinator-request-payment-0123456789abcdef",
    cluster: CONFIG.clusterArn,
    count: 1,
    enableExecuteCommand: false,
    launchType: "FARGATE",
    networkConfiguration: {
      awsvpcConfiguration: {
        assignPublicIp: "ENABLED",
        securityGroups: [
          CONFIG.securityGroupId,
        ],
        subnets: CONFIG.subnetIds,
      },
    },
    overrides: {
      containerOverrides: [
        {
          environment: [
            {
              name: "AWS_RUNTIME_INPUT",
              value:
                '{"paymentMoved":false,"schema":"clockchain.aws-runtime-input/v1"}',
            },
          ],
          name: CONFIG.containerName,
        },
      ],
    },
    platformVersion: "LATEST",
    taskDefinition:
      CONFIG.taskDefinitionArn,
  });
});

test("derives stable noncolliding ECS client tokens from child task and action identity", async () => {
  const calls = [];
  const ecs = {
    async send(command) {
      calls.push(command.input);
      return {
        failures: [],
        tasks: [
          {
            taskArn:
              "arn:aws:ecs:us-west-2:123456789012:task/clockchain/11111111111111111111111111111111",
          },
        ],
      };
    },
  };
  await launchPinnedTask(
    {
      clientToken: CLIENT_TOKEN,
      config: CONFIG,
      runtimeInput: RUNTIME_INPUT,
    },
    { ecs },
  );
  await launchPinnedTask(
    {
      clientToken: CLIENT_TOKEN,
      config: CONFIG,
      runtimeInput: RUNTIME_INPUT,
    },
    { ecs },
  );
  await launchPinnedTask(
    {
      clientToken: {
        childTask: "operator",
        action: "accept-payment",
        fingerprint:
          CLIENT_TOKEN.fingerprint,
      },
      config: CONFIG,
      runtimeInput: RUNTIME_INPUT,
    },
    { ecs },
  );
  assert.equal(
    calls[0].clientToken,
    calls[1].clientToken,
  );
  assert.notEqual(
    calls[0].clientToken,
    calls[2].clientToken,
  );
});

test("accepts only one stopped zero-exit task matching the launched ARN", async () => {
  const taskArn =
    "arn:aws:ecs:us-west-2:123456789012:task/clockchain/11111111111111111111111111111111";
  const result = await waitForPinnedTask(
    {
      clusterArn: CONFIG.clusterArn,
      containerName:
        CONFIG.containerName,
      paymentMoved: false,
      taskArn,
    },
    {
      describe: async () => ({
        failures: [],
        tasks: [
          {
            containers: [
              {
                exitCode: 0,
                name:
                  CONFIG.containerName,
              },
            ],
            lastStatus: "STOPPED",
            taskArn,
          },
        ],
      }),
      sleep: async () => {},
    },
  );
  assert.deepEqual(result, {
    paymentMoved: false,
    status: "SUCCEEDED",
    taskArn,
  });
});

test("fails closed on multiple tasks, launch failures, nonzero exits, and mutable environment input", async () => {
  await assert.rejects(
    launchPinnedTask(
      {
        clientToken: CLIENT_TOKEN,
        config: CONFIG,
        runtimeInput: {
          paymentMoved: false,
          schema:
            "clockchain.aws-runtime-input/v1",
          token: "must-not-pass",
        },
      },
      {
        ecs: {
          async send() {
            return {
              failures: [],
              tasks: [],
            };
          },
        },
      },
    ),
    /AWS ECS task runner failed safely/,
  );
  await assert.rejects(
    waitForPinnedTask(
      {
        clusterArn:
          CONFIG.clusterArn,
        containerName:
          CONFIG.containerName,
        paymentMoved: false,
        taskArn:
          "arn:aws:ecs:us-west-2:123456789012:task/clockchain/11111111111111111111111111111111",
      },
      {
        describe: async () => ({
          failures: [],
          tasks: [
            {
              containers: [
                {
                  exitCode: 1,
                  name: "coordinator",
                },
              ],
              lastStatus: "STOPPED",
              taskArn:
                "arn:aws:ecs:us-west-2:123456789012:task/clockchain/11111111111111111111111111111111",
            },
          ],
        }),
        sleep: async () => {},
      },
    ),
    /AWS ECS task runner failed safely/,
  );
});

test("fails closed before ECS launch when client token input is missing or malformed", async () => {
  let sendCount = 0;
  const dependencies = {
    ecs: {
      async send() {
        sendCount += 1;
        return {
          failures: [],
          tasks: [
            {
              taskArn:
                "arn:aws:ecs:us-west-2:123456789012:task/clockchain/11111111111111111111111111111111",
            },
          ],
        };
      },
    },
  };
  await assert.rejects(
    launchPinnedTask(
      {
        config: CONFIG,
        runtimeInput: RUNTIME_INPUT,
      },
      dependencies,
    ),
    /AWS ECS task runner failed safely/,
  );
  await assert.rejects(
    launchPinnedTask(
      {
        clientToken: {
          childTask: "coordinator",
          action: "request-payment",
          fingerprint:
            "contains-secret-token",
        },
        config: CONFIG,
        runtimeInput: RUNTIME_INPUT,
      },
      dependencies,
    ),
    /AWS ECS task runner failed safely/,
  );
  assert.equal(sendCount, 0);
});
