import {
  DescribeTasksCommand,
  RunTaskCommand,
} from "@aws-sdk/client-ecs";

const CONFIG_KEYS = Object.freeze([
  "clusterArn",
  "containerName",
  "paymentMoved",
  "securityGroupId",
  "subnetIds",
  "taskDefinitionArn",
]);
const WAIT_KEYS = Object.freeze([
  "clusterArn",
  "containerName",
  "paymentMoved",
  "taskArn",
]);
const CLUSTER_ARN =
  /^arn:aws(?:-[a-z]+)?:ecs:[a-z0-9-]+:[0-9]{12}:cluster\/[A-Za-z0-9_-]{1,255}$/;
const TASK_DEFINITION_ARN =
  /^arn:aws(?:-[a-z]+)?:ecs:[a-z0-9-]+:[0-9]{12}:task-definition\/[A-Za-z0-9_-]{1,255}:[1-9][0-9]*$/;
const TASK_ARN =
  /^arn:aws(?:-[a-z]+)?:ecs:[a-z0-9-]+:[0-9]{12}:task\/(?:[A-Za-z0-9_-]{1,255}\/)?[0-9a-f]{32}$/;
const NETWORK_ID =
  /^(?:sg|subnet)-[0-9a-f]{17}$/;
const NAME =
  /^[a-z][a-z0-9-]{0,63}$/;
const SENSITIVE_KEY =
  /^(?:capability|invitation|privateKey|secret|token)$/i;

export class AwsEcsTaskRunnerError extends Error {
  constructor() {
    super("AWS ECS task runner failed safely.");
    this.name = "AwsEcsTaskRunnerError";
    this.code = "AWS_ECS_TASK_RUNNER_INVALID";
    this.category = "verification";
  }
}

function fail() {
  throw new AwsEcsTaskRunnerError();
}

function exact(value, keys) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !==
      Object.prototype ||
    Reflect.ownKeys(value).length !==
      keys.length ||
    keys.some(
      (key, index) =>
        Reflect.ownKeys(value)[index] !== key,
    )
  ) {
    fail();
  }
  return value;
}

function config(value) {
  const input = exact(value, CONFIG_KEYS);
  if (
    !CLUSTER_ARN.test(input.clusterArn) ||
    !NAME.test(input.containerName) ||
    input.paymentMoved !== false ||
    !NETWORK_ID.test(
      input.securityGroupId,
    ) ||
    !Array.isArray(input.subnetIds) ||
    input.subnetIds.length < 2 ||
    input.subnetIds.length > 4 ||
    new Set(input.subnetIds).size !==
      input.subnetIds.length ||
    input.subnetIds.some(
      (subnet) =>
        !NETWORK_ID.test(subnet),
    ) ||
    !TASK_DEFINITION_ARN.test(
      input.taskDefinitionArn,
    )
  ) {
    fail();
  }
  return input;
}

function canonicalRuntimeInput(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !==
      Object.prototype ||
    value.paymentMoved !== false ||
    value.schema !==
      "clockchain.aws-runtime-input/v1"
  ) {
    fail();
  }
  const visit = (entry) => {
    if (
      entry === null ||
      typeof entry !== "object"
    ) {
      return;
    }
    if (Array.isArray(entry)) {
      for (const child of entry) {
        visit(child);
      }
      return;
    }
    for (const [key, child] of
      Object.entries(entry)) {
      if (SENSITIVE_KEY.test(key)) {
        fail();
      }
      visit(child);
    }
  };
  visit(value);
  const text = JSON.stringify(value);
  if (
    Buffer.byteLength(text, "utf8") >
      32_768
  ) {
    fail();
  }
  return text;
}

export async function launchPinnedTask(
  {
    config: configValue,
    runtimeInput,
  } = {},
  dependencies = {},
) {
  try {
    const input = config(configValue);
    const ecs = dependencies.ecs;
    if (
      ecs === null ||
      typeof ecs !== "object" ||
      typeof ecs.send !== "function"
    ) {
      fail();
    }
    const result = await ecs.send(
      new RunTaskCommand({
        cluster: input.clusterArn,
        count: 1,
        enableExecuteCommand: false,
        launchType: "FARGATE",
        networkConfiguration: {
          awsvpcConfiguration: {
            assignPublicIp: "ENABLED",
            securityGroups: [
              input.securityGroupId,
            ],
            subnets: input.subnetIds,
          },
        },
        overrides: {
          containerOverrides: [
            {
              environment: [
                {
                  name:
                    "AWS_RUNTIME_INPUT",
                  value:
                    canonicalRuntimeInput(
                      runtimeInput,
                    ),
                },
              ],
              name:
                input.containerName,
            },
          ],
        },
        platformVersion: "LATEST",
        taskDefinition:
          input.taskDefinitionArn,
      }),
    );
    if (
      !Array.isArray(result.failures) ||
      result.failures.length !== 0 ||
      !Array.isArray(result.tasks) ||
      result.tasks.length !== 1 ||
      !TASK_ARN.test(
        result.tasks[0]?.taskArn,
      )
    ) {
      fail();
    }
    return Object.freeze({
      paymentMoved: false,
      status: "RUNNING",
      taskArn:
        result.tasks[0].taskArn,
    });
  } catch (error) {
    if (
      error instanceof
      AwsEcsTaskRunnerError
    ) {
      throw error;
    }
    fail();
  }
}

export async function waitForPinnedTask(
  value,
  dependencies = {},
) {
  try {
    const input = exact(
      value,
      WAIT_KEYS,
    );
    if (
      !CLUSTER_ARN.test(
        input.clusterArn,
      ) ||
      !NAME.test(input.containerName) ||
      input.paymentMoved !== false ||
      !TASK_ARN.test(input.taskArn)
    ) {
      fail();
    }
    const describe =
      dependencies.describe ??
      (
        async () =>
          dependencies.ecs.send(
            new DescribeTasksCommand({
              cluster:
                input.clusterArn,
              tasks: [input.taskArn],
            }),
          )
      );
    const sleep =
      dependencies.sleep ??
      (
        (milliseconds) =>
          new Promise(
            (resolvePromise) =>
              setTimeout(
                resolvePromise,
                milliseconds,
              ),
          )
      );
    if (
      typeof describe !== "function" ||
      typeof sleep !== "function"
    ) {
      fail();
    }
    for (
      let attempt = 0;
      attempt < 120;
      attempt += 1
    ) {
      const result = await describe();
      if (
        !Array.isArray(
          result.failures,
        ) ||
        result.failures.length !== 0 ||
        !Array.isArray(result.tasks) ||
        result.tasks.length !== 1
      ) {
        fail();
      }
      const task = result.tasks[0];
      if (
        task.taskArn !== input.taskArn
      ) {
        fail();
      }
      if (task.lastStatus !== "STOPPED") {
        await sleep(5_000);
        continue;
      }
      if (
        !Array.isArray(
          task.containers,
        ) ||
        task.containers.length !== 1 ||
        task.containers[0].name !==
          input.containerName ||
        task.containers[0].exitCode !== 0
      ) {
        fail();
      }
      return Object.freeze({
        paymentMoved: false,
        status: "SUCCEEDED",
        taskArn: input.taskArn,
      });
    }
    fail();
  } catch (error) {
    if (
      error instanceof
      AwsEcsTaskRunnerError
    ) {
      throw error;
    }
    fail();
  }
}
