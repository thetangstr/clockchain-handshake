#!/usr/bin/env node

import {
  createHash,
  X509Certificate,
} from "node:crypto";
import {
  types,
} from "node:util";
import {
  DynamoDBDocumentClient,
} from "@aws-sdk/lib-dynamodb";

import {
  readAwsFundingResult,
} from "../../../scripts/run-aws-funding-task.mjs";
import {
  createAwsRuntimeClients,
} from "./aws-clients.mjs";
import {
  launchPinnedTask,
  waitForPinnedTask,
} from "./ecs-task-runner.mjs";
import {
  createAwsOperatorBootstrapFingerprintReader,
} from "./operator-bootstrap-fingerprint-reader.mjs";
import {
  createOperatorChildLauncher,
} from "./operator-child-launcher.mjs";
import {
  createDynamoOperatorLaunchRecordStore,
} from "./operator-dynamodb-launch-record-store.mjs";
import {
  createDurableOperatorLaunchRecord,
} from "./operator-launch-record.mjs";
import {
  runAwsOperatorLoop,
} from "./operator-runtime.mjs";
import {
  buildCoordinatorRuntimeInput,
} from "./operator-task-inputs.mjs";
import {
  createAwsOperatorTransitions,
} from "./operator-transitions.mjs";
import {
  readAwsFundingRecord,
  readAwsVerifierHandoff,
  readAwsVerifierPublication,
} from "./coordinator-operator-handoff.mjs";
import {
  parseRuntimeInput,
} from "./runtime-input.mjs";

const TOP_LEVEL_KEYS = Object.freeze([
  "operator",
  "paymentMoved",
  "schema",
]);
const OPERATOR_KEYS = Object.freeze([
  "actionQueueUrl",
  "actionTableName",
  "paymentMoved",
  "publicMonitorBucketName",
  "publicMonitorControlKey",
  "releaseId",
  "repositorySha",
  "schema",
  "sessionId",
]);
const PRODUCTION_OPERATOR_KEYS = Object.freeze([
  "actionQueueUrl",
  "actionTableName",
  "bootstrap",
  "children",
  "coordinator",
  "paymentMoved",
  "publicMonitorBucketName",
  "publicMonitorControlKey",
  "releaseId",
  "repositorySha",
  "schema",
  "sessionId",
]);
const BOOTSTRAP_KEYS = Object.freeze([
  "abortMarkerPath",
  "approvedPayerPublicPath",
  "bootstrapBrokerCapabilitySecretArn",
  "bootstrapBrokerUrl",
  "bootstrapStatePath",
  "operatorKeyId",
  "operatorKeySecretArn",
  "payeeLaunchManifestPath",
  "payerLaunchManifestPath",
  "publicMcpHostname",
  "tunnelGrantPath",
]);
const SHA40 = /^[0-9a-f]{40}$/;
const SHA64 = /^[0-9a-f]{64}$/;
const RELEASE = /^release-[0-9a-f]{16}$/;
const SESSION =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SQS_QUEUE_PATH =
  /^\/[0-9]{12}\/(?:[A-Za-z0-9_-]{1,80}|[A-Za-z0-9_-]{1,75}\.fifo)$/;
const TABLE = /^[A-Za-z0-9_.-]{3,255}$/;
const BUCKET =
  /^(?!\d+\.\d+\.\d+\.\d+$)(?=.{3,63}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])$/;
const SECRET_ARN =
  /^arn:aws(?:-[a-z]+)?:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]{1,512}$/;
const CLUSTER_ARN =
  /^arn:aws(?:-[a-z]+)?:ecs:[a-z0-9-]+:[0-9]{12}:cluster\/[A-Za-z0-9_-]{1,255}$/;
const TASK_DEFINITION_ARN =
  /^arn:aws(?:-[a-z]+)?:ecs:[a-z0-9-]+:[0-9]{12}:task-definition\/[A-Za-z0-9_-]{1,255}:[1-9][0-9]*$/;
const NETWORK_ID =
  /^(?:sg|subnet)-[0-9a-f]{17}$/;
const CONTAINER_NAME =
  /^[a-z][a-z0-9-]{0,63}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const ISO_INSTANT =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

class AwsOperatorWorkerEntrypointError extends Error {
  constructor() {
    super(
      "AWS operator worker entrypoint failed safely.",
    );
    this.name =
      "AwsOperatorWorkerEntrypointError";
  }
}

function fail() {
  throw new AwsOperatorWorkerEntrypointError();
}

function plain(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    !types.isProxy(value) &&
    Object.getPrototypeOf(value) ===
      Object.prototype
  );
}

function exact(value, keys) {
  if (!plain(value)) fail();
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== keys.length ||
    keys.some(
      (key, index) => ownKeys[index] !== key,
    )
  ) {
    fail();
  }
  for (const key of keys) {
    const descriptor =
      Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor?.enumerable !== true ||
      !Object.hasOwn(descriptor, "value")
    ) {
      fail();
    }
  }
  return value;
}

function expectedReleaseId(sessionId) {
  return `release-${createHash("sha256").update(sessionId, "utf8").digest("hex").slice(0, 16)}`;
}

function validateQueueUrl(value) {
  try {
    const url = new URL(value);
    return (
      url.href === value &&
      url.protocol === "https:" &&
      url.username === "" &&
      url.password === "" &&
      url.search === "" &&
      url.hash === "" &&
      SQS_QUEUE_PATH.test(url.pathname) &&
      /^sqs\.[a-z0-9-]+\.amazonaws\.com$/.test(
        url.hostname,
      )
    );
  } catch {
    return false;
  }
}

function validateOperator(value) {
  const operator = exact(value, OPERATOR_KEYS);
  if (
    !validateQueueUrl(operator.actionQueueUrl) ||
    !TABLE.test(operator.actionTableName) ||
    !BUCKET.test(
      operator.publicMonitorBucketName,
    ) ||
    operator.publicMonitorControlKey !==
      "control.json" ||
    operator.paymentMoved !== false ||
    !RELEASE.test(operator.releaseId) ||
    !SHA40.test(operator.repositorySha) ||
    operator.schema !==
      "clockchain.aws-operator-runtime/v1" ||
    !SESSION.test(operator.sessionId) ||
    operator.releaseId !==
      expectedReleaseId(operator.sessionId)
  ) {
    fail();
  }
  return Object.freeze({
    actionQueueUrl: operator.actionQueueUrl,
    actionTableName: operator.actionTableName,
    paymentMoved: false,
    publicMonitorBucketName:
      operator.publicMonitorBucketName,
    publicMonitorControlKey:
      "control.json",
    releaseId: operator.releaseId,
    repositorySha: operator.repositorySha,
    schema:
      "clockchain.aws-operator-runtime/v1",
    sessionId: operator.sessionId,
  });
}

function absolutePath(value) {
  if (
    typeof value !== "string" ||
    !value.startsWith("/") ||
    value.includes("\0")
  ) {
    fail();
  }
  return value;
}

function certificatePem(value, fingerprint) {
  try {
    if (
      typeof value !== "string" ||
      value.length === 0 ||
      Buffer.byteLength(value, "utf8") > 65_536
    ) {
      fail();
    }
    if (
      createHash("sha256")
        .update(new X509Certificate(value).raw)
        .digest("hex") !== fingerprint
    ) {
      fail();
    }
    return value;
  } catch (error) {
    if (
      error instanceof
      AwsOperatorWorkerEntrypointError
    ) {
      throw error;
    }
    fail();
  }
}

function taskConfig(value) {
  const input = exact(value, [
    "containerName",
    "securityGroupId",
    "subnetIds",
    "taskDefinitionArn",
  ]);
  if (
    !CONTAINER_NAME.test(input.containerName) ||
    !NETWORK_ID.test(input.securityGroupId) ||
    !Array.isArray(input.subnetIds) ||
    input.subnetIds.length < 2 ||
    input.subnetIds.length > 4 ||
    input.subnetIds.some(
      (subnet) => !NETWORK_ID.test(subnet),
    ) ||
    new Set(input.subnetIds).size !==
      input.subnetIds.length ||
    !TASK_DEFINITION_ARN.test(
      input.taskDefinitionArn,
    )
  ) {
    fail();
  }
  return Object.freeze({
    containerName: input.containerName,
    paymentMoved: false,
    securityGroupId: input.securityGroupId,
    subnetIds: Object.freeze([...input.subnetIds]),
    taskDefinitionArn: input.taskDefinitionArn,
  });
}

function taskConfigFields(value) {
  return taskConfig({
    containerName: value.containerName,
    securityGroupId: value.securityGroupId,
    subnetIds: value.subnetIds,
    taskDefinitionArn: value.taskDefinitionArn,
  });
}

function validateProductionOperator(value) {
  const operator = exact(
    value,
    PRODUCTION_OPERATOR_KEYS,
  );
  const base = validateOperator({
    actionQueueUrl: operator.actionQueueUrl,
    actionTableName: operator.actionTableName,
    paymentMoved: operator.paymentMoved,
    publicMonitorBucketName:
      operator.publicMonitorBucketName,
    publicMonitorControlKey:
      operator.publicMonitorControlKey,
    releaseId: operator.releaseId,
    repositorySha: operator.repositorySha,
    schema: operator.schema,
    sessionId: operator.sessionId,
  });
  const bootstrap = exact(
    operator.bootstrap,
    BOOTSTRAP_KEYS,
  );
  const approvedPayerPublicPath =
    `/var/lib/clockchain/approved-payer/releases/${base.releaseId}/approved-payer.json`;
  if (
    !SECRET_ARN.test(
      bootstrap.bootstrapBrokerCapabilitySecretArn,
    ) ||
    !SECRET_ARN.test(
      bootstrap.operatorKeySecretArn,
    )
  ) {
    fail();
  }
  for (const key of [
    "abortMarkerPath",
    "bootstrapStatePath",
    "payeeLaunchManifestPath",
    "payerLaunchManifestPath",
    "tunnelGrantPath",
  ]) {
    absolutePath(bootstrap[key]);
  }
  if (
    bootstrap.approvedPayerPublicPath !==
    approvedPayerPublicPath
  ) {
    fail();
  }
  const children = exact(operator.children, [
    "abort",
    "bootstrapApproval",
    "clusterArn",
    "funding",
    "rpcSecretArn",
    "verifier",
  ]);
  if (
    !CLUSTER_ARN.test(children.clusterArn) ||
    !SECRET_ARN.test(children.rpcSecretArn)
  ) {
    fail();
  }
  const funding = exact(children.funding, [
    "containerName",
    "createdAt",
    "expectedTreasuryAddress",
    "fundingRecordPath",
    "journalDirectory",
    "keystoreSecretArn",
    "passwordSecretArn",
    "securityGroupId",
    "subnetIds",
    "taskDefinitionArn",
  ]);
  if (
    !ISO_INSTANT.test(funding.createdAt) ||
    !ADDRESS.test(
      funding.expectedTreasuryAddress,
    ) ||
    !SECRET_ARN.test(
      funding.keystoreSecretArn,
    ) ||
    !SECRET_ARN.test(
      funding.passwordSecretArn,
    )
  ) {
    fail();
  }
  const verifier = exact(children.verifier, [
    "clockchainTokenSecretArn",
    "containerName",
    "securityGroupId",
    "subnetIds",
    "taskDefinitionArn",
  ]);
  if (
    !SECRET_ARN.test(
      verifier.clockchainTokenSecretArn,
    )
  ) {
    fail();
  }
  const coordinator = exact(operator.coordinator, [
    "clockchainTokenSecretArn",
    "clusterArn",
    "containerName",
    "operatorKeyId",
    "operatorKeySecretArn",
    "publicStaging",
    "relayUrl",
    "rpcSecretArn",
    "securityGroupId",
    "subnetIds",
    "taskDefinitionArn",
    "tlsCertificatePem",
    "tlsFingerprint",
  ]);
  if (
    !CLUSTER_ARN.test(coordinator.clusterArn) ||
    !SECRET_ARN.test(
      coordinator.clockchainTokenSecretArn,
    ) ||
    !SECRET_ARN.test(
      coordinator.operatorKeySecretArn,
    ) ||
    !SECRET_ARN.test(coordinator.rpcSecretArn) ||
    !SHA64.test(coordinator.tlsFingerprint)
  ) {
    fail();
  }
  certificatePem(
    coordinator.tlsCertificatePem,
    coordinator.tlsFingerprint,
  );
  const coordinatorRuntime =
    buildCoordinatorRuntimeInput({
      clockchainTokenSecretArn:
        coordinator.clockchainTokenSecretArn,
      operatorKeyId:
        coordinator.operatorKeyId,
      operatorKeySecretArn:
        coordinator.operatorKeySecretArn,
      paymentMoved: false,
      publicStaging:
        coordinator.publicStaging,
      releaseId: base.releaseId,
      releaseRoot:
        `/var/lib/clockchain/operator/releases/${base.releaseId}`,
      relayUrl: coordinator.relayUrl,
      repositorySha: base.repositorySha,
      rpcSecretArn: coordinator.rpcSecretArn,
      sessionId: base.sessionId,
      tlsCertificatePem:
        coordinator.tlsCertificatePem,
      tlsFingerprint:
        coordinator.tlsFingerprint,
    });
  return Object.freeze({
    ...base,
    bootstrap: Object.freeze({
      ...bootstrap,
      approvedPayerPublicPath,
    }),
    children: Object.freeze({
      abort: taskConfig(children.abort),
      bootstrapApproval: taskConfig(
        children.bootstrapApproval,
      ),
      clusterArn: children.clusterArn,
      funding: Object.freeze({
        ...taskConfigFields(funding),
        createdAt: funding.createdAt,
        expectedTreasuryAddress:
          funding.expectedTreasuryAddress,
        fundingRecordPath:
          absolutePath(
            funding.fundingRecordPath,
          ),
        journalDirectory:
          absolutePath(
            funding.journalDirectory,
          ),
        keystoreSecretArn:
          funding.keystoreSecretArn,
        passwordSecretArn:
          funding.passwordSecretArn,
      }),
      rpcSecretArn: children.rpcSecretArn,
      verifier: Object.freeze({
        ...taskConfigFields(verifier),
        clockchainTokenSecretArn:
          verifier.clockchainTokenSecretArn,
      }),
    }),
    coordinator: Object.freeze({
      ...taskConfigFields(coordinator),
      clockchainTokenSecretArn:
        coordinator.clockchainTokenSecretArn,
      clusterArn: coordinator.clusterArn,
      operatorKeyId:
        coordinator.operatorKeyId,
      operatorKeySecretArn:
        coordinator.operatorKeySecretArn,
      publicStaging:
        coordinatorRuntime.coordinator
          .publicStaging,
      relayUrl: coordinator.relayUrl,
      rpcSecretArn: coordinator.rpcSecretArn,
      tlsCertificatePem:
        coordinator.tlsCertificatePem,
      tlsFingerprint:
        coordinator.tlsFingerprint,
    }),
  });
}

function validateClients(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    value.dynamodb === null ||
    typeof value.dynamodb !== "object" ||
    typeof value.dynamodb.send !== "function" ||
    value.s3 === null ||
    typeof value.s3 !== "object" ||
    typeof value.s3.send !== "function" ||
    value.sqs === null ||
    typeof value.sqs !== "object" ||
    typeof value.sqs.send !== "function"
  ) {
    fail();
  }
  return value;
}

function requireEcs(clients) {
  if (
    clients.ecs === null ||
    typeof clients.ecs !== "object" ||
    typeof clients.ecs.send !== "function"
  ) {
    fail();
  }
  return clients.ecs;
}

function oneShotRuntimeInput(key, value) {
  return Object.freeze({
    [key]: Object.freeze(value),
    paymentMoved: false,
    schema: "clockchain.aws-runtime-input/v1",
  });
}

function clientToken(childTask, action, input) {
  return Object.freeze({
    childTask,
    action,
    fingerprint: createHash("sha256")
      .update(
        JSON.stringify({
          action,
          actionId: input.actionId,
          childTask,
          releaseId: input.releaseId,
          sessionId: input.sessionId,
        }),
        "utf8",
      )
      .digest("hex")
      .slice(0, 16),
  });
}

function createProductionBuildTransitions({
  clients,
  documentClient,
  operator,
}) {
  const ecs = requireEcs(clients);
  const launchRecord =
    createDurableOperatorLaunchRecord(
      createDynamoOperatorLaunchRecordStore({
        documentClient,
        tableName: operator.actionTableName,
      }),
    );
  const childLauncher =
    createOperatorChildLauncher({
      config: operator.children,
      launchPinnedTask: (input) =>
        launchPinnedTask(input, { ecs }),
      launchRecord,
      nowMs: () => Date.now(),
      readFundingRecord:
        readAwsFundingRecord,
      readFundingResult: async (input) =>
        readAwsFundingResult(
          `/var/lib/clockchain/funding-result/releases/${input.identity.releaseId}/actions/${input.identity.actionId}/funding-result.json`,
          {
            actionAtMs:
              input.identity.actionAtMs,
            actionId: input.identity.actionId,
            fundingRecordPath:
              operator.children.funding
                .fundingRecordPath,
            releaseId:
              input.identity.releaseId,
            repositorySha:
              input.identity.repositorySha,
            sessionId:
              input.identity.sessionId,
          },
        ),
      readVerifierHandoff:
        readAwsVerifierHandoff,
      readVerifierPublication:
        readAwsVerifierPublication,
      waitForPinnedTask: (input) =>
        waitForPinnedTask(input, { ecs }),
    });
  const bootstrapReader =
    createAwsOperatorBootstrapFingerprintReader({
      bootstrapStatePath:
        operator.bootstrap.bootstrapStatePath,
      nowMs: () => Date.now(),
      paymentMoved: false,
      releaseId: operator.releaseId,
      repositorySha: operator.repositorySha,
      sessionId: operator.sessionId,
    });
  return async (scope) => {
    const resultCache = new Map();
    const transitions =
      createAwsOperatorTransitions(scope, {
        abort: async (input) => {
          const launched = await launchPinnedTask(
            {
              clientToken: clientToken(
                "abort",
                "abort",
                input,
              ),
              config: {
                clusterArn:
                  operator.children.clusterArn,
                ...operator.children.abort,
              },
              runtimeInput: oneShotRuntimeInput(
                "abort",
                {
                  abortMarkerPath:
                    operator.bootstrap
                      .abortMarkerPath,
                  actionId: input.actionId,
                  expectedRevision:
                    input.expectedRevision,
                  paymentMoved: false,
                  releaseId: input.releaseId,
                  repositorySha:
                    input.repositorySha,
                  sessionId: input.sessionId,
                  tunnelGrantPath:
                    operator.bootstrap
                      .tunnelGrantPath,
                },
              ),
            },
            { ecs },
          );
          await waitForPinnedTask(
            {
              clusterArn:
                operator.children.clusterArn,
              containerName:
                operator.children.abort
                  .containerName,
              paymentMoved: false,
              taskArn: launched.taskArn,
            },
            { ecs },
          );
          return Object.freeze({
            paymentMoved: false,
            status: "ABORTED",
          });
        },
        activateTunnel: async () => {},
        approveAndSeal: async (input) => {
          const launched = await launchPinnedTask(
            {
              clientToken: clientToken(
                "approval",
                input.role,
                input,
              ),
              config: {
                clusterArn:
                  operator.children.clusterArn,
                ...operator.children
                  .bootstrapApproval,
              },
              runtimeInput: oneShotRuntimeInput(
                "bootstrapApproval",
                {
                  claimFingerprint:
                    input.claimFingerprint,
                  approvedPayerPublicPath:
                    operator.bootstrap
                      .approvedPayerPublicPath,
                  operatorKeySecretArn:
                    operator.bootstrap
                      .operatorKeySecretArn,
                  bootstrapBrokerCapabilitySecretArn:
                    operator.bootstrap
                      .bootstrapBrokerCapabilitySecretArn,
                  bootstrapBrokerUrl:
                    operator.bootstrap
                      .bootstrapBrokerUrl,
                  bootstrapStatePath:
                    operator.bootstrap
                      .bootstrapStatePath,
                  expectedRevision:
                    input.expectedRevision,
                  operatorKeyId:
                    operator.bootstrap
                      .operatorKeyId,
                  paymentMoved: false,
                  payeeLaunchManifestPath:
                    operator.bootstrap
                      .payeeLaunchManifestPath,
                  payerLaunchManifestPath:
                    operator.bootstrap
                      .payerLaunchManifestPath,
                  publicMcpHostname:
                    operator.bootstrap
                      .publicMcpHostname,
                  releaseId: input.releaseId,
                  repositorySha:
                    input.repositorySha,
                  role: input.role,
                  sessionId: input.sessionId,
                  tunnelGrantPath:
                    operator.bootstrap
                      .tunnelGrantPath,
                },
              ),
            },
            { ecs },
          );
          await waitForPinnedTask(
            {
              clusterArn:
                operator.children.clusterArn,
              containerName:
                operator.children
                  .bootstrapApproval
                  .containerName,
              paymentMoved: false,
              taskArn: launched.taskArn,
            },
            { ecs },
          );
          return Object.freeze({
            paymentMoved: false,
            status: "APPROVED",
          });
        },
        launch: async (kind, input) => {
          if (kind === "coordinator") {
            const launched =
              await launchPinnedTask(
                {
                  clientToken: clientToken(
                    "coordinator",
                    "launch",
                    input,
                  ),
                  config: {
                    clusterArn:
                      operator.coordinator
                        .clusterArn,
                    containerName:
                      operator.coordinator
                        .containerName,
                    paymentMoved: false,
                    securityGroupId:
                      operator.coordinator
                        .securityGroupId,
                    subnetIds:
                      operator.coordinator
                        .subnetIds,
                    taskDefinitionArn:
                      operator.coordinator
                        .taskDefinitionArn,
                  },
                  runtimeInput:
                    buildCoordinatorRuntimeInput({
                      clockchainTokenSecretArn:
                        operator.coordinator
                          .clockchainTokenSecretArn,
                      operatorKeyId:
                        operator.coordinator
                          .operatorKeyId,
                      operatorKeySecretArn:
                        operator.coordinator
                          .operatorKeySecretArn,
                      paymentMoved: false,
                      publicStaging:
                        operator.coordinator
                          .publicStaging,
                      releaseId: input.releaseId,
                      releaseRoot:
                        `/var/lib/clockchain/operator/releases/${input.releaseId}`,
                      relayUrl:
                        operator.coordinator
                          .relayUrl,
                      repositorySha:
                        input.repositorySha,
                      rpcSecretArn:
                        operator.coordinator
                          .rpcSecretArn,
                      sessionId:
                        input.sessionId,
                      tlsCertificatePem:
                        operator.coordinator
                          .tlsCertificatePem,
                      tlsFingerprint:
                        operator.coordinator
                          .tlsFingerprint,
                    }),
                },
                { ecs },
              );
            return launched;
          }
          const childResult =
            await childLauncher.launch(kind, input);
          resultCache.set(
            `${kind}:${input.actionId}`,
            childResult,
          );
          return Object.freeze({
            paymentMoved: false,
            status: "RUNNING",
          });
        },
        readExpectedClaimFingerprint:
          (input) =>
            bootstrapReader
              .readExpectedClaimFingerprint(
                input,
              ),
        readResult: async (kind, input) => {
          const key = `${kind}:${input.actionId}`;
          const cached = resultCache.get(key);
          if (cached === undefined) fail();
          resultCache.delete(key);
          return cached;
        },
        wait: async () => {},
      });
    return transitions;
  };
}

function validateDocumentClient(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    typeof value.send !== "function"
  ) {
    fail();
  }
  return value;
}

export async function main({
  buildTransitions,
  createClients = createAwsRuntimeClients,
  createDocumentClient = (client) =>
    DynamoDBDocumentClient.from(client),
  env = process.env,
  run = runAwsOperatorLoop,
  signal,
} = {}) {
  try {
    const input = exact(
      parseRuntimeInput(env),
      TOP_LEVEL_KEYS,
    );
    const operator =
      buildTransitions === undefined
        ? validateProductionOperator(
            input.operator,
          )
        : validateOperator(input.operator);
    const runtimeOperator = validateOperator({
      actionQueueUrl: operator.actionQueueUrl,
      actionTableName: operator.actionTableName,
      paymentMoved: operator.paymentMoved,
      publicMonitorBucketName:
        operator.publicMonitorBucketName,
      publicMonitorControlKey:
        operator.publicMonitorControlKey,
      releaseId: operator.releaseId,
      repositorySha: operator.repositorySha,
      schema: operator.schema,
      sessionId: operator.sessionId,
    });
    if (
      typeof createClients !== "function" ||
      typeof createDocumentClient !==
        "function" ||
      !(
        buildTransitions === undefined ||
        typeof buildTransitions ===
          "function"
      ) ||
      typeof run !== "function"
    ) {
      fail();
    }
    const clients = validateClients(
      await createClients(),
    );
    const documentClient =
      validateDocumentClient(
        createDocumentClient(clients.dynamodb),
      );
    const activeBuildTransitions =
      buildTransitions ??
      createProductionBuildTransitions({
        clients,
        documentClient,
        operator,
      });
    return await run(runtimeOperator, {
      buildTransitions:
        activeBuildTransitions,
      documentClient,
      s3: clients.s3,
      signal,
      sqs: clients.sqs,
    });
  } catch (error) {
    if (
      error instanceof
      AwsOperatorWorkerEntrypointError
    ) {
      throw error;
    }
    fail();
  }
}

if (
  process.argv[1] !== undefined &&
  import.meta.url ===
    new URL(`file://${process.argv[1]}`).href
) {
  main().catch(() => {
    process.stderr.write(
      "AWS_OPERATOR_WORKER_ENTRYPOINT_FAILED\n",
    );
    process.exitCode = 1;
  });
}
