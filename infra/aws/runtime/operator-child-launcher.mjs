import {
  buildFundingRuntimeInput,
  buildVerifierRuntimeInput,
} from "./operator-task-inputs.mjs";
import {
  deriveOperatorLaunchAttemptId,
} from "./operator-launch-record.mjs";
import { types } from "node:util";

const SHA40 = /^[0-9a-f]{40}$/;
const RELEASE =
  /^release-[0-9a-f]{16}$/;
const SESSION =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const UUID = SESSION;
const SHA64 = /^[0-9a-f]{64}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const TASK_ARN =
  /^arn:aws(?:-[a-z]+)?:ecs:[a-z0-9-]+:[0-9]{12}:task\/(?:[A-Za-z0-9_-]{1,255}\/)?[0-9a-f]{32}$/;

export class AwsOperatorChildLauncherError extends Error {
  constructor() {
    super(
      "AWS operator child launcher failed safely.",
    );
    this.name =
      "AwsOperatorChildLauncherError";
    this.code =
      "AWS_OPERATOR_CHILD_LAUNCHER_INVALID";
    this.category = "verification";
  }
}

function fail() {
  throw new AwsOperatorChildLauncherError();
}

function sanitize(error) {
  if (
    error instanceof
    AwsOperatorChildLauncherError
  ) {
    throw error;
  }
  fail();
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
    keys.some((key, index) =>
      ownKeys[index] !== key)
  ) {
    fail();
  }
  const snapshot = {};
  for (const key of keys) {
    const descriptor =
      Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor?.enumerable !== true ||
      !Object.hasOwn(descriptor, "value")
    ) {
      fail();
    }
    snapshot[key] = descriptor.value;
  }
  return Object.freeze(snapshot);
}

function common(value, kind) {
  const input = exact(value, [
    "actionId",
    "expectedRevision",
    "paymentMoved",
    "releaseId",
    "repositorySha",
    "sessionId",
  ]);
  if (
    !UUID.test(input.actionId) ||
    !Number.isSafeInteger(
      input.expectedRevision,
    ) ||
    input.expectedRevision < 0 ||
    input.paymentMoved !== false ||
    !RELEASE.test(input.releaseId) ||
    !SHA40.test(input.repositorySha) ||
    !SESSION.test(input.sessionId)
  ) {
    fail();
  }
  return Object.freeze({
    actionId: input.actionId,
    expectedRevision:
      input.expectedRevision,
    kind,
    releaseId: input.releaseId,
    repositorySha:
      input.repositorySha,
    sessionId: input.sessionId,
  });
}

function childConfig(config, kind) {
  const root = exact(config, [
    "clusterArn",
    "funding",
    "rpcSecretArn",
    "verifier",
  ]);
  const child = root[kind];
  if (!plain(child)) fail();
  return { child, root };
}

function taskArn(value) {
  if (
    typeof value !== "string" ||
    !TASK_ARN.test(value)
  ) {
    fail();
  }
  return value;
}

function launchedTask(value) {
  const input = exact(value, [
    "paymentMoved",
    "status",
    "taskArn",
  ]);
  if (
    input.paymentMoved !== false ||
    input.status !== "RUNNING"
  ) {
    fail();
  }
  return taskArn(input.taskArn);
}

function waitedTask(value, arn) {
  const input = exact(value, [
    "paymentMoved",
    "status",
    "taskArn",
  ]);
  if (
    input.paymentMoved !== false ||
    input.status !== "SUCCEEDED" ||
    input.taskArn !== arn
  ) {
    fail();
  }
}

function fundingResult(value, arn) {
  const keys = Reflect.ownKeys(value ?? {});
  const input =
    keys.length === 2
      ? exact(value, ["paymentMoved", "status"])
      : exact(value, [
          "paymentMoved",
          "status",
          "taskArn",
        ]);
  if (
    input.paymentMoved !== false ||
    input.status !== "FUNDED" ||
    (
      Object.hasOwn(input, "taskArn") &&
      input.taskArn !== arn
    )
  ) {
    fail();
  }
  return Object.freeze({
    paymentMoved: false,
    status: "FUNDED",
  });
}

function verifierPublication(value, {
  actionAtMs,
  attemptId,
  evidenceDigest,
  expectedRevision,
  repositorySha,
  taskArn: arn,
}) {
  const input = exact(value, [
    "attemptId",
    "evidenceDigest",
    "paymentMoved",
    "publicationDigest",
    "repositorySha",
    "revision",
    "schema",
    "status",
    "taskArn",
    "writtenAtMs",
  ]);
  if (
    input.attemptId !== attemptId ||
    input.evidenceDigest !==
      evidenceDigest ||
    input.paymentMoved !== false ||
    !SHA64.test(input.publicationDigest) ||
    input.repositorySha !== repositorySha ||
    input.revision !== expectedRevision ||
    input.schema !==
      "clockchain.aws-verifier-task-publication/v1" ||
    input.status !==
      "VERIFICATION_PASSED" ||
    input.taskArn !== arn ||
    typeof input.writtenAtMs !== "string" ||
    !DECIMAL.test(input.writtenAtMs) ||
    BigInt(input.writtenAtMs) <
      BigInt(actionAtMs)
  ) {
    fail();
  }
  return Object.freeze(input);
}

function verifierHandoff(value, identity) {
  const input = exact(value, [
    "descriptorDigest",
    "descriptorPath",
    "evidenceDigest",
    "mandateDigest",
    "payerMandatePath",
    "payeeResultsPath",
    "payerResultsPath",
    "paymentMoved",
    "paymentRequestPath",
    "publicationPath",
    "releaseId",
    "repositorySha",
    "requestDigest",
    "schema",
    "sessionDigest",
    "sessionId",
    "subjectRun",
  ]);
  const evidenceRoot =
    `/var/lib/clockchain/evidence/releases/${identity.releaseId}/stakeholder`;
  if (
    input.descriptorPath !==
      `${evidenceRoot}/descriptor.json` ||
    input.payerMandatePath !==
      `${evidenceRoot}/payer-mandate.json` ||
    input.paymentRequestPath !==
      `${evidenceRoot}/payment-request.json` ||
    input.payerResultsPath !==
      `${evidenceRoot}/payer-results` ||
    input.payeeResultsPath !==
      `${evidenceRoot}/payee-results` ||
    input.publicationPath !==
      `/var/lib/clockchain/verifier-output/releases/${identity.releaseId}/stakeholder-publication.json` ||
    input.paymentMoved !== false ||
    input.releaseId !== identity.releaseId ||
    input.repositorySha !==
      identity.repositorySha ||
    input.schema !==
      "clockchain.aws-verifier-handoff/v1" ||
    input.sessionId !== identity.sessionId ||
    input.subjectRun !== "stakeholder" ||
    !SHA64.test(input.descriptorDigest) ||
    !SHA64.test(input.evidenceDigest) ||
    !SHA64.test(input.mandateDigest) ||
    !SHA64.test(input.requestDigest) ||
    !SHA64.test(input.sessionDigest)
  ) {
    fail();
  }
  return input;
}

async function launchOrAdopt({
  actionAtMs,
  config,
  identity,
  launchPinnedTask,
  launchRecord,
  runtimeInput,
}) {
  const prepared = await launchRecord.prepare({
    actionAtMs,
    identity,
    runtimeInput,
  });
  if (prepared.taskArn !== null) {
    return taskArn(prepared.taskArn);
  }
  const result = await launchPinnedTask({
    clientToken: prepared.clientToken,
    config,
    runtimeInput,
  });
  const arn = launchedTask(result);
  await launchRecord.adoptTask({
    identity,
    runtimeInput,
    taskArn: arn,
  });
  return arn;
}

export function createOperatorChildLauncher(
  dependencies = {},
) {
  try {
    const required = [
      "config",
      "launchRecord",
      "launchPinnedTask",
      "nowMs",
      "readFundingRecord",
      "readFundingResult",
      "readVerifierHandoff",
      "readVerifierPublication",
      "waitForPinnedTask",
    ];
    if (
      !plain(dependencies) ||
      required.some(
        (key) => dependencies[key] === undefined,
      )
    ) {
      fail();
    }
    return Object.freeze({
      async launch(kind, value) {
        try {
          if (!["funding", "verifier"].includes(kind)) {
            fail();
          }
          const identity = common(value, kind);
          const { child, root } = childConfig(
            dependencies.config,
            kind,
          );
          if (kind === "funding") {
            const recordPath =
              child.fundingRecordPath;
            await dependencies.readFundingRecord({
              path: recordPath,
            });
            const actionAtMs =
              dependencies.nowMs();
            const runtimeInput =
              buildFundingRuntimeInput({
                createdAt: child.createdAt,
                expectedTreasuryAddress:
                  child.expectedTreasuryAddress,
                fundingRecordPath: recordPath,
                journalDirectory:
                  child.journalDirectory,
                keystoreSecretArn:
                  child.keystoreSecretArn,
                passwordSecretArn:
                  child.passwordSecretArn,
                paymentMoved: false,
                releaseId: identity.releaseId,
                repositorySha:
                  identity.repositorySha,
                rpcSecretArn:
                  root.rpcSecretArn,
                sessionId: identity.sessionId,
              });
            const arn = await launchOrAdopt({
              actionAtMs,
              config: {
                clusterArn: root.clusterArn,
                containerName:
                  child.containerName,
                paymentMoved: false,
                securityGroupId:
                  child.securityGroupId,
                subnetIds: child.subnetIds,
                taskDefinitionArn:
                  child.taskDefinitionArn,
              },
              identity,
              launchPinnedTask:
                dependencies.launchPinnedTask,
              launchRecord:
                dependencies.launchRecord,
              runtimeInput,
            });
            waitedTask(
              await dependencies.waitForPinnedTask({
                clusterArn: root.clusterArn,
                containerName:
                  child.containerName,
                paymentMoved: false,
                taskArn: arn,
              }),
              arn,
            );
            return fundingResult(
              await dependencies.readFundingResult({
                identity,
                taskArn: arn,
              }),
              arn,
            );
          }
          const handoff = verifierHandoff(
            await dependencies.readVerifierHandoff({
              path:
                `/var/lib/clockchain/operator/releases/${identity.releaseId}/verifier-handoff-stakeholder.json`,
            }),
            identity,
          );
          const attemptId =
            deriveOperatorLaunchAttemptId(
              identity,
            );
          const existing =
            typeof dependencies.launchRecord
              .read === "function"
              ? await dependencies.launchRecord.read({
                  identity,
                })
              : null;
          const actionAtMs =
            existing?.actionAtMs ??
            dependencies.nowMs();
          const runtimeInput =
            buildVerifierRuntimeInput({
              actionAtMs,
              attemptId,
              attemptRoot:
                `/var/lib/clockchain/verifier-output/releases/${identity.releaseId}/attempts/${attemptId}`,
              clockchainTokenSecretArn:
                child.clockchainTokenSecretArn,
              descriptorPath:
                handoff.descriptorPath,
              evidenceDigest:
                handoff.evidenceDigest,
              expectedRevision:
                identity.expectedRevision,
              mandateDigest:
                handoff.mandateDigest,
              payerMandatePath:
                handoff.payerMandatePath,
              payeeResultsPath:
                handoff.payeeResultsPath,
              payerResultsPath:
                handoff.payerResultsPath,
              paymentMoved: false,
              paymentRequestPath:
                handoff.paymentRequestPath,
              publicationPath:
                handoff.publicationPath,
              releaseId: identity.releaseId,
              repositorySha:
                identity.repositorySha,
              requestDigest:
                handoff.requestDigest,
              rpcSecretArn:
                root.rpcSecretArn,
              sessionDigest:
                handoff.sessionDigest,
              sessionId: identity.sessionId,
            });
          const arn = await launchOrAdopt({
            actionAtMs,
            config: {
              clusterArn: root.clusterArn,
              containerName:
                child.containerName,
              paymentMoved: false,
              securityGroupId:
                child.securityGroupId,
              subnetIds: child.subnetIds,
              taskDefinitionArn:
                child.taskDefinitionArn,
            },
            identity,
            launchPinnedTask:
              dependencies.launchPinnedTask,
            launchRecord:
              dependencies.launchRecord,
            runtimeInput,
          });
          waitedTask(
            await dependencies.waitForPinnedTask({
              clusterArn: root.clusterArn,
              containerName:
                child.containerName,
              paymentMoved: false,
              taskArn: arn,
            }),
            arn,
          );
          const adopted =
            await dependencies.launchRecord.prepare({
              actionAtMs,
              identity,
              runtimeInput,
            });
          const publication =
            verifierPublication(
              await dependencies.readVerifierPublication({
                expectedRevision:
                  identity.expectedRevision,
                handoff,
                path: handoff.publicationPath,
              }),
              {
                actionAtMs:
                  adopted.actionAtMs,
                attemptId:
                  adopted.attemptId,
                evidenceDigest:
                  handoff.evidenceDigest,
                expectedRevision:
                  identity.expectedRevision,
                repositorySha:
                  identity.repositorySha,
                taskArn: arn,
              },
            );
          return Object.freeze({
            paymentMoved: false,
            publicationDigest:
              publication.publicationDigest,
            status: "VERIFICATION_PASSED",
          });
        } catch (error) {
          sanitize(error);
        }
      },
    });
  } catch (error) {
    sanitize(error);
  }
}
