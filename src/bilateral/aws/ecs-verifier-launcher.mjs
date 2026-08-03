import { types } from "node:util";

export const AWS_VERIFIER_EVIDENCE_SCHEMA =
  "clockchain.aws-verifier-evidence/v1";
export const AWS_VERIFIER_PUBLICATION_SCHEMA =
  "clockchain.aws-verifier-task-publication/v1";

const LAUNCH_KEYS = Object.freeze([
  "evidenceDescriptor",
  "expectedRevision",
  "releaseId",
  "repositorySha",
  "sessionId",
]);
const EVIDENCE_KEYS = Object.freeze([
  "descriptorDigest",
  "evidenceDigest",
  "paymentMoved",
  "schema",
  "subjectRun",
]);
const DEFINITION_KEYS = Object.freeze([
  "containerName",
  "imageDigest",
  "mounts",
  "secretNames",
  "taskDefinitionArn",
]);
const MOUNT_KEYS = Object.freeze([
  "accessPointArn",
  "containerPath",
  "readOnly",
]);
const RUN_RESULT_KEYS = Object.freeze([
  "failures",
  "tasks",
]);
const TASK_KEYS = Object.freeze(["taskArn"]);
const STOPPED_KEYS = Object.freeze([
  "exitCode",
  "stoppedAtMs",
  "taskArn",
]);
const PUBLICATION_KEYS = Object.freeze([
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
const SHA40 = /^[0-9a-f]{40}$/;
const SHA64 = /^[0-9a-f]{64}$/;
const UUID_V4 =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const RELEASE_ID =
  /^release-[0-9a-f]{16}$/;
const SESSION_ID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const IMAGE_DIGEST =
  /^sha256:[0-9a-f]{64}$/;
const TASK_DEFINITION_ARN =
  /^arn:aws(?:-[a-z]+)?:ecs:[a-z0-9-]+:[0-9]{12}:task-definition\/[A-Za-z0-9_-]{1,255}:[1-9][0-9]*$/;
const TASK_ARN =
  /^arn:aws(?:-[a-z]+)?:ecs:[a-z0-9-]+:[0-9]{12}:task\/(?:[A-Za-z0-9_-]{1,255}\/)?[0-9a-f]{32}$/;
const ACCESS_POINT_ARN =
  /^arn:aws(?:-[a-z]+)?:elasticfilesystem:[a-z0-9-]+:[0-9]{12}:access-point\/fsap-[0-9a-f]{17}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const ALLOWED_SECRETS = Object.freeze([
  "CLOCKCHAIN_TOKEN",
  "SEPOLIA_RPC_URL",
]);

export class EcsVerifierLaunchError extends Error {
  constructor() {
    super("ECS verifier launch failed safely.");
    this.name = "EcsVerifierLaunchError";
    this.code = "ECS_VERIFIER_LAUNCH_INVALID";
    this.category = "verification";
  }
}

function invalid() {
  throw new EcsVerifierLaunchError();
}

function sanitize(error) {
  if (error instanceof EcsVerifierLaunchError) {
    throw error;
  }
  invalid();
}

function exactObject(value, keys) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    types.isProxy(value) ||
    Object.getPrototypeOf(value) !==
      Object.prototype
  ) {
    invalid();
  }
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== keys.length ||
    keys.some((key, index) =>
      ownKeys[index] !== key)
  ) {
    invalid();
  }
  for (const key of keys) {
    const descriptor =
      Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor?.enumerable !== true ||
      !Object.hasOwn(descriptor, "value")
    ) {
      invalid();
    }
  }
  return value;
}

function stringPattern(value, pattern) {
  if (
    typeof value !== "string" ||
    !pattern.test(value)
  ) {
    invalid();
  }
  return value;
}

function revision(value) {
  if (
    !Number.isSafeInteger(value) ||
    value < 0
  ) {
    invalid();
  }
  return value;
}

function timestamp(value) {
  if (
    typeof value !== "string" ||
    !DECIMAL.test(value) ||
    BigInt(value) >
      BigInt(Number.MAX_SAFE_INTEGER)
  ) {
    invalid();
  }
  return Number(value);
}

function clock(value) {
  if (
    !Number.isSafeInteger(value) ||
    value < 0
  ) {
    invalid();
  }
  return value;
}

function evidence(value) {
  const descriptor = exactObject(
    value,
    EVIDENCE_KEYS,
  );
  if (
    !SHA64.test(descriptor.descriptorDigest) ||
    !SHA64.test(descriptor.evidenceDigest) ||
    descriptor.paymentMoved !== false ||
    descriptor.schema !==
      AWS_VERIFIER_EVIDENCE_SCHEMA ||
    !["rehearsal", "stakeholder"].includes(
      descriptor.subjectRun,
    )
  ) {
    invalid();
  }
  return Object.freeze({ ...descriptor });
}

function mount(value) {
  const data = exactObject(value, MOUNT_KEYS);
  stringPattern(
    data.accessPointArn,
    ACCESS_POINT_ARN,
  );
  if (
    !["/evidence", "/verdict"].includes(
      data.containerPath,
    ) ||
    typeof data.readOnly !== "boolean"
  ) {
    invalid();
  }
  return data;
}

function validateDefinition(
  value,
  {
    evidenceAccessPointArn,
    imageDigest,
    outputAccessPointArn,
    taskDefinitionArn,
  },
) {
  const definition = exactObject(
    value,
    DEFINITION_KEYS,
  );
  if (
    definition.containerName !== "verifier" ||
    definition.imageDigest !== imageDigest ||
    definition.taskDefinitionArn !==
      taskDefinitionArn ||
    !Array.isArray(definition.mounts) ||
    definition.mounts.length !== 2 ||
    !Array.isArray(definition.secretNames) ||
    definition.secretNames.length !==
      ALLOWED_SECRETS.length ||
    definition.secretNames.some(
      (name, index) =>
        name !== ALLOWED_SECRETS[index],
    )
  ) {
    invalid();
  }
  const mounts = definition.mounts.map(mount);
  if (
    mounts[0].accessPointArn !==
      evidenceAccessPointArn ||
    mounts[0].containerPath !== "/evidence" ||
    mounts[0].readOnly !== true ||
    mounts[1].accessPointArn !==
      outputAccessPointArn ||
    mounts[1].containerPath !== "/verdict" ||
    mounts[1].readOnly !== false
  ) {
    invalid();
  }
}

function validateRunResult(value) {
  const result = exactObject(
    value,
    RUN_RESULT_KEYS,
  );
  if (
    !Array.isArray(result.failures) ||
    result.failures.length !== 0 ||
    !Array.isArray(result.tasks) ||
    result.tasks.length !== 1
  ) {
    invalid();
  }
  const task = exactObject(
    result.tasks[0],
    TASK_KEYS,
  );
  return stringPattern(task.taskArn, TASK_ARN);
}

function validateStopped(value, taskArn) {
  const result = exactObject(
    value,
    STOPPED_KEYS,
  );
  const stoppedAtMs =
    timestamp(result.stoppedAtMs);
  if (
    result.exitCode !== 0 ||
    result.taskArn !== taskArn
  ) {
    invalid();
  }
  return stoppedAtMs;
}

function validatePublication(
  value,
  {
    actionAtMs,
    attemptId,
    evidenceDigest,
    expectedRevision,
    repositorySha,
    stoppedAtMs,
    taskArn,
  },
) {
  const publication = exactObject(
    value,
    PUBLICATION_KEYS,
  );
  const writtenAtMs =
    timestamp(publication.writtenAtMs);
  if (
    publication.attemptId !== attemptId ||
    publication.evidenceDigest !==
      evidenceDigest ||
    publication.paymentMoved !== false ||
    !SHA64.test(
      publication.publicationDigest,
    ) ||
    publication.repositorySha !==
      repositorySha ||
    publication.revision !==
      expectedRevision ||
    publication.schema !==
      AWS_VERIFIER_PUBLICATION_SCHEMA ||
    publication.status !==
      "VERIFICATION_PASSED" ||
    publication.taskArn !== taskArn ||
    writtenAtMs < actionAtMs ||
    writtenAtMs > stoppedAtMs
  ) {
    invalid();
  }
  return publication;
}

export function createEcsVerifierLauncher({
  ecs,
  evidenceAccessPointArn,
  imageDigest,
  nowMs = Date.now,
  outputAccessPointArn,
  randomUUID,
  readCurrentRevision,
  readPublication,
  taskDefinitionArn,
} = {}) {
  try {
    if (
      ecs === null ||
      typeof ecs !== "object" ||
      types.isProxy(ecs) ||
      typeof ecs.describeTaskDefinition !==
        "function" ||
      typeof ecs.runTask !== "function" ||
      typeof ecs.waitForTask !== "function" ||
      typeof randomUUID !== "function" ||
      typeof readCurrentRevision !== "function" ||
      typeof readPublication !== "function" ||
      typeof nowMs !== "function"
    ) {
      invalid();
    }
    const expectedTaskDefinition =
      stringPattern(
        taskDefinitionArn,
        TASK_DEFINITION_ARN,
      );
    const expectedImage = stringPattern(
      imageDigest,
      IMAGE_DIGEST,
    );
    const expectedEvidenceAccessPoint =
      stringPattern(
        evidenceAccessPointArn,
        ACCESS_POINT_ARN,
      );
    const expectedOutputAccessPoint =
      stringPattern(
        outputAccessPointArn,
        ACCESS_POINT_ARN,
      );
    if (
      expectedEvidenceAccessPoint ===
        expectedOutputAccessPoint
    ) {
      invalid();
    }
    const seenTaskArns = new Set();
    const seenAttemptIds = new Set();
    return Object.freeze({
      async launch(value) {
        try {
          const input = exactObject(
            value,
            LAUNCH_KEYS,
          );
          const expectedRevision = revision(
            input.expectedRevision,
          );
          const repositorySha = stringPattern(
            input.repositorySha,
            SHA40,
          );
          const releaseId = stringPattern(
            input.releaseId,
            RELEASE_ID,
          );
          const sessionId = stringPattern(
            input.sessionId,
            SESSION_ID,
          );
          const evidenceDescriptor =
            evidence(input.evidenceDescriptor);
          validateDefinition(
            await ecs.describeTaskDefinition({
              taskDefinitionArn:
                expectedTaskDefinition,
            }),
            {
              evidenceAccessPointArn:
                expectedEvidenceAccessPoint,
              imageDigest: expectedImage,
              outputAccessPointArn:
                expectedOutputAccessPoint,
              taskDefinitionArn:
                expectedTaskDefinition,
            },
          );
          if (
            revision(
              await readCurrentRevision({
                releaseId,
                sessionId,
              }),
            ) !== expectedRevision
          ) {
            invalid();
          }
          const actionAtMs = clock(nowMs());
          const attemptId = stringPattern(
            randomUUID(),
            UUID_V4,
          );
          if (seenAttemptIds.has(attemptId)) {
            invalid();
          }
          seenAttemptIds.add(attemptId);
          const taskArn = validateRunResult(
            await ecs.runTask({
              action: "VERIFY",
              attemptId,
              evidenceDescriptor,
              expectedRevision,
              releaseId,
              repositorySha,
              sessionId,
              taskDefinitionArn:
                expectedTaskDefinition,
            }),
          );
          if (seenTaskArns.has(taskArn)) {
            invalid();
          }
          seenTaskArns.add(taskArn);
          const stoppedAtMs = validateStopped(
            await ecs.waitForTask({ taskArn }),
            taskArn,
          );
          if (stoppedAtMs < actionAtMs) {
            invalid();
          }
          const publication =
            validatePublication(
              await readPublication({
                attemptId,
                evidenceDigest:
                  evidenceDescriptor.evidenceDigest,
                expectedRevision,
                releaseId,
                repositorySha,
                sessionId,
                taskArn,
              }),
              {
                actionAtMs,
                attemptId,
                evidenceDigest:
                  evidenceDescriptor.evidenceDigest,
                expectedRevision,
                repositorySha,
                stoppedAtMs,
                taskArn,
              },
            );
          return Object.freeze({
            attemptId,
            publicationDigest:
              publication.publicationDigest,
            status: publication.status,
            taskArn,
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
