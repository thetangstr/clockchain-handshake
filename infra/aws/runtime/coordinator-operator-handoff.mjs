import {
  createHash,
} from "node:crypto";
import {
  constants,
} from "node:fs";
import {
  lstat,
  open,
} from "node:fs/promises";
import {
  dirname,
  isAbsolute,
  resolve,
} from "node:path";
import { types } from "node:util";

import {
  validateFundingRecord,
} from "../../../src/bilateral/funding/record.mjs";

const MAX_BYTES = 262_144;
const HANDOFF_KEYS = Object.freeze([
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
const RELEASE = /^release-[0-9a-f]{16}$/;
const SESSION =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA40 = /^[0-9a-f]{40}$/;
const SHA64 = /^[0-9a-f]{64}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const ATTEMPT_ID = SESSION;
const TASK_ARN =
  /^arn:aws(?:-[a-z]+)?:ecs:[a-z0-9-]+:[0-9]{12}:task\/(?:[A-Za-z0-9_-]{1,255}\/)?[0-9a-f]{32}$/;

export class AwsCoordinatorOperatorHandoffError extends Error {
  constructor() {
    super(
      "AWS coordinator operator handoff failed safely.",
    );
    this.name =
      "AwsCoordinatorOperatorHandoffError";
    this.code =
      "AWS_COORDINATOR_OPERATOR_HANDOFF_INVALID";
    this.category = "verification";
  }
}

function fail() {
  throw new AwsCoordinatorOperatorHandoffError();
}

function sanitize(error) {
  if (
    error instanceof
    AwsCoordinatorOperatorHandoffError
  ) {
    throw error;
  }
  fail();
}

function fileSystem(dependencies = {}) {
  const supplied = dependencies.fileSystem ?? {};
  if (
    supplied === null ||
    typeof supplied !== "object" ||
    Array.isArray(supplied)
  ) {
    fail();
  }
  return Object.freeze({
    lstat: supplied.lstat ?? lstat,
    open: supplied.open ?? open,
  });
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

function exactInput(value, keys) {
  try {
    return exact(value, keys);
  } catch (error) {
    sanitize(error);
  }
}

function absolutePath(path) {
  if (
    typeof path !== "string" ||
    !isAbsolute(path) ||
    resolve(path) !== path ||
    /[\u0000-\u001f\u007f]/u.test(path)
  ) {
    fail();
  }
  return path;
}

function sameFile(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.nlink === right.nlink &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs
  );
}

function privateFile(stats) {
  return (
    stats.isFile() &&
    !stats.isSymbolicLink() &&
    stats.nlink === 1 &&
    (stats.mode & 0o777) === 0o600 &&
    stats.size > 0 &&
    stats.size <= MAX_BYTES
  );
}

async function syncParent(path, fs) {
  const handle = await fs.open(
    dirname(path),
    constants.O_RDONLY,
  );
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function readPinned(path, deps) {
  const target = absolutePath(path);
  const fs = fileSystem(deps);
  try {
    const before = await fs.lstat(target);
    if (!privateFile(before)) fail();
    const handle = await fs.open(
      target,
      constants.O_RDONLY |
        (constants.O_NOFOLLOW ?? 0) |
        constants.O_NONBLOCK,
    );
    try {
      const opened = await handle.stat();
      if (!privateFile(opened) || !sameFile(before, opened)) {
        fail();
      }
      const bytes = await handle.readFile();
      const after = await fs.lstat(target);
      const afterOpen = await handle.stat();
      if (
        bytes.length !== before.size ||
        !sameFile(before, after) ||
        !sameFile(before, afterOpen)
      ) {
        fail();
      }
      return bytes;
    } finally {
      await handle.close();
    }
  } catch (error) {
    sanitize(error);
  }
}

async function writeExclusiveOrAdopt(path, bytes, deps) {
  const target = absolutePath(path);
  const fs = fileSystem(deps);
  let handle;
  try {
    handle = await fs.open(
      target,
      constants.O_WRONLY |
        constants.O_CREAT |
        constants.O_EXCL |
        (constants.O_NOFOLLOW ?? 0),
      0o600,
    );
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await syncParent(target, fs);
  } catch (error) {
    await handle?.close().catch(() => {});
    if (error?.code !== "EEXIST") {
      sanitize(error);
    }
    const existing = await readPinned(target, deps);
    if (!existing.equals(bytes)) fail();
    await syncParent(target, fs);
  }
}

function parseCanonical(bytes) {
  try {
    if (
      bytes.length === 0 ||
      bytes[bytes.length - 1] !== 0x0a
    ) {
      fail();
    }
    const text = bytes.toString("utf8");
    const parsed = JSON.parse(text.slice(0, -1));
    if (`${JSON.stringify(parsed)}\n` !== text) {
      fail();
    }
    return parsed;
  } catch (error) {
    sanitize(error);
  }
}

function fundingPayload(record) {
  try {
    const checked = validateFundingRecord(record);
    return Object.freeze({
      bytes: Buffer.from(
        `${JSON.stringify(checked)}\n`,
        "utf8",
      ),
      checked,
    });
  } catch (error) {
    sanitize(error);
  }
}

function stringPattern(value, pattern) {
  if (
    typeof value !== "string" ||
    !pattern.test(value)
  ) {
    fail();
  }
  return value;
}

function expectedReleaseId(sessionId) {
  return `release-${createHash("sha256")
    .update(sessionId, "utf8")
    .digest("hex")
    .slice(0, 16)}`;
}

function pathUnder(path, root) {
  const target = absolutePath(path);
  if (
    !target.startsWith(`${root}/`) ||
    target.length <= root.length + 1
  ) {
    fail();
  }
  return target;
}

function validateHandoff(value) {
  const input = exact(value, HANDOFF_KEYS);
  const descriptorDigest = stringPattern(
    input.descriptorDigest,
    SHA64,
  );
  const evidenceDigest = stringPattern(
    input.evidenceDigest,
    SHA64,
  );
  const mandateDigest = stringPattern(
    input.mandateDigest,
    SHA64,
  );
  const requestDigest = stringPattern(
    input.requestDigest,
    SHA64,
  );
  const sessionDigest = stringPattern(
    input.sessionDigest,
    SHA64,
  );
  const releaseId = stringPattern(
    input.releaseId,
    RELEASE,
  );
  const repositorySha = stringPattern(
    input.repositorySha,
    SHA40,
  );
  const sessionId = stringPattern(
    input.sessionId,
    SESSION,
  );
  if (
    input.paymentMoved !== false ||
    input.schema !==
      "clockchain.aws-verifier-handoff/v1" ||
    releaseId !== expectedReleaseId(sessionId) ||
    !["rehearsal", "stakeholder"].includes(input.subjectRun)
  ) {
    fail();
  }
  const evidenceRoot =
    `/var/lib/clockchain/evidence/releases/${releaseId}`;
  const outputRoot =
    `/var/lib/clockchain/verifier-output/releases/${releaseId}`;
  const paths = [
    pathUnder(input.descriptorPath, evidenceRoot),
    pathUnder(input.payerMandatePath, evidenceRoot),
    pathUnder(input.payeeResultsPath, evidenceRoot),
    pathUnder(input.payerResultsPath, evidenceRoot),
    pathUnder(input.paymentRequestPath, evidenceRoot),
    pathUnder(input.publicationPath, outputRoot),
  ];
  if (new Set(paths).size !== paths.length) fail();
  return Object.freeze({
    descriptorDigest,
    descriptorPath: paths[0],
    evidenceDigest,
    mandateDigest,
    payerMandatePath: paths[1],
    payeeResultsPath: paths[2],
    payerResultsPath: paths[3],
    paymentMoved: false,
    paymentRequestPath: paths[4],
    publicationPath: paths[5],
    releaseId,
    repositorySha,
    requestDigest,
    schema: "clockchain.aws-verifier-handoff/v1",
    sessionDigest,
    sessionId,
    subjectRun: input.subjectRun,
  });
}

function handoffPayload(value) {
  const checked = validateHandoff(value);
  return Object.freeze({
    bytes: Buffer.from(
      `${JSON.stringify(checked)}\n`,
      "utf8",
    ),
    checked,
  });
}

function validatePublication(value, {
  expectedRevision,
  handoff,
}) {
  const publication = exact(
    value,
    PUBLICATION_KEYS,
  );
  const attemptId = stringPattern(
    publication.attemptId,
    ATTEMPT_ID,
  );
  const publicationDigest = stringPattern(
    publication.publicationDigest,
    SHA64,
  );
  const taskArn = stringPattern(
    publication.taskArn,
    TASK_ARN,
  );
  const writtenAtMs = stringPattern(
    publication.writtenAtMs,
    DECIMAL,
  );
  if (
    publication.evidenceDigest !==
      handoff.evidenceDigest ||
    publication.paymentMoved !== false ||
    publication.repositorySha !==
      handoff.repositorySha ||
    publication.revision !== expectedRevision ||
    publication.schema !==
      "clockchain.aws-verifier-task-publication/v1" ||
    publication.status !==
      "VERIFICATION_PASSED"
  ) {
    fail();
  }
  return Object.freeze({
    attemptId,
    evidenceDigest: publication.evidenceDigest,
    paymentMoved: false,
    publicationDigest,
    repositorySha: publication.repositorySha,
    revision: publication.revision,
    schema:
      "clockchain.aws-verifier-task-publication/v1",
    status: "VERIFICATION_PASSED",
    taskArn,
    writtenAtMs,
  });
}

export async function publishAwsFundingRecord(
  value = {},
  deps = {},
) {
  try {
    const input = exactInput(
      value,
      ["path", "record"],
    );
    const { bytes, checked } =
      fundingPayload(input.record);
    await writeExclusiveOrAdopt(input.path, bytes, deps);
    return checked;
  } catch (error) {
    sanitize(error);
  }
}

export async function readAwsFundingRecord(
  value = {},
  deps = {},
) {
  try {
    const input = exactInput(value, ["path"]);
    return validateFundingRecord(
      parseCanonical(await readPinned(input.path, deps)),
    );
  } catch (error) {
    sanitize(error);
  }
}

export async function publishAwsVerifierHandoff(
  value,
  deps = {},
) {
  try {
    const input = exactInput(value, [
      "path",
      "handoff",
    ]);
    const { bytes, checked } = handoffPayload(
      input.handoff,
    );
    await writeExclusiveOrAdopt(
      input.path,
      bytes,
      deps,
    );
    return checked;
  } catch (error) {
    sanitize(error);
  }
}

export async function readAwsVerifierHandoff(
  value = {},
  deps = {},
) {
  try {
    const input = exactInput(value, ["path"]);
    return validateHandoff(
      parseCanonical(await readPinned(input.path, deps)),
    );
  } catch (error) {
    sanitize(error);
  }
}

export async function readAwsVerifierPublication(
  value = {},
  deps = {},
) {
  try {
    const input = exactInput(value, [
      "expectedRevision",
      "handoff",
      "path",
    ]);
    if (
      !Number.isSafeInteger(input.expectedRevision) ||
      input.expectedRevision < 0
    ) {
      fail();
    }
    const checkedHandoff =
      validateHandoff(input.handoff);
    if (input.path !== checkedHandoff.publicationPath) fail();
    const publication = validatePublication(
      parseCanonical(await readPinned(input.path, deps)),
      {
        expectedRevision: input.expectedRevision,
        handoff: checkedHandoff,
      },
    );
    return publication;
  } catch (error) {
    sanitize(error);
  }
}
