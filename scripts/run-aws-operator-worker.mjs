#!/usr/bin/env node

import { types } from "node:util";

import {
  AwsControlActionError,
  applyControlAction,
  controlActionBytes,
  controlActionDigest,
  validateControlAction,
} from "../src/bilateral/aws/control-actions.mjs";

const MESSAGE_KEYS = Object.freeze([
  "body",
  "messageId",
  "receiptHandle",
]);
const SESSION_PLACEHOLDER =
  "00000000-0000-4000-8000-000000000000";
const SHA64 = /^[0-9a-f]{64}$/;
const REQUIRED_DEPENDENCIES = Object.freeze([
  "abortSession",
  "approveBootstrapClaim",
  "commitControlState",
  "createSession",
  "deleteMessage",
  "launchCoordinator",
  "launchFundingTask",
  "launchVerifierTask",
  "readControlContext",
  "recordRejection",
]);

export class AwsOperatorWorkerError extends Error {
  constructor() {
    super("AWS operator worker failed safely.");
    this.name = "AwsOperatorWorkerError";
    this.code = "AWS_OPERATOR_WORKER_FAILED";
    this.category = "verification";
  }
}

function fail() {
  throw new AwsOperatorWorkerError();
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

function dependencies(value) {
  if (
    !plain(value) ||
    REQUIRED_DEPENDENCIES.some(
      (name) => typeof value[name] !== "function",
    )
  ) {
    fail();
  }
  return value;
}

function message(value) {
  const parsed = exact(value, MESSAGE_KEYS);
  if (
    typeof parsed.body !== "string" ||
    parsed.body.length === 0 ||
    Buffer.byteLength(parsed.body, "utf8") >
      16_384 ||
    typeof parsed.messageId !== "string" ||
    parsed.messageId.length === 0 ||
    parsed.messageId.length > 256 ||
    typeof parsed.receiptHandle !== "string" ||
    parsed.receiptHandle.length === 0 ||
    parsed.receiptHandle.length > 4096
  ) {
    fail();
  }
  return parsed;
}

function parseAction(body) {
  let candidate;
  try {
    candidate = JSON.parse(body);
    const action = validateControlAction(candidate);
    if (
      controlActionBytes(action).toString("utf8") !==
      body
    ) {
      return null;
    }
    return action;
  } catch {
    return null;
  }
}

function exactResult(value, status) {
  if (
    !plain(value) ||
    value.paymentMoved !== false ||
    value.status !== status
  ) {
    fail();
  }
  return value;
}

async function rejectDurably(
  queueMessage,
  active,
  {
    action = null,
    reason = "INVALID",
  } = {},
) {
  await active.recordRejection({
    actionDigest:
      action === null
        ? null
        : controlActionDigest(action),
    actionId: action?.actionId ?? null,
    messageId: queueMessage.messageId,
    paymentMoved: false,
    reason,
  });
  await active.deleteMessage({
    receiptHandle: queueMessage.receiptHandle,
  });
  return Object.freeze({
    paymentMoved: false,
    status: "REJECTED",
  });
}

function context(value) {
  if (
    !plain(value) ||
    Reflect.ownKeys(value).length !== 2 ||
    !Object.hasOwn(
      value,
      "expectedClaimFingerprint",
    ) ||
    !Object.hasOwn(value, "state") ||
    !plain(value.state) ||
    !(
      value.expectedClaimFingerprint === null ||
      (
        typeof value.expectedClaimFingerprint ===
          "string" &&
        SHA64.test(
          value.expectedClaimFingerprint,
        )
      )
    )
  ) {
    fail();
  }
  return value;
}

async function runTransition(
  action,
  active,
  nextState,
) {
  const common = Object.freeze({
    actionId: action.actionId,
    expectedRevision: action.expectedRevision,
    paymentMoved: false,
    releaseId: action.releaseId,
    repositorySha: action.repositorySha,
    sessionId: nextState.sessionId,
  });
  if (action.type === "START_RUN") {
    exactResult(
      await active.launchCoordinator(common),
      "RUNNING",
    );
    return;
  }
  if (
    action.type === "APPROVE_PAYER" ||
    action.type === "APPROVE_REQUESTOR"
  ) {
    exactResult(
      await active.approveBootstrapClaim({
        ...common,
        claimFingerprint:
          action.claimFingerprint,
        role:
          action.type === "APPROVE_PAYER"
            ? "payer"
            : "payee",
      }),
      "APPROVED",
    );
    return;
  }
  if (action.type === "FUND") {
    exactResult(
      await active.launchFundingTask(common),
      "FUNDED",
    );
    return;
  }
  if (action.type === "VERIFY") {
    const result = exactResult(
      await active.launchVerifierTask(common),
      "VERIFICATION_PASSED",
    );
    if (
      typeof result.publicationDigest !==
        "string" ||
      !SHA64.test(result.publicationDigest)
    ) {
      fail();
    }
    return;
  }
  if (action.type === "ABORT") {
    exactResult(
      await active.abortSession(common),
      "ABORTED",
    );
    return;
  }
  fail();
}

export async function processAwsOperatorMessage(
  value,
  dependencyInput,
) {
  let queueMessage;
  let active;
  try {
    queueMessage = message(value);
    active = dependencies(dependencyInput);
  } catch {
    fail();
  }
  const action = parseAction(queueMessage.body);
  if (action === null) {
    try {
      return await rejectDurably(
        queueMessage,
        active,
      );
    } catch {
      fail();
    }
  }

  let current;
  try {
    current = context(
      await active.readControlContext({
        releaseId: action.releaseId,
        sessionId:
          action.type === "START_RUN"
            ? null
            : action.sessionId,
      }),
    );
  } catch {
    fail();
  }

  let provisional;
  try {
    provisional = applyControlAction({
      action,
      createdSessionId:
        action.type === "START_RUN"
          ? SESSION_PLACEHOLDER
          : undefined,
      expectedClaimFingerprint:
        current.expectedClaimFingerprint,
      state: current.state,
    });
  } catch (error) {
    if (!(error instanceof AwsControlActionError)) {
      fail();
    }
    try {
      return await rejectDurably(
        queueMessage,
        active,
        { action },
      );
    } catch {
      fail();
    }
  }
  if (provisional === current.state) {
    try {
      return await rejectDurably(
        queueMessage,
        active,
        {
          action,
          reason: "DUPLICATE",
        },
      );
    } catch {
      fail();
    }
  }

  let nextState = provisional;
  try {
    if (action.type === "START_RUN") {
      const sessionId =
        await active.createSession({
          actionId: action.actionId,
          paymentMoved: false,
          releaseId: action.releaseId,
          repositorySha:
            action.repositorySha,
        });
      nextState = applyControlAction({
        action,
        createdSessionId: sessionId,
        state: current.state,
      });
    }
    await runTransition(
      action,
      active,
      nextState,
    );
    await active.commitControlState({
      action,
      actionDigest:
        controlActionDigest(action),
      nextState,
      previousRevision:
        current.state.revision,
    });
    await active.deleteMessage({
      receiptHandle:
        queueMessage.receiptHandle,
    });
  } catch {
    fail();
  }
  return Object.freeze({
    paymentMoved: false,
    revision: nextState.revision,
    status: "COMMITTED",
  });
}
