import { createHash } from "node:crypto";
import { types } from "node:util";

export const ACTION_TYPES = Object.freeze([
  "START_RUN",
  "APPROVE_PAYER",
  "APPROVE_REQUESTOR",
  "FUND",
  "VERIFY",
  "ABORT",
]);
export const AWS_CONTROL_STATE_SCHEMA =
  "clockchain.aws-control-state/v1";

const START_KEYS = Object.freeze([
  "actionId",
  "expectedRevision",
  "paymentMoved",
  "releaseId",
  "repositorySha",
  "type",
]);
const LATER_KEYS = Object.freeze([
  "actionId",
  "expectedRevision",
  "paymentMoved",
  "releaseId",
  "repositorySha",
  "sessionId",
  "type",
]);
const APPROVAL_KEYS = Object.freeze([
  "actionId",
  "claimFingerprint",
  "expectedRevision",
  "paymentMoved",
  "releaseId",
  "repositorySha",
  "sessionId",
  "type",
]);
const STATE_KEYS = Object.freeze([
  "actionHistory",
  "paymentMoved",
  "releaseId",
  "repositorySha",
  "revision",
  "schema",
  "sessionId",
  "status",
]);
const HISTORY_KEYS = Object.freeze([
  "actionDigest",
  "actionId",
  "type",
]);
const SHA40 = /^[0-9a-f]{40}$/;
const SHA64 = /^[0-9a-f]{64}$/;
const UUID_V4 =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SESSION_ID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const RELEASE_ID =
  /^release-[0-9a-f]{16}$/;
const STATUSES = new Set([
  "EMPTY",
  "RUN_STARTED",
  "PAYER_APPROVED",
  "REQUESTOR_APPROVED",
  "FUND_REQUESTED",
  "VERIFY_REQUESTED",
  "ABORTED",
]);
const NEXT = Object.freeze({
  EMPTY: Object.freeze(["START_RUN"]),
  RUN_STARTED: Object.freeze([
    "APPROVE_PAYER",
    "ABORT",
  ]),
  PAYER_APPROVED: Object.freeze([
    "APPROVE_REQUESTOR",
    "ABORT",
  ]),
  REQUESTOR_APPROVED: Object.freeze([
    "FUND",
    "ABORT",
  ]),
  FUND_REQUESTED: Object.freeze([
    "VERIFY",
    "ABORT",
  ]),
  VERIFY_REQUESTED: Object.freeze([]),
  ABORTED: Object.freeze([]),
});
const STATUS_AFTER = Object.freeze({
  START_RUN: "RUN_STARTED",
  APPROVE_PAYER: "PAYER_APPROVED",
  APPROVE_REQUESTOR: "REQUESTOR_APPROVED",
  FUND: "FUND_REQUESTED",
  VERIFY: "VERIFY_REQUESTED",
  ABORT: "ABORTED",
});

export class AwsControlActionError extends Error {
  constructor() {
    super("AWS control action failed safely.");
    this.name = "AwsControlActionError";
    this.code = "AWS_CONTROL_ACTION_INVALID";
    this.category = "verification";
  }
}

function invalid() {
  throw new AwsControlActionError();
}

function sanitize(error) {
  if (error instanceof AwsControlActionError) {
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
    value < 0 ||
    Object.is(value, -0)
  ) {
    invalid();
  }
  return value;
}

function freeze(value) {
  if (
    value !== null &&
    typeof value === "object"
  ) {
    for (const entry of Object.values(value)) {
      freeze(entry);
    }
    Object.freeze(value);
  }
  return value;
}

export function validateControlAction(value) {
  try {
    if (
      value === null ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      types.isProxy(value)
    ) {
      invalid();
    }
    const typeDescriptor =
      Object.getOwnPropertyDescriptor(value, "type");
    if (
      typeDescriptor?.enumerable !== true ||
      !Object.hasOwn(typeDescriptor, "value")
    ) {
      invalid();
    }
    const type = typeDescriptor.value;
    if (!ACTION_TYPES.includes(type)) invalid();
    const keys =
      type === "START_RUN"
        ? START_KEYS
        : type === "APPROVE_PAYER" ||
            type === "APPROVE_REQUESTOR"
          ? APPROVAL_KEYS
          : LATER_KEYS;
    const action = exactObject(value, keys);
    stringPattern(action.actionId, UUID_V4);
    revision(action.expectedRevision);
    if (
      action.paymentMoved !== false ||
      !RELEASE_ID.test(action.releaseId) ||
      !SHA40.test(action.repositorySha) ||
      (
        type === "START_RUN" &&
        action.expectedRevision !== 0
      )
    ) {
      invalid();
    }
    if (
      type !== "START_RUN" &&
      !SESSION_ID.test(action.sessionId)
    ) {
      invalid();
    }
    if (
      (
        type === "APPROVE_PAYER" ||
        type === "APPROVE_REQUESTOR"
      ) &&
      !SHA64.test(action.claimFingerprint)
    ) {
      invalid();
    }
    return freeze({ ...action });
  } catch (error) {
    sanitize(error);
  }
}

export function controlActionDigest(value) {
  try {
    return createHash("sha256")
      .update(controlActionBytes(value))
      .digest("hex");
  } catch (error) {
    sanitize(error);
  }
}

export function controlActionBytes(value) {
  try {
    return Buffer.from(
      JSON.stringify(
        validateControlAction(value),
      ),
      "utf8",
    );
  } catch (error) {
    sanitize(error);
  }
}

export function createInitialControlState() {
  return freeze({
    actionHistory: [],
    paymentMoved: false,
    releaseId: null,
    repositorySha: null,
    revision: 0,
    schema: AWS_CONTROL_STATE_SCHEMA,
    sessionId: null,
    status: "EMPTY",
  });
}

function validateState(value) {
  const state = exactObject(value, STATE_KEYS);
  if (
    state.schema !== AWS_CONTROL_STATE_SCHEMA ||
    state.paymentMoved !== false ||
    !Number.isSafeInteger(state.revision) ||
    state.revision < 0 ||
    !STATUSES.has(state.status) ||
    !Array.isArray(state.actionHistory) ||
    state.actionHistory.length !== state.revision
  ) {
    invalid();
  }
  if (state.status === "EMPTY") {
    if (
      state.revision !== 0 ||
      state.releaseId !== null ||
      state.repositorySha !== null ||
      state.sessionId !== null
    ) {
      invalid();
    }
  } else if (
    !RELEASE_ID.test(state.releaseId) ||
    !SHA40.test(state.repositorySha) ||
    !SESSION_ID.test(state.sessionId)
  ) {
    invalid();
  }
  const ids = new Set();
  let derivedStatus = "EMPTY";
  for (const entry of state.actionHistory) {
    const record = exactObject(
      entry,
      HISTORY_KEYS,
    );
    if (
      !SHA64.test(record.actionDigest) ||
      !UUID_V4.test(record.actionId) ||
      !ACTION_TYPES.includes(record.type) ||
      ids.has(record.actionId)
    ) {
      invalid();
    }
    if (
      !NEXT[derivedStatus].includes(record.type)
    ) {
      invalid();
    }
    derivedStatus = STATUS_AFTER[record.type];
    ids.add(record.actionId);
  }
  if (derivedStatus !== state.status) invalid();
  return state;
}

export function validateControlState(value) {
  try {
    const state = validateState(value);
    return freeze({
      ...state,
      actionHistory: state.actionHistory.map(
        (entry) => freeze({ ...entry }),
      ),
    });
  } catch (error) {
    sanitize(error);
  }
}

export function applyControlAction({
  action: candidate,
  createdSessionId,
  expectedClaimFingerprint,
  state: stateValue,
} = {}) {
  try {
    const state = validateState(stateValue);
    const action = validateControlAction(candidate);
    const actionDigest = controlActionDigest(action);
    const prior = state.actionHistory.find(
      (entry) =>
        entry.actionId === action.actionId,
    );
    if (prior !== undefined) {
      if (
        prior.actionDigest !== actionDigest ||
        prior.type !== action.type
      ) {
        invalid();
      }
      return state;
    }
    if (
      action.expectedRevision !== state.revision ||
      !NEXT[state.status].includes(action.type)
    ) {
      invalid();
    }
    let releaseId = state.releaseId;
    let repositorySha = state.repositorySha;
    let sessionId = state.sessionId;
    if (action.type === "START_RUN") {
      sessionId = stringPattern(
        createdSessionId,
        SESSION_ID,
      );
      releaseId = action.releaseId;
      repositorySha = action.repositorySha;
    } else if (
      action.releaseId !== state.releaseId ||
      action.repositorySha !==
        state.repositorySha ||
      action.sessionId !== state.sessionId
    ) {
      invalid();
    }
    if (
      action.type === "APPROVE_PAYER" ||
      action.type === "APPROVE_REQUESTOR"
    ) {
      if (
        !SHA64.test(expectedClaimFingerprint) ||
        action.claimFingerprint !==
          expectedClaimFingerprint
      ) {
        invalid();
      }
    }
    return freeze({
      actionHistory: [
        ...state.actionHistory.map((entry) => ({
          ...entry,
        })),
        {
          actionDigest,
          actionId: action.actionId,
          type: action.type,
        },
      ],
      paymentMoved: false,
      releaseId,
      repositorySha,
      revision: state.revision + 1,
      schema: AWS_CONTROL_STATE_SCHEMA,
      sessionId,
      status: STATUS_AFTER[action.type],
    });
  } catch (error) {
    sanitize(error);
  }
}
