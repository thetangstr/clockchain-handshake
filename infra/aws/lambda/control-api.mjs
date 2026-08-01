import { types } from "node:util";

import {
  applyControlAction,
  AWS_CONTROL_STATE_SCHEMA,
  controlActionBytes,
  controlActionDigest,
  validateControlAction,
} from "../../../src/bilateral/aws/control-actions.mjs";

export const CONTROL_API_BODY_LOGGING = false;

const MAX_BODY_BYTES = 16_384;
const SESSION_PLACEHOLDER =
  "00000000-0000-4000-8000-000000000000";
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

function header(headers, name) {
  try {
    if (!plain(headers)) return null;
    const matches = Object.entries(headers)
      .filter(([key]) =>
        key.toLowerCase() === name);
    if (
      matches.length !== 1 ||
      typeof matches[0][1] !== "string"
    ) {
      return null;
    }
    return matches[0][1];
  } catch {
    return null;
  }
}

function response(
  statusCode,
  status,
  {
    actionId = null,
    allowedOrigin,
    originAccepted = false,
    revision = null,
  },
) {
  return {
    body: JSON.stringify({
      actionId,
      revision,
      status,
    }),
    headers: {
      ...(originAccepted
        ? {
            "access-control-allow-origin":
              allowedOrigin,
            vary: "origin",
          }
        : {}),
      "cache-control": "no-store",
      "content-type":
        "application/json; charset=utf-8",
    },
    statusCode,
  };
}

function authenticatedClaims(
  value,
  {
    audience,
    issuer,
    nowMs,
    operatorGroup,
  },
) {
  if (
    !plain(value) ||
    Reflect.ownKeys(value).length !== 5 ||
    value.aud !== audience ||
    value.iss !== issuer ||
    typeof value.exp !== "number" ||
    !Number.isSafeInteger(value.exp) ||
    value.exp <= Math.floor(nowMs / 1_000) ||
    !Array.isArray(value.groups) ||
    value.groups.length === 0 ||
    value.groups.some((group) =>
      typeof group !== "string") ||
    !value.groups.includes(operatorGroup) ||
    typeof value.sub !== "string" ||
    value.sub.length === 0 ||
    value.sub.length > 128
  ) {
    return false;
  }
  return true;
}

function parseCanonicalAction(body) {
  if (
    typeof body !== "string" ||
    body.length === 0 ||
    Buffer.byteLength(body, "utf8") >
      MAX_BODY_BYTES
  ) {
    return null;
  }
  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch {
    return null;
  }
  let action;
  try {
    action = validateControlAction(parsed);
  } catch {
    return null;
  }
  if (
    controlActionBytes(action).toString("utf8") !==
      body
  ) {
    return null;
  }
  return action;
}

function exactDataRecord(value, keys) {
  if (!plain(value)) return null;
  const descriptors =
    Object.getOwnPropertyDescriptors(value);
  const names = Object.keys(descriptors);
  if (
    Reflect.ownKeys(value).length !==
      keys.length ||
    names.length !== keys.length ||
    !keys.every((key) =>
      Object.hasOwn(descriptors, key))
  ) {
    return null;
  }
  const record = {};
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (
      descriptor.enumerable !== true ||
      !Object.hasOwn(descriptor, "value")
    ) {
      return null;
    }
    record[key] = descriptor.value;
  }
  return record;
}

function exactDenseDataArray(value) {
  if (
    !Array.isArray(value) ||
    types.isProxy(value)
  ) {
    return null;
  }
  const descriptors =
    Object.getOwnPropertyDescriptors(value);
  const expectedKeys = [
    ...Array.from(
      { length: value.length },
      (_, index) => String(index),
    ),
    "length",
  ];
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== expectedKeys.length ||
    !expectedKeys.every(
      (key, index) => ownKeys[index] === key,
    )
  ) {
    return null;
  }
  const lengthDescriptor = descriptors.length;
  if (
    lengthDescriptor?.value !== value.length ||
    lengthDescriptor.enumerable !== false ||
    !Object.hasOwn(lengthDescriptor, "value")
  ) {
    return null;
  }
  const entries = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (
      descriptor?.enumerable !== true ||
      !Object.hasOwn(descriptor, "value")
    ) {
      return null;
    }
    entries.push(descriptor.value);
  }
  return entries;
}

function canonicalStoredControlState(value) {
  const state = exactDataRecord(value, STATE_KEYS);
  if (state === null) return null;
  if (state.schema !== AWS_CONTROL_STATE_SCHEMA) {
    return null;
  }
  const history = exactDenseDataArray(
    state.actionHistory,
  );
  if (history === null) return null;
  const actionHistory = [];
  for (const entry of history) {
    const record = exactDataRecord(
      entry,
      HISTORY_KEYS,
    );
    if (record === null) return null;
    actionHistory.push(record);
  }
  return {
    ...state,
    actionHistory,
  };
}

export function createControlApiHandler({
  allowedOrigin,
  audience,
  issuer,
  nowMs = Date.now,
  operatorGroup,
  putIdempotency,
  readSessionState,
  sendMessage,
  verifyJwt,
} = {}) {
  if (
    typeof allowedOrigin !== "string" ||
    !/^https:\/\/[a-z0-9.-]+(?::[1-9][0-9]{0,4})?$/.test(
      allowedOrigin,
    ) ||
    typeof audience !== "string" ||
    audience.length === 0 ||
    typeof issuer !== "string" ||
    !issuer.startsWith("https://") ||
    typeof operatorGroup !== "string" ||
    operatorGroup.length === 0 ||
    typeof nowMs !== "function" ||
    typeof putIdempotency !== "function" ||
    typeof readSessionState !== "function" ||
    typeof sendMessage !== "function" ||
    typeof verifyJwt !== "function"
  ) {
    throw new Error(
      "AWS control API configuration failed safely.",
    );
  }
  return async function handler(event) {
    const origin = header(
      event?.headers,
      "origin",
    );
    const originAccepted =
      origin === allowedOrigin;
    const reject = (statusCode) =>
      response(statusCode, "REJECTED", {
        allowedOrigin,
        originAccepted,
      });
    if (
      plain(event) &&
      event.httpMethod === "OPTIONS" &&
      event.path === "/actions" &&
      originAccepted
    ) {
      return {
        body: "",
        headers: {
          "access-control-allow-headers":
            "authorization,content-type",
          "access-control-allow-methods":
            "POST,OPTIONS",
          "access-control-allow-origin":
            allowedOrigin,
          "access-control-max-age": "300",
          "cache-control": "no-store",
          vary: "origin",
        },
        statusCode: 204,
      };
    }
    if (
      !plain(event) ||
      event.httpMethod !== "POST" ||
      event.path !== "/actions" ||
      !originAccepted ||
      header(event.headers, "content-type") !==
        "application/json"
    ) {
      return reject(400);
    }
    const authorization = header(
      event.headers,
      "authorization",
    );
    if (
      authorization === null ||
      !authorization.startsWith("Bearer ") ||
      authorization.length <= 7
    ) {
      return reject(401);
    }
    let claims;
    try {
      claims = await verifyJwt(
        authorization.slice(7),
      );
    } catch {
      return reject(401);
    }
    let currentTime;
    try {
      currentTime = nowMs();
    } catch {
      return reject(500);
    }
    let acceptedClaims = false;
    try {
      acceptedClaims = authenticatedClaims(claims, {
        audience,
        issuer,
        nowMs: currentTime,
        operatorGroup,
      });
    } catch {
      // Fixed authentication response below.
    }
    if (
      !Number.isSafeInteger(currentTime) ||
      currentTime < 0 ||
      !acceptedClaims
    ) {
      return reject(401);
    }
    const action = parseCanonicalAction(
      event.body,
    );
    if (action === null) return reject(400);
    let lookup;
    try {
      lookup = await readSessionState({
        releaseId: action.releaseId,
        sessionId:
          action.type === "START_RUN"
            ? null
            : action.sessionId,
      });
    } catch {
      return reject(500);
    }
    let lookupValid = false;
    let state;
    try {
      lookupValid =
        plain(lookup) &&
        Reflect.ownKeys(lookup).length === 2 &&
        Object.hasOwn(
          lookup,
          "expectedClaimFingerprint",
        ) &&
        Object.hasOwn(lookup, "state") &&
        plain(lookup.state);
      if (lookupValid) {
        state = canonicalStoredControlState(
          lookup.state,
        );
        lookupValid = state !== null;
      }
    } catch {
      // Fixed server response below.
    }
    if (!lookupValid) {
      return reject(500);
    }
    try {
      applyControlAction({
        action,
        createdSessionId:
          action.type === "START_RUN"
            ? SESSION_PLACEHOLDER
            : undefined,
        expectedClaimFingerprint:
          lookup.expectedClaimFingerprint,
        state,
      });
    } catch {
      return reject(409);
    }
    let idempotency;
    try {
      idempotency = await putIdempotency({
        actionDigest:
          controlActionDigest(action),
        actionId: action.actionId,
      });
    } catch {
      return reject(500);
    }
    if (idempotency === "CONFLICT") {
      return reject(409);
    }
    if (
      idempotency !== "CREATED" &&
      idempotency !== "SAME"
    ) {
      return reject(500);
    }
    try {
      await sendMessage({
        body: controlActionBytes(action),
        deduplicationId: action.actionId,
        groupId:
          action.type === "START_RUN"
            ? action.releaseId
            : action.sessionId,
      });
    } catch {
      return reject(500);
    }
    return response(202, "QUEUED", {
      actionId: action.actionId,
      allowedOrigin,
      originAccepted,
      revision: action.expectedRevision + 1,
    });
  };
}
