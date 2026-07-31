import { types } from "node:util";

import {
  applyControlAction,
  controlActionBytes,
  controlActionDigest,
  validateControlAction,
} from "../../../src/bilateral/aws/control-actions.mjs";

export const CONTROL_API_BODY_LOGGING = false;

const MAX_BODY_BYTES = 16_384;
const SESSION_PLACEHOLDER =
  "00000000-0000-4000-8000-000000000000";

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
        state: lookup.state,
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
