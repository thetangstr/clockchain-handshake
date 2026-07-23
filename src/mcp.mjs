import {
  MCP_BASE_URL,
  MCP_URL,
} from "./constants.mjs";
import { redact } from "./redact.mjs";

const DEFAULT_REQUEST_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_RESPONSE_BYTES = 1_048_576;
const DEFAULT_MAX_ATTEMPTS = 3;
const MAX_CONFIGURED_ATTEMPTS = 5;
const MAX_CONFIGURED_TIMEOUT_MS = 120_000;
const MAX_CONFIGURED_RESPONSE_BYTES = 4_194_304;
const MAX_REQUEST_BYTES = 262_144;
const MAX_RETRY_AFTER_MS = 30_000;
const MAX_TOKEN_LENGTH = 8_192;
const MAX_SUBJECT_LENGTH = 128;
const MAX_IDENTIFIER_LENGTH = 256;
const MAX_ACTION_LENGTH = 128;
const MAX_IDEMPOTENCY_KEY_LENGTH = 256;
const JSON_RPC_VERSION = "2.0";
const CANONICAL_SHA256_PATTERN = /^[0-9a-f]{64}$/;
const CONTROL_CHARACTER_PATTERN =
  /[\u0000-\u001f\u007f-\u009f]/;
const READ_RETRY_TOOLS = new Set([
  "resolve_agent",
  "get_timestamp",
  "complete_attestation",
  "verify_receipt",
  "verify_cross_party",
]);
const POLLABLE_RECEIPT_STATUSES = new Set([
  "pending",
  "degraded",
]);
const ATTEST_ACTION_KEYS = new Set([
  "agent_id",
  "action",
  "inputs",
  "outputs",
  "wait",
  "wait_ms",
  "idempotency_key",
  "allow_degraded",
]);

export class McpError extends Error {
  constructor(message, {
    category,
    code,
  }) {
    super(message);
    this.name = new.target.name;
    this.category = category;
    this.code = code;
  }
}

export class McpConfigurationError extends McpError {
  constructor(message, code = "MCP_CONFIGURATION") {
    super(message, { category: "configuration", code });
  }
}

export class McpNetworkError extends McpError {
  constructor(message, code = "MCP_NETWORK") {
    super(message, { category: "network", code });
  }
}

export class McpProtocolError extends McpError {
  constructor(message, code = "MCP_PROTOCOL") {
    super(message, { category: "protocol", code });
  }
}

export class McpVerificationError extends McpError {
  constructor(message, code = "MCP_VERIFICATION") {
    super(message, { category: "verification", code });
  }
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object") {
    return false;
  }

  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasOnlyKeys(value, allowedKeys) {
  return (
    isPlainObject(value) &&
    Reflect.ownKeys(value).every(
      (key) => typeof key === "string" && allowedKeys.has(key),
    )
  );
}

function sanitizeMessage(message, canaries = []) {
  const clean = redact(
    typeof message === "string" ? message : "",
    canaries,
  )
    .replace(/[\u0000-\u001f\u007f]+/g, " ")
    .trim();
  return clean.slice(0, 512);
}

function cloneSafeError(error, token) {
  const canaries = typeof token === "string" ? [token] : [];

  if (error instanceof McpConfigurationError) {
    return new McpConfigurationError(
      sanitizeMessage(error.message, canaries),
      error.code,
    );
  }
  if (error instanceof McpNetworkError) {
    return new McpNetworkError(
      sanitizeMessage(error.message, canaries),
      error.code,
    );
  }
  if (error instanceof McpProtocolError) {
    return new McpProtocolError(
      sanitizeMessage(error.message, canaries),
      error.code,
    );
  }
  if (error instanceof McpVerificationError) {
    return new McpVerificationError(
      sanitizeMessage(error.message, canaries),
      error.code,
    );
  }

  return new McpNetworkError(
    "Clockchain MCP request failed.",
    "MCP_TRANSPORT",
  );
}

function configurationInteger(
  value,
  label,
  {
    maximum = Number.MAX_SAFE_INTEGER,
    minimum = 1,
  } = {},
) {
  if (
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    throw new McpConfigurationError(`${label} is invalid.`);
  }
  return value;
}

function assertFetch(fetchImpl) {
  if (typeof fetchImpl !== "function") {
    throw new McpConfigurationError(
      "Clockchain fetch implementation is invalid.",
    );
  }
}

function validateToken(token) {
  if (
    typeof token !== "string" ||
    token.length === 0 ||
    token.length > MAX_TOKEN_LENGTH ||
    !/^[\x21-\x7e]+$/.test(token)
  ) {
    throw new McpConfigurationError(
      "Clockchain MCP token is invalid.",
    );
  }
  return token;
}

function sanitizeSubject(subject) {
  if (subject === undefined) {
    return undefined;
  }
  if (typeof subject !== "string") {
    throw new McpConfigurationError(
      "Clockchain token subject is invalid.",
    );
  }

  const sanitized = subject
    .normalize("NFKC")
    .replace(/[\u0000-\u001f\u007f]+/g, "-")
    .replace(/[^A-Za-z0-9._:@/-]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, MAX_SUBJECT_LENGTH)
    .replace(/-+$/g, "");

  if (sanitized.length === 0) {
    throw new McpConfigurationError(
      "Clockchain token subject is invalid.",
    );
  }
  return sanitized;
}

function responseHeader(headers, name) {
  if (headers && typeof headers.get === "function") {
    return headers.get(name);
  }
  if (isPlainObject(headers)) {
    const match = Object.entries(headers).find(
      ([key]) => key.toLowerCase() === name.toLowerCase(),
    );
    return match?.[1] ?? null;
  }
  return null;
}

async function readBoundedText(response, maxResponseBytes) {
  const contentLength = responseHeader(
    response?.headers,
    "content-length",
  );
  if (
    typeof contentLength === "string" &&
    /^\d+$/.test(contentLength) &&
    Number(contentLength) > maxResponseBytes
  ) {
    throw new McpProtocolError(
      "Clockchain response exceeds the size limit.",
      "MCP_RESPONSE_TOO_LARGE",
    );
  }

  if (typeof response?.body?.getReader === "function") {
    const reader = response.body.getReader();
    const chunks = [];
    let byteLength = 0;

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) {
          break;
        }
        if (!(value instanceof Uint8Array)) {
          throw new McpProtocolError(
            "Clockchain response body is invalid.",
            "MCP_INVALID_RESPONSE_BODY",
          );
        }

        byteLength += value.byteLength;
        if (byteLength > maxResponseBytes) {
          try {
            await reader.cancel();
          } catch {
            // The response is already rejected for exceeding the limit.
          }
          throw new McpProtocolError(
            "Clockchain response exceeds the size limit.",
            "MCP_RESPONSE_TOO_LARGE",
          );
        }
        chunks.push(value);
      }
    } finally {
      reader.releaseLock();
    }

    const bytes = new Uint8Array(byteLength);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      throw new McpProtocolError(
        "Clockchain response body encoding is invalid.",
        "MCP_INVALID_RESPONSE_ENCODING",
      );
    }
  }

  if (typeof response?.text !== "function") {
    throw new McpProtocolError(
      "Clockchain response body is invalid.",
      "MCP_INVALID_RESPONSE_BODY",
    );
  }

  const text = await response.text();
  if (
    typeof text !== "string" ||
    Buffer.byteLength(text, "utf8") > maxResponseBytes
  ) {
    throw new McpProtocolError(
      "Clockchain response exceeds the size limit.",
      "MCP_RESPONSE_TOO_LARGE",
    );
  }
  return text;
}

async function fetchBounded({
  fetchImpl,
  init,
  maxResponseBytes,
  requestTimeoutMs,
  timeoutMessage,
  transportMessage,
  url,
}) {
  const controller = new AbortController();
  let timer;
  const timeout = new Promise((_resolve, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(
        new McpNetworkError(timeoutMessage, "MCP_TIMEOUT"),
      );
    }, requestTimeoutMs);
  });

  const operation = (async () => {
    let response;

    try {
      response = await fetchImpl(url, {
        ...init,
        signal: controller.signal,
      });
    } catch {
      if (controller.signal.aborted) {
        throw new McpNetworkError(timeoutMessage, "MCP_TIMEOUT");
      }
      throw new McpNetworkError(
        transportMessage,
        "MCP_TRANSPORT",
      );
    }

    if (
      response === null ||
      typeof response !== "object" ||
      !Number.isInteger(response.status)
    ) {
      throw new McpProtocolError(
        "Clockchain response metadata is invalid.",
        "MCP_INVALID_RESPONSE",
      );
    }
    if (!isSuccessfulStatus(response.status)) {
      return { response, text: "" };
    }

    let text;
    try {
      text = await readBoundedText(response, maxResponseBytes);
    } catch (error) {
      if (error instanceof McpError) {
        throw error;
      }
      if (controller.signal.aborted) {
        throw new McpNetworkError(timeoutMessage, "MCP_TIMEOUT");
      }
      throw new McpNetworkError(
        transportMessage,
        "MCP_TRANSPORT",
      );
    }
    return { response, text };
  })();

  try {
    return await Promise.race([operation, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

function jsonCandidatesFromValue(value) {
  return Array.isArray(value) ? value : [value];
}

function parseJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    throw new McpProtocolError(
      "Clockchain JSON-RPC response is malformed.",
      "MCP_MALFORMED_JSON",
    );
  }
}

function parseSseCandidates(raw) {
  const normalized = raw.replace(/\r\n?|\u2028|\u2029/g, "\n");
  const candidates = [];
  let dataLines = [];
  let eventName = "";

  function flush() {
    if (
      dataLines.length > 0 &&
      (eventName === "" || eventName === "message")
    ) {
      const data = dataLines.join("\n").trim();
      if (data.length > 0) {
        candidates.push(...jsonCandidatesFromValue(parseJson(data)));
      }
    }
    dataLines = [];
    eventName = "";
  }

  for (const line of normalized.split("\n")) {
    if (line === "") {
      flush();
      continue;
    }
    if (line.startsWith(":")) {
      continue;
    }

    const separator = line.indexOf(":");
    const field =
      separator === -1 ? line : line.slice(0, separator);
    let value =
      separator === -1 ? "" : line.slice(separator + 1);
    if (value.startsWith(" ")) {
      value = value.slice(1);
    }

    if (field === "event") {
      eventName = value;
    } else if (field === "data") {
      dataLines.push(value);
    }
  }
  flush();
  return candidates;
}

function assertJsonRpcEnvelope(envelope) {
  if (
    !isPlainObject(envelope) ||
    envelope.jsonrpc !== JSON_RPC_VERSION ||
    !Object.hasOwn(envelope, "id") ||
    (Object.hasOwn(envelope, "result") ===
      Object.hasOwn(envelope, "error"))
  ) {
    throw new McpProtocolError(
      "Clockchain JSON-RPC response is invalid.",
      "MCP_INVALID_JSON_RPC",
    );
  }

  if (Object.hasOwn(envelope, "error")) {
    const remoteMessage = sanitizeMessage(envelope.error?.message);
    const suffix =
      remoteMessage.length > 0 ? `: ${remoteMessage}` : "";
    throw new McpProtocolError(
      `Clockchain JSON-RPC error${suffix}.`,
      "MCP_JSON_RPC_ERROR",
    );
  }
  return envelope;
}

export function parseSseJsonRpc(raw, options = {}) {
  if (
    !hasOnlyKeys(options, new Set(["expectedId"]))
  ) {
    throw new McpConfigurationError(
      "Clockchain JSON-RPC parser options are invalid.",
    );
  }
  const { expectedId } = options;

  if (typeof raw !== "string") {
    throw new McpProtocolError(
      "Clockchain JSON-RPC response is invalid.",
      "MCP_INVALID_RESPONSE",
    );
  }
  if (
    Buffer.byteLength(raw, "utf8") >
    DEFAULT_MAX_RESPONSE_BYTES
  ) {
    throw new McpProtocolError(
      "Clockchain response exceeds the size limit.",
      "MCP_RESPONSE_TOO_LARGE",
    );
  }

  const trimmed = raw.trim();
  if (trimmed.length === 0) {
    if (expectedId === undefined) {
      return undefined;
    }
    throw new McpProtocolError(
      "Clockchain JSON-RPC response was empty.",
      "MCP_EMPTY_RESPONSE",
    );
  }

  const candidates =
    trimmed.startsWith("{") || trimmed.startsWith("[")
      ? jsonCandidatesFromValue(parseJson(trimmed))
      : parseSseCandidates(raw);

  if (candidates.length === 0) {
    throw new McpProtocolError(
      "Clockchain JSON-RPC response has no message.",
      "MCP_MISSING_JSON_RPC",
    );
  }

  if (expectedId === undefined) {
    return assertJsonRpcEnvelope(candidates.at(-1));
  }

  const matches = candidates.filter(
    (candidate) =>
      isPlainObject(candidate) &&
      Object.hasOwn(candidate, "id") &&
      candidate.id === expectedId,
  );
  if (matches.length === 0) {
    throw new McpProtocolError(
      "Clockchain JSON-RPC response has no matching id.",
      "MCP_MISSING_JSON_RPC_ID",
    );
  }
  if (matches.length > 1) {
    throw new McpProtocolError(
      "Clockchain JSON-RPC response has multiple matching ids.",
      "MCP_AMBIGUOUS_JSON_RPC_ID",
    );
  }
  return assertJsonRpcEnvelope(matches[0]);
}

function assertToolPayload(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    (!Array.isArray(value) && !isPlainObject(value))
  ) {
    throw new McpProtocolError(
      "Clockchain MCP tool result is invalid.",
      "MCP_INVALID_TOOL_RESULT",
    );
  }
  return value;
}

export function parseToolResult(jsonRpc) {
  const envelope = assertJsonRpcEnvelope(jsonRpc);
  const { result } = envelope;

  if (!isPlainObject(result)) {
    throw new McpProtocolError(
      "Clockchain MCP tool result is invalid.",
      "MCP_INVALID_TOOL_RESULT",
    );
  }
  if (result.isError === true) {
    throw new McpProtocolError(
      "Clockchain MCP tool reported an error.",
      "MCP_TOOL_ERROR",
    );
  }

  if (Object.hasOwn(result, "structuredContent")) {
    return assertToolPayload(result.structuredContent);
  }

  const content = result.content;
  if (
    !Array.isArray(content) ||
    !isPlainObject(content[0]) ||
    content[0].type !== "text" ||
    typeof content[0].text !== "string"
  ) {
    throw new McpProtocolError(
      "Clockchain MCP tool result is invalid.",
      "MCP_INVALID_TOOL_RESULT",
    );
  }

  let value;
  try {
    value = JSON.parse(content[0].text);
  } catch {
    throw new McpProtocolError(
      "Clockchain MCP tool result is malformed.",
      "MCP_MALFORMED_TOOL_RESULT",
    );
  }
  return assertToolPayload(value);
}

function isSuccessfulStatus(status) {
  return status >= 200 && status < 300;
}

export async function mintDemoToken(options = {}) {
  if (
    !hasOnlyKeys(
      options,
      new Set([
        "fetchImpl",
        "subject",
        "requestTimeoutMs",
        "maxResponseBytes",
      ]),
    )
  ) {
    throw new McpConfigurationError(
      "Clockchain token options are invalid.",
    );
  }
  const {
    fetchImpl = globalThis.fetch,
    subject,
    requestTimeoutMs = DEFAULT_REQUEST_TIMEOUT_MS,
    maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES,
  } = options;

  assertFetch(fetchImpl);
  configurationInteger(
    requestTimeoutMs,
    "Clockchain request timeout",
    { maximum: MAX_CONFIGURED_TIMEOUT_MS },
  );
  configurationInteger(
    maxResponseBytes,
    "Clockchain response size limit",
    { maximum: MAX_CONFIGURED_RESPONSE_BYTES },
  );
  const safeSubject = sanitizeSubject(subject);
  const headers = { accept: "application/json" };
  if (safeSubject !== undefined) {
    headers["x-clockchain-sub"] = safeSubject;
  }

  let response;
  let text;
  try {
    ({ response, text } = await fetchBounded({
      fetchImpl,
      init: {
        method: "POST",
        headers,
        cache: "no-store",
      },
      maxResponseBytes,
      requestTimeoutMs,
      timeoutMessage: "Clockchain token request timed out.",
      transportMessage: "Clockchain token request failed.",
      url: `${MCP_BASE_URL}/token`,
    }));
  } catch (error) {
    if (error instanceof McpError) {
      throw cloneSafeError(error);
    }
    throw new McpNetworkError(
      "Clockchain token request failed.",
      "MCP_TRANSPORT",
    );
  }

  if (response.status === 401 || response.status === 403) {
    throw new McpConfigurationError(
      "Clockchain token authorization failed.",
      "MCP_AUTHORIZATION",
    );
  }
  if (response.status === 429) {
    throw new McpNetworkError(
      "Clockchain token rate limit was exceeded.",
      "MCP_RATE_LIMIT",
    );
  }
  if (response.status >= 500) {
    throw new McpNetworkError(
      "Clockchain token service is unavailable.",
      "MCP_SERVICE_UNAVAILABLE",
    );
  }
  if (!isSuccessfulStatus(response.status)) {
    throw new McpConfigurationError(
      "Clockchain token request was rejected.",
      "MCP_TOKEN_REJECTED",
    );
  }

  const cacheControl = responseHeader(
    response.headers,
    "cache-control",
  );
  const cacheDirectives =
    typeof cacheControl === "string"
      ? cacheControl
          .split(",")
          .map((directive) => directive.trim().toLowerCase())
      : [];
  if (!cacheDirectives.includes("no-store")) {
    throw new McpProtocolError(
      "Clockchain token response must be no-store.",
      "MCP_TOKEN_CACHE_POLICY",
    );
  }

  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw new McpProtocolError(
      "Clockchain token response is malformed.",
      "MCP_INVALID_TOKEN_RESPONSE",
    );
  }
  if (
    !isPlainObject(value) ||
    typeof value.token !== "string"
  ) {
    throw new McpProtocolError(
      "Clockchain invalid token response.",
      "MCP_INVALID_TOKEN_RESPONSE",
    );
  }

  try {
    return validateToken(value.token);
  } catch {
    throw new McpProtocolError(
      "Clockchain invalid token response.",
      "MCP_INVALID_TOKEN_RESPONSE",
    );
  }
}

function normalizeIdentifier(value, label) {
  let normalized;
  if (typeof value === "bigint") {
    if (value < 0n) {
      throw new McpConfigurationError(`${label} is invalid.`);
    }
    normalized = value.toString(10);
  } else if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new McpConfigurationError(`${label} is invalid.`);
    }
    normalized = value.toString(10);
  } else if (typeof value === "string") {
    normalized = value;
  } else {
    throw new McpConfigurationError(`${label} is invalid.`);
  }

  if (
    normalized.trim() !== normalized ||
    normalized.length === 0 ||
    normalized.length > MAX_IDENTIFIER_LENGTH ||
    /[\u0000-\u001f\u007f]/.test(normalized)
  ) {
    throw new McpConfigurationError(`${label} is invalid.`);
  }
  return normalized;
}

function nonemptyString(value, label, maximum) {
  if (
    typeof value !== "string" ||
    value.trim() !== value ||
    value.length === 0 ||
    value.length > maximum ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new McpConfigurationError(`${label} is invalid.`);
  }
  return value;
}

function assertJsonValue(
  value,
  label,
  seen = new WeakSet(),
  depth = 0,
) {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new McpConfigurationError(`${label} is invalid.`);
    }
    return;
  }
  if (
    typeof value !== "object" ||
    (!Array.isArray(value) && !isPlainObject(value)) ||
    seen.has(value) ||
    depth > 64 ||
    Reflect.ownKeys(value).some(
      (key) => typeof key !== "string",
    )
  ) {
    throw new McpConfigurationError(`${label} is invalid.`);
  }

  seen.add(value);
  for (const entry of Array.isArray(value)
    ? value
    : Object.values(value)) {
    assertJsonValue(entry, label, seen, depth + 1);
  }
  seen.delete(value);
}

function receiptArgument(receipt) {
  if (!isPlainObject(receipt)) {
    throw new McpConfigurationError(
      "Clockchain receipt is invalid.",
    );
  }
  assertJsonValue(receipt, "Clockchain receipt");
  return receipt;
}

function exactArguments(args, keys, label) {
  if (!hasOnlyKeys(args, keys)) {
    throw new McpConfigurationError(
      `${label} contains unexpected fields.`,
    );
  }
}

function normalizeAttestArguments(args) {
  exactArguments(args, ATTEST_ACTION_KEYS, "attest_action arguments");
  const normalized = {
    agent_id: normalizeIdentifier(
      args.agent_id,
      "Clockchain agent id",
    ),
    action: nonemptyString(
      args.action,
      "Clockchain action",
      MAX_ACTION_LENGTH,
    ),
  };

  if (Object.hasOwn(args, "inputs")) {
    assertJsonValue(args.inputs, "Clockchain action inputs");
    normalized.inputs = args.inputs;
  }
  if (Object.hasOwn(args, "outputs")) {
    assertJsonValue(args.outputs, "Clockchain action outputs");
    normalized.outputs = args.outputs;
  }
  if (Object.hasOwn(args, "wait")) {
    if (typeof args.wait !== "boolean") {
      throw new McpConfigurationError(
        "Clockchain wait option is invalid.",
      );
    }
    normalized.wait = args.wait;
  }
  if (Object.hasOwn(args, "wait_ms")) {
    normalized.wait_ms = configurationInteger(
      args.wait_ms,
      "Clockchain wait interval",
      { maximum: MAX_CONFIGURED_TIMEOUT_MS, minimum: 0 },
    );
  }
  if (Object.hasOwn(args, "idempotency_key")) {
    normalized.idempotency_key = nonemptyString(
      args.idempotency_key,
      "Clockchain idempotency_key",
      MAX_IDEMPOTENCY_KEY_LENGTH,
    );
  }
  if (Object.hasOwn(args, "allow_degraded")) {
    if (typeof args.allow_degraded !== "boolean") {
      throw new McpConfigurationError(
        "Clockchain degraded-mode option is invalid.",
      );
    }
    normalized.allow_degraded = args.allow_degraded;
  }
  return normalized;
}

function normalizeCrossPartyArguments(args) {
  const keys = new Set(["ledger_id", "block_height", "hash"]);
  exactArguments(args, keys, "verify_cross_party arguments");
  const normalized = {};

  if (Object.hasOwn(args, "ledger_id")) {
    normalized.ledger_id = nonemptyString(
      args.ledger_id,
      "Clockchain ledger id",
      MAX_IDENTIFIER_LENGTH,
    );
  }
  if (Object.hasOwn(args, "block_height")) {
    normalized.block_height = normalizeIdentifier(
      args.block_height,
      "Clockchain block height",
    );
  }
  if (Object.hasOwn(args, "hash")) {
    normalized.hash = nonemptyString(
      args.hash,
      "Clockchain event hash",
      MAX_IDENTIFIER_LENGTH,
    );
  }
  if (Object.keys(normalized).length === 0) {
    throw new McpConfigurationError(
      "Clockchain cross-party identifier is required.",
    );
  }
  return normalized;
}

function normalizeKnownToolArguments(name, args) {
  if (!isPlainObject(args)) {
    throw new McpConfigurationError(
      "Clockchain MCP tool arguments are invalid.",
    );
  }

  switch (name) {
    case "resolve_agent": {
      exactArguments(
        args,
        new Set(["agent_id"]),
        "resolve_agent arguments",
      );
      return {
        agent_id: normalizeIdentifier(
          args.agent_id,
          "Clockchain agent id",
        ),
      };
    }
    case "get_timestamp":
      exactArguments(
        args,
        new Set(),
        "get_timestamp arguments",
      );
      return {};
    case "attest_action":
      return normalizeAttestArguments(args);
    case "complete_attestation":
    case "verify_receipt":
      exactArguments(
        args,
        new Set(["receipt"]),
        `${name} arguments`,
      );
      return { receipt: receiptArgument(args.receipt) };
    case "verify_cross_party":
      return normalizeCrossPartyArguments(args);
    default:
      assertJsonValue(args, "Clockchain MCP tool arguments");
      return args;
  }
}

function requestIdValue(value) {
  if (
    (typeof value === "number" &&
      Number.isSafeInteger(value)) ||
    (typeof value === "string" &&
      value.length > 0 &&
      value.length <= MAX_IDENTIFIER_LENGTH)
  ) {
    return value;
  }
  throw new McpConfigurationError(
    "Clockchain JSON-RPC request id is invalid.",
  );
}

function parseRetryAfter(value, now = Date.now()) {
  if (typeof value === "string" && /^\d+(?:\.\d+)?$/.test(value)) {
    return Math.min(
      Math.ceil(Number(value) * 1_000),
      MAX_RETRY_AFTER_MS,
    );
  }
  if (typeof value === "string") {
    const timestamp = Date.parse(value);
    if (Number.isFinite(timestamp)) {
      return Math.min(
        Math.max(0, timestamp - now),
        MAX_RETRY_AFTER_MS,
      );
    }
  }
  return null;
}

function backoffDelay(attempt) {
  return Math.min(100 * 2 ** attempt, 1_000);
}

async function waitForRetry(sleeper, milliseconds) {
  try {
    await sleeper(milliseconds);
  } catch {
    throw new McpNetworkError(
      "Clockchain MCP retry wait failed.",
      "MCP_RETRY_WAIT",
    );
  }
}

function defaultSleeper(milliseconds) {
  return new Promise((resolve) => {
    setTimeout(resolve, milliseconds);
  });
}

export function createMcpClient(options = {}) {
  if (
    !hasOnlyKeys(
      options,
      new Set([
        "token",
        "fetchImpl",
        "requestTimeoutMs",
        "maxResponseBytes",
        "maxAttempts",
        "sleeper",
        "requestIdFactory",
      ]),
    )
  ) {
    throw new McpConfigurationError(
      "Clockchain MCP client options are invalid.",
    );
  }
  const {
    token,
    fetchImpl = globalThis.fetch,
    requestTimeoutMs = DEFAULT_REQUEST_TIMEOUT_MS,
    maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES,
    maxAttempts = DEFAULT_MAX_ATTEMPTS,
    sleeper = defaultSleeper,
    requestIdFactory,
  } = options;

  const safeToken = validateToken(token);
  assertFetch(fetchImpl);
  configurationInteger(
    requestTimeoutMs,
    "Clockchain request timeout",
    { maximum: MAX_CONFIGURED_TIMEOUT_MS },
  );
  configurationInteger(
    maxResponseBytes,
    "Clockchain response size limit",
    { maximum: MAX_CONFIGURED_RESPONSE_BYTES },
  );
  configurationInteger(maxAttempts, "Clockchain retry attempts", {
    maximum: MAX_CONFIGURED_ATTEMPTS,
  });
  if (typeof sleeper !== "function") {
    throw new McpConfigurationError(
      "Clockchain retry sleeper is invalid.",
    );
  }
  if (
    requestIdFactory !== undefined &&
    typeof requestIdFactory !== "function"
  ) {
    throw new McpConfigurationError(
      "Clockchain request id factory is invalid.",
    );
  }

  let nextRequestId = 1;

  async function call(name, args) {
    const toolName = nonemptyString(
      name,
      "Clockchain MCP tool name",
      MAX_IDENTIFIER_LENGTH,
    );
    let toolArguments;
    try {
      toolArguments = normalizeKnownToolArguments(toolName, args);
    } catch (error) {
      if (error instanceof McpError) {
        throw cloneSafeError(error, safeToken);
      }
      throw new McpConfigurationError(
        "Clockchain MCP tool arguments are invalid.",
      );
    }
    let id;
    try {
      id = requestIdValue(
        requestIdFactory
          ? requestIdFactory()
          : nextRequestId++,
      );
    } catch (error) {
      throw cloneSafeError(error, safeToken);
    }

    const request = {
      jsonrpc: JSON_RPC_VERSION,
      id,
      method: "tools/call",
      params: {
        name: toolName,
        arguments: toolArguments,
      },
    };
    let body;
    try {
      body = JSON.stringify(request);
    } catch {
      throw new McpConfigurationError(
        "Clockchain MCP request is invalid.",
      );
    }
    if (Buffer.byteLength(body, "utf8") > MAX_REQUEST_BYTES) {
      throw new McpConfigurationError(
        "Clockchain MCP request exceeds the size limit.",
      );
    }

    const mayRetry = READ_RETRY_TOOLS.has(toolName);

    for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
      let response;
      let text;

      try {
        ({ response, text } = await fetchBounded({
          fetchImpl,
          init: {
            method: "POST",
            headers: {
              accept: "application/json, text/event-stream",
              "content-type": "application/json",
              "x-api-key": safeToken,
            },
            body,
            cache: "no-store",
          },
          maxResponseBytes,
          requestTimeoutMs,
          timeoutMessage: "Clockchain MCP request timed out.",
          transportMessage: "Clockchain MCP request failed.",
          url: MCP_URL,
        }));
      } catch (error) {
        if (
          error instanceof McpNetworkError &&
          mayRetry &&
          attempt + 1 < maxAttempts
        ) {
          await waitForRetry(sleeper, backoffDelay(attempt));
          continue;
        }
        throw cloneSafeError(error, safeToken);
      }

      if (
        response.status === 401 ||
        response.status === 403
      ) {
        throw new McpConfigurationError(
          "Clockchain MCP authorization failed.",
          "MCP_AUTHORIZATION",
        );
      }

      if (response.status === 429) {
        if (mayRetry && attempt + 1 < maxAttempts) {
          const retryAfter = parseRetryAfter(
            responseHeader(response.headers, "retry-after"),
          );
          await waitForRetry(
            sleeper,
            retryAfter ?? backoffDelay(attempt),
          );
          continue;
        }
        throw new McpNetworkError(
          "Clockchain MCP rate limit was exceeded.",
          "MCP_RATE_LIMIT",
        );
      }

      if (response.status >= 500) {
        if (mayRetry && attempt + 1 < maxAttempts) {
          await waitForRetry(sleeper, backoffDelay(attempt));
          continue;
        }
        throw new McpNetworkError(
          "Clockchain MCP service is unavailable.",
          "MCP_SERVICE_UNAVAILABLE",
        );
      }

      if (!isSuccessfulStatus(response.status)) {
        throw new McpProtocolError(
          "Clockchain MCP request was rejected.",
          "MCP_HTTP_ERROR",
        );
      }

      try {
        return parseToolResult(
          parseSseJsonRpc(text, { expectedId: id }),
        );
      } catch (error) {
        throw cloneSafeError(error, safeToken);
      }
    }

    throw new McpNetworkError(
      "Clockchain MCP request failed.",
      "MCP_NETWORK",
    );
  }

  return {
    call,
    resolveAgent: async (agentId) =>
      call("resolve_agent", { agent_id: agentId }),
    getTimestamp: async () => call("get_timestamp", {}),
    attestAction: async (args) =>
      call("attest_action", args),
    completeAttestation: async (receipt) =>
      call("complete_attestation", { receipt }),
    verifyReceipt: async (receipt) =>
      call("verify_receipt", { receipt }),
    verifyCrossParty: async (identifiers = {}) => {
      if (
        !hasOnlyKeys(
          identifiers,
          new Set(["ledgerId", "blockHeight", "hash"]),
        )
      ) {
        throw new McpConfigurationError(
          "Clockchain cross-party identifiers are invalid.",
        );
      }
      const {
        ledgerId,
        blockHeight,
        hash,
      } = identifiers;
      const args = {};
      if (ledgerId !== undefined) {
        args.ledger_id = ledgerId;
      }
      if (blockHeight !== undefined) {
        args.block_height = blockHeight;
      }
      if (hash !== undefined) {
        args.hash = hash;
      }
      return call("verify_cross_party", args);
    },
  };
}

function identityField(identity, key) {
  if (Object.hasOwn(identity, key)) {
    return identity[key];
  }
  const aliases = {
    agentId: "agent_id",
    agent_id: "agentId",
    identityReference: "identity_reference",
    identity_reference: "identityReference",
  };
  return aliases[key] && Object.hasOwn(identity, aliases[key])
    ? identity[aliases[key]]
    : undefined;
}

function verificationValuesMatch(actual, expected, key) {
  if (
    key === "agentId" ||
    key === "agent_id" ||
    typeof expected === "bigint"
  ) {
    try {
      return (
        normalizeIdentifier(actual, "Resolved identity") ===
        normalizeIdentifier(expected, "Expected identity")
      );
    } catch {
      return false;
    }
  }
  if (
    typeof actual === "string" &&
    typeof expected === "string" &&
    /^0x[0-9a-f]{40}$/i.test(actual) &&
    /^0x[0-9a-f]{40}$/i.test(expected)
  ) {
    return actual.toLowerCase() === expected.toLowerCase();
  }
  return Object.is(actual, expected);
}

export function assertResolvedIdentity(identity, expected) {
  if (!isPlainObject(identity) || identity.status !== "active") {
    throw new McpVerificationError(
      "Clockchain resolved identity must be active.",
      "MCP_IDENTITY_INACTIVE",
    );
  }

  if (expected !== undefined) {
    const expectedFields = isPlainObject(expected)
      ? Object.entries(expected)
      : [["agentId", expected]];

    for (const [key, value] of expectedFields) {
      if (
        value !== undefined &&
        !verificationValuesMatch(
          identityField(identity, key),
          value,
          key,
        )
      ) {
        throw new McpVerificationError(
          "Clockchain resolved identity does not match.",
          "MCP_IDENTITY_MISMATCH",
        );
      }
    }
  }
  return identity;
}

function hasCanonicalConfirmedAnchor(receipt) {
  return (
    isPlainObject(receipt) &&
    receipt.status === "anchored" &&
    isPlainObject(receipt.anchor) &&
    receipt.anchor.confirmed === true &&
    typeof receipt.anchor.blockHeight === "string" &&
    /^(0|[1-9]\d*)$/.test(receipt.anchor.blockHeight)
  );
}

function isAwaitingConsensusTime(receipt) {
  return (
    hasCanonicalConfirmedAnchor(receipt) &&
    (!Object.hasOwn(receipt.anchor, "consensusTime") ||
      receipt.anchor.consensusTime === null)
  );
}

function isCompletionText(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.trim() === value &&
    !CONTROL_CHARACTER_PATTERN.test(value)
  );
}

function hasCompletionReadyFields(receipt) {
  return (
    isPlainObject(receipt) &&
    Object.hasOwn(receipt, "agentId") &&
    isCompletionText(receipt.agentId) &&
    Object.hasOwn(receipt, "action") &&
    isCompletionText(receipt.action) &&
    Object.hasOwn(receipt, "eventHash") &&
    typeof receipt.eventHash === "string" &&
    CANONICAL_SHA256_PATTERN.test(receipt.eventHash) &&
    Object.hasOwn(receipt, "network") &&
    isCompletionText(receipt.network) &&
    Object.hasOwn(receipt, "payload") &&
    isPlainObject(receipt.payload) &&
    Object.hasOwn(receipt.payload, "inputs") &&
    Object.hasOwn(receipt.payload, "outputs") &&
    Object.hasOwn(receipt, "anchor") &&
    isPlainObject(receipt.anchor) &&
    Object.hasOwn(receipt.anchor, "ledgerId") &&
    isCompletionText(receipt.anchor.ledgerId)
  );
}

function hasCanonicalUnconfirmedAnchor(receipt) {
  return (
    isPlainObject(receipt?.anchor) &&
    receipt.anchor.confirmed === false &&
    receipt.anchor.blockHeight === null
  );
}

function assertCompletionReadyReceipt(receipt) {
  const hasPollableState =
    (POLLABLE_RECEIPT_STATUSES.has(receipt?.status) &&
      hasCanonicalUnconfirmedAnchor(receipt)) ||
    isAwaitingConsensusTime(receipt);

  if (
    !hasCompletionReadyFields(receipt) ||
    !hasPollableState
  ) {
    throw new McpVerificationError(
      "Clockchain receipt is not safe to complete.",
      "MCP_INVALID_RECEIPT",
    );
  }
  return receipt;
}

export function assertAnchoredReceipt(receipt) {
  if (
    !hasCanonicalConfirmedAnchor(receipt) ||
    typeof receipt.anchor.consensusTime !== "string" ||
    receipt.anchor.consensusTime.length === 0 ||
    receipt.anchor.consensusTime.trim() !==
      receipt.anchor.consensusTime ||
    /[\u0000-\u001f\u007f-\u009f]/.test(
      receipt.anchor.consensusTime,
    )
  ) {
    throw new McpVerificationError(
      "Clockchain receipt must be anchored, confirmed, and include a block height and consensus time.",
      "MCP_RECEIPT_NOT_ANCHORED",
    );
  }
  return receipt;
}

export function assertReceiptVerification(result) {
  if (!isPlainObject(result) || result.match !== true) {
    throw new McpVerificationError(
      "Clockchain receipt verification must match.",
      "MCP_RECEIPT_MISMATCH",
    );
  }
  if (result.verifiedAgainst !== "on-chain block") {
    throw new McpVerificationError(
      "Clockchain receipt must be verified against an on-chain block.",
      "MCP_RECEIPT_NOT_ON_CHAIN",
    );
  }
  return result;
}

export function assertCrossPartyVerification(result) {
  if (
    !isPlainObject(result) ||
    !isPlainObject(result.onChain) ||
    result.onChain.verifiedAgainst !== "on-chain block"
  ) {
    throw new McpVerificationError(
      "Clockchain cross-party result must be verified against an on-chain block.",
      "MCP_CROSS_PARTY_NOT_ON_CHAIN",
    );
  }
  if (result.onChain.keyless !== true) {
    throw new McpVerificationError(
      "Clockchain cross-party verification must be keyless.",
      "MCP_CROSS_PARTY_NOT_KEYLESS",
    );
  }
  return result;
}

export async function completeReceipt(
  client,
  receipt,
  options = {},
) {
  if (
    !hasOnlyKeys(
      options,
      new Set(["attempts", "intervalMs", "sleeper"]),
    )
  ) {
    throw new McpConfigurationError(
      "Clockchain completion options are invalid.",
    );
  }
  const {
    attempts = 8,
    intervalMs = 1_500,
    sleeper = defaultSleeper,
  } = options;

  if (
    !client ||
    typeof client.completeAttestation !== "function"
  ) {
    throw new McpConfigurationError(
      "Clockchain completion client is invalid.",
    );
  }
  configurationInteger(attempts, "Clockchain completion attempts", {
    maximum: 100,
  });
  configurationInteger(
    intervalMs,
    "Clockchain completion interval",
    {
      maximum: MAX_CONFIGURED_TIMEOUT_MS,
      minimum: 0,
    },
  );
  if (typeof sleeper !== "function") {
    throw new McpConfigurationError(
      "Clockchain completion sleeper is invalid.",
    );
  }
  if (!isPlainObject(receipt)) {
    throw new McpVerificationError(
      "Clockchain receipt status is invalid.",
      "MCP_INVALID_RECEIPT",
    );
  }
  const awaitingConsensusTime =
    isAwaitingConsensusTime(receipt);
  if (
    receipt.status === "anchored" &&
    !awaitingConsensusTime
  ) {
    return assertAnchoredReceipt(receipt);
  }
  if (
    !POLLABLE_RECEIPT_STATUSES.has(receipt.status) &&
    !awaitingConsensusTime
  ) {
    throw new McpVerificationError(
      "Clockchain receipt status must be pending, degraded, or anchored.",
      "MCP_INVALID_RECEIPT_STATUS",
    );
  }
  assertCompletionReadyReceipt(receipt);

  let current = receipt;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    await sleeper(intervalMs);
    current = await client.completeAttestation(current);

    if (current?.status === "anchored") {
      if (isAwaitingConsensusTime(current)) {
        assertCompletionReadyReceipt(current);
        continue;
      }
      return assertAnchoredReceipt(current);
    }
    if (
      !isPlainObject(current) ||
      !POLLABLE_RECEIPT_STATUSES.has(current.status)
    ) {
      throw new McpVerificationError(
        "Clockchain receipt did not reach an anchored status.",
        "MCP_RECEIPT_COMPLETION_FAILED",
      );
    }
    assertCompletionReadyReceipt(current);
  }

  throw new McpVerificationError(
    "Clockchain receipt did not reach strict anchored evidence after bounded attempts.",
    "MCP_RECEIPT_PENDING",
  );
}
