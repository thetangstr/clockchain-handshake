import {
  MCP_BASE_URL,
  MCP_URL,
} from "./constants.mjs";
import { redact } from "./redact.mjs";

// Live probing of the hosted Clockchain MCP endpoint observed `rate_limited`
// after roughly 4 concurrent or 6-9 sequential calls inside 30 seconds, with
// server-supplied `retry_after_seconds` values up to 31. Every wait bound below
// is derived from that observed 31s ceiling, not from a guessed default.
// The observed throttle answers immediately, either with HTTP 429 or with an
// in-body `rate_limited` object; it does not hold the connection open for the
// window. The request budget therefore stays at its baseline and the throttle
// is absorbed by the waits below, not by a longer request timeout.
const DEFAULT_REQUEST_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_RESPONSE_BYTES = 1_048_576;
// One attempt more than the baseline 3: with an honoured retry_after, four
// attempts cover one observed ~30s window without looping unbounded.
const DEFAULT_MAX_ATTEMPTS = 4;
const MAX_CONFIGURED_ATTEMPTS = 6;
const MAX_CONFIGURED_TIMEOUT_MS = 120_000;
const MAX_CONFIGURED_RESPONSE_BYTES = 4_194_304;
const MAX_REQUEST_BYTES = 262_144;
// Twice the observed 31s ceiling. The previous 30_000 cap silently truncated a
// server-supplied 31s wait and retried straight back into the same throttle.
const MAX_RETRY_AFTER_MS = 62_000;
// Backoff spaces retries after a transport error or a 5xx blip only. A throttle
// never reaches it: it waits the server's retry_after, or the rate-limit floor
// below when no usable hint arrives. This ceiling is reachable — at
// MAX_CONFIGURED_ATTEMPTS the sequence is [100, 200, 400, 800, 1_000] — so it
// stays a real bound rather than a decorative one.
const MAX_BACKOFF_DELAY_MS = 1_000;
// One maximal observed wait. This binds before the attempt cap at defaults, so
// one call may sit out at most one observed throttle window and a longer
// throttle fails closed for the caller to decide about. The worst case for a
// default read call is therefore 4 x 10s of request time plus 62s of waiting,
// i.e. 102s.
const MAX_TOTAL_RETRY_WAIT_MS = 62_000;
// Applied when a throttle arrives without a usable retry_after hint: the
// observed limiter needs several seconds of quiet before it clears, so the
// sub-second backoff would retry straight back into the same throttle.
const RATE_LIMIT_FLOOR_WAIT_MS = 5_000;
// One receipt completion polls `complete_attestation` once per attempt, and
// each poll is bounded by the 102s above. Without an elapsed-time deadline the
// worst case multiplies into tens of minutes against a demo whose documented
// budget is 30-90 seconds. 120s covers two observed throttle windows plus the
// nominal polling. This is both the default and the hard ceiling: a caller may
// lower it but never raise it, so the worst case for one completion stays at
// 120s plus the single poll already in flight when the deadline is crossed,
// i.e. 120_000 + 1_500 + 102_000 = 223_500ms.
const MAX_COMPLETION_DEADLINE_MS = 120_000;
const MAX_TOKEN_LENGTH = 8_192;
const MAX_SUBJECT_LENGTH = 128;
const MAX_IDENTIFIER_LENGTH = 256;
const MAX_ACTION_LENGTH = 128;
const MAX_IDEMPOTENCY_KEY_LENGTH = 256;
const JSON_RPC_VERSION = "2.0";
const CANONICAL_SHA256_PATTERN = /^[0-9a-f]{64}$/;
const CONTROL_CHARACTER_PATTERN =
  /[\u0000-\u001f\u007f-\u009f]/;
// Only read-only tools may be replayed automatically. A retried write can
// double-write irreversible ledger state, so this set must stay read-only.
const READ_RETRY_TOOLS = new Set([
  "resolve_agent",
  "get_timestamp",
  "complete_attestation",
  "verify_receipt",
  "verify_cross_party",
  // The three bilateral-protocol reads. They poll for a counterparty
  // transition, so they must be replayable through a throttle window.
  // `log_action`, the write they pair with, must never join them.
  "search_actions",
  "get_block",
  "generate_audit_trail",
]);
// Tools that create irreversible ledger or identity state. Nothing here may
// ever be added to READ_RETRY_TOOLS.
const WRITE_TOOLS = new Set([
  "attest_action",
  "log_action",
  "mint_identity",
  "revoke_identity",
  "delegate_authority",
  "create_schedule",
  "tsa_issue",
  "tsa_attest",
  "tsa_settle",
  "tsa_checkpoint",
]);
const RATE_LIMITED_ERROR_CODE = "rate_limited";
// RFC 9110 section 5.6.7 requires a recipient to accept all three HTTP-date
// shapes, so all three are matched explicitly: IMF-fixdate, the obsolete
// RFC 850 form, and asctime. Matching explicitly rather than deferring to
// Date.parse keeps the Clockchain ISO-8601 and `24-07-2026_19:27:50:981`
// stamps out, since Date.parse would silently invent a wait from them.
// Capture order is day, month, year, hours, minutes, seconds.
const IMF_FIXDATE_PATTERN =
  /^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), (0[1-9]|[12]\d|3[01]) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (\d{4}) ([01]\d|2[0-3]):([0-5]\d):([0-5]\d) GMT$/;
const RFC_850_DATE_PATTERN =
  /^(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), (0[1-9]|[12]\d|3[01])-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)-(\d{4}|\d{2}) ([01]\d|2[0-3]):([0-5]\d):([0-5]\d) GMT$/;
// asctime carries no zone; RFC 9110 fixes it at UTC. Capture order is month,
// day, hours, minutes, seconds, year.
const ASCTIME_DATE_PATTERN =
  /^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) ( [1-9]|[12]\d|3[01]) ([01]\d|2[0-3]):([0-5]\d):([0-5]\d) (\d{4})$/;
const MONTH_INDEX = new Map([
  ["Jan", 0],
  ["Feb", 1],
  ["Mar", 2],
  ["Apr", 3],
  ["May", 4],
  ["Jun", 5],
  ["Jul", 6],
  ["Aug", 7],
  ["Sep", 8],
  ["Oct", 9],
  ["Nov", 10],
  ["Dec", 11],
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
// Bilateral reference ids: lowercase, digits, `:` the sole separator, at most
// 120 bytes (design section 4.7). The gateway demonstrably normalizes at
// least one sibling field server-side, and exact-match search tolerates zero
// mutation, so the charset is asserted before every write and every search.
// This mirrors REFID_PATTERN in src/bilateral/refid.mjs, restated here so the
// transport stays free of protocol-module imports.
const REFERENCE_ID_PATTERN = /^[0-9a-z:]{1,120}$/;
const SHA256_HASH_TYPE = "SHA-256";
const LOG_ACTION_KEYS = new Set([
  "asset_reference_id",
  "asset_hash",
  "hash_type",
  "version_number",
  "idempotency_key",
  "wait",
  "wait_ms",
  "allow_degraded",
]);
// Spec-banned log_action parameters (design section 4.8): `content` makes the
// server hash a serialization we do not control, `did` mutates the reference
// id server-side in an undocumented way, and `additional_info` is
// punctuation-stripped and absent from the on-chain projection.
const LOG_ACTION_FORBIDDEN_KEYS = Object.freeze([
  "content",
  "did",
  "additional_info",
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

export class McpRateLimitedError extends McpNetworkError {
  constructor(message, options = {}) {
    const {
      code = "MCP_RATE_LIMIT",
      retryAfterMs = null,
    } = options;
    super(message, code);
    this.retryAfterMs =
      Number.isSafeInteger(retryAfterMs) && retryAfterMs >= 0
        ? Math.min(retryAfterMs, MAX_RETRY_AFTER_MS)
        : null;
  }
}

export class McpVerificationError extends McpError {
  constructor(message, code = "MCP_VERIFICATION") {
    super(message, { category: "verification", code });
  }
}

export const READ_RETRY_TOOL_NAMES = Object.freeze([
  ...READ_RETRY_TOOLS,
]);
export const WRITE_TOOL_NAMES = Object.freeze([...WRITE_TOOLS]);

for (const name of WRITE_TOOLS) {
  if (READ_RETRY_TOOLS.has(name)) {
    throw new McpConfigurationError(
      "Clockchain read-only retry set must never include a write tool.",
    );
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
  if (error instanceof McpRateLimitedError) {
    return new McpRateLimitedError(
      sanitizeMessage(error.message, canaries),
      {
        code: error.code,
        retryAfterMs: error.retryAfterMs,
      },
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

function clampWaitMs(milliseconds) {
  return Math.min(Math.max(0, milliseconds), MAX_RETRY_AFTER_MS);
}

function retryAfterSecondsToMs(value) {
  if (
    typeof value === "number" &&
    Number.isFinite(value) &&
    value >= 0
  ) {
    return clampWaitMs(Math.ceil(value * 1_000));
  }
  if (
    typeof value === "string" &&
    /^\d+(?:\.\d+)?$/.test(value)
  ) {
    return clampWaitMs(Math.ceil(Number(value) * 1_000));
  }
  return null;
}

// `retry_after_seconds` is the key observed live; `retry_after` is accepted as
// the other plausible spelling. Both are optional and preferred in that order,
// and any other shape yields no hint, so the transport falls back to the
// rate-limit floor rather than inventing a wait from an unknown field.
function throttleHintMs(payload) {
  if (Object.hasOwn(payload, "retry_after_seconds")) {
    return retryAfterSecondsToMs(payload.retry_after_seconds);
  }
  if (Object.hasOwn(payload, "retry_after")) {
    return retryAfterSecondsToMs(payload.retry_after);
  }
  return null;
}

// The hosted service also throttles inside an HTTP 200 tool result whose body
// is {"error":"rate_limited","retry_after_seconds":N}. Returning that body as a
// normal payload is a fail-open: a caller polling for a counterparty record
// would read it as "the peer never published".
//
// Considered and deliberately not handled: a throttle raised at the JSON-RPC
// layer, i.e. an envelope whose `error` member names `rate_limited`.
// `assertJsonRpcEnvelope` rejects any error envelope as McpProtocolError before
// this runs. That is fail-closed but discards the retry_after hint and is not
// retried. No live response has been observed in that shape, so no speculative
// parser is added here — a future reader must not assume the path is covered.
function assertNotRateLimited(payload) {
  if (
    !isPlainObject(payload) ||
    payload.error !== RATE_LIMITED_ERROR_CODE
  ) {
    return payload;
  }
  throw new McpRateLimitedError(
    "Clockchain MCP rate limit was exceeded.",
    {
      code: "MCP_RATE_LIMITED_BODY",
      retryAfterMs: throttleHintMs(payload),
    },
  );
}

function toolResultPreview(result) {
  if (Object.hasOwn(result, "structuredContent")) {
    return result.structuredContent;
  }
  const text =
    Array.isArray(result.content) &&
    isPlainObject(result.content[0])
      ? result.content[0].text
      : undefined;
  if (typeof text !== "string") {
    return undefined;
  }
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
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
    assertNotRateLimited(toolResultPreview(result));
    throw new McpProtocolError(
      "Clockchain MCP tool reported an error.",
      "MCP_TOOL_ERROR",
    );
  }

  if (Object.hasOwn(result, "structuredContent")) {
    return assertNotRateLimited(
      assertToolPayload(result.structuredContent),
    );
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
  return assertNotRateLimited(assertToolPayload(value));
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
    throw new McpRateLimitedError(
      "Clockchain token rate limit was exceeded.",
      {
        retryAfterMs: parseRetryAfter(
          responseHeader(response.headers, "retry-after"),
        ),
      },
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

function referenceIdArgument(value) {
  if (
    typeof value !== "string" ||
    !REFERENCE_ID_PATTERN.test(value)
  ) {
    throw new McpConfigurationError(
      "Clockchain asset reference id is invalid.",
    );
  }
  return value;
}

function normalizeLogActionArguments(args) {
  for (const key of LOG_ACTION_FORBIDDEN_KEYS) {
    if (Object.hasOwn(args, key)) {
      throw new McpConfigurationError(
        `log_action must never send ${key}.`,
        "MCP_FORBIDDEN_LOG_ACTION_FIELD",
      );
    }
  }
  exactArguments(args, LOG_ACTION_KEYS, "log_action arguments");
  if (
    typeof args.asset_hash !== "string" ||
    !CANONICAL_SHA256_PATTERN.test(args.asset_hash)
  ) {
    throw new McpConfigurationError(
      "Clockchain asset hash is invalid.",
    );
  }
  const normalized = {
    asset_reference_id: referenceIdArgument(
      args.asset_reference_id,
    ),
    asset_hash: args.asset_hash,
  };

  if (Object.hasOwn(args, "hash_type")) {
    if (args.hash_type !== SHA256_HASH_TYPE) {
      throw new McpConfigurationError(
        "Clockchain hash type is invalid.",
      );
    }
    normalized.hash_type = args.hash_type;
  }
  if (Object.hasOwn(args, "version_number")) {
    normalized.version_number = configurationInteger(
      args.version_number,
      "Clockchain version number",
    );
  }
  if (Object.hasOwn(args, "idempotency_key")) {
    normalized.idempotency_key = nonemptyString(
      args.idempotency_key,
      "Clockchain idempotency_key",
      MAX_IDEMPOTENCY_KEY_LENGTH,
    );
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

function normalizeReferenceIdArguments(name, args) {
  exactArguments(
    args,
    new Set(["asset_reference_id"]),
    `${name} arguments`,
  );
  return {
    asset_reference_id: referenceIdArgument(
      args.asset_reference_id,
    ),
  };
}

function normalizeGetBlockArguments(args) {
  exactArguments(
    args,
    new Set(["height"]),
    "get_block arguments",
  );
  if (args.height === "latest") {
    return { height: "latest" };
  }
  // Heights travel as canonical decimal strings: every endpoint except
  // get_block's own response already uses strings, and a string cannot lose
  // precision on the wire.
  const height = canonicalDecimalText(args.height);
  if (height === null) {
    throw new McpConfigurationError(
      "Clockchain block height is invalid.",
    );
  }
  return { height };
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
    case "log_action":
      return normalizeLogActionArguments(args);
    case "search_actions":
    case "generate_audit_trail":
      return normalizeReferenceIdArguments(name, args);
    case "get_block":
      return normalizeGetBlockArguments(args);
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

// RFC 9110 section 5.6.7: a two-digit year that would land more than 50 years
// in the future denotes the most recent past year with the same two digits.
function expandHttpDateYear(text, now) {
  if (text.length === 4) {
    return Number(text);
  }
  const currentYear = new Date(now).getUTCFullYear();
  const candidate =
    Math.floor(currentYear / 100) * 100 + Number(text);
  return candidate - currentYear > 50 ? candidate - 100 : candidate;
}

// Converts an HTTP-date through Date.UTC rather than Date.parse, because
// Date.parse reads an asctime stamp in the host's local zone.
function httpDateToMs(value, now) {
  const fixdate =
    IMF_FIXDATE_PATTERN.exec(value) ??
    RFC_850_DATE_PATTERN.exec(value);
  const asctime = fixdate
    ? null
    : ASCTIME_DATE_PATTERN.exec(value);
  if (fixdate === null && asctime === null) {
    return null;
  }

  const [day, month, year, hours, minutes, seconds] = fixdate
    ? fixdate.slice(1)
    : [
        asctime[2],
        asctime[1],
        asctime[6],
        asctime[3],
        asctime[4],
        asctime[5],
      ];
  return Date.UTC(
    expandHttpDateYear(year, now),
    MONTH_INDEX.get(month),
    Number(day),
    Number(hours),
    Number(minutes),
    Number(seconds),
  );
}

// Retry-After is either delay-seconds or one of the three RFC 9110 HTTP-date
// shapes. Every other shape is rejected so an unrecognized stamp falls back to
// the rate-limit floor instead of letting a lenient Date.parse invent a wait.
function parseRetryAfter(value, now = Date.now()) {
  if (typeof value !== "string") {
    return null;
  }
  if (/^\d+(?:\.\d+)?$/.test(value)) {
    return retryAfterSecondsToMs(value);
  }

  const timestamp = httpDateToMs(value, now);
  if (timestamp === null || !Number.isFinite(timestamp)) {
    return null;
  }
  return clampWaitMs(timestamp - now);
}

// Only spaces retries after a transport error or a 5xx blip; throttles use
// retry_after or RATE_LIMIT_FLOOR_WAIT_MS instead.
function backoffDelay(attempt) {
  return Math.min(100 * 2 ** attempt, MAX_BACKOFF_DELAY_MS);
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

function clockReading(now) {
  const reading = now();
  if (typeof reading !== "number" || !Number.isFinite(reading)) {
    throw new McpConfigurationError(
      "Clockchain elapsed-time clock is invalid.",
    );
  }
  return reading;
}

function protocolText(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= MAX_IDENTIFIER_LENGTH &&
    value.trim() === value &&
    !CONTROL_CHARACTER_PATTERN.test(value)
  );
}

// log_action's response shape is unverified upstream and the bilateral design
// derives no protocol state from a write response: the mandatory read-back is
// the source of truth. Only the ledger id and an optional block height are
// validated and returned; everything else is dropped untrusted.
function assertLogActionResult(payload) {
  if (
    !isPlainObject(payload) ||
    !protocolText(payload.ledgerId)
  ) {
    throw new McpProtocolError(
      "Clockchain log_action result is invalid.",
      "MCP_INVALID_LOG_RESULT",
    );
  }
  const rawHeight = Object.hasOwn(payload, "blockHeight")
    ? payload.blockHeight
    : null;
  if (rawHeight === null) {
    return { ledgerId: payload.ledgerId, blockHeight: null };
  }
  const blockHeight = canonicalDecimalText(rawHeight);
  if (blockHeight === null) {
    throw new McpProtocolError(
      "Clockchain log_action result is invalid.",
      "MCP_INVALID_LOG_RESULT",
    );
  }
  return { ledgerId: payload.ledgerId, blockHeight };
}

// The Array contract is the bilateral protocol's safety: search_actions is
// the only read that misses cleanly, so a non-array reply means the service
// answered with something other than a search result, and treating it as
// "absent" would fail open. Length 0 is the one clean miss. Only the five
// fields the verification recipe reads survive; hostile extra keys —
// including the operator's email in `clientId` — are dropped untrusted.
// Returned assetReferenceId values are NOT held to the write-side charset:
// legacy attest-generated ids contain underscores, and byte-equality against
// the derived key belongs to src/bilateral/refid.mjs, not the transport.
function assertSearchActionsResult(payload) {
  if (!Array.isArray(payload)) {
    throw new McpProtocolError(
      "Clockchain search_actions result must be an array.",
      "MCP_SEARCH_NOT_ARRAY",
    );
  }
  return payload.map((record) => {
    const blockHeight = isPlainObject(record)
      ? canonicalDecimalText(record.blockHeight)
      : null;
    if (
      blockHeight === null ||
      !protocolText(record.ledgerId) ||
      !protocolText(record.assetReferenceId) ||
      typeof record.assetHash !== "string" ||
      !CANONICAL_SHA256_PATTERN.test(record.assetHash) ||
      record.hashType !== SHA256_HASH_TYPE
    ) {
      throw new McpProtocolError(
        "Clockchain search_actions record is invalid.",
        "MCP_INVALID_SEARCH_RECORD",
      );
    }
    return {
      ledgerId: record.ledgerId,
      assetReferenceId: record.assetReferenceId,
      assetHash: record.assetHash,
      blockHeight,
      hashType: record.hashType,
    };
  });
}

// blockTime is returned VERBATIM: src/bilateral/blocktime.mjs owns parsing,
// and parsing here would re-create the Date.parse hazards the design bans.
// blockHeight is a NUMBER in this one endpoint and a STRING everywhere else,
// so it is normalized to the canonical decimal text used across the repo.
function assertBlockResult(payload) {
  const blockHeight = isPlainObject(payload)
    ? canonicalDecimalText(payload.blockHeight)
    : null;
  if (
    blockHeight === null ||
    !protocolText(payload.proposerAddress) ||
    !protocolText(payload.blockTime)
  ) {
    throw new McpProtocolError(
      "Clockchain get_block result is invalid.",
      "MCP_INVALID_BLOCK_RESULT",
    );
  }
  return {
    blockHeight,
    proposerAddress: payload.proposerAddress,
    blockTime: payload.blockTime,
  };
}

// The aggregate verifier gates duplicates on `count` alone (design section
// 6.5), so only that surface is validated and returned. A count that
// disagrees with the events it summarizes is hostile or broken either way
// and fails closed rather than letting the caller pick a side.
function assertAuditTrailResult(payload) {
  const count = isPlainObject(payload)
    ? canonicalDecimalText(payload.count)
    : null;
  if (
    count === null ||
    !protocolText(payload.assetReferenceId) ||
    !Array.isArray(payload.events) ||
    !payload.events.every(isPlainObject) ||
    count !== String(payload.events.length)
  ) {
    throw new McpProtocolError(
      "Clockchain generate_audit_trail result is invalid.",
      "MCP_INVALID_AUDIT_TRAIL",
    );
  }
  return {
    assetReferenceId: payload.assetReferenceId,
    count,
  };
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

    // The two sets are proven disjoint at module load, so membership in
    // READ_RETRY_TOOLS is already proof that `toolName` is not a write.
    const mayRetry = READ_RETRY_TOOLS.has(toolName);
    let totalWaitMs = 0;

    async function waitBeforeRetry(attempt, retryAfterMs, fallbackMs) {
      if (!mayRetry || attempt + 1 >= maxAttempts) {
        return false;
      }

      const delay = retryAfterMs ?? fallbackMs;
      if (totalWaitMs + delay > MAX_TOTAL_RETRY_WAIT_MS) {
        return false;
      }
      totalWaitMs += delay;
      await waitForRetry(sleeper, delay);
      return true;
    }

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
          (await waitBeforeRetry(
            attempt,
            null,
            backoffDelay(attempt),
          ))
        ) {
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
        const retryAfterMs = parseRetryAfter(
          responseHeader(response.headers, "retry-after"),
        );
        if (
          await waitBeforeRetry(
            attempt,
            retryAfterMs,
            RATE_LIMIT_FLOOR_WAIT_MS,
          )
        ) {
          continue;
        }
        throw new McpRateLimitedError(
          "Clockchain MCP rate limit was exceeded.",
          { retryAfterMs },
        );
      }

      if (response.status >= 500) {
        if (
          await waitBeforeRetry(
            attempt,
            null,
            backoffDelay(attempt),
          )
        ) {
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
        if (
          error instanceof McpRateLimitedError &&
          (await waitBeforeRetry(
            attempt,
            error.retryAfterMs,
            RATE_LIMIT_FLOOR_WAIT_MS,
          ))
        ) {
          continue;
        }
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
    logAction: async (args) =>
      assertLogActionResult(await call("log_action", args)),
    searchActions: async (args) =>
      assertSearchActionsResult(
        await call("search_actions", args),
      ),
    getBlock: async (args) =>
      assertBlockResult(await call("get_block", args)),
    generateAuditTrail: async (args) =>
      assertAuditTrailResult(
        await call("generate_audit_trail", args),
      ),
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

function canonicalDecimalText(value) {
  if (
    typeof value === "string" &&
    /^(0|[1-9]\d*)$/.test(value)
  ) {
    return value;
  }
  if (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= 0
  ) {
    return String(value);
  }
  if (typeof value === "bigint" && value >= 0n) {
    return String(value);
  }
  return null;
}

function hasExpectedCrossPartyBinding(expected) {
  return (
    isPlainObject(expected) &&
    Object.hasOwn(expected, "ledgerId") &&
    typeof expected.ledgerId === "string" &&
    expected.ledgerId.length > 0 &&
    Object.hasOwn(expected, "blockHeight") &&
    canonicalDecimalText(expected.blockHeight) !== null &&
    Object.hasOwn(expected, "anchoredHash") &&
    typeof expected.anchoredHash === "string" &&
    expected.anchoredHash.length > 0 &&
    (
      !Object.hasOwn(expected, "assetReferenceId") ||
      (
        typeof expected.assetReferenceId === "string" &&
        expected.assetReferenceId.length > 0
      )
    )
  );
}

export function assertCrossPartyVerification(
  result,
  expected,
) {
  if (!hasExpectedCrossPartyBinding(expected)) {
    throw new McpVerificationError(
      "Clockchain cross-party verification requires an expected receipt binding.",
      "MCP_CROSS_PARTY_BINDING_REQUIRED",
    );
  }
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
  if (
    result.onChain.ledgerId !== expected.ledgerId ||
    canonicalDecimalText(result.onChain.blockHeight) !==
      canonicalDecimalText(expected.blockHeight) ||
    result.onChain.anchoredHash !== expected.anchoredHash ||
    (
      Object.hasOwn(expected, "assetReferenceId") &&
      result.onChain.assetReferenceId !==
        expected.assetReferenceId
    )
  ) {
    throw new McpVerificationError(
      "Clockchain cross-party verification does not match the expected receipt binding.",
      "MCP_CROSS_PARTY_BINDING_MISMATCH",
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
      new Set([
        "attempts",
        "deadlineMs",
        "intervalMs",
        "now",
        "sleeper",
      ]),
    )
  ) {
    throw new McpConfigurationError(
      "Clockchain completion options are invalid.",
    );
  }
  const {
    attempts = 8,
    deadlineMs = MAX_COMPLETION_DEADLINE_MS,
    intervalMs = 1_500,
    now = Date.now,
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
    deadlineMs,
    "Clockchain completion deadline",
    { maximum: MAX_COMPLETION_DEADLINE_MS },
  );
  configurationInteger(
    intervalMs,
    "Clockchain completion interval",
    {
      maximum: MAX_CONFIGURED_TIMEOUT_MS,
      minimum: 0,
    },
  );
  if (typeof now !== "function") {
    throw new McpConfigurationError(
      "Clockchain completion clock is invalid.",
    );
  }
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

  const started = clockReading(now);
  let current = receipt;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    // The attempt cap alone does not bound wall-clock time: each poll is a
    // whole transport call, itself bounded by MAX_TOTAL_RETRY_WAIT_MS of
    // throttle waiting. The deadline is what keeps one completion inside the
    // demo's documented budget.
    if (clockReading(now) - started > deadlineMs) {
      throw new McpVerificationError(
        "Clockchain receipt completion exceeded its elapsed-time budget.",
        "MCP_RECEIPT_DEADLINE",
      );
    }
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
