import { createHash, randomBytes as nodeRandomBytes, timingSafeEqual } from "node:crypto";
import https from "node:https";
import net from "node:net";

import {
  PAYMENT_INTAKE_TOOL_DESCRIPTOR,
  REQUEST_PAYMENT_TOOL_NAME,
  buildPaymentIntakeToolResult,
} from "./payment-intake.mjs";

export const PAYER_MCP_PROTOCOL_VERSION = "2025-11-25";

const MAX_HEADERS = 32;
const MAX_BODY_BYTES = 65_536;
const HEADER_TIMEOUT_MS = 5_000;
const REQUEST_TIMEOUT_MS = 10_000;
const FAILED_AUTH_LIMIT = 16;
const FAILED_AUTH_WINDOW_MS = 60_000;
const SESSION_REQUEST_LIMIT = 8;
const DIGEST_PATTERN = /^[0-9a-f]{64}$/;
const CAPABILITY_PATTERN = /^[0-9a-f]{64}$/;
const JSON_CONTENT_TYPE = "application/json";
const JSON_ACCEPT = "application/json, text/event-stream";
const GENERIC_FAILURE = Object.freeze({ error: "PAYER_MCP_PROTOCOL_FAILED", paymentMoved: false });

function fail() {
  throw new Error("Payer MCP server failed safely.");
}

function validateHost(host) {
  if (typeof host !== "string" || net.isIP(host) === 0 || host === "0.0.0.0" || host === "::" || host === "::0") fail();
  return host;
}

function validatePort(port) {
  if (!Number.isInteger(port) || port < 0 || port > 65_535) fail();
  return port;
}

function validateDigest(value) {
  if (typeof value !== "string" || !DIGEST_PATTERN.test(value)) fail();
  return value;
}

function validateRepositorySha(value) {
  if (typeof value !== "string" || !/^[0-9a-f]{40}$/.test(value)) fail();
  return value;
}

function validatePem(value) {
  if (typeof value !== "string" || !value.includes("-----BEGIN") || !value.includes("-----END")) fail();
  return value;
}

function validateIntakeStore(value) {
  if (!value || typeof value.writeIntake !== "function") fail();
  return value;
}

function response(res, statusCode, body, headers = {}) {
  res.statusCode = statusCode;
  res.setHeader("Content-Type", JSON_CONTENT_TYPE);
  for (const [key, value] of Object.entries(headers)) res.setHeader(key, value);
  res.end(JSON.stringify(body));
}

function emptyResponse(res, statusCode) {
  res.statusCode = statusCode;
  res.end();
}

function protocolFailure(res, statusCode = 400) {
  response(res, statusCode, GENERIC_FAILURE);
}

function exactObject(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) fail();
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.length !== keys.length || keys.some((key, index) => ownKeys[index] !== key)) fail();
  return value;
}

function parseAuthorization(value) {
  if (typeof value !== "string" || !value.startsWith("Bearer ")) return null;
  const capability = value.slice("Bearer ".length);
  if (!CAPABILITY_PATTERN.test(capability)) return null;
  return capability;
}

function capabilityDigest(capability) {
  return createHash("sha256").update(Buffer.from(capability, "hex")).digest();
}

function authorized({ authorization, expectedDigest }) {
  const supplied = parseAuthorization(authorization);
  const expected = Buffer.from(expectedDigest, "hex");
  const actual = supplied === null ? Buffer.alloc(32) : capabilityDigest(supplied);
  const equal = timingSafeEqual(actual, expected);
  return supplied !== null && equal;
}

function sessionId(bytes) {
  return bytes.toString("base64url");
}

function validateCommonHeaders(req, expectedHost) {
  if (req.rawHeaders.length / 2 > MAX_HEADERS) return 431;
  if (req.url !== "/mcp") return 404;
  if (!["POST", "GET", "DELETE"].includes(req.method)) return 405;
  if (req.headers.host !== expectedHost) return 400;
  if (Object.hasOwn(req.headers, "origin")) return 400;
  if (req.method === "GET") return 405;
  if (req.headers.accept !== JSON_ACCEPT) return 400;
  if (req.method === "POST" && req.headers["content-type"] !== JSON_CONTENT_TYPE) return 415;
  const contentLength = req.headers["content-length"];
  if (contentLength !== undefined && (!/^(?:0|[1-9][0-9]*)$/.test(contentLength) || Number(contentLength) > MAX_BODY_BYTES)) return 413;
  return 0;
}

async function readBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) fail();
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function parseJsonRpc(text) {
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    fail();
  }
  return value;
}

function hasDuplicateId(session, id) {
  if (id === undefined) return false;
  const key = String(id);
  if (session.ids.has(key)) return true;
  session.ids.add(key);
  return false;
}

function validateRpcRequest(value) {
  exactObject(value, ["id", "jsonrpc", "method", "params"]);
  if (value.jsonrpc !== "2.0" || typeof value.method !== "string" || !(typeof value.id === "number" || typeof value.id === "string")) fail();
  return value;
}

function validateNotification(value) {
  exactObject(value, ["jsonrpc", "method"]);
  if (value.jsonrpc !== "2.0" || value.method !== "notifications/initialized") fail();
  return value;
}

function validateProtocolHeader(req) {
  if (req.headers["mcp-protocol-version"] !== PAYER_MCP_PROTOCOL_VERSION) fail();
}

function assertSessionRequest(session) {
  session.requests += 1;
  if (session.requests > SESSION_REQUEST_LIMIT) {
    session.retired = true;
    fail();
  }
  if (session.retired) fail();
}

export function createPayerMcpServer({
  capabilityDigest: expectedCapabilityDigest,
  host,
  intakeStore,
  nowMs = () => Date.now(),
  port,
  randomBytes = nodeRandomBytes,
  repositorySha,
  tlsCertificatePem,
  tlsPrivateKeyPem,
} = {}) {
  const bindHost = validateHost(host);
  const bindPort = validatePort(port);
  const digest = validateDigest(expectedCapabilityDigest);
  const sha = validateRepositorySha(repositorySha);
  const store = validateIntakeStore(intakeStore);
  const certificate = validatePem(tlsCertificatePem);
  const privateKey = validatePem(tlsPrivateKeyPem);
  if (typeof nowMs !== "function" || typeof randomBytes !== "function") fail();

  const sessions = new Map();
  const failedAuth = [];
  let server;

  function currentPort() {
    const address = server?.address();
    return typeof address === "object" && address !== null ? address.port : bindPort;
  }

  function expectedHost() {
    return `${bindHost}:${currentPort()}`;
  }

  function authBlocked() {
    const now = nowMs();
    while (failedAuth.length > 0 && now - failedAuth[0] > FAILED_AUTH_WINDOW_MS) failedAuth.shift();
    return failedAuth.length >= FAILED_AUTH_LIMIT;
  }

  function recordFailedAuth() {
    const now = nowMs();
    while (failedAuth.length > 0 && now - failedAuth[0] > FAILED_AUTH_WINDOW_MS) failedAuth.shift();
    failedAuth.push(now);
  }

  async function handlePost(req, res) {
    const text = await readBody(req);
    const value = parseJsonRpc(text);
    if (value.method === "notifications/initialized") {
      validateNotification(value);
      const id = req.headers["mcp-session-id"];
      validateProtocolHeader(req);
      const session = sessions.get(id);
      if (!session) fail();
      assertSessionRequest(session);
      session.initialized = true;
      emptyResponse(res, 202);
      return;
    }

    const rpc = validateRpcRequest(value);
    if (rpc.method === "initialize") {
      if (req.headers["mcp-session-id"] !== undefined) fail();
      const params = exactObject(rpc.params, ["protocolVersion"]);
      if (params.protocolVersion !== PAYER_MCP_PROTOCOL_VERSION) fail();
      const id = sessionId(randomBytes(16));
      const session = { ids: new Set([String(rpc.id)]), initialized: false, requests: 1, retired: false };
      sessions.set(id, session);
      response(res, 200, {
        id: rpc.id,
        jsonrpc: "2.0",
        result: {
          capabilities: { tools: {} },
          protocolVersion: PAYER_MCP_PROTOCOL_VERSION,
          serverInfo: { name: "clockchain-payer-local-mcp", version: "1.0.0" },
        },
      }, {
        "MCP-Protocol-Version": PAYER_MCP_PROTOCOL_VERSION,
        "MCP-Session-Id": id,
      });
      return;
    }

    validateProtocolHeader(req);
    const session = sessions.get(req.headers["mcp-session-id"]);
    if (!session || !session.initialized || hasDuplicateId(session, rpc.id)) fail();
    assertSessionRequest(session);
    if (rpc.method === "tools/list") {
      exactObject(rpc.params, []);
      response(res, 200, { id: rpc.id, jsonrpc: "2.0", result: { tools: [PAYMENT_INTAKE_TOOL_DESCRIPTOR] } });
      return;
    }
    if (rpc.method === "tools/call") {
      const params = exactObject(rpc.params, ["arguments", "name"]);
      if (params.name !== REQUEST_PAYMENT_TOOL_NAME) fail();
      const result = buildPaymentIntakeToolResult({ repositorySha: sha, toolInput: params.arguments });
      const record = await store.writeIntake({ request: params.arguments, response: result });
      response(res, 200, { id: rpc.id, jsonrpc: "2.0", result: record.response });
      return;
    }
    fail();
  }

  async function handleRequest(req, res) {
    try {
      req.setTimeout(REQUEST_TIMEOUT_MS, () => req.destroy());
      const headerStatus = validateCommonHeaders(req, expectedHost());
      if (headerStatus) {
        if (headerStatus === 405 && req.method === "GET" && req.url === "/mcp") {
          res.setHeader("Allow", "POST, DELETE");
        }
        protocolFailure(res, headerStatus);
        return;
      }
      if (authBlocked()) {
        protocolFailure(res, 429);
        return;
      }
      if (!authorized({ authorization: req.headers.authorization, expectedDigest: digest })) {
        recordFailedAuth();
        protocolFailure(res, 401);
        return;
      }
      if (req.method === "DELETE") {
        validateProtocolHeader(req);
        const id = req.headers["mcp-session-id"];
        const session = sessions.get(id);
        if (!session) fail();
        assertSessionRequest(session);
        session.retired = true;
        sessions.delete(id);
        response(res, 200, { paymentMoved: false, status: "deleted" });
        return;
      }
      await handlePost(req, res);
    } catch {
      if (!res.headersSent) protocolFailure(res);
      else res.destroy();
    }
  }

  return Object.freeze({
    async start() {
      if (server) fail();
      server = https.createServer({ cert: certificate, key: privateKey }, handleRequest);
      server.headersTimeout = HEADER_TIMEOUT_MS;
      server.requestTimeout = REQUEST_TIMEOUT_MS;
      await new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(bindPort, bindHost, () => {
          server.off("error", reject);
          resolve();
        });
      });
      return Object.freeze({ host: bindHost, port: currentPort(), url: `https://${bindHost}:${currentPort()}/mcp` });
    },
    async stop() {
      if (!server) return;
      const closing = server;
      server = undefined;
      await new Promise((resolve, reject) => closing.close((error) => error ? reject(error) : resolve()));
    },
  });
}
