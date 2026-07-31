import { createHash, randomBytes as nodeRandomBytes, timingSafeEqual, X509Certificate } from "node:crypto";
import http from "node:http";
import https from "node:https";
import net from "node:net";

import {
  PAYMENT_INTAKE_TOOL_DESCRIPTOR,
  REQUEST_PAYMENT_TOOL_NAME,
  buildPaymentIntakeToolResult,
} from "./payment-intake.mjs";
import { canonicalBytes } from "../canonical.mjs";
import { validatePublicEndpoint as validateNetworkEndpoint } from "../network-endpoint.mjs";

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
const BOOTSTRAP_ACCEPT = "application/json";
const GENERIC_FAILURE = Object.freeze({ error: "PAYER_MCP_PROTOCOL_FAILED", paymentMoved: false });
const BOOTSTRAP_FAILURE = Object.freeze({ error: "REQUESTOR_BOOTSTRAP_FAILED", paymentMoved: false });
const BOOTSTRAP_BROKER_RESPONSE_SCHEMA = "clockchain.requestor-bootstrap-broker-response/v1";
const PARSER_FAILURE_RESPONSE = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const SINGLETON_HEADERS = new Set([
  "accept",
  "authorization",
  "content-length",
  "content-type",
  "host",
  "mcp-protocol-version",
  "mcp-session-id",
]);
const BOOTSTRAP_CLAIM_KEYS = Object.freeze(["claimNonce", "paymentMoved", "repositorySha", "requestorPublicKey"]);
const UUID_V4_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const BASE64URL_32_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const BOOTSTRAP_ENVELOPE_ALGORITHM = "X25519-HKDF-SHA256-AES-256-GCM";
const BOOTSTRAP_ENVELOPE_SCHEMA = "clockchain.requestor-bootstrap-envelope/v1";
const KEY_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,63}$/;
const MAX_BOOTSTRAP_CIPHERTEXT_BYTES = 65_536;

function fail() {
  throw new Error("Payer MCP server failed safely.");
}

function closeParserFailureSocket(socket) {
  if (socket?.writable === true && typeof socket.end === "function") {
    try {
      socket.end(PARSER_FAILURE_RESPONSE);
      return;
    } catch {}
  }
  try {
    socket?.destroy?.();
  } catch {}
}

function validateHost(host) {
  if (typeof host !== "string" || host !== host.toLowerCase() || host.includes("%")) fail();
  const family = net.isIP(host);
  if (family === 0) fail();
  if (family === 4) {
    const octets = host.split(".");
    if (
      octets.length !== 4 ||
      octets.some((octet) => !/^(?:0|[1-9][0-9]{0,2})$/.test(octet) || String(Number(octet)) !== octet || Number(octet) > 255) ||
      octets.every((octet) => octet === "0")
    ) {
      fail();
    }
    return host;
  }
  let canonical;
  try {
    const parsed = new URL(`https://[${host}]/`);
    if (!parsed.hostname.startsWith("[") || !parsed.hostname.endsWith("]")) fail();
    canonical = parsed.hostname.slice(1, -1);
  } catch {
    fail();
  }
  if (
    host !== canonical ||
    canonical === "::" ||
    canonical === "::ffff:0:0"
  ) {
    fail();
  }
  return host;
}

function hostAuthority(host, port) {
  return net.isIP(host) === 6 ? `[${host}]:${port}` : `${host}:${port}`;
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

function validatePublicEndpoint(value, certificatePem, allowTestAddresses) {
  if (value === undefined) return null;
  if (typeof value !== "string") fail();
  let url;
  try {
    url = new URL(value);
  } catch {
    fail();
  }
  if (url.port === "") fail();
  let endpoint;
  try {
    endpoint = validateNetworkEndpoint(value, {
      allowedPaths: ["/mcp"],
      allowTestAddresses,
      defaultPort: Number(url.port),
      protocols: ["https:"],
    });
  } catch {
    fail();
  }
  let certificate;
  try {
    certificate = new X509Certificate(certificatePem);
  } catch {
    fail();
  }
  const certificateIdentity =
    net.isIP(endpoint.hostname) === 0
      ? certificate.checkHost(endpoint.hostname)
      : certificate.checkIP(endpoint.hostname);
  if (certificateIdentity !== endpoint.hostname) fail();
  return Object.freeze({
    authority: hostAuthority(endpoint.hostname, endpoint.port),
    url: endpoint.url,
  });
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
  res.setHeader("Content-Type", JSON_CONTENT_TYPE);
  res.end();
}

function protocolFailure(res, statusCode = 400) {
  response(res, statusCode, GENERIC_FAILURE);
}

function bootstrapFailure(res, statusCode = 400) {
  response(res, statusCode, BOOTSTRAP_FAILURE);
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
  const seenHeaders = new Map();
  for (let index = 0; index < req.rawHeaders.length; index += 2) {
    const name = req.rawHeaders[index];
    if (typeof name !== "string") return 400;
    const key = name.toLowerCase();
    seenHeaders.set(key, (seenHeaders.get(key) ?? 0) + 1);
  }
  for (const key of SINGLETON_HEADERS) {
    if ((seenHeaders.get(key) ?? 0) > 1 || (req.headersDistinct?.[key]?.length ?? 0) > 1) return 400;
  }
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
  rejectDuplicateJsonKeys(text);
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    fail();
  }
  return value;
}

function parseJson(text) {
  rejectDuplicateJsonKeys(text);
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    fail();
  }
  return value;
}

function rejectDuplicateJsonKeys(text) {
  if (typeof text !== "string" || text.length === 0 || text.length > MAX_BODY_BYTES) fail();
  let index = 0;
  const whitespace = () => {
    while (/[\t\n\r ]/.test(text[index] ?? "")) index += 1;
  };
  const parseString = () => {
    if (text[index] !== "\"") fail();
    index += 1;
    let value = "";
    while (index < text.length) {
      const char = text[index];
      if (char === "\"") {
        index += 1;
        return value;
      }
      if (char === "\\") {
        index += 1;
        const escaped = text[index];
        if (escaped === undefined) fail();
        if ("\"\\/".includes(escaped)) value += escaped;
        else if (escaped === "b") value += "\b";
        else if (escaped === "f") value += "\f";
        else if (escaped === "n") value += "\n";
        else if (escaped === "r") value += "\r";
        else if (escaped === "t") value += "\t";
        else if (escaped === "u") {
          const hex = text.slice(index + 1, index + 5);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail();
          value += String.fromCharCode(Number.parseInt(hex, 16));
          index += 4;
        } else {
          fail();
        }
      } else {
        if (char < " ") fail();
        value += char;
      }
      index += 1;
    }
    fail();
  };
  const parseNumber = () => {
    const start = index;
    if (text[index] === "-") index += 1;
    if (text[index] === "0") index += 1;
    else if (/[1-9]/.test(text[index] ?? "")) {
      while (/[0-9]/.test(text[index] ?? "")) index += 1;
    } else fail();
    if (text[index] === ".") {
      index += 1;
      if (!/[0-9]/.test(text[index] ?? "")) fail();
      while (/[0-9]/.test(text[index] ?? "")) index += 1;
    }
    if (text[index] === "e" || text[index] === "E") {
      index += 1;
      if (text[index] === "+" || text[index] === "-") index += 1;
      if (!/[0-9]/.test(text[index] ?? "")) fail();
      while (/[0-9]/.test(text[index] ?? "")) index += 1;
    }
    if (index === start) fail();
  };
  const parseLiteral = (literal) => {
    if (text.slice(index, index + literal.length) !== literal) fail();
    index += literal.length;
  };
  const parseArray = () => {
    index += 1;
    whitespace();
    if (text[index] === "]") {
      index += 1;
      return;
    }
    while (true) {
      parseValue();
      whitespace();
      if (text[index] === "]") {
        index += 1;
        return;
      }
      if (text[index] !== ",") fail();
      index += 1;
      whitespace();
    }
  };
  const parseObject = () => {
    index += 1;
    const keys = new Set();
    whitespace();
    if (text[index] === "}") {
      index += 1;
      return;
    }
    while (true) {
      const key = parseString();
      if (keys.has(key)) fail();
      keys.add(key);
      whitespace();
      if (text[index] !== ":") fail();
      index += 1;
      parseValue();
      whitespace();
      if (text[index] === "}") {
        index += 1;
        return;
      }
      if (text[index] !== ",") fail();
      index += 1;
      whitespace();
    }
  };
  function parseValue() {
    whitespace();
    const char = text[index];
    if (char === "{") return parseObject();
    if (char === "[") return parseArray();
    if (char === "\"") {
      parseString();
      return;
    }
    if (char === "t") return parseLiteral("true");
    if (char === "f") return parseLiteral("false");
    if (char === "n") return parseLiteral("null");
    return parseNumber();
  }
  parseValue();
  whitespace();
  if (index !== text.length) fail();
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

function validateBootstrapClaim(value, repositorySha) {
  exactObject(value, BOOTSTRAP_CLAIM_KEYS);
  if (
    !UUID_V4_PATTERN.test(value.claimNonce) ||
    value.paymentMoved !== false ||
    value.repositorySha !== repositorySha ||
    typeof value.requestorPublicKey !== "string" ||
    !BASE64URL_32_PATTERN.test(value.requestorPublicKey)
  ) {
    fail();
  }
  const keyBytes = Buffer.from(value.requestorPublicKey, "base64url");
  if (keyBytes.length !== 32 || keyBytes.toString("base64url") !== value.requestorPublicKey) fail();
  return Object.freeze({
    claimNonce: value.claimNonce,
    paymentMoved: false,
    repositorySha: value.repositorySha,
    requestorPublicKey: value.requestorPublicKey,
  });
}

function requestorBootstrapClaimFingerprint(claim) {
  return createHash("sha256").update(canonicalBytes(claim)).digest("hex");
}

function exactBase64url(value, decodedLength = null, maxDecodedLength = null) {
  if (typeof value !== "string" || value.length === 0 || value.includes("=") || !BASE64URL_PATTERN.test(value)) fail();
  const decoded = Buffer.from(value, "base64url");
  if (
    decoded.length === 0 ||
    (decodedLength !== null && decoded.length !== decodedLength) ||
    (maxDecodedLength !== null && decoded.length > maxDecodedLength) ||
    decoded.toString("base64url") !== value
  ) {
    fail();
  }
  return decoded;
}

function exactBase64(value, decodedLength) {
  if (typeof value !== "string" || !BASE64_PATTERN.test(value)) fail();
  const decoded = Buffer.from(value, "base64");
  if (decoded.length !== decodedLength || decoded.toString("base64") !== value) fail();
}

function validateBootstrapHeaders(req, expectedHost) {
  if (req.rawHeaders.length / 2 > MAX_HEADERS) return 431;
  const seenHeaders = new Map();
  for (let index = 0; index < req.rawHeaders.length; index += 2) {
    const name = req.rawHeaders[index];
    if (typeof name !== "string") return 400;
    const key = name.toLowerCase();
    seenHeaders.set(key, (seenHeaders.get(key) ?? 0) + 1);
  }
  for (const key of SINGLETON_HEADERS) {
    if ((seenHeaders.get(key) ?? 0) > 1 || (req.headersDistinct?.[key]?.length ?? 0) > 1) return 400;
  }
  if (req.url !== "/bootstrap") return 404;
  if (req.method !== "POST") return 405;
  if (req.headers.host !== expectedHost) return 400;
  if (Object.hasOwn(req.headers, "authorization")) return 400;
  if (Object.hasOwn(req.headers, "origin")) return 400;
  if (Object.hasOwn(req.headers, "mcp-protocol-version") || Object.hasOwn(req.headers, "mcp-session-id")) return 400;
  if (req.headers.accept !== BOOTSTRAP_ACCEPT) return 400;
  if (req.headers["content-type"] !== JSON_CONTENT_TYPE) return 415;
  const contentLength = req.headers["content-length"];
  if (contentLength !== undefined && (!/^(?:0|[1-9][0-9]*)$/.test(contentLength) || Number(contentLength) > MAX_BODY_BYTES)) return 413;
  return 0;
}

function validateBootstrapBrokerResponse(value, { claim, repositorySha }) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) fail();
  const keys = Reflect.ownKeys(value);
  if (value.status === "PENDING_APPROVAL") {
    exactObject(value, ["claimFingerprint", "paymentMoved", "repositorySha", "schema", "status"]);
  } else if (value.status === "SEALED") {
    exactObject(value, ["claimFingerprint", "context", "envelope", "paymentMoved", "repositorySha", "schema", "signature", "status"]);
    exactObject(value.context, ["claimNonce", "paymentMoved", "releaseId", "repositorySha", "sessionId"]);
    exactObject(value.envelope, ["algorithm", "ciphertextBase64url", "ephemeralPublicKey", "ivBase64url", "paymentMoved", "schema", "tagBase64url"]);
    exactObject(value.signature, ["algorithm", "keyId", "value"]);
    if (
      value.context.claimNonce !== claim.claimNonce ||
      value.context.paymentMoved !== false ||
      value.context.repositorySha !== repositorySha ||
      typeof value.context.releaseId !== "string" ||
      !UUID_V4_PATTERN.test(value.context.sessionId) ||
      value.envelope.algorithm !== BOOTSTRAP_ENVELOPE_ALGORITHM ||
      value.envelope.paymentMoved !== false ||
      value.envelope.schema !== BOOTSTRAP_ENVELOPE_SCHEMA ||
      value.signature.algorithm !== "ed25519" ||
      typeof value.signature.keyId !== "string" ||
      !KEY_ID_PATTERN.test(value.signature.keyId) ||
      typeof value.signature.value !== "string"
    ) {
      fail();
    }
    exactBase64url(value.envelope.ciphertextBase64url, null, MAX_BOOTSTRAP_CIPHERTEXT_BYTES);
    exactBase64url(value.envelope.ephemeralPublicKey, 32);
    exactBase64url(value.envelope.ivBase64url, 12);
    exactBase64url(value.envelope.tagBase64url, 16);
    exactBase64(value.signature.value, 64);
  } else {
    fail();
  }
  if (
    keys.length === 0 ||
    value.claimFingerprint !== requestorBootstrapClaimFingerprint(claim) ||
    value.paymentMoved !== false ||
    value.repositorySha !== repositorySha ||
    value.schema !== BOOTSTRAP_BROKER_RESPONSE_SCHEMA
  ) {
    fail();
  }
  return Object.freeze(value);
}

function validateBrokerUrl(value) {
  if (typeof value !== "string") fail();
  let url;
  try {
    url = new URL(value);
  } catch {
    fail();
  }
  if (
    url.protocol !== "http:" ||
    url.pathname !== "/" ||
    url.search !== "" ||
    url.hash !== "" ||
    url.username !== "" ||
    url.password !== "" ||
    url.port === "" ||
    !["127.0.0.1", "[::1]"].includes(url.hostname)
  ) {
    fail();
  }
  return url;
}

function brokerHostname(url) {
  return url.hostname === "[::1]" ? "::1" : url.hostname;
}

function validateBrokerCapability(value) {
  if (typeof value !== "string" || !CAPABILITY_PATTERN.test(value)) fail();
  return value;
}

function validateClaimRequestorBootstrap(value) {
  if (value === undefined) return null;
  if (typeof value !== "function") fail();
  return value;
}

export function createRequestorBootstrapBrokerClient({ brokerCapability, brokerUrl, requestHttp } = {}) {
  const url = validateBrokerUrl(brokerUrl);
  const capability = validateBrokerCapability(brokerCapability);
  const request = requestHttp ?? (({ body, headers }) => new Promise((resolvePromise, rejectPromise) => {
    const payload = Buffer.from(JSON.stringify(body), "utf8");
    const req = http.request({
      agent: false,
      headers: {
        ...headers,
        "Content-Length": String(payload.length),
      },
      host: brokerHostname(url),
      method: "POST",
      path: "/claim",
      port: Number(url.port),
      timeout: REQUEST_TIMEOUT_MS,
    }, (res) => {
      const chunks = [];
      let size = 0;
      res.on("data", (chunk) => {
        size += chunk.length;
        if (size > MAX_BODY_BYTES) res.destroy(new Error("response too large"));
        else chunks.push(chunk);
      });
      res.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        resolvePromise({
          body: text === "" ? null : parseJson(text),
          headers: res.headers,
          statusCode: res.statusCode,
          text,
        });
      });
    });
    req.once("timeout", () => req.destroy(new Error("request timeout")));
    req.once("error", rejectPromise);
    req.end(payload);
  }));
  if (typeof request !== "function") fail();
  return Object.freeze({
    async claimRequestorBootstrap(claim) {
      const result = await request({
        body: claim,
        headers: {
          Accept: BOOTSTRAP_ACCEPT,
          Authorization: `Bearer ${capability}`,
          "Content-Type": JSON_CONTENT_TYPE,
          Host: hostAuthority(brokerHostname(url), Number(url.port)),
        },
        method: "POST",
        url,
      });
      if (!((result.statusCode === 202 && result.body?.status === "PENDING_APPROVAL") || (result.statusCode === 200 && result.body?.status === "SEALED"))) fail();
      return result.body;
    },
  });
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
  allowTestAddresses = false,
  capabilityDigest: expectedCapabilityDigest,
  claimRequestorBootstrap,
  createHttpsServer = https.createServer,
  host,
  intakeStore,
  nowMs = () => Date.now(),
  port,
  publicUrl,
  randomBytes = nodeRandomBytes,
  repositorySha,
  tlsCertificatePem,
  tlsPrivateKeyPem,
} = {}) {
  if (typeof allowTestAddresses !== "boolean") fail();
  const bindHost = validateHost(host);
  const bindPort = validatePort(port);
  const digest = validateDigest(expectedCapabilityDigest);
  const sha = validateRepositorySha(repositorySha);
  const store = validateIntakeStore(intakeStore);
  const certificate = validatePem(tlsCertificatePem);
  const privateKey = validatePem(tlsPrivateKeyPem);
  const publicEndpoint = validatePublicEndpoint(
    publicUrl,
    certificate,
    allowTestAddresses,
  );
  const bootstrapBroker = validateClaimRequestorBootstrap(claimRequestorBootstrap);
  if (typeof createHttpsServer !== "function" || typeof nowMs !== "function" || typeof randomBytes !== "function") fail();

  const sessions = new Map();
  const failedAuth = [];
  let server;

  function currentPort() {
    const address = server?.address();
    return typeof address === "object" && address !== null ? address.port : bindPort;
  }

  function advertisedAuthority() {
    return publicEndpoint?.authority ?? hostAuthority(bindHost, currentPort());
  }

  function advertisedUrl() {
    return publicEndpoint?.url ?? `https://${hostAuthority(bindHost, currentPort())}/mcp`;
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
      if (!session || session.state !== "initialized") fail();
      assertSessionRequest(session);
      session.state = "ready";
      emptyResponse(res, 202);
      return;
    }

    const rpc = validateRpcRequest(value);
    if (rpc.method === "initialize") {
      if (req.headers["mcp-session-id"] !== undefined) fail();
      const params = exactObject(rpc.params, ["protocolVersion"]);
      if (params.protocolVersion !== PAYER_MCP_PROTOCOL_VERSION) fail();
      const id = sessionId(randomBytes(16));
      const session = { ids: new Set([String(rpc.id)]), requests: 1, retired: false, state: "initialized" };
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
    if (!session || hasDuplicateId(session, rpc.id)) fail();
    assertSessionRequest(session);
    if (rpc.method === "tools/list") {
      if (session.state !== "ready") fail();
      exactObject(rpc.params, []);
      session.state = "listed";
      response(res, 200, { id: rpc.id, jsonrpc: "2.0", result: { tools: [PAYMENT_INTAKE_TOOL_DESCRIPTOR] } });
      return;
    }
    if (rpc.method === "tools/call") {
      if (session.state !== "listed") fail();
      const params = exactObject(rpc.params, ["arguments", "name"]);
      if (params.name !== REQUEST_PAYMENT_TOOL_NAME) fail();
      const result = buildPaymentIntakeToolResult({ repositorySha: sha, toolInput: params.arguments });
      const record = await store.writeIntake({ request: params.arguments, response: result });
      session.state = "called";
      response(res, 200, { id: rpc.id, jsonrpc: "2.0", result: record.response });
      return;
    }
    fail();
  }

  async function handleBootstrap(req, res) {
    if (bootstrapBroker === null) {
      bootstrapFailure(res, 404);
      return;
    }
    const headerStatus = validateBootstrapHeaders(req, advertisedAuthority());
    if (headerStatus) {
      bootstrapFailure(res, headerStatus);
      return;
    }
    const claim = validateBootstrapClaim(parseJson(await readBody(req)), sha);
    const brokerResponse = validateBootstrapBrokerResponse(await bootstrapBroker(claim), { claim, repositorySha: sha });
    response(res, brokerResponse.status === "PENDING_APPROVAL" ? 202 : 200, brokerResponse, { "Cache-Control": "no-store" });
  }

  async function handleRequest(req, res) {
    try {
      req.setTimeout(REQUEST_TIMEOUT_MS, () => req.destroy());
      if (req.url === "/bootstrap") {
        await handleBootstrap(req, res);
        return;
      }
      const headerStatus = validateCommonHeaders(req, advertisedAuthority());
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
        if (!session || session.state !== "called") fail();
        assertSessionRequest(session);
        session.retired = true;
        sessions.delete(id);
        response(res, 200, { paymentMoved: false, status: "deleted" });
        return;
      }
      await handlePost(req, res);
    } catch {
      if (!res.headersSent && req.url === "/bootstrap") bootstrapFailure(res);
      else if (!res.headersSent) protocolFailure(res);
      else res.destroy();
    }
  }

  return Object.freeze({
    async start() {
      if (server) fail();
      const candidate = createHttpsServer({ cert: certificate, key: privateKey }, handleRequest);
      server = candidate;
      candidate.headersTimeout = HEADER_TIMEOUT_MS;
      candidate.requestTimeout = REQUEST_TIMEOUT_MS;
      candidate.on?.("clientError", (_error, socket) => closeParserFailureSocket(socket));
      await new Promise((resolve, reject) => {
        const onError = (error) => {
          if (server === candidate) server = undefined;
          candidate.close?.(() => {});
          reject(error);
        };
        candidate.once("error", onError);
        candidate.listen(bindPort, bindHost, () => {
          candidate.off("error", onError);
          resolve();
        });
      });
      return Object.freeze({ host: bindHost, port: currentPort(), url: advertisedUrl() });
    },
    async stop() {
      if (!server) return;
      const closing = server;
      server = undefined;
      sessions.clear();
      failedAuth.length = 0;
      await new Promise((resolve, reject) => closing.close((error) => error ? reject(error) : resolve()));
    },
  });
}
