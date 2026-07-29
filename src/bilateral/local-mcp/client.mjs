import { createHash, randomBytes, X509Certificate } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { link, lstat, mkdir, open, readdir, unlink } from "node:fs/promises";
import https from "node:https";
import net from "node:net";
import { join, resolve } from "node:path";
import { isDeepStrictEqual } from "node:util";

import { canonicalBytes } from "../canonical.mjs";
import {
  PAYMENT_INTAKE_TOOL_DESCRIPTOR,
  validatePaymentIntakeToolResult,
} from "./payment-intake.mjs";

export const REQUESTOR_MCP_INTAKE_FILE_NAME = "payer-mcp-handshake-required.json";
export const REQUESTOR_MCP_PROTOCOL_VERSION = "2025-11-25";

const CAPABILITY_PATTERN = /^[0-9a-f]{64}$/;
const FINGERPRINT_PATTERN = /^[0-9a-f]{64}$/;
const REPOSITORY_SHA_PATTERN = /^[0-9a-f]{40}$/;
const UUID_V4_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MAX_RESPONSE_BYTES = 65_536;
const REQUEST_TIMEOUT_MS = 10_000;
const ACCEPT = "application/json, text/event-stream";
const JSON_CONTENT_TYPE = "application/json";
const expectedUid = process.getuid?.();
const TEMPORARY_INTAKE_FILE = /^\.requestor-mcp-intake-[0-9a-f]{32}\.tmp$/;

function fail() {
  throw new Error("Requestor MCP client failed safely.");
}

function sanitize(error) {
  if (error?.message === "Requestor MCP client failed safely.") throw error;
  fail();
}

function deepFreeze(value) {
  if (value && typeof value === "object") {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function hasPrivateDirectoryMetadata(metadata) {
  return metadata.isDirectory() && !metadata.isSymbolicLink() && metadata.uid === expectedUid && (metadata.mode & 0o777) === 0o700;
}

function hasPrivateFileMetadata(metadata) {
  return metadata.isFile() && !metadata.isSymbolicLink() && metadata.nlink === 1 && metadata.uid === expectedUid && (metadata.mode & 0o777) === 0o600;
}

async function createPrivateStateRoot(rootPath) {
  if (typeof rootPath !== "string" || expectedUid === undefined) fail();
  try {
    const existing = await lstat(rootPath);
    if (!hasPrivateDirectoryMetadata(existing)) fail();
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    await mkdir(rootPath, { mode: 0o700 });
  }
  const before = await lstat(rootPath);
  if (!hasPrivateDirectoryMetadata(before)) fail();
  const handle = await open(rootPath, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | (fsConstants.O_NOFOLLOW ?? 0));
  try {
    const opened = await handle.stat();
    if (!sameIdentity(before, opened) || !hasPrivateDirectoryMetadata(opened)) fail();
    const assertPinned = async () => {
      const current = await lstat(rootPath);
      const live = await handle.stat();
      if (!sameIdentity(before, current) || !sameIdentity(before, live) || !hasPrivateDirectoryMetadata(current) || !hasPrivateDirectoryMetadata(live)) fail();
    };
    await assertPinned();
    for (const entry of await readdir(rootPath)) {
      if (TEMPORARY_INTAKE_FILE.test(entry)) fail();
    }
    return Object.freeze({ assertPinned, handle, rootPath });
  } catch (error) {
    await handle.close();
    throw error;
  }
}

function exactObject(value, keys) {
  try {
    if (value === null || typeof value !== "object" || Array.isArray(value)) fail();
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) fail();
    const ownKeys = Reflect.ownKeys(value);
    if (ownKeys.length !== keys.length || keys.some((key, index) => ownKeys[index] !== key)) fail();
    const result = Object.create(null);
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value")) fail();
      result[key] = descriptor.value;
    }
    return result;
  } catch {
    fail();
  }
}

function validateUrl(value) {
  if (typeof value !== "string") fail();
  let url;
  try {
    url = new URL(value);
  } catch {
    fail();
  }
  if (
    url.protocol !== "https:" ||
    url.pathname !== "/mcp" ||
    url.search !== "" ||
    url.hash !== "" ||
    url.username !== "" ||
    url.password !== "" ||
    url.port === "" ||
    net.isIP(url.hostname) === 0
  ) {
    fail();
  }
  const port = Number(url.port);
  if (!Number.isInteger(port) || port < 1 || port > 65_535 || String(port) !== url.port) fail();
  if (net.isIP(url.hostname) === 4) {
    const octets = url.hostname.split(".");
    if (octets.length !== 4 || octets.some((octet) => String(Number(octet)) !== octet || Number(octet) > 255)) fail();
  }
  return url;
}

function hostHeader(url) {
  return net.isIP(url.hostname) === 6 ? `[${url.hostname}]:${url.port}` : `${url.hostname}:${url.port}`;
}

function validateInput({
  capability,
  intakeRequestId,
  mcpUrl,
  repositorySha,
  stateRoot,
  tlsCertificatePem,
  tlsFingerprint,
}) {
  if (typeof capability !== "string" || !CAPABILITY_PATTERN.test(capability)) fail();
  if (typeof intakeRequestId !== "string" || !UUID_V4_PATTERN.test(intakeRequestId)) fail();
  if (typeof repositorySha !== "string" || !REPOSITORY_SHA_PATTERN.test(repositorySha)) fail();
  if (typeof stateRoot !== "string" || resolve(stateRoot) !== stateRoot || stateRoot === "/") fail();
  if (typeof tlsCertificatePem !== "string" || !tlsCertificatePem.includes("-----BEGIN CERTIFICATE-----") || !tlsCertificatePem.includes("-----END CERTIFICATE-----")) fail();
  if (typeof tlsFingerprint !== "string" || !FINGERPRINT_PATTERN.test(tlsFingerprint)) fail();
  const certificateFingerprint = createHash("sha256").update(new X509Certificate(tlsCertificatePem).raw).digest("hex");
  if (certificateFingerprint !== tlsFingerprint) fail();
  return Object.freeze({
    capability,
    intakeRequestId,
    mcpUrl: validateUrl(mcpUrl),
    repositorySha,
    stateRoot,
    tlsCertificatePem,
    tlsFingerprint,
  });
}

function paymentInput(intakeRequestId) {
  return Object.freeze({
    amount: Object.freeze({ currency: "USD", value: "100" }),
    intakeRequestId,
    invoiceReference: "invoice-001",
    paymentMoved: false,
    purpose: "Handshake demo",
    schema: "clockchain.payer-mcp-payment-intake/v1",
  });
}

function rejectDuplicateJsonKeys(text) {
  if (typeof text !== "string" || text.length === 0 || text.length > MAX_RESPONSE_BYTES) fail();
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
        } else fail();
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
    else if (/[1-9]/.test(text[index] ?? "")) while (/[0-9]/.test(text[index] ?? "")) index += 1;
    else fail();
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
    for (;;) {
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
    for (;;) {
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
    if (char === "\"") return parseString();
    if (char === "t") return parseLiteral("true");
    if (char === "f") return parseLiteral("false");
    if (char === "n") return parseLiteral("null");
    return parseNumber();
  }
  parseValue();
  whitespace();
  if (index !== text.length) fail();
}

function parseJson(text) {
  rejectDuplicateJsonKeys(text);
  try {
    return JSON.parse(text);
  } catch {
    fail();
  }
}

async function defaultRequestJsonRpc({ body, headers, method, tlsCertificatePem, tlsFingerprint, url }) {
  return new Promise((resolvePromise, rejectPromise) => {
    const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body), "utf8");
    const request = https.request({
      agent: false,
      ca: tlsCertificatePem,
      headers: {
        ...headers,
        ...(payload === undefined ? {} : { "Content-Length": String(payload.length) }),
      },
      host: url.hostname,
      method,
      path: url.pathname,
      port: Number(url.port),
      rejectUnauthorized: true,
      timeout: REQUEST_TIMEOUT_MS,
    }, (response) => {
      const peer = response.socket.getPeerCertificate(true);
      const raw = Buffer.isBuffer(peer?.raw) ? peer.raw : null;
      if (!raw || createHash("sha256").update(raw).digest("hex") !== tlsFingerprint) {
        response.destroy();
        rejectPromise(new Error("fingerprint mismatch"));
        return;
      }
      const chunks = [];
      let size = 0;
      response.on("data", (chunk) => {
        size += chunk.length;
        if (size > MAX_RESPONSE_BYTES) response.destroy(new Error("response too large"));
        else chunks.push(chunk);
      });
      response.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        resolvePromise({
          body: text === "" ? null : parseJson(text),
          headers: response.headers,
          statusCode: response.statusCode,
          text,
        });
      });
    });
    request.once("timeout", () => request.destroy(new Error("request timeout")));
    request.once("error", rejectPromise);
    request.end(payload);
  });
}

function commonHeaders({ capability, sessionId, url }) {
  return {
    Accept: ACCEPT,
    Authorization: `Bearer ${capability}`,
    "Content-Type": JSON_CONTENT_TYPE,
    Host: hostHeader(url),
    "MCP-Protocol-Version": REQUESTOR_MCP_PROTOCOL_VERSION,
    ...(sessionId === undefined ? {} : { "MCP-Session-Id": sessionId }),
  };
}

function validateJsonResponse(response, statusCode) {
  if (response?.statusCode !== statusCode) fail();
  if (response.headers?.["content-type"] !== JSON_CONTENT_TYPE) fail();
  if (typeof response.text === "string" && response.text.includes("text/event-stream")) fail();
  if (typeof response.text === "string" && response.text !== "") {
    const parsed = parseJson(response.text);
    if (response.body !== null && response.body !== undefined && !isDeepStrictEqual(parsed, response.body)) fail();
  }
  return response.body;
}

function validateRpcResponse(response, id) {
  const rpc = exactObject(validateJsonResponse(response, 200), ["id", "jsonrpc", "result"]);
  if (rpc.id !== id || rpc.jsonrpc !== "2.0") fail();
  return rpc.result;
}

function validateInitialize(response) {
  const result = exactObject(validateRpcResponse(response, 1), ["capabilities", "protocolVersion", "serverInfo"]);
  const capabilities = exactObject(result.capabilities, ["tools"]);
  exactObject(capabilities.tools, []);
  const serverInfo = exactObject(result.serverInfo, ["name", "version"]);
  if (
    result.protocolVersion !== REQUESTOR_MCP_PROTOCOL_VERSION ||
    serverInfo.name !== "clockchain-payer-local-mcp" ||
    serverInfo.version !== "1.0.0" ||
    response.headers?.["mcp-protocol-version"] !== REQUESTOR_MCP_PROTOCOL_VERSION ||
    typeof response.headers?.["mcp-session-id"] !== "string" ||
    !/^[A-Za-z0-9_-]{22}$/.test(response.headers["mcp-session-id"])
  ) {
    fail();
  }
  return response.headers["mcp-session-id"];
}

function validateTools(response) {
  const result = exactObject(validateRpcResponse(response, 2), ["tools"]);
  if (!Array.isArray(result.tools) || result.tools.length !== 1 || !isDeepStrictEqual(result.tools[0], PAYMENT_INTAKE_TOOL_DESCRIPTOR)) fail();
}

async function persistRequestorIntake({ result, stateRoot }) {
  const path = join(stateRoot, REQUESTOR_MCP_INTAKE_FILE_NAME);
  const temporary = join(stateRoot, `.requestor-mcp-intake-${randomBytes(16).toString("hex")}.tmp`);
  let handle;
  if (resolve(path) !== path || !path.startsWith(`${stateRoot}/`) || resolve(temporary) !== temporary || !temporary.startsWith(`${stateRoot}/`)) fail();
  const root = await createPrivateStateRoot(stateRoot);
  const bytes = Buffer.from(canonicalBytes(result).toString("utf8"), "utf8");
  try {
    await root.assertPinned();
    handle = await open(temporary, fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY | (fsConstants.O_NOFOLLOW ?? 0), 0o600);
    const openedTemporary = await handle.stat();
    if (!hasPrivateFileMetadata(openedTemporary)) fail();
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await root.assertPinned();
    await link(temporary, path);
    await unlink(temporary);
    await root.assertPinned();
    await root.handle.sync();
    const finalMetadata = await lstat(path);
    if (!hasPrivateFileMetadata(finalMetadata) || finalMetadata.size !== bytes.length) fail();
    const readbackHandle = await open(path, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
    try {
      const openedFinal = await readbackHandle.stat();
      if (!sameIdentity(finalMetadata, openedFinal) || !hasPrivateFileMetadata(openedFinal)) fail();
      const buffer = Buffer.alloc(bytes.length + 1);
      const { bytesRead } = await readbackHandle.read(buffer, 0, buffer.length, 0);
      if (bytesRead !== bytes.length || !buffer.subarray(0, bytesRead).equals(bytes)) fail();
      const parsed = parseJson(buffer.subarray(0, bytesRead).toString("utf8"));
      if (!isDeepStrictEqual(parsed, result) || canonicalBytes(parsed).toString("utf8") !== bytes.toString("utf8")) fail();
    } finally {
      await readbackHandle.close();
    }
  } finally {
    if (handle) await handle.close();
    await unlink(temporary).catch(() => {});
    await root.handle.close();
  }
}

export async function requestPaymentThroughPayerMcp(input) {
  let sessionId;
  let validated;
  let requestJsonRpc;
  let toolInput;
  try {
    validated = validateInput(input);
    requestJsonRpc = input.requestJsonRpc ?? defaultRequestJsonRpc;
    if (typeof requestJsonRpc !== "function") fail();
    toolInput = paymentInput(validated.intakeRequestId);
    const request = (payload) => requestJsonRpc({
      ...payload,
      tlsCertificatePem: validated.tlsCertificatePem,
      tlsFingerprint: validated.tlsFingerprint,
      url: validated.mcpUrl,
    });

    sessionId = validateInitialize(await request({
      body: { id: 1, jsonrpc: "2.0", method: "initialize", params: { protocolVersion: REQUESTOR_MCP_PROTOCOL_VERSION } },
      headers: commonHeaders({ capability: validated.capability, url: validated.mcpUrl }),
      method: "POST",
    }));

    validateJsonResponse(await request({
      body: { jsonrpc: "2.0", method: "notifications/initialized" },
      headers: commonHeaders({ capability: validated.capability, sessionId, url: validated.mcpUrl }),
      method: "POST",
    }), 202);

    validateTools(await request({
      body: { id: 2, jsonrpc: "2.0", method: "tools/list", params: {} },
      headers: commonHeaders({ capability: validated.capability, sessionId, url: validated.mcpUrl }),
      method: "POST",
    }));

    const callResult = validateRpcResponse(await request({
      body: { id: 3, jsonrpc: "2.0", method: "tools/call", params: { arguments: toolInput, name: "request_payment" } },
      headers: commonHeaders({ capability: validated.capability, sessionId, url: validated.mcpUrl }),
      method: "POST",
    }), 3);
    const structuredContent = validatePaymentIntakeToolResult({
      repositorySha: validated.repositorySha,
      result: callResult,
      toolInput,
    });
    await request({
      body: undefined,
      headers: commonHeaders({ capability: validated.capability, sessionId, url: validated.mcpUrl }),
      method: "DELETE",
    }).then((response) => {
      const body = exactObject(validateJsonResponse(response, 200), ["paymentMoved", "status"]);
      if (body.paymentMoved !== false || body.status !== "deleted") fail();
    });
    sessionId = undefined;
    await persistRequestorIntake({ result: structuredContent, stateRoot: validated.stateRoot });
    return deepFreeze(structuredContent);
  } catch (error) {
    if (sessionId !== undefined && validated && requestJsonRpc) {
      try {
        await requestJsonRpc({
          body: undefined,
          headers: commonHeaders({ capability: validated.capability, sessionId, url: validated.mcpUrl }),
          method: "DELETE",
          tlsCertificatePem: validated.tlsCertificatePem,
          tlsFingerprint: validated.tlsFingerprint,
          url: validated.mcpUrl,
        });
      } catch {
        // Cleanup is best-effort on the failure path; the original safe failure wins.
      }
    }
    sanitize(error);
  }
  fail();
}
