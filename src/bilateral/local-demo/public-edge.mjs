import { createHash } from "node:crypto";
import https from "node:https";
import { isIP } from "node:net";
import { isAbsolute, resolve } from "node:path";

const EDGE_KEYS = Object.freeze([
  "coordinationPublicUrl",
  "host",
  "hostKeyFile",
  "identityFile",
  "payerMcpRemotePort",
  "port",
  "relayRemotePort",
  "user",
]);
const LOCAL_PORT_KEYS = Object.freeze(["payerMcp", "relay"]);
const SHA64 = /^[0-9a-f]{64}$/;
const HOST = /^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/;
const SESSION_READINESS =
  /^\/v1\/sessions\/([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\/enrollment-readiness\?waitMs=0$/;
const MAX_BODY_BYTES = 8_192;

export class HybridPublicEdgeError extends Error {
  constructor(code = "HYBRID_PUBLIC_EDGE_INVALID") {
    super("Hybrid public edge failed safely.");
    this.name = "HybridPublicEdgeError";
    this.code = code;
    this.category = "network";
  }
}

function fail(code = "HYBRID_PUBLIC_EDGE_INVALID") {
  throw new HybridPublicEdgeError(code);
}

function plain(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function exact(value, keys) {
  if (!plain(value)) fail();
  const own = Reflect.ownKeys(value);
  if (own.length !== keys.length || keys.some((key) => !own.includes(key))) {
    fail();
  }
  return value;
}

function port(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 65_535) fail();
  return value;
}

function safePath(value) {
  if (
    typeof value !== "string" ||
    value.includes("\0") ||
    !isAbsolute(value) ||
    resolve(value) !== value ||
    value === "/" ||
    value.startsWith("--")
  ) {
    fail();
  }
  return value;
}

function hostname(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.includes("\0") ||
    (!HOST.test(value) && isIP(value) === 0)
  ) {
    fail();
  }
  return value;
}

function publicUrl(value) {
  if (typeof value !== "string") fail();
  let url;
  try {
    url = new URL(value);
  } catch {
    fail();
  }
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== ""
  ) {
    fail();
  }
  return url;
}

export function buildPublicEdgeArguments(publicEdge, localPorts) {
  const edge = exact(publicEdge, EDGE_KEYS);
  const locals = exact(localPorts, LOCAL_PORT_KEYS);
  hostname(edge.host);
  safePath(edge.hostKeyFile);
  safePath(edge.identityFile);
  port(edge.port);
  port(edge.relayRemotePort);
  port(edge.payerMcpRemotePort);
  port(locals.relay);
  port(locals.payerMcp);
  if (edge.user !== "clockchain-tunnel") fail();

  const relay = publicUrl(edge.coordinationPublicUrl);
  if (
    relay.hostname !== edge.host ||
    relay.pathname !== "/" ||
    Number(relay.port) !== edge.relayRemotePort ||
    edge.payerMcpRemotePort !== 9443
  ) {
    fail();
  }

  return Object.freeze([
    "-N", "-T",
    "-o", "BatchMode=yes",
    "-o", "ExitOnForwardFailure=yes",
    "-o", "ForwardAgent=no",
    "-o", "ControlMaster=no",
    "-o", "ControlPath=none",
    "-o", `UserKnownHostsFile=${edge.hostKeyFile}`,
    "-o", "StrictHostKeyChecking=yes",
    "-o", "ServerAliveInterval=15",
    "-o", "ServerAliveCountMax=2",
    "-i", edge.identityFile,
    "-p", String(edge.port),
    "-R", `0.0.0.0:${edge.relayRemotePort}:127.0.0.1:${locals.relay}`,
    "-R", `0.0.0.0:${edge.payerMcpRemotePort}:127.0.0.1:${locals.payerMcp}`,
    `${edge.user}@${edge.host}`,
  ]);
}

function validateProbeInput(value) {
  if (!plain(value)) fail();
  const allowed = new Set([
    "expectedFingerprint",
    "host",
    "path",
    "port",
    "timeoutMs",
  ]);
  const keys = Reflect.ownKeys(value);
  if (
    ![4, 5].includes(keys.length) ||
    keys.some((key) => !allowed.has(key)) ||
    !keys.includes("expectedFingerprint") ||
    !keys.includes("host") ||
    !keys.includes("path") ||
    !keys.includes("port")
  ) {
    fail();
  }
  hostname(value.host);
  port(value.port);
  if (
    typeof value.expectedFingerprint !== "string" ||
    !SHA64.test(value.expectedFingerprint) ||
    !(
      value.path === "/" ||
      value.path === "/mcp" ||
      SESSION_READINESS.test(value.path)
    )
  ) {
    fail();
  }
  const timeoutMs = value.timeoutMs ?? 2_000;
  if (
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs < 25 ||
    timeoutMs > 10_000
  ) {
    fail();
  }
  return Object.freeze({
    expectedFingerprint: value.expectedFingerprint,
    host: value.host,
    path: value.path,
    port: value.port,
    timeoutMs,
  });
}

function exactJson(body) {
  if (
    typeof body !== "string" ||
    body.length === 0 ||
    Buffer.byteLength(body, "utf8") > MAX_BODY_BYTES
  ) {
    fail("HYBRID_PUBLIC_EDGE_PROTOCOL_MISMATCH");
  }
  const text = body.endsWith("\n") ? body.slice(0, -1) : body;
  if (text.includes("\n") || text.includes("\r")) {
    fail("HYBRID_PUBLIC_EDGE_PROTOCOL_MISMATCH");
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    fail("HYBRID_PUBLIC_EDGE_PROTOCOL_MISMATCH");
  }
  if (!plain(value) || JSON.stringify(value) !== text) {
    fail("HYBRID_PUBLIC_EDGE_PROTOCOL_MISMATCH");
  }
  return value;
}

function validateProbeResponse(input, response) {
  const value = exactJson(response.body);
  if (input.path === "/") {
    if (
      response.statusCode !== 400 ||
      Reflect.ownKeys(value).length !== 2 ||
      value.code !== "COORDINATION_RELAY_REQUEST_INVALID" ||
      value.paymentMoved !== false
    ) {
      fail("HYBRID_PUBLIC_EDGE_PROTOCOL_MISMATCH");
    }
    return;
  }
  if (input.path === "/mcp") {
    if (
      response.statusCode !== 405 ||
      response.headers.allow !== "POST, DELETE" ||
      Reflect.ownKeys(value).length !== 2 ||
      value.error !== "PAYER_MCP_PROTOCOL_FAILED" ||
      value.paymentMoved !== false
    ) {
      fail("HYBRID_PUBLIC_EDGE_PROTOCOL_MISMATCH");
    }
    return;
  }
  const match = input.path.match(SESSION_READINESS);
  if (
    response.statusCode !== 200 ||
    match === null ||
    Reflect.ownKeys(value).length !== 6 ||
    value.schema !== "clockchain.bilateral-enrollment-readiness/v1" ||
    value.paymentMoved !== false ||
    typeof value.ready !== "boolean" ||
    typeof value.releaseId !== "string" ||
    !/^release-[0-9a-f]{16}$/.test(value.releaseId) ||
    typeof value.repositorySha !== "string" ||
    !/^[0-9a-f]{40}$/.test(value.repositorySha) ||
    value.sessionId !== match[1]
  ) {
    fail("HYBRID_PUBLIC_EDGE_PROTOCOL_MISMATCH");
  }
}

function requestProbe(input, httpsModule = https) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (operation, value) => {
      if (settled) return;
      settled = true;
      operation(value);
    };
    const request = httpsModule.request({
      agent: false,
      headers: Object.freeze({ Accept: "application/json" }),
      host: input.host,
      method: "GET",
      path: input.path,
      port: input.port,
      rejectUnauthorized: false,
      servername: isIP(input.host) === 0 ? input.host : "",
    }, (response) => {
      const certificate = response.socket.getPeerCertificate(true);
      if (!Buffer.isBuffer(certificate?.raw)) {
        response.destroy();
        finish(reject, new HybridPublicEdgeError("HYBRID_PUBLIC_EDGE_IDENTITY_MISMATCH"));
        return;
      }
      const fingerprint = createHash("sha256").update(certificate.raw).digest("hex");
      if (fingerprint !== input.expectedFingerprint) {
        response.destroy();
        finish(reject, new HybridPublicEdgeError("HYBRID_PUBLIC_EDGE_IDENTITY_MISMATCH"));
        return;
      }
      const chunks = [];
      let size = 0;
      response.on("data", (chunk) => {
        size += chunk.length;
        if (size > MAX_BODY_BYTES) {
          response.destroy();
          finish(reject, new HybridPublicEdgeError("HYBRID_PUBLIC_EDGE_PROTOCOL_MISMATCH"));
          return;
        }
        chunks.push(chunk);
      });
      response.once("end", () => finish(resolve, {
        body: Buffer.concat(chunks).toString("utf8"),
        headers: response.headers,
        statusCode: response.statusCode,
      }));
      response.once("error", (error) => finish(reject, error));
    });
    request.setTimeout(input.timeoutMs, () => {
      request.destroy(new HybridPublicEdgeError("HYBRID_PUBLIC_EDGE_UNAVAILABLE"));
    });
    request.once("error", (error) => finish(reject, error));
    request.end();
  });
}

export async function probePinnedTlsEndpoint(input, dependencies = {}) {
  try {
    if (
      !plain(dependencies) ||
      Reflect.ownKeys(dependencies).some((key) => key !== "https") ||
      (dependencies.https !== undefined &&
        typeof dependencies.https?.request !== "function")
    ) {
      fail();
    }
    const checked = validateProbeInput(input);
    const response = await requestProbe(checked, dependencies.https ?? https);
    validateProbeResponse(checked, response);
    return Object.freeze({ paymentMoved: false, ready: true });
  } catch (error) {
    if (error instanceof HybridPublicEdgeError) throw error;
    fail("HYBRID_PUBLIC_EDGE_UNAVAILABLE");
  }
}

export async function waitForPublicEdge(input, dependencies = {}) {
  try {
    const checked = exact(input, ["coordination", "deadlineMs", "payerMcp"]);
    if (!plain(dependencies)) fail();
    const allowedDependencies = new Set(["now", "probe", "sleep"]);
    if (Reflect.ownKeys(dependencies).some((key) => !allowedDependencies.has(key))) {
      fail();
    }
    const deps = Object.freeze({
      now: dependencies.now ?? Date.now,
      probe: dependencies.probe ?? probePinnedTlsEndpoint,
      sleep: dependencies.sleep ?? ((delayMs) => new Promise((resolve_) => setTimeout(resolve_, delayMs))),
    });
    if (
      !Number.isSafeInteger(checked.deadlineMs) ||
      checked.deadlineMs < 100 ||
      checked.deadlineMs > 120_000 ||
      typeof deps.now !== "function" ||
      typeof deps.probe !== "function" ||
      typeof deps.sleep !== "function"
    ) {
      fail();
    }
    const startedAt = deps.now();
    if (!Number.isSafeInteger(startedAt) || startedAt < 0) fail();
    for (;;) {
      try {
        const coordination = await deps.probe(checked.coordination);
        if (coordination?.paymentMoved !== false || coordination.ready !== true) fail();
        const payerMcp = await deps.probe(checked.payerMcp);
        if (payerMcp?.paymentMoved !== false || payerMcp.ready !== true) fail();
        return Object.freeze({
          coordinationReady: true,
          payerMcpReady: true,
          paymentMoved: false,
        });
      } catch (error) {
        if (
          error instanceof HybridPublicEdgeError &&
          error.code === "HYBRID_PUBLIC_EDGE_IDENTITY_MISMATCH"
        ) {
          throw error;
        }
        const now = deps.now();
        if (!Number.isSafeInteger(now) || now < startedAt) fail();
        const elapsed = now - startedAt;
        if (elapsed >= checked.deadlineMs) {
          fail("HYBRID_PUBLIC_EDGE_DEADLINE");
        }
        await deps.sleep(Math.min(100, checked.deadlineMs - elapsed));
      }
    }
  } catch (error) {
    if (error instanceof HybridPublicEdgeError) throw error;
    fail();
  }
}
