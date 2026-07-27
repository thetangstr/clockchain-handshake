import { createServer, request as httpRequest } from "node:http";
import { constants } from "node:fs";
import {
  lstat,
  open,
  readdir,
  realpath,
  rename,
  unlink,
} from "node:fs/promises";
import path from "node:path";
import process from "node:process";

import { createFakeBilateralClockchain } from "./fake-bilateral-clockchain.mjs";
import { assertSecretFree } from "../../src/redact.mjs";

const HOST = "127.0.0.1";
const PATHNAME = "/v1/call";
const MAX_BODY_BYTES = 64 * 1024;
const REQUEST_TIMEOUT_MS = 2_000;
const MAX_STATE_BYTES = 128 * 1024;
const MAX_OPERATIONS = 128;
const REJECTED = Object.freeze({ error: "request rejected", ok: false });
const STATE_SCHEMA = "clockchain.fake-bilateral-clockchain-state/v1";
const LISTEN_SCHEMA = "clockchain.fake-bilateral-clockchain-listen/v1";
const READ_METHODS = Object.freeze([
  "generateAuditTrail", "getBlock", "resolveAgent", "searchActions", "snapshot", "verifyCrossParty",
]);
const METHODS = new Set(["logAction", ...READ_METHODS, "registerAgent"]);
const DECIMAL_ID = /^(?:0|[1-9][0-9]*)$/;
const LEDGER_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HASH = /^[0-9a-f]{64}$/;

function successorTimestamp(blockTime) {
  const match = /^(.*)\.(\d{9})Z$/.exec(blockTime);
  if (match === null) throw new Error("invalid authoritative block time");
  const successor = /^(.*)\.(\d{3})Z$/.exec(new Date(Date.parse(blockTime) + 1_100).toISOString());
  if (successor === null) throw new Error("invalid authoritative block time");
  return `${successor[1]}.${successor[2]}${match[2].slice(3)}Z`;
}

function exactKeys(value, keys) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype && Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key));
}

function exactResponseMetadata(response) {
  if (response.httpVersion !== "1.1" || response.statusCode !== 200 || response.rawHeaders.length !== 8) return false;
  const headers = new Map();
  for (let index = 0; index < response.rawHeaders.length; index += 2) {
    const name = response.rawHeaders[index].toLowerCase();
    if (!new Set(["cache-control", "connection", "content-length", "content-type"]).has(name) || headers.has(name)) return false;
    headers.set(name, response.rawHeaders[index + 1]);
  }
  const length = headers.get("content-length");
  return headers.get("cache-control") === "no-store" && headers.get("connection") === "close" && headers.get("content-type") === "application/json" &&
    /^(?:0|[1-9][0-9]*)$/.test(length) && Number.isSafeInteger(Number(length)) && Number(length) <= MAX_BODY_BYTES;
}

function canonicalize(value, ancestors = new Set()) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (Array.isArray(value)) {
    if (ancestors.has(value)) throw new Error("cyclic value");
    ancestors.add(value);
    const result = value.map((entry) => canonicalize(entry, ancestors));
    ancestors.delete(value);
    return result;
  }
  if (typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype || ancestors.has(value)) {
    throw new Error("noncanonical value");
  }
  ancestors.add(value);
  const result = {};
  for (const key of Object.keys(value).sort()) result[key] = canonicalize(value[key], ancestors);
  ancestors.delete(value);
  return result;
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

function decimalId(value, maximumDigits) {
  const text = String(value);
  return (typeof value === "string" || Number.isSafeInteger(value)) && text.length <= maximumDigits && DECIMAL_ID.test(text);
}

function validParams(method, params) {
  switch (method) {
    case "logAction":
      return exactKeys(params, ["allow_degraded", "asset_hash", "asset_reference_id", "hash_type", "idempotency_key", "version_number", "wait", "wait_ms"]) &&
        params.allow_degraded === true && /^[0-9a-f]{64}$/.test(params.asset_hash) && /^[0-9a-z:]{1,120}$/.test(params.asset_reference_id) &&
        params.hash_type === "SHA-256" && /^[0-9a-f]{32}$/.test(params.idempotency_key) &&
        params.version_number === 1 && params.wait === true && params.wait_ms === 20_000;
    case "searchActions":
    case "generateAuditTrail":
      return exactKeys(params, ["asset_reference_id"]) && /^[0-9a-z:]{1,120}$/.test(params.asset_reference_id);
    case "verifyCrossParty":
      return (exactKeys(params, ["hash"]) && HASH.test(params.hash)) ||
        (exactKeys(params, ["ledgerId", "blockHeight"]) && LEDGER_ID.test(params.ledgerId) && typeof params.blockHeight === "string" && decimalId(params.blockHeight, 16));
    case "getBlock":
      return exactKeys(params, ["height"]) && typeof params.height === "string" && decimalId(params.height, 16);
    case "resolveAgent":
      return exactKeys(params, ["agentId"]) && decimalId(params.agentId, 20);
    case "registerAgent":
      return exactKeys(params, ["agentId", "owner", "status"]) && decimalId(params.agentId, 20) && /^0x[0-9a-f]{40}$/.test(params.owner) && params.status === "active";
    case "snapshot":
      return exactKeys(params, []);
    default:
      return false;
  }
}

function validateRequest(value, bytes) {
  return exactKeys(value, ["method", "params"]) && typeof value.method === "string" && METHODS.has(value.method) &&
    validParams(value.method, value.params) && Buffer.from(canonicalJson(value), "utf8").equals(bytes);
}

function owned(info, mode) {
  return info.uid === process.getuid() && (info.mode & 0o777) === mode;
}

async function pinPrivateParent(target) {
  if (typeof target !== "string" || !path.isAbsolute(target) || path.normalize(target) !== target) {
    throw new Error("private target must be a canonical absolute path");
  }
  const parentPath = await realpath(path.dirname(target));
  if (path.join(parentPath, path.basename(target)) !== target) throw new Error("private target must not traverse a symlink");
  const before = await lstat(parentPath);
  if (!before.isDirectory() || !owned(before, 0o700)) throw new Error("private target requires an owned 0700 parent");
  const handle = await open(parentPath, constants.O_RDONLY | constants.O_DIRECTORY | (constants.O_NOFOLLOW ?? 0));
  const pinned = await handle.stat();
  if (pinned.dev !== before.dev || pinned.ino !== before.ino || !owned(pinned, 0o700)) {
    await handle.close();
    throw new Error("private parent changed while opening");
  }
  return { handle, ino: pinned.ino, path: parentPath, dev: pinned.dev, target };
}

async function assertPinned(parent) {
  const current = await lstat(parent.path);
  const pinned = await parent.handle.stat();
  if (!current.isDirectory() || current.dev !== parent.dev || current.ino !== parent.ino ||
    pinned.dev !== parent.dev || pinned.ino !== parent.ino || !owned(current, 0o700) || !owned(pinned, 0o700)) {
    throw new Error("private parent changed");
  }
}

async function targetIdentity(target) {
  try {
    const info = await lstat(target);
    if (info.isSymbolicLink() || !info.isFile() || info.nlink !== 1 || !owned(info, 0o600)) throw new Error("private target must be an owned 0600 regular file");
    return { dev: info.dev, ino: info.ino, nlink: info.nlink, size: info.size };
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
}

function sameIdentity(left, right) {
  return left !== null && right !== null && left.dev === right.dev && left.ino === right.ino &&
    left.nlink === right.nlink && left.size === right.size;
}

async function raceHook(hooks, name, details) {
  const hook = hooks?.[name];
  if (hook === undefined) return;
  if (typeof hook !== "function") throw new Error("invalid fake-service race hook");
  await hook(Object.freeze(details));
}

async function assertNoStaleTemps(parent, target) {
  const prefix = `.${path.basename(target)}.`;
  if ((await readdir(parent.path)).some((name) => name.startsWith(prefix) && name.endsWith(".tmp"))) {
    throw new Error("stale private temporary file");
  }
}

async function readStablePrivateTarget(parent, expected) {
  const handle = await open(parent.target, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = await handle.stat();
    if (!sameIdentity(expected, opened)) throw new Error("private target readback changed");
    const buffer = Buffer.alloc(MAX_STATE_BYTES + 1);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    if (bytesRead > MAX_STATE_BYTES) throw new Error("private target readback too large");
    const after = await targetIdentity(parent.target);
    if (!sameIdentity(expected, after)) throw new Error("private target readback changed");
    await assertPinned(parent);
    return buffer.subarray(0, bytesRead);
  } finally {
    await handle.close();
  }
}

async function readExistingPrivateState(parent, hooks) {
  await assertPinned(parent);
  const before = await targetIdentity(parent.target);
  if (before === null) return null;
  await raceHook(hooks, "beforeExistingStateOpen", { parent, target: parent.target });
  const bytes = await readStablePrivateTarget(parent, before);
  return bytes.toString("utf8");
}

async function writePrivateJson(parent, value, hooks) {
  await assertPinned(parent);
  const previous = await targetIdentity(parent.target);
  await assertNoStaleTemps(parent, parent.target);
  const temporary = path.join(parent.path, `.${path.basename(parent.target)}.${process.pid}.${crypto.randomUUID()}.tmp`);
  const bytes = Buffer.from(`${canonicalJson(value)}\n`, "utf8");
  try {
    const handle = await open(temporary, "wx", 0o600);
    let temporaryIdentity;
    try {
      const tempInfo = await handle.stat();
      if (!tempInfo.isFile() || tempInfo.nlink !== 1 || !owned(tempInfo, 0o600)) throw new Error("private temporary changed");
      temporaryIdentity = { dev: tempInfo.dev, ino: tempInfo.ino };
      await handle.writeFile(bytes);
      await handle.sync();
    } finally {
      await handle.close();
    }
    await raceHook(hooks, "afterTemporaryWrite", { parent, temporary });
    await assertPinned(parent);
    const temporaryPathIdentity = await targetIdentity(temporary);
    if (temporaryPathIdentity === null || temporaryPathIdentity.dev !== temporaryIdentity.dev || temporaryPathIdentity.ino !== temporaryIdentity.ino) throw new Error("private temporary path changed");
    const current = await targetIdentity(parent.target);
    if ((previous === null) !== (current === null) || (previous !== null && (previous.dev !== current.dev || previous.ino !== current.ino))) {
      throw new Error("private target changed during write");
    }
    await rename(temporary, parent.target);
    await assertPinned(parent);
    const installed = await targetIdentity(parent.target);
    if (installed === null || installed.nlink !== 1 || installed.dev !== temporaryIdentity.dev || installed.ino !== temporaryIdentity.ino) throw new Error("private target changed after rename");
    await raceHook(hooks, "afterInstalledBeforeReadback", { parent });
    const readback = await readStablePrivateTarget(parent, installed);
    if (!readback.equals(bytes)) throw new Error("private target readback mismatch");
    await parent.handle.sync();
  } finally {
    await unlink(temporary).catch(() => {});
  }
}

function sanitize(value) {
  if (Array.isArray(value)) return value.map(sanitize);
  if (value === null || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value)
    .filter(([key]) => !/(?:token|private|secret|credential|authorization|password)/i.test(key))
    .map(([key, child]) => [key, sanitize(child)]));
}

function readJson(request) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    const timeout = setTimeout(() => reject(new Error("request timed out")), REQUEST_TIMEOUT_MS);
    request.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        clearTimeout(timeout);
        reject(new Error("body too large"));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => {
      clearTimeout(timeout);
      const bytes = Buffer.concat(chunks);
      try { resolve({ bytes, value: JSON.parse(bytes.toString("utf8")) }); } catch { reject(new Error("invalid json")); }
    });
    request.on("error", (error) => { clearTimeout(timeout); reject(error); });
  });
}

function sendJson(response, statusCode, value) {
  assertSecretFree(value);
  const body = canonicalJson(value);
  response.writeHead(statusCode, { "cache-control": "no-store", connection: "close", "content-length": Buffer.byteLength(body), "content-type": "application/json" });
  response.end(body);
}

export function createFakeBilateralClockchainService({ statePath, listenPath, dependencies = {} }) {
  let server;
  let stateParent;
  let listenParent;
  let accepting = true;
  let poisoned = false;
  let closed = false;
  let closePromise;
  let handlesClosed = false;
  let operations = 0;
  let listenIdentity;
  let writeCount = 0;
  let highestKnownHeight;
  let queue = Promise.resolve();
  const sockets = new Set();
  const registeredAgents = new Map();
  const readCounters = Object.fromEntries(READ_METHODS.map((method) => [method, 0]));
  const serviceCalls = Object.fromEntries([...METHODS].filter((method) => method !== "registerAgent" && method !== "snapshot").map((method) => [method, []]));
  const serviceCallSequence = [];
  const bindingsByHash = new Map();
  const fake = createFakeBilateralClockchain();
  const raceHooks = dependencies.raceHooks;
  const maxStateBytes = dependencies.maxStateBytes ?? MAX_STATE_BYTES;
  if (!Number.isSafeInteger(maxStateBytes) || maxStateBytes < 1_024 || maxStateBytes > MAX_STATE_BYTES) throw new Error("invalid fake-service state limit");

  function snapshot({ calls = serviceCalls, callSequence = serviceCallSequence, counters = readCounters, agents = registeredAgents, writes = writeCount } = {}) {
    const state = { calls, callSequence, paymentMoved: false, readCounters: counters, registeredAgents: [...agents.values()].sort((left, right) => left.agentId.localeCompare(right.agentId)), schema: STATE_SCHEMA, writeCount: writes };
    assertSecretFree(state);
    return state;
  }
  function assertSnapshotFits(value) {
    if (Buffer.byteLength(`${canonicalJson(value)}\n`, "utf8") > maxStateBytes) throw new Error("prospective fake state too large");
  }
  function prospectiveSnapshot(method, params) {
    const calls = canonicalize(serviceCalls); const callSequence = canonicalize(serviceCallSequence); const counters = { ...readCounters }; const agents = new Map(registeredAgents); let writes = writeCount;
    if (method === "snapshot") counters.snapshot += 1;
    else if (method === "registerAgent") agents.set(params.agentId, sanitize(params));
    else {
      const argument = method === "resolveAgent" ? params.agentId : params;
      calls[method].push(sanitize(argument)); callSequence.push({ args: sanitize(argument), name: method });
      if (method === "logAction") writes += 1;
      if (READ_METHODS.includes(method)) counters[method] += 1;
    }
    return snapshot({ agents, callSequence, calls, counters, writes });
  }
  function recordServiceCall(method, argument) {
    const args = canonicalize(argument);
    serviceCalls[method].push(args); serviceCallSequence.push({ args: canonicalize(args), name: method });
  }
  async function readBlock(params) {
    const requestedHeight = Number(params.height);
    if (Number.isSafeInteger(highestKnownHeight) && requestedHeight === highestKnownHeight + 1) {
      const anchored = await fake.getBlock({ height: String(highestKnownHeight) });
      return { ...anchored, blockHeight: params.height, blockTime: successorTimestamp(anchored.blockTime) };
    }
    return fake.getBlock(params);
  }
  async function persistState() { const state = snapshot(); assertSnapshotFits(state); await writePrivateJson(stateParent, state, raceHooks); }
  function exclusive(work) {
    if (!accepting || poisoned) return Promise.reject(new Error("fake service is unavailable"));
    const next = queue.then(work, work);
    queue = next.catch(() => {});
    return next;
  }
  async function closeHandles() {
    if (handlesClosed) return;
    handlesClosed = true;
    await stateParent?.handle.close().catch(() => {});
    if (listenParent?.handle !== stateParent?.handle) await listenParent?.handle.close().catch(() => {});
  }
  async function removeCapturedReadiness() {
    if (listenIdentity === undefined) return;
    const current = await targetIdentity(listenPath);
    if (current !== null && current.dev === listenIdentity.dev && current.ino === listenIdentity.ino) {
      await unlink(listenPath);
      await assertPinned(listenParent);
      await listenParent.handle.sync();
    }
  }
  async function stopServer() {
    if (server === undefined) return;
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve_) => server.close(() => resolve_()));
  }
  async function shutdown() {
    accepting = false;
    await stopServer();
    await queue;
    await removeCapturedReadiness();
    await closeHandles();
  }
  async function invoke(method, params) {
    if (poisoned) throw new Error("fake service is unavailable");
    if (operations >= MAX_OPERATIONS) throw new Error("operation limit");
    assertSnapshotFits(prospectiveSnapshot(method, params));
    operations += 1;
    let mutated = false;
    let persistenceStarted = false;
    try {
      if (method === "snapshot") {
        readCounters.snapshot += 1; mutated = true;
        persistenceStarted = true;
        await persistState();
        return snapshot();
      }
      if (method === "registerAgent") {
        fake.registerAgent(params); registeredAgents.set(params.agentId, sanitize(params)); mutated = true;
        persistenceStarted = true;
        await persistState();
        return null;
      }
      const argument = method === "resolveAgent" ? params.agentId : params;
      let result;
      if (method === "verifyCrossParty" && Object.hasOwn(params, "hash")) {
        const binding = bindingsByHash.get(params.hash);
        result = { onChain: binding === undefined ? { anchoredHash: params.hash, assetReferenceId: null, blockHeight: null, keyless: false, ledgerId: null, verifiedAgainst: "none" } : { ...binding, keyless: true, verifiedAgainst: "on-chain block" } };
      } else if (method === "getBlock") result = await readBlock(params);
      else result = await fake[method](argument);
      recordServiceCall(method, argument); mutated = true;
      if (method === "logAction") writeCount += 1;
      if (method === "logAction") bindingsByHash.set(params.asset_hash, Object.freeze({ anchoredHash: params.asset_hash, assetReferenceId: params.asset_reference_id, blockHeight: result.blockHeight, ledgerId: result.ledgerId }));
      if (method === "logAction") highestKnownHeight = Number(result.blockHeight);
      if (READ_METHODS.includes(method)) readCounters[method] += 1;
      persistenceStarted = true;
      await persistState();
      const returned = sanitize(result); assertSecretFree(returned); return returned;
    } catch (error) {
      if (mutated && persistenceStarted) { poisoned = true; accepting = false; }
      throw error;
    }
  }
  async function start() {
    if (statePath === listenPath) throw new Error("state and listen targets must be distinct");
    stateParent = await pinPrivateParent(statePath);
    try {
      listenParent = await pinPrivateParent(listenPath);
      await targetIdentity(statePath);
      if (await targetIdentity(listenPath)) throw new Error("readiness target must be absent at startup");
      await assertNoStaleTemps(stateParent, statePath);
      await assertNoStaleTemps(listenParent, listenPath);
      const stateInfo = await targetIdentity(statePath);
      if (stateInfo !== null && stateInfo.size > MAX_STATE_BYTES) throw new Error("state too large");
      const existing = await readExistingPrivateState(stateParent, raceHooks);
      if (existing !== null && existing.length > 0) throw new Error("refusing to recover nonempty prior fake state");
      server = createServer(async (request, response) => {
        response.sendDate = false;
        response.setTimeout(REQUEST_TIMEOUT_MS, () => response.destroy());
        if (request.socket.remoteAddress !== HOST || request.method !== "POST" || request.url !== PATHNAME || request.headers["content-type"] !== "application/json") {
          sendJson(response, 400, REJECTED);
          return;
        }
        try {
          const body = await readJson(request);
          if (!validateRequest(body.value, body.bytes)) throw new Error("invalid request");
          sendJson(response, 200, { ok: true, result: await exclusive(() => invoke(body.value.method, body.value.params)) });
        } catch {
          if (!response.headersSent) sendJson(response, 400, REJECTED);
        }
      });
      server.sendDate = false;
      server.requestTimeout = REQUEST_TIMEOUT_MS;
      server.headersTimeout = REQUEST_TIMEOUT_MS;
      server.keepAliveTimeout = 1_000;
      server.on("connection", (socket) => { sockets.add(socket); socket.on("close", () => sockets.delete(socket)); });
      await new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen({ host: HOST, port: 0 }, () => { server.off("error", reject); resolve(); });
      });
      const address = server.address();
      await writePrivateJson(listenParent, { host: HOST, paymentMoved: false, pid: process.pid, port: address.port, schema: LISTEN_SCHEMA }, raceHooks);
      listenIdentity = await targetIdentity(listenPath);
      return { host: HOST, port: address.port };
    } catch (error) {
      if (closePromise === undefined) { closed = true; closePromise = shutdown(); }
      await closePromise;
      throw error;
    }
  }
  return {
    get fake() { return fake; }, get server() { return server; }, start,
    async close() {
      if (closePromise === undefined) { closed = true; closePromise = shutdown(); }
      await closePromise;
    },
  };
}

export async function startFakeBilateralClockchainService(options) {
  const service = createFakeBilateralClockchainService(options);
  const listen = await service.start();
  return Object.freeze({ get fake() { return service.fake; }, get server() { return service.server; }, close: () => service.close(), listen });
}

export function createFakeBilateralClockchainHttpClient(options) {
  if (options === null || typeof options !== "object" || Array.isArray(options) || Object.getPrototypeOf(options) !== Object.prototype) throw new Error("invalid fake service endpoint");
  const endpointKeys = options.timeoutMs === undefined ? ["host", "port"] : ["host", "port", "timeoutMs"];
  const readinessKeys = ["host", "paymentMoved", "pid", "port", "schema"];
  const readiness = exactKeys(options, readinessKeys);
  if (!readiness && !exactKeys(options, endpointKeys)) throw new Error("invalid fake service endpoint");
  if (options.host !== HOST || !Number.isSafeInteger(options.port) || options.port < 1 || options.port > 65_535) throw new Error("invalid fake service endpoint");
  if (readiness && (options.paymentMoved !== false || !Number.isSafeInteger(options.pid) || options.pid < 1 || options.pid > 2_147_483_647 || options.schema !== LISTEN_SCHEMA)) throw new Error("invalid fake readiness record");
  const timeoutMs = options.timeoutMs ?? REQUEST_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > REQUEST_TIMEOUT_MS) throw new Error("invalid fake service timeout");
  const { host, port } = options;
  async function call(method, params) {
    const body = canonicalJson({ method, params });
    return new Promise((resolve, reject) => {
      let settled = false;
      let response;
      const finish = (error, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(deadline);
        client.destroy();
        response?.destroy();
        if (error) reject(error); else resolve(value);
      };
      const deadline = setTimeout(() => finish(new Error("fake service request failed")), timeoutMs);
      const client = httpRequest({ host, port, method: "POST", path: PATHNAME, timeout: timeoutMs, headers: { "content-length": Buffer.byteLength(body), "content-type": "application/json" } }, (response) => {
        if (!exactResponseMetadata(response)) return finish(new Error("fake service request failed"));
        const chunks = []; let size = 0;
        response.on("data", (chunk) => { size += chunk.length; if (size > MAX_BODY_BYTES) finish(new Error("fake service request failed")); else chunks.push(chunk); });
        response.on("end", () => {
          try {
            const bytes = Buffer.concat(chunks); const value = JSON.parse(bytes.toString("utf8"));
            if (!response.complete || response.rawTrailers.length !== 0 || Number(response.headers["content-length"]) !== bytes.length || !Buffer.from(canonicalJson(value), "utf8").equals(bytes) || !exactKeys(value, ["ok", "result"]) || value.ok !== true) throw new Error("invalid response");
            finish(null, value.result);
          } catch { finish(new Error("fake service request failed")); }
        });
        response.on("aborted", () => finish(new Error("fake service request failed")));
        response.on("error", () => finish(new Error("fake service request failed")));
        response.on("close", () => { if (!response.complete) finish(new Error("fake service request failed")); });
      });
      client.setTimeout(timeoutMs, () => finish(new Error("fake service request failed")));
      client.on("error", () => finish(new Error("fake service request failed")));
      client.end(body);
    });
  }
  return Object.freeze({
    generateAuditTrail: (params) => call("generateAuditTrail", params), getBlock: (params) => call("getBlock", params),
    logAction: (params) => call("logAction", params), registerAgent: (params) => call("registerAgent", params),
    resolveAgent: (agentId) => call("resolveAgent", { agentId }), searchActions: (params) => call("searchActions", params),
    snapshot: () => call("snapshot", {}), verifyCrossParty: (params) => call("verifyCrossParty", params),
  });
}

function cliArguments(argv) {
  if (argv.length !== 4 || argv[0] !== "--state" || argv[2] !== "--listen-file") throw new Error("usage: --state <private canonical path> --listen-file <private canonical path>");
  return { statePath: argv[1], listenPath: argv[3] };
}

if (import.meta.url === new URL(process.argv[1], "file:").href) {
  let service; let started = false; let signalReceived = false; let closePromise;
  const close = async () => {
    signalReceived = true;
    if (!started) return;
    if (closePromise === undefined) closePromise = (async () => { try { await service.close(); process.exitCode = 0; } catch { process.exitCode = 1; } })();
    await closePromise;
  };
  process.once("SIGINT", () => { void close(); }); process.once("SIGTERM", () => { void close(); });
  try { service = createFakeBilateralClockchainService(cliArguments(process.argv.slice(2))); await service.start(); started = true; if (signalReceived) await close(); } catch { process.exitCode = 1; }
}
