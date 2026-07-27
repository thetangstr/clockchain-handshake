import assert from "node:assert/strict";
import { chmod, link, lstat, mkdtemp, readFile, realpath, rename, rm, stat, symlink, unlink, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import http, { createServer } from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { assertSecretFree } from "../src/redact.mjs";
import { parseBlockTime } from "../src/bilateral/blocktime.mjs";

import {
  canonicalJson,
  createFakeBilateralClockchainService,
  createFakeBilateralClockchainHttpClient,
  startFakeBilateralClockchainService,
} from "./helpers/fake-bilateral-clockchain-service.mjs";

function runCli(args) {
  return new Promise((resolve, reject) => {
    const { NODE_TEST_CONTEXT, ...environment } = process.env;
    const child = spawn(process.execPath, args, { env: environment, stdio: ["ignore", "ignore", "pipe"] });
    let stderr = "";
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.once("error", reject);
    child.once("close", (code, signal) => resolve({ code, signal, stderr }));
  });
}

test("fake service is inert when directly discovered by node:test but rejects an empty CLI", async () => {
  const helper = new URL("./helpers/fake-bilateral-clockchain-service.mjs", import.meta.url).pathname;
  const discovered = await runCli(["--test", helper]);
  assert.equal(discovered.code, 0, discovered.stderr);
  const direct = await runCli([helper]);
  assert.notEqual(direct.code, 0);
});

async function request(listen, body, options = {}) {
  return new Promise((resolve, reject) => {
    const encoded = options.raw ?? canonicalJson(body);
    const client = http.request({
      host: "127.0.0.1",
      port: listen.port,
      path: options.path ?? "/v1/call",
      method: options.method ?? "POST",
      headers: {
        "content-type": options.contentType ?? "application/json",
        "content-length": Buffer.byteLength(encoded),
      },
    }, (response) => {
      let data = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => { data += chunk; });
      response.on("end", () => resolve({
        statusCode: response.statusCode,
        body: JSON.parse(data),
      }));
    });
    client.on("error", reject);
    client.end(encoded);
  });
}

async function eventually(read, timeoutMs = 1_000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try { return await read(); } catch (error) {
      if (Date.now() >= deadline) throw error;
      await new Promise((resolve_) => setTimeout(resolve_, 10));
    }
  }
}

test("service writes a private readiness record and exposes deterministic calls", async (t) => {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), "fake-clockchain-service-")));
  const statePath = path.join(directory, "state.json");
  const listenPath = path.join(directory, "listen.json");
  const service = await startFakeBilateralClockchainService({ statePath, listenPath });
  t.after(() => service.close());

  const listen = JSON.parse(await readFile(listenPath, "utf8"));
  assert.deepEqual(Object.keys(listen).sort(), ["host", "paymentMoved", "pid", "port", "schema"]);
  assert.equal(listen.schema, "clockchain.fake-bilateral-clockchain-listen/v1");
  assert.equal(listen.paymentMoved, false);
  assert.equal(listen.pid, process.pid);
  assert.equal(listen.host, "127.0.0.1");
  assert.ok(Number.isInteger(listen.port) && listen.port > 0);
  assert.equal((await stat(listenPath)).mode & 0o777, 0o600);

  const registered = await request(listen, {
    method: "registerAgent",
    params: { agentId: "1", owner: "0x1111111111111111111111111111111111111111", status: "active" },
  });
  assert.deepEqual(registered, { statusCode: 200, body: { ok: true, result: null } });

  const written = await request(listen, {
    method: "logAction",
    params: {
      allow_degraded: true,
      asset_reference_id: "m1",
      asset_hash: "a".repeat(64),
      hash_type: "SHA-256",
      idempotency_key: "b".repeat(32),
      version_number: 1,
      wait: true,
      wait_ms: 20_000,
    },
  });
  assert.deepEqual(written.body, {
    ok: true,
    result: { blockHeight: "3375601", ledgerId: "00000000-0000-4000-8000-000000000001" },
  });

  const found = await request(listen, {
    method: "searchActions",
    params: { asset_reference_id: "m1" },
  });
  assert.deepEqual(found.body.result, [{
    assetHash: "a".repeat(64),
    assetReferenceId: "m1",
    blockHeight: "3375601",
    hashType: "SHA-256",
    ledgerId: "00000000-0000-4000-8000-000000000001",
  }]);

  const stateBytes = await readFile(statePath, "utf8");
  const state = JSON.parse(stateBytes);
  assert.equal((await stat(statePath)).mode & 0o777, 0o600);
  assert.equal(stateBytes, `${canonicalJson(state)}\n`);
  assert.equal(state.schema, "clockchain.fake-bilateral-clockchain-state/v1");
  assert.equal(state.paymentMoved, false);
  assert.deepEqual(Object.keys(state).sort(), ["callSequence", "calls", "paymentMoved", "readCounters", "registeredAgents", "schema", "writeCount"]);
  assert.equal(state.writeCount, 1);
  assert.deepEqual(state.registeredAgents, [{ agentId: "1", owner: "0x1111111111111111111111111111111111111111", status: "active" }]);
  assert.equal(state.callSequence.map(({ name }) => name).join(","), "logAction,searchActions");
  assert.deepEqual(state.readCounters, {
    generateAuditTrail: 0,
    getBlock: 0,
    resolveAgent: 0,
    searchActions: 1,
    snapshot: 0,
    verifyCrossParty: 0,
  });

  const client = createFakeBilateralClockchainHttpClient(listen);
  const snapshot = await client.snapshot();
  assert.equal(snapshot.readCounters.snapshot, 1);
  assert.equal(JSON.parse(await readFile(statePath, "utf8")).readCounters.snapshot, 1);
});

test("started service exposes its live server and closes without deleting a replacement readiness file", async (t) => {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), "fake-clockchain-lifecycle-")));
  const listenPath = path.join(directory, "listen.json");
  const service = await startFakeBilateralClockchainService({ statePath: path.join(directory, "state.json"), listenPath });
  t.after(() => service.close());
  assert.equal(typeof service.server?.close, "function");
  const captured = await lstat(listenPath);
  await rename(listenPath, `${listenPath}.original`);
  await writeFile(listenPath, "replacement\n", { mode: 0o600 });
  await service.close();
  const replacement = await lstat(listenPath);
  assert.notEqual(replacement.ino, captured.ino);
  assert.equal(await readFile(listenPath, "utf8"), "replacement\n");
});

test("close destroys an active connection and drains work already queued before shutdown", async (t) => {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), "fake-clockchain-close-")));
  const statePath = path.join(directory, "state.json"); let releaseWrite; let writes = 0;
  const blocked = new Promise((resolve_) => { releaseWrite = resolve_; });
  const service = await startFakeBilateralClockchainService({ statePath, listenPath: path.join(directory, "listen.json"), dependencies: { raceHooks: { async afterTemporaryWrite({ parent }) { if (parent.target === statePath && writes++ === 0) await blocked; } } } });
  t.after(() => service.close());
  const raw = http.request({ host: service.listen.host, port: service.listen.port, path: "/v1/call", method: "POST", headers: { "content-type": "application/json", "content-length": "100" } });
  raw.on("error", () => {}); raw.write('{"method":"snapshot"');
  const first = request(service.listen, { method: "snapshot", params: {} }).catch(() => null);
  const second = request(service.listen, { method: "snapshot", params: {} }).catch(() => null);
  await eventually(async () => { if (writes !== 1) throw new Error("write has not blocked"); });
  const closing = service.close();
  releaseWrite();
  await Promise.race([closing, new Promise((_resolve, reject) => setTimeout(() => reject(new Error("close timed out")), 500))]);
  await Promise.all([first, second]);
  assert.ok(writes >= 2);
});

test("CLI removes readiness and exits successfully after SIGTERM", async (t) => {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), "fake-clockchain-cli-")));
  const statePath = path.join(directory, "state.json"); const listenPath = path.join(directory, "listen.json");
  t.after(() => rm(directory, { recursive: true, force: true }));
  const child = spawn(process.execPath, [new URL("./helpers/fake-bilateral-clockchain-service.mjs", import.meta.url).pathname, "--state", statePath, "--listen-file", listenPath, "--max-operations", "512"], { stdio: "ignore" });
  await eventually(() => readFile(listenPath, "utf8"));
  child.kill("SIGTERM");
  const [code] = await Promise.race([new Promise((resolve_) => child.once("exit", (exitCode) => resolve_([exitCode]))), new Promise((_resolve, reject) => setTimeout(() => reject(new Error("CLI did not exit")), 1_000))]);
  assert.equal(code, 0);
  await assert.rejects(readFile(listenPath), /ENOENT/);
});

test("service rejects malformed closed API requests with generic failures", async (t) => {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), "fake-clockchain-service-")));
  const service = await startFakeBilateralClockchainService({
    statePath: path.join(directory, "state.json"),
    listenPath: path.join(directory, "listen.json"),
  });
  t.after(() => service.close());
  const listen = JSON.parse(await readFile(path.join(directory, "listen.json"), "utf8"));

  for (const options of [
    { path: "/wrong" },
    { method: "GET" },
    { contentType: "text/plain" },
  ]) {
    const response = await request(listen, { method: "unknown", params: {} }, options);
    assert.deepEqual(response, { statusCode: 400, body: { ok: false, error: "request rejected" } });
  }
  const extra = await request(listen, { method: "snapshot", params: {}, extra: true });
  assert.deepEqual(extra, { statusCode: 400, body: { ok: false, error: "request rejected" } });
  const forbidden = await request(listen, { method: "verifyPackage", params: {} });
  assert.deepEqual(forbidden, { statusCode: 400, body: { ok: false, error: "request rejected" } });
  const noncanonical = await request(listen, { method: "snapshot", params: {} }, {
    raw: '{"params":{},"method":"snapshot"}',
  });
  assert.deepEqual(noncanonical, { statusCode: 400, body: { ok: false, error: "request rejected" } });
});

test("service preserves exact hash and ledger cross-party verification requests", async (t) => {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), "fake-clockchain-cross-party-")));
  const service = await startFakeBilateralClockchainService({ statePath: path.join(directory, "state.json"), listenPath: path.join(directory, "listen.json") });
  t.after(() => service.close());
  const logged = await request(service.listen, { method: "logAction", params: { allow_degraded: true, asset_hash: "a".repeat(64), asset_reference_id: "m1", hash_type: "SHA-256", idempotency_key: "b".repeat(32), version_number: 1, wait: true, wait_ms: 20_000 } });
  const binding = logged.body.result;
  const hash = await request(service.listen, { method: "verifyCrossParty", params: { hash: "a".repeat(64) } });
  const ledger = await request(service.listen, { method: "verifyCrossParty", params: { blockHeight: binding.blockHeight, ledgerId: binding.ledgerId } });
  assert.deepEqual(hash.body.result, ledger.body.result);
  assert.deepEqual(hash.body.result.onChain, { anchoredHash: "a".repeat(64), assetReferenceId: "m1", blockHeight: binding.blockHeight, keyless: true, ledgerId: binding.ledgerId, verifiedAgainst: "on-chain block" });
  for (const params of [
    {}, { hash: "a".repeat(64), blockHeight: binding.blockHeight, ledgerId: binding.ledgerId }, { hash: "a".repeat(64), token: "secret-value" }, { ledgerId: binding.ledgerId }, { blockHeight: binding.blockHeight }, { blockHeight: 1, ledgerId: binding.ledgerId },
  ]) assert.deepEqual(await request(service.listen, { method: "verifyCrossParty", params }), { statusCode: 400, body: { ok: false, error: "request rejected" } });
  assert.deepEqual(await request(service.listen, { method: "getBlock", params: { height: Number(binding.blockHeight) } }), { statusCode: 400, body: { ok: false, error: "request rejected" } });
  const snapshot = (await request(service.listen, { method: "snapshot", params: {} })).body.result;
  assert.deepEqual(snapshot.calls.verifyCrossParty, [{ hash: "a".repeat(64) }, { blockHeight: binding.blockHeight, ledgerId: binding.ledgerId }]);
  assert.deepEqual(snapshot.callSequence.filter(({ name }) => name === "verifyCrossParty").map(({ args }) => args), snapshot.calls.verifyCrossParty);
  assert.doesNotThrow(() => assertSecretFree(snapshot));
});

test("service exposes only the immediate read-only successor of the highest anchored block", async (t) => {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), "fake-clockchain-successor-")));
  const service = await startFakeBilateralClockchainService({ statePath: path.join(directory, "state.json"), listenPath: path.join(directory, "listen.json") });
  t.after(() => service.close());
  const actions = [];
  for (const index of [0, 1, 2]) actions.push(await request(service.listen, {
    method: "logAction",
    params: { allow_degraded: true, asset_hash: String.fromCharCode(97 + index).repeat(64), asset_reference_id: `m${index + 1}`, hash_type: "SHA-256", idempotency_key: String(index + 1).padStart(32, "0"), version_number: 1, wait: true, wait_ms: 20_000 },
  }));
  assert.deepEqual(actions.map(({ statusCode }) => statusCode), [200, 200, 200]);
  const heights = actions.map(({ body }) => body.result.blockHeight);
  const anchoredHeight = String(Number(heights[1]) + 1);
  assert.equal(anchoredHeight, heights[2]);
  const anchored = await request(service.listen, { method: "getBlock", params: { height: anchoredHeight } });
  const successorHeight = String(Number(anchoredHeight) + 1);
  const successor = await request(service.listen, { method: "getBlock", params: { height: successorHeight } });
  assert.equal(anchored.statusCode, 200);
  assert.deepEqual(successor.body.result, {
    ...anchored.body.result,
    blockHeight: successorHeight,
    blockTime: "2026-07-24T20:00:04.400123456Z",
  });
  assert.equal(parseBlockTime(successor.body.result.blockTime), parseBlockTime(anchored.body.result.blockTime) + 1_100);
  const snapshot = (await request(service.listen, { method: "snapshot", params: {} })).body.result;
  assert.equal(snapshot.writeCount, 3);
  assert.deepEqual(snapshot.calls.logAction.map(({ asset_reference_id }) => asset_reference_id), ["m1", "m2", "m3"]);
  assert.deepEqual(snapshot.calls.getBlock, [{ height: anchoredHeight }, { height: successorHeight }]);
  assert.deepEqual(await request(service.listen, { method: "getBlock", params: { height: "9999999" } }), { statusCode: 400, body: { ok: false, error: "request rejected" } });
  assert.deepEqual((await request(service.listen, { method: "searchActions", params: { asset_reference_id: "m3" } })).body.result, [{
    assetHash: "c".repeat(64), assetReferenceId: "m3", blockHeight: heights[2], hashType: "SHA-256", ledgerId: actions[2].body.result.ledgerId,
  }]);
});

test("service fails closed on nonempty or symlinked private state targets", async () => {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), "fake-clockchain-service-")));
  const statePath = path.join(directory, "state.json");
  const listenPath = path.join(directory, "listen.json");
  await writeFile(statePath, "prior state", { mode: 0o600 });
  await assert.rejects(
    startFakeBilateralClockchainService({ statePath, listenPath }),
    /nonempty prior fake state/,
  );

  const target = path.join(directory, "target.json");
  await writeFile(target, "", { mode: 0o600 });
  await unlink(statePath);
  await symlink(target, statePath);
  await assert.rejects(
    startFakeBilateralClockchainService({ statePath, listenPath }),
    /private target/,
  );
});

test("service accepts only the exact production logAction contract and private 0700 parents", async (t) => {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), "fake-clockchain-service-")));
  const service = await startFakeBilateralClockchainService({
    statePath: path.join(directory, "state.json"),
    listenPath: path.join(directory, "listen.json"),
  });
  t.after(() => service.close());
  const listen = JSON.parse(await readFile(path.join(directory, "listen.json"), "utf8"));
  const exact = {
    allow_degraded: true,
    asset_hash: "c".repeat(64),
    asset_reference_id: "m2",
    hash_type: "SHA-256",
    idempotency_key: "d".repeat(32),
    version_number: 1,
    wait: true,
    wait_ms: 20_000,
  };
  assert.equal((await request(listen, { method: "logAction", params: exact })).statusCode, 200);
  for (const params of [
    { ...exact, additional_info: "no" },
    { ...exact, content: "no" },
    { ...exact, did: "no" },
    { ...exact, allow_degraded: false },
    { ...exact, wait_ms: 1 },
    (({ wait, ...rest }) => rest)(exact),
  ]) {
    assert.deepEqual(await request(listen, { method: "logAction", params }), {
      statusCode: 400,
      body: { ok: false, error: "request rejected" },
    });
  }

  const unsafe = await realpath(await mkdtemp(path.join(os.tmpdir(), "fake-clockchain-unsafe-")));
  await chmod(unsafe, 0o755);
  await assert.rejects(startFakeBilateralClockchainService({
    statePath: path.join(unsafe, "state.json"),
    listenPath: path.join(unsafe, "listen.json"),
  }), /0700 parent/);
});

test("client has an absolute response deadline even while a peer trickles bytes", async (t) => {
  const server = createServer((request, response) => {
    response.writeHead(200, { "cache-control": "no-store", connection: "close", "content-length": "100", "content-type": "application/json" });
    const interval = setInterval(() => response.write(" "), 10);
    response.on("close", () => clearInterval(interval));
  });
  server.sendDate = false;
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const { port } = server.address();
  const client = createFakeBilateralClockchainHttpClient({ host: "127.0.0.1", port, timeoutMs: 50 });
  const started = Date.now();
  await assert.rejects(client.snapshot(), /fake service request failed/);
  assert.ok(Date.now() - started < 500);
});

test("HTTP client accepts only an exact closed fake-service response", async () => {
  const body = canonicalJson({ ok: true, result: {} });
  const requiredHeaders = (length = Buffer.byteLength(body)) => ["cache-control: no-store", "connection: close", `content-length: ${length}`, "content-type: application/json"];
  const cases = [
    { name: "valid", accept: true },
    { name: "extra header", headers: [...requiredHeaders(), "x-extra: nope"] },
    { name: "duplicate required header", headers: [...requiredHeaders(), "cache-control: no-store"] },
    { name: "noncanonical length", headers: requiredHeaders(`0${Buffer.byteLength(body)}`) },
    { name: "wrong status", status: 201 },
    { name: "wrong type", headers: ["cache-control: no-store", "connection: close", `content-length: ${Buffer.byteLength(body)}`, "content-type: text/plain"] },
    { name: "wrong cache", headers: ["cache-control: private", "connection: close", `content-length: ${Buffer.byteLength(body)}`, "content-type: application/json"] },
    { name: "wrong connection", headers: ["cache-control: no-store", "connection: keep-alive", `content-length: ${Buffer.byteLength(body)}`, "content-type: application/json"] },
    { name: "malformed envelope", body: "{" },
    { name: "noncanonical envelope", body: '{"result":{},"ok":true}' },
    { name: "extra envelope key", body: '{"extra":true,"ok":true,"result":{}}' },
    { name: "truncated body", body: body.slice(0, -1), length: Buffer.byteLength(body) },
    { name: "aborted body", abort: true },
    { name: "trickled body", trickle: true },
    { name: "trailer", headers: ["cache-control: no-store", "connection: close", "transfer-encoding: chunked", "content-type: application/json", "trailer: x-extra"], chunked: true },
  ];
  const sockets = new Set();
  for (const scenario of cases) {
    const server = net.createServer((socket) => {
      sockets.add(socket); socket.on("close", () => sockets.delete(socket));
      socket.once("data", () => {
        if (scenario.trickle) {
          socket.write(`HTTP/1.1 200 OK\r\n${requiredHeaders(100).join("\r\n")}\r\n\r\n`);
          const interval = setInterval(() => socket.write(" "), 10);
          socket.on("close", () => clearInterval(interval));
          return;
        }
        const responseBody = scenario.body ?? body;
        const headers = scenario.headers ?? requiredHeaders(scenario.length ?? Buffer.byteLength(responseBody));
        socket.write(`HTTP/1.1 ${scenario.status ?? 200} OK\r\n${headers.join("\r\n")}\r\n\r\n`);
        if (scenario.chunked) socket.end(`${Buffer.byteLength(body).toString(16)}\r\n${body}\r\n0\r\nx-extra: nope\r\n\r\n`);
        else if (scenario.abort) { socket.write(body.slice(0, -1)); socket.destroy(); }
        else socket.end(responseBody);
      });
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const client = createFakeBilateralClockchainHttpClient({ host: "127.0.0.1", port: server.address().port, timeoutMs: 50 });
      const started = Date.now();
      if (scenario.accept) await assert.doesNotReject(client.snapshot(), scenario.name);
      else {
        await assert.rejects(client.snapshot(), /fake service request failed/, scenario.name);
        assert.ok(Date.now() - started < 500, `${scenario.name} should reject promptly`);
      }
    } finally {
      for (const socket of sockets) socket.destroy();
      await new Promise((resolve) => server.close(resolve));
    }
  }
});

test("HTTP client accepts only exact local endpoint or readiness records", () => {
  const endpoint = { host: "127.0.0.1", port: 8443 };
  const readiness = { host: "127.0.0.1", paymentMoved: false, pid: process.pid, port: 8443, schema: "clockchain.fake-bilateral-clockchain-listen/v1" };
  assert.doesNotThrow(() => createFakeBilateralClockchainHttpClient(endpoint));
  assert.doesNotThrow(() => createFakeBilateralClockchainHttpClient(readiness));
  for (const options of [
    { host: "localhost", port: 8443 }, { host: "127.0.0.1", port: 0 }, { host: "127.0.0.1", port: 8443, timeoutMs: 0 }, { host: "127.0.0.1", port: 8443, timeoutMs: 2_001 },
    { ...readiness, paymentMoved: true }, { ...readiness, schema: "other" }, { ...readiness, pid: 0 }, { ...readiness, extra: true }, { port: 8443 },
  ]) assert.throws(() => createFakeBilateralClockchainHttpClient(options));
});

test("service rejects hardlinks, duplicate targets, and invalid production-shaped values", async () => {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), "fake-clockchain-service-")));
  const statePath = path.join(directory, "state.json");
  const listenPath = path.join(directory, "listen.json");
  await writeFile(statePath, "", { mode: 0o600 });
  await link(statePath, path.join(directory, "state-link.json"));
  await assert.rejects(startFakeBilateralClockchainService({ statePath, listenPath }), /0600 regular file/);
  await assert.rejects(startFakeBilateralClockchainService({ statePath: listenPath, listenPath }), /distinct/);

  await unlink(statePath);
  const service = await startFakeBilateralClockchainService({ statePath, listenPath });
  const listen = JSON.parse(await readFile(listenPath, "utf8"));
  try {
    for (const params of [
      { agentId: "001", owner: "0x1111111111111111111111111111111111111111", status: "active" },
      { agentId: "1", owner: "0x111111111111111111111111111111111111111A", status: "active" },
      { agentId: "1", owner: "0x1111111111111111111111111111111111111111", status: "inactive" },
    ]) {
      assert.equal((await request(listen, { method: "registerAgent", params })).statusCode, 400);
    }
    assert.equal((await request(listen, { method: "searchActions", params: { asset_reference_id: "M1" } })).statusCode, 400);
  } finally {
    await service.close();
  }
});

test("oversized prospective fake state is rejected before it mutates counters or durable state", async (t) => {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), "fake-clockchain-state-limit-")));
  const statePath = path.join(directory, "state.json");
  const service = await startFakeBilateralClockchainService({ statePath, listenPath: path.join(directory, "listen.json"), dependencies: { maxStateBytes: 4_096 } });
  t.after(() => service.close());
  let priorBytes; let rejected = false;
  for (let index = 0; index < 128; index += 1) {
    const response = await request(service.listen, {
      method: "logAction",
      params: { allow_degraded: true, asset_hash: "a".repeat(64), asset_reference_id: `m${index}`, hash_type: "SHA-256", idempotency_key: index.toString(16).padStart(32, "0"), version_number: 1, wait: true, wait_ms: 20_000 },
    });
    if (response.statusCode === 400) { rejected = true; break; }
    assert.deepEqual(response.body.ok, true);
    priorBytes = await readFile(statePath);
  }
  assert.equal(rejected, true);
  const prior = JSON.parse(priorBytes.toString("utf8"));
  for (let index = 0; index < 128; index += 1) {
    assert.deepEqual(await request(service.listen, {
      method: "logAction",
      params: { allow_degraded: true, asset_hash: "a".repeat(64), asset_reference_id: "mx", hash_type: "SHA-256", idempotency_key: "f".repeat(32), version_number: 1, wait: true, wait_ms: 20_000 },
    }), { statusCode: 400, body: { ok: false, error: "request rejected" } });
  }
  const after = await request(service.listen, { method: "snapshot", params: {} });
  assert.equal(after.statusCode, 200);
  assert.equal(after.body.result.writeCount, prior.writeCount);
  assert.deepEqual(after.body.result.calls, prior.calls);
  assert.deepEqual(after.body.result.callSequence, prior.callSequence);
  assert.deepEqual(after.body.result.readCounters, { ...prior.readCounters, snapshot: prior.readCounters.snapshot + 1 });
  assert.deepEqual(JSON.parse(await readFile(statePath, "utf8")), after.body.result);
});

test("fake-service state limit seam is bounded by the production cap", () => {
  for (const maxStateBytes of [1_023, 128 * 1024 + 1, "4096"]) {
    assert.throws(() => createFakeBilateralClockchainService({ statePath: "/private/state.json", listenPath: "/private/listen.json", dependencies: { maxStateBytes } }));
  }
});

test("fake-service operation ceiling is explicit and remains bounded", async (t) => {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), "fake-clockchain-operation-limit-")));
  const service = await startFakeBilateralClockchainService({
    statePath: path.join(directory, "state.json"),
    listenPath: path.join(directory, "listen.json"),
    dependencies: { maxOperations: 2 },
  });
  t.after(() => service.close());

  assert.equal((await request(service.listen, { method: "snapshot", params: {} })).statusCode, 200);
  assert.equal((await request(service.listen, { method: "snapshot", params: {} })).statusCode, 200);
  assert.deepEqual(
    await request(service.listen, { method: "snapshot", params: {} }),
    { statusCode: 400, body: { ok: false, error: "request rejected" } },
  );

  for (const maxOperations of [0, 1_025, "512"]) {
    assert.throws(() => createFakeBilateralClockchainService({
      statePath: "/private/state.json",
      listenPath: "/private/listen.json",
      dependencies: { maxOperations },
    }));
  }
});

test("post-mutation persistence failure poisons the service before a rejected anchor can be observed", async (t) => {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), "fake-clockchain-poison-")));
  const statePath = path.join(directory, "state.json"); let failed = false;
  const service = await startFakeBilateralClockchainService({
    statePath, listenPath: path.join(directory, "listen.json"),
    dependencies: { raceHooks: { async afterTemporaryWrite({ parent }) { if (parent.target === statePath && !failed) { failed = true; throw new Error("persistence failed"); } } } },
  });
  t.after(() => service.close());
  const action = { allow_degraded: true, asset_hash: "a".repeat(64), asset_reference_id: "m1", hash_type: "SHA-256", idempotency_key: "b".repeat(32), version_number: 1, wait: true, wait_ms: 20_000 };
  assert.deepEqual(await request(service.listen, { method: "logAction", params: action }), { statusCode: 400, body: { ok: false, error: "request rejected" } });
  assert.equal(failed, true);
  assert.deepEqual(await request(service.listen, { method: "searchActions", params: { asset_reference_id: "m1" } }), { statusCode: 400, body: { ok: false, error: "request rejected" } });
  assert.deepEqual(await request(service.listen, { method: "snapshot", params: {} }), { statusCode: 400, body: { ok: false, error: "request rejected" } });
  await assert.rejects(readFile(statePath), /ENOENT/);
  await Promise.race([service.close(), new Promise((_resolve, reject) => setTimeout(() => reject(new Error("poisoned close timed out")), 500))]);
});

test("private state writes reject deterministic substitutions at every atomic boundary", async (t) => {
  const scenarios = [
    {
      name: "temporary path before rename",
      hook: "afterTemporaryWrite",
      async replace({ temporary }) {
        await unlink(temporary);
        await writeFile(temporary, "attacker\n", { mode: 0o600 });
      },
      state: null,
    },
    {
      name: "target during write",
      hook: "afterTemporaryWrite",
      async replace({ parent }) {
        await writeFile(parent.target, "attacker\n", { mode: 0o600 });
      },
      state: "attacker\n",
    },
    {
      name: "installed target before readback",
      hook: "afterInstalledBeforeReadback",
      async replace({ parent }) {
        await unlink(parent.target);
        await writeFile(parent.target, "attacker\n", { mode: 0o600 });
      },
      state: "attacker\n",
    },
  ];
  for (const scenario of scenarios) {
    const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), "fake-clockchain-race-")));
    const statePath = path.join(directory, "state.json");
    const listenPath = path.join(directory, "listen.json");
    let fired = false;
    const service = createFakeBilateralClockchainService({
      statePath,
      listenPath,
      dependencies: {
        raceHooks: {
          async [scenario.hook](details) {
            if (details.parent.target !== statePath || fired) return;
            fired = true;
            await scenario.replace(details);
          },
        },
      },
    });
    await service.start();
    t.after(() => service.close());
    const listen = JSON.parse(await readFile(listenPath, "utf8"));
    const response = await request(listen, { method: "snapshot", params: {} });
    assert.equal(fired, true, scenario.name);
    assert.deepEqual(response, { statusCode: 400, body: { ok: false, error: "request rejected" } }, scenario.name);
    if (scenario.state === null) await assert.rejects(readFile(statePath), /ENOENT/, scenario.name);
    else assert.equal(await readFile(statePath, "utf8"), scenario.state, scenario.name);
  }
});

test("existing private state read rejects replacement between lstat and nofollow open", async () => {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), "fake-clockchain-state-read-race-")));
  const statePath = path.join(directory, "state.json");
  const listenPath = path.join(directory, "listen.json");
  await writeFile(statePath, "", { mode: 0o600 });
  const service = createFakeBilateralClockchainService({
    statePath,
    listenPath,
    dependencies: {
      raceHooks: {
        async beforeExistingStateOpen({ target }) {
          await rename(target, `${target}.old`);
          await writeFile(target, "attacker\n", { mode: 0o600 });
        },
      },
    },
  });
  await assert.rejects(service.start(), /private target readback changed/);
});
