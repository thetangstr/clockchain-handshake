import assert from "node:assert/strict";
import { chmod, mkdtemp, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createConsoleServer, createStateRootProjection } from "../src/bilateral/coordination/console-server.mjs";
import { parseConsoleArguments, readConsoleTlsInput } from "../bin/handshake-console.mjs";

test("console serves only fixed read-only no-store routes on loopback", async (t) => {
  const app = createConsoleServer({ projection: () => ({ paymentMoved: false }) });
  await new Promise((resolve) => app.listen(0, "127.0.0.1", resolve));
  t.after(() => app.close());
  const port = app.address().port;
  const home = await fetch(`http://127.0.0.1:${port}/`);
  assert.equal(home.status, 200); assert.equal(home.headers.get("cache-control"), "no-store");
  assert.match(home.headers.get("content-security-policy"), /default-src 'none'/);
  assert.equal((await fetch(`http://127.0.0.1:${port}/../package.json`)).status, 404);
  assert.equal((await fetch(`http://127.0.0.1:${port}/v1/console/session`, { method: "POST" })).status, 405);
  assert.deepEqual(await (await fetch(`http://127.0.0.1:${port}/v1/console/session`)).json(), { paymentMoved: false });
});

test("console CLI requires state root and LAN acknowledgement with TLS files", () => {
  assert.deepEqual(parseConsoleArguments(["--state-root", "/private/state"]), { allowLan: false, host: "127.0.0.1", port: 8787, stateRoot: "/private/state", tlsCertificate: null, tlsKey: null });
  for (const args of [["--host", "0.0.0.0", "--state-root", "/private/state"], ["--allow-lan", "--host", "0.0.0.0", "--state-root", "/private/state"], ["--state-root", "/private/state", "--token", "no"]]) assert.throws(() => parseConsoleArguments(args));
});

test("state-root projection re-reads bounded canonical state on every request", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "console-state-")); await chmod(root, 0o700); t.after(() => import("node:fs/promises").then(({ rm }) => rm(root, { recursive: true, force: true })));
  const file = join(root, "console-state.json"); const state = (phase) => ({ lifecycleView: { releaseId: "release-a", repositorySha: "a".repeat(40), sessionId: "11111111-2222-4333-8444-555555555555", state: phase }, mandate: {}, nowMs: 0, request: {}, verifierPublication: null, watcherSnapshot: {} });
  await writeFile(file, `${JSON.stringify(state("REHEARSAL_RUNNING"))}\n`, { mode: 0o600 });
  const projection = createStateRootProjection({ stateRoot: root });
  assert.equal(projection().phase.value, "REHEARSAL_RUNNING");
  await writeFile(file, `${JSON.stringify(state("STAKEHOLDER_RUNNING"))}\n`, { mode: 0o600 });
  assert.equal(projection().phase.value, "STAKEHOLDER_RUNNING");
  await writeFile(file, '{"token":"canary"}\n', { mode: 0o600 });
  assert.throws(projection);
});

test("state-root projection rejects a symlinked console-state file", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "console-state-symlink-"));
  await chmod(root, 0o700);
  t.after(() => import("node:fs/promises").then(({ rm }) => rm(root, { recursive: true, force: true })));
  const target = join(root, "target.json");
  const file = join(root, "console-state.json");
  await writeFile(target, `${JSON.stringify({ lifecycleView: {}, mandate: {}, nowMs: 0, request: {}, verifierPublication: null, watcherSnapshot: {} })}\n`, { mode: 0o600 });
  await symlink(target, file);
  const projection = createStateRootProjection({ stateRoot: root });
  assert.throws(projection);
});

test("console TLS inputs reject symlinks before reading bytes", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "console-tls-symlink-"));
  await chmod(root, 0o700);
  t.after(() => import("node:fs/promises").then(({ rm }) => rm(root, { recursive: true, force: true })));
  const target = join(root, "tls.pem");
  const link = join(root, "tls-link.pem");
  await writeFile(target, "not-a-real-cert\n", { mode: 0o600 });
  await symlink(target, link);
  assert.throws(() => readConsoleTlsInput(link));
});
