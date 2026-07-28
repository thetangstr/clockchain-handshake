import assert from "node:assert/strict";
import { chmod, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createConsoleServer, createStateRootProjection } from "../src/bilateral/coordination/console-server.mjs";
import { parseConsoleArguments } from "../bin/handshake-console.mjs";

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
  await writeFile(file, `${JSON.stringify(state("ONE"))}\n`, { mode: 0o600 });
  const projection = createStateRootProjection({ stateRoot: root });
  assert.equal(projection().phase.value, "ONE");
  await writeFile(file, `${JSON.stringify(state("TWO"))}\n`, { mode: 0o600 });
  assert.equal(projection().phase.value, "TWO");
  await writeFile(file, '{"token":"canary"}\n', { mode: 0o600 });
  assert.throws(projection);
});
