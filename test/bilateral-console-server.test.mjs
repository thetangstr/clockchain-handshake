import assert from "node:assert/strict";
import { chmod, mkdtemp, readFile, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createConsoleServer, createStateRootProjection } from "../src/bilateral/coordination/console-server.mjs";
import { parseConsoleArguments, readConsoleTlsInput } from "../bin/handshake-console.mjs";

const digest = (value) => value.repeat(64);

test("console serves only fixed read-only no-store routes on loopback", async (t) => {
  const app = createConsoleServer({ projection: () => ({ paymentMoved: false }) });
  await new Promise((resolve) => app.listen(0, "127.0.0.1", resolve));
  t.after(() => app.close());
  const port = app.address().port;
  const home = await fetch(`http://127.0.0.1:${port}/`);
  assert.equal(home.status, 200); assert.equal(home.headers.get("cache-control"), "no-store");
  assert.match(home.headers.get("content-security-policy"), /default-src 'none'/);
  assert.equal((await fetch(`http://127.0.0.1:${port}/../package.json`)).status, 404);
  for (const method of ["HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]) {
    const response = await fetch(`http://127.0.0.1:${port}/v1/console/session`, { method });
    assert.equal(response.status, 405, method);
    assert.equal(response.headers.get("allow"), "GET", method);
    assert.equal(response.headers.get("cache-control"), "no-store", method);
  }
  assert.deepEqual(await (await fetch(`http://127.0.0.1:${port}/v1/console/session`)).json(), { paymentMoved: false });
});

test("console UI renders structured public fields with textContent only", async () => {
  const [index, app] = await Promise.all([
    readFile(new URL("../src/bilateral/coordination/console/index.html", import.meta.url), "utf8"),
    readFile(new URL("../src/bilateral/coordination/console/app.js", import.meta.url), "utf8"),
  ]);

  for (const id of [
    "operator-health",
    "payer-health",
    "requestor-health",
    "request-status",
    "mandate-status",
    "anchor-timeline",
    "deadline-freshness",
    "failure-recovery",
    "relay-advisory",
    "watcher-advisory",
    "verifier-state",
  ]) {
    assert.match(index, new RegExp(`id="${id}"`), id);
  }
  assert.match(app, /\.textContent\s*=/);
  assert.doesNotMatch(app, /\binnerHTML\b|\blocalStorage\b|\bsessionStorage\b|document\.cookie|JSON\.stringify/);
});

test("console CLI requires state root and LAN acknowledgement with TLS files", () => {
  assert.deepEqual(parseConsoleArguments(["--state-root", "/private/state"]), { allowLan: false, host: "127.0.0.1", port: 8787, stateRoot: "/private/state", tlsCertificate: null, tlsKey: null });
  for (const args of [["--host", "0.0.0.0", "--state-root", "/private/state"], ["--allow-lan", "--host", "0.0.0.0", "--state-root", "/private/state"], ["--state-root", "/private/state", "--token", "no"]]) assert.throws(() => parseConsoleArguments(args));
});

test("console CLI accepts only canonical decimal ports", () => {
  assert.equal(parseConsoleArguments(["--state-root", "/private/state", "--port", "1"]).port, 1);
  assert.equal(parseConsoleArguments(["--state-root", "/private/state", "--port", "65535"]).port, 65535);
  for (const port of [
    "0",
    "65536",
    "01",
    "1.5",
    "1e3",
    "0x50",
    "+1",
    "-1",
    " 1",
    "1 ",
  ]) {
    assert.throws(
      () => parseConsoleArguments(["--state-root", "/private/state", "--port", port]),
      /Console arguments failed safely/,
      port,
    );
  }
});

test("state-root projection re-reads bounded canonical state on every request", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "console-state-")); await chmod(root, 0o700); t.after(() => import("node:fs/promises").then(({ rm }) => rm(root, { recursive: true, force: true })));
  const file = join(root, "console-state.json"); const state = (phase) => ({ lifecycleView: { releaseId: "release-a", repositorySha: "a".repeat(40), sessionId: "11111111-2222-4333-8444-555555555555", state: phase }, mandate: {}, nowMs: 0, request: {}, verifierPublication: null, watcherSnapshot: {} });
  await writeFile(file, `${JSON.stringify(state("REHEARSAL_RUNNING"))}\n`, { mode: 0o600 });
  const projection = createStateRootProjection({ now: () => 2, stateRoot: root });
  assert.equal(projection().phase.value, "REHEARSAL_RUNNING");
  await writeFile(file, `${JSON.stringify(state("STAKEHOLDER_RUNNING"))}\n`, { mode: 0o600 });
  assert.equal(projection().phase.value, "STAKEHOLDER_RUNNING");
  await writeFile(file, '{"token":"canary"}\n', { mode: 0o600 });
  assert.throws(projection);
});

test("state-root projection permits exact nested lifecycle health without widening top-level keys", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "console-state-health-")); await chmod(root, 0o700); t.after(() => import("node:fs/promises").then(({ rm }) => rm(root, { recursive: true, force: true })));
  const file = join(root, "console-state.json");
  await writeFile(
    file,
    `${JSON.stringify({ lifecycleView: { health: { schema: "clockchain.bilateral-console-health/v1", observedAtMs: "1", expiresAtMs: "3", actors: { operator: "READY", payer: "WAITING", payee: "UNAVAILABLE" }, services: { relay: "READY", watcher: "WAITING" } } }, mandate: {}, nowMs: 2, request: {}, verifierPublication: null, watcherSnapshot: {} })}\n`,
    { mode: 0o600 },
  );
  const projection = createStateRootProjection({ now: () => 2, stateRoot: root });
  assert.equal(projection().actors.operator.health, "READY");
});

test("state-root projection recomputes freshness from server time", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "console-state-clock-")); await chmod(root, 0o700); t.after(() => import("node:fs/promises").then(({ rm }) => rm(root, { recursive: true, force: true })));
  const file = join(root, "console-state.json");
  await writeFile(
    file,
    `${JSON.stringify({
      lifecycleView: { releaseId: "release-a", repositorySha: "a".repeat(40), sessionId: "11111111-2222-4333-8444-555555555555", state: "STAKEHOLDER_RUNNING", facts: { payerMandateReady: { stakeholder: true }, paymentRequestReady: { stakeholder: true }, paymentRequestMatched: { stakeholder: true } } },
      mandate: { mandate: { amount: { currency: "USD", value: "100" }, expiresAtMs: "1785297600000", paymentMoved: false }, mandateDigest: digest("e") },
      nowMs: 1785294300000,
      request: { request: { amount: { currency: "USD", value: "100" }, expiresAtMs: "1785297000000", paymentMoved: false }, requestDigest: digest("f") },
      verifierPublication: { markerComplete: true, paymentMoved: false, publicationDigest: digest("a"), releaseId: "release-a", repositorySha: "a".repeat(40), schema: "clockchain.bilateral-verifier-publication/v1", sessionId: "11111111-2222-4333-8444-555555555555", status: "VERIFICATION_PASSED", subjectRun: "stakeholder", descriptorDigest: digest("d"), mandateDigest: digest("e"), requestDigest: digest("f"), packageDigests: { payer: digest("b"), payee: digest("c") }, anchorDigests: [digest("1"), digest("2"), digest("3")] },
      watcherSnapshot: { descriptorDigest: digest("d"), packageDigests: { payer: digest("b"), payee: digest("c") }, anchors: [
        { digest: digest("1"), kind: "PROPOSED", block: "10", verified: true },
        { digest: digest("2"), kind: "ACCEPTED", block: "11", verified: true },
        { digest: digest("3"), kind: "ACKNOWLEDGED", block: "12", verified: true },
      ] },
    })}\n`,
    { mode: 0o600 },
  );
  const projection = createStateRootProjection({ now: () => 1785298000000, stateRoot: root });
  const value = projection();
  assert.equal(value.deadline.freshness, "EXPIRED");
  assert.equal(value.verifier.status, "PENDING");
});

test("state-root projection rejects unsafe or nonmonotonic server clocks", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "console-state-nonmonotonic-clock-")); await chmod(root, 0o700); t.after(() => import("node:fs/promises").then(({ rm }) => rm(root, { recursive: true, force: true })));
  const file = join(root, "console-state.json");
  await writeFile(
    file,
    `${JSON.stringify({ lifecycleView: {}, mandate: {}, nowMs: 0, request: {}, verifierPublication: null, watcherSnapshot: {} })}\n`,
    { mode: 0o600 },
  );
  const times = [2, 1];
  const projection = createStateRootProjection({ now: () => times.shift(), stateRoot: root });
  assert.equal(projection().deadline.nowMs, 2);
  assert.throws(projection);
  assert.throws(() => createStateRootProjection({ now: () => 1.5, stateRoot: root })());
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
