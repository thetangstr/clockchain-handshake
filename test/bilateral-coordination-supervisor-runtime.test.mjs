import assert from "node:assert/strict";
import { mkdtemp, readdir, stat } from "node:fs/promises";
import { mkdir } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { createGitInspector, createPrivateRoot, createPrivateSupervisorStateStore, createSupervisorLauncher, createVerifierPublicationVerifier, scanSupervisorCheckpointDirectories } from "../src/bilateral/coordination/supervisor-runtime.mjs";
import { verifyRepositoryState } from "../src/bilateral/coordination/supervisor-runtime.mjs";
import { ensureToken } from "../src/bilateral/coordination/supervisor-runtime.mjs";
import { ensureInvitations } from "../src/bilateral/coordination/supervisor-runtime.mjs";
import { writeFile } from "node:fs/promises";
import { unlink } from "node:fs/promises";
import { recoverMessageAddress } from "viem";
import { invitationProofPreimage } from "../src/bilateral/coordination/enrollment.mjs";
import { createProductionSepoliaRpc } from "../src/bilateral/coordination/supervisor-runtime.mjs";

test("creates private state and round-trips a canonical checkpoint", async () => {
  const root = await mkdtemp(join(tmpdir(), "supervisor-runtime-"));
  const dependencies = await createPrivateSupervisorStateStore({ stateRoot: root });
  await dependencies.writeState({ phase: "EMPTY", paymentMoved: false });
  assert.deepEqual(await dependencies.readState(), { paymentMoved: false, phase: "EMPTY" });
  assert.equal((await stat(root)).mode & 0o777, 0o700);
});

test("reads verifier publication through the context-bound client route", async () => {
  const verify = createVerifierPublicationVerifier();
  const context = { event: { artifactDigest: "a".repeat(64), kind: "VERIFICATION_PASSED", role: "operator", subjectRun: "rehearsal" }, releaseId: "release-a", repositorySha: "a".repeat(40), sessionId: "session-a" };
  let request;
  await assert.doesNotReject(verify(context, { async readVerifierPublication(value) {
    request = value;
    assert.deepEqual(value, { subjectRun: "rehearsal" });
    return { paymentMoved: false, publicationDigest: context.event.artifactDigest, releaseId: context.releaseId, repositorySha: context.repositorySha, schema: "clockchain.bilateral-verifier-publication/v1", sessionId: context.sessionId, status: "VERIFICATION_PASSED", subjectRun: "rehearsal" };
  } }));
  assert.deepEqual(request, { subjectRun: "rehearsal" });
});

test("rejects every stale supervisor temporary file and noncanonical checkpoints", async () => {
  const root = await mkdtemp(join(tmpdir(), "supervisor-runtime-"));
  for (const name of [
    ".supervisor-state-abandoned.tmp",
    ".retired-launch-manifest-abandoned.tmp",
    ".supervisor-artifact-abandoned.tmp",
    ".coordination-identity-abandoned.tmp",
  ]) {
    await writeFile(join(root, name), "stale", { mode: 0o600 });
    await assert.rejects(createPrivateSupervisorStateStore({ stateRoot: root }));
    await unlink(join(root, name));
  }
  const store = await createPrivateSupervisorStateStore({ stateRoot: root });
  await writeFile(join(root, "supervisor-state.json"), '{"phase":"EMPTY", "paymentMoved":false}\n', { mode: 0o600 });
  await assert.rejects(store.readState());
});

test("rejects supervisor artifact leftovers in every private artifact directory", async () => {
  const root = await mkdtemp(join(tmpdir(), "supervisor-runtime-"));
  for (const directory of [
    root,
    join(root, "preflight"),
    join(root, "rehearsal"),
    join(root, "stakeholder"),
    join(root, "rehearsal", "identity"),
    join(root, "stakeholder", "result"),
  ]) {
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const temporary = join(directory, ".supervisor-artifact-abandoned.tmp");
    await writeFile(temporary, "stale", { mode: 0o600 });
    await assert.rejects(createPrivateRoot(directory));
    await unlink(temporary);
    const pinned = await createPrivateRoot(directory);
    await pinned.handle.close();
  }
});

test("scans every checkpoint-derived private directory before a resumed client can exist", async () => {
  const root = await mkdtemp(join(tmpdir(), "supervisor-runtime-"));
  const rehearsal = join(root, "rehearsal"), stakeholder = join(root, "stakeholder");
  for (const directory of [join(root, "preflight"), rehearsal, stakeholder, join(rehearsal, "identity"), join(rehearsal, "result"), join(stakeholder, "identity"), join(stakeholder, "result")]) await mkdir(directory, { recursive: true, mode: 0o700 });
  const checkpoint = {
    stateRoot: root,
    preflight: { planPath: join(root, "preflight", "plan.json"), outputPath: join(root, "preflight", "report.json"), privateKeyPath: join(root, "preflight", "key.pem"), publicArtifactPath: join(root, "preflight", "public.json") },
    rehearsal: { descriptorPath: join(rehearsal, "descriptor.json"), identityDirectory: join(rehearsal, "identity"), resultDirectory: join(rehearsal, "result") },
    stakeholder: { descriptorPath: join(stakeholder, "descriptor.json"), identityDirectory: join(stakeholder, "identity"), resultDirectory: join(stakeholder, "result") },
  };
  await scanSupervisorCheckpointDirectories({ checkpoint, stateRoot: root });
  const stale = join(stakeholder, "result", ".supervisor-artifact-abandoned.tmp");
  await writeFile(stale, "stale", { mode: 0o600 });
  await assert.rejects(scanSupervisorCheckpointDirectories({ checkpoint, stateRoot: root }));
  await unlink(stale);
  await mkdir(join(rehearsal, "identity", "unexpected"), { mode: 0o700 });
  await assert.rejects(scanSupervisorCheckpointDirectories({ checkpoint, stateRoot: root }));
});

test("securely unlinks a launch manifest without retaining bootstrap capability in active state", async () => {
  const stateRoot = await mkdtemp(join(tmpdir(), "supervisor-state-"));
  const manifestRoot = await mkdtemp(join(tmpdir(), "supervisor-manifest-"));
  const manifestPath = join(manifestRoot, "launch-manifest.json");
  const rawManifest = `${JSON.stringify({ bootstrapCapability: "11".repeat(32) })}\n`;
  await writeFile(manifestPath, rawManifest, { mode: 0o600 });
  const store = await createPrivateSupervisorStateStore({ stateRoot });

  await store.retireLaunchManifest(manifestPath);
  await store.retireLaunchManifest(manifestPath);

  await assert.rejects(stat(manifestPath));
  assert.deepEqual(await readdir(stateRoot), []);
  await assert.rejects(store.retireLaunchManifest(join(stateRoot, "preflight", "launch-manifest.json")));
});

test("mints once then reuses the private token path", async () => {
  const root = await mkdtemp(join(tmpdir(), "supervisor-token-")); let calls = 0;
  const mint = async ({ tokenPath }) => { calls += 1; await writeFile(tokenPath, "token-value", { mode: 0o600 }); };
  await ensureToken({ role: "payer", repositorySha: "a".repeat(40), stateRoot: root, mint });
  await ensureToken({ role: "payer", repositorySha: "a".repeat(40), stateRoot: root, mint });
  assert.equal(calls, 1);
});

test("accepts only a clean exact repository probe", async () => {
  const sha = "a".repeat(40);
  await assert.doesNotReject(verifyRepositoryState({ repositorySha: sha, probe: async () => ({ head: sha, clean: true }) }));
  for (const probe of [async () => ({ head: "b".repeat(40), clean: true }), async () => ({ head: sha, clean: false })]) await assert.rejects(verifyRepositoryState({ repositorySha: sha, probe }));
});

test("builds the production Sepolia funding RPC seam without an injected RPC function", async () => {
  const calls = [];
  const rpc = createProductionSepoliaRpc({
    createClient({ chain, transport }) {
      assert.equal(chain.id, 11155111);
      assert.equal(typeof transport, "function");
      return {
        async getBalance(input) { calls.push(["balance", input]); return 5_000_000_000_000_000n; },
        async getTransactionCount(input) { calls.push(["nonce", input]); return 0n; },
      };
    },
  });
  assert.equal(await rpc({ method: "eth_getBalance", params: [`0x${"1".repeat(40)}`, "latest"] }), "0x11c37937e08000");
  assert.equal(await rpc({ method: "eth_getTransactionCount", params: [`0x${"1".repeat(40)}`, "latest"] }), "0x0");
  assert.deepEqual(calls, [["balance", { address: `0x${"1".repeat(40)}` }], ["nonce", { address: `0x${"1".repeat(40)}`, blockTag: "latest" }]]);
});

test("pins Git inspection to a clean frozen repository object despite poisoned environment", async () => {
  const root = await mkdtemp(join(tmpdir(), "supervisor-git-"));
  const git = (...arguments_) => execFileSync("/usr/bin/git", arguments_, { cwd: root, encoding: "utf8" });
  git("init"); git("config", "user.email", "test@example.invalid"); git("config", "user.name", "test");
  await mkdir(join(root, "docs", "operator-keys"), { recursive: true });
  const frozenKey = Buffer.alloc(32, 7).toString("base64");
  await writeFile(join(root, "docs", "operator-keys", "operator.pub"), `${frozenKey}\n`);
  git("add", "."); git("commit", "-m", "fixture");
  const sha = git("rev-parse", "HEAD").trim(); const inspector = createGitInspector(root);
  const originalGitDir = process.env.GIT_DIR, originalPath = process.env.PATH;
  process.env.GIT_DIR = "/not/a/repository"; process.env.PATH = "/not/a/bin";
  try {
    assert.deepEqual(await inspector.probe(), { clean: true, head: sha });
    assert.equal(await inspector.operatorKey(sha, "operator"), frozenKey);
    await writeFile(join(root, "docs", "operator-keys", "operator.pub"), `${Buffer.alloc(32, 8).toString("base64")}\n`);
    assert.equal(await inspector.operatorKey(sha, "operator"), frozenKey);
    await assert.rejects(inspector.operatorKey("b".repeat(40), "operator"));
    await assert.rejects(inspector.probe());
  } finally {
    if (originalGitDir === undefined) delete process.env.GIT_DIR; else process.env.GIT_DIR = originalGitDir;
    if (originalPath === undefined) delete process.env.PATH; else process.env.PATH = originalPath;
  }
});

test("creates invitation proofs once and rejects partial secrets", async () => {
  const root = await mkdtemp(join(tmpdir(), "supervisor-invitations-"));
  const input = { capabilityDigest: "1".repeat(64), releaseId: "release-a", repositorySha: "a".repeat(40), role: "payer", sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd", stateRoot: root };
  const proofs = await ensureInvitations(input);
  assert.equal(proofs.length, 2);
  assert.notEqual(proofs[0].address, proofs[1].address);
  for (const proof of proofs) assert.equal((await recoverMessageAddress({ message: { raw: invitationProofPreimage({ address: proof.address, capabilityDigest: input.capabilityDigest, releaseId: input.releaseId, repositorySha: input.repositorySha, role: input.role, run: proof.subjectRun, sessionId: input.sessionId }) }, signature: proof.signature })).toLowerCase(), proof.address);
  await assert.doesNotReject(ensureInvitations({ ...input, create: async () => { throw new Error("recreated"); } }));
  await unlink(proofs[0].secretPath);
  await assert.rejects(ensureInvitations(input));
});

test("rejects incomplete child argv before any process can be considered ready", async () => {
  const launcher = createSupervisorLauncher({ repositoryRoot: process.cwd() });
  await assert.rejects(launcher({ command: "scripts/probe-bilateral-rendezvous.mjs", args: [] }));
  await assert.rejects(launcher({ command: "sh", args: ["-c", "true"] }));
  await assert.rejects(launcher({ command: "bin/handshake-propose.mjs", args: ["--output", "relative"] }));
  await assert.rejects(launcher({ command: "bin/handshake-propose.mjs", args: ["--clockchain-token-file", "/token", "--descriptor", "/descriptor", "--invitation", "/invitation", "--output", "/result", "--i-understand-this-writes-to-clockchain", "extra"] }));
});

test("announces a role child only after its exact authenticated readiness line", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "supervisor-ready-"));
  await mkdir(join(root, "bin"));
  await writeFile(join(root, "package.json"), '{"type":"module"}\n');
  const script = join(root, "bin", "handshake-propose.mjs");
  t.after(() => unlink(script).catch(() => {}));
  await writeFile(script, [
    "import { closeSync, writeSync } from 'node:fs';",
    "const fd = Number.parseInt(process.env.CLOCKCHAIN_BILATERAL_ROLE_READY_FD, 10);",
    "writeSync(fd, `${JSON.stringify({ nonce: process.env.CLOCKCHAIN_BILATERAL_ROLE_READY_NONCE, role: 'payer', schema: process.env.CLOCKCHAIN_BILATERAL_ROLE_READY_SCHEMA })}\\n`);",
    "closeSync(fd);",
    "setTimeout(() => process.exit(0), 100);",
  ].join("\n"));
  const launcher = createSupervisorLauncher({ repositoryRoot: root });
  const result = await launcher({
    command: "bin/handshake-propose.mjs",
    args: ["--clockchain-token-file", "/token", "--descriptor", "/descriptor", "--invitation", "/invitation", "--output", "/result", "--i-understand-this-writes-to-clockchain"],
  });
  assert.equal(result.started, true);
  assert.deepEqual(await result.completion, { ambiguous: false, exitCode: 0 });
});

test("requires readiness EOF after the exact line and rejects a delayed duplicate", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "supervisor-ready-eof-"));
  await mkdir(join(root, "bin"));
  await writeFile(join(root, "package.json"), '{"type":"module"}\n');
  const script = join(root, "bin", "handshake-propose.mjs");
  t.after(() => unlink(script).catch(() => {}));
  const line = "`${JSON.stringify({ nonce: process.env.CLOCKCHAIN_BILATERAL_ROLE_READY_NONCE, role: 'payer', schema: process.env.CLOCKCHAIN_BILATERAL_ROLE_READY_SCHEMA })}\\n`";
  await writeFile(script, [
    "import { writeSync } from 'node:fs';",
    `const line = ${line};`,
    "writeSync(3, line);",
    "setTimeout(() => { writeSync(3, line); process.exit(0); }, 25);",
  ].join("\n"));
  const launcher = createSupervisorLauncher({ readinessDeadlineMs: 100, repositoryRoot: root });
  const args = ["--clockchain-token-file", "/token", "--descriptor", "/descriptor", "--invitation", "/invitation", "--output", "/result", "--i-understand-this-writes-to-clockchain"];
  await assert.rejects(launcher({ command: "bin/handshake-propose.mjs", args }));
});

test("passes only the sanitized environment plus readiness values to role children", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "supervisor-ready-env-"));
  const output = join(root, "environment.json");
  await mkdir(join(root, "bin"));
  await writeFile(join(root, "package.json"), '{"type":"module"}\n');
  const script = join(root, "bin", "handshake-propose.mjs");
  t.after(() => unlink(script).catch(() => {}));
  await writeFile(script, [
    "import { closeSync, writeFile, writeSync } from 'node:fs';",
    "writeFile(process.argv[process.argv.indexOf('--output') + 1], JSON.stringify(Object.keys(process.env).sort()), () => {});",
    "writeSync(3, `${JSON.stringify({ nonce: process.env.CLOCKCHAIN_BILATERAL_ROLE_READY_NONCE, role: 'payer', schema: process.env.CLOCKCHAIN_BILATERAL_ROLE_READY_SCHEMA })}\\n`);",
    "closeSync(3);",
    "setTimeout(() => process.exit(0), 20);",
  ].join("\n"));
  const launcher = createSupervisorLauncher({ repositoryRoot: root });
  const args = ["--clockchain-token-file", "/token", "--descriptor", "/descriptor", "--invitation", "/invitation", "--output", output, "--i-understand-this-writes-to-clockchain"];
  const result = await launcher({ command: "bin/handshake-propose.mjs", args });
  await result.completion;
  const keys = JSON.parse(await (await import("node:fs/promises")).readFile(output, "utf8"));
  assert.deepEqual(keys.filter((key) => key !== "__CF_USER_TEXT_ENCODING"), ["CLOCKCHAIN_BILATERAL_ROLE_READY_FD", "CLOCKCHAIN_BILATERAL_ROLE_READY_NONCE", "CLOCKCHAIN_BILATERAL_ROLE_READY_SCHEMA", "LANG", "LC_ALL", "PATH"]);
});

test("rejects malformed, wrong-role, and duplicate role readiness before start", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "supervisor-ready-"));
  await mkdir(join(root, "bin"));
  await writeFile(join(root, "package.json"), '{"type":"module"}\n');
  const script = join(root, "bin", "handshake-propose.mjs");
  const launcher = createSupervisorLauncher({ repositoryRoot: root });
  const args = ["--clockchain-token-file", "/token", "--descriptor", "/descriptor", "--invitation", "/invitation", "--output", "/result", "--i-understand-this-writes-to-clockchain"];
  for (const body of [
    "import { writeSync } from 'node:fs'; writeSync(3, 'not-json\\n');",
    "import { writeSync } from 'node:fs'; writeSync(3, `${JSON.stringify({ nonce: '0'.repeat(64), role: 'payer', schema: process.env.CLOCKCHAIN_BILATERAL_ROLE_READY_SCHEMA })}\\n`);",
    "import { writeSync } from 'node:fs'; writeSync(3, `${JSON.stringify({ nonce: process.env.CLOCKCHAIN_BILATERAL_ROLE_READY_NONCE, role: 'payee', schema: process.env.CLOCKCHAIN_BILATERAL_ROLE_READY_SCHEMA })}\\n`);",
    "import { writeSync } from 'node:fs'; const line = `${JSON.stringify({ nonce: process.env.CLOCKCHAIN_BILATERAL_ROLE_READY_NONCE, role: 'payer', schema: process.env.CLOCKCHAIN_BILATERAL_ROLE_READY_SCHEMA })}\\n`; writeSync(3, line + line);",
  ]) {
    await writeFile(script, body);
    await assert.rejects(launcher({ command: "bin/handshake-propose.mjs", args }));
  }
});
