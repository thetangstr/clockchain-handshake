import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { test } from "node:test";

import {
  DEFAULT_CLIENT_COMMANDS,
  runCleanClients,
} from "../scripts/run-clean-clients.mjs";
import {
  expectedReceiptHash,
  verifyLiveResults,
} from "../scripts/verify-live-results.mjs";
import {
  REGISTRY_ADDRESS,
  SINGLE_VALIDATOR_DISCLAIMER,
} from "../src/constants.mjs";
import {
  renderResultMarkdown,
} from "../src/evidence.mjs";

const PROMPT = Buffer.from(
  "Run this exact Handshake prompt.\nSecond line stays byte-identical.\n",
  "utf8",
);
const REPOSITORY_URL =
  "https://github.com/example/clockchain-handshake.git";
const REPOSITORY_REF = "feature/turnkey";
const CODEX_INVITE = "/private/codex.secret.json";
const CLAUDE_INVITE = "/private/claude.secret.json";
const REGISTER_TX_A = `0x${"a".repeat(64)}`;
const METADATA_TX_A = `0x${"b".repeat(64)}`;
const REGISTER_TX_B = `0x${"c".repeat(64)}`;
const METADATA_TX_B = `0x${"d".repeat(64)}`;
const OWNER_A = "0x1111111111111111111111111111111111111111";
const OWNER_B = "0x2222222222222222222222222222222222222222";
const LEDGER_A = "11111111-1111-4111-8111-111111111111";
const LEDGER_B = "22222222-2222-4222-8222-222222222222";
const RUN_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const RUN_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const CODEX_AUTH_CANARY = "openai-auth-canary-value";
const CLAUDE_AUTH_CANARY = "anthropic-auth-canary-value";

function passResult({
  agentId,
  blockHeight,
  displayName,
  ledgerId,
  metadataTx,
  owner,
  registerTx,
  runId,
}) {
  return {
    schema: "clockchain.handshake-result/v1",
    status: "PASS",
    runId,
    startedAt: "2026-07-23T08:00:00.000Z",
    completedAt: "2026-07-23T08:00:01.234Z",
    elapsedMs: 1234,
    scenario: {
      action: "trust_handshake",
      amount: {
        value: "100",
        currency: "USD",
        moved: false,
      },
      counterparty: "clockchain:handshake",
    },
    identity: {
      reference:
        `eip155:11155111:${REGISTRY_ADDRESS}:${agentId}`,
      agentId,
      displayName,
      owner,
      registerTx,
      metadataTx,
    },
    clockchain: {
      ledgerId,
      blockHeight,
      consensusTime: "2026-07-23T08:00:01.000Z",
      receiptStatus: "anchored",
      receiptVerified: true,
      crossPartyVerified: true,
      verifiedAgainst: "on-chain block",
      keyless: true,
      poolHealth: {
        totalNodes: 1,
        nodeParticipationPct: 0,
        degradedAtSubmission: true,
      },
    },
    disclaimer: SINGLE_VALIDATOR_DISCLAIMER,
  };
}

const CODEX_RESULT = passResult({
  agentId: "101",
  blockHeight: "9001",
  displayName: "Billy",
  ledgerId: LEDGER_A,
  metadataTx: METADATA_TX_A,
  owner: OWNER_A,
  registerTx: REGISTER_TX_A,
  runId: RUN_A,
});
const CLAUDE_RESULT = passResult({
  agentId: "102",
  blockHeight: "9002",
  displayName: "Iris",
  ledgerId: LEDGER_B,
  metadataTx: METADATA_TX_B,
  owner: OWNER_B,
  registerTx: REGISTER_TX_B,
  runId: RUN_B,
});

async function writeFixture(directory, result) {
  await mkdir(directory, { recursive: true });
  const jsonPath = join(directory, "result.json");
  const markdownPath = join(directory, "RESULT.md");
  await writeFile(
    jsonPath,
    `${JSON.stringify(result, null, 2)}\n`,
    { mode: 0o600 },
  );
  await writeFile(
    markdownPath,
    renderResultMarkdown(result),
    { mode: 0o600 },
  );
  return { jsonPath, markdownPath };
}

async function writePrompt(directory) {
  const promptPath = join(directory, "prompt.md");
  await writeFile(promptPath, PROMPT, { mode: 0o600 });
  return promptPath;
}

async function writeFakeClient(directory) {
  const executable = join(directory, "fake-client.mjs");
  await writeFile(
    executable,
    `#!/usr/bin/env node
import { spawn } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

if (process.argv.includes("--version")) {
  process.stdout.write("fake-client 1.2.3\\n");
  process.exit(0);
}

const [mode, jsonFixture, markdownFixture, marker] =
  process.argv.slice(2);
if (mode === "hang") {
  spawn(process.execPath, [
    "-e",
    "setTimeout(() => require('node:fs').writeFileSync(" +
      JSON.stringify(marker) + ", 'escaped'), 650)",
  ], { stdio: "ignore" });
  process.on("SIGTERM", () => {});
  setInterval(() => {}, 10_000);
} else {
  let input = "";
  process.stdin.setEncoding("utf8");
  for await (const chunk of process.stdin) input += chunk;
  writeFileSync(
    join(process.cwd(), "capture.json"),
    JSON.stringify({
      args: process.argv.slice(2),
      cwd: process.cwd(),
      env: process.env,
      promptBase64: Buffer.from(input, "utf8").toString("base64"),
    }),
  );
  const runDirectory = join(process.env.TMPDIR, "agent-run");
  mkdirSync(runDirectory, { recursive: true });
  writeFileSync(
    join(runDirectory, "result.json"),
    readFileSync(jsonFixture),
  );
  writeFileSync(
    join(runDirectory, "RESULT.md"),
    readFileSync(markdownFixture),
  );
  process.stdout.write(
    "invite=" + process.env.HANDSHAKE_INVITE_FILE +
      " openai=" + (process.env.OPENAI_API_KEY ?? "") +
      " anthropic=" + (process.env.ANTHROPIC_API_KEY ?? "") +
      " Bearer cc_abcdefghijklmnopqrstuvwxyz123456\\n",
  );
  process.stderr.write(
    "wallet private key: 0x" + "9".repeat(64) + "\\n",
  );
  process.exit(mode === "fail" ? 7 : 0);
}
`,
    { mode: 0o700 },
  );
  await chmod(executable, 0o700);
  return executable;
}

function harnessOptions({
  directory,
  executable,
  codexFixture,
  claudeFixture,
  codexMode = "pass",
  claudeMode = "pass",
  timeoutMs = 3_000,
  terminationGraceMs = 100,
  marker,
}) {
  return {
    baseEnvironment: {
      PATH: process.env.PATH,
      HOME: process.env.HOME,
      TMPDIR: process.env.TMPDIR,
      LANG: "en_US.UTF-8",
      OPENAI_API_KEY: CODEX_AUTH_CANARY,
      ANTHROPIC_API_KEY: CLAUDE_AUTH_CANARY,
      HANDSHAKE_CODEX_INVITE_FILE: "must-not-leak",
      HANDSHAKE_CLAUDE_INVITE_FILE: "must-not-leak",
      UNRELATED_SECRET: "unrelated-environment-value",
    },
    commands: {
      codex: {
        executable,
        args: [
          codexMode,
          codexFixture.jsonPath,
          codexFixture.markdownPath,
          marker ?? "",
        ],
        versionArgs: ["--version"],
      },
      claude: {
        executable,
        args: [
          claudeMode,
          claudeFixture.jsonPath,
          claudeFixture.markdownPath,
          marker ?? "",
        ],
        versionArgs: ["--version"],
      },
    },
    invitations: {
      codex: CODEX_INVITE,
      claude: CLAUDE_INVITE,
    },
    outputRoot: join(directory, "artifacts"),
    promptFile: join(directory, "prompt.md"),
    repositoryRef: REPOSITORY_REF,
    repositoryUrl: REPOSITORY_URL,
    terminationGraceMs,
    timeoutMs,
  };
}

test("defines the exact native Codex and Claude clean-client commands", () => {
  assert.deepEqual(DEFAULT_CLIENT_COMMANDS, {
    codex: {
      executable: "codex",
      args: [
        "exec",
        "--ephemeral",
        "--skip-git-repo-check",
        "--dangerously-bypass-approvals-and-sandbox",
        "-",
      ],
      versionArgs: ["--version"],
    },
    claude: {
      executable: "claude",
      args: [
        "-p",
        "--no-session-persistence",
        "--permission-mode",
        "bypassPermissions",
        "--dangerously-skip-permissions",
      ],
      versionArgs: ["--version"],
    },
  });
});

test("matches the deployed Clockchain canonical event-hash contract", () => {
  assert.equal(
    expectedReceiptHash(CODEX_RESULT),
    "530a1aee7571994b98ba89fedbe011e2279627677d8d1ecfa67b8a9a10a30858",
  );
});

test("runs clean clients sequentially with identical prompts and isolated minimal environments", async (t) => {
  const directory = await mkdtemp(
    join(process.env.TMPDIR, "handshake-harness-"),
  );
  t.after(() =>
    rm(directory, { force: true, recursive: true }));
  const promptPath = await writePrompt(directory);
  assert.equal(promptPath, join(directory, "prompt.md"));
  const executable = await writeFakeClient(directory);
  const codexFixture = await writeFixture(
    join(directory, "fixtures", "codex"),
    CODEX_RESULT,
  );
  const claudeFixture = await writeFixture(
    join(directory, "fixtures", "claude"),
    CLAUDE_RESULT,
  );

  const result = await runCleanClients(
    harnessOptions({
      claudeFixture,
      codexFixture,
      directory,
      executable,
    }),
  );

  assert.equal(result.status, "PASS");
  assert.equal(
    result.promptSha256,
    createHash("sha256").update(PROMPT).digest("hex"),
  );
  const codexCapture = JSON.parse(
    await readFile(
      join(result.clients.codex.workDirectory, "capture.json"),
      "utf8",
    ),
  );
  const claudeCapture = JSON.parse(
    await readFile(
      join(result.clients.claude.workDirectory, "capture.json"),
      "utf8",
    ),
  );
  assert.notEqual(codexCapture.cwd, claudeCapture.cwd);
  assert.equal(
    Buffer.from(codexCapture.promptBase64, "base64").equals(PROMPT),
    true,
  );
  assert.equal(
    Buffer.from(claudeCapture.promptBase64, "base64").equals(PROMPT),
    true,
  );
  assert.equal(
    codexCapture.env.HANDSHAKE_INVITE_FILE,
    CODEX_INVITE,
  );
  assert.equal(
    claudeCapture.env.HANDSHAKE_INVITE_FILE,
    CLAUDE_INVITE,
  );
  assert.equal(codexCapture.env.OPENAI_API_KEY, CODEX_AUTH_CANARY);
  assert.equal(
    Object.hasOwn(codexCapture.env, "ANTHROPIC_API_KEY"),
    false,
  );
  assert.equal(
    claudeCapture.env.ANTHROPIC_API_KEY,
    CLAUDE_AUTH_CANARY,
  );
  assert.equal(
    Object.hasOwn(claudeCapture.env, "OPENAI_API_KEY"),
    false,
  );
  for (const capture of [codexCapture, claudeCapture]) {
    assert.equal(capture.env.HANDSHAKE_REPO_URL, REPOSITORY_URL);
    assert.equal(capture.env.HANDSHAKE_REPO_REF, REPOSITORY_REF);
    assert.equal(
      Object.hasOwn(capture.env, "HANDSHAKE_CODEX_INVITE_FILE"),
      false,
    );
    assert.equal(
      Object.hasOwn(capture.env, "HANDSHAKE_CLAUDE_INVITE_FILE"),
      false,
    );
    assert.equal(
      Object.hasOwn(capture.env, "UNRELATED_SECRET"),
      false,
    );
  }
  assert.equal(result.clients.codex.cliVersion, "fake-client 1.2.3");
  assert.equal(result.clients.claude.cliVersion, "fake-client 1.2.3");
  assert.match(result.clients.codex.resultPaths.json, /codex\/result\.json$/);
  assert.match(
    result.clients.claude.resultPaths.markdown,
    /claude\/RESULT\.md$/,
  );
  const manifest = await readFile(result.manifestPath, "utf8");
  for (const forbidden of [
    CODEX_INVITE,
    CLAUDE_INVITE,
    CODEX_AUTH_CANARY,
    CLAUDE_AUTH_CANARY,
  ]) {
    assert.equal(manifest.includes(forbidden), false);
  }

  for (const client of ["codex", "claude"]) {
    const stdout = await readFile(
      result.clients[client].stdoutLog,
      "utf8",
    );
    const stderr = await readFile(
      result.clients[client].stderrLog,
      "utf8",
    );
    assert.equal(stdout.includes(CODEX_INVITE), false);
    assert.equal(stdout.includes(CLAUDE_INVITE), false);
    assert.equal(stdout.includes(CODEX_AUTH_CANARY), false);
    assert.equal(stdout.includes(CLAUDE_AUTH_CANARY), false);
    assert.equal(stdout.includes("cc_abcdefghijklmnopqrstuvwxyz123456"), false);
    assert.equal(stderr.includes(`0x${"9".repeat(64)}`), false);
    assert.match(`${stdout}${stderr}`, /\[REDACTED\]/);
  }
});

test("rejects a shared invitation path before launching either client", async (t) => {
  const directory = await mkdtemp(
    join(process.env.TMPDIR, "handshake-shared-invite-"),
  );
  t.after(() =>
    rm(directory, { force: true, recursive: true }));
  await writePrompt(directory);
  const executable = await writeFakeClient(directory);
  const codexFixture = await writeFixture(
    join(directory, "fixtures", "codex"),
    CODEX_RESULT,
  );
  const claudeFixture = await writeFixture(
    join(directory, "fixtures", "claude"),
    CLAUDE_RESULT,
  );
  const options = harnessOptions({
    claudeFixture,
    codexFixture,
    directory,
    executable,
  });
  options.invitations.claude = options.invitations.codex;

  await assert.rejects(
    runCleanClients(options),
    /configuration/i,
  );
  await assert.rejects(
    readFile(join(options.outputRoot, "codex", "stdout.log")),
    /ENOENT/,
  );
});

test("terminates a timed-out client process group and fails the aggregate verdict", async (t) => {
  const directory = await mkdtemp(
    join(process.env.TMPDIR, "handshake-timeout-"),
  );
  t.after(() => rm(directory, { force: true, recursive: true }));
  await writePrompt(directory);
  const executable = await writeFakeClient(directory);
  const codexFixture = await writeFixture(
    join(directory, "fixtures", "codex"),
    CODEX_RESULT,
  );
  const claudeFixture = await writeFixture(
    join(directory, "fixtures", "claude"),
    CLAUDE_RESULT,
  );
  const marker = join(directory, "escaped-grandchild.txt");

  const result = await runCleanClients(
    harnessOptions({
      claudeFixture,
      codexFixture,
      codexMode: "hang",
      directory,
      executable,
      marker,
      terminationGraceMs: 50,
      timeoutMs: 100,
    }),
  );
  await delay(800);

  assert.equal(result.status, "FAIL");
  assert.equal(result.clients.codex.timedOut, true);
  assert.equal(result.clients.claude.status, "PASS");
  await assert.rejects(readFile(marker), /ENOENT/);
});

test("a nonzero client exit fails the aggregate while the other isolated client still runs", async (t) => {
  const directory = await mkdtemp(
    join(process.env.TMPDIR, "handshake-failure-"),
  );
  t.after(() => rm(directory, { force: true, recursive: true }));
  await writePrompt(directory);
  const executable = await writeFakeClient(directory);
  const codexFixture = await writeFixture(
    join(directory, "fixtures", "codex"),
    CODEX_RESULT,
  );
  const claudeFixture = await writeFixture(
    join(directory, "fixtures", "claude"),
    CLAUDE_RESULT,
  );

  const result = await runCleanClients(
    harnessOptions({
      claudeFixture,
      claudeMode: "fail",
      codexFixture,
      directory,
      executable,
    }),
  );

  assert.equal(result.status, "FAIL");
  assert.equal(result.clients.codex.status, "PASS");
  assert.equal(result.clients.claude.status, "FAIL");
  assert.equal(result.clients.claude.exitCode, 7);
});

function fakePublicClient(results) {
  const calls = [];
  return {
    calls,
    async getChainId() {
      calls.push({ functionName: "getChainId" });
      return 11155111;
    },
    async getCode({ address }) {
      calls.push({ address, functionName: "getCode" });
      return "0x6000";
    },
    async readContract({ address, args, functionName }) {
      calls.push({ address, args, functionName });
      const result = results.find(
        ({ identity }) => identity.agentId === String(args[0]),
      );
      assert.ok(result);
      if (functionName === "ownerOf") {
        return result.identity.owner;
      }
      if (functionName === "getAgentWallet") {
        return result.identity.owner;
      }
      if (functionName === "tokenURI") {
        const document = {
          type: "https://eips.ethereum.org/EIPS/eip-8004#registration-v1",
          name: result.identity.displayName,
          description:
            "Ephemeral Clockchain Handshake testnet identity; registration does not establish capability or trust.",
          services: [],
          x402Support: false,
          active: true,
          registrations: [
            {
              agentRegistry:
                `eip155:11155111:${REGISTRY_ADDRESS}`,
              agentId: Number(result.identity.agentId),
            },
          ],
        };
        return `data:application/json;base64,${
          Buffer.from(JSON.stringify(document), "utf8").toString("base64")
        }`;
      }
      throw new Error(`Unexpected read ${functionName}`);
    },
  };
}

function fakeClockchain(results, observations) {
  return {
    async tokenIssuer(options) {
      observations.tokenSubjects.push(options.subject);
      return "cc_verifier_token_canary_1234567890";
    },
    clientFactory({ token }) {
      observations.factoryTokens.push(token);
      return {
        async verifyCrossParty(identifiers) {
          observations.crossParty.push(identifiers);
          const result = results.find(
            ({ clockchain }) =>
              clockchain.ledgerId === identifiers.ledgerId,
          );
          assert.ok(result);
          return {
            onChain: {
              verifiedAgainst: "on-chain block",
              keyless: true,
              ledgerId: identifiers.ledgerId,
              blockHeight: identifiers.blockHeight,
              anchoredHash: expectedReceiptHash(result),
              assetReferenceId:
                `${result.identity.agentId}:trust_handshake:1780000000000`,
            },
          };
        },
      };
    },
  };
}

test("independently verifies both identities and recomputed receipt hashes before writing PASS", async (t) => {
  const directory = await mkdtemp(
    join(process.env.TMPDIR, "handshake-verifier-"),
  );
  t.after(() => rm(directory, { force: true, recursive: true }));
  const codexDirectory = join(directory, "codex");
  const claudeDirectory = join(directory, "claude");
  await writeFixture(codexDirectory, CODEX_RESULT);
  await writeFixture(claudeDirectory, CLAUDE_RESULT);
  await writeFile(
    join(codexDirectory, "stdout.log"),
    "sanitized public progress\n",
  );
  const publicClient = fakePublicClient([
    CODEX_RESULT,
    CLAUDE_RESULT,
  ]);
  const observations = {
    crossParty: [],
    factoryTokens: [],
    tokenSubjects: [],
  };
  const clockchain = fakeClockchain(
    [CODEX_RESULT, CLAUDE_RESULT],
    observations,
  );
  const outputFile = join(directory, "acceptance-verdict.json");

  const verdict = await verifyLiveResults({
    clientFactory: clockchain.clientFactory,
    now: () => new Date("2026-07-23T09:00:00.000Z"),
    outputFile,
    publicClient,
    randomUUID: () => "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
    resultDirectories: {
      codex: codexDirectory,
      claude: claudeDirectory,
    },
    tokenIssuer: clockchain.tokenIssuer,
  });

  assert.equal(
    verdict.status,
    "PASS",
    JSON.stringify({
      verdict,
      observations,
      calls: publicClient.calls,
    }, (_key, value) =>
      typeof value === "bigint" ? value.toString() : value),
  );
  assert.equal(verdict.aggregate.distinctIdentities, true);
  assert.equal(verdict.aggregate.distinctLedgerIds, true);
  assert.equal(verdict.aggregate.distinctBlockHeights, true);
  assert.equal(observations.tokenSubjects.length, 1);
  assert.equal(observations.factoryTokens.length, 1);
  assert.deepEqual(observations.crossParty, [
    { ledgerId: LEDGER_A, blockHeight: "9001" },
    { ledgerId: LEDGER_B, blockHeight: "9002" },
  ]);
  const functions = publicClient.calls.map(({ functionName }) =>
    functionName);
  assert.deepEqual(
    functions.filter((name) =>
      ["ownerOf", "getAgentWallet", "tokenURI"].includes(name)),
    [
      "ownerOf",
      "getAgentWallet",
      "tokenURI",
      "ownerOf",
      "getAgentWallet",
      "tokenURI",
    ],
  );
  assert.equal(
    publicClient.calls
      .filter(({ address }) => address)
      .every(({ address }) => address === REGISTRY_ADDRESS),
    true,
  );
  const serialized = await readFile(outputFile, "utf8");
  assert.equal(
    serialized.includes("cc_verifier_token_canary_1234567890"),
    false,
  );
});

test("extracts secret canaries from operator files and fails closed without echoing them", async (t) => {
  const directory = await mkdtemp(
    join(process.env.TMPDIR, "handshake-verifier-fail-"),
  );
  t.after(() => rm(directory, { force: true, recursive: true }));
  const codexDirectory = join(directory, "codex");
  const claudeDirectory = join(directory, "claude");
  await writeFixture(codexDirectory, CODEX_RESULT);
  await writeFixture(claudeDirectory, CLAUDE_RESULT);
  const secretCanary = "invitation-code-canary-never-persist";
  const canaryFile = join(directory, "operator.secret.json");
  await writeFile(
    canaryFile,
    JSON.stringify({ code: secretCanary }),
    { mode: 0o600 },
  );
  await writeFile(
    join(codexDirectory, "stdout.log"),
    `accidental ${secretCanary}\n`,
  );
  const publicClient = fakePublicClient([
    CODEX_RESULT,
    CLAUDE_RESULT,
  ]);
  const observations = {
    crossParty: [],
    factoryTokens: [],
    tokenSubjects: [],
  };
  const clockchain = fakeClockchain(
    [CODEX_RESULT, CLAUDE_RESULT],
    observations,
  );
  const outputFile = join(directory, "acceptance-verdict.json");

  const verdict = await verifyLiveResults({
    canaryFiles: [canaryFile],
    clientFactory: clockchain.clientFactory,
    outputFile,
    publicClient,
    resultDirectories: {
      codex: codexDirectory,
      claude: claudeDirectory,
    },
    tokenIssuer: clockchain.tokenIssuer,
  });

  assert.equal(verdict.status, "FAIL");
  assert.equal(verdict.clients.codex.status, "FAIL");
  assert.equal(verdict.clients.claude.status, "PASS");
  const serialized = await readFile(outputFile, "utf8");
  assert.equal(serialized.includes(secretCanary), false);
  assert.equal(serialized.includes("cc_verifier_token"), false);
});

test("fails a client whose live ERC-8004 owner differs from its evidence", async (t) => {
  const directory = await mkdtemp(
    join(process.env.TMPDIR, "handshake-owner-mismatch-"),
  );
  t.after(() =>
    rm(directory, { force: true, recursive: true }));
  const codexDirectory = join(directory, "codex");
  const claudeDirectory = join(directory, "claude");
  await writeFixture(codexDirectory, CODEX_RESULT);
  await writeFixture(claudeDirectory, CLAUDE_RESULT);
  const publicClient = fakePublicClient([
    CODEX_RESULT,
    CLAUDE_RESULT,
  ]);
  const originalRead = publicClient.readContract;
  publicClient.readContract = async (options) => {
    if (
      options.functionName === "ownerOf" &&
      String(options.args[0]) === CODEX_RESULT.identity.agentId
    ) {
      return OWNER_B;
    }
    return originalRead.call(publicClient, options);
  };
  const observations = {
    crossParty: [],
    factoryTokens: [],
    tokenSubjects: [],
  };
  const clockchain = fakeClockchain(
    [CODEX_RESULT, CLAUDE_RESULT],
    observations,
  );

  const verdict = await verifyLiveResults({
    clientFactory: clockchain.clientFactory,
    outputFile: join(directory, "verdict.json"),
    publicClient,
    resultDirectories: {
      codex: codexDirectory,
      claude: claudeDirectory,
    },
    tokenIssuer: clockchain.tokenIssuer,
  });

  assert.equal(verdict.status, "FAIL");
  assert.equal(
    verdict.clients.codex.errorCode,
    "ERC8004_IDENTITY_MISMATCH",
  );
  assert.equal(verdict.clients.claude.status, "PASS");
});

test("rejects two otherwise verified runs that reuse one ERC-8004 identity", async (t) => {
  const directory = await mkdtemp(
    join(process.env.TMPDIR, "handshake-duplicate-identity-"),
  );
  t.after(() =>
    rm(directory, { force: true, recursive: true }));
  const codexDirectory = join(directory, "codex");
  const claudeDirectory = join(directory, "claude");
  const duplicateIdentity = structuredClone(CODEX_RESULT);
  duplicateIdentity.runId = RUN_B;
  duplicateIdentity.startedAt = "2026-07-23T08:01:00.000Z";
  duplicateIdentity.completedAt = "2026-07-23T08:01:01.234Z";
  duplicateIdentity.clockchain = structuredClone(
    CLAUDE_RESULT.clockchain,
  );
  await writeFixture(codexDirectory, CODEX_RESULT);
  await writeFixture(claudeDirectory, duplicateIdentity);
  const publicClient = fakePublicClient([
    CODEX_RESULT,
    duplicateIdentity,
  ]);
  const observations = {
    crossParty: [],
    factoryTokens: [],
    tokenSubjects: [],
  };
  const clockchain = fakeClockchain(
    [CODEX_RESULT, duplicateIdentity],
    observations,
  );

  const verdict = await verifyLiveResults({
    clientFactory: clockchain.clientFactory,
    outputFile: join(directory, "verdict.json"),
    publicClient,
    resultDirectories: {
      codex: codexDirectory,
      claude: claudeDirectory,
    },
    tokenIssuer: clockchain.tokenIssuer,
  });

  assert.equal(verdict.clients.codex.status, "PASS");
  assert.equal(verdict.clients.claude.status, "PASS");
  assert.equal(verdict.aggregate.distinctIdentities, false);
  assert.equal(verdict.aggregate.distinctLedgerIds, true);
  assert.equal(verdict.aggregate.distinctBlockHeights, true);
  assert.equal(verdict.status, "FAIL");
});
