import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { constants as fileSystemConstants } from "node:fs";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import {
  delimiter,
  dirname,
  join,
  relative,
  sep,
} from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { test } from "node:test";

import {
  encodeAbiParameters,
  encodeEventTopics,
  encodeFunctionData,
} from "viem";

import {
  BOUNDED_READ_FLAGS_FOR_TESTING,
  DEFAULT_CLIENT_COMMANDS,
  buildClientEnvironment,
  main as runClientsMain,
  readBoundedFileForTesting,
  runCleanClients,
} from "../scripts/run-clean-clients.mjs";
import * as cleanClientsHarness from "../scripts/run-clean-clients.mjs";
import {
  expectedReceiptHash,
  main as verifyResultsMain,
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
const REPOSITORY_REF = "A".repeat(40);
const CODEX_INVITE = "/private/codex.secret.json";
const CLAUDE_INVITE = "/private/claude.secret.json";
const CODEX_INVITE_CODE =
  "codex-invitation-code-canary-value";
const CLAUDE_INVITE_CODE =
  "claude-invitation-code-canary-value";
const CODEX_CIPHERTEXT =
  "codex-unlabeled-ciphertext-canary-value";
const CLAUDE_CIPHERTEXT =
  "claude-unlabeled-ciphertext-canary-value";
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

function memoryOutput() {
  let value = "";
  return {
    stream: {
      write(chunk) {
        value += String(chunk);
        return true;
      },
    },
    text() {
      return value;
    },
  };
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

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
  await Promise.all([
    writeFile(join(directory, "stdout.log"), "", {
      mode: 0o600,
    }),
    writeFile(join(directory, "stderr.log"), "", {
      mode: 0o600,
    }),
  ]);
  return { jsonPath, markdownPath };
}

async function writePrompt(directory) {
  const promptPath = join(directory, "prompt.md");
  await writeFile(promptPath, PROMPT, { mode: 0o600 });
  return promptPath;
}

async function writeFakeClient(directory) {
  const executables = {};
  for (const role of ["codex", "claude"]) {
    const executable = join(directory, `${role}-fake-client.mjs`);
    const version = role === "codex"
      ? "codex-cli 0.144.1"
      : "2.1.218 (Claude Code)";
    await writeFile(
      executable,
      `#!/usr/bin/env node
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

if (process.argv.includes("--version")) {
  process.stdout.write(${JSON.stringify(`${version}\n`)});
  process.exit(0);
}

const [
  mode,
  jsonFixture,
  markdownFixture,
  marker,
] =
  process.argv.slice(2);
const leakedCode = ${JSON.stringify(
  role === "codex"
    ? CODEX_INVITE_CODE
    : CLAUDE_INVITE_CODE,
)};
const leakedCiphertext = ${JSON.stringify(
  role === "codex"
    ? CODEX_CIPHERTEXT
    : CLAUDE_CIPHERTEXT,
)};
if (mode === "hang") {
  spawn(process.execPath, [
    "-e",
    "setTimeout(() => require('node:fs').writeFileSync(" +
      JSON.stringify(marker) + ", 'escaped'), 650)",
  ], { stdio: "ignore" });
  process.on("SIGTERM", () => {});
  setInterval(() => {}, 10_000);
} else if (mode === "leader-exits") {
  const descendant = spawn(process.execPath, [
    "-e",
    "process.on('SIGTERM', () => {});" +
      "process.stdout.write('ready');" +
      "setTimeout(() => require('node:fs').writeFileSync(" +
      JSON.stringify(marker) + ", 'escaped'), 650);" +
      "setInterval(() => {}, 10000)",
  ], { stdio: ["ignore", "pipe", "ignore"] });
  await once(descendant.stdout, "data");
  process.on("SIGTERM", () => process.exit(0));
  setInterval(() => {}, 10_000);
} else {
  let input = "";
  process.stdin.setEncoding("utf8");
  for await (const chunk of process.stdin) input += chunk;
  const runDirectory = mode === "bare-mktemp"
    ? spawnSync("mktemp", ["-d"], {
        encoding: "utf8",
      }).stdout.trim()
    : join(process.env.TMPDIR, "agent-run");
  writeFileSync(
    join(process.cwd(), "capture.json"),
    JSON.stringify({
      args: process.argv.slice(2),
      cwd: process.cwd(),
      env: process.env,
      promptBase64: Buffer.from(input, "utf8").toString("base64"),
      runDirectory,
    }),
  );
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
      " Bearer cc_abcdefghijklmnopqrstuvwxyz123456 " +
      leakedCode + " " +
      JSON.stringify({ code: leakedCiphertext }) + "\\n",
  );
  process.stderr.write(
    "diagnostic 0x" + "9".repeat(64) + "\\n",
  );
  if (
    mode === "lingering-success" ||
    mode === "lingering-success-inherited"
  ) {
    spawn(process.execPath, [
      "-e",
      "process.on('SIGTERM', () => {});" +
        "setTimeout(() => require('node:fs').writeFileSync(" +
        JSON.stringify(marker) + ", 'escaped'), 650);" +
        "setInterval(() => {}, 10000)",
    ], {
      stdio: mode === "lingering-success-inherited"
        ? ["ignore", "inherit", "inherit"]
        : "ignore",
    });
  }
  process.exit(mode === "fail" ? 7 : 0);
}
`,
      { mode: 0o700 },
    );
    await chmod(executable, 0o700);
    executables[role] = executable;
  }
  return executables;
}

async function writeMacLikeMktemp(directory) {
  const binDirectory = join(directory, "macos-bin");
  const macosTemporaryDirectory = join(
    directory,
    "macos-user-temp",
  );
  await mkdir(binDirectory, { mode: 0o700 });
  await mkdir(macosTemporaryDirectory, { mode: 0o700 });
  const executable = join(binDirectory, "mktemp");
  await writeFile(
    executable,
    `#!/usr/bin/env node
import { mkdtempSync } from "node:fs";
import { join } from "node:path";

const args = process.argv.slice(2);
const template = args.length === 1 && args[0] === "-d"
  ? join(
      ${JSON.stringify(macosTemporaryDirectory)},
      "tmp.XXXXXXXXXX",
    )
  : args.length === 2 && args[0] === "-d"
    ? args[1]
    : null;
if (template === null || !/X+$/.test(template)) {
  process.exit(64);
}
process.stdout.write(
  mkdtempSync(template.replace(/X+$/, "")) + "\\n",
);
`,
    { mode: 0o700 },
  );
  await chmod(executable, 0o700);
  return binDirectory;
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
        executable: executable.codex,
        args: [
          codexMode,
          codexFixture.jsonPath,
          codexFixture.markdownPath,
          marker ?? "",
        ],
        versionArgs: ["--version"],
      },
      claude: {
        executable: executable.claude,
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
    operatorRiskAcknowledged: true,
    outputRoot: join(directory, "artifacts"),
    promptFile: join(directory, "prompt.md"),
    readInvitation: async (path) => {
      if (path === CODEX_INVITE) {
        return {
          code: CODEX_INVITE_CODE,
          bundle: {
            crypto: { ciphertext: CODEX_CIPHERTEXT },
          },
        };
      }
      if (path === CLAUDE_INVITE) {
        return {
          code: CLAUDE_INVITE_CODE,
          bundle: {
            crypto: { ciphertext: CLAUDE_CIPHERTEXT },
          },
        };
      }
      throw new Error("unexpected invitation path");
    },
    repositoryRef: REPOSITORY_REF,
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
        "--ignore-user-config",
        "--ignore-rules",
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
        "--safe-mode",
      ],
      versionArgs: ["--version"],
    },
  });
});

test("requires and normalizes an immutable repository commit", () => {
  const base = {
    baseEnvironment: {
      PATH: "/usr/bin",
      HOME: "/tmp/home",
      HANDSHAKE_REPO_URL: "https://attacker.invalid/repo.git",
    },
    clientName: "codex",
    invitationFile: CODEX_INVITE,
    temporaryDirectory: "/tmp/handshake-client",
  };
  assert.throws(
    () => buildClientEnvironment(base),
    /configuration/i,
  );

  const commitEnvironment = buildClientEnvironment({
    ...base,
    repositoryRef: REPOSITORY_REF,
  });
  assert.equal(
    commitEnvironment.HANDSHAKE_REPO_REF,
    REPOSITORY_REF.toLowerCase(),
  );
  assert.equal(
    Object.hasOwn(commitEnvironment, "HANDSHAKE_REPO_URL"),
    false,
  );
  assert.throws(
    () =>
      buildClientEnvironment({
        ...base,
        repositoryRef: "feature/turnkey",
      }),
    /configuration/i,
  );
});

test("accepts the Node process environment for production client isolation", () => {
  const environment = buildClientEnvironment({
    baseEnvironment: process.env,
    clientName: "codex",
    invitationFile: CODEX_INVITE,
    repositoryRef: REPOSITORY_REF,
    temporaryDirectory: "/tmp/handshake-client",
  });

  assert.equal(environment.PATH, process.env.PATH);
  assert.equal(environment.HOME, process.env.HOME);
  for (const invalid of [null, [], "environment"]) {
    assert.throws(
      () =>
        buildClientEnvironment({
          baseEnvironment: invalid,
          clientName: "codex",
          invitationFile: CODEX_INVITE,
          repositoryRef: REPOSITORY_REF,
          temporaryDirectory: "/tmp/handshake-client",
        }),
      /configuration/i,
    );
  }
});

test("client CLI refuses to launch without explicit operator risk acknowledgement", async () => {
  const stdout = memoryOutput();
  const stderr = memoryOutput();
  let calls = 0;
  const exitCode = await runClientsMain({
    argv: [
      "--codex-invite",
      CODEX_INVITE,
      "--claude-invite",
      CLAUDE_INVITE,
      "--repo-ref",
      REPOSITORY_REF,
    ],
    environment: {
      PATH: process.env.PATH,
      HOME: process.env.HOME,
    },
    async run() {
      calls += 1;
      return {
        status: "PASS",
        manifestPath: "/tmp/client-acceptance.json",
      };
    },
    stderr: stderr.stream,
    stdout: stdout.stream,
  });

  assert.equal(exitCode, 2);
  assert.equal(calls, 0);
  assert.equal(stdout.text(), "");
  assert.equal(
    stderr.text(),
    "Clean-client acceptance is operator-only: it disables client permission safeguards, inherits selected local credentials, HOME, and invitation access, and is not an OS or container sandbox. Re-run only with --acknowledge-agent-permission-risk.\n",
  );
});

test("client CLI accepts risk acknowledgement only as one exact valueless flag", async (t) => {
  const baseArguments = [
    "--codex-invite",
    CODEX_INVITE,
    "--claude-invite",
    CLAUDE_INVITE,
    "--repo-ref",
    REPOSITORY_REF,
  ];
  const cases = [
    {
      label: "duplicate flag",
      argv: [
        ...baseArguments,
        "--acknowledge-agent-permission-risk",
        "--acknowledge-agent-permission-risk",
      ],
      environment: {},
    },
    {
      label: "value after flag",
      argv: [
        ...baseArguments,
        "--acknowledge-agent-permission-risk",
        "acknowledgement-value-canary",
      ],
      environment: {},
    },
    {
      label: "environment substitute",
      argv: baseArguments,
      environment: {
        HANDSHAKE_ACKNOWLEDGE_AGENT_PERMISSION_RISK:
          "environment-acknowledgement-canary",
      },
    },
  ];

  for (const testCase of cases) {
    await t.test(testCase.label, async () => {
      const stdout = memoryOutput();
      const stderr = memoryOutput();
      let calls = 0;
      const exitCode = await runClientsMain({
        argv: testCase.argv,
        environment: {
          PATH: process.env.PATH,
          HOME: process.env.HOME,
          ...testCase.environment,
        },
        async run() {
          calls += 1;
          return {
            status: "PASS",
            manifestPath: "/tmp/client-acceptance.json",
          };
        },
        stderr: stderr.stream,
        stdout: stdout.stream,
      });

      assert.equal(exitCode, 2);
      assert.equal(calls, 0);
      assert.equal(stdout.text(), "");
      assert.notEqual(stderr.text(), "");
      assert.doesNotMatch(
        stderr.text(),
        /(?:acknowledgement-value|environment-acknowledgement)-canary/,
      );
    });
  }
});

test("client CLI rejects option collisions without echoing their values", async (t) => {
  const cases = [
    {
      label: "acknowledgement flag consumed as an option value",
      argv: [
        "--codex-invite",
        "--acknowledge-agent-permission-risk",
        "--claude-invite",
        CLAUDE_INVITE,
        "--repo-ref",
        REPOSITORY_REF,
        "--acknowledge-agent-permission-risk",
      ],
    },
    {
      label: "duplicate valued option",
      argv: [
        "--codex-invite",
        CODEX_INVITE,
        "--codex-invite",
        "/private/duplicate-invite-canary.secret.json",
        "--claude-invite",
        CLAUDE_INVITE,
        "--repo-ref",
        REPOSITORY_REF,
        "--acknowledge-agent-permission-risk",
      ],
    },
  ];

  for (const testCase of cases) {
    await t.test(testCase.label, async () => {
      const stdout = memoryOutput();
      const stderr = memoryOutput();
      let calls = 0;
      const exitCode = await runClientsMain({
        argv: testCase.argv,
        environment: {
          PATH: process.env.PATH,
          HOME: process.env.HOME,
        },
        async run() {
          calls += 1;
          return {
            status: "PASS",
            manifestPath: "/tmp/client-acceptance.json",
          };
        },
        stderr: stderr.stream,
        stdout: stdout.stream,
      });

      assert.equal(exitCode, 2);
      assert.equal(calls, 0);
      assert.equal(stdout.text(), "");
      assert.equal(
        stderr.text(),
        "Clean-client acceptance configuration failed.\n",
      );
      assert.doesNotMatch(
        stderr.text(),
        /duplicate-invite-canary/,
      );
    });
  }
});

test("client CLI requires an immutable repository SHA and never exposes executable overrides", async (t) => {
  await t.test("missing repository SHA", async () => {
    const stdout = memoryOutput();
    const stderr = memoryOutput();
    let calls = 0;
    const exitCode = await runClientsMain({
      argv: [
        "--codex-invite",
        CODEX_INVITE,
        "--claude-invite",
        CLAUDE_INVITE,
        "--acknowledge-agent-permission-risk",
      ],
      environment: {
        PATH: process.env.PATH,
        HOME: process.env.HOME,
      },
      async run() {
        calls += 1;
        return {
          status: "PASS",
          manifestPath: "/tmp/client-acceptance.json",
        };
      },
      stderr: stderr.stream,
      stdout: stdout.stream,
    });

    assert.equal(exitCode, 2);
    assert.equal(calls, 0);
    assert.equal(stdout.text(), "");
    assert.match(stderr.text(), /configuration failed/i);
  });

  await t.test("CLI executable override", async () => {
    let calls = 0;
    const exitCode = await runClientsMain({
      argv: [
        "--codex-invite",
        CODEX_INVITE,
        "--claude-invite",
        CLAUDE_INVITE,
        "--repo-ref",
        REPOSITORY_REF,
        "--acknowledge-agent-permission-risk",
        "--codex-command",
        "/tmp/attacker-codex",
      ],
      environment: {
        PATH: process.env.PATH,
        HOME: process.env.HOME,
      },
      async run() {
        calls += 1;
        return {
          status: "PASS",
          manifestPath: "/tmp/client-acceptance.json",
        };
      },
      stderr: memoryOutput().stream,
      stdout: memoryOutput().stream,
    });

    assert.equal(exitCode, 2);
    assert.equal(calls, 0);
  });

  await t.test("environment executable override", async () => {
    let captured;
    const exitCode = await runClientsMain({
      argv: [
        "--codex-invite",
        CODEX_INVITE,
        "--claude-invite",
        CLAUDE_INVITE,
        "--repo-ref",
        REPOSITORY_REF,
        "--acknowledge-agent-permission-risk",
      ],
      environment: {
        PATH: process.env.PATH,
        HOME: process.env.HOME,
        HANDSHAKE_CODEX_EXECUTABLE: "/tmp/attacker-codex",
        HANDSHAKE_CLAUDE_EXECUTABLE: "/tmp/attacker-claude",
      },
      async run(options) {
        captured = options;
        return {
          status: "PASS",
          manifestPath: "/tmp/client-acceptance.json",
        };
      },
      stderr: memoryOutput().stream,
      stdout: memoryOutput().stream,
    });

    assert.equal(exitCode, 0);
    assert.deepEqual(captured.commands, DEFAULT_CLIENT_COMMANDS);
    assert.equal(captured.operatorRiskAcknowledged, true);
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

  const options = harnessOptions({
    claudeFixture,
    codexFixture,
    directory,
    executable,
  });
  const result = await runCleanClients(options);

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
    assert.equal(
      Object.hasOwn(capture.env, "HANDSHAKE_REPO_URL"),
      false,
    );
    assert.equal(
      capture.env.HANDSHAKE_REPO_REF,
      REPOSITORY_REF.toLowerCase(),
    );
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
  assert.equal(result.clients.codex.cliVersion, "codex-cli 0.144.1");
  assert.equal(
    result.clients.claude.cliVersion,
    "2.1.218 (Claude Code)",
  );
  assert.match(result.clients.codex.resultPaths.json, /codex\/result\.json$/);
  assert.match(
    result.clients.claude.resultPaths.markdown,
    /claude\/RESULT\.md$/,
  );
  const manifest = await readFile(result.manifestPath, "utf8");
  const manifestObject = JSON.parse(manifest);
  assert.equal(
    manifestObject.repositorySha,
    REPOSITORY_REF.toLowerCase(),
  );
  assert.equal(
    manifestObject.promptSha256,
    sha256(PROMPT),
  );
  for (const client of ["codex", "claude"]) {
    assert.deepEqual(
      manifestObject.clients[client].command,
      {
        executable: options.commands[client].executable,
        args: options.commands[client].args,
      },
    );
    for (const format of ["json", "markdown"]) {
      const evidence =
        manifestObject.clients[client].evidence[format];
      assert.equal(
        evidence.path,
        result.clients[client].resultPaths[format],
      );
      assert.equal(
        evidence.sha256,
        sha256(await readFile(evidence.path)),
      );
    }
  }
  assert.ok(
    Date.parse(manifestObject.clients.codex.completedAt) <=
      Date.parse(manifestObject.clients.claude.startedAt),
  );
  for (const forbidden of [
    CODEX_INVITE,
    CLAUDE_INVITE,
    CODEX_AUTH_CANARY,
    CLAUDE_AUTH_CANARY,
    CODEX_INVITE_CODE,
    CLAUDE_INVITE_CODE,
    CODEX_CIPHERTEXT,
    CLAUDE_CIPHERTEXT,
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
    assert.equal(stdout.includes(CODEX_INVITE_CODE), false);
    assert.equal(stdout.includes(CLAUDE_INVITE_CODE), false);
    assert.equal(stdout.includes(CODEX_CIPHERTEXT), false);
    assert.equal(stdout.includes(CLAUDE_CIPHERTEXT), false);
    assert.equal(stderr.includes(`0x${"9".repeat(64)}`), false);
    assert.match(`${stdout}${stderr}`, /\[REDACTED\]/);
  }
});

test("contains bare macOS mktemp directories inside each clean-client root", async (t) => {
  const directory = await mkdtemp(
    join(process.env.TMPDIR, "handshake-macos-mktemp-"),
  );
  t.after(() =>
    rm(directory, { force: true, recursive: true }));
  await writePrompt(directory);
  const executable = await writeFakeClient(directory);
  const macosBin = await writeMacLikeMktemp(directory);
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
    claudeMode: "bare-mktemp",
    codexFixture,
    codexMode: "bare-mktemp",
    directory,
    executable,
  });
  options.baseEnvironment.PATH = [
    macosBin,
    process.env.PATH,
  ].join(delimiter);

  const result = await runCleanClients(options);

  for (const client of ["codex", "claude"]) {
    const capture = JSON.parse(
      await readFile(
        join(result.clients[client].workDirectory, "capture.json"),
        "utf8",
      ),
    );
    const clientRoot = dirname(
      result.clients[client].workDirectory,
    );
    const evidenceRelativePath = relative(
      clientRoot,
      capture.runDirectory,
    );
    assert.equal(
      evidenceRelativePath === ".." ||
        evidenceRelativePath.startsWith(`..${sep}`),
      false,
    );
    assert.deepEqual(
      (await readdir(capture.runDirectory)).sort(),
      ["RESULT.md", "result.json"],
    );
  }
  assert.equal(result.status, "PASS");
});

test("fails closed without publishing client evidence that contains an invitation canary", async (t) => {
  const directory = await mkdtemp(
    join(process.env.TMPDIR, "handshake-evidence-canary-"),
  );
  t.after(() =>
    rm(directory, { force: true, recursive: true }));
  await writePrompt(directory);
  const executable = await writeFakeClient(directory);
  const contaminatedResult = structuredClone(CODEX_RESULT);
  contaminatedResult.identity.displayName = CODEX_INVITE_CODE;
  const codexFixture = await writeFixture(
    join(directory, "fixtures", "codex"),
    contaminatedResult,
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

  assert.equal(result.status, "FAIL");
  assert.equal(result.clients.codex.status, "FAIL");
  assert.equal(
    result.clients.codex.errorCode,
    "CLIENT_EVIDENCE_INVALID",
  );
  assert.equal(result.clients.codex.resultPaths, null);
  assert.equal(result.clients.claude.status, "PASS");
  await assert.rejects(
    readFile(
      join(directory, "artifacts", "codex", "result.json"),
    ),
    /ENOENT/,
  );
  const manifest = await readFile(result.manifestPath, "utf8");
  assert.equal(manifest.includes(CODEX_INVITE_CODE), false);
});

test("rejects a private-key-shaped value in schema-valid evidence", async (t) => {
  const directory = await mkdtemp(
    join(process.env.TMPDIR, "handshake-evidence-private-key-"),
  );
  t.after(() =>
    rm(directory, { force: true, recursive: true }));
  await writePrompt(directory);
  const executable = await writeFakeClient(directory);
  const privateKeyShape = `0x${"e".repeat(64)}`;
  const contaminatedResult = structuredClone(CODEX_RESULT);
  contaminatedResult.identity.displayName = privateKeyShape;
  const codexFixture = await writeFixture(
    join(directory, "fixtures", "codex"),
    contaminatedResult,
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

  assert.equal(result.status, "FAIL");
  assert.equal(result.clients.codex.status, "FAIL");
  assert.equal(
    result.clients.codex.errorCode,
    "CLIENT_EVIDENCE_INVALID",
  );
  assert.equal(result.clients.codex.resultPaths, null);
  assert.equal(result.clients.claude.status, "PASS");
  await assert.rejects(
    readFile(
      join(directory, "artifacts", "codex", "result.json"),
    ),
    /ENOENT/,
  );
  await assert.rejects(
    readFile(
      join(directory, "artifacts", "codex", "RESULT.md"),
    ),
    /ENOENT/,
  );
  const manifest = await readFile(result.manifestPath, "utf8");
  assert.equal(manifest.includes(privateKeyShape), false);
});

test("redacts unlabeled Ethereum private-key-shaped values from client logs", async (t) => {
  const directory = await mkdtemp(
    join(process.env.TMPDIR, "handshake-unlabeled-key-"),
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

  const result = await runCleanClients(
    harnessOptions({
      claudeFixture,
      codexFixture,
      directory,
      executable,
    }),
  );
  const privateKeyShape = `0x${"9".repeat(64)}`;
  for (const client of ["codex", "claude"]) {
    const stderr = await readFile(
      result.clients[client].stderrLog,
      "utf8",
    );
    assert.equal(stderr.includes(privateKeyShape), false);
    assert.match(stderr, /\[REDACTED\]/);
  }
});

test("rejects an exact invitation canary hidden in a duplicate raw JSON key", async (t) => {
  const directory = await mkdtemp(
    join(process.env.TMPDIR, "handshake-duplicate-canary-"),
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
  const canonical = await readFile(codexFixture.jsonPath, "utf8");
  const attacked = canonical.replace(
    '    "displayName": "Billy",',
    `    "displayName": "${CODEX_INVITE_CODE}",\n` +
      '    "displayName": "Billy",',
  );
  assert.notEqual(attacked, canonical);
  await writeFile(codexFixture.jsonPath, attacked);

  const result = await runCleanClients(
    harnessOptions({
      claudeFixture,
      codexFixture,
      directory,
      executable,
    }),
  );

  assert.equal(result.status, "FAIL");
  assert.equal(
    result.clients.codex.errorCode,
    "CLIENT_EVIDENCE_INVALID",
  );
  await assert.rejects(
    readFile(
      join(directory, "artifacts", "codex", "result.json"),
    ),
    /ENOENT/,
  );
});

test("publishes parsed evidence only through canonical JSON serialization", async (t) => {
  const directory = await mkdtemp(
    join(process.env.TMPDIR, "handshake-canonical-evidence-"),
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
  const canonical = await readFile(codexFixture.jsonPath, "utf8");
  const duplicate = canonical.replace(
    '  "status": "PASS",',
    '  "status": "FAIL",\n  "status": "PASS",',
  );
  assert.notEqual(duplicate, canonical);
  await writeFile(codexFixture.jsonPath, duplicate);

  const result = await runCleanClients(
    harnessOptions({
      claudeFixture,
      codexFixture,
      directory,
      executable,
    }),
  );

  assert.equal(result.clients.codex.status, "PASS");
  assert.equal(
    await readFile(result.clients.codex.resultPaths.json, "utf8"),
    `${JSON.stringify(CODEX_RESULT, null, 2)}\n`,
  );
});

test("requires an exact programmatic risk acknowledgement before invitation reads, spawning, or artifacts", async (t) => {
  const directory = await mkdtemp(
    join(process.env.TMPDIR, "handshake-programmatic-ack-"),
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

  for (const acknowledgement of [
    undefined,
    false,
    "true",
    1,
  ]) {
    let invitationReads = 0;
    let spawnCalls = 0;
    const options = harnessOptions({
      claudeFixture,
      codexFixture,
      directory,
      executable,
    });
    if (acknowledgement === undefined) {
      delete options.operatorRiskAcknowledged;
    } else {
      options.operatorRiskAcknowledged = acknowledgement;
    }
    options.readInvitation = async () => {
      invitationReads += 1;
      throw new Error("must not read");
    };
    options.spawnImpl = () => {
      spawnCalls += 1;
      throw new Error("must not spawn");
    };

    await assert.rejects(
      runCleanClients(options),
      (error) =>
        error?.name === "HarnessConfigurationError" &&
        error?.code === "HARNESS_CONFIGURATION",
    );
    assert.equal(invitationReads, 0);
    assert.equal(spawnCalls, 0);
  }
  await assert.rejects(
    readFile(join(directory, "artifacts")),
    /ENOENT/,
  );
});

test("supports the operator acceptance harness only on macOS and Linux", () => {
  assert.equal(
    typeof cleanClientsHarness
      .assertAcceptanceHarnessPlatformForTesting,
    "function",
  );
  assert.doesNotThrow(() =>
    cleanClientsHarness
      .assertAcceptanceHarnessPlatformForTesting("darwin"));
  assert.doesNotThrow(() =>
    cleanClientsHarness
      .assertAcceptanceHarnessPlatformForTesting("linux"));
  assert.throws(
    () =>
      cleanClientsHarness
        .assertAcceptanceHarnessPlatformForTesting("win32"),
    (error) =>
      error?.name === "UnsupportedAcceptancePlatformError" &&
      error?.code === "HARNESS_UNSUPPORTED_PLATFORM",
  );
});

test("rejects an unsupported runtime platform before invitations, spawning, or artifacts", {
  concurrency: false,
}, async (t) => {
  const directory = await mkdtemp(
    join(process.env.TMPDIR, "handshake-platform-"),
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
  let invitationReads = 0;
  let spawnCalls = 0;
  options.readInvitation = async () => {
    invitationReads += 1;
    throw new Error("must not read");
  };
  options.spawnImpl = () => {
    spawnCalls += 1;
    throw new Error("must not spawn");
  };
  const originalPlatform = process.platform;
  Object.defineProperty(process, "platform", {
    configurable: true,
    value: "win32",
  });

  try {
    await assert.rejects(
      runCleanClients(options),
      (error) =>
        error?.name === "UnsupportedAcceptancePlatformError" &&
        error?.code === "HARNESS_UNSUPPORTED_PLATFORM",
    );
  } finally {
    Object.defineProperty(process, "platform", {
      configurable: true,
      value: originalPlatform,
    });
  }

  assert.equal(invitationReads, 0);
  assert.equal(spawnCalls, 0);
  await assert.rejects(
    readFile(options.outputRoot),
    /ENOENT/,
  );
});

test("rejects a mutable repository ref before reading invitations or launching clients", async (t) => {
  const directory = await mkdtemp(
    join(process.env.TMPDIR, "handshake-mutable-ref-"),
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
  let invitationReads = 0;
  const options = harnessOptions({
    claudeFixture,
    codexFixture,
    directory,
    executable,
  });
  options.repositoryRef = "feature/turnkey";
  options.readInvitation = async () => {
    invitationReads += 1;
    throw new Error("must not read");
  };

  await assert.rejects(
    runCleanClients(options),
    /configuration/i,
  );
  assert.equal(invitationReads, 0);
});

test("rejects one custom executable reused for both clean-client roles before reading invitations", async (t) => {
  const directory = await mkdtemp(
    join(process.env.TMPDIR, "handshake-shared-executable-"),
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
  let invitationReads = 0;
  const options = harnessOptions({
    claudeFixture,
    codexFixture,
    directory,
    executable,
  });
  options.commands.claude.executable =
    options.commands.codex.executable;
  options.readInvitation = async () => {
    invitationReads += 1;
    throw new Error("must not read");
  };

  await assert.rejects(
    runCleanClients(options),
    /configuration/i,
  );
  assert.equal(invitationReads, 0);
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
      timeoutMs: 300,
    }),
  );
  await delay(800);

  assert.equal(result.status, "FAIL");
  assert.equal(result.clients.codex.timedOut, true);
  assert.equal(result.clients.claude.status, "PASS");
  await assert.rejects(readFile(marker), /ENOENT/);
});

test("SIGKILLs descendants after grace even when the timed-out leader exits on SIGTERM", async (t) => {
  const directory = await mkdtemp(
    join(process.env.TMPDIR, "handshake-descendant-timeout-"),
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
  const marker = join(directory, "escaped-descendant.txt");

  const result = await runCleanClients(
    harnessOptions({
      claudeFixture,
      codexFixture,
      codexMode: "leader-exits",
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
  await assert.rejects(readFile(marker), /ENOENT/);
});

test("reaps lingering descendants after a successful leader exit without reporting a timeout", async (t) => {
  const directory = await mkdtemp(
    join(process.env.TMPDIR, "handshake-descendant-success-"),
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
  const marker = join(directory, "escaped-success-descendant.txt");

  const result = await runCleanClients(
    harnessOptions({
      claudeFixture,
      codexFixture,
      codexMode: "lingering-success",
      directory,
      executable,
      marker,
      terminationGraceMs: 50,
    }),
  );
  await delay(800);

  assert.equal(result.status, "PASS");
  assert.equal(result.clients.codex.timedOut, false);
  assert.equal(result.clients.codex.outputLimitExceeded, false);
  await assert.rejects(readFile(marker), /ENOENT/);
});

test("starts cleanup on leader exit when a descendant inherits output pipes", async (t) => {
  const directory = await mkdtemp(
    join(process.env.TMPDIR, "handshake-descendant-pipes-"),
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
  const marker = join(directory, "escaped-inherited-descendant.txt");

  const result = await runCleanClients(
    harnessOptions({
      claudeFixture,
      codexFixture,
      codexMode: "lingering-success-inherited",
      directory,
      executable,
      marker,
      terminationGraceMs: 20,
      timeoutMs: 250,
    }),
  );
  await delay(700);

  assert.equal(result.status, "PASS");
  assert.equal(result.clients.codex.timedOut, false);
  assert.equal(result.clients.codex.outputLimitExceeded, false);
  await assert.rejects(readFile(marker), /ENOENT/);
});

test("waits for confirmed process-group absence before launching the client command", {
  concurrency: false,
}, async (t) => {
  const directory = await mkdtemp(
    join(process.env.TMPDIR, "handshake-cleanup-confirmed-"),
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
    terminationGraceMs: 1,
  });
  const originalKill = process.kill;
  let groupPresent = true;
  let spawnCalls = 0;
  let settled = false;
  let hardKillObserved;
  const hardKillSeen = new Promise((resolveSeen) => {
    hardKillObserved = resolveSeen;
  });
  process.kill = (pid, signal) => {
    if (pid < 0) {
      if (signal === 0) {
        if (groupPresent) {
          return true;
        }
        const error = new Error("group absent");
        error.code = "ESRCH";
        throw error;
      }
      if (signal === "SIGKILL") {
        hardKillObserved();
      }
      return true;
    }
    return originalKill(pid, signal);
  };
  options.spawnImpl = (...args) => {
    spawnCalls += 1;
    return spawn(...args);
  };

  let pending;
  let earlyAssertion;
  try {
    pending = runCleanClients(options).then((result) => {
      settled = true;
      return result;
    });
    await hardKillSeen;
    await delay(25);
    try {
      assert.equal(spawnCalls, 1);
      assert.equal(settled, false);
    } catch (error) {
      earlyAssertion = error;
    }
    groupPresent = false;
    const result = await pending;
    if (earlyAssertion) {
      throw earlyAssertion;
    }
    assert.equal(result.status, "PASS");
    assert.equal(result.clients.codex.timedOut, false);
    assert.equal(
      result.clients.codex.outputLimitExceeded,
      false,
    );
  } finally {
    groupPresent = false;
    await pending?.catch(() => {});
    process.kill = originalKill;
  }
});

test("fails closed and skips the second client when process-group disappearance cannot be confirmed", {
  concurrency: false,
}, async (t) => {
  const directory = await mkdtemp(
    join(process.env.TMPDIR, "handshake-cleanup-unconfirmed-"),
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
    terminationGraceMs: 1,
  });
  const originalKill = process.kill;
  let spawnCalls = 0;
  process.kill = (pid, signal) => {
    if (pid < 0) {
      return true;
    }
    return originalKill(pid, signal);
  };
  options.spawnImpl = (...args) => {
    spawnCalls += 1;
    return spawn(...args);
  };

  try {
    const result = await runCleanClients(options);
    assert.equal(result.status, "FAIL");
    assert.equal(spawnCalls, 1);
    assert.equal(
      result.clients.codex.errorCode,
      "CLIENT_PROCESS_GROUP_CLEANUP_FAILED",
    );
    assert.equal(result.clients.codex.timedOut, false);
    assert.equal(
      result.clients.codex.outputLimitExceeded,
      false,
    );
    assert.equal(result.clients.codex.resultPaths, null);
    assert.equal(
      result.clients.claude.errorCode,
      "CLIENT_SKIPPED_AFTER_CLEANUP_FAILURE",
    );
    await assert.rejects(
      readFile(
        join(
          directory,
          "artifacts",
          "codex",
          "result.json",
        ),
      ),
      /ENOENT/,
    );
  } finally {
    process.kill = originalKill;
  }
});

test("bounded evidence reads own no-follow descriptor flags and reject metadata changes", async (t) => {
  const directory = await mkdtemp(
    join(process.env.TMPDIR, "handshake-evidence-descriptor-"),
  );
  t.after(() =>
    rm(directory, { force: true, recursive: true }));
  const evidencePath = join(directory, "result.json");
  const symlinkTarget = join(directory, "target.json");
  const symlinkPath = join(directory, "linked-result.json");
  await writeFile(evidencePath, '{"status":"PASS"}\n');
  await writeFile(symlinkTarget, '{"status":"PASS"}\n');
  await symlink(symlinkTarget, symlinkPath);

  assert.equal(
    BOUNDED_READ_FLAGS_FOR_TESTING,
    fileSystemConstants.O_RDONLY |
      fileSystemConstants.O_NOFOLLOW |
      fileSystemConstants.O_NONBLOCK,
  );
  await assert.rejects(
    readBoundedFileForTesting(evidencePath, 1_024, {
      afterRead: () => writeFile(evidencePath, "changed\n"),
    }),
    /boundary/i,
  );
  await assert.rejects(
    readBoundedFileForTesting(symlinkPath, 1_024),
  );
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

test("client CLI resolves documented relative invitation paths without accepting a repository URL", async () => {
  const stdout = memoryOutput();
  const stderr = memoryOutput();
  let captured;
  const exitCode = await runClientsMain({
    argv: [
      "--codex-invite",
      ".context/invitations/codex.secret.json",
      "--claude-invite",
      ".context/invitations/claude.secret.json",
      "--repo-ref",
      REPOSITORY_REF,
      "--acknowledge-agent-permission-risk",
    ],
    environment: {
      PATH: process.env.PATH,
      HOME: process.env.HOME,
    },
    async run(options) {
      captured = options;
      return {
        status: "PASS",
        manifestPath: "/tmp/client-acceptance.json",
      };
    },
    stderr: stderr.stream,
    stdout: stdout.stream,
  });

  assert.equal(exitCode, 0);
  assert.equal(captured.operatorRiskAcknowledged, true);
  assert.equal(
    captured.invitations.codex,
    join(
      process.cwd(),
      ".context/invitations/codex.secret.json",
    ),
  );
  assert.equal(
    captured.invitations.claude,
    join(
      process.cwd(),
      ".context/invitations/claude.secret.json",
    ),
  );
  assert.equal(
    Object.hasOwn(captured, "repositoryUrl"),
    false,
  );
  assert.equal(stderr.text(), "");
  assert.match(stdout.text(), /PASS/);
});

function registrationUris(result) {
  const initial = {
    type: "https://eips.ethereum.org/EIPS/eip-8004#registration-v1",
    name: result.identity.displayName,
    description:
      "Ephemeral Clockchain Handshake testnet identity; registration does not establish capability or trust.",
    services: [],
    x402Support: false,
    active: true,
    registrations: [],
  };
  const final = {
    ...initial,
    registrations: [
      {
        agentRegistry:
          `eip155:11155111:${REGISTRY_ADDRESS}`,
        agentId: Number(result.identity.agentId),
      },
    ],
  };
  const uri = (document) =>
    `data:application/json;base64,${
      Buffer.from(JSON.stringify(document), "utf8").toString("base64")
    }`;
  return {
    initial: uri(initial),
    final: uri(final),
  };
}

function transactionEvidence(result, index) {
  const { initial, final } = registrationUris(result);
  const registerBlock = 10_000n + BigInt(index * 2);
  const metadataBlock = registerBlock + 1n;
  const registerInput = encodeFunctionData({
    abi: [
      {
        type: "function",
        name: "register",
        stateMutability: "nonpayable",
        inputs: [{ name: "agentURI", type: "string" }],
        outputs: [{ name: "agentId", type: "uint256" }],
      },
    ],
    functionName: "register",
    args: [initial],
  });
  const metadataInput = encodeFunctionData({
    abi: [
      {
        type: "function",
        name: "setAgentURI",
        stateMutability: "nonpayable",
        inputs: [
          { name: "agentId", type: "uint256" },
          { name: "newURI", type: "string" },
        ],
        outputs: [],
      },
    ],
    functionName: "setAgentURI",
    args: [BigInt(result.identity.agentId), final],
  });
  const registeredLog = {
    address: REGISTRY_ADDRESS,
    data: encodeAbiParameters(
      [{ name: "agentURI", type: "string" }],
      [initial],
    ),
    topics: encodeEventTopics({
      abi: [
        {
          type: "event",
          name: "Registered",
          anonymous: false,
          inputs: [
            {
              name: "agentId",
              type: "uint256",
              indexed: true,
            },
            {
              name: "agentURI",
              type: "string",
              indexed: false,
            },
            {
              name: "owner",
              type: "address",
              indexed: true,
            },
          ],
        },
      ],
      eventName: "Registered",
      args: {
        agentId: BigInt(result.identity.agentId),
        owner: result.identity.owner,
      },
    }),
    blockNumber: registerBlock,
    transactionHash: result.identity.registerTx,
  };
  const transaction = ({
    blockNumber,
    hash,
    input,
    nonce,
  }) => ({
    hash,
    blockNumber,
    chainId: 11155111,
    from: result.identity.owner,
    to: REGISTRY_ADDRESS,
    value: 0n,
    nonce,
    input,
    transactionIndex: 0,
  });
  const receipt = ({
    blockNumber,
    hash,
    logs = [],
  }) => ({
    status: "success",
    transactionHash: hash,
    blockNumber,
    transactionIndex: 0,
    from: result.identity.owner,
    to: REGISTRY_ADDRESS,
    logs,
  });
  return {
    registerTransaction: transaction({
      blockNumber: registerBlock,
      hash: result.identity.registerTx,
      input: registerInput,
      nonce: 0,
    }),
    metadataTransaction: transaction({
      blockNumber: metadataBlock,
      hash: result.identity.metadataTx,
      input: metadataInput,
      nonce: 1,
    }),
    registerReceipt: receipt({
      blockNumber: registerBlock,
      hash: result.identity.registerTx,
      logs: [registeredLog],
    }),
    metadataReceipt: receipt({
      blockNumber: metadataBlock,
      hash: result.identity.metadataTx,
    }),
  };
}

async function writeAcceptanceManifest(
  directory,
  {
    codexDirectory,
    claudeDirectory,
    repositorySha = REPOSITORY_REF.toLowerCase(),
    mutate = (manifest) => manifest,
  },
) {
  const prompt = await readFile(
    join(process.cwd(), "prompts", "run-turnkey-demo.md"),
  );
  const client = async (
    name,
    resultDirectory,
    startedAt,
    completedAt,
    cliVersion,
  ) => {
    const jsonPath = join(resultDirectory, "result.json");
    const markdownPath = join(resultDirectory, "RESULT.md");
    return {
      status: "PASS",
      command: {
        executable: DEFAULT_CLIENT_COMMANDS[name].executable,
        args: [...DEFAULT_CLIENT_COMMANDS[name].args],
      },
      cliVersion,
      startedAt,
      completedAt,
      exitCode: 0,
      signal: null,
      timedOut: false,
      outputLimitExceeded: false,
      errorCode: null,
      evidence: {
        json: {
          path: jsonPath,
          sha256: sha256(await readFile(jsonPath)),
        },
        markdown: {
          path: markdownPath,
          sha256: sha256(await readFile(markdownPath)),
        },
      },
    };
  };
  const manifest = {
    schema: "clockchain.handshake-client-acceptance/v1",
    status: "PASS",
    repositorySha,
    promptSha256: sha256(prompt),
    startedAt: "2026-07-23T08:00:00.000Z",
    completedAt: "2026-07-23T08:00:04.000Z",
    clients: {
      codex: await client(
        "codex",
        codexDirectory,
        "2026-07-23T08:00:00.000Z",
        "2026-07-23T08:00:02.000Z",
        "codex-cli 0.144.1",
      ),
      claude: await client(
        "claude",
        claudeDirectory,
        "2026-07-23T08:00:02.001Z",
        "2026-07-23T08:00:04.000Z",
        "2.1.218 (Claude Code)",
      ),
    },
  };
  const activeManifest = mutate(structuredClone(manifest));
  const path = join(directory, "client-acceptance.json");
  await writeFile(
    path,
    `${JSON.stringify(activeManifest, null, 2)}\n`,
    { mode: 0o600 },
  );
  return path;
}

async function verificationProvenance(
  directory,
  {
    codexDirectory,
    claudeDirectory,
    results = [CODEX_RESULT, CLAUDE_RESULT],
  },
) {
  const manifestFile = await writeAcceptanceManifest(
    directory,
    { codexDirectory, claudeDirectory },
  );
  const canaryFiles = [
    join(directory, "codex.secret.json"),
    join(directory, "claude.secret.json"),
  ];
  const invitations = results.map((result, index) => ({
    code: index === 0
      ? CODEX_INVITE_CODE
      : CLAUDE_INVITE_CODE,
    bundle: {
      address: result.identity.owner,
      displayName: result.identity.displayName,
      crypto: {
        ciphertext: index === 0
          ? CODEX_CIPHERTEXT
          : CLAUDE_CIPHERTEXT,
      },
    },
  }));
  await Promise.all(
    canaryFiles.map((path, index) =>
      writeFile(
        path,
        `${JSON.stringify(invitations[index])}\n`,
        { mode: 0o600 },
      )),
  );
  return {
    canaryFiles,
    expectedRepositorySha: REPOSITORY_REF,
    manifestFile,
    readInvitation: async (path) =>
      invitations[canaryFiles.indexOf(path)],
  };
}

function fakePublicClient(results) {
  const calls = [];
  const transactions = results.map(transactionEvidence);
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
    async getTransaction({ hash }) {
      calls.push({ functionName: "getTransaction", hash });
      for (const evidence of transactions) {
        if (evidence.registerTransaction.hash === hash) {
          return structuredClone(evidence.registerTransaction);
        }
        if (evidence.metadataTransaction.hash === hash) {
          return structuredClone(evidence.metadataTransaction);
        }
      }
      throw new Error("Unknown transaction");
    },
    async getTransactionReceipt({ hash }) {
      calls.push({
        functionName: "getTransactionReceipt",
        hash,
      });
      for (const evidence of transactions) {
        if (evidence.registerReceipt.transactionHash === hash) {
          return structuredClone(evidence.registerReceipt);
        }
        if (evidence.metadataReceipt.transactionHash === hash) {
          return structuredClone(evidence.metadataReceipt);
        }
      }
      throw new Error("Unknown receipt");
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
        return registrationUris(result).final;
      }
      throw new Error(`Unexpected read ${functionName}`);
    },
  };
}

function fakeClockchain(
  results,
  observations,
  { mutateCompleted = (receipt) => receipt } = {},
) {
  return {
    async tokenIssuer(options) {
      observations.tokenSubjects.push(options.subject);
      return "cc_verifier_token_canary_1234567890";
    },
    clientFactory({ token }) {
      observations.factoryTokens.push(token);
      return {
        async completeAttestation(receipt) {
          observations.completions.push(receipt);
          const result = results.find(
            ({ clockchain }) =>
              clockchain.ledgerId === receipt.anchor.ledgerId,
          );
          assert.ok(result);
          const completed = {
            schema: "clockchain.receipt/v1",
            network: "testnet",
            status: "anchored",
            agentId: result.identity.agentId,
            action: "trust_handshake",
            eventHash: expectedReceiptHash(result),
            hashType: "SHA-256",
            payload: structuredClone(receipt.payload),
            anchor: {
              ledgerId: result.clockchain.ledgerId,
              assetReferenceId:
                `${result.identity.agentId}:trust_handshake:1780000000000`,
              blockHeight: result.clockchain.blockHeight,
              recordedAt: "2026-07-23T08:00:00.000Z",
              consensusTime: result.clockchain.consensusTime,
              confirmed: true,
            },
            poolHealth: {
              totalNodes:
                result.clockchain.poolHealth.totalNodes,
              nodeParticipationPct:
                result.clockchain.poolHealth.nodeParticipationPct,
              degraded:
                result.clockchain.poolHealth.degradedAtSubmission,
            },
          };
          return mutateCompleted(completed, result);
        },
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

test("rejects an unbound client-acceptance manifest before any live verification", async (t) => {
  const directory = await mkdtemp(
    join(process.env.TMPDIR, "handshake-unbound-manifest-"),
  );
  t.after(() =>
    rm(directory, { force: true, recursive: true }));
  const codexDirectory = join(directory, "codex");
  const claudeDirectory = join(directory, "claude");
  await writeFixture(codexDirectory, CODEX_RESULT);
  await writeFixture(claudeDirectory, CLAUDE_RESULT);
  const manifestFile = await writeAcceptanceManifest(
    directory,
    {
      codexDirectory,
      claudeDirectory,
      mutate(manifest) {
        manifest.repositorySha = "f".repeat(40);
        manifest.clients.codex.command.executable =
          "/tmp/attacker-codex";
        return manifest;
      },
    },
  );
  const publicClient = fakePublicClient([
    CODEX_RESULT,
    CLAUDE_RESULT,
  ]);
  const observations = {
    completions: [],
    crossParty: [],
    factoryTokens: [],
    tokenSubjects: [],
  };
  const clockchain = fakeClockchain(
    [CODEX_RESULT, CLAUDE_RESULT],
    observations,
  );

  await assert.rejects(
    verifyLiveResults({
      clientFactory: clockchain.clientFactory,
      expectedRepositorySha: REPOSITORY_REF,
      manifestFile,
      outputFile: join(directory, "verdict.json"),
      publicClient,
      resultDirectories: {
        codex: codexDirectory,
        claude: claudeDirectory,
      },
      tokenIssuer: clockchain.tokenIssuer,
    }),
    /configuration|manifest/i,
  );
  assert.equal(publicClient.calls.length, 0);
  assert.equal(observations.tokenSubjects.length, 0);
});

test("binds each result owner and display name to its ordered operator invitation", async (t) => {
  const directory = await mkdtemp(
    join(process.env.TMPDIR, "handshake-operator-binding-"),
  );
  t.after(() =>
    rm(directory, { force: true, recursive: true }));
  const codexDirectory = join(directory, "codex");
  const claudeDirectory = join(directory, "claude");
  await writeFixture(codexDirectory, CODEX_RESULT);
  await writeFixture(claudeDirectory, CLAUDE_RESULT);
  const manifestFile = await writeAcceptanceManifest(
    directory,
    { codexDirectory, claudeDirectory },
  );
  const invitationFiles = [
    join(directory, "codex.secret.json"),
    join(directory, "claude.secret.json"),
  ];
  const invitations = [
    {
      code: CODEX_INVITE_CODE,
      bundle: {
        address: OWNER_B,
        displayName: CODEX_RESULT.identity.displayName,
        crypto: { ciphertext: CODEX_CIPHERTEXT },
      },
    },
    {
      code: CLAUDE_INVITE_CODE,
      bundle: {
        address: CLAUDE_RESULT.identity.owner,
        displayName: CLAUDE_RESULT.identity.displayName,
        crypto: { ciphertext: CLAUDE_CIPHERTEXT },
      },
    },
  ];
  await Promise.all(
    invitationFiles.map((path, index) =>
      writeFile(
        path,
        `${JSON.stringify(invitations[index])}\n`,
        { mode: 0o600 },
      )),
  );
  const publicClient = fakePublicClient([
    CODEX_RESULT,
    CLAUDE_RESULT,
  ]);
  const observations = {
    completions: [],
    crossParty: [],
    factoryTokens: [],
    tokenSubjects: [],
  };
  const clockchain = fakeClockchain(
    [CODEX_RESULT, CLAUDE_RESULT],
    observations,
  );

  const verdict = await verifyLiveResults({
    canaryFiles: invitationFiles,
    clientFactory: clockchain.clientFactory,
    expectedRepositorySha: REPOSITORY_REF,
    manifestFile,
    outputFile: join(directory, "verdict.json"),
    publicClient,
    readInvitation: async (path) =>
      invitations[invitationFiles.indexOf(path)],
    resultDirectories: {
      codex: codexDirectory,
      claude: claudeDirectory,
    },
    tokenIssuer: clockchain.tokenIssuer,
  });

  assert.equal(verdict.status, "FAIL");
  assert.equal(
    verdict.clients.codex.errorCode,
    "OPERATOR_IDENTITY_MISMATCH",
  );
  assert.equal(verdict.clients.claude.status, "PASS");
});

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
    completions: [],
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
    ...(await verificationProvenance(directory, {
      codexDirectory,
      claudeDirectory,
    })),
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
  assert.equal(observations.completions.length, 2);
  assert.deepEqual(observations.crossParty, [
    {
      ledgerId: LEDGER_A,
      blockHeight: "9001",
      hash: expectedReceiptHash(CODEX_RESULT),
    },
    {
      ledgerId: LEDGER_B,
      blockHeight: "9002",
      hash: expectedReceiptHash(CLAUDE_RESULT),
    },
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
    functions.filter((name) => name === "getTransaction").length,
    4,
  );
  assert.equal(
    functions.filter(
      (name) => name === "getTransactionReceipt",
    ).length,
    4,
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
  const secretCanary = CODEX_INVITE_CODE;
  await writeFile(
    join(codexDirectory, "stdout.log"),
    `accidental ${secretCanary}\n`,
  );
  const publicClient = fakePublicClient([
    CODEX_RESULT,
    CLAUDE_RESULT,
  ]);
  const observations = {
    completions: [],
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
    ...(await verificationProvenance(directory, {
      codexDirectory,
      claudeDirectory,
    })),
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
    completions: [],
    crossParty: [],
    factoryTokens: [],
    tokenSubjects: [],
  };
  const clockchain = fakeClockchain(
    [CODEX_RESULT, CLAUDE_RESULT],
    observations,
  );

  const verdict = await verifyLiveResults({
    ...(await verificationProvenance(directory, {
      codexDirectory,
      claudeDirectory,
    })),
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
    completions: [],
    crossParty: [],
    factoryTokens: [],
    tokenSubjects: [],
  };
  const clockchain = fakeClockchain(
    [CODEX_RESULT, duplicateIdentity],
    observations,
  );

  const verdict = await verifyLiveResults({
    ...(await verificationProvenance(directory, {
      codexDirectory,
      claudeDirectory,
      results: [CODEX_RESULT, duplicateIdentity],
    })),
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

test("rejects forged ERC-8004 transaction proof even when final owner and URI reads match", async (t) => {
  const cases = [
    {
      name: "registry target",
      mutateTransaction(transaction) {
        transaction.to = OWNER_B;
      },
    },
    {
      name: "register calldata",
      mutateTransaction(transaction) {
        transaction.input = "0x12345678";
      },
    },
    {
      name: "receipt status",
      mutateReceipt(receipt) {
        receipt.status = "reverted";
      },
    },
    {
      name: "Registered event",
      mutateReceipt(receipt) {
        receipt.logs = [];
      },
    },
  ];

  for (const attack of cases) {
    await t.test(attack.name, async (subtest) => {
      const directory = await mkdtemp(
        join(process.env.TMPDIR, "handshake-forged-tx-"),
      );
      subtest.after(() =>
        rm(directory, { force: true, recursive: true }));
      const codexDirectory = join(directory, "codex");
      const claudeDirectory = join(directory, "claude");
      await writeFixture(codexDirectory, CODEX_RESULT);
      await writeFixture(claudeDirectory, CLAUDE_RESULT);
      const publicClient = fakePublicClient([
        CODEX_RESULT,
        CLAUDE_RESULT,
      ]);
      const originalGetTransaction =
        publicClient.getTransaction;
      const originalGetTransactionReceipt =
        publicClient.getTransactionReceipt;
      publicClient.getTransaction = async (options) => {
        const transaction = await originalGetTransaction.call(
          publicClient,
          options,
        );
        if (options.hash === CODEX_RESULT.identity.registerTx) {
          attack.mutateTransaction?.(transaction);
        }
        return transaction;
      };
      publicClient.getTransactionReceipt = async (options) => {
        const receipt =
          await originalGetTransactionReceipt.call(
            publicClient,
            options,
          );
        if (options.hash === CODEX_RESULT.identity.registerTx) {
          attack.mutateReceipt?.(receipt);
        }
        return receipt;
      };
      const observations = {
        completions: [],
        crossParty: [],
        factoryTokens: [],
        tokenSubjects: [],
      };
      const clockchain = fakeClockchain(
        [CODEX_RESULT, CLAUDE_RESULT],
        observations,
      );

      const verdict = await verifyLiveResults({
        ...(await verificationProvenance(directory, {
          codexDirectory,
          claudeDirectory,
        })),
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
        "ERC8004_TRANSACTION_MISMATCH",
      );
      assert.equal(verdict.clients.claude.status, "PASS");
    });
  }
});

test("rejects forged consensus time and pool-health result fields against a read-only completed receipt", async (t) => {
  for (const field of ["consensusTime", "poolHealth"]) {
    await t.test(field, async () => {
      const directory = await mkdtemp(
        join(
          process.env.TMPDIR,
          `handshake-forged-${field}-`,
        ),
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
      const observations = {
        completions: [],
        crossParty: [],
        factoryTokens: [],
        tokenSubjects: [],
      };
      const clockchain = fakeClockchain(
        [CODEX_RESULT, CLAUDE_RESULT],
        observations,
        {
          mutateCompleted(receipt, result) {
            if (result.identity.agentId !== "101") {
              return receipt;
            }
            if (field === "consensusTime") {
              receipt.anchor.consensusTime =
                "2026-07-23T09:09:09.000Z";
            } else {
              receipt.poolHealth.totalNodes = 2;
            }
            return receipt;
          },
        },
      );

      const verdict = await verifyLiveResults({
        ...(await verificationProvenance(directory, {
          codexDirectory,
          claudeDirectory,
        })),
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
        "CLOCKCHAIN_RECEIPT_MISMATCH",
      );
      assert.equal(verdict.clients.claude.status, "PASS");
    });
  }
});

test("verifier CLI accepts two documented result paths and activates conventional secret canaries", async () => {
  const stdout = memoryOutput();
  const stderr = memoryOutput();
  let captured;
  const customOutput = "artifacts/custom-verdict.json";
  const exitCode = await verifyResultsMain({
    argv: [
      "artifacts/codex/result.json",
      "artifacts/claude/result.json",
      "--manifest",
      "artifacts/client-acceptance.json",
      "--repo-sha",
      REPOSITORY_REF,
      "--output",
      customOutput,
    ],
    async verify(options) {
      captured = options;
      return { status: "PASS" };
    },
    stderr: stderr.stream,
    stdout: stdout.stream,
  });

  assert.equal(exitCode, 0);
  assert.deepEqual(captured.resultDirectories, {
    codex: join(process.cwd(), "artifacts/codex"),
    claude: join(process.cwd(), "artifacts/claude"),
  });
  assert.deepEqual(captured.canaryFiles, [
    join(
      process.cwd(),
      ".context/invitations/codex.secret.json",
    ),
    join(
      process.cwd(),
      ".context/invitations/claude.secret.json",
    ),
  ]);
  assert.equal(
    captured.manifestFile,
    join(process.cwd(), "artifacts/client-acceptance.json"),
  );
  assert.equal(
    captured.expectedRepositorySha,
    REPOSITORY_REF.toLowerCase(),
  );
  assert.equal(
    captured.outputFile,
    join(process.cwd(), customOutput),
  );
  assert.equal(stderr.text(), "");
  assert.match(
    stdout.text(),
    new RegExp(customOutput.replace(".", "\\.")),
  );
});
