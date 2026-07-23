import assert from "node:assert/strict";
import {
  mkdtemp,
  readFile,
  readdir,
  rm,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  EvidenceRedactionError,
  renderResultMarkdown,
  validatePassResult,
  writeEvidence,
} from "../src/evidence.mjs";
import {
  RESULT_SCHEMA,
  SINGLE_VALIDATOR_DISCLAIMER,
} from "../src/constants.mjs";

const RUN_ID = "123e4567-e89b-42d3-a456-426614174000";
const OWNER = "0x1111111111111111111111111111111111111111";
const REGISTER_TX = `0x${"22".repeat(32)}`;
const METADATA_TX = `0x${"33".repeat(32)}`;
const REGISTRY =
  "0x8004A818BFB912233c491871b3d84c89A494BD9e";

function validResult(overrides = {}) {
  const base = {
    schema: RESULT_SCHEMA,
    status: "PASS",
    runId: RUN_ID,
    startedAt: "2026-07-23T07:00:00.000Z",
    completedAt: "2026-07-23T07:00:01.234Z",
    elapsedMs: 1_234,
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
      reference: `eip155:11155111:${REGISTRY}:42`,
      agentId: "42",
      displayName: "Billy",
      owner: OWNER,
      registerTx: REGISTER_TX,
      metadataTx: METADATA_TX,
    },
    clockchain: {
      ledgerId: "223e4567-e89b-42d3-a456-426614174001",
      blockHeight: "123",
      consensusTime: "23-07-2026_07:00:01:234",
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

  return {
    ...base,
    ...overrides,
    scenario: {
      ...base.scenario,
      ...overrides.scenario,
      amount: {
        ...base.scenario.amount,
        ...overrides.scenario?.amount,
      },
    },
    identity: {
      ...base.identity,
      ...overrides.identity,
    },
    clockchain: {
      ...base.clockchain,
      ...overrides.clockchain,
      poolHealth:
        overrides.clockchain?.poolHealth === undefined
          ? base.clockchain.poolHealth
          : overrides.clockchain.poolHealth,
    },
  };
}

async function temporaryDirectory(t) {
  const directory = await mkdtemp(
    join(tmpdir(), "handshake-evidence-test-"),
  );
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}

test("validates the exact PASS schema including truthful submission pool health", () => {
  const result = validResult();

  assert.equal(validatePassResult(result), result);
  assert.throws(
    () =>
      validatePassResult({
        ...result,
        unexpected: true,
      }),
    /result/i,
  );
  assert.throws(
    () =>
      validatePassResult(
        validResult({
          clockchain: {
            poolHealth: {
              totalNodes: 1,
              nodeParticipationPct: 0,
              degradedAtSubmission: false,
            },
          },
        }),
      ),
    /pool|result/i,
  );
});

test("rejects incomplete identity and verification evidence", () => {
  const cases = [
    validResult({ identity: { registerTx: undefined } }),
    validResult({ identity: { metadataTx: null } }),
    validResult({ clockchain: { blockHeight: null } }),
    validResult({ clockchain: { receiptVerified: false } }),
    validResult({ clockchain: { crossPartyVerified: false } }),
    validResult({ clockchain: { verifiedAgainst: "cache" } }),
    validResult({ clockchain: { keyless: false } }),
    validResult({ clockchain: { receiptStatus: "pending" } }),
  ];

  for (const result of cases) {
    assert.throws(() => validatePassResult(result), /result/i);
  }
});

test("renders Markdown with fixed claims, transaction links, and escaped untrusted text", () => {
  const markdown = renderResultMarkdown(
    validResult({
      identity: {
        displayName: "Billy [ops](unsafe)\u001b[31m\n# heading",
      },
      clockchain: {
        consensusTime: "time` **unsafe**",
      },
    }),
  );

  assert.match(markdown, /^# Clockchain Handshake result/m);
  assert.match(markdown, /Status: PASS/);
  assert.match(
    markdown,
    new RegExp(
      `https://sepolia\\.etherscan\\.io/tx/${REGISTER_TX}`,
    ),
  );
  assert.match(
    markdown,
    new RegExp(
      `https://sepolia\\.etherscan\\.io/tx/${METADATA_TX}`,
    ),
  );
  assert.match(markdown, /Degraded at submission: yes/);
  assert.match(markdown, /Node participation: 0%/);
  assert.equal(
    markdown.includes("Billy \\[ops\\]\\(unsafe\\)"),
    true,
  );
  assert.equal(markdown.includes("\u001b"), false);
  assert.equal(markdown.includes("\n# heading"), false);
  assert.equal(
    markdown.includes("Consensus time: time\\` \\*\\*unsafe\\*\\*"),
    true,
  );
  assert.match(markdown, new RegExp(SINGLE_VALIDATOR_DISCLAIMER));
});

test("writes, re-reads, and cross-checks both final evidence files", async (t) => {
  const directory = await temporaryDirectory(t);
  const result = validResult();

  const paths = await writeEvidence({
    directory,
    result,
    canaries: [
      "invitation-code-canary",
      `0x${"aa".repeat(32)}`,
      `cc_${"b".repeat(48)}`,
    ],
  });

  assert.deepEqual(paths, {
    jsonPath: join(directory, "result.json"),
    markdownPath: join(directory, "RESULT.md"),
  });
  assert.deepEqual(
    JSON.parse(await readFile(paths.jsonPath, "utf8")),
    result,
  );
  assert.equal(
    await readFile(paths.markdownPath, "utf8"),
    renderResultMarkdown(result),
  );
  assert.deepEqual(
    (await readdir(directory)).sort(),
    ["RESULT.md", "result.json"],
  );
});

test("fails closed when redaction changes a canary and leaves no artifact", async (t) => {
  const directory = await temporaryDirectory(t);
  const code = "fresh-invitation-code-canary";
  const result = validResult({
    identity: {
      displayName: `Billy ${code}`,
    },
  });

  await assert.rejects(
    () =>
      writeEvidence({
        directory,
        result,
        canaries: [code],
      }),
    (error) => {
      assert.ok(error instanceof EvidenceRedactionError);
      assert.equal(error.category, "redaction");
      assert.equal(error.code, "HANDSHAKE_EVIDENCE_REDACTION");
      assert.equal(error.message.includes(code), false);
      assert.equal(error.stack.includes(code), false);
      return true;
    },
  );
  assert.deepEqual(await readdir(directory), []);
});
