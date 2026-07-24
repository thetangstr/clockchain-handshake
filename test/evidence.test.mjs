import assert from "node:assert/strict";
import {
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  computeReceiptEventHash,
  EvidenceRedactionError,
  EvidenceValidationError,
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

function validReceiptEvent() {
  return {
    agentId: "42",
    action: "trust_handshake",
    inputs: {
      runId: RUN_ID,
      identityReference:
        `eip155:11155111:${REGISTRY}:42`,
      counterparty: "clockchain:handshake",
      authorization: {
        amount: "100",
        currency: "USD",
        settlement: "not-executed",
      },
    },
    outputs: {
      decision: "approved-for-demo",
      scope: "identity-and-time-receipt-only",
      paymentMoved: false,
    },
  };
}

test("computes the deployed canonical receipt event hash", () => {
  assert.equal(
    computeReceiptEventHash(validReceiptEvent()),
    "19f9abc99b6d2b65e50629bd025bffebd991fd5ee22bad92234829d014cb3b10",
  );
});

test("hashes a nested own enumerable __proto__ key", () => {
  const cleanEvent = validReceiptEvent();
  const hostileEvent = validReceiptEvent();
  Object.defineProperty(
    hostileEvent.inputs.authorization,
    "__proto__",
    {
      enumerable: true,
      value: "own-data",
    },
  );

  assert.notEqual(
    computeReceiptEventHash(hostileEvent),
    computeReceiptEventHash(cleanEvent),
  );
});

test("rejects non-plain or non-JSON-safe receipt events without echoing values", () => {
  const secret = "receipt-event-secret-canary";
  const accessorInputs = {};
  Object.defineProperty(accessorInputs, "leak", {
    enumerable: true,
    get() {
      throw new Error(secret);
    },
  });
  const cyclicInputs = {};
  cyclicInputs.self = cyclicInputs;
  const cases = [
    undefined,
    {
      ...validReceiptEvent(),
      inputs: { omitted: undefined },
    },
    {
      ...validReceiptEvent(),
      inputs: { invalidNumber: Number.NaN },
    },
    {
      ...validReceiptEvent(),
      outputs: new Date("2026-07-23T07:00:00.000Z"),
    },
    {
      ...validReceiptEvent(),
      inputs: accessorInputs,
    },
    {
      ...validReceiptEvent(),
      inputs: cyclicInputs,
    },
  ];

  for (const event of cases) {
    assert.throws(
      () => computeReceiptEventHash(event),
      (error) => {
        assert.ok(error instanceof EvidenceValidationError);
        assert.equal(error.code, "HANDSHAKE_RESULT_INVALID");
        assert.equal(error.message, "Handshake PASS result is invalid.");
        assert.equal(error.message.includes(secret), false);
        return true;
      },
    );
  }
});

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

test("restores the exact prior pair when the second publication rename fails", async (t) => {
  const directory = await temporaryDirectory(t);
  const jsonPath = join(directory, "result.json");
  const markdownPath = join(directory, "RESULT.md");
  const priorJson = "{\"prior\":\"json\"}\n";
  const priorMarkdown = "# Prior PASS\n";
  await writeFile(jsonPath, priorJson, "utf8");
  await writeFile(markdownPath, priorMarkdown, "utf8");
  let rejectedSecondRename = false;

  await assert.rejects(
    () =>
      writeEvidence({
        directory,
        result: validResult(),
        canaries: [],
        fileSystem: {
          async rename(source, destination) {
            if (
              !rejectedSecondRename &&
              destination === markdownPath &&
              source.includes(".result.")
            ) {
              rejectedSecondRename = true;
              throw new Error("injected second rename failure");
            }
            return rename(source, destination);
          },
        },
      }),
    /evidence/i,
  );

  assert.equal(rejectedSecondRename, true);
  assert.equal(await readFile(jsonPath, "utf8"), priorJson);
  assert.equal(
    await readFile(markdownPath, "utf8"),
    priorMarkdown,
  );
  assert.deepEqual(
    (await readdir(directory)).sort(),
    ["RESULT.md", "result.json"],
  );
});

test("removes newly published finals when final read-back fails without a prior pair", async (t) => {
  const directory = await temporaryDirectory(t);
  const jsonPath = join(directory, "result.json");
  let publicationRenames = 0;
  let rejectedFinalRead = false;

  await assert.rejects(
    () =>
      writeEvidence({
        directory,
        result: validResult(),
        canaries: [],
        fileSystem: {
          async readFile(path, options) {
            if (
              publicationRenames === 2 &&
              path === jsonPath &&
              !rejectedFinalRead
            ) {
              rejectedFinalRead = true;
              throw new Error("injected final read failure");
            }
            return readFile(path, options);
          },
          async rename(source, destination) {
            const value = await rename(source, destination);
            if (
              destination === jsonPath ||
              destination === join(directory, "RESULT.md")
            ) {
              publicationRenames += 1;
            }
            return value;
          },
        },
      }),
    /evidence/i,
  );

  assert.equal(rejectedFinalRead, true);
  assert.deepEqual(await readdir(directory), []);
});
