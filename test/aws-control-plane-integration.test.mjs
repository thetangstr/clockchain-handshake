import assert from "node:assert/strict";
import {
  execFile,
} from "node:child_process";
import { promisify } from "node:util";
import { test } from "node:test";

const execute = promisify(execFile);
const CHILD = new URL(
  "helpers/aws-control-plane-child.mjs",
  import.meta.url,
).pathname;

async function scenario(name) {
  const { stderr, stdout } = await execute(
    process.execPath,
    [CHILD, name],
    {
      encoding: "utf8",
      env: Object.fromEntries(
        Object.entries(process.env).filter(
          ([key]) =>
            key !== "NODE_TEST_CONTEXT",
        ),
      ),
      maxBuffer: 1024 * 1024,
      timeout: 30_000,
    },
  );
  assert.equal(stderr, "");
  return JSON.parse(stdout);
}

test("runs the deterministic hosted topology through fresh verification", async () => {
  const result = await scenario("full");
  assert.deepEqual(result.sequence, [
    "START_RUN",
    "PAYER_CLAIM_APPROVED",
    "PAYER_MCP_READY",
    "REQUEST_PAYMENT",
    "HANDSHAKE_REQUIRED",
    "REQUESTOR_CLAIM_APPROVED",
    "FUND",
    "PROPOSED",
    "ACCEPTED",
    "ACKNOWLEDGED",
    "VERIFY",
    "VERIFIED",
  ]);
  assert.equal(result.paymentMoved, false);
  assert.deepEqual(
    result.funding.transfers.map(
      ({ valueWei }) => valueWei,
    ),
    Array(4).fill("10000000000000000"),
  );
  assert.equal(
    new Set(
      result.funding.transfers.map(
        ({ address }) => address,
      ),
    ).size,
    4,
  );
  assert.deepEqual(
    result.receipts.map(
      ({ kind, signerRole }) => [
        kind,
        signerRole,
      ],
    ),
    [
      ["PROPOSED", "payer"],
      ["ACCEPTED", "payee"],
      ["ACKNOWLEDGED", "payer"],
    ],
  );
  assert.equal(
    result.verifier.onlyAuthorityOutput,
    true,
  );
  assert.equal(
    result.verifier.status,
    "VERIFIED",
  );
  assert.equal(
    result.publicMonitor.runStatus,
    "VERIFIED",
  );
  assert.equal(
    result.publicMonitor.anchors.length,
    3,
  );
});
