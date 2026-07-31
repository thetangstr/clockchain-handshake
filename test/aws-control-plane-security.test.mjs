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

test("hostile topology inputs fail closed without public or log leakage", async () => {
  const canaries = [
    "operator-secret-canary",
    "stakeholder-secret-canary",
  ];
  const { stderr, stdout } = await execute(
    process.execPath,
    [CHILD, "hostile", ...canaries],
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
  const result = JSON.parse(stdout);
  assert.deepEqual(result.rejected.sort(), [
    "changed-claim",
    "changed-mcp-fingerprint",
    "duplicate-relay-evidence",
    "extra-listen-port",
    "funding-journal-ambiguity",
    "mismatched-anchor",
    "reordered-relay-evidence",
    "second-stakeholder-session",
    "stale-action",
    "unapproved-ssh-key",
  ]);
  assert.equal(result.fundingAttempts, 0);
  assert.equal(result.anchorWrites, 0);
  assert.equal(result.paymentMoved, false);
  const publicAndLogs = JSON.stringify({
    logs: result.logs,
    public: result.public,
  });
  for (const canary of canaries) {
    assert.equal(
      publicAndLogs.includes(canary),
      false,
    );
  }
});
