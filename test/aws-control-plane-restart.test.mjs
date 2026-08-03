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

test("restarts every stateful boundary without replay or regression", async () => {
  const { stderr, stdout } = await execute(
    process.execPath,
    [CHILD, "restart"],
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
  assert.deepEqual(
    Object.keys(result.restarts).sort(),
    [
      "bootstrap",
      "coordinator",
      "operator",
      "publisher",
      "relay",
      "tunnel",
    ],
  );
  for (const pids of Object.values(
    result.restarts,
  )) {
    assert.equal(pids.length, 2);
    assert.notEqual(pids[0], pids[1]);
  }
  assert.equal(
    result.authenticatedRelayReplay,
    true,
  );
  assert.equal(
    result.sameKeyTunnelReconnect,
    true,
  );
  assert.equal(result.fundingAttempts, 1);
  assert.equal(
    new Set(result.verifierAttemptIds).size,
    result.verifierAttemptIds.length,
  );
  assert.deepEqual(
    result.monitorStates,
    ["FRESH", "STALE", "FRESH"],
  );
  assert.deepEqual(
    result.revisions,
    [...result.revisions].sort(
      (left, right) => left - right,
    ),
  );
  assert.equal(result.paymentMoved, false);
});
