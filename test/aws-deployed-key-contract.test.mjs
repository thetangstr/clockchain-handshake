import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const DEPLOYED_OPERATOR_KEY_ID =
  "clockchain-demo-2026";

test("the deployed AWS operator key is available to a frozen public checkout", async () => {
  const deployedKey = await readFile(
    new URL(
      `../docs/operator-keys/${DEPLOYED_OPERATOR_KEY_ID}.pub`,
      import.meta.url,
    ),
    "utf8",
  );
  const reviewedKey = await readFile(
    new URL(
      "../docs/operator-keys/bilateral-demo-2026-07-28.pub",
      import.meta.url,
    ),
    "utf8",
  );

  assert.match(deployedKey, /^[A-Za-z0-9+/]{43}=\n$/);
  assert.equal(deployedKey, reviewedKey);
});
