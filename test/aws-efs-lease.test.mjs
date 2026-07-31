import assert from "node:assert/strict";
import {
  chmod,
  link,
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  AWS_EFS_LEASE_FILE,
  createAwsEfsLeaseManager,
} from "../src/bilateral/aws/efs-lease.mjs";

const TASK_A =
  "arn:aws:ecs:us-west-2:123456789012:task/clockchain/11111111111111111111111111111111";
const TASK_B =
  "arn:aws:ecs:us-west-2:123456789012:task/clockchain/22222222222222222222222222222222";
const NONCE_A = "11111111-1111-4111-8111-111111111111";
const NONCE_B = "22222222-2222-4222-8222-222222222222";
const START = 2_000_000_000_000;
const TTL = 10_000;

async function privateRoot(t) {
  const root = await mkdtemp(join(tmpdir(), "aws-efs-lease-"));
  await chmod(root, 0o700);
  t.after(() => rm(root, { force: true, recursive: true }));
  return root;
}

function manager({
  leasePath,
  now,
  nonce = NONCE_A,
  ownerTaskArn = TASK_A,
} = {}) {
  return createAwsEfsLeaseManager({
    leasePath,
    nowMs: now,
    ownerTaskArn,
    randomUUID: () => nonce,
    ttlMs: TTL,
  });
}

test("acquires, heartbeats, asserts, and releases an ECS-task lease without a PID", async (t) => {
  const root = await privateRoot(t);
  const leasePath = join(root, "relay-owner");
  let now = START;
  const handle = await manager({
    leasePath,
    now: () => now,
  }).acquire();
  assert.deepEqual(handle.record, {
    acquiredAtMs: String(START),
    expiresAtMs: String(START + TTL),
    leaseNonce: NONCE_A,
    ownerTaskArn: TASK_A,
    schema: "clockchain.aws-efs-lease/v1",
  });
  const recordPath = join(
    leasePath,
    AWS_EFS_LEASE_FILE,
  );
  assert.deepEqual(
    JSON.parse(await readFile(recordPath, "utf8")),
    handle.record,
  );
  assert.equal(
    (await readFile(recordPath, "utf8")).includes("pid"),
    false,
  );

  now += 4_000;
  const heartbeat = await handle.heartbeat();
  assert.equal(
    heartbeat.expiresAtMs,
    String(now + TTL),
  );
  await handle.assertCurrent();
  await handle.release();
  await assert.rejects(handle.assertCurrent());
});

test("rejects live contention and permits one expired takeover with old-owner fencing", async (t) => {
  const root = await privateRoot(t);
  const leasePath = join(root, "coordinator-owner");
  let now = START;
  const first = await manager({
    leasePath,
    now: () => now,
  }).acquire();
  await assert.rejects(
    manager({
      leasePath,
      nonce: NONCE_B,
      now: () => now,
      ownerTaskArn: TASK_B,
    }).acquire(),
    /AWS EFS lease failed safely/,
  );

  now += TTL;
  const second = await manager({
    leasePath,
    nonce: NONCE_B,
    now: () => now,
    ownerTaskArn: TASK_B,
  }).acquire();
  assert.equal(second.record.ownerTaskArn, TASK_B);
  assert.equal(second.record.leaseNonce, NONCE_B);
  await assert.rejects(
    first.heartbeat(),
    /AWS EFS lease failed safely/,
  );
  await second.assertCurrent();
  await second.release();
});

test("fails closed on clock rollback, malformed records, symlinks, and hard links", async (t) => {
  const root = await privateRoot(t);
  const leasePath = join(root, "worker-owner");
  let now = START;
  const handle = await manager({
    leasePath,
    now: () => now,
  }).acquire();
  now -= 1;
  await assert.rejects(
    handle.heartbeat(),
    /AWS EFS lease failed safely/,
  );
  now = START;

  const recordPath = join(
    leasePath,
    AWS_EFS_LEASE_FILE,
  );
  const hardLinkPath = join(root, "lease-hard-link");
  await link(recordPath, hardLinkPath);
  await assert.rejects(
    handle.assertCurrent(),
    /AWS EFS lease failed safely/,
  );
  await rm(hardLinkPath);

  const malformedPath = join(root, "malformed");
  await mkdir(malformedPath, { mode: 0o700 });
  await writeFile(
    join(malformedPath, AWS_EFS_LEASE_FILE),
    '{"schema":"clockchain.aws-efs-lease/v1"}',
    { mode: 0o600 },
  );
  await assert.rejects(
    manager({
      leasePath: malformedPath,
      now: () => START + TTL,
    }).acquire(),
    /AWS EFS lease failed safely/,
  );

  const symlinkPath = join(root, "symlink");
  const targetPath = join(root, "target");
  await mkdir(symlinkPath, { mode: 0o700 });
  await writeFile(targetPath, "{}", { mode: 0o600 });
  await symlink(
    targetPath,
    join(symlinkPath, AWS_EFS_LEASE_FILE),
  );
  await assert.rejects(
    manager({
      leasePath: symlinkPath,
      now: () => START + TTL,
    }).acquire(),
    /AWS EFS lease failed safely/,
  );
});

test("rejects an exact-byte lease record replacement after acquisition", async (t) => {
  const root = await privateRoot(t);
  const leasePath = join(root, "replaced-record");
  const handle = await manager({
    leasePath,
    now: () => START,
  }).acquire();
  const recordPath = join(
    leasePath,
    AWS_EFS_LEASE_FILE,
  );
  const replacementPath = join(
    leasePath,
    ".replacement",
  );
  await writeFile(
    replacementPath,
    await readFile(recordPath),
    { mode: 0o600 },
  );
  await rename(replacementPath, recordPath);
  await assert.rejects(
    handle.assertCurrent(),
    /AWS EFS lease failed safely/,
  );
});

test("recovers an expired crash tombstone using task identity rather than process identity", async (t) => {
  const root = await privateRoot(t);
  const leasePath = join(root, "crashed-owner");
  let now = START;
  await manager({
    leasePath,
    now: () => now,
  }).acquire();

  now += TTL + 1;
  const recovered = await manager({
    leasePath,
    nonce: NONCE_B,
    now: () => now,
    ownerTaskArn: TASK_A,
  }).acquire();
  assert.equal(recovered.record.ownerTaskArn, TASK_A);
  assert.equal(recovered.record.leaseNonce, NONCE_B);
  assert.equal(
    JSON.stringify(recovered.record).includes(
      String(process.pid),
    ),
    false,
  );
  await recovered.release();
});
