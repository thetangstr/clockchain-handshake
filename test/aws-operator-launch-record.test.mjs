import assert from "node:assert/strict";
import { test } from "node:test";

import {
  createDurableOperatorLaunchRecord,
} from "../infra/aws/runtime/operator-launch-record.mjs";

const IDENTITY = Object.freeze({
  actionId:
    "11111111-1111-4111-8111-111111111111",
  expectedRevision: 7,
  kind: "verifier",
  releaseId: "release-0123456789abcdef",
  repositorySha:
    "abcdef0123456789abcdef0123456789abcdef01",
  sessionId:
    "22222222-2222-4222-8222-222222222222",
});
const RUNTIME_INPUT = Object.freeze({
  attemptId:
    "33333333-3333-4333-8333-333333333333",
  paymentMoved: false,
  schema:
    "clockchain.aws-runtime-input/v1",
});
const TASK_ARN =
  "arn:aws:ecs:us-west-2:123456789012:task/clockchain/11111111111111111111111111111111";

function fixture() {
  const records = new Map();
  const calls = [];
  return {
    calls,
    records,
    store: {
      async readRecord(key) {
        calls.push(["read", key]);
        return records.get(key) ?? null;
      },
      async writeRecord(key, record) {
        calls.push(["write", key, record]);
        records.set(key, record);
        return record;
      },
    },
  };
}

test("creates and adopts the same exact durable launch intent across retries", async () => {
  const fx = fixture();
  const recorder =
    createDurableOperatorLaunchRecord(fx.store);
  const first = await recorder.prepare({
    actionAtMs: 1000,
    identity: IDENTITY,
    runtimeInput: RUNTIME_INPUT,
  });
  const second = await recorder.prepare({
    actionAtMs: 9999,
    identity: IDENTITY,
    runtimeInput: RUNTIME_INPUT,
  });
  assert.deepEqual(second, first);
  assert.equal(second.actionAtMs, 1000);
  assert.match(
    first.attemptId,
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
  );
  assert.deepEqual(first.clientToken, {
    childTask: "verifier",
    action: "verify",
    fingerprint: first.intentDigest.slice(0, 16),
  });
  assert.deepEqual(
    Object.keys(first.clientToken),
    ["childTask", "action", "fingerprint"],
  );

  const adopted = await recorder.adoptTask({
    identity: IDENTITY,
    runtimeInput: RUNTIME_INPUT,
    taskArn: TASK_ARN,
  });
  const retry = await recorder.prepare({
    actionAtMs: 9999,
    identity: IDENTITY,
    runtimeInput: RUNTIME_INPUT,
  });
  assert.equal(adopted.taskArn, TASK_ARN);
  assert.equal(retry.taskArn, TASK_ARN);
  assert.equal(retry.attemptId, first.attemptId);
  assert.equal(
    fx.calls.filter(([name]) => name === "write").length,
    2,
  );
});

test("rejects changed runtime input, cross-action scope, and conflicting task adoption", async () => {
  const fx = fixture();
  const recorder =
    createDurableOperatorLaunchRecord(fx.store);
  await recorder.prepare({
    actionAtMs: 1000,
    identity: IDENTITY,
    runtimeInput: RUNTIME_INPUT,
  });
  await assert.rejects(
    recorder.prepare({
      actionAtMs: 1000,
      identity: IDENTITY,
      runtimeInput: {
        ...RUNTIME_INPUT,
        attemptId:
          "44444444-4444-4444-8444-444444444444",
      },
    }),
    /AWS operator launch record failed safely/,
  );
  await recorder.adoptTask({
    identity: IDENTITY,
    runtimeInput: RUNTIME_INPUT,
    taskArn: TASK_ARN,
  });
  await assert.rejects(
    recorder.adoptTask({
      identity: IDENTITY,
      runtimeInput: RUNTIME_INPUT,
      taskArn:
        "arn:aws:ecs:us-west-2:123456789012:task/clockchain/22222222222222222222222222222222",
    }),
    /AWS operator launch record failed safely/,
  );
  await assert.rejects(
    recorder.prepare({
      actionAtMs: 1000,
      identity: {
        ...IDENTITY,
        sessionId:
          "55555555-5555-4555-8555-555555555555",
      },
      runtimeInput: RUNTIME_INPUT,
    }),
    /AWS operator launch record failed safely/,
  );
});

test("rejects proxy, accessor, and coercion canary runtime input before store writes", async () => {
  let writes = 0;
  let getterCalls = 0;
  const recorder =
    createDurableOperatorLaunchRecord({
      async readRecord() {
        return null;
      },
      async writeRecord() {
        writes += 1;
      },
    });
  const accessor = {
    paymentMoved: false,
    schema:
      "clockchain.aws-runtime-input/v1",
  };
  Object.defineProperty(accessor, "verifier", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return {};
    },
  });
  const coercion = {
    paymentMoved: false,
    schema:
      "clockchain.aws-runtime-input/v1",
    verifier: {
      get toJSON() {
        getterCalls += 1;
        return () => ({});
      },
    },
  };
  for (const runtimeInput of [
    new Proxy(RUNTIME_INPUT, {}),
    accessor,
    coercion,
  ]) {
    await assert.rejects(
      recorder.prepare({
        actionAtMs: 1000,
        identity: IDENTITY,
        runtimeInput,
      }),
      /AWS operator launch record failed safely/,
    );
  }
  assert.equal(writes, 0);
  assert.equal(getterCalls, 0);
});

test("rejects unsafe runtime arrays without indexed reads or store writes", async () => {
  let writes = 0;
  let getterCalls = 0;
  const recorder =
    createDurableOperatorLaunchRecord({
      async readRecord() {
        return null;
      },
      async writeRecord() {
        writes += 1;
      },
    });
  const accessorArray = [];
  Object.defineProperty(accessorArray, "0", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return "must-not-read";
    },
  });
  Object.defineProperty(accessorArray, "length", {
    value: 1,
  });
  const sparseArray = [];
  sparseArray.length = 1;
  const extraKeyArray = ["safe"];
  extraKeyArray.extra = "not-canonical";
  for (const items of [
    accessorArray,
    sparseArray,
    extraKeyArray,
    new Proxy(["safe"], {}),
  ]) {
    await assert.rejects(
      recorder.prepare({
        actionAtMs: 1000,
        identity: IDENTITY,
        runtimeInput: {
          items,
          paymentMoved: false,
          schema:
            "clockchain.aws-runtime-input/v1",
        },
      }),
      /AWS operator launch record failed safely/,
    );
  }
  assert.equal(writes, 0);
  assert.equal(getterCalls, 0);
});
