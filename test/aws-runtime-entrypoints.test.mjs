import assert from "node:assert/strict";
import {
  lstat,
  mkdtemp,
  readFile,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  installSecretFile,
  parseRuntimeInput,
} from "../infra/aws/runtime/runtime-input.mjs";
import {
  main as coordinatorEntrypoint,
} from "../infra/aws/runtime/coordinator-entrypoint.mjs";
import {
  main as verifierEntrypoint,
} from "../infra/aws/runtime/verifier-entrypoint.mjs";

const VERIFIER_ATTEMPT_ID =
  "11111111-1111-4111-8111-111111111111";
const VERIFIER_TASK_ARN =
  "arn:aws:ecs:us-west-2:123456789012:task/clockchain/11111111111111111111111111111111";

function verifierRuntimeInput(overrides = {}) {
  const verifier = {
    actionAtMs: 2_000_000_000_000,
    attemptId: VERIFIER_ATTEMPT_ID,
    attemptRoot: `/verdict/${VERIFIER_ATTEMPT_ID}`,
    clockchainTokenSecretArn:
      "arn:aws:secretsmanager:us-west-2:123456789012:secret:clockchain-token",
    descriptorPath: "/evidence/descriptor.json",
    evidenceDigest: "d".repeat(64),
    expectedRevision: 5,
    mandateDigest: "e".repeat(64),
    payerMandatePath: "/evidence/payer-mandate.json",
    payeeResultsPath: "/evidence/payee-results",
    payerResultsPath: "/evidence/payer-results",
    paymentRequestPath: "/evidence/payment-request.json",
    publicationPath: "/verdict/task-publication.json",
    repositorySha:
      "abcdef0123456789abcdef0123456789abcdef01",
    requestDigest: "f".repeat(64),
    rpcSecretArn:
      "arn:aws:secretsmanager:us-west-2:123456789012:secret:rpc-url",
    sessionDigest: "a".repeat(64),
    ...overrides,
  };
  return JSON.stringify({
    paymentMoved: false,
    schema: "clockchain.aws-runtime-input/v1",
    verifier,
  });
}

test("every AWS task entrypoint is present and no production entrypoint is a placeholder", async () => {
  for (const name of [
    "bootstrap",
    "coordinator",
    "funding",
    "operator-worker",
    "publisher",
    "relay",
    "tunnel",
    "verifier",
  ]) {
    const path =
      `infra/aws/runtime/${name}-entrypoint.mjs`;
    const source = await readFile(path, "utf8");
    assert.doesNotMatch(
      source,
      /wiring is supplied by the deployed task definition/i,
      path,
    );
    const module = await import(
      `../${path}?test=${Date.now()}-${name}`
    );
    assert.equal(
      typeof module.main,
      "function",
      path,
    );
  }
});

test("runtime input accepts one exact canonical JSON object and rejects ambiguous environment data", () => {
  assert.deepEqual(
    parseRuntimeInput({
      AWS_RUNTIME_INPUT:
        '{"paymentMoved":false,"schema":"clockchain.aws-runtime-input/v1"}',
    }),
    {
      paymentMoved: false,
      schema: "clockchain.aws-runtime-input/v1",
    },
  );
  for (const value of [
    "",
    " {}",
    "{}\n",
    '{"schema":"clockchain.aws-runtime-input/v1","paymentMoved":false}',
    '{"paymentMoved":true,"schema":"clockchain.aws-runtime-input/v1"}',
  ]) {
    assert.throws(
      () =>
        parseRuntimeInput({
          AWS_RUNTIME_INPUT: value,
        }),
      /AWS runtime input failed safely/,
    );
  }
});

test("secret material is installed atomically with mode 0600 and never returned", async () => {
  const root = await mkdtemp(
    join(tmpdir(), "clockchain-runtime-"),
  );
  const path = join(root, "secret");
  const calls = [];
  const result = await installSecretFile({
    client: {
      async send(command) {
        calls.push(command.input);
        return {
          SecretString: "secret-canary",
        };
      },
    },
    commandFactory: (input) => ({
      input,
    }),
    path,
    secretArn:
      "arn:aws:secretsmanager:us-west-2:123456789012:secret:demo",
    validate: (value) =>
      value === "secret-canary",
  });
  assert.equal(result, undefined);
  assert.deepEqual(calls, [
    {
      SecretId:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:demo",
    },
  ]);
  assert.equal(
    (await lstat(path)).mode & 0o777,
    0o600,
  );
  assert.equal(
    await readFile(path, "utf8"),
    "secret-canary",
  );
  await writeFile(
    join(root, "already"),
    "existing",
    { mode: 0o600 },
  );
  await assert.rejects(
    installSecretFile({
      client: {
        async send() {
          return {
            SecretString: "replacement",
          };
        },
      },
      commandFactory: (input) => ({
        input,
      }),
      path: join(root, "already"),
      secretArn:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:demo",
      validate: () => true,
    }),
    /AWS runtime input failed safely/,
  );
});

test("coordinator entrypoint binds the operator-created release and session identity", async () => {
  const calls = [];
  await coordinatorEntrypoint({
    env: {
      AWS_RUNTIME_INPUT:
        '{"coordinator":{"argv":["--test"],"releaseIdentity":{"releaseId":"release-bd7662a5eeb41614","sessionId":"11111111-1111-4111-8111-111111111111"}},"paymentMoved":false,"schema":"clockchain.aws-runtime-input/v1"}',
    },
    run: async (argv, dependencies) => {
      calls.push([
        argv,
        dependencies.releaseIdentity,
      ]);
      return 0;
    },
  });
  assert.deepEqual(calls, [
    [
      ["--test"],
      {
        releaseId:
          "release-bd7662a5eeb41614",
        sessionId:
          "11111111-1111-4111-8111-111111111111",
      },
    ],
  ]);
});

test("verifier entrypoint resolves metadata and secrets before running the canonical verifier task", async () => {
  const root = await mkdtemp(
    join(tmpdir(), "clockchain-verifier-entrypoint-"),
  );
  const calls = [];
  const result = await verifierEntrypoint({
    client: {
      async send(command) {
        calls.push(["secret", command.input]);
        return {
          SecretString:
            command.input.SecretId.endsWith("rpc-url")
              ? "https://sepolia.example.invalid/path?api_key=provider"
              : "clockchain-token-canary",
        };
      },
    },
    env: {
      AWS_RUNTIME_INPUT:
        verifierRuntimeInput(),
      ECS_CONTAINER_METADATA_URI_V4:
        "http://169.254.170.2/v4/metadata/container",
    },
    fetch: async (url) => {
      calls.push(["fetch", url]);
      return {
        ok: true,
        async json() {
          return {
            TaskARN: VERIFIER_TASK_ARN,
          };
        },
      };
    },
    run: async (input) => {
      const tokenMode =
        (await lstat(input.clockchainTokenFile))
          .mode & 0o777;
      calls.push([
        "run",
        {
          ...input,
          clockchainTokenFileMode: tokenMode,
          clockchainTokenValue: await readFile(
            input.clockchainTokenFile,
            "utf8",
          ),
        },
      ]);
      return {
        paymentMoved: false,
        verifier: { status: "VERIFIED" },
      };
    },
    tempDir: root,
  });
  assert.deepEqual(result, {
    paymentMoved: false,
    verifier: { status: "VERIFIED" },
  });
  assert.deepEqual(calls.slice(0, 3), [
    [
      "fetch",
      "http://169.254.170.2/v4/metadata/container/task",
    ],
    [
      "secret",
      {
        SecretId:
          "arn:aws:secretsmanager:us-west-2:123456789012:secret:clockchain-token",
      },
    ],
    [
      "secret",
      {
        SecretId:
          "arn:aws:secretsmanager:us-west-2:123456789012:secret:rpc-url",
      },
    ],
  ]);
  const runInput = calls.find(
    ([name]) => name === "run",
  )[1];
  assert.deepEqual(runInput, {
    actionAtMs: 2_000_000_000_000,
    attemptId: VERIFIER_ATTEMPT_ID,
    attemptRoot: `/verdict/${VERIFIER_ATTEMPT_ID}`,
    clockchainTokenFile:
      runInput.clockchainTokenFile,
    clockchainTokenFileMode: 0o600,
    clockchainTokenValue:
      "clockchain-token-canary",
    descriptorPath: "/evidence/descriptor.json",
    evidenceDigest: "d".repeat(64),
    expectedRevision: 5,
    mandateDigest: "e".repeat(64),
    payerMandatePath:
      "/evidence/payer-mandate.json",
    payeeResultsPath: "/evidence/payee-results",
    payerResultsPath: "/evidence/payer-results",
    paymentRequestPath:
      "/evidence/payment-request.json",
    publicationPath:
      "/verdict/task-publication.json",
    repositorySha:
      "abcdef0123456789abcdef0123456789abcdef01",
    requestDigest: "f".repeat(64),
    rpcUrl:
      "https://sepolia.example.invalid/path?api_key=provider",
    sessionDigest: "a".repeat(64),
    taskArn: VERIFIER_TASK_ARN,
  });
  await assert.rejects(
    lstat(runInput.clockchainTokenFile),
    { code: "ENOENT" },
  );
});

test("verifier entrypoint fails closed before secret reads for unsafe runtime input and metadata", async () => {
  const safeEnv = () => ({
    AWS_RUNTIME_INPUT: verifierRuntimeInput(),
    ECS_CONTAINER_METADATA_URI_V4:
      "http://169.254.170.2/v4/metadata/container",
  });
  const cases = [
    {
      env: {
        ...safeEnv(),
        AWS_RUNTIME_INPUT: JSON.stringify({
          paymentMoved: false,
          schema:
            "clockchain.aws-runtime-input/v1",
          verifier: JSON.parse(
            verifierRuntimeInput(),
          ).verifier,
          z: "unknown",
        }),
      },
    },
    {
      env: {
        ...safeEnv(),
        AWS_RUNTIME_INPUT:
          verifierRuntimeInput({
            taskArn: VERIFIER_TASK_ARN,
          }),
      },
    },
    {
      env: {
        ...safeEnv(),
        AWS_RUNTIME_INPUT:
          verifierRuntimeInput({
            clockchainTokenFile: "/tmp/token",
          }),
      },
    },
    {
      env: {
        ...safeEnv(),
        AWS_RUNTIME_INPUT:
          verifierRuntimeInput({
            rpcUrl:
              "https://sepolia.example.invalid",
          }),
      },
    },
    {
      env: {
        ...safeEnv(),
        AWS_RUNTIME_INPUT:
          verifierRuntimeInput({
            descriptorPath: "relative.json",
          }),
      },
    },
    {
      env: {
        ...safeEnv(),
        AWS_RUNTIME_INPUT:
          verifierRuntimeInput({
            repositorySha: "a".repeat(39),
          }),
      },
    },
    {
      env: {
        ...safeEnv(),
        ECS_CONTAINER_METADATA_URI_V4:
          "http://example.invalid/v4/metadata/container",
      },
    },
    {
      env: {
        ...safeEnv(),
        ECS_CONTAINER_METADATA_URI_V4:
          "http://169.254.170.2/v4/metadata/container?x=1",
      },
    },
    {
      env: safeEnv(),
      fetch: async () => ({
        ok: true,
        async json() {
          return {
            TaskARN:
              "arn:aws:ecs:us-west-2:123456789012:task/clockchain/not-a-task-id",
          };
        },
      }),
    },
  ];
  for (const options of cases) {
    let secretReads = 0;
    await assert.rejects(
      verifierEntrypoint({
        client: {
          async send() {
            secretReads += 1;
            return { SecretString: "secret" };
          },
        },
        env: options.env,
        fetch:
          options.fetch ??
          (async () => ({
            ok: true,
            async json() {
              return {
                TaskARN: VERIFIER_TASK_ARN,
              };
            },
          })),
        run: async () => {},
        tempDir: tmpdir(),
      }),
      /AWS verifier entrypoint failed safely|AWS runtime input failed safely/,
    );
    assert.equal(secretReads, 0);
  }
});

test("verifier entrypoint rejects invalid secrets and preexisting token paths without leaking secret output", async () => {
  const root = await mkdtemp(
    join(tmpdir(), "clockchain-verifier-entrypoint-"),
  );
  await writeFile(
    join(root, "clockchain-token"),
    "preexisting",
    { mode: 0o600 },
  );
  for (const secrets of [
    ["token\u0000value", "https://sepolia.example.invalid"],
    ["token", "http://sepolia.example.invalid"],
    ["token", "https://user@sepolia.example.invalid"],
    ["token", "https://sepolia.example.invalid/#fragment"],
    ["token", "https://sepolia.example.invalid/"],
  ]) {
    const stderr = [];
    await assert.rejects(
      verifierEntrypoint({
        client: {
          async send(command) {
            return {
              SecretString:
                command.input.SecretId.endsWith("rpc-url")
                  ? secrets[1]
                  : secrets[0],
            };
          },
        },
        env: {
          AWS_RUNTIME_INPUT:
            verifierRuntimeInput(),
          ECS_CONTAINER_METADATA_URI_V4:
            "http://169.254.170.2/v4/metadata/container",
        },
        fetch: async () => ({
          ok: true,
          async json() {
            return {
              TaskARN: VERIFIER_TASK_ARN,
            };
          },
        }),
        run: async () => {},
        stderr: {
          write(value) {
            stderr.push(value);
          },
        },
        tempDir: root,
      }),
      /AWS verifier entrypoint failed safely|AWS runtime input failed safely/,
    );
    assert.equal(stderr.join(""), "");
  }
  assert.equal(
    await readFile(
      join(root, "clockchain-token"),
      "utf8",
    ),
    "preexisting",
  );
});
