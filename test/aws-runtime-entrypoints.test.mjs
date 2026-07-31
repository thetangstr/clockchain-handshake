import assert from "node:assert/strict";
import {
  lstat,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
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
  const calls = [];
  const results = [];
  for (let index = 0; index < 2; index += 1) {
    results.push(
      await verifierEntrypoint({
        client: {
          async send(command) {
            calls.push(["secret", command.input]);
            return {
              SecretString:
                command.input.SecretId.endsWith("rpc-url")
                  ? "https://ethereum-rpc.publicnode.com/path?api_key=provider"
                  : `clockchain-token-canary-${index}`,
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
            (await lstat(
              input.clockchainTokenFile,
            )).mode & 0o777;
          const tokenDir =
            dirname(input.clockchainTokenFile);
          const tokenDirMode =
            (await lstat(tokenDir)).mode & 0o777;
          calls.push([
            "run",
            {
              ...input,
              clockchainTokenFileMode: tokenMode,
              clockchainTokenDir: tokenDir,
              clockchainTokenDirMode:
                tokenDirMode,
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
      }),
    );
  }
  assert.deepEqual(results, [
    {
      paymentMoved: false,
      verifier: { status: "VERIFIED" },
    },
    {
      paymentMoved: false,
      verifier: { status: "VERIFIED" },
    },
  ]);
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
  const runInputs = calls
    .filter(([name]) => name === "run")
    .map(([, input]) => input);
  assert.equal(runInputs.length, 2);
  assert.notEqual(
    runInputs[0].clockchainTokenFile,
    runInputs[1].clockchainTokenFile,
  );
  assert.notEqual(
    runInputs[0].clockchainTokenDir,
    runInputs[1].clockchainTokenDir,
  );
  for (const [index, runInput] of runInputs.entries()) {
    assert.deepEqual(runInput, {
      actionAtMs: 2_000_000_000_000,
      attemptId: VERIFIER_ATTEMPT_ID,
      attemptRoot: `/verdict/${VERIFIER_ATTEMPT_ID}`,
      clockchainTokenFile:
        runInput.clockchainTokenFile,
      clockchainTokenDir:
        runInput.clockchainTokenDir,
      clockchainTokenDirMode: 0o700,
      clockchainTokenFileMode: 0o600,
      clockchainTokenValue:
        `clockchain-token-canary-${index}`,
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
        "https://ethereum-rpc.publicnode.com/path?api_key=provider",
      sessionDigest: "a".repeat(64),
      taskArn: VERIFIER_TASK_ARN,
    });
    await assert.rejects(
      lstat(runInput.clockchainTokenFile),
      { code: "ENOENT" },
    );
    await assert.rejects(
      lstat(runInput.clockchainTokenDir),
      { code: "ENOENT" },
    );
  }
});

test("verifier entrypoint rejects cleanup failure after run and attempts token and scratch removal", async () => {
  const root = await mkdtemp(
    join(tmpdir(), "clockchain-verifier-entrypoint-"),
  );
  const scratch = join(root, "clockchain-verifier-");
  const calls = [];
  try {
    await assert.rejects(
      verifierEntrypoint({
        client: {
          async send(command) {
            return {
              SecretString:
                command.input.SecretId.endsWith("rpc-url")
                  ? "https://ethereum-rpc.publicnode.com/path?api_key=provider"
                  : "clockchain-token-canary",
            };
          },
        },
        createTempDir: async (prefix) => {
          const path = await mkdtemp(
            `${scratch}-`,
          );
          calls.push([
            "createTempDir",
            prefix,
            path,
          ]);
          return path;
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
        removeDir: async (path) => {
          calls.push(["removeDir", path]);
          throw new Error("dir cleanup canary");
        },
        removeFile: async (path) => {
          calls.push(["removeFile", path]);
          throw new Error("file cleanup canary");
        },
        run: async () => {
          calls.push(["run"]);
          return {
            paymentMoved: false,
            verifier: { status: "VERIFIED" },
          };
        },
      }),
      (error) => {
        assert.equal(
          error.message,
          "AWS verifier entrypoint failed safely.",
        );
        assert.doesNotMatch(
          String(error),
          /cleanup canary|clockchain-token-canary|ethereum-rpc/,
        );
        return true;
      },
    );
  } finally {
    await rm(root, {
      force: true,
      recursive: true,
    });
  }
  const scratchDir = calls[0][2];
  assert.deepEqual(calls, [
    [
      "createTempDir",
      join(tmpdir(), "clockchain-verifier-"),
      scratchDir,
    ],
    ["run"],
    [
      "removeFile",
      join(scratchDir, "clockchain-token"),
    ],
    ["removeDir", scratchDir],
  ]);
});

test("verifier entrypoint rejects invalid token secrets before creating scratch space", async () => {
  const calls = [];
  await assert.rejects(
    verifierEntrypoint({
      client: {
        async send(command) {
          calls.push(command.input.SecretId);
          return {
            SecretString: "token\u0000value",
          };
        },
      },
      createTempDir: async () => {
        calls.push("createTempDir");
        throw new Error(
          "scratch should not be created",
        );
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
      run: async () => {
        calls.push("run");
      },
    }),
    /AWS verifier entrypoint failed safely|AWS runtime input failed safely/,
  );
  assert.deepEqual(calls, [
    "arn:aws:secretsmanager:us-west-2:123456789012:secret:clockchain-token",
  ]);
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

test("verifier entrypoint rejects invalid Clockchain token secrets before RPC lookup or run", async () => {
  const root = await mkdtemp(
    join(tmpdir(), "clockchain-verifier-entrypoint-"),
  );
  const calls = [];
  await assert.rejects(
    verifierEntrypoint({
      client: {
        async send(command) {
          calls.push(command.input.SecretId);
          return {
            SecretString: "token\u0000value",
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
      run: async () => {
        calls.push("run");
      },
      tempDir: root,
    }),
    (error) => {
      assert.match(
        error.message,
        /AWS verifier entrypoint failed safely|AWS runtime input failed safely/,
      );
      assert.doesNotMatch(
        String(error),
        /token\u0000value/,
      );
      return true;
    },
  );
  assert.deepEqual(calls, [
    "arn:aws:secretsmanager:us-west-2:123456789012:secret:clockchain-token",
  ]);
});

test("verifier entrypoint rejects noncanonical, reserved, or private RPC URLs before installing the token or running", async () => {
  const invalidRpcUrls = [
    "http://ethereum-rpc.publicnode.com",
    "https://user@ethereum-rpc.publicnode.com",
    "https://ethereum-rpc.publicnode.com/#fragment",
    "https://ETHEREUM-RPC.publicnode.com/path",
    "https://sepolia.invalid/",
    "https://sepolia.test/",
    "https://sepolia.example/",
    "https://sepolia.localhost/",
    "https://sepolia.local/",
    "https://localhost/",
    "https://127.0.0.1/",
    "https://10.0.0.1/",
    "https://172.16.0.1/",
    "https://192.168.0.1/",
    "https://169.254.1.1/",
    "https://0.0.0.0/",
    "https://[::1]/",
    "https://[fc00::1]/",
    "https://[fe80::1]/",
    "https://[::]/",
  ];
  for (const rpcUrl of invalidRpcUrls) {
    const root = await mkdtemp(
      join(
        tmpdir(),
        "clockchain-verifier-entrypoint-",
      ),
    );
    const calls = [];
    await assert.rejects(
      verifierEntrypoint({
        client: {
          async send(command) {
            calls.push(command.input.SecretId);
            return {
              SecretString:
                command.input.SecretId.endsWith("rpc-url")
                  ? rpcUrl
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
        fetch: async () => ({
          ok: true,
          async json() {
            return {
              TaskARN: VERIFIER_TASK_ARN,
            };
          },
        }),
        run: async () => {
          calls.push("run");
        },
        tempDir: root,
      }),
      (error) => {
        assert.match(
          error.message,
          /AWS verifier entrypoint failed safely|AWS runtime input failed safely/,
        );
        assert.doesNotMatch(
          String(error),
          /clockchain-token-canary|ethereum-rpc|sepolia|127\.0\.0\.1/,
        );
        return true;
      },
    );
    assert.deepEqual(calls, [
      "arn:aws:secretsmanager:us-west-2:123456789012:secret:clockchain-token",
      "arn:aws:secretsmanager:us-west-2:123456789012:secret:rpc-url",
    ]);
    await assert.rejects(
      lstat(join(root, "clockchain-token")),
      { code: "ENOENT" },
    );
  }
});

test("verifier entrypoint rejects a preexisting token path after validated secrets and before run", async () => {
  const root = await mkdtemp(
    join(tmpdir(), "clockchain-verifier-entrypoint-"),
  );
  const scratch = await mkdtemp(
    join(root, "clockchain-verifier-"),
  );
  await writeFile(
    join(scratch, "clockchain-token"),
    "preexisting",
    { mode: 0o600 },
  );
  const calls = [];
  await assert.rejects(
    verifierEntrypoint({
      client: {
        async send(command) {
          calls.push(command.input.SecretId);
          return {
            SecretString:
              command.input.SecretId.endsWith("rpc-url")
                ? "https://ethereum-rpc.publicnode.com/path?api_key=provider"
                : "clockchain-token-canary",
          };
        },
      },
      createTempDir: async () => scratch,
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
      run: async () => {
        calls.push("run");
      },
    }),
    (error) => {
      assert.match(
        error.message,
        /AWS verifier entrypoint failed safely|AWS runtime input failed safely/,
      );
      assert.doesNotMatch(
        String(error),
        /clockchain-token-canary|ethereum-rpc/,
      );
      return true;
    },
  );
  assert.deepEqual(calls, [
    "arn:aws:secretsmanager:us-west-2:123456789012:secret:clockchain-token",
    "arn:aws:secretsmanager:us-west-2:123456789012:secret:rpc-url",
  ]);
  assert.equal(
    await readFile(
      join(scratch, "clockchain-token"),
      "utf8",
    ),
    "preexisting",
  );
});
