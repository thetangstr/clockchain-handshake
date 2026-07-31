import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  createHash,
  generateKeyPairSync,
} from "node:crypto";
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
import { promisify } from "node:util";

import {
  installSecretFile,
  parseRuntimeInput,
} from "../infra/aws/runtime/runtime-input.mjs";
import {
  main as coordinatorEntrypoint,
} from "../infra/aws/runtime/coordinator-entrypoint.mjs";
import {
  main as fundingEntrypoint,
} from "../infra/aws/runtime/funding-entrypoint.mjs";
import {
  main as operatorWorkerEntrypoint,
} from "../infra/aws/runtime/operator-worker-entrypoint.mjs";
import {
  main as verifierEntrypoint,
} from "../infra/aws/runtime/verifier-entrypoint.mjs";

const execFileAsync = promisify(execFile);
const VERIFIER_ATTEMPT_ID =
  "11111111-1111-4111-8111-111111111111";
const VERIFIER_TASK_ARN =
  "arn:aws:ecs:us-west-2:123456789012:task/clockchain/11111111111111111111111111111111";
const OPERATOR_SESSION_ID =
  "22222222-2222-4222-8222-222222222222";
const OPERATOR_RELEASE_ID = `release-${createHash("sha256").update(OPERATOR_SESSION_ID, "utf8").digest("hex").slice(0, 16)}`;
const COORDINATOR_SESSION_ID =
  "33333333-3333-4333-8333-333333333333";
const COORDINATOR_RELEASE_ID = `release-${createHash("sha256").update(COORDINATOR_SESSION_ID, "utf8").digest("hex").slice(0, 16)}`;
const COORDINATOR_RELEASE_ROOT =
  `/var/lib/clockchain/operator/releases/${COORDINATOR_RELEASE_ID}`;
const TREASURY_ADDRESS =
  "0x157a377e4181f3f87c7f6efed5ddc340ccc00dce";

function ed25519PrivateKeyPem() {
  const { privateKey } = generateKeyPairSync(
    "ed25519",
  );
  return privateKey.export({
    format: "pem",
    type: "pkcs8",
  });
}

function fundingKeystore(address = TREASURY_ADDRESS) {
  return JSON.stringify({
    version: 3,
    id: "demo-wallet",
    address: address.slice(2),
    crypto: {
      ciphertext: "a".repeat(64),
      cipherparams: {
        iv: "b".repeat(32),
      },
      cipher: "aes-128-ctr",
      kdf: "scrypt",
      kdfparams: {
        dklen: 32,
        salt: "c".repeat(64),
        n: 262144,
        r: 8,
        p: 1,
      },
      mac: "d".repeat(64),
    },
  });
}

function mutateFundingKeystore(mutator) {
  const value = JSON.parse(fundingKeystore());
  mutator(value);
  return JSON.stringify(value);
}

function fundingRuntimeInput(overrides = {}) {
  const funding = {
    createdAt: "2026-07-31T00:00:00.000Z",
    expectedTreasuryAddress: TREASURY_ADDRESS,
    fundingRecordPath: "/operator/funding-record.json",
    journalDirectory: "/operator/funding-journal",
    keystoreSecretArn:
      "arn:aws:secretsmanager:us-west-2:123456789012:secret:treasury-keystore",
    passwordSecretArn:
      "arn:aws:secretsmanager:us-west-2:123456789012:secret:treasury-password",
    repositorySha:
      "abcdef0123456789abcdef0123456789abcdef01",
    rpcSecretArn:
      "arn:aws:secretsmanager:us-west-2:123456789012:secret:rpc-url",
    ...overrides,
  };
  return JSON.stringify({
    funding,
    paymentMoved: false,
    schema: "clockchain.aws-runtime-input/v1",
  });
}

function operatorRuntimeInput(overrides = {}) {
  const operator = {
    actionQueueUrl:
      "https://sqs.us-west-2.amazonaws.com/123456789012/clockchain-actions",
    actionTableName:
      "ClockchainHandshakeControl",
    paymentMoved: false,
    releaseId: OPERATOR_RELEASE_ID,
    repositorySha:
      "abcdef0123456789abcdef0123456789abcdef01",
    schema:
      "clockchain.aws-operator-runtime/v1",
    sessionId: OPERATOR_SESSION_ID,
    ...overrides,
  };
  return JSON.stringify({
    operator,
    paymentMoved: false,
    schema: "clockchain.aws-runtime-input/v1",
  });
}

function coordinatorRuntimeInput(overrides = {}) {
  const coordinator = {
    clockchainTokenSecretArn:
      "arn:aws:secretsmanager:us-west-2:123456789012:secret:clockchain-token",
    operatorKeyId: "clockchain-demo-2026",
    operatorKeySecretArn:
      "arn:aws:secretsmanager:us-west-2:123456789012:secret:operator-key",
    releaseIdentity: {
      releaseId: COORDINATOR_RELEASE_ID,
      sessionId: COORDINATOR_SESSION_ID,
    },
    releaseRoot:
      COORDINATOR_RELEASE_ROOT,
    relayUrl:
      "https://relay.clockchain.network:8443",
    repositorySha:
      "abcdef0123456789abcdef0123456789abcdef01",
    rpcSecretArn:
      "arn:aws:secretsmanager:us-west-2:123456789012:secret:rpc-url",
    tlsCertificatePath:
      `${COORDINATOR_RELEASE_ROOT}/payer-mcp.crt`,
    tlsFingerprint: "b".repeat(64),
    ...overrides,
  };
  return JSON.stringify({
    coordinator,
    paymentMoved: false,
    schema: "clockchain.aws-runtime-input/v1",
  });
}

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

test("coordinator entrypoint materializes validated secrets into unique private argv files", async () => {
  const operatorKey = ed25519PrivateKeyPem();
  const secretReads = [];
  const runCalls = [];
  for (let index = 0; index < 2; index += 1) {
    await coordinatorEntrypoint({
      client: {
        async send(command) {
          secretReads.push(command.input);
          if (
            command.input.SecretId.endsWith(
              "clockchain-token",
            )
          ) {
            return {
              SecretString: `clockchain-token-${index}`,
            };
          }
          if (
            command.input.SecretId.endsWith(
              "operator-key",
            )
          ) {
            return {
              SecretString: operatorKey,
            };
          }
          if (
            command.input.SecretId.endsWith(
              "rpc-url",
            )
          ) {
            return {
              SecretString:
                "https://ethereum-rpc.publicnode.com/",
            };
          }
          assert.fail(
            `unexpected secret read ${command.input.SecretId}`,
          );
        },
      },
      env: {
        AWS_RUNTIME_INPUT:
          coordinatorRuntimeInput(),
      },
      run: async (argv, dependencies) => {
        const values = Object.fromEntries(
          Array.from(
            { length: argv.length / 2 },
            (_, pair) => [
              argv[pair * 2],
              argv[pair * 2 + 1],
            ],
          ),
        );
        runCalls.push({
          argv,
          dependencies,
          values,
        });
        assert.equal(
          (await lstat(
            values["--clockchain-token-file"],
          )).mode & 0o777,
          0o600,
        );
        assert.equal(
          (await lstat(
            values["--operator-private-key"],
          )).mode & 0o777,
          0o600,
        );
        assert.equal(
          (await lstat(
            values["--rpc-url-file"],
          )).mode & 0o777,
          0o600,
        );
        assert.equal(
          await readFile(
            values["--clockchain-token-file"],
            "utf8",
          ),
          `clockchain-token-${index}`,
        );
        assert.equal(
          await readFile(
            values["--operator-private-key"],
            "utf8",
          ),
          operatorKey,
        );
        assert.equal(
          await readFile(
            values["--rpc-url-file"],
            "utf8",
          ),
          "https://ethereum-rpc.publicnode.com/\n",
        );
        return 0;
      },
    });
  }

  assert.deepEqual(secretReads, [
    {
      SecretId:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:clockchain-token",
    },
    {
      SecretId:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:operator-key",
    },
    {
      SecretId:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:rpc-url",
    },
    {
      SecretId:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:clockchain-token",
    },
    {
      SecretId:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:operator-key",
    },
    {
      SecretId:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:rpc-url",
    },
  ]);
  assert.equal(runCalls.length, 2);
  const expectedPublicArgv = (values) => [
    "--clockchain-token-file",
    values["--clockchain-token-file"],
    "--operator-key-id",
    "clockchain-demo-2026",
    "--operator-private-key",
    values["--operator-private-key"],
    "--release-root",
    COORDINATOR_RELEASE_ROOT,
    "--relay-url",
    "https://relay.clockchain.network:8443",
    "--repository-sha",
    "abcdef0123456789abcdef0123456789abcdef01",
    "--rpc-url-file",
    values["--rpc-url-file"],
    "--tls-certificate",
    `${COORDINATOR_RELEASE_ROOT}/payer-mcp.crt`,
    "--tls-fingerprint",
    "b".repeat(64),
  ];
  for (const call of runCalls) {
    assert.deepEqual(
      call.argv,
      expectedPublicArgv(call.values),
    );
    assert.deepEqual(call.dependencies, {
      releaseIdentity: {
        releaseId: COORDINATOR_RELEASE_ID,
        sessionId: COORDINATOR_SESSION_ID,
      },
    });
    await assert.rejects(
      lstat(
        call.values["--clockchain-token-file"],
      ),
      { code: "ENOENT" },
    );
    await assert.rejects(
      lstat(
        call.values["--operator-private-key"],
      ),
      { code: "ENOENT" },
    );
    await assert.rejects(
      lstat(call.values["--rpc-url-file"]),
      { code: "ENOENT" },
    );
  }
  assert.notEqual(
    dirname(
      runCalls[0].values[
        "--clockchain-token-file"
      ],
    ),
    dirname(
      runCalls[1].values[
        "--clockchain-token-file"
      ],
    ),
  );
});

test("coordinator entrypoint rejects malformed runtime input before secret reads", async () => {
  const cases = [
    coordinatorRuntimeInput({
      releaseIdentity: {
        releaseId: "release-0000000000000000",
        sessionId: COORDINATOR_SESSION_ID,
      },
    }),
    coordinatorRuntimeInput({
      releaseRoot:
        "/var/lib/clockchain/operator/releases/release-0000000000000000",
    }),
    coordinatorRuntimeInput({
      tlsCertificatePath:
        "/var/lib/clockchain/operator/releases/release-0000000000000000/payer-mcp.crt",
    }),
    coordinatorRuntimeInput({
      tlsCertificatePath:
        COORDINATOR_RELEASE_ROOT,
    }),
    coordinatorRuntimeInput({
      tlsCertificatePath:
        "/var/lib/clockchain/operator/releases/release-0000000000000000/../payer-mcp.crt",
    }),
    coordinatorRuntimeInput({
      relayUrl:
        "https://relay.clockchain.network:8443?x=1",
    }),
    coordinatorRuntimeInput({
      relayUrl:
        "https://relay.clockchain.network",
    }),
    coordinatorRuntimeInput({
      operatorKeyId: "Clockchain-Demo-2026",
    }),
    coordinatorRuntimeInput({
      operatorKeyId: "-clockchain-demo-2026",
    }),
    coordinatorRuntimeInput({
      tlsCertificatePath:
        "/tmp/payer-mcp.crt",
    }),
    coordinatorRuntimeInput({
      tlsFingerprint: "B".repeat(64),
    }),
    coordinatorRuntimeInput({
      rpcSecretArn: "not-an-arn",
    }),
    JSON.stringify({
      coordinator: JSON.parse(
        coordinatorRuntimeInput(),
      ).coordinator,
      paymentMoved: false,
      schema:
        "clockchain.aws-runtime-input/v1",
      z: "unknown",
    }),
  ];
  for (const runtimeInput of cases) {
    let secretReads = 0;
    await assert.rejects(
      coordinatorEntrypoint({
        client: {
          async send() {
            secretReads += 1;
            return { SecretString: "secret" };
          },
        },
        env: {
          AWS_RUNTIME_INPUT: runtimeInput,
        },
        run: async () => {
          assert.fail("run must not start");
        },
      }),
      /AWS coordinator entrypoint failed safely|AWS runtime input failed safely/,
    );
    assert.equal(secretReads, 0);
  }
});

test("coordinator entrypoint rejects invalid secrets before scratch creation or run", async () => {
  const operatorKey = ed25519PrivateKeyPem();
  const rsaKey = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  }).privateKey.export({
    format: "pem",
    type: "pkcs8",
  });
  const cases = [
    {
      token: "clockchain-token\nsecond-line",
      operatorKey,
      rpc: "https://ethereum-rpc.publicnode.com/",
    },
    {
      token: "clockchain-token",
      operatorKey: rsaKey,
      rpc: "https://ethereum-rpc.publicnode.com/",
    },
    {
      token: "clockchain-token",
      operatorKey,
      rpc: "https://127.0.0.1/",
    },
    {
      token: "clockchain-token",
      operatorKey,
      rpc: "https://[::ffff:7f00:1]/",
    },
    {
      token: "clockchain-token",
      operatorKey,
      rpc: "https://[2001:db8::1]/",
    },
  ];
  for (const value of cases) {
    const calls = [];
    await assert.rejects(
      coordinatorEntrypoint({
        client: {
          async send(command) {
            calls.push(command.input.SecretId);
            if (
              command.input.SecretId.endsWith(
                "clockchain-token",
              )
            ) {
              return { SecretString: value.token };
            }
            if (
              command.input.SecretId.endsWith(
                "operator-key",
              )
            ) {
              return {
                SecretString: value.operatorKey,
              };
            }
            return { SecretString: value.rpc };
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
            coordinatorRuntimeInput(),
        },
        run: async () => {
          calls.push("run");
        },
      }),
      (error) => {
        assert.match(
          error.message,
          /AWS coordinator entrypoint failed safely|AWS runtime input failed safely/,
        );
        assert.doesNotMatch(
          String(error),
          /clockchain-token|ethereum-rpc|PRIVATE KEY|127\.0\.0\.1/,
        );
        return true;
      },
    );
    assert.deepEqual(
      calls.filter(
        (call) => call === "createTempDir" || call === "run",
      ),
      [],
    );
  }
});

test("coordinator entrypoint rejects non-public RPC IP literals before scratch creation or run", async () => {
  const operatorKey = ed25519PrivateKeyPem();
  for (const rpc of [
    "https://100.64.0.1/",
    "https://192.0.0.1/",
    "https://192.0.2.1/",
    "https://192.88.99.1/",
    "https://198.18.0.1/",
    "https://198.51.100.1/",
    "https://203.0.113.1/",
    "https://224.0.0.1/",
    "https://240.0.0.1/",
    "https://[100::1]/",
    "https://[2001::1]/",
    "https://[2002::1]/",
    "https://[ff02::1]/",
    "https://[::ffff:100.64.0.1]/",
    "https://[::ffff:c612:1]/",
  ]) {
    const calls = [];
    await assert.rejects(
      coordinatorEntrypoint({
        client: {
          async send(command) {
            calls.push(command.input.SecretId);
            if (
              command.input.SecretId.endsWith(
                "clockchain-token",
              )
            ) {
              return {
                SecretString: "clockchain-token",
              };
            }
            if (
              command.input.SecretId.endsWith(
                "operator-key",
              )
            ) {
              return { SecretString: operatorKey };
            }
            return { SecretString: rpc };
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
            coordinatorRuntimeInput(),
        },
        run: async () => {
          calls.push("run");
        },
      }),
      /AWS coordinator entrypoint failed safely|AWS runtime input failed safely/,
      rpc,
    );
    assert.deepEqual(
      calls.filter(
        (call) => call === "createTempDir" || call === "run",
      ),
      [],
      rpc,
    );
  }
});

test("coordinator entrypoint accepts known public IPv4 and IPv6 RPC literals", async () => {
  const operatorKey = ed25519PrivateKeyPem();
  const calls = [];
  for (const rpc of [
    "https://8.8.8.8/",
    "https://[2606:4700:4700::1111]/",
  ]) {
    await coordinatorEntrypoint({
      client: {
        async send(command) {
          if (
            command.input.SecretId.endsWith(
              "clockchain-token",
            )
          ) {
            return {
              SecretString: "clockchain-token",
            };
          }
          if (
            command.input.SecretId.endsWith(
              "operator-key",
            )
          ) {
            return { SecretString: operatorKey };
          }
          return { SecretString: rpc };
        },
      },
      env: {
        AWS_RUNTIME_INPUT:
          coordinatorRuntimeInput(),
      },
      run: async (argv) => {
        const values = Object.fromEntries(
          Array.from(
            { length: argv.length / 2 },
            (_, pair) => [
              argv[pair * 2],
              argv[pair * 2 + 1],
            ],
          ),
        );
        calls.push(
          await readFile(
            values["--rpc-url-file"],
            "utf8",
          ),
        );
        return 0;
      },
    });
  }
  assert.deepEqual(calls, [
    "https://8.8.8.8/\n",
    "https://[2606:4700:4700::1111]/\n",
  ]);
});

test("coordinator entrypoint accepts a known public IPv6 RPC literal", async () => {
  const operatorKey = ed25519PrivateKeyPem();
  const calls = [];
  await coordinatorEntrypoint({
    client: {
      async send(command) {
        if (
          command.input.SecretId.endsWith(
            "clockchain-token",
          )
        ) {
          return {
            SecretString: "clockchain-token",
          };
        }
        if (
          command.input.SecretId.endsWith(
            "operator-key",
          )
        ) {
          return { SecretString: operatorKey };
        }
        return {
          SecretString:
            "https://[2606:4700:4700::1111]/",
        };
      },
    },
    env: {
      AWS_RUNTIME_INPUT: coordinatorRuntimeInput(),
    },
    run: async (argv) => {
      const values = Object.fromEntries(
        Array.from(
          { length: argv.length / 2 },
          (_, pair) => [
            argv[pair * 2],
            argv[pair * 2 + 1],
          ],
        ),
      );
      calls.push(
        await readFile(
          values["--rpc-url-file"],
          "utf8",
        ),
      );
      return 0;
    },
  });
  assert.deepEqual(calls, [
    "https://[2606:4700:4700::1111]/\n",
  ]);
});

test("coordinator entrypoint attempts all cleanup and fails closed when cleanup fails", async () => {
  const root = await mkdtemp(
    join(
      tmpdir(),
      "clockchain-coordinator-entrypoint-",
    ),
  );
  const scratch = join(
    root,
    "clockchain-coordinator-",
  );
  const calls = [];
  try {
    await assert.rejects(
      coordinatorEntrypoint({
        client: {
          async send(command) {
            if (
              command.input.SecretId.endsWith(
                "clockchain-token",
              )
            ) {
              return {
                SecretString: "clockchain-token",
              };
            }
            if (
              command.input.SecretId.endsWith(
                "operator-key",
              )
            ) {
              return {
                SecretString: ed25519PrivateKeyPem(),
              };
            }
            return {
              SecretString:
                "https://ethereum-rpc.publicnode.com/",
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
            coordinatorRuntimeInput(),
        },
        removeDir: async (path) => {
          calls.push(["removeDir", path]);
          throw new Error("cleanup canary");
        },
        removeFile: async (path) => {
          calls.push([
            "removeFile",
            path,
          ]);
          throw new Error("cleanup canary");
        },
        run: async () => {
          calls.push(["run"]);
          return 0;
        },
      }),
      (error) => {
        assert.equal(
          error.message,
          "AWS coordinator entrypoint failed safely.",
        );
        assert.doesNotMatch(
          String(error),
          /cleanup canary|clockchain-token|ethereum-rpc|PRIVATE KEY/,
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
      join(tmpdir(), "clockchain-coordinator-"),
      scratchDir,
    ],
    ["run"],
    [
      "removeFile",
      join(scratchDir, "clockchain-token"),
    ],
    [
      "removeFile",
      join(
        scratchDir,
        "operator-private-key.pem",
      ),
    ],
    [
      "removeFile",
      join(scratchDir, "sepolia-rpc-url"),
    ],
    ["removeDir", scratchDir],
  ]);
});

test("coordinator production CLI fails closed without leaking runtime values", async () => {
  const result = await execFileAsync(
    process.execPath,
    ["infra/aws/runtime/coordinator-entrypoint.mjs"],
    {
      env: {
        ...process.env,
        AWS_RUNTIME_INPUT: coordinatorRuntimeInput(),
      },
    },
  ).catch((error) => error);
  assert.equal(result.code, 1);
  assert.equal(
    result.stderr,
    "AWS_COORDINATOR_ENTRYPOINT_FAILED\n",
  );
  assert.equal(result.stdout, "");
});

test("operator worker entrypoint composes exact AWS clients and loop dependencies", async () => {
  const sqs = { send: async () => ({}) };
  const dynamodb = {
    name: "dynamodb",
    send: async () => ({}),
  };
  const documentClient = { send: async () => ({}) };
  const buildTransitions = async () => ({});
  const signal = AbortSignal.abort();
  const calls = [];
  await operatorWorkerEntrypoint({
    buildTransitions,
    createClients: async () => {
      calls.push(["createClients"]);
      return {
        dynamodb,
        ecs: { send: async () => ({}) },
        s3: { send: async () => ({}) },
        secrets: { send: async () => ({}) },
        sqs,
      };
    },
    createDocumentClient: (client) => {
      calls.push([
        "createDocumentClient",
        client,
      ]);
      return documentClient;
    },
    env: {
      AWS_RUNTIME_INPUT: operatorRuntimeInput(),
    },
    run: async (config, dependencies) => {
      calls.push([
        "run",
        config,
        dependencies,
      ]);
      return {
        paymentMoved: false,
        status: "IDLE",
      };
    },
    signal,
  });
  assert.deepEqual(calls, [
    ["createClients"],
    ["createDocumentClient", dynamodb],
    [
      "run",
      {
        actionQueueUrl:
          "https://sqs.us-west-2.amazonaws.com/123456789012/clockchain-actions",
        actionTableName:
          "ClockchainHandshakeControl",
        paymentMoved: false,
        releaseId: OPERATOR_RELEASE_ID,
        repositorySha:
          "abcdef0123456789abcdef0123456789abcdef01",
        schema:
          "clockchain.aws-operator-runtime/v1",
        sessionId: OPERATOR_SESSION_ID,
      },
      {
        buildTransitions,
        documentClient,
        signal,
        sqs,
      },
    ],
  ]);
});

test("operator worker entrypoint provides default transition composition when not injected", async () => {
  const calls = [];
  await operatorWorkerEntrypoint({
    createClients: async () => ({
      dynamodb: { send: async () => ({}) },
      sqs: { send: async () => ({}) },
    }),
    createDocumentClient: (client) => ({
      client,
      send: async () => ({}),
    }),
    env: {
      AWS_RUNTIME_INPUT: operatorRuntimeInput(),
    },
    run: async (config, dependencies) => {
      calls.push([
        config.releaseId,
        typeof dependencies.buildTransitions,
      ]);
      await assert.rejects(
        dependencies.buildTransitions(config),
        /AWS operator worker entrypoint failed safely/,
      );
      return {
        paymentMoved: false,
        status: "IDLE",
      };
    },
  });
  assert.deepEqual(calls, [
    [OPERATOR_RELEASE_ID, "function"],
  ]);
});

test("operator worker entrypoint accepts the default operator loop with an aborted signal", async () => {
  await operatorWorkerEntrypoint({
    buildTransitions: async () => ({}),
    createClients: async () => ({
      dynamodb: { send: async () => ({}) },
      sqs: { send: async () => ({}) },
    }),
    createDocumentClient: (client) => ({
      client,
      send: async () => ({}),
    }),
    env: {
      AWS_RUNTIME_INPUT: operatorRuntimeInput(),
    },
    signal: AbortSignal.abort(),
  });
});

test("operator worker entrypoint accepts SQS queue names at the standard and FIFO length boundaries", async () => {
  const acceptedQueueNames = [
    "a".repeat(80),
    `${"a".repeat(75)}.fifo`,
  ];
  for (const queueName of acceptedQueueNames) {
    const calls = [];
    await operatorWorkerEntrypoint({
      buildTransitions: async () => ({}),
      createClients: async () => ({
        dynamodb: { send: async () => ({}) },
        sqs: { send: async () => ({}) },
      }),
      createDocumentClient: (client) => ({
        client,
        send: async () => ({}),
      }),
      env: {
        AWS_RUNTIME_INPUT: operatorRuntimeInput({
          actionQueueUrl:
            `https://sqs.us-west-2.amazonaws.com/123456789012/${queueName}`,
        }),
      },
      run: async (config) => {
        calls.push(config.actionQueueUrl);
        return {
          paymentMoved: false,
          status: "IDLE",
        };
      },
    });
    assert.deepEqual(calls, [
      `https://sqs.us-west-2.amazonaws.com/123456789012/${queueName}`,
    ]);
  }
});

test("operator worker entrypoint rejects malformed operator runtime input before client creation", async () => {
  const cases = [
    operatorRuntimeInput({
      releaseId: "release-0000000000000000",
    }),
    operatorRuntimeInput({
      paymentMoved: true,
    }),
    operatorRuntimeInput({
      actionQueueUrl:
        "http://sqs.us-west-2.amazonaws.com/123456789012/clockchain-actions",
    }),
    operatorRuntimeInput({
      actionQueueUrl:
        "https://sqs.us-west-2.amazonaws.com/",
    }),
    operatorRuntimeInput({
      actionQueueUrl:
        "https://sqs.us-west-2.amazonaws.com/123456789012",
    }),
    operatorRuntimeInput({
      actionQueueUrl:
        "https://sqs.us-west-2.amazonaws.com/123456789012/",
    }),
    operatorRuntimeInput({
      actionQueueUrl:
        "https://sqs.us-west-2.amazonaws.com/12345678901/clockchain-actions",
    }),
    operatorRuntimeInput({
      actionQueueUrl:
        "https://sqs.us-west-2.amazonaws.com/123456789012/clockchain-actions/extra",
    }),
    operatorRuntimeInput({
      actionQueueUrl:
        "https://sqs.us-west-2.amazonaws.com/123456789012//clockchain-actions",
    }),
    operatorRuntimeInput({
      actionQueueUrl:
        "https://sqs.us-west-2.amazonaws.com/123456789012/clockchain actions",
    }),
    operatorRuntimeInput({
      actionQueueUrl:
        `https://sqs.us-west-2.amazonaws.com/123456789012/${"a".repeat(81)}`,
    }),
    operatorRuntimeInput({
      actionQueueUrl:
        `https://sqs.us-west-2.amazonaws.com/123456789012/${"a".repeat(76)}.fifo`,
    }),
    operatorRuntimeInput({
      actionTableName: "no spaces",
    }),
    operatorRuntimeInput({
      repositorySha: "a".repeat(39),
    }),
    JSON.stringify({
      operator: JSON.parse(
        operatorRuntimeInput(),
      ).operator,
      paymentMoved: false,
      schema:
        "clockchain.aws-runtime-input/v1",
      z: "unknown",
    }),
    JSON.stringify({
      paymentMoved: false,
      operator: JSON.parse(
        operatorRuntimeInput(),
      ).operator,
      schema:
        "clockchain.aws-runtime-input/v1",
    }),
  ];
  for (const runtimeInput of cases) {
    let clientCreations = 0;
    await assert.rejects(
      operatorWorkerEntrypoint({
        buildTransitions: async () => ({}),
        createClients: async () => {
          clientCreations += 1;
          return {};
        },
        env: {
          AWS_RUNTIME_INPUT: runtimeInput,
        },
        run: async () => {
          assert.fail("run must not start");
        },
      }),
      /AWS operator worker entrypoint failed safely|AWS runtime input failed safely/,
    );
    assert.equal(clientCreations, 0);
  }
});

test("operator worker entrypoint rejects invalid dependency composition safely", async () => {
  const cases = [
    {
      createClients: null,
    },
    {
      createClients: async () => ({
        dynamodb: {},
        sqs: { send: async () => ({}) },
      }),
    },
    {
      createClients: async () => ({
        dynamodb: { send: async () => ({}) },
      }),
    },
    {
      createDocumentClient: null,
    },
    {
      buildTransitions: null,
    },
    {
      run: null,
    },
  ];
  for (const overrides of cases) {
    await assert.rejects(
      operatorWorkerEntrypoint({
        buildTransitions: async () => ({}),
        createClients: async () => ({
          dynamodb: { send: async () => ({}) },
          sqs: { send: async () => ({}) },
        }),
        createDocumentClient: () => ({
          send: async () => ({}),
        }),
        env: {
          AWS_RUNTIME_INPUT: operatorRuntimeInput(),
        },
        run: async () => {},
        ...overrides,
      }),
      /AWS operator worker entrypoint failed safely|AWS runtime input failed safely/,
    );
  }
});

test("operator worker production CLI fails closed without live runtime dependencies", async () => {
  const result = await execFileAsync(
    process.execPath,
    ["infra/aws/runtime/operator-worker-entrypoint.mjs"],
    {
      env: {
        ...process.env,
        AWS_RUNTIME_INPUT: operatorRuntimeInput(),
      },
      reject: false,
    },
  ).catch((error) => error);
  assert.equal(result.code, 1);
  assert.equal(
    result.stderr,
    "AWS_OPERATOR_WORKER_ENTRYPOINT_FAILED\n",
  );
  assert.equal(result.stdout, "");
});

test("funding entrypoint materializes keystore metadata and RPC secrets into private scratch paths", async () => {
  const secretReads = [];
  const runCalls = [];
  const keystore = fundingKeystore();
  const client = {
    async send(command) {
      secretReads.push(command.input);
      if (
        command.input.SecretId.endsWith(
          "treasury-keystore",
        )
      ) {
        return { SecretString: keystore };
      }
      if (command.input.SecretId.endsWith("rpc-url")) {
        return {
          SecretString:
            "https://ethereum-rpc.publicnode.com/path",
        };
      }
      assert.fail(
        `unexpected eager secret read: ${command.input.SecretId}`,
      );
    },
  };
  for (let index = 0; index < 2; index += 1) {
    await fundingEntrypoint({
      client,
      env: {
        AWS_RUNTIME_INPUT: fundingRuntimeInput(),
      },
      run: async (input, dependencies) => {
        runCalls.push(input);
        assert.equal(
          typeof dependencies.readSecret,
          "function",
        );
        const keystoreBytes = await readFile(
          input.keystorePath,
        );
        const metadata = JSON.parse(
          await readFile(
            input.keystorePath.replace(
              /\.json$/,
              ".public.json",
            ),
            "utf8",
          ),
        );
        assert.equal(
          (await lstat(dirname(input.keystorePath)))
            .mode & 0o777,
          0o700,
        );
        assert.equal(
          (await lstat(input.keystorePath)).mode &
            0o777,
          0o600,
        );
        assert.equal(
          (await lstat(input.rpcUrlFile)).mode &
            0o777,
          0o600,
        );
        assert.equal(
          (
            await lstat(
              input.keystorePath.replace(
                /\.json$/,
                ".public.json",
              ),
            )
          ).mode & 0o777,
          0o600,
        );
        assert.deepEqual(metadata, {
          schemaVersion: 1,
          chainId: 11155111,
          fundingAddress: TREASURY_ADDRESS,
          keystoreSha256: createHash("sha256")
            .update(keystoreBytes)
            .digest("hex"),
          createdAt: "2026-07-31T00:00:00.000Z",
        });
        assert.equal(
          await readFile(input.rpcUrlFile, "utf8"),
          "https://ethereum-rpc.publicnode.com/path\n",
        );
        return {
          paymentMoved: false,
          status: "FUNDED",
        };
      },
    });
  }

  assert.deepEqual(secretReads, [
    {
      SecretId:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:treasury-keystore",
    },
    {
      SecretId:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:rpc-url",
    },
    {
      SecretId:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:treasury-keystore",
    },
    {
      SecretId:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:rpc-url",
    },
  ]);
  assert.equal(runCalls.length, 2);
  assert.notEqual(
    dirname(runCalls[0].keystorePath),
    dirname(runCalls[1].keystorePath),
  );
  for (const runCall of runCalls) {
    assert.deepEqual(runCall, {
      expectedTreasuryAddress: TREASURY_ADDRESS,
      fundingRecordPath: "/operator/funding-record.json",
      journalDirectory: "/operator/funding-journal",
      keystorePath: runCall.keystorePath,
      repositorySha:
        "abcdef0123456789abcdef0123456789abcdef01",
      rpcUrlFile: runCall.rpcUrlFile,
      secretId:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:treasury-password",
    });
    assert.notEqual(
      runCall.keystorePath,
      "/secrets/treasury-keystore.json",
    );
    assert.notEqual(
      runCall.rpcUrlFile,
      "/secrets/sepolia-rpc",
    );
    await assert.rejects(
      lstat(runCall.keystorePath),
      { code: "ENOENT" },
    );
    await assert.rejects(
      lstat(
        runCall.keystorePath.replace(
          /\.json$/,
          ".public.json",
        ),
      ),
      { code: "ENOENT" },
    );
    await assert.rejects(
      lstat(runCall.rpcUrlFile),
      { code: "ENOENT" },
    );
  }
});

test("funding entrypoint rejects caller-supplied secret paths before reading secrets", async () => {
  const cases = [
    { keystorePath: "/secrets/treasury-keystore.json" },
    { rpcUrlFile: "/secrets/sepolia-rpc" },
    {
      secretId:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:treasury-password",
    },
    {
      keystoreSecretArn: "not-an-arn",
    },
    {
      passwordSecretArn: "not-an-arn",
    },
    {
      rpcSecretArn:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:rpc-url",
      z: "unknown",
    },
  ];
  for (const overrides of cases) {
    let secretReads = 0;
    await assert.rejects(
      fundingEntrypoint({
        client: {
          async send() {
            secretReads += 1;
            return { SecretString: "secret" };
          },
        },
        env: {
          AWS_RUNTIME_INPUT:
            fundingRuntimeInput(overrides),
        },
        run: async () => {
          assert.fail("run must not start");
        },
      }),
      /AWS funding entrypoint failed safely|AWS runtime input failed safely/,
    );
    assert.equal(secretReads, 0);
  }
});

test("funding entrypoint rejects invalid keystore and RPC secrets before scratch or run", async () => {
  const cases = [
    {
      name: "address mismatch",
      secrets: {
        "treasury-keystore": fundingKeystore(
          "0x257a377e4181f3f87c7f6efed5ddc340ccc00dce",
        ),
        "rpc-url":
          "https://ethereum-rpc.publicnode.com/path",
      },
    },
    {
      name: "noncanonical keystore",
      secrets: {
        "treasury-keystore": `${fundingKeystore()}\n`,
        "rpc-url":
          "https://ethereum-rpc.publicnode.com/path",
      },
    },
    {
      name: "unsafe rpc",
      secrets: {
        "treasury-keystore": fundingKeystore(),
        "rpc-url":
          "http://ethereum-rpc.publicnode.com/path?api_key=provider",
      },
    },
    {
      name: "rpc with query",
      secrets: {
        "treasury-keystore": fundingKeystore(),
        "rpc-url":
          "https://ethereum-rpc.publicnode.com/path?api_key=provider",
      },
    },
    {
      name: "extra keystore key",
      secrets: {
        "treasury-keystore": mutateFundingKeystore(
          (value) => {
            value.extra = true;
          },
        ),
        "rpc-url":
          "https://ethereum-rpc.publicnode.com/path",
      },
    },
    {
      name: "wrong cipher",
      secrets: {
        "treasury-keystore": mutateFundingKeystore(
          (value) => {
            value.crypto.cipher = "aes-256-ctr";
          },
        ),
        "rpc-url":
          "https://ethereum-rpc.publicnode.com/path",
      },
    },
    {
      name: "wrong kdf",
      secrets: {
        "treasury-keystore": mutateFundingKeystore(
          (value) => {
            value.crypto.kdf = "pbkdf2";
          },
        ),
        "rpc-url":
          "https://ethereum-rpc.publicnode.com/path",
      },
    },
    {
      name: "non power-of-two scrypt n",
      secrets: {
        "treasury-keystore": mutateFundingKeystore(
          (value) => {
            value.crypto.kdfparams.n = 3;
          },
        ),
        "rpc-url":
          "https://ethereum-rpc.publicnode.com/path",
      },
    },
    {
      name: "zero address",
      input: fundingRuntimeInput({
        expectedTreasuryAddress:
          "0x0000000000000000000000000000000000000000",
      }),
      secrets: {
        "treasury-keystore": fundingKeystore(
          "0x0000000000000000000000000000000000000000",
        ),
        "rpc-url":
          "https://ethereum-rpc.publicnode.com/path",
      },
    },
  ];
  for (const { input, name, secrets } of cases) {
    const calls = [];
    await assert.rejects(
      fundingEntrypoint({
        client: {
          async send(command) {
            calls.push(["secret", command.input]);
            const key = command.input.SecretId.endsWith(
              "treasury-keystore",
            )
              ? "treasury-keystore"
              : "rpc-url";
            return { SecretString: secrets[key] };
          },
        },
        createTempDir: async () => {
          calls.push(["createTempDir"]);
          throw new Error("scratch must not start");
        },
        env: {
          AWS_RUNTIME_INPUT:
            input ?? fundingRuntimeInput(),
        },
        run: async () => {
          calls.push(["run"]);
          assert.fail("run must not start");
        },
      }),
      /AWS funding entrypoint failed safely|AWS runtime input failed safely/,
      name,
    );
    assert.equal(
      calls.some(([call]) => call === "createTempDir"),
      false,
      name,
    );
    assert.equal(
      calls.some(([call]) => call === "run"),
      false,
      name,
    );
  }
});

test("funding entrypoint fails closed when scratch cleanup fails after run", async () => {
  const root = await mkdtemp(
    join(tmpdir(), "clockchain-funding-entrypoint-"),
  );
  const scratch = join(root, "clockchain-funding-");
  const calls = [];
  try {
    await assert.rejects(
      fundingEntrypoint({
        client: {
          async send(command) {
            return {
              SecretString:
                command.input.SecretId.endsWith(
                  "treasury-keystore",
                )
                  ? fundingKeystore()
                  : "https://ethereum-rpc.publicnode.com/path",
            };
          },
        },
        createTempDir: async (prefix) => {
          const path = await mkdtemp(`${scratch}-`);
          calls.push(["createTempDir", prefix, path]);
          return path;
        },
        env: {
          AWS_RUNTIME_INPUT: fundingRuntimeInput(),
        },
        removeDir: async (path) => {
          calls.push(["removeDir", path]);
          throw new Error("cleanup canary");
        },
        removeFile: async (path) => {
          calls.push(["removeFile", path]);
          throw new Error("cleanup canary");
        },
        run: async () => {
          calls.push(["run"]);
          return {
            paymentMoved: false,
            status: "FUNDED",
          };
        },
      }),
      (error) => {
        assert.equal(
          error.message,
          "AWS funding entrypoint failed safely.",
        );
        assert.doesNotMatch(
          String(error),
          /cleanup canary|treasury|ethereum-rpc/,
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
      join(tmpdir(), "clockchain-funding-"),
      scratchDir,
    ],
    ["run"],
    [
      "removeFile",
      join(scratchDir, "treasury-keystore.json"),
    ],
    [
      "removeFile",
      join(
        scratchDir,
        "treasury-keystore.public.json",
      ),
    ],
    [
      "removeFile",
      join(scratchDir, "sepolia-rpc-url"),
    ],
    ["removeDir", scratchDir],
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
