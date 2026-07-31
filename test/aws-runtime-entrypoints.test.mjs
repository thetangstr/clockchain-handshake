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
