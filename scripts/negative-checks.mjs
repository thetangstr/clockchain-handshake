#!/usr/bin/env node

// G1a negative-check harness. Four adversarial scenarios, each pinned
// to the public reason code it must fail closed with:
//
//   replay            divergent duplicate mandate artifacts -> DUPLICATE
//   reorder           later slot anchored without predecessor -> REORDERED
//   tamper            inauthentic mandate signature           -> FAILED
//   duplicate-funding funding batch diverging from binding    -> FUNDING_REPLAYED
//
// Any mismatch, missing error, or unexpected success exits 1.

import { generateKeyPairSync, randomUUID } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { REGISTRY_ADDRESS } from "../src/core/descriptor.mjs";
import {
  BILATERAL_PROTOCOL_ID,
} from "../src/core/mandate-construction.mjs";
import { BilateralVerdictError } from "../src/core/verdict.mjs";
import { createRelayServer } from "../src/relay/server.mjs";
import {
  OPERATOR_CONFIG_SCHEMA,
  OPERATOR_SESSION_SCHEMA,
  OperatorError,
  runOperator,
} from "../src/roles/operator.mjs";
import { runVerification } from "../src/verifier/run.mjs";
import {
  buildFixture,
  captureStdout,
  KEY_ID,
  PROMPT_SHA256,
  RELAY_SESSION_ID,
  REPOSITORY_SHA,
} from "../test/helpers/bilateral-fixture.mjs";

const results = [];

function record(name, expected, actual) {
  const ok = actual === expected;
  results.push(ok);
  process.stdout.write(
    ok
      ? `NEGATIVE ${name} ${actual} OK\n`
      : `NEGATIVE ${name} expected ${expected} got ${actual ?? "no error"}\n`,
  );
}

async function expectVerdictCode(name, options, expectedCode) {
  const harness = await buildFixture(null, options);
  try {
    await runVerification({
      clockchain: harness.clockchain,
      operatorKeyId: KEY_ID,
      operatorPrivateKeyPem: harness.operatorPrivateKeyPem,
      ownerOf: harness.ownerOf,
      relay: harness.relay,
      repositoryPublicKeyResolver: async () =>
        harness.repositoryPublicKey,
      sessionId: RELAY_SESSION_ID,
      subjectRun: harness.subjectRun,
    });
    record(name, expectedCode, undefined);
  } catch (error) {
    record(
      name,
      expectedCode,
      error instanceof BilateralVerdictError
        ? error.terminalCode
        : error.constructor.name,
    );
  } finally {
    await harness.cleanup();
  }
}

async function expectFundingReplay() {
  const name = "duplicate-funding";
  const relayStateDir = await mkdtemp(
    join(tmpdir(), "negative-relay-"),
  );
  const stateDir = await mkdtemp(
    join(tmpdir(), "negative-operator-"),
  );
  const server = createRelayServer({ stateDir: relayStateDir });
  try {
    const address = await server.listen();
    const relayUrl = `http://127.0.0.1:${address.port}`;
    const sessionState = {
      funding: {
        "batch-a": {
          addresses: [
            `0x${"1".repeat(40)}`,
            `0x${"2".repeat(40)}`,
            `0x${"4".repeat(40)}`,
            `0x${"5".repeat(40)}`,
          ],
          completed: false,
        },
        "batch-b": null,
      },
      operatorKeyId: KEY_ID,
      relayUrl,
      schema: OPERATOR_SESSION_SCHEMA,
      subRuns: {
        rehearsal: {
          discovery: null,
          payerAgentId: null,
          sessionId: randomUUID(),
        },
        stakeholder: {
          discovery: null,
          payerAgentId: null,
          sessionId: randomUUID(),
        },
      },
    };
    await writeFile(
      join(stateDir, "operator-session.json"),
      JSON.stringify(sessionState),
      { encoding: "utf8", mode: 0o600 },
    );
    const { privateKey } = generateKeyPairSync("ed25519");
    const fundCalls = [];
    try {
      await runOperator({
        config: {
          operatorKeyId: KEY_ID,
          relayUrl,
          rpcUrlFile: "/tmp/negative-checks-rpc",
          schema: OPERATOR_CONFIG_SCHEMA,
          treasuryAddress: `0x${"3".repeat(40)}`,
          treasuryKeystoreFile: "/tmp/negative-checks-keystore",
          treasuryPasswordFile: "/tmp/negative-checks-password",
        },
        deps: {
          evidencePollIntervalMs: 25,
          fundBatch: async ({ recordPath }) => {
            fundCalls.push(recordPath);
          },
          operatorPrivateKeyPem: privateKey.export({
            format: "pem",
            type: "pkcs8",
          }),
          preflight: async () => {},
          promptSha256: PROMPT_SHA256,
          publicClient: {
            getBalance: async () => 0n,
            getTransactionCount: async () => 0,
          },
          releasePin: {
            chainId: "11155111",
            clockchainUrl: "https://mcp.clockchain.network/mcp",
            generatedAtMs: "1784923000000",
            kitManifestDigest: "c".repeat(64),
            kitRepoUrl:
              "https://github.com/thetangstr/clockchain-handshake.git",
            protocolVersion: BILATERAL_PROTOCOL_ID,
            registry: REGISTRY_ADDRESS,
            repositorySha: REPOSITORY_SHA,
            schema: "handshake-release/v1",
          },
          spawnProcess: () => ({
            exited: Promise.resolve(0),
            kill: () => {},
          }),
          stdout: captureStdout(),
        },
        stateDir,
      });
      record(name, "FUNDING_REPLAYED", undefined);
    } catch (error) {
      if (fundCalls.length !== 0) {
        record(name, "FUNDING_REPLAYED", "treasury touched");
      } else {
        record(
          name,
          "FUNDING_REPLAYED",
          error instanceof OperatorError
            ? error.code
            : error.constructor.name,
        );
      }
    }
  } finally {
    await server.close();
    await rm(relayStateDir, { recursive: true, force: true });
    await rm(stateDir, { recursive: true, force: true });
  }
}

await expectVerdictCode(
  "replay",
  { duplicateMandate: true },
  "DUPLICATE",
);
await expectVerdictCode(
  "reorder",
  { anchors: "reordered" },
  "REORDERED",
);
await expectVerdictCode(
  "tamper",
  { tamperMandate: true },
  "FAILED",
);
await expectFundingReplay();

if (results.every(Boolean)) {
  process.stdout.write("negative-checks: clean\n");
} else {
  process.exitCode = 1;
}
