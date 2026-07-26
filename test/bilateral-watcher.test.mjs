import assert from "node:assert/strict";
import {
  generateKeyPairSync,
} from "node:crypto";
import { execFile } from "node:child_process";
import {
  chmod,
  mkdtemp,
  readFile,
  rm,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import {
  deadlineMs,
} from "../src/bilateral/blocktime.mjs";
import {
  createSignedEnvelope,
  dSession,
  rawPublicKeyBase64FromPem,
} from "../src/bilateral/descriptor.mjs";
import {
  authoritativeTriple,
  buildAcceptance,
  buildAcknowledgment,
  buildProposal,
  transitionDigest,
} from "../src/bilateral/messages.mjs";
import { sessionKey } from "../src/bilateral/refid.mjs";
import {
  createFakeBilateralClockchain,
} from "./helpers/fake-bilateral-clockchain.mjs";
import {
  WATCHER_REPORT_SCHEMA,
  main,
  observeBilateralSession,
  runCli,
  watchBilateralSession,
} from "../scripts/watch-bilateral-session.mjs";

const DESCRIPTOR = Object.freeze({
  amountOptions: [
    { currency: "USD", value: "100" },
    { currency: "USD", value: "250" },
  ],
  chainId: "11155111",
  expirySeconds: "600",
  namespace: "cbv1",
  payee: {
    address: "0xffeeddccbbaa99887766554433221100ffeeddcc",
    agentId: "8678",
    displayName: "Iris",
    role: "payee",
  },
  payer: {
    address: "0x00112233445566778899aabbccddeeff00112233",
    agentId: "8677",
    displayName: "Billy",
    role: "payer",
  },
  paymentMoved: false,
  promptSha256:
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  protocol: "clockchain.bilateral-authorization/v1",
  protocolVersion: "1",
  registry: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
  repositorySha: "0123456789abcdef0123456789abcdef01234567",
  schema: "clockchain.bilateral-session-descriptor/v1",
  sessionId: "00112233445566778899aabbccddeeff",
  settlement: "not-executed",
});
const SESSION_DIGEST = dSession(DESCRIPTOR);
const execFileAsync = promisify(execFile);

function signedDescriptorFixture() {
  const { privateKey, publicKey } =
    generateKeyPairSync("ed25519");
  return {
    envelope: createSignedEnvelope(DESCRIPTOR, {
      keyId: "watcher-test",
      privateKeyPem: privateKey.export({
        format: "pem",
        type: "pkcs8",
      }),
    }),
    repositoryPublicKey: rawPublicKeyBase64FromPem(
      publicKey.export({
        format: "pem",
        type: "spki",
      }),
    ),
  };
}

async function seedFake(count = 3, options = {}) {
  const fake = createFakeBilateralClockchain(options);
  fake.registerAgent({
    agentId: DESCRIPTOR.payer.agentId,
    owner: DESCRIPTOR.payer.address,
    status: "active",
  });
  fake.registerAgent({
    agentId: DESCRIPTOR.payee.agentId,
    owner: DESCRIPTOR.payee.address,
    status: "active",
  });
  const messages = [];
  const verified = [];
  const proposal = buildProposal({
    amount: { currency: "USD", value: "100" },
    descriptor: DESCRIPTOR,
    sessionDigest: SESSION_DIGEST,
  });
  messages.push(proposal);

  for (let index = 0; index < count; index += 1) {
    const message = messages[index];
    const written = await fake.logAction({
      allow_degraded: true,
      asset_hash: transitionDigest(message),
      asset_reference_id: sessionKey(
        SESSION_DIGEST,
        message.kind,
      ),
      hash_type: "SHA-256",
      idempotency_key: String(index + 1).padStart(32, "0"),
      version_number: 1,
      wait: true,
      wait_ms: 20000,
    });
    const triple = authoritativeTriple({
      anchoredHash: transitionDigest(message),
      blockHeight: written.blockHeight,
      kind: message.kind,
      ledgerId: written.ledgerId,
    });
    verified.push(triple);
    if (index === 0 && count > 1) {
      messages.push(
        buildAcceptance({
          proposal,
          proposalTriple: triple,
        }),
      );
    }
    if (index === 1 && count > 2) {
      messages.push(
        buildAcknowledgment({
          acceptance: messages[1],
          acceptanceTriple: triple,
          proposalTriple: verified[0],
        }),
      );
    }
  }
  return { fake, messages };
}

test("read-only observer reconstructs and verifies the complete derived-key chain", async () => {
  const { fake } = await seedFake(3);
  const writesBefore = fake.calls.logAction.length;
  const canary = "cc_secret_observer_token_123456789";
  const snapshot = await observeBilateralSession({
    advisory: {
      health: `degraded ${canary}`,
      status: "anchored operator@example.com",
    },
    canaries: [canary],
    client: fake,
    descriptor: DESCRIPTOR,
    now: () => 1_784_923_300_000,
  });

  assert.equal(snapshot.schema, WATCHER_REPORT_SCHEMA);
  assert.equal(snapshot.state, "ACKNOWLEDGED");
  assert.equal(snapshot.terminal, null);
  assert.equal(snapshot.paymentMoved, false);
  assert.equal(snapshot.sessionDigest, SESSION_DIGEST);
  assert.equal(snapshot.transitions.length, 3);
  assert.deepEqual(
    snapshot.transitions.map(
      ({ cardinality, slot, verified }) => ({
        cardinality,
        slot,
        verified,
      }),
    ),
    [
      { cardinality: "1", slot: "proposal", verified: true },
      { cardinality: "1", slot: "acceptance", verified: true },
      {
        cardinality: "1",
        slot: "acknowledgment",
        verified: true,
      },
    ],
  );
  assert.ok(
    BigInt(snapshot.transitions[0].blockHeight) <
      BigInt(snapshot.transitions[1].blockHeight),
  );
  assert.ok(
    BigInt(snapshot.transitions[1].blockHeight) <
      BigInt(snapshot.transitions[2].blockHeight),
  );
  assert.equal(
    snapshot.deadlineMs,
    String(
      deadlineMs(
        Number(snapshot.transitions[0].blockTimeMs),
      ),
    ),
  );
  assert.equal(snapshot.advisory.label, "DISCLOSURE_ONLY");
  assert.equal(snapshot.advisory.health.includes(canary), false);
  assert.equal(
    snapshot.advisory.status.includes("operator@example.com"),
    false,
  );
  assert.equal(fake.calls.logAction.length, writesBefore);
  assert.deepEqual(
    new Set(fake.callSequence.slice(writesBefore).map(({ name }) => name)),
    new Set([
      "searchActions",
      "verifyCrossParty",
      "getBlock",
      "resolveAgent",
    ]),
  );
  assert.equal(
    JSON.stringify(snapshot).includes("AUTHOR" + "IZED"),
    false,
  );
});

test("partial chains display non-authorizing runner states and all three cardinalities", async () => {
  for (const [count, expected] of [
    [0, "UNSTARTED"],
    [1, "PROPOSED"],
    [2, "ACCEPTED"],
  ]) {
    const { fake } = await seedFake(count);
    const snapshot = await observeBilateralSession({
      advisory: { health: null, status: null },
      canaries: [],
      client: fake,
      descriptor: DESCRIPTOR,
      now: () => 1_784_923_300_000,
    });
    assert.equal(snapshot.state, expected);
    assert.equal(snapshot.transitions.length, 3);
    assert.deepEqual(
      snapshot.transitions.map(({ cardinality }) => cardinality),
      [
        count >= 1 ? "1" : "0",
        count >= 2 ? "1" : "0",
        count >= 3 ? "1" : "0",
      ],
    );
  }
});

test("orphaned or reordered successor slots terminate as REORDERED without polling", async () => {
  const { fake } = await seedFake(3);
  const records = await Promise.all(
    ["proposal", "acceptance", "acknowledgment"].map(
      (slot) =>
        fake.searchActions({
          asset_reference_id: sessionKey(
            SESSION_DIGEST,
            slot,
          ),
        }),
    ),
  );
  for (const presence of [
    [false, true, false],
    [false, false, true],
    [true, false, true],
  ]) {
    let sleeperCalls = 0;
    const client = {
      getBlock: (...arguments_) =>
        fake.getBlock(...arguments_),
      resolveAgent: (...arguments_) =>
        fake.resolveAgent(...arguments_),
      searchActions: async ({ asset_reference_id }) => {
        const index = [
          "proposal",
          "acceptance",
          "acknowledgment",
        ].findIndex(
          (slot) =>
            sessionKey(SESSION_DIGEST, slot) ===
            asset_reference_id,
        );
        return presence[index] ? records[index] : [];
      },
      verifyCrossParty: (...arguments_) =>
        fake.verifyCrossParty(...arguments_),
    };
    const snapshots = [];
    const snapshot = await watchBilateralSession({
      advisory: { health: null, status: null },
      canaries: [],
      client,
      descriptor: DESCRIPTOR,
      intervalMs: 20_000,
      now: () => 1_784_923_300_000,
      output: (value) => snapshots.push(value),
      sleeper: async () => {
        sleeperCalls += 1;
      },
      windowMs: 60_000,
    });
    assert.equal(snapshot.terminal, "REORDERED");
    assert.equal(snapshot.paymentMoved, false);
    assert.equal(snapshots.length, 1);
    assert.equal(sleeperCalls, 0);
    assert.deepEqual(
      snapshot.transitions.map(
        ({ cardinality, verified }) => ({
          cardinality,
          verified,
        }),
      ),
      presence.map((present) => ({
        cardinality: present ? "1" : "0",
        verified: false,
      })),
    );
  }
});

test("duplicates, rate limits, malformed bodies, and hostile failures produce fixed safe terminal snapshots", async () => {
  const duplicate = await seedFake(1, {
    duplicateSearch: true,
  });
  const rateLimited = await seedFake(1, {
    rateLimitSearch: true,
  });
  const malformed = await seedFake(1, {
    nonArraySearch: true,
  });
  const hostile = {
    async getBlock() {
      throw new Error("cc_secret_should_not_escape_123456");
    },
    async resolveAgent() {
      throw new Error("operator@example.com");
    },
    async searchActions() {
      throw new Proxy({}, {
        get() {
          throw new Error("secret getter");
        },
      });
    },
    async verifyCrossParty() {
      throw new Error("private key: 0x" + "ab".repeat(32));
    },
  };

  for (const [client, terminal] of [
    [duplicate.fake, "DUPLICATE"],
    [rateLimited.fake, "RATE_BLOCKED"],
    [malformed.fake, "FAILED"],
    [hostile, "FAILED"],
  ]) {
    const snapshot = await observeBilateralSession({
      advisory: { health: null, status: null },
      canaries: ["cc_secret_should_not_escape_123456"],
      client,
      descriptor: DESCRIPTOR,
      now: () => 1_784_923_300_000,
    });
    assert.equal(snapshot.terminal, terminal);
    const output = JSON.stringify(snapshot);
    assert.equal(output.includes("cc_secret"), false);
    assert.equal(output.includes("operator@example.com"), false);
    assert.equal(output.includes("ab".repeat(32)), false);
  }
});

test("watch loop uses injected clock/sleeper/output and stops after acknowledgment", async () => {
  const { fake } = await seedFake(3);
  let now = 10_000;
  const sleeps = [];
  const outputs = [];
  const result = await watchBilateralSession({
    advisory: { health: "single-validator", status: "observed" },
    canaries: [],
    client: fake,
    descriptor: DESCRIPTOR,
    intervalMs: 20_000,
    now: () => now,
    output: (snapshot) => outputs.push(snapshot),
    sleeper: async (milliseconds) => {
      sleeps.push(milliseconds);
      now += milliseconds;
    },
    windowMs: 60_000,
  });

  assert.equal(result.state, "ACKNOWLEDGED");
  assert.equal(outputs.length, 1);
  assert.deepEqual(sleeps, []);
});

test("CLI verifies an injected repository key before creating a client and watches the inner descriptor", async () => {
  const { fake } = await seedFake(1);
  const lines = [];
  const token = "cc_secret_cli_token_123456789";
  const signed = signedDescriptorFixture();
  const events = [];
  const exitCode = await runCli(
    [
      "--descriptor-file",
      "/public/session.json",
      "--token-file",
      "/secret/token",
    ],
    {
      createClient: ({ token: received }) => {
        events.push("client");
        assert.equal(received, token);
        return fake;
      },
      now: () => 10_000,
      output: (line) => lines.push(line),
      readText: async (path) => {
        events.push(
          path.endsWith("session.json")
            ? "descriptor"
            : "token",
        );
        return path.endsWith("session.json")
          ? JSON.stringify(signed.envelope)
          : token;
      },
      repositoryPublicKeyResolver: async (request) => {
        events.push("repository-key");
        assert.deepEqual(request, {
          repositoryPath:
            "docs/operator-keys/watcher-test.pub",
          repositorySha: DESCRIPTOR.repositorySha,
        });
        return signed.repositoryPublicKey;
      },
      sleeper: async () => {},
      windowMs: 0,
    },
  );

  assert.equal(exitCode, 0);
  assert.equal(lines.length, 1);
  assert.equal(lines[0].includes(token), false);
  assert.equal(
    JSON.parse(lines[0]).state,
    "PROPOSED",
  );
  assert.deepEqual(events, [
    "descriptor",
    "repository-key",
    "token",
    "client",
  ]);
  await assert.rejects(
    () => main(["--descriptor-file", "/public/session.json"]),
    /watcher/i,
  );
});

test("CLI default repository-key resolution reads the descriptor-pinned Git object", async () => {
  const { fake } = await seedFake(0);
  const signed = signedDescriptorFixture();
  const gitCalls = [];
  let clientCalls = 0;
  const result = await main(
    [
      "--descriptor-file",
      "/public/session.json",
      "--token-file",
      "/secret/token",
    ],
    {
      createClient: () => {
        clientCalls += 1;
        return fake;
      },
      now: () => 10_000,
      output: () => {},
      readText: async (path) =>
        path.endsWith("session.json")
          ? JSON.stringify(signed.envelope)
          : "cc_secret_default_key_token",
      runGit: async (...arguments_) => {
        gitCalls.push(arguments_);
        return {
          stdout: `${signed.repositoryPublicKey}\n`,
        };
      },
      sleeper: async () => {},
      windowMs: 0,
    },
  );

  assert.equal(result.state, "UNSTARTED");
  assert.equal(clientCalls, 1);
  assert.deepEqual(
    gitCalls.map(([command, arguments_]) => [
      command,
      arguments_,
    ]),
    [
      [
        "git",
        [
          "cat-file",
          "-e",
          `${DESCRIPTOR.repositorySha}^{commit}`,
        ],
      ],
      [
        "git",
        [
        "show",
        `${DESCRIPTOR.repositorySha}:docs/operator-keys/watcher-test.pub`,
        ],
      ],
    ],
  );
});

test("CLI default key resolution rejects a non-commit before token read or client creation", async () => {
  const signed = signedDescriptorFixture();
  const reads = [];
  const gitCalls = [];
  let clientCalls = 0;
  const exitCode = await runCli(
    [
      "--descriptor-file",
      "/public/session.json",
      "--token-file",
      "/secret/token",
    ],
    {
      createClient: () => {
        clientCalls += 1;
        return {};
      },
      readText: async (path) => {
        reads.push(path);
        if (path.endsWith("session.json")) {
          return JSON.stringify(signed.envelope);
        }
        assert.fail(
          "non-commit provenance must fail before token read",
        );
      },
      runGit: async (command, arguments_) => {
        gitCalls.push([command, arguments_]);
        const error = new Error("object is not a commit");
        error.code = 1;
        throw error;
      },
      writeError: () => {},
    },
  );
  assert.equal(exitCode, 1);
  assert.equal(clientCalls, 0);
  assert.deepEqual(reads, ["/public/session.json"]);
  assert.deepEqual(gitCalls, [[
    "git",
    [
      "cat-file",
      "-e",
      `${DESCRIPTOR.repositorySha}^{commit}`,
    ],
  ]]);
});

test("CLI rejects malformed provenance before reading the token or creating a Clockchain client", async (t) => {
  const valid = signedDescriptorFixture();
  const wrong = signedDescriptorFixture();
  const forged = structuredClone(valid.envelope);
  forged.operator.signature =
    `${forged.operator.signature.slice(0, -2)}AA`;

  for (const [name, descriptorText, key] of [
    ["raw descriptor", JSON.stringify(DESCRIPTOR), valid.repositoryPublicKey],
    ["forged signature", JSON.stringify(forged), valid.repositoryPublicKey],
    [
      "repository key mismatch",
      JSON.stringify(valid.envelope),
      wrong.repositoryPublicKey,
    ],
    ["malformed JSON", "{", valid.repositoryPublicKey],
  ]) {
    await t.test(name, async () => {
      const reads = [];
      let clientCalls = 0;
      const exitCode = await runCli(
        [
          "--descriptor-file",
          "/public/session.json",
          "--token-file",
          "/secret/token",
        ],
        {
          createClient: () => {
            clientCalls += 1;
            return {};
          },
          readText: async (path) => {
            reads.push(path);
            if (path.endsWith("session.json")) {
              return descriptorText;
            }
            throw new Error("token must not be read");
          },
          repositoryPublicKeyResolver: async () => key,
          writeError: () => {},
        },
      );
      assert.equal(exitCode, 1);
      assert.equal(clientCalls, 0);
      assert.deepEqual(reads, ["/public/session.json"]);
    });
  }
});

test("CLI rejects a wrong-chain descriptor before reading the token or creating a client", async () => {
  const valid = signedDescriptorFixture();
  const wrongChain = structuredClone(valid.envelope);
  wrongChain.descriptor.chainId = "1";
  const reads = [];
  let clientCalls = 0;
  const exitCode = await runCli(
    [
      "--descriptor-file",
      "/public/session.json",
      "--token-file",
      "/secret/token",
    ],
    {
      createClient: () => {
        clientCalls += 1;
        return {};
      },
      readText: async (path) => {
        reads.push(path);
        if (path.endsWith("session.json")) {
          return JSON.stringify(wrongChain);
        }
        assert.fail("wrong chain must fail before token read");
      },
      repositoryPublicKeyResolver: async () =>
        valid.repositoryPublicKey,
      writeError: () => {},
    },
  );
  assert.equal(exitCode, 1);
  assert.equal(clientCalls, 0);
  assert.deepEqual(reads, ["/public/session.json"]);
});

async function watcherFileFixture(t) {
  const root = await mkdtemp(
    join(tmpdir(), "bilateral-watcher-files-"),
  );
  await chmod(root, 0o700);
  t.after(() =>
    rm(root, { force: true, recursive: true }));
  const signed = signedDescriptorFixture();
  const descriptorPath = join(root, "descriptor.json");
  const tokenPath = join(root, "clockchain.token");
  await writeFile(
    descriptorPath,
    JSON.stringify(signed.envelope),
    { mode: 0o644 },
  );
  await writeFile(
    tokenPath,
    "cc_runtime_generated_watcher_token_123456",
    { mode: 0o600 },
  );
  return {
    descriptorPath,
    repositoryPublicKey: signed.repositoryPublicKey,
    root,
    tokenPath,
  };
}

test("watcher rejects permissive, symlink, and FIFO token inputs before client construction", async (t) => {
  const fixture = await watcherFileFixture(t);
  const arguments_ = [
    "--descriptor-file",
    fixture.descriptorPath,
    "--token-file",
    fixture.tokenPath,
  ];
  let clientCalls = 0;
  const dependencies = {
    createClient: () => {
      clientCalls += 1;
      return {};
    },
    repositoryPublicKeyResolver: async () =>
      fixture.repositoryPublicKey,
    writeError: () => {},
  };

  await chmod(fixture.tokenPath, 0o644);
  assert.equal(await runCli(arguments_, dependencies), 1);
  assert.equal(clientCalls, 0);

  await unlink(fixture.tokenPath);
  const target = join(fixture.root, "target.token");
  await writeFile(
    target,
    "cc_runtime_generated_watcher_token_654321",
    { mode: 0o600 },
  );
  await symlink(target, fixture.tokenPath);
  assert.equal(await runCli(arguments_, dependencies), 1);
  assert.equal(clientCalls, 0);

  if (process.platform !== "win32") {
    await unlink(fixture.tokenPath);
    await execFileAsync("mkfifo", [fixture.tokenPath]);
    await chmod(fixture.tokenPath, 0o600);
    assert.equal(
      await runCli(arguments_, dependencies),
      1,
    );
    assert.equal(clientCalls, 0);
  }
});

test("bounded watcher reads reject descriptor identity changes and close failures", async () => {
  const watcherModule = await import(
    "../scripts/watch-bilateral-session.mjs"
  );
  assert.equal(
    typeof watcherModule.readBoundedText,
    "function",
    "watcher must expose its bounded reader for focused race testing",
  );
  const token =
    "cc_runtime_generated_watcher_token_race";
  let statCalls = 0;
  let closeCalls = 0;
  const metadata = (ino) => ({
    dev: 1,
    ino,
    isFile: () => true,
    mode: 0o100600,
    mtimeMs: 1,
    size: Buffer.byteLength(token),
  });
  await assert.rejects(
    () =>
      watcherModule.readBoundedText(
        "/secret/token",
        "token",
        async () => {
          let consumed = false;
          return {
            async close() {
              closeCalls += 1;
            },
            async read(buffer, offset) {
              if (consumed) {
                return { bytesRead: 0 };
              }
              consumed = true;
              Buffer.from(token).copy(buffer, offset);
              return {
                bytesRead: Buffer.byteLength(token),
              };
            },
            async stat() {
              statCalls += 1;
              return metadata(
                statCalls === 1 ? 10 : 11,
              );
            },
          };
        },
      ),
    /watcher/i,
  );
  assert.equal(closeCalls, 1);

  await assert.rejects(
    () =>
      watcherModule.readBoundedText(
        "/secret/token",
        "token",
        async () => {
          let consumed = false;
          return {
            async close() {
              throw new Error("close failed");
            },
            async read(buffer, offset) {
              if (consumed) {
                return { bytesRead: 0 };
              }
              consumed = true;
              Buffer.from(token).copy(buffer, offset);
              return {
                bytesRead: Buffer.byteLength(token),
              };
            },
            async stat() {
              return metadata(10);
            },
          };
        },
      ),
    /watcher/i,
  );
});

test("bounded watcher reads use maximum-plus-one reads and reject growth overflow", async () => {
  const maximum = 4096;
  const token = "x".repeat(maximum + 1);
  let readCalls = 0;
  let closeCalls = 0;
  const metadata = {
    dev: 1,
    ino: 10,
    isFile: () => true,
    mode: 0o100600,
    mtimeMs: 1,
    size: maximum,
  };
  await assert.rejects(
    () =>
      import(
        "../scripts/watch-bilateral-session.mjs"
      ).then(({ readBoundedText }) =>
        readBoundedText(
          "/secret/token",
          "token",
          async () => ({
            async close() {
              closeCalls += 1;
            },
            async read(buffer, offset, length) {
              readCalls += 1;
              assert.equal(length, maximum + 1);
              Buffer.from(token).copy(buffer, offset);
              return { bytesRead: maximum + 1 };
            },
            async readFile() {
              assert.fail(
                "bounded reader must not call readFile",
              );
            },
            async stat() {
              return metadata;
            },
          }),
        ),
      ),
    /watcher/i,
  );
  assert.equal(readCalls, 1);
  assert.equal(closeCalls, 1);
});

test("a full valid 4096-byte token is accepted as a redaction canary", async () => {
  const { fake } = await seedFake(0);
  const signed = signedDescriptorFixture();
  const token = "x".repeat(4096);
  const lines = [];
  let clientCalls = 0;
  const result = await main(
    [
      "--descriptor-file",
      "/public/session.json",
      "--token-file",
      "/secret/token",
    ],
    {
      createClient: ({ token: received }) => {
        clientCalls += 1;
        assert.equal(received, token);
        return fake;
      },
      now: () => 10_000,
      output: (line) => lines.push(line),
      readText: async (path) =>
        path.endsWith("session.json")
          ? JSON.stringify(signed.envelope)
          : token,
      repositoryPublicKeyResolver: async () =>
        signed.repositoryPublicKey,
      sleeper: async () => {},
      windowMs: 0,
    },
  );
  assert.equal(result.state, "UNSTARTED");
  assert.equal(clientCalls, 1);
  assert.equal(lines.length, 1);
  assert.equal(lines[0].includes(token), false);
});

test("watcher source contains no write call, evidence writer, or authorizing verdict literal", async () => {
  const source = await readFile(
    new URL(
      "../scripts/watch-bilateral-session.mjs",
      import.meta.url,
    ),
    "utf8",
  );
  assert.equal(source.includes(".logAction"), false);
  assert.equal(source.includes("writePartyResult"), false);
  assert.equal(source.includes("AUTHOR" + "IZED"), false);
});
