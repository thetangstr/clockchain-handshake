import assert from "node:assert/strict";
import {
  createHash,
  generateKeyPairSync,
} from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  open as nodeOpen,
  readFile,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  generatePrivateKey,
  privateKeyToAccount,
} from "viem/accounts";

import { assertSecretFree } from "../src/redact.mjs";
import { canonicalBytes } from "../src/bilateral/canonical.mjs";
import {
  createSignedEnvelope,
  dSession,
  rawPublicKeyBase64FromPem,
} from "../src/bilateral/descriptor.mjs";
import {
  authoritativeTriple,
  buildAcceptance,
  buildProposal,
  transitionDigest,
} from "../src/bilateral/messages.mjs";
import {
  ProtocolFailureError,
} from "../src/bilateral/protocol.mjs";
import { sessionKey } from "../src/bilateral/refid.mjs";
import {
  encryptInvitation,
} from "../src/invitation.mjs";
import {
  buildDefaultRoleInput,
  ROLE_REPOSITORY_ROOT,
  ROLE_RESULT_KEYS,
  ROLE_CLI_ARGUMENTS,
  ROLE_RISK_FLAG,
  runPayerRole,
  runPayeeRole,
} from "../src/bilateral/roles.mjs";
import { main as proposeMain } from "../bin/handshake-propose.mjs";
import { main as acceptMain } from "../bin/handshake-accept.mjs";
import {
  createFakeBilateralClockchain,
} from "./helpers/fake-bilateral-clockchain.mjs";
import * as roleModule from "../src/bilateral/roles.mjs";

const PAYER_PRIVATE_KEY = generatePrivateKey();
const PAYEE_PRIVATE_KEY = generatePrivateKey();
const PAYER_ACCOUNT =
  privateKeyToAccount(PAYER_PRIVATE_KEY);
const PAYEE_ACCOUNT =
  privateKeyToAccount(PAYEE_PRIVATE_KEY);
const PAYER_ADDRESS = PAYER_ACCOUNT.address.toLowerCase();
const PAYEE_ADDRESS = PAYEE_ACCOUNT.address.toLowerCase();
const REPOSITORY_PROMPTS = Object.freeze({
  payer: "# Iris role prompt\nUse the signed session.\n",
  payee: "# Billie role prompt\nUse the signed session.\n",
});
const REPOSITORY_PROMPT_DIGESTS = Object.freeze({
  payer: createHash("sha256")
    .update(Buffer.from(REPOSITORY_PROMPTS.payer))
    .digest("hex"),
  payee: createHash("sha256")
    .update(Buffer.from(REPOSITORY_PROMPTS.payee))
    .digest("hex"),
});
const PROMPT_SHA256 = createHash("sha256")
  .update(canonicalBytes(REPOSITORY_PROMPT_DIGESTS))
  .digest("hex");

function descriptor() {
  return {
    amountOptions: [
      { currency: "USD", value: "100" },
      { currency: "USD", value: "250" },
    ],
    chainId: "11155111",
    expirySeconds: "600",
    mandateDigest: "b".repeat(64),
    namespace: "cbv1",
    payee: {
      address: PAYEE_ADDRESS,
      agentId: "8678",
      displayName: "Billie",
      role: "payee",
    },
    payer: {
      address: PAYER_ADDRESS,
      agentId: "8677",
      displayName: "Iris",
      role: "payer",
    },
    paymentMoved: false,
    promptSha256: PROMPT_SHA256,
    protocol: "clockchain.bilateral-authorization/v1",
    protocolVersion: "1",
    registry:
      "0x8004a818bfb912233c491871b3d84c89a494bd9e",
    repositorySha:
      "0123456789abcdef0123456789abcdef01234567",
    requestDigest: "c".repeat(64),
    schema: "clockchain.bilateral-session-descriptor/v2",
    sessionId: "00112233445566778899aabbccddeeff",
    settlement: "not-executed",
  };
}

function signedDescriptor() {
  const { privateKey, publicKey } =
    generateKeyPairSync("ed25519");
  const privateKeyPem = privateKey.export({
    format: "pem",
    type: "pkcs8",
  });
  const publicKeyPem = publicKey.export({
    format: "pem",
    type: "spki",
  });
  const value = descriptor();
  return {
    descriptor: value,
    envelope: createSignedEnvelope(value, {
      keyId: "bilateral-role-test",
      privateKeyPem,
    }),
    repositoryPublicKey:
      rawPublicKeyBase64FromPem(publicKeyPem),
  };
}

function writeArgs(message) {
  return {
    allow_degraded: true,
    asset_hash: transitionDigest(message),
    asset_reference_id: sessionKey(
      message.sessionDigest,
      message.kind,
    ),
    hash_type: "SHA-256",
    idempotency_key: createHash("sha256")
      .update(
        `${message.sessionDigest}|${message.kind}`,
        "utf8",
      )
      .digest("hex")
      .slice(0, 32),
    version_number: 1,
    wait: true,
    wait_ms: 20000,
  };
}

function configuredFake() {
  const fake = createFakeBilateralClockchain();
  fake.registerAgent({
    agentId: "8677",
    owner: PAYER_ADDRESS,
    status: "active",
  });
  fake.registerAgent({
    agentId: "8678",
    owner: PAYEE_ADDRESS,
    status: "active",
  });
  return fake;
}

function ownerOf({ agentId }) {
  if (agentId === "8677") {
    return PAYER_ADDRESS;
  }
  if (agentId === "8678") {
    return PAYEE_ADDRESS;
  }
  throw new Error("unexpected identity");
}

async function outputDirectory(t) {
  const directory = await mkdtemp(
    join(tmpdir(), "bilateral-role-"),
  );
  t.after(() =>
    rm(directory, { force: true, recursive: true }));
  return directory;
}

function triple(kind, record) {
  return authoritativeTriple({
    anchoredHash: record.assetHash,
    blockHeight: record.blockHeight,
    kind,
    ledgerId: record.ledgerId,
  });
}

test("role module exposes generic protocol-role runners without persona exports", () => {
  assert.equal(typeof roleModule.runPayerRole, "function");
  assert.equal(typeof roleModule.runPayeeRole, "function");
  assert.equal("runBillyRole" in roleModule, false);
  assert.equal("runIrisRole" in roleModule, false);
});

test("role CLIs dispatch through generic protocol runners", async () => {
  const files = [
    ["../bin/handshake-propose.mjs", "runPayerRole", "runBillyRole"],
    ["../bin/handshake-accept.mjs", "runPayeeRole", "runIrisRole"],
  ];
  for (const [relative, expected, rejected] of files) {
    const source = await readFile(
      new URL(relative, import.meta.url),
      "utf8",
    );
    assert.match(source, new RegExp(`\\b${expected}\\b`), relative);
    assert.doesNotMatch(source, new RegExp(`\\b${rejected}\\b`), relative);
  }
});

test("descriptor fixtures use Iris payer and Billie payee personas", () => {
  assert.equal(descriptor().payer.displayName, "Iris");
  assert.equal(descriptor().payee.displayName, "Billie");
});

test("payer publishes USD 100, verifies payee acceptance, acknowledges, signs, and emits payer evidence", async (t) => {
  const directory = await outputDirectory(t);
  const {
    descriptor: sessionDescriptor,
    envelope,
    repositoryPublicKey,
  } = signedDescriptor();
  const fake = configuredFake();
  const sessionDigest = dSession(sessionDescriptor);
  const proposal = buildProposal({
    amount: { currency: "USD", value: "100" },
    descriptor: sessionDescriptor,
    sessionDigest,
  });
  const published = [];
  let monotonicMs = 0;
  let acceptanceWritten = false;

  const result = await runPayerRole({
    canaries: ["role-secret-canary"],
    client: fake,
    descriptorEnvelope: envelope,
    jitter: () => 0,
    monotonicNow: () => monotonicMs,
    outputDirectory: directory,
    ownerOf,
    publishEvidence: async (options) => {
      published.push(options);
    },
    repositoryPublicKey,
    signMessage: (bytes) =>
      PAYER_ACCOUNT.signMessage({
        message: { raw: bytes },
      }),
    sleeper: async (delayMs) => {
      monotonicMs += delayMs;
      if (acceptanceWritten) {
        return;
      }
      acceptanceWritten = true;
      const [proposalRecord] = await fake.searchActions({
        asset_reference_id: sessionKey(
          sessionDigest,
          "proposal",
        ),
      });
      const acceptance = buildAcceptance({
        proposal,
        proposalTriple: triple(
          "proposal",
          proposalRecord,
        ),
      });
      await fake.logAction(writeArgs(acceptance));
    },
  });

  assert.deepEqual(Object.keys(result), ROLE_RESULT_KEYS);
  assert.equal(result.localVerdict, "LOCAL_OK");
  assert.equal(result.paymentMoved, false);
  assert.equal(result.role, "payer");
  assert.equal(result.state, "ACKNOWLEDGED");
  assert.equal(result.transitions.length, 3);
  assert.deepEqual(
    result.transitions.map(({ message }) => message.kind),
    ["proposal", "acceptance", "acknowledgment"],
  );
  assert.deepEqual(
    fake.calls.logAction.map(
      ({ asset_reference_id }) => asset_reference_id,
    ),
    [
      sessionKey(sessionDigest, "proposal"),
      sessionKey(sessionDigest, "acceptance"),
      sessionKey(sessionDigest, "acknowledgment"),
    ],
  );
  assert.equal(published.length, 1);
  assert.equal(published[0].directory, directory);
  assert.deepEqual(published[0].canaries, [
    "role-secret-canary",
  ]);
  assert.equal(
    published[0].result.signature.address,
    PAYER_ADDRESS,
  );
  assert.equal(
    published[0].result.signature.algorithm,
    "eip191",
  );
});

test("payee uniquely recovers payer proposal and preserves acceptance when acknowledgment is absent", async (t) => {
  const directory = await outputDirectory(t);
  const {
    descriptor: sessionDescriptor,
    envelope,
    repositoryPublicKey,
  } = signedDescriptor();
  const fake = configuredFake();
  const sessionDigest = dSession(sessionDescriptor);
  const proposal = buildProposal({
    amount: { currency: "USD", value: "100" },
    descriptor: sessionDescriptor,
    sessionDigest,
  });
  await fake.logAction(writeArgs(proposal));
  const published = [];
  let monotonicMs = 0;

  const result = await runPayeeRole({
    acknowledgmentPollDurationMs: 20000,
    client: fake,
    descriptorEnvelope: envelope,
    jitter: () => 0,
    monotonicNow: () => monotonicMs,
    now: () => 1784923200000,
    outputDirectory: directory,
    ownerOf,
    publishEvidence: async (options) => {
      published.push(options);
    },
    repositoryPublicKey,
    signMessage: (bytes) =>
      PAYEE_ACCOUNT.signMessage({
        message: { raw: bytes },
      }),
    sleeper: async (delayMs) => {
      monotonicMs += delayMs;
    },
  });

  assert.equal(result.localVerdict, "LOCAL_OK");
  assert.equal(result.paymentMoved, false);
  assert.equal(result.role, "payee");
  assert.equal(result.state, "ACCEPTED");
  assert.equal(result.ackObserved, false);
  assert.deepEqual(
    result.transitions.map(({ message }) => message.kind),
    ["proposal", "acceptance"],
  );
  assert.equal(fake.calls.logAction.length, 2);
  assert.equal(
    published[0].result.signature.address,
    PAYEE_ADDRESS,
  );
});

test("both identity sources must match before either role can write", async (t) => {
  const directory = await outputDirectory(t);
  const {
    envelope,
    repositoryPublicKey,
  } = signedDescriptor();
  const fake = configuredFake();
  let published = false;

  await assert.rejects(
    runPayerRole({
      client: fake,
      descriptorEnvelope: envelope,
      outputDirectory: directory,
      ownerOf: async () => PAYER_ADDRESS,
      publishEvidence: async () => {
        published = true;
      },
      repositoryPublicKey,
      signMessage: () => {
        throw new Error("must not sign");
      },
    }),
    (error) =>
      error instanceof ProtocolFailureError &&
      error.terminalCode === "FAILED",
  );
  assert.equal(fake.calls.logAction.length, 0);
  assert.equal(published, false);
});

test("one pinned output identity spans every role write and evidence publication", async (t) => {
  const root = await outputDirectory(t);
  const directory = join(root, "output");
  const moved = join(root, "moved-output");
  const replacement = join(root, "replacement");
  await mkdir(directory, { mode: 0o700 });
  await mkdir(replacement, { mode: 0o700 });
  const {
    descriptor: sessionDescriptor,
    envelope,
    repositoryPublicKey,
  } = signedDescriptor();
  const fake = configuredFake();
  const sessionDigest = dSession(sessionDescriptor);
  const proposal = buildProposal({
    amount: { currency: "USD", value: "100" },
    descriptor: sessionDescriptor,
    sessionDigest,
  });
  let monotonicMs = 0;
  let replaced = false;
  let published = false;

  await assert.rejects(
    runPayerRole({
      client: fake,
      descriptorEnvelope: envelope,
      fileSystem: {
        lstat,
        open: nodeOpen,
      },
      jitter: () => 0,
      monotonicNow: () => monotonicMs,
      outputDirectory: directory,
      ownerOf,
      publishEvidence: async () => {
        published = true;
      },
      repositoryPublicKey,
      signMessage: (bytes) =>
        PAYER_ACCOUNT.signMessage({
          message: { raw: bytes },
        }),
      sleeper: async (delayMs) => {
        monotonicMs += delayMs;
        if (replaced) {
          return;
        }
        replaced = true;
        const [proposalRecord] = await fake.searchActions({
          asset_reference_id: sessionKey(
            sessionDigest,
            "proposal",
          ),
        });
        const acceptance = buildAcceptance({
          proposal,
          proposalTriple: triple(
            "proposal",
            proposalRecord,
          ),
        });
        await fake.logAction(writeArgs(acceptance));
        await rename(directory, moved);
        await rename(replacement, directory);
      },
    }),
    (error) =>
      error instanceof ProtocolFailureError &&
      error.terminalCode === "FAILED",
  );
  assert.equal(fake.calls.logAction.length, 2);
  assert.equal(published, false);
});

test("role identity binding ignores non-authoritative resolveAgent status data", async (t) => {
  for (const statusVariant of [
    "inactive",
    undefined,
    "hostile-getter",
  ]) {
    await t.test(String(statusVariant), async (t) => {
      const directory = await outputDirectory(t);
      const {
        envelope,
        repositoryPublicKey,
      } = signedDescriptor();
      const fake = configuredFake();
      const originalResolveAgent = fake.resolveAgent;
      fake.resolveAgent = async (agentId) => {
        const resolved = await originalResolveAgent(agentId);
        const identity = { owner: resolved.owner };
        if (statusVariant === "hostile-getter") {
          Object.defineProperty(identity, "status", {
            enumerable: true,
            get() {
              throw new Error("status must not be read");
            },
          });
        } else if (statusVariant !== undefined) {
          identity.status = statusVariant;
        }
        return identity;
      };

      let monotonicMs = 0;
      await assert.rejects(
        runPayeeRole({
          client: fake,
          descriptorEnvelope: envelope,
          jitter: () => 0,
          monotonicNow: () => monotonicMs,
          now: () => 1784923200000,
          outputDirectory: directory,
          ownerOf,
          proposalPollDurationMs: 20000,
          publishEvidence: async () => {
            assert.fail("an absent proposal must not publish");
          },
          repositoryPublicKey,
          signMessage: () => {
            assert.fail("an absent proposal must not sign");
          },
          sleeper: async (delayMs) => {
            monotonicMs += delayMs;
          },
        }),
        (error) =>
          error instanceof ProtocolFailureError &&
          error.terminalCode === "EXPIRED",
      );
    });
  }
});

test("payee never converts a rate-limited proposal window into absence", async (t) => {
  const directory = await outputDirectory(t);
  const {
    envelope,
    repositoryPublicKey,
  } = signedDescriptor();
  const fake = createFakeBilateralClockchain({
    rateLimitSearch: true,
  });
  fake.registerAgent({
    agentId: "8677",
    owner: PAYER_ADDRESS,
    status: "active",
  });
  fake.registerAgent({
    agentId: "8678",
    owner: PAYEE_ADDRESS,
    status: "active",
  });
  let monotonicMs = 0;

  await assert.rejects(
    runPayeeRole({
      client: fake,
      descriptorEnvelope: envelope,
      jitter: () => 0,
      monotonicNow: () => monotonicMs,
      now: () => 1784923200000,
      outputDirectory: directory,
      ownerOf,
      proposalPollDurationMs: 20000,
      publishEvidence: async () => {
        assert.fail("rate-limited discovery must not publish");
      },
      repositoryPublicKey,
      signMessage: () => {
        assert.fail("rate-limited discovery must not sign");
      },
      sleeper: async (delayMs) => {
        monotonicMs += delayMs;
      },
    }),
    (error) =>
      error instanceof ProtocolFailureError &&
      error.terminalCode === "RATE_BLOCKED",
  );
  assert.equal(fake.calls.logAction.length, 0);
});

test("both CLIs require the exact frozen path flags and valueless write acknowledgement", async () => {
  assert.deepEqual(ROLE_CLI_ARGUMENTS, [
    "--descriptor",
    "--invitation",
    "--clockchain-token-file",
    "--output",
  ]);
  assert.equal(
    ROLE_RISK_FLAG,
    "--i-understand-this-writes-to-clockchain",
  );
  const arguments_ = [
    "--descriptor",
    "/public/session.json",
    "--invitation",
    "/secret/invitation.json",
    "--clockchain-token-file",
    "/secret/clockchain.token",
    "--output",
    "/evidence/payer",
    ROLE_RISK_FLAG,
  ];
  for (const [main, role, state] of [
    [proposeMain, "payer", "ACKNOWLEDGED"],
    [acceptMain, "payee", "ACCEPTED"],
  ]) {
    const roleArguments = arguments_.map((value, index) => (
      arguments_[index - 1] === "--output" ? `/evidence/${role}` : value
    ));
    const writes = [];
    const seen = [];
    const exitCode = await main(roleArguments, {
      buildRoleInput: async (values, actualRole) => {
        seen.push([values, actualRole]);
        return {};
      },
      runRole: async () => ({
        localVerdict: "LOCAL_OK",
        paymentMoved: false,
        role,
        state,
      }),
      stderr: { write: (value) => writes.push(["err", value]) },
      stdout: { write: (value) => writes.push(["out", value]) },
    });
    assert.equal(exitCode, 0);
    assert.equal(seen[0][1], role);
    assert.deepEqual(seen[0][0], {
      descriptorPath: "/public/session.json",
      invitationPath: "/secret/invitation.json",
      clockchainTokenPath: "/secret/clockchain.token",
      outputDirectory: `/evidence/${role === "payer" ? "payer" : "payee"}`,
    });
    assert.deepEqual(writes, [[
      "out",
      `${JSON.stringify({
        localVerdict: "LOCAL_OK",
        paymentMoved: false,
        role,
        state,
      })}\n`,
    ]]);
  }
});

test("role CLIs reject missing acknowledgement, extra flags, and secret argv without calling dependencies", async () => {
  let calls = 0;
  const dependencies = {
    buildRoleInput: async () => {
      calls += 1;
    },
    runRole: async () => {
      calls += 1;
    },
    stderr: { write() {} },
    stdout: { write() {} },
  };
  for (const arguments_ of [
    [],
    [
      "--descriptor", "d",
      "--invitation", "i",
      "--clockchain-token-file", "t",
      "--output", "o",
    ],
    [
      "--descriptor", "d",
      "--invitation", "i",
      "--clockchain-token-file", "t",
      "--output", "o",
      "--private-key-file", "k",
      ROLE_RISK_FLAG,
    ],
    [
      "--descriptor", "d",
      "--invitation", "i",
      "--clockchain-token-file", "t",
      "--output", "o",
      "--private-key", "secret",
      ROLE_RISK_FLAG,
    ],
    [
      "--descriptor", "d",
      "--invitation", "i",
      "--clockchain-token-file", "t",
      "--output", "o",
      ROLE_RISK_FLAG,
      "yes",
    ],
  ]) {
    assert.equal(
      await proposeMain(arguments_, dependencies),
      1,
    );
  }
  assert.equal(calls, 0);
});

test("role CLI emits readiness only after valid argv and input construction", async () => {
  const writes = [];
  let entered = false;
  const arguments_ = [
    "--descriptor", "/public/session.json",
    "--invitation", "/secret/invitation.json",
    "--clockchain-token-file", "/secret/clockchain.token",
    "--output", "/evidence/payer",
    ROLE_RISK_FLAG,
  ];
  const exitCode = await proposeMain(arguments_, {
    buildRoleInput: async () => ({
      notifyReady: () => writes.push("ready"),
    }),
    runRole: async (input) => {
      input.notifyReady();
      entered = true;
      return { localVerdict: "LOCAL_OK", paymentMoved: false, state: "ACKNOWLEDGED" };
    },
    stderr: { write() {} },
    stdout: { write() {} },
  });
  assert.equal(exitCode, 0);
  assert.deepEqual(writes, ["ready"]);
  assert.equal(entered, true);

  writes.length = 0;
  assert.equal(await proposeMain([], {
    buildRoleInput: async () => assert.fail("invalid argv must not build input"),
    runRole: async () => assert.fail("invalid argv must not enter role"),
    stderr: { write() {} },
    stdout: { write() {} },
  }), 1);
  assert.deepEqual(writes, []);
});

test("role modules and CLIs contain no authorizing verdict literal", async () => {
  for (const relative of [
    "../src/bilateral/roles.mjs",
    "../bin/handshake-propose.mjs",
    "../bin/handshake-accept.mjs",
  ]) {
    const source = await import("node:fs/promises").then(
      ({ readFile }) =>
        readFile(new URL(relative, import.meta.url), "utf8"),
    );
    assert.equal(
      source.includes(`AUTHOR${"IZED"}`),
      false,
    );
  }
});

test("role tests contain no private-key-shaped literal", async () => {
  const source = await readFile(
    new URL(import.meta.url),
    "utf8",
  );
  assert.doesNotMatch(source, /0x[0-9a-fA-F]{64}/);
});

async function defaultBuilderFixture(t) {
  const root = await outputDirectory(t);
  const output = join(root, "role-output");
  await mkdir(output, { mode: 0o700 });
  await writeFile(
    join(output, "proposal.intent.json"),
    "{}\n",
    { mode: 0o600 },
  );
  const {
    envelope,
    repositoryPublicKey,
  } = signedDescriptor();
  const descriptorPath = join(root, "descriptor.json");
  await writeFile(
    descriptorPath,
    `${JSON.stringify(envelope)}\n`,
  );
  const privateKey = PAYER_PRIVATE_KEY;
  const code = "builder-invitation-code";
  const bundle = await encryptInvitation(
    {
      address: PAYER_ADDRESS,
      displayName: "Iris",
      privateKey,
    },
    code,
  );
  const invitationPath = join(root, "invitation.json");
  await writeFile(
    invitationPath,
    `${JSON.stringify({ bundle, code })}\n`,
    { mode: 0o600 },
  );
  const token = "clockchain-token-canary";
  const clockchainTokenPath = join(
    root,
    "clockchain.token",
  );
  await writeFile(
    clockchainTokenPath,
    `${token}\n`,
    { mode: 0o600 },
  );
  return {
    dependencies: {
      createClockchainClient: ({ token }) => ({ token }),
      createIdentityClient: () => ({
        async getChainId() {
          return 11155111;
        },
        async readContract() {
          return PAYER_ADDRESS;
        },
      }),
      repositoryPromptResolver: async (request) => {
        assert.equal(
          request.repositoryRoot,
          ROLE_REPOSITORY_ROOT,
        );
        assert.equal(
          request.repositorySha,
          "0123456789abcdef0123456789abcdef01234567",
        );
        if (
          request.repositoryPath ===
          "prompts/run-iris-bilateral-demo.md"
        ) {
          return Buffer.from(REPOSITORY_PROMPTS.payer);
        }
        if (
          request.repositoryPath ===
          "prompts/run-billie-bilateral-demo.md"
        ) {
          return Buffer.from(REPOSITORY_PROMPTS.payee);
        }
        assert.fail("unexpected repository prompt path");
      },
      repositoryPublicKeyResolver: async (request) => {
        assert.deepEqual(request, {
          repositoryPath:
            "docs/operator-keys/bilateral-role-test.pub",
          repositoryRoot: ROLE_REPOSITORY_ROOT,
          repositorySha:
            "0123456789abcdef0123456789abcdef01234567",
        });
        return repositoryPublicKey;
      },
      repositoryStateResolver: async (request) => {
        assert.deepEqual(request, {
          repositoryRoot: ROLE_REPOSITORY_ROOT,
        });
        return {
          headSha:
            "0123456789abcdef0123456789abcdef01234567",
          worktreeStatus: "",
        };
      },
    },
    privateKey,
    token,
    values: {
      clockchainTokenPath,
      descriptorPath,
      invitationPath,
      outputDirectory: output,
    },
  };
}

function adversarialReadHandle(
  handle,
  {
    metadataField,
    onRead,
    overflow = false,
  } = {},
) {
  let statCalls = 0;
  return {
    close: () => handle.close(),
    async read(buffer, offset, length, position) {
      onRead?.(length);
      if (overflow) {
        buffer.fill(0x78, offset, offset + length);
        return { buffer, bytesRead: length };
      }
      return handle.read(buffer, offset, length, position);
    },
    readFile() {
      assert.fail("bounded readers must not call readFile()");
    },
    async stat() {
      const metadata = await handle.stat();
      statCalls += 1;
      if (statCalls === 1 || metadataField === undefined) {
        return metadata;
      }
      return {
        ...metadata,
        [metadataField]: metadata[metadataField] + 1,
        isFile: () => true,
      };
    },
  };
}

test("role repository root is fixed from the role module location", () => {
  assert.equal(
    ROLE_REPOSITORY_ROOT,
    new URL("../", import.meta.url).pathname.replace(/\/$/, ""),
  );
});

test("default builder fails provenance closed before secrets, clients, or tokens", async (t) => {
  const cases = [
    {
      name: "wrong full HEAD",
      override: {
        repositoryStateResolver: async () => ({
          headSha:
            "fedcba9876543210fedcba9876543210fedcba98",
          worktreeStatus: "",
        }),
      },
    },
    {
      name: "dirty worktree",
      override: {
        repositoryStateResolver: async () => ({
          headSha:
            "0123456789abcdef0123456789abcdef01234567",
          worktreeStatus: " M src/bilateral/roles.mjs\n",
        }),
      },
    },
    {
      name: "state resolution failure",
      override: {
        repositoryStateResolver: async () => {
          throw new Error("git failed");
        },
      },
    },
    {
      name: "prompt bundle mismatch",
      override: {
        repositoryPromptResolver: async ({
          repositoryPath,
        }) =>
          Buffer.from(
            repositoryPath.includes("iris")
              ? `${REPOSITORY_PROMPTS.payer}mutated\n`
              : REPOSITORY_PROMPTS.payee,
          ),
      },
    },
    {
      name: "prompt resolution failure",
      override: {
        repositoryPromptResolver: async () => {
          throw new Error("git show failed");
        },
      },
    },
  ];

  for (const scenario of cases) {
    await t.test(scenario.name, async (t) => {
      const fixture = await defaultBuilderFixture(t);
      const calls = {
        clockchainClients: 0,
        identityClients: 0,
        secretReads: 0,
        tokenReads: 0,
      };
      const dependencies = {
        ...fixture.dependencies,
        ...scenario.override,
        createClockchainClient() {
          calls.clockchainClients += 1;
          return {};
        },
        createIdentityClient() {
          calls.identityClients += 1;
          return {};
        },
        fileSystem: {
          async open(path, flags, mode) {
            if (path === fixture.values.clockchainTokenPath) {
              calls.tokenReads += 1;
            }
            return nodeOpen(path, flags, mode);
          },
        },
        async loadInvitation() {
          calls.secretReads += 1;
          throw new Error("must not read invitation");
        },
      };

      await assert.rejects(
        buildDefaultRoleInput(
          fixture.values,
          "payer",
          dependencies,
        ),
        (error) =>
          error instanceof ProtocolFailureError &&
          error.terminalCode === "FAILED",
      );
      assert.deepEqual(calls, {
        clockchainClients: 0,
        identityClients: 0,
        secretReads: 0,
        tokenReads: 0,
      });
    });
  }
});

test("default builder binds the live identity RPC chain before reading protected credential files", async (t) => {
  for (const chainId of [
    11155112,
    "11155112",
    11155111.5,
    "011155111",
    -1,
    null,
    {},
  ]) {
    await t.test(String(chainId), async (t) => {
      const fixture = await defaultBuilderFixture(t);
      const calls = {
        clockchainClients: 0,
        secretReads: 0,
        tokenReads: 0,
      };
      const dependencies = {
        ...fixture.dependencies,
        createClockchainClient() {
          calls.clockchainClients += 1;
          return {};
        },
        createIdentityClient: () => ({
          async getChainId() {
            return chainId;
          },
          async readContract() {
            return PAYER_ADDRESS;
          },
        }),
        fileSystem: {
          async open(path, flags, mode) {
            if (path === fixture.values.clockchainTokenPath) {
              calls.tokenReads += 1;
            }
            return nodeOpen(path, flags, mode);
          },
        },
        async loadInvitation() {
          calls.secretReads += 1;
          throw new Error("must not read invitation");
        },
      };

      await assert.rejects(
        buildDefaultRoleInput(
          fixture.values,
          "payer",
          dependencies,
        ),
        ProtocolFailureError,
      );
      assert.deepEqual(calls, {
        clockchainClients: 0,
        secretReads: 0,
        tokenReads: 0,
      });
    });
  }
});

test("default builder safely reuses an existing intent directory without live network", async (t) => {
  const fixture = await defaultBuilderFixture(t);
  const first = await buildDefaultRoleInput(
    fixture.values,
    "payer",
    fixture.dependencies,
  );
  const second = await buildDefaultRoleInput(
    fixture.values,
    "payer",
    fixture.dependencies,
  );

  assert.equal(first.outputDirectory, fixture.values.outputDirectory);
  assert.equal(second.outputDirectory, fixture.values.outputDirectory);
  assert.equal(first.client.token, "clockchain-token-canary");
  assert.equal(
    await first.ownerOf({
      agentId: "8677",
      registry:
        "0x8004a818bfb912233c491871b3d84c89a494bd9e",
    }),
    PAYER_ADDRESS,
  );
  assert.ok(first.canaries.includes(fixture.privateKey));
  assert.ok(first.canaries.includes("clockchain-token-canary"));
});

test("default builder emits full-size overlapping canaries for long secrets", async (t) => {
  const fragmentExpectation = (secret) => {
    if (secret.length <= 256) {
      return [secret];
    }
    const fragments = [];
    for (let offset = 0; offset + 256 <= secret.length; offset += 256) {
      fragments.push(secret.slice(offset, offset + 256));
    }
    if (secret.length % 256 !== 0) {
      fragments.push(secret.slice(secret.length - 256));
    }
    return fragments;
  };
  const tokenForLength = (length) =>
    length === 257
      ? `${"a".repeat(256)}e`
      : Array.from(
        { length },
        (_value, index) =>
          String.fromCharCode(33 + (index % 90)),
      ).join("");

  for (const length of [256, 257, 4096]) {
    await t.test(`token length ${length}`, async (t) => {
      const fixture = await defaultBuilderFixture(t);
      const invitation = JSON.parse(
        await readFile(fixture.values.invitationPath, "utf8"),
      );
      assert.ok(
        invitation.bundle.crypto.ciphertext.length > 256,
      );
      const token = tokenForLength(length);
      await writeFile(
        fixture.values.clockchainTokenPath,
        length === 4096 ? token : `${token}\n`,
        { mode: 0o600 },
      );

      const input = await buildDefaultRoleInput(
        fixture.values,
        "payer",
        fixture.dependencies,
      );
      const expected = [
        invitation.code,
        invitation.bundle.crypto.ciphertext,
        fixture.privateKey,
        token,
      ].flatMap(fragmentExpectation);
      const tokenFragments = input.canaries.slice(
        -fragmentExpectation(token).length,
      );

      assert.deepEqual(input.canaries, expected);
      assert.ok(tokenFragments.every(
        (fragment) => fragment.length === 256,
      ));
      assert.equal(
        tokenFragments[0], token.slice(0, 256),
      );
      assert.equal(
        tokenFragments.at(-1), token.slice(-256));
      assert.throws(() => assertSecretFree(token, tokenFragments));
      assert.doesNotThrow(() =>
        assertSecretFree("ordinary rendered evidence", tokenFragments),
      );
    });
  }

  await t.test("accepted maximum credential sizes stay within the evidence ceiling", async (t) => {
    const fixture = await defaultBuilderFixture(t);
    const code = "c".repeat(1024);
    const ciphertext = "d".repeat(8192);
    const token = tokenForLength(4096);
    await writeFile(
      fixture.values.clockchainTokenPath,
      token,
      { mode: 0o600 },
    );

    const input = await buildDefaultRoleInput(
      fixture.values,
      "payer",
      {
        ...fixture.dependencies,
        async decryptInvitation() {
          return {
            address: PAYER_ADDRESS,
            privateKey: fixture.privateKey,
          };
        },
        async loadInvitation() {
          return {
            bundle: { crypto: { ciphertext } },
            code,
          };
        },
      },
    );
    const expected = [
      code,
      ciphertext,
      fixture.privateKey,
      token,
    ].flatMap(fragmentExpectation);

    assert.equal(input.canaries.length, 53);
    assert.ok(input.canaries.every(
      (canary) => canary.length > 0 && canary.length <= 256,
    ));
    assert.deepEqual(input.canaries, expected);
  });
});

test("default role builder bounds descriptor and token reads at max plus one", async (t) => {
  for (const target of ["descriptor", "token"]) {
    await t.test(target, async (t) => {
      const fixture = await defaultBuilderFixture(t);
      const targetPath =
        target === "descriptor"
          ? fixture.values.descriptorPath
          : fixture.values.clockchainTokenPath;
      let readLength = 0;
      await assert.rejects(
        buildDefaultRoleInput(
          fixture.values,
          "payer",
          {
            ...fixture.dependencies,
            fileSystem: {
              async open(path, flags, mode) {
                const handle = await nodeOpen(path, flags, mode);
                return path === targetPath
                  ? adversarialReadHandle(handle, {
                      onRead(length) {
                        readLength = length;
                      },
                      overflow: true,
                    })
                  : handle;
              },
            },
          },
        ),
        ProtocolFailureError,
      );
      assert.equal(
        readLength,
        target === "descriptor"
          ? (1024 * 1024) + 1
          : 4097,
      );
    });
  }
});

test("default role builder rejects full-metadata races after bounded reads", async (t) => {
  for (const target of ["descriptor", "token"]) {
    await t.test(target, async (t) => {
      const fixture = await defaultBuilderFixture(t);
      const targetPath =
        target === "descriptor"
          ? fixture.values.descriptorPath
          : fixture.values.clockchainTokenPath;
      const readLengths = [];
      await assert.rejects(
        buildDefaultRoleInput(
          fixture.values,
          "payer",
          {
            ...fixture.dependencies,
            fileSystem: {
              async open(path, flags, mode) {
                const handle = await nodeOpen(path, flags, mode);
                return path === targetPath
                  ? adversarialReadHandle(handle, {
                      metadataField: "ctimeMs",
                      onRead(length) {
                        readLengths.push(length);
                      },
                    })
                  : handle;
              },
            },
          },
        ),
        ProtocolFailureError,
      );
      assert.equal(
        readLengths[0],
        target === "descriptor"
          ? (1024 * 1024) + 1
          : 4097,
      );
      assert.ok(readLengths.length >= 2);
    });
  }
});

test("default builder rejects unsafe output, invitation, token, and duplicate-key inputs before a Clockchain client", async (t) => {
  const fixture = await defaultBuilderFixture(t);
  let clockchainClients = 0;
  const dependencies = {
    ...fixture.dependencies,
    createClockchainClient: () => {
      clockchainClients += 1;
      return {};
    },
  };

  await chmod(fixture.values.outputDirectory, 0o755);
  await assert.rejects(
    buildDefaultRoleInput(
      fixture.values,
      "payer",
      dependencies,
    ),
    ProtocolFailureError,
  );
  await chmod(fixture.values.outputDirectory, 0o700);

  const linkedOutput = join(
    fixture.values.outputDirectory,
    "..",
    "linked-output",
  );
  await symlink(fixture.values.outputDirectory, linkedOutput);
  await assert.rejects(
    buildDefaultRoleInput(
      {
        ...fixture.values,
        outputDirectory: linkedOutput,
      },
      "payer",
      dependencies,
    ),
    ProtocolFailureError,
  );

  const fileOutput = join(
    fixture.values.outputDirectory,
    "..",
    "file-output",
  );
  await writeFile(fileOutput, "not a directory\n", {
    mode: 0o600,
  });
  await assert.rejects(
    buildDefaultRoleInput(
      {
        ...fixture.values,
        outputDirectory: fileOutput,
      },
      "payer",
      dependencies,
    ),
    ProtocolFailureError,
  );

  await chmod(fixture.values.invitationPath, 0o644);
  await assert.rejects(
    buildDefaultRoleInput(
      fixture.values,
      "payer",
      dependencies,
    ),
    ProtocolFailureError,
  );
  await chmod(fixture.values.invitationPath, 0o600);

  await chmod(fixture.values.clockchainTokenPath, 0o644);
  await assert.rejects(
    buildDefaultRoleInput(
      fixture.values,
      "payer",
      dependencies,
    ),
    ProtocolFailureError,
  );
  await chmod(fixture.values.clockchainTokenPath, 0o600);

  await chmod(fixture.values.clockchainTokenPath, 0o400);
  await assert.rejects(
    buildDefaultRoleInput(
      fixture.values,
      "payer",
      dependencies,
    ),
    ProtocolFailureError,
  );
  await chmod(fixture.values.clockchainTokenPath, 0o600);

  const linkedToken = join(
    fixture.values.outputDirectory,
    "..",
    "linked-clockchain.token",
  );
  await symlink(
    fixture.values.clockchainTokenPath,
    linkedToken,
  );
  await assert.rejects(
    buildDefaultRoleInput(
      {
        ...fixture.values,
        clockchainTokenPath: linkedToken,
      },
      "payer",
      dependencies,
    ),
    ProtocolFailureError,
  );

  await assert.rejects(
    buildDefaultRoleInput(
      {
        ...fixture.values,
        clockchainTokenPath: join(
          fixture.values.outputDirectory,
          "..",
          "missing-clockchain.token",
        ),
      },
      "payer",
      dependencies,
    ),
    ProtocolFailureError,
  );

  await writeFile(
    fixture.values.clockchainTokenPath,
    "\n",
    { mode: 0o600 },
  );
  await assert.rejects(
    buildDefaultRoleInput(
      fixture.values,
      "payer",
      dependencies,
    ),
    ProtocolFailureError,
  );

  await writeFile(
    fixture.values.clockchainTokenPath,
    ` ${fixture.token} \n`,
    { mode: 0o600 },
  );
  await assert.rejects(
    buildDefaultRoleInput(
      fixture.values,
      "payer",
      dependencies,
    ),
    ProtocolFailureError,
  );

  await assert.rejects(
    buildDefaultRoleInput(
      {
        ...fixture.values,
        privateKeyPath: join(
          fixture.values.outputDirectory,
          "duplicate-secret.key",
        ),
      },
      "payer",
      dependencies,
    ),
    ProtocolFailureError,
  );
  assert.equal(clockchainClients, 0);
});
