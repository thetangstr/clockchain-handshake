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

import { assertSecretFree } from "../src/core/redact.mjs";
import { canonicalBytes } from "../src/core/canonical.mjs";
import {
  createSignedEnvelope,
  dSession,
  rawPublicKeyBase64FromPem,
} from "../src/core/descriptor.mjs";
import {
  authoritativeTriple,
  buildAcceptance,
  buildProposal,
  transitionDigest,
} from "../src/core/messages.mjs";
import {
  ProtocolFailureError,
} from "../src/core/protocol.mjs";
import { sessionKey } from "../src/core/refid.mjs";
import {
  ROLE_REPOSITORY_ROOT,
  ROLE_RESULT_KEYS,
  runPayerRole,
  runPayeeRole,
} from "../src/core/roles-core.mjs";
import {
  createFakeBilateralClockchain,
} from "./helpers/fake-bilateral-clockchain.mjs";
import * as roleModule from "../src/core/roles-core.mjs";


const PAYER_PRIVATE_KEY = generatePrivateKey();
const PAYEE_PRIVATE_KEY = generatePrivateKey();
const PAYER_ACCOUNT =
  privateKeyToAccount(PAYER_PRIVATE_KEY);
const PAYEE_ACCOUNT =
  privateKeyToAccount(PAYEE_PRIVATE_KEY);
const PAYER_ADDRESS = PAYER_ACCOUNT.address.toLowerCase();
const PAYEE_ADDRESS = PAYEE_ACCOUNT.address.toLowerCase();
const REPOSITORY_PROMPTS = Object.freeze({
  payer: "# Payer role prompt\nUse the signed session.\n",
  payee: "# Requestor role prompt\nUse the signed session.\n",
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
      displayName: "Requestor",
      role: "payee",
    },
    payer: {
      address: PAYER_ADDRESS,
      agentId: "8677",
      displayName: "Payer",
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
  assert.equal("runBillieRole" in roleModule, false);
  assert.equal("runBillyRole" in roleModule, false);
  assert.equal("runIrisRole" in roleModule, false);
});

test("descriptor fixtures use generic display names while protocol keys stay stable", () => {
  assert.equal(descriptor().payer.displayName, "Payer");
  assert.equal(descriptor().payee.displayName, "Requestor");
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

test("role modules and CLIs contain no authorizing verdict literal", async () => {
  for (const relative of [
    "../src/core/roles-core.mjs",
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

test("role repository root is fixed from the role module location", () => {
  assert.equal(
    ROLE_REPOSITORY_ROOT,
    new URL("../", import.meta.url).pathname.replace(/\/$/, ""),
  );
});

