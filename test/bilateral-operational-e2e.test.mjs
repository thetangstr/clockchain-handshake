import assert from "node:assert/strict";
import {
  execFile,
} from "node:child_process";
import {
  createHash,
  generateKeyPairSync,
} from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  unlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import {
  dirname,
  join,
} from "node:path";
import {
  fileURLToPath,
  pathToFileURL,
} from "node:url";
import { promisify } from "node:util";
import test from "node:test";

import {
  recoverMessageAddress,
} from "viem";
import {
  generatePrivateKey,
  privateKeyToAccount,
} from "viem/accounts";

import {
  createSignedEnvelope,
  dSession,
  rawPublicKeyBase64FromPem,
} from "../src/bilateral/descriptor.mjs";
import {
  partySignatureBytes,
  renderPartyResultMarkdown,
} from "../src/bilateral/evidence.mjs";
import {
  buildProposal,
  authoritativeTriple,
  transitionDigest,
} from "../src/bilateral/messages.mjs";
import {
  payerMandateDigest,
  signPayerMandate,
} from "../src/bilateral/payer-mandate.mjs";
import {
  paymentRequestDigest,
  signPaymentRequest,
} from "../src/bilateral/payment-request.mjs";
import {
  ProtocolFailureError,
} from "../src/bilateral/protocol.mjs";
import {
  runPayerRole,
  runPayeeRole,
} from "../src/bilateral/roles.mjs";
import {
  pollForTransition,
  writeOrAdoptTransition,
} from "../src/bilateral/runner.mjs";
import {
  BilateralVerdictError,
  verifyBilateralAuthorization,
} from "../src/bilateral/verdict.mjs";
import {
  sessionKey,
} from "../src/bilateral/refid.mjs";
import {
  observeBilateralSession,
} from "../scripts/watch-bilateral-session.mjs";
import {
  PREFLIGHT_POLL_INTERVAL_MS,
  runBilateralPreflight,
} from "../scripts/probe-bilateral-rendezvous.mjs";
import {
  createFakeBilateralClockchain,
} from "./helpers/fake-bilateral-clockchain.mjs";
import { McpNetworkError } from "../src/mcp.mjs";

const execFileAsync = promisify(execFile);
const ROOT_DIRECTORY = dirname(
  dirname(fileURLToPath(import.meta.url)),
);
const PAYER = privateKeyToAccount(generatePrivateKey());
const PAYEE = privateKeyToAccount(generatePrivateKey());
const INTAKE_DIGEST = "b".repeat(64);
const INTAKE_REQUEST_ID = "22222222-3333-4444-8555-666666666666";
const ROLE_CANARY = "operational-role-secret-canary";
const SLOTS = Object.freeze([
  "proposal",
  "acceptance",
  "acknowledgment",
]);

function descriptorFixture({ mandateDigest, requestDigest } = {}) {
  return {
    amountOptions: [
      { currency: "USD", value: "100" },
      { currency: "USD", value: "250" },
    ],
    chainId: "11155111",
    expirySeconds: "600",
    mandateDigest: mandateDigest ?? "b".repeat(64),
    namespace: "cbv1",
    payee: {
      address: PAYEE.address.toLowerCase(),
      agentId: "8678",
      displayName: "Billie",
      role: "payee",
    },
    payer: {
      address: PAYER.address.toLowerCase(),
      agentId: "8677",
      displayName: "Iris",
      role: "payer",
    },
    paymentMoved: false,
    promptSha256:
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    protocol: "clockchain.bilateral-authorization/v1",
    protocolVersion: "1",
    registry:
      "0x8004a818bfb912233c491871b3d84c89a494bd9e",
    repositorySha:
      "0123456789abcdef0123456789abcdef01234567",
    requestDigest: requestDigest ?? "c".repeat(64),
    schema: "clockchain.bilateral-session-descriptor/v2",
    sessionId: "00112233445566778899aabbccddeeff",
    settlement: "not-executed",
  };
}

async function intentEnvelopes() {
  const sessionId = "00112233-4455-6677-8899-aabbccddeeff";
  const mandate = {
    amount: { currency: "USD", value: "100" },
    expiresAtMs: "1784923800000",
    intakeDigest: INTAKE_DIGEST,
    intakeRequestId: INTAKE_REQUEST_ID,
    invoiceReferencePrefix: "INV-",
    issuedAtMs: "1784923100000",
    payee: { address: PAYEE.address.toLowerCase(), agentId: "8678" },
    payer: { address: PAYER.address.toLowerCase(), agentId: "8677" },
    paymentMoved: false,
    protocol: "clockchain.bilateral-authorization/v1",
    purpose: "Invoice settlement",
    releaseId: "release-1",
    repositorySha: "0123456789abcdef0123456789abcdef01234567",
    requestEndpoint: `/v1/sessions/${sessionId}/payment-requests`,
    schema: "clockchain.bilateral-payer-mandate/v1",
    sessionId,
    subjectRun: "rehearsal",
  };
  const mandateEnvelope = await signPayerMandate({
    mandate,
    signMessage: (raw) => PAYER.signMessage({ message: { raw } }),
  });
  const requestEnvelope = await signPaymentRequest({
    request: {
      amount: mandate.amount,
      createdAtMs: "1784923150000",
      expiresAtMs: "1784923700000",
      intakeDigest: INTAKE_DIGEST,
      intakeRequestId: INTAKE_REQUEST_ID,
      invoiceReference: "INV-0001",
      mandateDigest: payerMandateDigest(mandateEnvelope),
      payee: mandate.payee,
      payer: mandate.payer,
      paymentMoved: false,
      protocol: mandate.protocol,
      purpose: mandate.purpose,
      releaseId: mandate.releaseId,
      repositorySha: mandate.repositorySha,
      requestId: "00000000-0000-4000-8000-000000000001",
      schema: "clockchain.bilateral-payment-request/v1",
      sessionId,
      subjectRun: mandate.subjectRun,
    },
    signMessage: (raw) => PAYEE.signMessage({ message: { raw } }),
  });
  return Object.freeze({ mandateEnvelope, requestEnvelope });
}

async function signedDescriptorFixture() {
  const { privateKey, publicKey } =
    generateKeyPairSync("ed25519");
  const { mandateEnvelope, requestEnvelope } =
    await intentEnvelopes();
  const descriptor = descriptorFixture({
    mandateDigest: payerMandateDigest(mandateEnvelope),
    requestDigest: paymentRequestDigest(requestEnvelope),
  });
  return {
    descriptor,
    descriptorEnvelope: createSignedEnvelope(descriptor, {
      keyId: "operational-e2e",
      privateKeyPem: privateKey.export({
        format: "pem",
        type: "pkcs8",
      }),
    }),
    mandateEnvelope,
    repositoryPublicKey: rawPublicKeyBase64FromPem(
      publicKey.export({
        format: "pem",
        type: "spki",
      }),
    ),
    requestEnvelope,
  };
}

function configuredFake(options) {
  const fake = createFakeBilateralClockchain(options);
  fake.registerAgent({
    agentId: "8677",
    owner: PAYER.address.toLowerCase(),
    status: "active",
  });
  fake.registerAgent({
    agentId: "8678",
    owner: PAYEE.address.toLowerCase(),
    status: "active",
  });
  return fake;
}

function ownerOf({ agentId }) {
  if (agentId === "8677") {
    return PAYER.address.toLowerCase();
  }
  if (agentId === "8678") {
    return PAYEE.address.toLowerCase();
  }
  throw new Error("unknown agent");
}

function cooperativeClock() {
  let elapsedMs = 0;
  return {
    monotonicNow: () => elapsedMs,
    sleeper: async (delayMs) => {
      assert.equal(Number.isSafeInteger(delayMs), true);
      elapsedMs += 1;
      await new Promise((resolve) => setImmediate(resolve));
    },
  };
}

async function operationalRoot(t) {
  const root = await mkdtemp(
    join(tmpdir(), "bilateral-operational-e2e-"),
  );
  t.after(() =>
    rm(root, { force: true, recursive: true }));
  return root;
}

async function runIsolatedRoles(t, options = {}) {
  const root = await operationalRoot(t);
  const payerDirectory = join(root, "payer");
  const payeeDirectory = join(root, "payee");
  await Promise.all([
    mkdir(payerDirectory, { mode: 0o700 }),
    mkdir(payeeDirectory, { mode: 0o700 }),
  ]);
  const signed = await signedDescriptorFixture();
  const fake = configuredFake(options.fakeOptions);
  const payerClock = cooperativeClock();
  const payeeClock = cooperativeClock();

  const payeePromise = runPayeeRole({
    acknowledgmentPollDurationMs: 120_000,
    canaries: [ROLE_CANARY],
    client: fake,
    descriptorEnvelope: signed.descriptorEnvelope,
    jitter: () => 0,
    monotonicNow: payeeClock.monotonicNow,
    now: () => 1_784_923_200_000,
    outputDirectory: payeeDirectory,
    ownerOf,
    proposalPollDurationMs: 120_000,
    repositoryPublicKey: signed.repositoryPublicKey,
    signMessage: (bytes) =>
      PAYEE.signMessage({ message: { raw: bytes } }),
    sleeper: payeeClock.sleeper,
  });
  const payerPromise = runPayerRole({
    canaries: [ROLE_CANARY],
    client: fake,
    descriptorEnvelope: signed.descriptorEnvelope,
    jitter: () => 0,
    monotonicNow: payerClock.monotonicNow,
    outputDirectory: payerDirectory,
    ownerOf,
    repositoryPublicKey: signed.repositoryPublicKey,
    signMessage: (bytes) =>
      PAYER.signMessage({ message: { raw: bytes } }),
    sleeper: payerClock.sleeper,
  });
  const [payeeResult, payerResult] = await Promise.all([
    payeePromise,
    payerPromise,
  ]);
  return {
    ...signed,
    fake,
    payeeDirectory,
    payeeResult,
    payerDirectory,
    payerResult,
    root,
    sessionDigest: dSession(signed.descriptor),
  };
}

async function readPartyResult(directory) {
  return JSON.parse(
    await readFile(join(directory, "party-result.json"), "utf8"),
  );
}

async function assertValidPartySignature(party) {
  const recovered = await recoverMessageAddress({
    message: {
      raw: partySignatureBytes({
        role: party.role,
        sessionDigest: party.sessionDigest,
        transitions: party.transitions,
      }),
    },
    signature: party.signature.signature,
  });
  assert.equal(
    recovered.toLowerCase(),
    party.signature.address.toLowerCase(),
  );
}

function authoritativeEntry(entry) {
  return authoritativeTriple({
    anchoredHash: entry.onChain.anchoredHash,
    blockHeight: entry.onChain.blockHeight,
    kind: entry.message.kind,
    ledgerId: entry.onChain.ledgerId,
  });
}

async function publicReadModel(fake, descriptor, sessionDigest) {
  const searches = {};
  const crossParty = {};
  const blocks = {};
  const audits = {};
  for (const slot of SLOTS) {
    const referenceId = sessionKey(sessionDigest, slot);
    const records = await fake.searchActions({
      asset_reference_id: referenceId,
    });
    searches[referenceId] = records;
    audits[referenceId] = await fake.generateAuditTrail({
      asset_reference_id: referenceId,
    });
    for (const record of records) {
      const key = `${record.ledgerId}|${record.blockHeight}`;
      crossParty[key] = await fake.verifyCrossParty({
        blockHeight: record.blockHeight,
        ledgerId: record.ledgerId,
      });
      blocks[record.blockHeight] = await fake.getBlock({
        height: record.blockHeight,
      });
    }
  }
  const agents = {};
  for (const party of [descriptor.payer, descriptor.payee]) {
    agents[party.agentId] = await fake.resolveAgent(party.agentId);
  }
  return {
    agents,
    audits,
    blocks,
    crossParty,
    searches,
  };
}

function unavailableBlock() {
  return new McpNetworkError(
    "deterministic MCP read exhausted retries",
  );
}

function readOnlyClockchain(readModel, overrides = {}) {
  const base = {
    async generateAuditTrail({
      asset_reference_id: referenceId,
    }) {
      return structuredClone(
        readModel.audits[referenceId],
      );
    },
    async getBlock({ height }) {
      const block = readModel.blocks[String(height)];
      if (block === undefined) {
        throw unavailableBlock();
      }
      return structuredClone(block);
    },
    async resolveAgent(agentId) {
      return structuredClone(
        readModel.agents[String(agentId)],
      );
    },
    async searchActions({
      asset_reference_id: referenceId,
    }) {
      return structuredClone(
        readModel.searches[referenceId] ?? [],
      );
    },
    async verifyCrossParty({
      blockHeight,
      ledgerId,
    }) {
      return structuredClone(
        readModel.crossParty[
          `${ledgerId}|${blockHeight}`
        ],
      );
    },
  };
  return {
    ...base,
    ...overrides,
  };
}

function aggregateInput(
  fixture,
  clockchain,
  overrides = {},
) {
  return {
    canaries: overrides.canaries ?? [],
    clockchain,
    descriptorEnvelope: fixture.descriptorEnvelope,
    mandateEnvelope:
      overrides.mandateEnvelope ?? fixture.mandateEnvelope,
    ownerOf: overrides.ownerOf ?? ownerOf,
    payeeDirectory:
      overrides.payeeDirectory ??
      fixture.payeeDirectory,
    payerDirectory:
      overrides.payerDirectory ??
      fixture.payerDirectory,
    requestEnvelope:
      overrides.requestEnvelope ?? fixture.requestEnvelope,
    repositoryPublicKeyResolver:
      overrides.repositoryPublicKeyResolver ??
      (async () => fixture.repositoryPublicKey),
  };
}

async function rewriteCompletionMarker(directory) {
  const json = await readFile(
    join(directory, "party-result.json"),
  );
  const markdown = await readFile(
    join(directory, "PARTY-RESULT.md"),
  );
  await writeFile(
    join(directory, ".party-result.complete.json"),
    `${JSON.stringify({
      jsonSha256: createHash("sha256")
        .update(json)
        .digest("hex"),
      markdownSha256: createHash("sha256")
        .update(markdown)
        .digest("hex"),
      schema:
        "clockchain.bilateral-party-result-completion/v1",
    })}\n`,
    "utf8",
  );
}

async function assertAggregateFailure(
  operation,
  expectedCode,
  forbiddenText,
) {
  await assert.rejects(operation, (error) => {
    assert.ok(error instanceof BilateralVerdictError);
    if (expectedCode !== undefined) {
      assert.equal(error.terminalCode, expectedCode);
    }
    assert.equal(
      error.message.includes("AUTHORIZED"),
      false,
    );
    if (forbiddenText !== undefined) {
      assert.equal(
        error.message.includes(forbiddenText),
        false,
      );
    }
    return true;
  });
}

async function runProcessIsolatedAggregateVerifier(fixture) {
  const verifierUrl = pathToFileURL(
    join(
      ROOT_DIRECTORY,
      "src/bilateral/verdict.mjs",
    ),
  ).href;
  const mcpUrl = pathToFileURL(
    join(ROOT_DIRECTORY, "src/mcp.mjs"),
  ).href;
  const childPath = join(
    fixture.root,
    "fresh-aggregate-verifier.mjs",
  );
  const inputPath = join(
    fixture.root,
    "fresh-aggregate-input.json",
  );
  const readModel = await publicReadModel(
    fixture.fake,
    fixture.descriptor,
    fixture.sessionDigest,
  );
  await writeFile(
    inputPath,
    `${JSON.stringify({
      descriptorEnvelope: fixture.descriptorEnvelope,
      mandateEnvelope: fixture.mandateEnvelope,
      owners: {
        "8677": PAYER.address.toLowerCase(),
        "8678": PAYEE.address.toLowerCase(),
      },
      payeeDirectory: fixture.payeeDirectory,
      payerDirectory: fixture.payerDirectory,
      readModel,
      repositoryPublicKey: fixture.repositoryPublicKey,
      requestEnvelope: fixture.requestEnvelope,
    })}\n`,
    "utf8",
  );
  await writeFile(
    childPath,
    `import { readFile } from "node:fs/promises";
import { verifyBilateralAuthorization } from ${JSON.stringify(verifierUrl)};
import { McpNetworkError } from ${JSON.stringify(mcpUrl)};

const input = JSON.parse(await readFile(process.argv[2], "utf8"));
const clone = (value) => structuredClone(value);
const clockchain = {
  async generateAuditTrail({ asset_reference_id: key }) {
    return clone(input.readModel.audits[key]);
  },
  async getBlock({ height }) {
    const block = input.readModel.blocks[String(height)];
    if (block === undefined) {
      throw new McpNetworkError("serialized public read unavailable");
    }
    return clone(block);
  },
  async resolveAgent(agentId) {
    return clone(input.readModel.agents[String(agentId)]);
  },
  async searchActions({ asset_reference_id: key }) {
    return clone(input.readModel.searches[key] ?? []);
  },
  async verifyCrossParty({ ledgerId, blockHeight }) {
    return clone(input.readModel.crossParty[\`\${ledgerId}|\${blockHeight}\`]);
  },
};
const verdict = await verifyBilateralAuthorization({
  canaries: [],
  clockchain,
  descriptorEnvelope: input.descriptorEnvelope,
  mandateEnvelope: input.mandateEnvelope,
  ownerOf: async ({ agentId }) => input.owners[String(agentId)],
  payeeDirectory: input.payeeDirectory,
  payerDirectory: input.payerDirectory,
  requestEnvelope: input.requestEnvelope,
  repositoryPublicKeyResolver: async () => input.repositoryPublicKey,
});
process.stdout.write(JSON.stringify({ pid: process.pid, verdict }));
`,
    "utf8",
  );
  const { stderr, stdout } = await execFileAsync(
    process.execPath,
    [childPath, inputPath],
    {
      encoding: "utf8",
      env: {
        PATH: process.env.PATH,
      },
    },
  );
  assert.equal(stderr, "");
  return {
    parsed: JSON.parse(stdout),
    stdout,
  };
}

test("isolated payer and payee roles authorize only through a process-isolated aggregate over serialized public reads", async (t) => {
  const fixture = await runIsolatedRoles(t);
  const payer = await readPartyResult(
    fixture.payerDirectory,
  );
  const payee = await readPartyResult(
    fixture.payeeDirectory,
  );

  assert.equal(fixture.fake.calls.logAction.length, 3);
  assert.deepEqual(
    fixture.fake.calls.logAction.map(
      ({ asset_reference_id }) => asset_reference_id,
    ),
    SLOTS.map((slot) =>
      sessionKey(fixture.sessionDigest, slot)),
  );
  assert.equal(
    new Set(
      payer.transitions.map(
        ({ onChain }) => onChain.ledgerId),
    ).size,
    3,
  );
  assert.deepEqual(
    payer.transitions.map(
      ({ message }) => message.kind),
    [...SLOTS],
  );
  assert.deepEqual(
    payee.transitions.map(
      ({ message }) => message.kind),
    [...SLOTS],
  );
  assert.deepEqual(
    payer.transitions[1].message.predecessor,
    authoritativeEntry(payer.transitions[0]),
  );
  assert.deepEqual(
    payer.transitions[2].message.predecessor,
    authoritativeEntry(payer.transitions[1]),
  );
  assert.deepEqual(
    payer.transitions[2].message.proposal,
    authoritativeEntry(payer.transitions[0]),
  );
  for (const [party, directory] of [
    [payer, fixture.payerDirectory],
    [payee, fixture.payeeDirectory],
  ]) {
    assert.equal(party.paymentMoved, false);
    await assertValidPartySignature(party);
    for (const artifact of [
      "party-result.json",
      "PARTY-RESULT.md",
      ".party-result.complete.json",
    ]) {
      assert.equal(
        (await readFile(join(directory, artifact))).length > 0,
        true,
      );
    }
  }

  const watcher = await observeBilateralSession({
    advisory: {
      health: "disclosure-only",
      recordStatus: "anchored",
    },
    canaries: [ROLE_CANARY],
    client: fixture.fake,
    descriptor: fixture.descriptor,
    now: () => 1_784_923_205_000,
  });
  assert.equal(watcher.state, "ACKNOWLEDGED");
  assert.equal(watcher.paymentMoved, false);
  assert.equal(
    JSON.stringify({
      payee: fixture.payeeResult,
      payer: fixture.payerResult,
      watcher,
    }).includes("AUTHORIZED"),
    false,
  );

  const aggregate =
    await runProcessIsolatedAggregateVerifier(fixture);
  assert.notEqual(aggregate.parsed.pid, process.pid);
  assert.equal(aggregate.parsed.verdict.outcome, "AUTHORIZED");
  assert.equal(
    aggregate.parsed.verdict.paymentMoved,
    false,
  );
  assert.deepEqual(
    aggregate.parsed.verdict.transitions.map(
      ({ kind }) => kind),
    [...SLOTS],
  );
  assert.equal(
    aggregate.stdout.match(/AUTHORIZED/g)?.length,
    1,
  );
  assert.equal(
    aggregate.stdout.includes(ROLE_CANARY),
    false,
  );
  for (const transition of aggregate.parsed.verdict.transitions) {
    assert.equal(
      transition.anchoredHash,
      transition.digest,
    );
    assert.equal(
      transition.digest,
      transitionDigest(
        payer.transitions.find(
          ({ message }) =>
            message.kind === transition.kind,
        ).message,
      ),
    );
  }
});

test("operational aggregate authorization is independent of resolveAgent status", async (t) => {
  const fixture = await runIsolatedRoles(t);
  const readModel = await publicReadModel(
    fixture.fake,
    fixture.descriptor,
    fixture.sessionDigest,
  );
  for (const agent of Object.values(readModel.agents)) {
    agent.status = "inactive";
  }
  const verdict = await verifyBilateralAuthorization(
    aggregateInput(
      fixture,
      readOnlyClockchain(readModel),
    ),
  );
  assert.equal(verdict.outcome, "AUTHORIZED");
});

const AGGREGATE_HOSTILE_CASES = Object.freeze([
  Object.freeze({
    expectedCode: "FAILED",
    name: "hostile read exception",
    rows: Object.freeze([]),
    async prepare({ fixture, readModel }) {
      const hostileText =
        "hostile-operational-read-secret";
      return {
        forbiddenText: hostileText,
        input: aggregateInput(
          fixture,
          readOnlyClockchain(readModel, {
            async searchActions() {
              throw new Error(hostileText);
            },
          }),
        ),
      };
    },
  }),
  Object.freeze({
    expectedCode: "EXPIRED",
    name: "missing proposal anchor",
    rows: Object.freeze([]),
    async prepare({ fixture, readModel }) {
      readModel.searches[
        sessionKey(
          fixture.sessionDigest,
          "proposal",
        )
      ] = [];
      return {
        input: aggregateInput(
          fixture,
          readOnlyClockchain(readModel),
        ),
      };
    },
  }),
  Object.freeze({
    expectedCode: "DUPLICATE",
    name: "duplicate proposal anchor",
    rows: Object.freeze([3]),
    async prepare({ fixture, readModel }) {
      const referenceId = sessionKey(
        fixture.sessionDigest,
        "proposal",
      );
      readModel.searches[referenceId] = [
        readModel.searches[referenceId][0],
        readModel.searches[referenceId][0],
      ];
      return {
        input: aggregateInput(
          fixture,
          readOnlyClockchain(readModel),
        ),
      };
    },
  }),
  Object.freeze({
    expectedCode: "ANCHOR_UNVERIFIED",
    name: "non-on-chain cross-party response",
    rows: Object.freeze([5]),
    async prepare({ fixture, readModel }) {
      const record =
        readModel.searches[
          sessionKey(
            fixture.sessionDigest,
            "proposal",
          )
        ][0];
      const response =
        readModel.crossParty[
          `${record.ledgerId}|${record.blockHeight}`
        ];
      response.onChain.verifiedAgainst = "none";
      response.onChain.keyless = false;
      return {
        input: aggregateInput(
          fixture,
          readOnlyClockchain(readModel),
        ),
      };
    },
  }),
  Object.freeze({
    expectedCode: "BINDING_MISMATCH",
    name: "cross-party binding mismatch",
    rows: Object.freeze([6]),
    async prepare({ fixture, readModel }) {
      const record =
        readModel.searches[
          sessionKey(
            fixture.sessionDigest,
            "proposal",
          )
        ][0];
      readModel.crossParty[
        `${record.ledgerId}|${record.blockHeight}`
      ].onChain.anchoredHash = "0".repeat(64);
      return {
        input: aggregateInput(
          fixture,
          readOnlyClockchain(readModel),
        ),
      };
    },
  }),
  Object.freeze({
    expectedCode: "AMOUNT_UNRESOLVED",
    name: "proposal amount cannot be uniquely recovered",
    rows: Object.freeze([8]),
    async prepare({ fixture, readModel }) {
      readModel.searches[
        sessionKey(
          fixture.sessionDigest,
          "proposal",
        )
      ][0].assetHash = "0".repeat(64);
      return {
        input: aggregateInput(
          fixture,
          readOnlyClockchain(readModel),
        ),
      };
    },
  }),
  Object.freeze({
    expectedCode: "FAILED",
    name: "direct owner mismatch",
    rows: Object.freeze([11]),
    async prepare({ fixture, readModel }) {
      return {
        input: aggregateInput(
          fixture,
          readOnlyClockchain(readModel),
          {
            ownerOf: async ({ agentId }) =>
              agentId === fixture.descriptor.payer.agentId
                ? fixture.descriptor.payee.address
                : fixture.descriptor.payee.address,
          },
        ),
      };
    },
  }),
  Object.freeze({
    expectedCode: "FAILED",
    name: "invalid operator descriptor signature",
    rows: Object.freeze([13]),
    async prepare({ fixture, readModel }) {
      const descriptorEnvelope = structuredClone(
        fixture.descriptorEnvelope,
      );
      descriptorEnvelope.operator.signature =
        `${descriptorEnvelope.operator.signature.slice(0, -2)}AA`;
      return {
        input: {
          ...aggregateInput(
            fixture,
            readOnlyClockchain(readModel),
          ),
          descriptorEnvelope,
        },
      };
    },
  }),
  Object.freeze({
    expectedCode: "FAILED",
    name: "package repository pin mismatch",
    rows: Object.freeze([14]),
    async prepare({ fixture, readModel }) {
      const path = join(
        fixture.payeeDirectory,
        "party-result.json",
      );
      const payee = JSON.parse(
        await readFile(path, "utf8"),
      );
      payee.repositorySha = "f".repeat(40);
      await writeFile(
        path,
        `${JSON.stringify(payee, null, 2)}\n`,
        "utf8",
      );
      await writeFile(
        join(fixture.payeeDirectory, "PARTY-RESULT.md"),
        renderPartyResultMarkdown(payee),
        "utf8",
      );
      await rewriteCompletionMarker(
        fixture.payeeDirectory,
      );
      return {
        input: aggregateInput(
          fixture,
          readOnlyClockchain(readModel),
        ),
      };
    },
  }),
  Object.freeze({
    expectedCode: "FAILED",
    name: "package predecessor divergence",
    rows: Object.freeze([15]),
    async prepare({ fixture, readModel }) {
      const path = join(
        fixture.payeeDirectory,
        "party-result.json",
      );
      const payee = JSON.parse(
        await readFile(path, "utf8"),
      );
      payee.transitions[1].message.predecessor.ledgerId =
        "ffffffff-ffff-4fff-8fff-ffffffffffff";
      await writeFile(
        path,
        `${JSON.stringify(payee, null, 2)}\n`,
        "utf8",
      );
      await rewriteCompletionMarker(
        fixture.payeeDirectory,
      );
      return {
        input: aggregateInput(
          fixture,
          readOnlyClockchain(readModel),
        ),
      };
    },
  }),
  Object.freeze({
    expectedCode: "FAILED",
    name: "reordered package transitions",
    rows: Object.freeze([16]),
    async prepare({ fixture, readModel }) {
      const path = join(
        fixture.payerDirectory,
        "party-result.json",
      );
      const payer = JSON.parse(
        await readFile(path, "utf8"),
      );
      payer.transitions = [
        payer.transitions[0],
        payer.transitions[2],
        payer.transitions[1],
      ];
      await writeFile(
        path,
        `${JSON.stringify(payer, null, 2)}\n`,
        "utf8",
      );
      await rewriteCompletionMarker(
        fixture.payerDirectory,
      );
      return {
        input: aggregateInput(
          fixture,
          readOnlyClockchain(readModel),
        ),
      };
    },
  }),
  Object.freeze({
    expectedCode: "EXPIRED",
    name: "late verifier upper bound",
    rows: Object.freeze([17]),
    async prepare({ fixture, readModel }) {
      const acknowledgmentReference = sessionKey(
        fixture.sessionDigest,
        "acknowledgment",
      );
      const acknowledgment =
        readModel.searches[acknowledgmentReference][0];
      const proposalReference = sessionKey(
        fixture.sessionDigest,
        "proposal",
      );
      const proposal =
        readModel.searches[proposalReference][0];
      const proposalTime = Date.parse(
        readModel.blocks[proposal.blockHeight]
          .blockTime,
      );
      const lateBlockTime = new Date(
        proposalTime + 601_000,
      )
        .toISOString()
        .replace(/\.000Z$/, ".000000000Z");
      let acknowledgmentReads = 0;
      return {
        input: aggregateInput(
          fixture,
          readOnlyClockchain(readModel, {
            async getBlock({ height }) {
              const block =
                readModel.blocks[String(height)];
              if (block === undefined) {
                throw unavailableBlock();
              }
              if (
                String(height) ===
                acknowledgment.blockHeight
              ) {
                acknowledgmentReads += 1;
                if (acknowledgmentReads === 2) {
                  return {
                    ...structuredClone(block),
                    blockTime: lateBlockTime,
                  };
                }
              }
              return structuredClone(block);
            },
          }),
        ),
      };
    },
  }),
  Object.freeze({
    expectedCode: "FAILED",
    name: "malformed package with matching marker",
    rows: Object.freeze([]),
    async prepare({ fixture, readModel }) {
      await writeFile(
        join(
          fixture.payeeDirectory,
          "party-result.json",
        ),
        "{malformed-json\n",
        "utf8",
      );
      await rewriteCompletionMarker(
        fixture.payeeDirectory,
      );
      return {
        input: aggregateInput(
          fixture,
          readOnlyClockchain(readModel),
        ),
      };
    },
  }),
  Object.freeze({
    expectedCode: "FAILED",
    name: "incomplete publication marker",
    rows: Object.freeze([]),
    async prepare({ fixture, readModel }) {
      await unlink(
        join(
          fixture.payeeDirectory,
          ".party-result.complete.json",
        ),
      );
      return {
        input: aggregateInput(
          fixture,
          readOnlyClockchain(readModel),
        ),
      };
    },
  }),
  Object.freeze({
    name: "untrusted advisory and package APIs",
    rows: Object.freeze([22, 23, 28]),
    shouldAuthorize: true,
    async prepare({ fixture, readModel }) {
      for (const records of Object.values(
        readModel.searches,
      )) {
        for (const record of records) {
          record.status = "anchored";
          record.createdTimestamp =
            "2099-01-01T00:00:00Z";
          record.updatedTimestamp =
            "2099-01-01T00:00:00Z";
          record.additionalInfo = {
            paymentMoved: true,
          };
        }
      }
      const unused = () => {
        throw new Error(
          "untrusted advisory API was consulted",
        );
      };
      const clockchain = readOnlyClockchain(
        readModel,
      );
      clockchain.verifyPackage = unused;
      clockchain.verifyAsset = unused;
      clockchain.getValidation = unused;
      clockchain.getTime = unused;
      clockchain.getTimestamp = unused;
      return {
        input: aggregateInput(
          fixture,
          clockchain,
        ),
      };
    },
  }),
  Object.freeze({
    expectedCode: "FAILED",
    name: "secret canary in marker-complete artifact",
    rows: Object.freeze([26]),
    async prepare({ fixture, readModel }) {
      const canary = "artifact-secret-canary";
      const markdownPath = join(
        fixture.payeeDirectory,
        "PARTY-RESULT.md",
      );
      await writeFile(
        markdownPath,
        `${await readFile(markdownPath, "utf8")}\n${canary}\n`,
        "utf8",
      );
      await rewriteCompletionMarker(
        fixture.payeeDirectory,
      );
      return {
        forbiddenText: canary,
        input: aggregateInput(
          fixture,
          readOnlyClockchain(readModel),
          { canaries: [canary] },
        ),
      };
    },
  }),
]);

test("aggregate verification fails closed across hostile operational evidence", async (t) => {
  for (const scenario of AGGREGATE_HOSTILE_CASES) {
    await t.test(scenario.name, async (t) => {
      const fixture = await runIsolatedRoles(t);
      const readModel = await publicReadModel(
        fixture.fake,
        fixture.descriptor,
        fixture.sessionDigest,
      );
      const prepared = await scenario.prepare({
        fixture,
        readModel,
      });
      if (scenario.shouldAuthorize) {
        const verdict =
          await verifyBilateralAuthorization(
            prepared.input,
          );
        assert.equal(verdict.outcome, "AUTHORIZED");
        assert.equal(verdict.paymentMoved, false);
        return;
      }
      await assertAggregateFailure(
        () =>
          verifyBilateralAuthorization(
            prepared.input,
          ),
        scenario.expectedCode,
        prepared.forbiddenText,
      );
    });
  }
});

test("Phase -1 fails closed after exactly two isolated-client probe writes", async () => {
  const payerClient = configuredFake();
  const payeeClient = configuredFake();
  const randomValues = [
    Buffer.from(
      "00112233445566778899aabbccddeeff",
      "hex",
    ),
    Buffer.from("11".repeat(32), "hex"),
    Buffer.from("22".repeat(32), "hex"),
  ];
  let nowMs = 1_000_000;
  const envelope = await runBilateralPreflight({
    now: () => nowMs,
    payeeClient,
    payerClient,
    pollIntervalMs: PREFLIGHT_POLL_INTERVAL_MS,
    randomBytes: (size) => {
      const value = randomValues.shift();
      assert.equal(value.length, size);
      return value;
    },
    scope: {
      separateCredentialsAttested: true,
      separateMachinesAttested: true,
    },
    signer: () => ({
      algorithm: "ed25519",
      keyId: "operational-e2e",
      value: Buffer.alloc(64, 1).toString("base64"),
    }),
    sleeper: async (delayMs) => {
      nowMs += delayMs;
    },
    windowMs: PREFLIGHT_POLL_INTERVAL_MS,
  });
  assert.equal(
    envelope.report.outcome,
    "RENDEZVOUS_UNAVAILABLE",
  );
  assert.equal(envelope.report.paymentMoved, false);
  assert.equal(
    payerClient.calls.logAction.length +
      payeeClient.calls.logAction.length,
    2,
  );
});

function transitionClient(fake, overrides = {}) {
  return {
    getBlock: fake.getBlock.bind(fake),
    logAction: fake.logAction.bind(fake),
    resolveAgent: fake.resolveAgent.bind(fake),
    searchActions: fake.searchActions.bind(fake),
    verifyCrossParty:
      fake.verifyCrossParty.bind(fake),
    ...overrides,
  };
}

test("writer crash recovery adopts the landed anchor after one ambiguous dispatch", async (t) => {
  const root = await operationalRoot(t);
  const signed = await signedDescriptorFixture();
  const proposal = buildProposal({
    amount: { currency: "USD", value: "100" },
    descriptor: signed.descriptor,
    sessionDigest: dSession(signed.descriptor),
  });
  const fake = configuredFake();
  const markerPath = join(root, "proposal.intent.json");
  let dispatches = 0;
  const ambiguousClient = transitionClient(fake, {
    async logAction(args) {
      dispatches += 1;
      await fake.logAction(args);
      throw new Error("simulated post-write crash");
    },
  });

  const recovered = await writeOrAdoptTransition({
    client: ambiguousClient,
    markerPath,
    message: proposal,
  });
  assert.equal(recovered.source, "adopted");
  assert.equal(recovered.markerCreated, true);
  const resumed = await writeOrAdoptTransition({
    client: ambiguousClient,
    markerPath,
    message: proposal,
  });
  assert.equal(resumed.source, "adopted");
  assert.equal(resumed.markerCreated, false);
  assert.equal(dispatches, 1);
  assert.equal(fake.calls.logAction.length, 1);
});

test("a refused writer attempt fails closed after one dispatch", async (t) => {
  const root = await operationalRoot(t);
  const signed = await signedDescriptorFixture();
  const proposal = buildProposal({
    amount: { currency: "USD", value: "100" },
    descriptor: signed.descriptor,
    sessionDigest: dSession(signed.descriptor),
  });
  const refused = configuredFake({
    refuseWrite: true,
  });
  await assert.rejects(
    () =>
      writeOrAdoptTransition({
        client: refused,
        markerPath: join(
          root,
          "refused.intent.json",
        ),
        message: proposal,
      }),
    (error) =>
      error instanceof ProtocolFailureError &&
      error.terminalCode === "FAILED",
  );
  assert.equal(refused.calls.logAction.length, 1);
});

test("rate limits exhaust the operational poll budget without writing", async () => {
  const signed = await signedDescriptorFixture();
  const proposal = buildProposal({
    amount: { currency: "USD", value: "100" },
    descriptor: signed.descriptor,
    sessionDigest: dSession(signed.descriptor),
  });
  const limited = configuredFake({
    rateLimitSearch: true,
  });
  let monotonicMs = 0;
  await assert.rejects(
    () =>
      pollForTransition({
        client: limited,
        jitter: () => 0,
        message: proposal,
        monotonicNow: () => monotonicMs,
        pollDurationMs: 20_000,
        sleeper: async (delayMs) => {
          monotonicMs += delayMs;
        },
      }),
    (error) =>
      error instanceof ProtocolFailureError &&
      error.terminalCode === "RATE_BLOCKED",
  );
  assert.equal(limited.calls.logAction.length, 0);
});

const FOCUSED_MATRIX_CITATIONS = Object.freeze([
  Object.freeze({
    file: "test/bilateral-preflight.test.mjs",
    row: 1,
    test:
      "three-stage distributed CLI performs one write per participant and authorizes only the aggregate",
  }),
  Object.freeze({
    file: "test/bilateral-protocol.test.mjs",
    row: 2,
    test:
      "search result shapes distinguish rate limiting from malformed replies",
  }),
  Object.freeze({
    file: "test/bilateral-runner.test.mjs",
    row: 4,
    test:
      "polls at least every 20 seconds and verifies a discovered transition",
  }),
  Object.freeze({
    file: "test/bilateral-protocol.test.mjs",
    row: 7,
    test:
      "the message digest is recomputed and caller input cannot redefine it",
  }),
  Object.freeze({
    file: "test/bilateral-runner.test.mjs",
    row: 9,
    test:
      "writes exactly once, then performs mandatory verification",
  }),
  Object.freeze({
    file: "test/bilateral-descriptor.test.mjs",
    row: 12,
    test:
      "payer and payee must be distinct in address and agentId",
  }),
  Object.freeze({
    file: "test/bilateral-operational-e2e.test.mjs",
    row: 10,
    test:
      "operational aggregate authorization is independent of resolveAgent status",
  }),
  Object.freeze({
    file: "test/bilateral-protocol.test.mjs",
    row: 18,
    test:
      "missing, 502-like, and malformed block time are non-verification",
  }),
  Object.freeze({
    file: "test/bilateral-protocol.test.mjs",
    row: 19,
    test:
      "missing or pending cross-party verification is non-verification",
  }),
  Object.freeze({
    file: "test/bilateral-runner.test.mjs",
    row: 20,
    test:
      "transport and unknown write outcomes retry after confirmed-absent discovery, then stay discovery-only",
  }),
  Object.freeze({
    file: "test/bilateral-runner.test.mjs",
    row: 21,
    test:
      "a pre-existing marker makes an empty slot discovery-only",
  }),
  Object.freeze({
    file: "test/bilateral-operational-e2e.test.mjs",
    row: 24,
    test:
      "a refused writer attempt fails closed after one dispatch",
  }),
  Object.freeze({
    file: "test/bilateral-runner.test.mjs",
    row: 25,
    test:
      "poll cap expires empty discovery and honors Retry-After",
  }),
  Object.freeze({
    file: "test/bilateral-roles.test.mjs",
    row: 27,
    test:
      "role modules and CLIs contain no authorizing verdict literal",
  }),
]);

test("the operational matrix uses one integrated row or one exact focused-test citation per requirement", async () => {
  const aggregateRows = AGGREGATE_HOSTILE_CASES.flatMap(
    ({ rows }) => rows,
  );
  assert.equal(
    new Set(aggregateRows).size,
    aggregateRows.length,
  );
  const citedRows = FOCUSED_MATRIX_CITATIONS.map(
    ({ row }) => row,
  );
  assert.equal(new Set(citedRows).size, citedRows.length);
  assert.deepEqual(
    aggregateRows.filter((row) => citedRows.includes(row)),
    [],
  );
  assert.deepEqual(
    [...aggregateRows, ...citedRows].sort(
      (left, right) => left - right,
    ),
    Array.from(
      { length: 28 },
      (_value, index) => index + 1,
    ),
  );
  const uniqueCitations = new Set();
  for (const citation of FOCUSED_MATRIX_CITATIONS) {
    const identity = `${citation.file}#${citation.test}`;
    assert.equal(uniqueCitations.has(identity), false);
    uniqueCitations.add(identity);
    const source = await readFile(
      join(ROOT_DIRECTORY, citation.file),
      "utf8",
    );
    assert.equal(
      source.includes(`test("${citation.test}"`),
      true,
      `row ${citation.row} citation is stale: ${identity}`,
    );
  }
});
