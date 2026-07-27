import assert from "node:assert/strict";
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify as verifySignature,
  X509Certificate,
} from "node:crypto";
import {
  execFile as execFileCallback,
} from "node:child_process";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import {
  basename,
  dirname,
  join,
} from "node:path";
import {
  promisify,
} from "node:util";
import { canonicalBytes } from "../src/bilateral/canonical.mjs";
import {
  canonicalizeReceiptEventValue,
} from "../src/canonical.mjs";
import {
  publicKeyPemFromRawBase64,
  rawPublicKeyBase64FromPem,
} from "../src/bilateral/descriptor.mjs";
import {
  coordinationEnrollmentSignaturePreimage,
} from "../src/bilateral/coordination/enrollment.mjs";
import {
  createCoordinationReceipt,
} from "../src/bilateral/coordination/receipt.mjs";
import { McpRateLimitedError } from "../src/mcp.mjs";
import test from "node:test";

import {
  PREFLIGHT_POLL_INTERVAL_MS,
  PREFLIGHT_REPORT_SCHEMA,
  PREFLIGHT_REPOSITORY_ROOT,
  PREFLIGHT_WINDOW_MS,
  main,
  runBilateralPreflight,
  runCli,
  verifyCoordinationPreparationSet,
} from "../scripts/probe-bilateral-rendezvous.mjs";

const execFileAsync = promisify(execFileCallback);

const SIGNATURE = Buffer.alloc(64, 1).toString("base64");
const PREFLIGHT_KEY_ENROLLMENT_SIGNATURE_DOMAIN =
  "clockchain.bilateral-preflight-key-enrollment-signature/v1\n";
const TOKEN_COMMITMENT_SIGNATURE_DOMAIN =
  "clockchain.bilateral-token-commitment-signature/v1\n";

function stableBytes(value) {
  return Buffer.from(
    JSON.stringify(canonicalizeReceiptEventValue(value)),
    "utf8",
  );
}

function deterministicRandom() {
  const values = [
    Buffer.from("00112233445566778899aabbccddeeff", "hex"),
    Buffer.from("11".repeat(32), "hex"),
    Buffer.from("22".repeat(32), "hex"),
  ];
  return (size) => {
    const value = values.shift();
    assert.equal(value.length, size);
    return value;
  };
}

function fakeClock() {
  let time = 1_000_000;
  const sleeps = [];
  return {
    now: () => time,
    sleeps,
    sleeper: async (milliseconds) => {
      sleeps.push(milliseconds);
      time += milliseconds;
    },
  };
}

function fakeNetwork({
  digestVisibility = {},
  malformedSearch = new Set(),
  rateLimitOnce = new Set(),
  referenceVisibility = {},
} = {}) {
  const records = [];
  const calls = [];
  const clients = new Map();
  const throttled = new Set();

  function visible(table, observer, writer) {
    return table[observer]?.includes(writer) === true;
  }

  function client(observer) {
    if (clients.has(observer)) {
      return clients.get(observer);
    }
    const value = {
      async logAction(args) {
        calls.push({ args: structuredClone(args), observer, tool: "log" });
        const record = {
          assetHash: args.asset_hash,
          assetReferenceId: args.asset_reference_id,
          blockHeight: String(4_000 + records.length),
          hashType: args.hash_type,
          ledgerId:
            "00000000-0000-4000-8000-000000000001",
          writer: observer,
        };
        records.push(record);
        return {
          blockHeight: record.blockHeight,
          ledgerId: record.ledgerId,
        };
      },
      async searchActions({ asset_reference_id: referenceId }) {
        calls.push({ observer, tool: "search" });
        const throttleKey = `${observer}:search`;
        if (
          rateLimitOnce.has(throttleKey) &&
          !throttled.has(throttleKey)
        ) {
          throttled.add(throttleKey);
          throw new McpRateLimitedError("redacted", {
            code: "MCP_RATE_LIMITED_BODY",
            retryAfterMs: 25_000,
          });
        }
        if (malformedSearch.has(observer)) {
          return { records: [] };
        }
        return records
          .filter(
            (record) =>
              record.assetReferenceId === referenceId &&
              (
                record.writer === observer ||
                visible(
                  referenceVisibility,
                  observer,
                  record.writer,
                )
              ),
          )
          .map(({ writer: _writer, ...record }) => record);
      },
      async verifyCrossParty(args) {
        const channel = Object.hasOwn(args, "hash")
          ? "digest"
          : "final";
        calls.push({ observer, tool: channel });
        const record = Object.hasOwn(args, "hash")
          ? records.find(
              (candidate) =>
                candidate.assetHash === args.hash &&
                (
                  candidate.writer === observer ||
                  visible(
                    digestVisibility,
                    observer,
                    candidate.writer,
                  )
                ),
            )
          : records.find(
              (candidate) =>
                candidate.ledgerId === args.ledgerId &&
                candidate.blockHeight === String(args.blockHeight),
            );
        if (record === undefined) {
          return {
            onChain: {
              anchoredHash: null,
              assetReferenceId: null,
              blockHeight: String(args.blockHeight ?? "0"),
              keyless: false,
              ledgerId: args.ledgerId ?? "missing",
              verifiedAgainst: "none",
            },
          };
        }
        return {
          onChain: {
            anchoredHash: record.assetHash,
            assetReferenceId: record.assetReferenceId,
            blockHeight: record.blockHeight,
            keyless: true,
            ledgerId: record.ledgerId,
            verifiedAgainst: "on-chain block",
          },
        };
      },
    };
    clients.set(observer, value);
    return value;
  }

  return { calls, client };
}

function signer(bytes) {
  assert.ok(Buffer.isBuffer(bytes));
  return {
    algorithm: "ed25519",
    keyId: "test-operator",
    value: SIGNATURE,
  };
}

async function runScenario({
  network,
  payerClient = network.client("payer"),
  payeeClient = network.client("payee"),
  scope = {
    separateCredentialsAttested: true,
    separateMachinesAttested: true,
  },
  windowMs = PREFLIGHT_WINDOW_MS,
} = {}) {
  const clock = fakeClock();
  const envelope = await runBilateralPreflight({
    now: clock.now,
    payerClient,
    payeeClient,
    pollIntervalMs: PREFLIGHT_POLL_INTERVAL_MS,
    randomBytes: deterministicRandom(),
    scope,
    signer,
    sleeper: clock.sleeper,
    windowMs,
  });
  return { clock, envelope };
}

test("same-process deterministic core records two writes but never claims cross-machine authority", async () => {
  const network = fakeNetwork({
    digestVisibility: {
      payer: ["payee"],
      payee: ["payer"],
    },
    referenceVisibility: {
      payer: ["payee"],
      payee: ["payer"],
    },
  });
  const { envelope } = await runScenario({ network });

  assert.equal(envelope.report.schema, PREFLIGHT_REPORT_SCHEMA);
  assert.equal(
    envelope.report.outcome,
    "RENDEZVOUS_UNAVAILABLE",
  );
  assert.equal(envelope.report.paymentMoved, false);
  assert.equal(envelope.report.channel, "derived-reference-id");
  assert.equal(envelope.report.tenancy, "cross-client");
  assert.equal(envelope.report.startedAtMs, "1000000");
  assert.equal(
    envelope.report.deadlineAtMs,
    String(1_000_000 + PREFLIGHT_WINDOW_MS),
  );
  assert.deepEqual(
    envelope.report.writes.map(({ key }) => key),
    [
      "cbv1:probe:00112233445566778899aabbccddeeff:payer",
      "cbv1:probe:00112233445566778899aabbccddeeff:payee",
    ],
  );
  assert.equal(
    new Set(
      envelope.report.writes.map(
        ({ blockHeight, ledgerId }) =>
          `${ledgerId}:${blockHeight}`,
      ),
    )
      .size,
    2,
  );
  assert.deepEqual(
    envelope.report.directions.map((direction) => ({
      digest: direction.digestResolved,
      final: direction.finalVerified,
      reference: direction.referenceResolved,
    })),
    [
      { digest: true, final: true, reference: true },
      { digest: true, final: true, reference: true },
    ],
  );
  assert.equal(
    network.calls.filter(({ tool }) => tool === "log").length,
    2,
  );
  assert.equal(envelope.signature.value, SIGNATURE);
  assert.equal(Object.isFrozen(envelope), true);
  assert.equal(Object.isFrozen(envelope.report), true);
  assert.equal(Object.isFrozen(envelope.report.directions), true);
  assert.equal(
    Object.isFrozen(envelope.report.directions[0]),
    true,
  );
  assert.throws(() => {
    envelope.report.directions[0].finalVerified = false;
  }, TypeError);
  assert.equal(
    JSON.stringify(envelope).includes("AUTHOR" + "IZED"),
    false,
  );
});

test("same-process digest fallback is recorded but remains unavailable", async () => {
  const network = fakeNetwork({
    digestVisibility: {
      payer: ["payee"],
      payee: ["payer"],
    },
  });
  const { envelope } = await runScenario({ network });
  assert.equal(
    envelope.report.outcome,
    "RENDEZVOUS_UNAVAILABLE",
  );
  assert.equal(envelope.report.channel, "digest-hash");
  assert.ok(
    envelope.report.directions.every(
      ({ digestResolved, referenceResolved }) =>
        digestResolved && !referenceResolved,
    ),
  );
});

test("tenancy is same-client by identity and otherwise remains unknown without both attestations", async () => {
  const sameNetwork = fakeNetwork();
  const shared = sameNetwork.client("shared");
  const same = await runScenario({
    network: sameNetwork,
    payerClient: shared,
    payeeClient: shared,
  });
  assert.equal(same.envelope.report.tenancy, "same-client");

  const crossNetwork = fakeNetwork({
    digestVisibility: {
      payer: ["payee"],
      payee: ["payer"],
    },
    referenceVisibility: {
      payer: ["payee"],
      payee: ["payer"],
    },
  });
  const unknown = await runScenario({
    network: crossNetwork,
    scope: {
      separateCredentialsAttested: true,
      separateMachinesAttested: false,
    },
  });
  assert.equal(unknown.envelope.report.tenancy, "unknown");
});

test("asymmetric visibility, malformed bodies, and exhausted budget fail before session state", async () => {
  for (const network of [
    fakeNetwork({
      digestVisibility: { payer: ["payee"] },
      referenceVisibility: { payer: ["payee"] },
    }),
    fakeNetwork({
      malformedSearch: new Set(["payer", "payee"]),
    }),
  ]) {
    const { envelope } = await runScenario({
      network,
      windowMs: 40_000,
    });
    assert.equal(
      envelope.report.outcome,
      "RENDEZVOUS_UNAVAILABLE",
    );
    assert.equal(envelope.report.channel, "unavailable");
    assert.equal(
      network.calls.filter(({ tool }) => tool === "log").length,
      2,
    );
    assert.ok(
      network.calls.filter(({ tool }) => tool === "search").length <=
        6,
    );
  }
});

test("rate limits preserve wire classification and retry metadata while honoring serialized cadence", async () => {
  const network = fakeNetwork({
    digestVisibility: {
      payer: ["payee"],
      payee: ["payer"],
    },
    rateLimitOnce: new Set(["payer:search"]),
    referenceVisibility: {
      payer: ["payee"],
      payee: ["payer"],
    },
  });
  const { clock, envelope } = await runScenario({ network });

  assert.equal(
    envelope.report.outcome,
    "RENDEZVOUS_UNAVAILABLE",
  );
  assert.deepEqual(envelope.report.rateLimits, [
    {
      channel: "derived-reference-id",
      code: "MCP_RATE_LIMITED_BODY",
      observer: "payer",
      retryAfterMs: "25000",
      wireShape: "body-rate_limited",
    },
  ]);
  assert.deepEqual(clock.sleeps, [25_000]);
  assert.equal(
    envelope.report.serializedCadenceMs,
    String(PREFLIGHT_POLL_INTERVAL_MS),
  );
});

async function writeSecret(path, value) {
  await writeFile(path, value, {
    encoding: "utf8",
    mode: 0o600,
  });
  await chmod(path, 0o600);
}

function artifactSignaturePreimage(domain, artifact) {
  return Buffer.concat([
    Buffer.from(domain, "ascii"),
    Buffer.from(
      createHash("sha256")
        .update(canonicalBytes(artifact))
        .digest("hex"),
      "ascii",
    ),
  ]);
}

async function rolePreparationArtifacts(fixture, role) {
  const preflight = generateKeyPairSync("ed25519");
  const coordination = generateKeyPairSync("ed25519");
  const publicKey = rawPublicKeyBase64FromPem(
    preflight.publicKey.export({
      format: "pem",
      type: "spki",
    }),
  );
  const coordinationPublicKey =
    rawPublicKeyBase64FromPem(
      coordination.publicKey.export({
        format: "pem",
        type: "spki",
      }),
    );
  const enrollmentUnsigned = {
    algorithm: "ed25519",
    paymentMoved: false,
    publicKey,
    repositorySha: fixture.repositorySha,
    role,
    schema:
      "clockchain.bilateral-preflight-key-enrollment/v1",
  };
  const enrollment = {
    ...enrollmentUnsigned,
    signature: sign(
      null,
      artifactSignaturePreimage(
        PREFLIGHT_KEY_ENROLLMENT_SIGNATURE_DOMAIN,
        enrollmentUnsigned,
      ),
      preflight.privateKey,
    ).toString("base64"),
  };
  const tokenPath =
    role === "payer"
      ? fixture.payerTokenPath
      : fixture.payeeTokenPath;
  const tokenBytes = await readFile(tokenPath);
  const commitmentUnsigned = {
    algorithm: "ed25519",
    coordinationPublicKey,
    paymentMoved: false,
    repositorySha: fixture.repositorySha,
    role,
    schema:
      "clockchain.bilateral-token-commitment/v1",
    tokenSha256: createHash("sha256")
      .update(tokenBytes)
      .digest("hex"),
  };
  const tokenCommitment = {
    ...commitmentUnsigned,
    signature: sign(
      null,
      artifactSignaturePreimage(
        TOKEN_COMMITMENT_SIGNATURE_DOMAIN,
        commitmentUnsigned,
      ),
      coordination.privateKey,
    ).toString("base64"),
  };
  const privateKeyPath = join(
    fixture.root,
    `${role}-local-preflight.ed25519.pem`,
  );
  const enrollmentPath = join(
    fixture.root,
    `${role}-preflight-key-enrollment.json`,
  );
  const tokenCommitmentPath = join(
    fixture.root,
    `${role}-token-commitment.json`,
  );
  await Promise.all([
    writeSecret(
      privateKeyPath,
      preflight.privateKey.export({
        format: "pem",
        type: "pkcs8",
      }),
    ),
    writeSecret(
      enrollmentPath,
      canonicalBytes(enrollment).toString("utf8"),
    ),
    writeSecret(
      tokenCommitmentPath,
      canonicalBytes(tokenCommitment).toString("utf8"),
    ),
  ]);
  return {
    coordinationPrivateKeyPem:
      coordination.privateKey.export({
        format: "pem",
        type: "pkcs8",
      }),
    coordinationPublicKey,
    enrollment,
    enrollmentPath,
    privateKeyPath,
    publicKey,
    tokenCommitment,
    tokenCommitmentPath,
  };
}

async function distributedFixture(t) {
  const root = await mkdtemp(
    join(tmpdir(), "bilateral-preflight-distributed-"),
  );
  t.after(() =>
    rm(root, { force: true, recursive: true }));
  const { privateKey, publicKey } =
    generateKeyPairSync("ed25519");
  const operatorPrivateKeyPath = join(
    root,
    "operator.ed25519.pem",
  );
  const payerTokenPath = join(root, "payer.token");
  const payeeTokenPath = join(root, "payee.token");
  await Promise.all([
    writeSecret(
      operatorPrivateKeyPath,
      privateKey.export({
        format: "pem",
        type: "pkcs8",
      }),
    ),
    writeSecret(payerTokenPath, "payer-token"),
    writeSecret(payeeTokenPath, "payee-token"),
  ]);
  const fixture = {
    operatorPrivateKeyPath,
    operatorPublicKey:
      rawPublicKeyBase64FromPem(
        publicKey.export({
          format: "pem",
          type: "spki",
        }),
      ),
    payerTokenPath,
    payeeTokenPath,
    repositorySha:
      "0123456789abcdef0123456789abcdef01234567",
    root,
  };
  fixture.payerPreparation =
    await rolePreparationArtifacts(fixture, "payer");
  fixture.payeePreparation =
    await rolePreparationArtifacts(fixture, "payee");
  return fixture;
}

function repositoryResolver(fixture) {
  return async ({ repositoryPath, repositorySha }) => {
    assert.equal(
      repositoryPath,
      "docs/operator-keys/preflight-operator.pub",
    );
    assert.equal(
      repositorySha,
      fixture.repositorySha,
    );
    return fixture.operatorPublicKey;
  };
}

function repositoryStateResolver(
  fixture,
  state = {
    commitSha: fixture.repositorySha,
    headSha: fixture.repositorySha,
    worktreeStatus: "",
  },
) {
  return async ({ repositoryRoot, repositorySha }) => {
    assert.equal(repositoryRoot, PREFLIGHT_REPOSITORY_ROOT);
    assert.equal(repositorySha, fixture.repositorySha);
    return state;
  };
}

function preflightDependencies(fixture, additions = {}) {
  return {
    prepareArtifacts: async ({ repositorySha }) => {
      assert.equal(repositorySha, fixture.repositorySha);
      return {
        payee: {
          coordinationPublicKey:
            fixture.payeePreparation
              .coordinationPublicKey,
          preflightEnrollment:
            fixture.payeePreparation.enrollment,
          tokenCommitment:
            fixture.payeePreparation.tokenCommitment,
        },
        payer: {
          coordinationPublicKey:
            fixture.payerPreparation
              .coordinationPublicKey,
          preflightEnrollment:
            fixture.payerPreparation.enrollment,
          tokenCommitment:
            fixture.payerPreparation.tokenCommitment,
        },
      };
    },
    repositoryPublicKeyResolver:
      repositoryResolver(fixture),
    repositoryStateResolver:
      repositoryStateResolver(fixture),
    ...additions,
  };
}

function coordinationEnrollmentArtifact(fixture, role) {
  const preparation = fixture[`${role}Preparation`];
  const invitationDigits =
    role === "payer" ? ["1", "2"] : ["3", "4"];
  const unsigned = {
    capabilityDigest:
      role === "payer" ? "a".repeat(64) : "b".repeat(64),
    coordinationKey: {
      algorithm: "ed25519",
      keyId: `${role}-coordination`,
      publicKey: preparation.coordinationPublicKey,
    },
    invitations: {
      rehearsal: {
        address: `0x${invitationDigits[0].repeat(40)}`,
        algorithm: "eip191",
        signature: `0x${invitationDigits[0].repeat(130)}`,
      },
      stakeholder: {
        address: `0x${invitationDigits[1].repeat(40)}`,
        algorithm: "eip191",
        signature: `0x${invitationDigits[1].repeat(130)}`,
      },
    },
    paymentMoved: false,
    preflightKey: {
      algorithm: "ed25519",
      keyId: `${role}-preflight`,
      publicKey: preparation.publicKey,
    },
    releaseId: "preflight-test-release",
    repositorySha: fixture.repositorySha,
    role,
    schema: "clockchain.bilateral-coordination-enrollment/v1",
    sessionId: "00000000-0000-4000-8000-000000000001",
  };
  return {
    ...unsigned,
    signature: sign(
      null,
      coordinationEnrollmentSignaturePreimage(unsigned),
      createPrivateKey(preparation.coordinationPrivateKeyPem),
    ).toString("base64"),
  };
}

function resignedCoordinationEnrollment(
  fixture,
  role,
  changes,
) {
  const enrollment = coordinationEnrollmentArtifact(
    fixture,
    role,
  );
  const { signature: _signature, ...unsigned } = enrollment;
  const updated = { ...unsigned, ...changes };
  return {
    ...updated,
    signature: sign(
      null,
      coordinationEnrollmentSignaturePreimage(updated),
      createPrivateKey(
        fixture[`${role}Preparation`]
          .coordinationPrivateKeyPem,
      ),
    ).toString("base64"),
  };
}

async function coordinationPreparationInput(
  fixture,
  enrollmentOverrides = {},
) {
  const certificatePath = join(fixture.root, "relay-cert.pem");
  const keyPath = join(fixture.root, "relay-key.pem");
  await execFileAsync("openssl", [
    "req",
    "-x509",
    "-newkey",
    "ed25519",
    "-keyout",
    keyPath,
    "-out",
    certificatePath,
    "-nodes",
    "-days",
    "1",
    "-subj",
    "/CN=127.0.0.1",
  ]);
  const [certificate, key] = await Promise.all([
    readFile(certificatePath, "utf8"),
    readFile(keyPath),
  ]);
  const certificateSha256 = createHash("sha256")
    .update(new X509Certificate(certificate).raw)
    .digest("hex");
  const signer = {
    certificateSha256,
    sign: (preimage) => sign(
      null,
      preimage,
      createPrivateKey(key),
    ),
    signatureAlgorithm: "ed25519",
    verify: (preimage, signature) => verifySignature(
      null,
      preimage,
      new X509Certificate(certificate).publicKey,
      signature,
    ),
  };
  const enrollments = {};
  const selectedEnrollments = {};
  for (const role of ["payer", "payee"]) {
    const enrollment = coordinationEnrollmentArtifact(
      fixture, role,
    );
    const selected = enrollmentOverrides[role] ?? enrollment;
    selectedEnrollments[role] = selected;
    const enrollmentBytes = canonicalBytes(selected);
    enrollments[role] = {
      enrollmentBase64: enrollmentBytes.toString("base64"),
      enrollmentDigest: createHash("sha256")
        .update(enrollmentBytes)
        .digest("hex"),
      receiptBase64: (await createCoordinationReceipt({
        context: {
          capabilityDigest: selected.capabilityDigest,
          enrollmentDigest: createHash("sha256")
            .update(enrollmentBytes)
            .digest("hex"),
          releaseId: selected.releaseId,
          repositorySha: selected.repositorySha,
          role,
          sessionId: selected.sessionId,
        },
        signer,
      })).toString("base64"),
    };
  }
  return {
    capabilityDigests: {
      payer: selectedEnrollments.payer.capabilityDigest,
      payee: selectedEnrollments.payee.capabilityDigest,
    },
    enrollmentSetBytes: stableBytes({
      enrollments,
      paymentMoved: false,
      releaseId: "preflight-test-release",
      repositorySha: fixture.repositorySha,
      schema:
        "clockchain.bilateral-coordination-enrollment-set/v1",
      sessionId: "00000000-0000-4000-8000-000000000001",
    }),
    releaseId: "preflight-test-release",
    repositorySha: fixture.repositorySha,
    sessionId: "00000000-0000-4000-8000-000000000001",
    tlsCertificatePem: certificate,
    tokenCommitments: {
      payer: fixture.payerPreparation.tokenCommitment,
      payee: fixture.payeePreparation.tokenCommitment,
    },
  };
}

test("prepare accepts coordination-enrollment-bound public artifacts", async (t) => {
  const fixture = await distributedFixture(t);
  const input = await coordinationPreparationInput(fixture);
  const envelope = await main(
    [
      "prepare",
      "--operator-private-key",
      fixture.operatorPrivateKeyPath,
      "--operator-key-id",
      "preflight-operator",
      "--repository-sha",
      fixture.repositorySha,
      "--output",
      join(fixture.root, "enrollment-bound-prepare"),
    ],
    preflightDependencies(fixture, {
      prepareArtifacts: async () =>
        verifyCoordinationPreparationSet(input),
      randomBytes: deterministicRandom(),
    }),
  );

  assert.deepEqual(envelope.plan.participants.payer, {
    coordinationPublicKey:
      fixture.payerPreparation.coordinationPublicKey,
    publicKey: fixture.payerPreparation.publicKey,
    tokenCommitment: fixture.payerPreparation.tokenCommitment,
  });
  assert.deepEqual(envelope.plan.participants.payee, {
    coordinationPublicKey:
      fixture.payeePreparation.coordinationPublicKey,
    publicKey: fixture.payeePreparation.publicKey,
    tokenCommitment: fixture.payeePreparation.tokenCommitment,
  });
});

function mutatedEnrollmentSet(input, mutate) {
  const value = JSON.parse(
    input.enrollmentSetBytes.toString("utf8"),
  );
  mutate(value);
  return {
    ...input,
    enrollmentSetBytes: stableBytes(value),
  };
}

test("coordination preparation accepts only exact receipt-bound enrollment sets", async (t) => {
  const fixture = await distributedFixture(t);
  const input = await coordinationPreparationInput(fixture);
  const preparation =
    await verifyCoordinationPreparationSet(input);
  assert.equal(Object.isFrozen(preparation), true);
  assert.equal(Object.isFrozen(preparation.participants), true);

  const duplicateInvitation =
    resignedCoordinationEnrollment(fixture, "payer", {
      invitations: {
        rehearsal: {
          address: "0x3333333333333333333333333333333333333333",
          algorithm: "eip191",
          signature: `0x${"3".repeat(130)}`,
        },
        stakeholder: {
          address: "0x2222222222222222222222222222222222222222",
          algorithm: "eip191",
          signature: `0x${"2".repeat(130)}`,
        },
      },
    });
  const duplicateKeyId =
    resignedCoordinationEnrollment(fixture, "payer", {
      coordinationKey: {
        algorithm: "ed25519",
        keyId: "payee-coordination",
        publicKey: fixture.payerPreparation.coordinationPublicKey,
      },
    });
  const changedInvitation =
    resignedCoordinationEnrollment(fixture, "payer", {
      invitations: {
        rehearsal: {
          address: "0x5555555555555555555555555555555555555555",
          algorithm: "eip191",
          signature: `0x${"5".repeat(130)}`,
        },
        stakeholder: {
          address: "0x6666666666666666666666666666666666666666",
          algorithm: "eip191",
          signature: `0x${"6".repeat(130)}`,
        },
      },
    });
  const wrongCertificate =
    await coordinationPreparationInput(fixture);
  const sharedCapabilityPayee =
    resignedCoordinationEnrollment(fixture, "payee", {
      capabilityDigest: "a".repeat(64),
    });
  const cases = [
    ["wrong release", { ...input, releaseId: "wrong-release" }],
    ["wrong session", {
      ...input,
      sessionId: "00000000-0000-4000-8000-000000000002",
    }],
    ["wrong capability", {
      ...input,
      capabilityDigests: {
        ...input.capabilityDigests,
        payer: "b".repeat(64),
      },
    }],
    ["forged receipt", mutatedEnrollmentSet(input, (set) => {
      set.enrollments.payer.receiptBase64 =
        Buffer.alloc(64, 9).toString("base64");
    })],
    ["missing receipt", mutatedEnrollmentSet(input, (set) => {
      delete set.enrollments.payer.receiptBase64;
    })],
    // Relay bootstrap validates EIP-191 invitation proofs before issuing
    // this TLS-signed receipt; its enrollment digest prevents substitution.
    ["changed invitations with stale receipt", mutatedEnrollmentSet(
      input,
      (set) => {
        const bytes = canonicalBytes(changedInvitation);
        set.enrollments.payer.enrollmentBase64 =
          bytes.toString("base64");
        set.enrollments.payer.enrollmentDigest =
          createHash("sha256").update(bytes).digest("hex");
      },
    )],
    ["wrong certificate", {
      ...input,
      tlsCertificatePem: wrongCertificate.tlsCertificatePem,
    }],
    ["duplicate invitations", await coordinationPreparationInput(
      fixture,
      { payer: duplicateInvitation },
    )],
    ["duplicate key IDs", await coordinationPreparationInput(
      fixture,
      { payer: duplicateKeyId },
    )],
    ["shared role capability", await coordinationPreparationInput(
      fixture,
      { payee: sharedCapabilityPayee },
    )],
    ["mismatched token", {
      ...input,
      tokenCommitments: {
        payer: input.tokenCommitments.payee,
        payee: input.tokenCommitments.payee,
      },
    }],
  ];

  for (const [label, value] of cases) {
    await assert.rejects(
      () => verifyCoordinationPreparationSet(value),
      { code: "BILATERAL_PREFLIGHT_FAILED" },
      label,
    );
  }

  await assert.rejects(
    () => main(
      ["prepare", "--operator-private-key", fixture.operatorPrivateKeyPath,
        "--operator-key-id", "preflight-operator", "--repository-sha",
        fixture.repositorySha, "--output", join(fixture.root, "lookalike")],
      preflightDependencies(fixture, {
        prepareArtifacts: async () => ({
          participants: preparation.participants,
        }),
        randomBytes: deterministicRandom(),
      }),
    ),
    { code: "BILATERAL_PREFLIGHT_FAILED" },
  );
  const enrollmentSet = JSON.parse(
    input.enrollmentSetBytes.toString("utf8"),
  );
  await assert.rejects(
    () => main(
      ["prepare", "--operator-private-key", fixture.operatorPrivateKeyPath,
        "--operator-key-id", "preflight-operator", "--repository-sha",
        fixture.repositorySha, "--output", join(fixture.root, "bare")],
      preflightDependencies(fixture, {
        prepareArtifacts: async () => ({
          payer: {
            coordinationEnrollment: JSON.parse(Buffer.from(
              enrollmentSet.enrollments.payer.enrollmentBase64,
              "base64",
            ).toString("utf8")),
            tokenCommitment: input.tokenCommitments.payer,
          },
          payee: {
            coordinationEnrollment: JSON.parse(Buffer.from(
              enrollmentSet.enrollments.payee.enrollmentBase64,
              "base64",
            ).toString("utf8")),
            tokenCommitment: input.tokenCommitments.payee,
          },
        }),
        randomBytes: deterministicRandom(),
      }),
    ),
    { code: "BILATERAL_PREFLIGHT_FAILED" },
  );
});

async function prepareDistributedPlan(fixture) {
  const output = join(fixture.root, "prepare");
  const envelope = await main(
    [
      "prepare",
      "--operator-private-key",
      fixture.operatorPrivateKeyPath,
      "--operator-key-id",
      "preflight-operator",
      "--repository-sha",
      fixture.repositorySha,
      "--output",
      output,
    ],
    preflightDependencies(fixture, {
      randomBytes: deterministicRandom(),
    }),
  );
  return {
    envelope,
    output,
    payeeKeyPath:
      fixture.payeePreparation.privateKeyPath,
    payerKeyPath:
      fixture.payerPreparation.privateKeyPath,
    planPath: join(output, "probe-plan.json"),
  };
}

test("prepare consumes only verified role public artifacts and writes no participant private keys", async (t) => {
  const fixture = await distributedFixture(t);
  const payer = await rolePreparationArtifacts(
    fixture,
    "payer",
  );
  const payee = await rolePreparationArtifacts(
    fixture,
    "payee",
  );
  const output = join(fixture.root, "public-only-prepare");
  const envelope = await main(
    [
      "prepare",
      "--operator-private-key",
      fixture.operatorPrivateKeyPath,
      "--operator-key-id",
      "preflight-operator",
      "--repository-sha",
      fixture.repositorySha,
      "--payer-preflight-enrollment",
      payer.enrollmentPath,
      "--payee-preflight-enrollment",
      payee.enrollmentPath,
      "--payer-token-commitment",
      payer.tokenCommitmentPath,
      "--payee-token-commitment",
      payee.tokenCommitmentPath,
      "--payer-coordination-public-key",
      payer.coordinationPublicKey,
      "--payee-coordination-public-key",
      payee.coordinationPublicKey,
      "--output",
      output,
    ],
    preflightDependencies(fixture, {
      prepareArtifacts: undefined,
      randomBytes: deterministicRandom(),
    }),
  );

  assert.deepEqual(
    envelope.plan.participants.payer,
    {
      coordinationPublicKey:
        payer.coordinationPublicKey,
      publicKey: payer.publicKey,
      tokenCommitment: payer.tokenCommitment,
    },
  );
  assert.deepEqual(
    envelope.plan.participants.payee,
    {
      coordinationPublicKey:
        payee.coordinationPublicKey,
      publicKey: payee.publicKey,
      tokenCommitment: payee.tokenCommitment,
    },
  );
  await assert.rejects(
    lstat(
      join(output, "payer-participant.ed25519.pem"),
    ),
    { code: "ENOENT" },
  );
  await assert.rejects(
    lstat(
      join(output, "payee-participant.ed25519.pem"),
    ),
    { code: "ENOENT" },
  );
});

async function runParticipant({
  clock,
  createClient,
  fixture,
  keyPath,
  output,
  planPath,
  role,
  sleeper,
  tokenPath,
  windowMs = PREFLIGHT_WINDOW_MS,
}) {
  return main(
    [
      "participant",
      "--role",
      role,
      "--plan",
      planPath,
      "--token-file",
      tokenPath,
      "--participant-private-key",
      keyPath,
      "--output",
      output,
    ],
    preflightDependencies(fixture, {
      createClient,
      now: clock.now,
      sleeper:
        sleeper ??
        (async (milliseconds) => {
          clock.sleeps.push(milliseconds);
          await new Promise((resolve) =>
            setImmediate(resolve));
          clock.advance(milliseconds);
        }),
      windowMs,
    }),
  );
}

async function runDistributedScenario(t, network) {
  const fixture = await distributedFixture(t);
  const prepared = await prepareDistributedPlan(
    fixture,
  );
  const payerClock = distributedClock();
  const payeeClock = distributedClock();
  const payerOutput = join(fixture.root, "payer-output");
  const payeeOutput = join(fixture.root, "payee-output");
  let announcePayerSleep;
  let releasePayerSleep;
  const payerSleeping = new Promise((resolve) => {
    announcePayerSleep = resolve;
  });
  const payerMayContinue = new Promise((resolve) => {
    releasePayerSleep = resolve;
  });
  const payerPromise = runParticipant({
    clock: payerClock,
    createClient: () => network.client("payer"),
    fixture,
    keyPath: prepared.payerKeyPath,
    output: payerOutput,
    planPath: prepared.planPath,
    role: "payer",
    sleeper: async (milliseconds) => {
      payerClock.sleeps.push(milliseconds);
      announcePayerSleep();
      await payerMayContinue;
      payerClock.advance(milliseconds);
    },
    tokenPath: fixture.payerTokenPath,
  });
  await payerSleeping;
  const payeePromise = runParticipant({
    clock: payeeClock,
    createClient: () => network.client("payee"),
    fixture,
    keyPath: prepared.payeeKeyPath,
    output: payeeOutput,
    planPath: prepared.planPath,
    role: "payee",
    tokenPath: fixture.payeeTokenPath,
  });
  while (
    network.calls.filter(({ tool }) => tool === "log")
      .length < 2
  ) {
    await new Promise((resolve) =>
      setImmediate(resolve));
  }
  releasePayerSleep();
  const [payer, payee] = await Promise.all([
    payerPromise,
    payeePromise,
  ]);
  return {
    fixture,
    network,
    payee,
    payeeOutput,
    payer,
    payerOutput,
    prepared,
  };
}

function distributedClock() {
  let time = 1_000_000;
  const sleeps = [];
  return {
    advance: (milliseconds) => {
      time += milliseconds;
    },
    now: () => time,
    sleeps,
  };
}

async function aggregateDistributed(
  scenario,
  flags = [
    "--attest-separate-credentials",
    "--attest-separate-machines",
  ],
) {
  const output = join(
    scenario.fixture.root,
    `aggregate-${flags.length}`,
  );
  const envelope = await main(
    [
      "aggregate",
      "--plan",
      scenario.prepared.planPath,
      "--payer-report-dir",
      scenario.payerOutput,
      "--payee-report-dir",
      scenario.payeeOutput,
      "--operator-private-key",
      scenario.fixture.operatorPrivateKeyPath,
      "--output",
      output,
      ...flags,
    ],
    preflightDependencies(scenario.fixture, {
      now: () => 1_500_000,
    }),
  );
  return { envelope, output };
}

async function rewriteSignedParticipantReport(
  scenario,
  role,
  mutate,
) {
  const output =
    role === "payer"
      ? scenario.payerOutput
      : scenario.payeeOutput;
  const reportPath = join(
    output,
    "participant-report.json",
  );
  const envelope = JSON.parse(
    await readFile(reportPath, "utf8"),
  );
  mutate(envelope.report);
  const keyPath =
    role === "payer"
      ? scenario.prepared.payerKeyPath
      : scenario.prepared.payeeKeyPath;
  envelope.signature.value = sign(
    null,
    canonicalBytes(envelope.report),
    createPrivateKey(await readFile(keyPath, "utf8")),
  ).toString("base64");
  const bytes = canonicalBytes(envelope);
  await writeFile(reportPath, bytes);
  await writeFile(
    join(output, ".participant-report.complete.json"),
    canonicalBytes({
      fileSha256: createHash("sha256")
        .update(bytes)
        .digest("hex"),
      schema:
        "clockchain.bilateral-preflight-participant-completion/v1",
    }),
  );
}

function observedFileSystem(secretPaths, secretReads) {
  return {
    lstat,
    mkdir,
    open: async (path, ...arguments_) => {
      if (secretPaths.has(path)) {
        secretReads.push(path);
      }
      return open(path, ...arguments_);
    },
  };
}

function swappingOutputFileSystem(
  output,
  targetEvent,
) {
  const displaced = `${output}.displaced`;
  let lastOutputFile = null;
  let swapped = false;
  const maybeSwap = async (event) => {
    if (!swapped && event === targetEvent) {
      swapped = true;
      await rename(output, displaced);
      await mkdir(output, { mode: 0o700 });
    }
  };
  const wrapOutputFile = (handle, name) => ({
    async close() {
      return handle.close();
    },
    async sync() {
      await maybeSwap(`sync:${name}`);
      return handle.sync();
    },
    async writeFile(...arguments_) {
      await maybeSwap(`write:${name}`);
      return handle.writeFile(...arguments_);
    },
  });
  const wrapOutputDirectory = (handle) => ({
    async close() {
      return handle.close();
    },
    async stat() {
      return handle.stat();
    },
    async sync() {
      await maybeSwap(
        `dir-sync:${lastOutputFile}`,
      );
      return handle.sync();
    },
  });
  return {
    displaced,
    fileSystem: {
      lstat,
      mkdir,
      open: async (path, ...arguments_) => {
        if (
          dirname(path) === output &&
          path !== output
        ) {
          const name = basename(path);
          await maybeSwap(`open:${name}`);
          const handle = await open(path, ...arguments_);
          lastOutputFile = name;
          return wrapOutputFile(handle, name);
        }
        const handle = await open(path, ...arguments_);
        if (path === output) {
          return wrapOutputDirectory(handle);
        }
        return handle;
      },
    },
    swapped: () => swapped,
  };
}

async function assertNoReplacementPayload(
  output,
  file,
) {
  try {
    const metadata = await stat(join(output, file));
    assert.equal(metadata.size, 0);
  } catch (error) {
    if (error?.code !== "ENOENT") {
      throw error;
    }
  }
}

test("prepare, participant, and aggregate reject wrong HEAD, dirty state, and non-commit provenance before private inputs or publication", async (t) => {
  const scenario = await runDistributedScenario(
    t,
    fakeNetwork({
      digestVisibility: {
        payer: ["payee"],
        payee: ["payer"],
      },
      referenceVisibility: {
        payer: ["payee"],
        payee: ["payer"],
      },
    }),
  );
  const { fixture, prepared } = scenario;
  const wrongHead =
    `${fixture.repositorySha.slice(0, -1)}8`;
  assert.equal(wrongHead.length, 40);
  assert.equal(
    wrongHead.slice(0, -1),
    fixture.repositorySha.slice(0, -1),
  );
  const badStates = [
    [
      "wrong full HEAD",
      {
        commitSha: fixture.repositorySha,
        headSha: wrongHead,
        worktreeStatus: "",
      },
    ],
    [
      "dirty worktree",
      {
        commitSha: fixture.repositorySha,
        headSha: fixture.repositorySha,
        worktreeStatus: "?? hostile\n",
      },
    ],
    [
      "non-commit SHA",
      {
        commitSha: "f".repeat(40),
        headSha: fixture.repositorySha,
        worktreeStatus: "",
      },
    ],
  ];

  for (const stage of [
    "prepare",
    "participant",
    "aggregate",
  ]) {
    for (const [name, state] of badStates) {
      await t.test(`${stage}: ${name}`, async () => {
        const suffix = `${stage}-${name.replaceAll(" ", "-")}`;
        const output = join(fixture.root, suffix);
        const secretReads = [];
        const secrets = new Set(
          stage === "participant"
            ? [
                prepared.payerKeyPath,
                fixture.payerTokenPath,
              ]
            : [fixture.operatorPrivateKeyPath],
        );
        const fileSystem = observedFileSystem(
          secrets,
          secretReads,
        );
        const writesBefore = scenario.network.calls.filter(
          ({ tool }) => tool === "log",
        ).length;
        const common = preflightDependencies(fixture, {
          fileSystem,
          repositoryStateResolver:
            repositoryStateResolver(fixture, state),
        });
        const invocation =
          stage === "prepare"
            ? main(
                [
                  "prepare",
                  "--operator-private-key",
                  fixture.operatorPrivateKeyPath,
                  "--operator-key-id",
                  "preflight-operator",
                  "--repository-sha",
                  fixture.repositorySha,
                  "--output",
                  output,
                ],
                {
                  ...common,
                  randomBytes: deterministicRandom(),
                },
              )
            : stage === "participant"
              ? main(
                  [
                    "participant",
                    "--role",
                    "payer",
                    "--plan",
                    prepared.planPath,
                    "--token-file",
                    fixture.payerTokenPath,
                    "--participant-private-key",
                    prepared.payerKeyPath,
                    "--output",
                    output,
                  ],
                  {
                    ...common,
                    createClient: () =>
                      scenario.network.client("payer"),
                    now: () => 1_000_000,
                    sleeper: async () => {},
                    windowMs: 0,
                  },
                )
              : main(
                  [
                    "aggregate",
                    "--plan",
                    prepared.planPath,
                    "--payer-report-dir",
                    scenario.payerOutput,
                    "--payee-report-dir",
                    scenario.payeeOutput,
                    "--operator-private-key",
                    fixture.operatorPrivateKeyPath,
                    "--output",
                    output,
                    "--attest-separate-credentials",
                    "--attest-separate-machines",
                  ],
                  {
                    ...common,
                    now: () => 1_500_000,
                  },
                );

        await assert.rejects(() => invocation, /preflight/i);
        assert.deepEqual(secretReads, []);
        assert.equal(
          scenario.network.calls.filter(
            ({ tool }) => tool === "log",
          ).length,
          writesBefore,
        );
        await assert.rejects(
          () => lstat(output),
          { code: "ENOENT" },
        );
      });
    }
  }
});

test("default provenance uses the module repository root, full HEAD, empty porcelain, and exact commit peeling", async (t) => {
  const fixture = await distributedFixture(t);
  const calls = [];
  const runGit = async (command, arguments_, options) => {
    calls.push({ arguments_, command, options });
    if (arguments_[0] === "rev-parse") {
      return { stdout: `${fixture.repositorySha}\n` };
    }
    if (arguments_[0] === "status") {
      return { stdout: "" };
    }
    if (arguments_[0] === "cat-file") {
      return { stdout: "" };
    }
    assert.fail(`unexpected git arguments: ${arguments_.join(" ")}`);
  };
  await main(
    [
      "prepare",
      "--operator-private-key",
      fixture.operatorPrivateKeyPath,
      "--operator-key-id",
      "preflight-operator",
      "--repository-sha",
      fixture.repositorySha,
      "--output",
      join(fixture.root, "default-provenance"),
    ],
    {
      prepareArtifacts:
        preflightDependencies(fixture)
          .prepareArtifacts,
      randomBytes: deterministicRandom(),
      repositoryPublicKeyResolver:
        repositoryResolver(fixture),
      runGit,
    },
  );
  assert.deepEqual(
    calls.map(({ arguments_ }) => arguments_),
    [
      ["rev-parse", "HEAD"],
      [
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
      ],
      [
        "cat-file",
        "-e",
        `${fixture.repositorySha}^{commit}`,
      ],
    ],
  );
  assert.ok(
    calls.every(
      ({ options }) =>
        options.cwd === PREFLIGHT_REPOSITORY_ROOT,
    ),
  );

  const secretReads = [];
  await assert.rejects(
    () =>
      main(
        [
          "prepare",
          "--operator-private-key",
          fixture.operatorPrivateKeyPath,
          "--operator-key-id",
          "preflight-operator",
          "--repository-sha",
          fixture.repositorySha,
          "--output",
          join(fixture.root, "tree-provenance"),
        ],
        {
          fileSystem: observedFileSystem(
            new Set([fixture.operatorPrivateKeyPath]),
            secretReads,
          ),
          randomBytes: deterministicRandom(),
          repositoryPublicKeyResolver:
            repositoryResolver(fixture),
          runGit: async (_command, arguments_) => {
            if (arguments_[0] === "rev-parse") {
              return { stdout: `${fixture.repositorySha}\n` };
            }
            if (arguments_[0] === "status") {
              return { stdout: "" };
            }
            throw Object.assign(
              new Error("tree is not a commit"),
              { code: 1 },
            );
          },
        },
      ),
    /preflight/i,
  );
  assert.deepEqual(secretReads, []);
});

test("plan and report reads use maximum-plus-one loops and reject growth or metadata races", async () => {
  const module = await import(
    "../scripts/probe-bilateral-rendezvous.mjs"
  );
  assert.equal(
    typeof module.readBoundedFile,
    "function",
    "preflight must expose its bounded reader for focused race tests",
  );
  const maximum = 8;
  const metadata = ({
    mtimeMs = 1,
    size = 1,
  } = {}) => ({
    ctimeMs: 1,
    dev: 1,
    gid: 20,
    ino: 2,
    isFile: () => true,
    mode: 0o100600,
    mtimeMs,
    nlink: 1,
    size,
    uid: 501,
  });
  let statCalls = 0;
  let closeCalls = 0;
  let readFileCalls = 0;
  const readLengths = [];
  await assert.rejects(
    () =>
      module.readBoundedFile("/public/probe-plan.json", {
        fileSystem: {
          open: async () => ({
            async close() {
              closeCalls += 1;
            },
            async read(buffer, offset, length) {
              readLengths.push(length);
              buffer.fill(0x61, offset, offset + length);
              return { buffer, bytesRead: length };
            },
            async readFile() {
              readFileCalls += 1;
              return Buffer.alloc(10_000_000);
            },
            async stat() {
              statCalls += 1;
              return metadata({
                size: statCalls === 1 ? 1 : maximum + 1,
              });
            },
          }),
        },
        maximum,
      }),
    /preflight/i,
  );
  assert.equal(readFileCalls, 0);
  assert.equal(closeCalls, 1);
  assert.equal(
    readLengths.reduce((sum, value) => sum + value, 0),
    maximum + 1,
  );
  assert.ok(
    readLengths.every(
      (value) => value <= maximum + 1,
    ),
  );

  statCalls = 0;
  await assert.rejects(
    () =>
      module.readBoundedFile(
        "/public/participant-report.json",
        {
          fileSystem: {
            open: async () => ({
              async close() {},
              async read(buffer, offset, length) {
                if (offset > 0) {
                  return { buffer, bytesRead: 0 };
                }
                buffer[offset] = 0x61;
                return { buffer, bytesRead: Math.min(1, length) };
              },
              async stat() {
                statCalls += 1;
                return metadata({
                  mtimeMs: statCalls,
                });
              },
            }),
          },
          maximum,
        },
      ),
    /preflight/i,
  );
});

test("pinned output directories reject observed pathname swaps at every sensitive publication boundary", async (t) => {
  const fixture = await distributedFixture(t);
  const preparationCases = [];
  for (const file of ["probe-plan.json"]) {
    for (const operation of [
      "open",
      "write",
      "sync",
      "dir-sync",
    ]) {
      preparationCases.push({
        event: `${operation}:${file}`,
        file,
      });
    }
  }
  for (const { event, file } of preparationCases) {
    await t.test(`prepare ${event}`, async () => {
      const output = join(
        fixture.root,
        `swap-prepare-${event.replaceAll(":", "-")}`,
      );
      const race = swappingOutputFileSystem(
        output,
        event,
      );
      await assert.rejects(
        () =>
          main(
            [
              "prepare",
              "--operator-private-key",
              fixture.operatorPrivateKeyPath,
              "--operator-key-id",
              "preflight-operator",
              "--repository-sha",
              fixture.repositorySha,
              "--output",
              output,
            ],
            preflightDependencies(fixture, {
              fileSystem: race.fileSystem,
              randomBytes: deterministicRandom(),
            }),
          ),
        /preflight/i,
      );
      assert.equal(race.swapped(), true);
      await assertNoReplacementPayload(output, file);
    });
  }

  const prepared = await prepareDistributedPlan(
    fixture,
  );
  for (const operation of [
    "open",
    "write",
    "sync",
    "dir-sync",
  ]) {
    await t.test(
      `participant intent ${operation}`,
      async () => {
        const file = "write-intent.json";
        const event = `${operation}:${file}`;
        const output = join(
          fixture.root,
          `swap-participant-${operation}`,
        );
        const race = swappingOutputFileSystem(
          output,
          event,
        );
        const network = fakeNetwork();
        await assert.rejects(
          () =>
            main(
              [
                "participant",
                "--role",
                "payer",
                "--plan",
                prepared.planPath,
                "--token-file",
                fixture.payerTokenPath,
                "--participant-private-key",
                prepared.payerKeyPath,
                "--output",
                output,
              ],
              preflightDependencies(fixture, {
                createClient: () =>
                  network.client("payer"),
                fileSystem: race.fileSystem,
                now: () => 1_000_000,
                sleeper: async () => {},
                windowMs: 0,
              }),
            ),
          /preflight/i,
        );
        assert.equal(race.swapped(), true);
        assert.equal(
          network.calls.filter(
            ({ tool }) => tool === "log",
          ).length,
          0,
        );
        await assertNoReplacementPayload(output, file);
      },
    );
  }

  const scenario = await runDistributedScenario(
    t,
    fakeNetwork({
      digestVisibility: {
        payer: ["payee"],
        payee: ["payer"],
      },
      referenceVisibility: {
        payer: ["payee"],
        payee: ["payer"],
      },
    }),
  );
  const writesBefore = scenario.network.calls.filter(
    ({ tool }) => tool === "log",
  ).length;
  for (const file of [
    "preflight-report.json",
    ".preflight-report.complete.json",
  ]) {
    for (const operation of [
      "open",
      "write",
      "sync",
      "dir-sync",
    ]) {
      await t.test(`aggregate ${operation}:${file}`, async () => {
        const event = `${operation}:${file}`;
        const output = join(
          scenario.fixture.root,
          `swap-aggregate-${operation}-${file.replaceAll(".", "-")}`,
        );
        const race = swappingOutputFileSystem(
          output,
          event,
        );
        await assert.rejects(
          () =>
            main(
              [
                "aggregate",
                "--plan",
                scenario.prepared.planPath,
                "--payer-report-dir",
                scenario.payerOutput,
                "--payee-report-dir",
                scenario.payeeOutput,
                "--operator-private-key",
                scenario.fixture.operatorPrivateKeyPath,
                "--output",
                output,
                "--attest-separate-credentials",
                "--attest-separate-machines",
              ],
              preflightDependencies(
                scenario.fixture,
                {
                  fileSystem: race.fileSystem,
                  now: () => 1_500_000,
                },
              ),
            ),
          /preflight/i,
        );
        assert.equal(race.swapped(), true);
        assert.equal(
          scenario.network.calls.filter(
            ({ tool }) => tool === "log",
          ).length,
          writesBefore,
        );
        await assertNoReplacementPayload(output, file);
      });
    }
  }
});

test("participant token input is exact printable ASCII bounded to 4096 UTF-8 bytes before output or client construction", async (t) => {
  const fixture = await distributedFixture(t);
  const acceptedToken = "A".repeat(4096);
  await writeSecret(
    fixture.payerTokenPath,
    acceptedToken,
  );
  fixture.payerPreparation =
    await rolePreparationArtifacts(fixture, "payer");
  const prepared = await prepareDistributedPlan(
    fixture,
  );
  const acceptedPath = fixture.payerTokenPath;
  const acceptedNetwork = fakeNetwork();
  let acceptedClientCalls = 0;
  const accepted = await main(
    [
      "participant",
      "--role",
      "payer",
      "--plan",
      prepared.planPath,
      "--token-file",
      acceptedPath,
      "--participant-private-key",
      prepared.payerKeyPath,
      "--output",
      join(fixture.root, "accepted-token-output"),
    ],
    preflightDependencies(fixture, {
      createClient: ({ token }) => {
        acceptedClientCalls += 1;
        assert.equal(token, acceptedToken);
        return acceptedNetwork.client("payer");
      },
      now: () => 1_000_000,
      sleeper: async () => {},
      windowMs: 0,
    }),
  );
  assert.equal(accepted.report.role, "payer");
  assert.equal(acceptedClientCalls, 1);

  for (const [name, token] of [
    ["4097 bytes", "A".repeat(4097)],
    ["control byte", "valid\u0007token"],
    ["trailing newline", "valid-token\n"],
    ["embedded newline", "valid\n token"],
    ["committed token swap", "B".repeat(4096)],
  ]) {
    await t.test(name, async () => {
      const tokenPath = join(
        fixture.root,
        `rejected-${name.replaceAll(" ", "-")}.token`,
      );
      const output = join(
        fixture.root,
        `rejected-${name.replaceAll(" ", "-")}-output`,
      );
      await writeSecret(tokenPath, token);
      let clientCalls = 0;
      const network = fakeNetwork();
      await assert.rejects(
        () =>
          main(
            [
              "participant",
              "--role",
              "payer",
              "--plan",
              prepared.planPath,
              "--token-file",
              tokenPath,
              "--participant-private-key",
              prepared.payerKeyPath,
              "--output",
              output,
            ],
            preflightDependencies(fixture, {
              createClient: () => {
                clientCalls += 1;
                return network.client("payer");
              },
              now: () => 1_000_000,
              sleeper: async () => {},
              windowMs: 0,
            }),
          ),
        /preflight/i,
      );
      assert.equal(clientCalls, 0);
      assert.equal(
        network.calls.filter(
          ({ tool }) => tool === "log",
        ).length,
        0,
      );
      await assert.rejects(
        () => lstat(output),
        { code: "ENOENT" },
      );
    });
  }
});

test("three-stage distributed CLI performs one write per participant and authorizes only the aggregate", async (t) => {
  const network = fakeNetwork({
    digestVisibility: {
      payer: ["payee"],
      payee: ["payer"],
    },
    referenceVisibility: {
      payer: ["payee"],
      payee: ["payer"],
    },
  });
  const scenario = await runDistributedScenario(
    t,
    network,
  );
  const aggregate = await aggregateDistributed(
    scenario,
  );

  assert.equal(
    scenario.prepared.envelope.plan.schema,
    "clockchain.bilateral-preflight-plan/v1",
  );
  assert.equal(
    scenario.prepared.envelope.plan.writeBudget,
    "2",
  );
  assert.notEqual(
    scenario.prepared.envelope.plan.participants.payer
      .publicKey,
    scenario.prepared.envelope.plan.participants.payee
      .publicKey,
  );
  assert.equal(
    (await stat(scenario.prepared.output)).mode & 0o777,
    0o700,
  );
  for (const keyPath of [
    scenario.prepared.payerKeyPath,
    scenario.prepared.payeeKeyPath,
  ]) {
    assert.equal(
      (await stat(keyPath)).mode & 0o777,
      0o600,
    );
  }
  assert.equal(
    network.calls.filter(({ tool }) => tool === "log")
      .length,
    2,
  );
  assert.deepEqual(
    network.calls
      .filter(({ tool }) => tool === "log")
      .map(({ observer }) => observer)
      .sort(),
    ["payee", "payer"],
  );
  for (const [role, participant, output] of [
    ["payer", scenario.payer, scenario.payerOutput],
    ["payee", scenario.payee, scenario.payeeOutput],
  ]) {
    assert.equal(
      participant.report.schema,
      "clockchain.bilateral-preflight-participant/v1",
    );
    assert.equal(participant.report.role, role);
    assert.equal(participant.report.paymentMoved, false);
    assert.equal(
      participant.report.tokenCommitment?.schema,
      "clockchain.bilateral-token-commitment/v1",
    );
    assert.deepEqual(
      participant.report.tokenCommitment,
      scenario.prepared.envelope.plan.participants[
        role
      ].tokenCommitment,
    );
    assert.equal(
      participant.report.peerObservation
        .referenceResolved,
      true,
    );
    assert.equal(
      participant.report.peerObservation.finalVerified,
      true,
    );
    await readFile(
      join(output, "participant-report.json"),
    );
    await readFile(
      join(
        output,
        ".participant-report.complete.json",
      ),
    );
    const publicKey =
      scenario.prepared.envelope.plan.participants[
        role
      ].publicKey;
    assert.equal(
      verifySignature(
        null,
        canonicalBytes(participant.report),
        createPublicKey(
          publicKeyPemFromRawBase64(publicKey),
        ),
        Buffer.from(
          participant.signature.value,
          "base64",
        ),
      ),
      true,
    );
  }
  assert.equal(
    aggregate.envelope.report.schema,
    "clockchain.bilateral-preflight/v2",
  );
  assert.equal(
    aggregate.envelope.report.outcome,
    "RENDEZVOUS_OK",
  );
  assert.equal(
    aggregate.envelope.report.channel,
    "derived-reference-id",
  );
  assert.equal(
    aggregate.envelope.report.paymentMoved,
    false,
  );
  assert.deepEqual(
    aggregate.envelope.report.writes.map(
      ({ role }) => role),
    ["payer", "payee"],
  );
  assert.equal(
    JSON.stringify({
      aggregate: aggregate.envelope,
      payee: scenario.payee,
      payer: scenario.payer,
    }).includes("AUTHOR" + "IZED"),
    false,
  );
});

test("digest-only distributed observations are recorded but aggregate unavailable", async (t) => {
  const scenario = await runDistributedScenario(
    t,
    fakeNetwork({
      digestVisibility: {
        payer: ["payee"],
        payee: ["payer"],
      },
    }),
  );
  const aggregate = await aggregateDistributed(
    scenario,
  );
  assert.ok(
    [scenario.payer, scenario.payee].every(
      ({ report }) =>
        report.peerObservation.digestResolved &&
        !report.peerObservation.referenceResolved &&
        report.peerObservation.finalVerified,
    ),
  );
  assert.equal(
    aggregate.envelope.report.channel,
    "digest-hash",
  );
  assert.equal(
    aggregate.envelope.report.outcome,
    "RENDEZVOUS_UNAVAILABLE",
  );
});

test("participant intent marker survives a crash and blocks every rerun before another write", async (t) => {
  const fixture = await distributedFixture(t);
  const prepared = await prepareDistributedPlan(
    fixture,
  );
  const network = fakeNetwork();
  const client = network.client("payer");
  const crashingClient = {
    ...client,
    async logAction(args) {
      await client.logAction(args);
      throw new Error("simulated crash");
    },
  };
  const output = join(fixture.root, "crashed-payer");
  const arguments_ = [
    "participant",
    "--role",
    "payer",
    "--plan",
    prepared.planPath,
    "--token-file",
    fixture.payerTokenPath,
    "--participant-private-key",
    prepared.payerKeyPath,
    "--output",
    output,
  ];
  await assert.rejects(
    () =>
      main(arguments_, preflightDependencies(fixture, {
        createClient: () => crashingClient,
        now: () => 1_000_000,
        sleeper: async () => {},
        windowMs: 0,
      })),
    /preflight/i,
  );
  await readFile(join(output, "write-intent.json"));
  assert.equal(
    network.calls.filter(({ tool }) => tool === "log")
      .length,
    1,
  );
  await assert.rejects(
    () =>
      main(arguments_, preflightDependencies(fixture, {
        createClient: () => {
          throw new Error("client must not be created");
        },
      })),
    /preflight/i,
  );
  assert.equal(
    network.calls.filter(({ tool }) => tool === "log")
      .length,
    1,
  );
});

test("plan, participant signature, role, and private-key tampering fail before authority", async (t) => {
  const fixture = await distributedFixture(t);
  const prepared = await prepareDistributedPlan(
    fixture,
  );
  const wrong = generateKeyPairSync("ed25519").privateKey.export({
    format: "pem",
    type: "pkcs8",
  });
  const wrongKeyPath = join(fixture.root, "wrong.pem");
  await writeSecret(wrongKeyPath, wrong);
  const plan = JSON.parse(
    await readFile(prepared.planPath, "utf8"),
  );
  plan.plan.digests.payer = "f".repeat(64);
  const tamperedPlanPath = join(
    fixture.root,
    "tampered-plan.json",
  );
  await writeFile(
    tamperedPlanPath,
    `${JSON.stringify(plan)}\n`,
    "utf8",
  );
  const network = fakeNetwork();

  let rejectedIndex = 0;
  for (const [role, planPath, keyPath] of [
    ["payer", tamperedPlanPath, prepared.payerKeyPath],
    ["payer", prepared.planPath, wrongKeyPath],
    ["payee", prepared.planPath, prepared.payerKeyPath],
  ]) {
    rejectedIndex += 1;
    await assert.rejects(
      () =>
        main(
          [
            "participant",
            "--role",
            role,
            "--plan",
            planPath,
            "--token-file",
            fixture.payerTokenPath,
            "--participant-private-key",
            keyPath,
            "--output",
            join(
              fixture.root,
              `rejected-${role}-${rejectedIndex}`,
            ),
          ],
          preflightDependencies(fixture, {
            createClient: () => network.client(role),
          }),
        ),
      /preflight/i,
    );
  }
  assert.equal(
    network.calls.filter(({ tool }) => tool === "log")
      .length,
    0,
  );
});

test("asymmetric, malformed, and rate-limited distributed observations remain unavailable", async (t) => {
  for (const [name, network] of [
    [
      "asymmetric",
      fakeNetwork({
        digestVisibility: { payer: ["payee"] },
        referenceVisibility: { payer: ["payee"] },
      }),
    ],
    [
      "malformed",
      fakeNetwork({
        malformedSearch: new Set(["payer", "payee"]),
      }),
    ],
    [
      "rate",
      fakeNetwork({
        digestVisibility: {
          payer: ["payee"],
          payee: ["payer"],
        },
        rateLimitOnce: new Set([
          "payer:search",
          "payee:search",
        ]),
        referenceVisibility: {
          payer: ["payee"],
          payee: ["payer"],
        },
      }),
    ],
  ]) {
    await t.test(name, async (t) => {
      const scenario = await runDistributedScenario(
        t,
        network,
      );
      const aggregate = await aggregateDistributed(
        scenario,
      );
      assert.equal(
        aggregate.envelope.report.outcome,
        name === "rate"
          ? "RENDEZVOUS_OK"
          : "RENDEZVOUS_UNAVAILABLE",
      );
      assert.equal(
        network.calls.filter(
          ({ tool }) => tool === "log",
        ).length,
        2,
      );
    });
  }
});

test("aggregate rejects participant report tampering and missing physical attestations", async (t) => {
  const scenario = await runDistributedScenario(
    t,
    fakeNetwork({
      digestVisibility: {
        payer: ["payee"],
        payee: ["payer"],
      },
      referenceVisibility: {
        payer: ["payee"],
        payee: ["payer"],
      },
    }),
  );
  const withoutAttestation = await aggregateDistributed(
    scenario,
    [],
  );
  assert.equal(
    withoutAttestation.envelope.report.outcome,
    "RENDEZVOUS_UNAVAILABLE",
  );
  const path = join(
    scenario.payeeOutput,
    "participant-report.json",
  );
  const report = JSON.parse(await readFile(path, "utf8"));
  report.report.write.digest = "f".repeat(64);
  await writeFile(path, `${JSON.stringify(report)}\n`);
  await assert.rejects(
    () => aggregateDistributed(scenario),
    /preflight/i,
  );
});

test("aggregate revalidates the commitment signature and exact plan equality inside a valid participant signature", async (t) => {
  const scenario = await runDistributedScenario(
    t,
    fakeNetwork({
      digestVisibility: {
        payer: ["payee"],
        payee: ["payer"],
      },
      referenceVisibility: {
        payer: ["payee"],
        payee: ["payer"],
      },
    }),
  );

  await rewriteSignedParticipantReport(
    scenario,
    "payer",
    (report) => {
      report.tokenCommitment = {
        ...report.tokenCommitment,
        signature: Buffer.alloc(64, 4).toString("base64"),
      };
    },
  );
  await assert.rejects(
    () => aggregateDistributed(scenario),
    /preflight/i,
  );

  await rewriteSignedParticipantReport(
    scenario,
    "payer",
    (report) => {
      const unsigned = {
        ...scenario.prepared.envelope.plan.participants
          .payer.tokenCommitment,
        tokenSha256: "e".repeat(64),
      };
      delete unsigned.signature;
      report.tokenCommitment = {
        ...unsigned,
        signature: sign(
          null,
          artifactSignaturePreimage(
            TOKEN_COMMITMENT_SIGNATURE_DOMAIN,
            unsigned,
          ),
          scenario.fixture.payerPreparation
            .coordinationPrivateKeyPem,
        ).toString("base64"),
      };
    },
  );
  await assert.rejects(
    () => aggregateDistributed(scenario),
    /preflight/i,
  );
});

test("aggregate rejects a validly signed observation that does not bind the peer write", async (t) => {
  const scenario = await runDistributedScenario(
    t,
    fakeNetwork({
      digestVisibility: {
        payer: ["payee"],
        payee: ["payer"],
      },
      referenceVisibility: {
        payer: ["payee"],
        payee: ["payer"],
      },
    }),
  );
  await rewriteSignedParticipantReport(
    scenario,
    "payee",
    (report) => {
      report.peerObservation.referenceAnchor.blockHeight =
        "999999";
    },
  );
  await assert.rejects(
    () => aggregateDistributed(scenario),
    /preflight/i,
  );
});

test("CLI outputs are secret-free and source contains no embedded private key", async (t) => {
  const fixture = await distributedFixture(t);
  const lines = [];
  const code = await runCli(
    [
      "prepare",
      "--operator-private-key",
      fixture.operatorPrivateKeyPath,
      "--operator-key-id",
      "preflight-operator",
      "--repository-sha",
      fixture.repositorySha,
      "--output",
      join(fixture.root, "cli-prepare"),
    ],
    preflightDependencies(fixture, {
      output: (line) => lines.push(line),
      randomBytes: deterministicRandom(),
    }),
  );
  assert.equal(code, 0);
  assert.equal(lines.length, 1);
  assert.equal(lines[0].includes("payer-token"), false);
  assert.equal(lines[0].includes("payee-token"), false);
  const source = await readFile(
    new URL(
      "../scripts/probe-bilateral-rendezvous.mjs",
      import.meta.url,
    ),
    "utf8",
  );
  assert.equal(source.includes("BEGIN PRIVATE KEY"), false);
  assert.equal(
    source.includes("11".repeat(32)),
    false,
  );
  assert.equal(
    source.includes("22".repeat(32)),
    false,
  );
  assert.equal(
    source.includes("AUTHOR" + "IZED"),
    false,
  );
});
