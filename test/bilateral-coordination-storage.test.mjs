import assert from "node:assert/strict";
import {
  appendFile,
  constants as fsConstants,
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  rename,
  rm,
  stat,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import {
  createHash,
  generateKeyPairSync,
  sign,
} from "node:crypto";
import {
  recoverMessageAddress,
} from "viem";
import {
  privateKeyToAccount,
} from "viem/accounts";

import {
  COORDINATION_ENVELOPE_SCHEMA,
  createCoordinationEnvelope,
} from "../src/bilateral/coordination/envelope.mjs";
import {
  COORDINATION_ENROLLMENT_SCHEMA,
  COORDINATION_ENROLLMENT_SET_SCHEMA,
  COORDINATION_ENROLLMENT_SIGNATURE_DOMAIN,
  INVITATION_PROOF_DOMAIN,
  MAX_COORDINATION_ENROLLMENT_BYTES,
  coordinationEnrollmentSignaturePreimage,
  invitationProofPreimage,
  parseCoordinationEnrollment,
  parseCoordinationEnrollmentSet,
  verifyCoordinationEnrollment,
} from "../src/bilateral/coordination/enrollment.mjs";
import { canonicalBytes } from "../src/bilateral/canonical.mjs";
import {
  PARTY_RESULT_SCHEMA,
  partySignatureBytes,
  renderPartyResultMarkdown,
  writePartyResult,
} from "../src/bilateral/evidence.mjs";
import {
  createSignedEnvelope,
} from "../src/bilateral/descriptor.mjs";
import {
  probeKey,
} from "../src/bilateral/refid.mjs";
import { canonicalizeReceiptEventValue } from "../src/canonical.mjs";
import {
  ARTIFACT_POLICIES,
  MAX_RELAY_ARTIFACT_BYTES,
  MAX_RELAY_PACKAGE_BYTES,
  RELAY_PACKAGE_SCHEMA,
  validateRelayArtifact,
  validateRelayArtifactWithFacts,
} from "../src/bilateral/coordination/artifact.mjs";
import {
  COORDINATION_OWNER_LOCK_LIMITATION,
  openCoordinationStore,
} from "../src/bilateral/coordination/storage.mjs";

const REPOSITORY_SHA = "c".repeat(40);
const SESSION_ID = "8f953393-86d0-4f99-9d6a-102f525fbecd";
const RELEASE_ID = "release-a";
const NOW_MS = 1_785_120_000_000;
const RAW_CAPABILITY = Buffer.alloc(32, 0x42);
const RECEIPT_SCHEMA =
  "clockchain.bilateral-coordination-receipt/v1";
const PREFLIGHT_KEY_ENROLLMENT_SIGNATURE_DOMAIN =
  "clockchain.bilateral-preflight-key-enrollment-signature/v1\n";
const TOKEN_COMMITMENT_SIGNATURE_DOMAIN =
  "clockchain.bilateral-token-commitment-signature/v1\n";

const keyPair = generateKeyPairSync("ed25519");
const PRIVATE_KEY_PEM = keyPair.privateKey.export({
  format: "pem",
  type: "pkcs8",
});
const PUBLIC_KEY = keyPair.publicKey
  .export({ format: "der", type: "spki" })
  .subarray(-32)
  .toString("base64");
const preflightKeyPair = generateKeyPairSync("ed25519");
const PREFLIGHT_PUBLIC_KEY = preflightKeyPair.publicKey
  .export({ format: "der", type: "spki" })
  .subarray(-32)
  .toString("base64");
const payeeKeyPair = generateKeyPairSync("ed25519");
const PAYEE_PUBLIC_KEY = payeeKeyPair.publicKey
  .export({ format: "der", type: "spki" })
  .subarray(-32)
  .toString("base64");
const payeePreflightKeyPair =
  generateKeyPairSync("ed25519");
const PAYEE_PREFLIGHT_PUBLIC_KEY =
  payeePreflightKeyPair.publicKey
    .export({ format: "der", type: "spki" })
    .subarray(-32)
    .toString("base64");

function enrollmentValue(overrides = {}) {
  const unsigned = {
    capabilityDigest: sha256(
      overrides.capability ?? RAW_CAPABILITY,
    ),
    coordinationKey: {
      algorithm: "ed25519",
      keyId: "payer-coordination",
      publicKey: PUBLIC_KEY,
    },
    invitations: {
      rehearsal: {
        address: `0x${"1".repeat(40)}`,
        algorithm: "eip191",
        signature: `0x${"1".repeat(130)}`,
      },
      stakeholder: {
        address: `0x${"2".repeat(40)}`,
        algorithm: "eip191",
        signature: `0x${"2".repeat(130)}`,
      },
    },
    paymentMoved: false,
    preflightKey: {
      algorithm: "ed25519",
      keyId: "payer-preflight",
      publicKey: PREFLIGHT_PUBLIC_KEY,
    },
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    role: "payer",
    schema: COORDINATION_ENROLLMENT_SCHEMA,
    sessionId: SESSION_ID,
    ...overrides,
  };
  delete unsigned.capability;
  delete unsigned.privateKeyPem;
  const privateKeyPem =
    overrides.privateKeyPem ?? PRIVATE_KEY_PEM;
  return {
    ...unsigned,
    signature: sign(
      null,
      coordinationEnrollmentSignaturePreimage(
        unsigned,
      ),
      privateKeyPem,
    ).toString("base64"),
  };
}

function enrollmentBytes(overrides = {}) {
  return canonicalBytes(enrollmentValue(overrides));
}

function signedDescriptorBytes({
  keyId = "storage-test-operator",
  privateKeyPem = PRIVATE_KEY_PEM,
} = {}) {
  return stableBytes(
    createSignedEnvelope(
      {
        amountOptions: [
          { currency: "USD", value: "100" },
        ],
        chainId: "11155111",
        expirySeconds: "600",
        namespace: "cbv1",
        payee: {
          address: `0x${"2".repeat(40)}`,
          agentId: "8678",
          displayName: "Iris",
          role: "payee",
        },
        payer: {
          address: `0x${"1".repeat(40)}`,
          agentId: "8677",
          displayName: "Billy",
          role: "payer",
        },
        paymentMoved: false,
        promptSha256: "3".repeat(64),
        protocol:
          "clockchain.bilateral-authorization/v1",
        protocolVersion: "1",
        registry:
          "0x8004a818bfb912233c491871b3d84c89a494bd9e",
        repositorySha: REPOSITORY_SHA,
        schema:
          "clockchain.bilateral-session-descriptor/v1",
        sessionId: "4".repeat(32),
        settlement: "not-executed",
      },
      {
        keyId,
        privateKeyPem,
      },
    ),
  );
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function stableBytes(value) {
  return Buffer.from(
    JSON.stringify(canonicalizeReceiptEventValue(value)),
    "utf8",
  );
}

function signedDigestPreimage(domain, value) {
  return Buffer.concat([
    Buffer.from(domain, "ascii"),
    Buffer.from(sha256(canonicalBytes(value)), "ascii"),
  ]);
}

function preflightPublicKeyArtifact(overrides = {}) {
  const unsigned = {
    algorithm: "ed25519",
    paymentMoved: false,
    publicKey: PREFLIGHT_PUBLIC_KEY,
    repositorySha: REPOSITORY_SHA,
    role: "payer",
    schema:
      "clockchain.bilateral-preflight-key-enrollment/v1",
    ...overrides,
  };
  delete unsigned.privateKeyPem;
  return {
    ...unsigned,
    signature: sign(
      null,
      signedDigestPreimage(
        PREFLIGHT_KEY_ENROLLMENT_SIGNATURE_DOMAIN,
        unsigned,
      ),
      overrides.privateKeyPem ??
        preflightKeyPair.privateKey,
    ).toString("base64"),
  };
}

function tokenCommitmentArtifact(overrides = {}) {
  const unsigned = {
    algorithm: "ed25519",
    coordinationPublicKey: PUBLIC_KEY,
    paymentMoved: false,
    repositorySha: REPOSITORY_SHA,
    role: "payer",
    schema: "clockchain.bilateral-token-commitment/v1",
    tokenSha256: "a".repeat(64),
    ...overrides,
  };
  delete unsigned.privateKeyPem;
  return {
    ...unsigned,
    signature: sign(
      null,
      signedDigestPreimage(
        TOKEN_COMMITMENT_SIGNATURE_DOMAIN,
        unsigned,
      ),
      overrides.privateKeyPem ?? PRIVATE_KEY_PEM,
    ).toString("base64"),
  };
}

function decodeJournal(bytes) {
  const records = [];
  let offset = 0;
  while (offset < bytes.length) {
    const length = bytes.readUInt32BE(offset);
    offset += 4;
    records.push(
      JSON.parse(
        bytes
          .subarray(offset, offset + length)
          .toString("utf8"),
      ),
    );
    offset += length;
  }
  return records;
}

function encodeJournal(records) {
  return Buffer.concat(
    records.map((record) => {
      const bytes = stableBytes(record);
      const header = Buffer.alloc(4);
      header.writeUInt32BE(bytes.length);
      return Buffer.concat([header, bytes]);
    }),
  );
}

function withRecordDigest(record) {
  const { recordDigest: _recordDigest, ...body } = record;
  return {
    ...body,
    recordDigest: sha256(stableBytes(body)),
  };
}

function receiptValue({
  capability = RAW_CAPABILITY,
  capabilityDigest = sha256(capability),
  certificateSha256 = "d".repeat(64),
  enrollmentDigest,
  paymentMoved = false,
  releaseId = RELEASE_ID,
  repositorySha = REPOSITORY_SHA,
  role = "payer",
  schema = RECEIPT_SCHEMA,
  sessionId = SESSION_ID,
  signature = Buffer.from(
    "coordination-receipt-signature",
  ).toString("base64"),
  signatureAlgorithm = "ed25519",
} = {}) {
  const boundEnrollmentDigest =
    enrollmentDigest ??
    sha256(
      enrollmentBytes({
        capability,
        releaseId,
        repositorySha,
        role,
        sessionId,
      }),
    );
  return {
    capabilityDigest,
    certificateSha256,
    enrollmentDigest: boundEnrollmentDigest,
    paymentMoved,
    releaseId,
    repositorySha,
    role,
    schema,
    sessionId,
    signature,
    signatureAlgorithm,
  };
}

function receiptBytes(overrides = {}) {
  return stableBytes(receiptValue(overrides));
}

const RECEIPT_BYTES = receiptBytes();

function payeeEnrollmentValue(overrides = {}) {
  return enrollmentValue({
    capability: Buffer.alloc(32, 0x43),
    coordinationKey: {
      algorithm: "ed25519",
      keyId: "payee-coordination",
      publicKey: PAYEE_PUBLIC_KEY,
    },
    invitations: {
      rehearsal: {
        address: `0x${"3".repeat(40)}`,
        algorithm: "eip191",
        signature: `0x${"3".repeat(130)}`,
      },
      stakeholder: {
        address: `0x${"4".repeat(40)}`,
        algorithm: "eip191",
        signature: `0x${"4".repeat(130)}`,
      },
    },
    preflightKey: {
      algorithm: "ed25519",
      keyId: "payee-preflight",
      publicKey: PAYEE_PREFLIGHT_PUBLIC_KEY,
    },
    privateKeyPem: payeeKeyPair.privateKey,
    role: "payee",
    ...overrides,
  });
}

function enrollmentSetValue({
  payee = payeeEnrollmentValue(),
  payer = enrollmentValue(),
  ...overrides
} = {}) {
  const payeeBytes = canonicalBytes(payee);
  const payerBytes = canonicalBytes(payer);
  return {
    enrollments: {
      payee: {
        enrollmentBase64:
          payeeBytes.toString("base64"),
        enrollmentDigest: sha256(payeeBytes),
        receiptBase64: receiptBytes({
          capabilityDigest:
            payee.capabilityDigest,
          enrollmentDigest: sha256(payeeBytes),
          role: "payee",
        }).toString("base64"),
      },
      payer: {
        enrollmentBase64:
          payerBytes.toString("base64"),
        enrollmentDigest: sha256(payerBytes),
        receiptBase64: receiptBytes({
          capabilityDigest:
            payer.capabilityDigest,
          enrollmentDigest: sha256(payerBytes),
          role: "payer",
        }).toString("base64"),
      },
    },
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    schema:
      "clockchain.bilateral-coordination-enrollment-set/v1",
    sessionId: SESSION_ID,
    ...overrides,
  };
}

function base64PadBitAlias(value) {
  const alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const padIndex = value.endsWith("==")
    ? value.length - 3
    : value.length - 2;
  const original = alphabet.indexOf(value[padIndex]);
  const aliasIndex = value.endsWith("==")
    ? (original & 0b110000) | 0b000001
    : (original & 0b111100) | 0b000001;
  return (
    value.slice(0, padIndex) +
    alphabet[aliasIndex] +
    value.slice(padIndex + 1)
  );
}

function consumeInput({
  capability = RAW_CAPABILITY,
  enrollment = enrollmentBytes({ capability }),
  enrollmentDigest = sha256(enrollment),
  receiptFactory = async (context) =>
    receiptBytes(context),
  scoped = false,
} = {}) {
  return {
    capability,
    enrollmentBytes: enrollment,
    enrollmentDigest,
    receiptFactory,
    ...(scoped
      ? {
          releaseId: RELEASE_ID,
          role: "payer",
          sessionId: SESSION_ID,
        }
      : {}),
  };
}

async function privateRoot(t) {
  const root = await mkdtemp(
    join(tmpdir(), "handshake-coordination-store-"),
  );
  await chmod(root, 0o700);
  t.after(() => rm(root, { force: true, recursive: true }));
  return root;
}

function event({
  digest = null,
  kind = "ENROLLMENT_CONFIRMED",
  previousEventDigest = null,
  releaseId = RELEASE_ID,
  role = "payer",
  sequence = "0",
  subjectRun = "release",
} = {}) {
  return createCoordinationEnvelope({
    artifactDigest: digest,
    kind,
    paymentMoved: false,
    previousEventDigest,
    privateKeyPem: PRIVATE_KEY_PEM,
    publicKey: PUBLIC_KEY,
    publicKeyId: `${role}-release-key`,
    releaseId,
    repositorySha: REPOSITORY_SHA,
    role,
    schema: COORDINATION_ENVELOPE_SCHEMA,
    sequence,
    sessionId: SESSION_ID,
    subjectRun,
  });
}

async function storeFixture(t, options = {}) {
  const root = options.root ?? (await privateRoot(t));
  const store = await openCoordinationStore({
    now: () => NOW_MS,
    repositorySha: REPOSITORY_SHA,
    root,
  });
  t.after(() => store.close().catch(() => {}));
  return { root, store };
}

async function register(store, overrides = {}) {
  return store.registerCapability({
    capabilityDigest: sha256(RAW_CAPABILITY),
    expiresAtMs: String(NOW_MS + 60_000),
    releaseId: RELEASE_ID,
    role: "payer",
    sessionId: SESSION_ID,
    ...overrides,
  });
}

async function assertReceiptRejected(
  store,
  value,
  {
    capability = RAW_CAPABILITY,
    enrollment = enrollmentBytes({ capability }),
    enrollmentDigest = sha256(enrollment),
    label,
    secretCanary,
  } = {},
) {
  await assert.rejects(
    store.consumeCapability({
      capability,
      enrollmentBytes: enrollment,
      enrollmentDigest,
      receiptFactory: async () => stableBytes(value),
    }),
    (error) => {
      assert.equal(
        error.code,
        "COORDINATION_STORAGE_INVALID",
      );
      assert.equal(
        error.message,
        "Coordination storage operation failed safely.",
      );
      if (secretCanary !== undefined) {
        assert.equal(
          `${error.message}\n${error.stack}`.includes(
            secretCanary,
          ),
          false,
        );
      }
      return true;
    },
    label,
  );
}

function testFileSystem(overrides = {}) {
  return {
    link,
    lstat,
    mkdir,
    open,
    readdir,
    rename,
    unlink,
    ...overrides,
  };
}

function handleFacade(handle, overrides = {}) {
  return {
    chmod: handle.chmod.bind(handle),
    close: handle.close.bind(handle),
    read: handle.read.bind(handle),
    readFile: handle.readFile.bind(handle),
    stat: handle.stat.bind(handle),
    sync: handle.sync.bind(handle),
    truncate: handle.truncate.bind(handle),
    writeFile: handle.writeFile.bind(handle),
    ...overrides,
  };
}

test("pins exact enrollment schemas, domains, and canonical proof preimages", () => {
  assert.equal(
    COORDINATION_ENROLLMENT_SCHEMA,
    "clockchain.bilateral-coordination-enrollment/v1",
  );
  assert.equal(
    COORDINATION_ENROLLMENT_SIGNATURE_DOMAIN,
    "clockchain.bilateral-coordination-enrollment-signature/v1\n",
  );
  assert.equal(
    INVITATION_PROOF_DOMAIN,
    "clockchain.bilateral-invitation-proof/v1\n",
  );
  assert.equal(MAX_COORDINATION_ENROLLMENT_BYTES, 65_536);

  const enrollment = enrollmentValue();
  const challenge = {
    address: enrollment.invitations.rehearsal.address,
    capabilityDigest: enrollment.capabilityDigest,
    releaseId: enrollment.releaseId,
    repositorySha: enrollment.repositorySha,
    role: enrollment.role,
    run: "rehearsal",
    sessionId: enrollment.sessionId,
  };
  assert.deepEqual(
    invitationProofPreimage(challenge),
    Buffer.concat([
      Buffer.from(INVITATION_PROOF_DOMAIN, "ascii"),
      Buffer.from(
        sha256(canonicalBytes(challenge)),
        "ascii",
      ),
    ]),
  );
  const { signature: _signature, ...unsigned } =
    enrollment;
  assert.deepEqual(
    coordinationEnrollmentSignaturePreimage(unsigned),
    Buffer.concat([
      Buffer.from(
        COORDINATION_ENROLLMENT_SIGNATURE_DOMAIN,
        "ascii",
      ),
      Buffer.from(
        sha256(canonicalBytes(unsigned)),
        "ascii",
      ),
    ]),
  );
});

test("verifies, detaches, and freezes an exact canonical coordination enrollment", () => {
  const source = enrollmentValue();
  const verified = verifyCoordinationEnrollment(source);
  const parsed = parseCoordinationEnrollment(
    canonicalBytes(source),
  );
  assert.deepEqual(verified, parsed);
  assert.notEqual(verified, source);
  assert.notEqual(
    verified.coordinationKey,
    source.coordinationKey,
  );
  assert.equal(Object.isFrozen(verified), true);
  assert.equal(
    Object.isFrozen(verified.invitations.rehearsal),
    true,
  );
  source.coordinationKey.publicKey =
    PREFLIGHT_PUBLIC_KEY;
  assert.equal(verified.coordinationKey.publicKey, PUBLIC_KEY);
});

test("parses one exact frozen authenticated enrollment set and rejects hostile scope, digest, canonicality, and cross-role identity reuse", () => {
  assert.equal(
    COORDINATION_ENROLLMENT_SET_SCHEMA,
    "clockchain.bilateral-coordination-enrollment-set/v1",
  );
  const exact = enrollmentSetValue();
  const bytes = stableBytes(exact);
  const parsed = parseCoordinationEnrollmentSet(bytes);
  assert.deepEqual(parsed, exact);
  assert.equal(Object.isFrozen(parsed), true);
  assert.equal(Object.isFrozen(parsed.enrollments), true);
  assert.equal(
    Object.isFrozen(parsed.enrollments.payer),
    true,
  );

  const cases = [];
  for (const key of Object.keys(exact)) {
    const candidate = structuredClone(exact);
    delete candidate[key];
    cases.push({ label: `missing ${key}`, value: candidate });
  }
  for (const role of ["payee", "payer"]) {
    for (const key of Object.keys(
      exact.enrollments[role],
    )) {
      const candidate = structuredClone(exact);
      delete candidate.enrollments[role][key];
      cases.push({
        label: `missing ${role}.${key}`,
        value: candidate,
      });
    }
  }
  cases.push(
    {
      label: "extra top-level field",
      value: { ...exact, advisoryStatus: "ready" },
    },
    {
      label: "extra enrollment field",
      value: {
        ...exact,
        enrollments: {
          ...exact.enrollments,
          payer: {
            ...exact.enrollments.payer,
            receiptDigest: "0".repeat(64),
          },
        },
      },
    },
    {
      label: "payment moved",
      value: { ...exact, paymentMoved: true },
    },
    {
      label: "substituted role",
      value: {
        ...exact,
        enrollments: {
          payee: exact.enrollments.payer,
          payer: exact.enrollments.payer,
        },
      },
    },
    {
      label: "digest mismatch",
      value: {
        ...exact,
        enrollments: {
          ...exact.enrollments,
          payer: {
            ...exact.enrollments.payer,
            enrollmentDigest: "0".repeat(64),
          },
        },
      },
    },
    {
      label: "cross-release enrollment",
      value: enrollmentSetValue({
        payee: payeeEnrollmentValue({
          releaseId: "release-b",
        }),
      }),
    },
    {
      label: "invalid enrollment signature",
      value: enrollmentSetValue({
        payee: {
          ...payeeEnrollmentValue(),
          signature:
            Buffer.alloc(64).toString("base64"),
        },
      }),
    },
  );

  const sameCoordination = payeeEnrollmentValue({
    coordinationKey: {
      algorithm: "ed25519",
      keyId: "payee-coordination",
      publicKey: PUBLIC_KEY,
    },
    privateKeyPem: PRIVATE_KEY_PEM,
  });
  cases.push({
    label: "same coordination key",
    value: enrollmentSetValue({
      payee: sameCoordination,
    }),
  });
  cases.push({
    label: "same preflight key",
    value: enrollmentSetValue({
      payee: payeeEnrollmentValue({
        preflightKey: {
          algorithm: "ed25519",
          keyId: "payee-preflight",
          publicKey: PREFLIGHT_PUBLIC_KEY,
        },
      }),
    }),
  });
  cases.push({
    label: "same invitation address",
    value: enrollmentSetValue({
      payee: payeeEnrollmentValue({
        invitations: {
          rehearsal: {
            address:
              enrollmentValue().invitations.rehearsal.address,
            algorithm: "eip191",
            signature: `0x${"3".repeat(130)}`,
          },
          stakeholder: {
            address: `0x${"4".repeat(40)}`,
            algorithm: "eip191",
            signature: `0x${"4".repeat(130)}`,
          },
        },
      }),
    }),
  });
  const aliased = structuredClone(exact);
  aliased.enrollments.payer.enrollmentBase64 =
    base64PadBitAlias(
      aliased.enrollments.payer.enrollmentBase64,
    );
  assert.deepEqual(
    Buffer.from(
      aliased.enrollments.payer.enrollmentBase64,
      "base64",
    ),
    Buffer.from(
      exact.enrollments.payer.enrollmentBase64,
      "base64",
    ),
  );
  cases.push({
    label: "noncanonical enrollment base64",
    value: aliased,
  });

  for (const { label, value } of cases) {
    assert.throws(
      () =>
        parseCoordinationEnrollmentSet(
          stableBytes(value),
        ),
      { code: "COORDINATION_ENROLLMENT_INVALID" },
      label,
    );
  }
  assert.throws(
    () =>
      parseCoordinationEnrollmentSet(
        Buffer.from(`${bytes.toString("utf8")} `),
      ),
    { code: "COORDINATION_ENROLLMENT_INVALID" },
    "noncanonical JSON",
  );
  assert.throws(
    () =>
      parseCoordinationEnrollmentSet(
        Buffer.from(
          bytes
            .toString("utf8")
            .replace(
              '"paymentMoved":false,',
              '"paymentMoved":false,"paymentMoved":false,',
            ),
        ),
      ),
    { code: "COORDINATION_ENROLLMENT_INVALID" },
    "duplicate JSON key",
  );
});

test("rejects missing, extra, nested, malformed, and self-conflicting enrollment fields", () => {
  const exact = enrollmentValue();
  for (const key of Object.keys(exact)) {
    const candidate = structuredClone(exact);
    delete candidate[key];
    assert.throws(
      () => verifyCoordinationEnrollment(candidate),
      { code: "COORDINATION_ENROLLMENT_INVALID" },
      `missing ${key}`,
    );
  }
  for (const candidate of [
    { ...exact, extra: "forbidden" },
    {
      ...exact,
      rawCapability: RAW_CAPABILITY.toString("base64"),
    },
    {
      ...exact,
      coordinationKey: {
        ...exact.coordinationKey,
        nested: {},
      },
    },
    { ...exact, paymentMoved: true },
    {
      ...exact,
      schema:
        "clockchain.bilateral-coordination-enrollment/v2",
    },
    {
      ...exact,
      coordinationKey: exact.preflightKey,
    },
    {
      ...exact,
      preflightKey: exact.coordinationKey,
    },
    {
      ...exact,
      invitations: {
        ...exact.invitations,
        stakeholder: exact.invitations.rehearsal,
      },
    },
    {
      ...exact,
      invitations: {
        ...exact.invitations,
        rehearsal: {
          ...exact.invitations.rehearsal,
          address: exact.invitations.rehearsal.address
            .toUpperCase(),
        },
      },
    },
    {
      ...exact,
      invitations: {
        ...exact.invitations,
        rehearsal: {
          ...exact.invitations.rehearsal,
          signature: `0x${"A".repeat(130)}`,
        },
      },
    },
  ]) {
    assert.throws(
      () => verifyCoordinationEnrollment(candidate),
      { code: "COORDINATION_ENROLLMENT_INVALID" },
    );
  }
});

test("rejects wrong enrollment signatures, signing keys, domains, and noncanonical bytes generically", () => {
  const wrongKeyPair = generateKeyPairSync("ed25519");
  const wrongPublicKey = wrongKeyPair.publicKey
    .export({ format: "der", type: "spki" })
    .subarray(-32)
    .toString("base64");
  const exact = enrollmentValue();
  const cases = [
    { ...exact, signature: "A".repeat(86) + "==" },
    {
      ...exact,
      coordinationKey: {
        ...exact.coordinationKey,
        publicKey: wrongPublicKey,
      },
    },
    enrollmentValue({
      privateKeyPem: wrongKeyPair.privateKey.export({
        format: "pem",
        type: "pkcs8",
      }),
    }),
  ];
  const { signature: _signature, ...unsigned } = exact;
  cases.push({
    ...exact,
    signature: sign(
      null,
      Buffer.concat([
        Buffer.from("wrong-domain\n", "ascii"),
        Buffer.from(
          sha256(canonicalBytes(unsigned)),
          "ascii",
        ),
      ]),
      PRIVATE_KEY_PEM,
    ).toString("base64"),
  });
  for (const candidate of cases) {
    assert.throws(
      () => verifyCoordinationEnrollment(candidate),
      {
        code: "COORDINATION_ENROLLMENT_INVALID",
        message:
          "Coordination enrollment validation failed.",
      },
    );
  }
  const noncanonical = Buffer.from(
    `${JSON.stringify(exact)}\n`,
    "utf8",
  );
  assert.throws(
    () => parseCoordinationEnrollment(noncanonical),
    { code: "COORDINATION_ENROLLMENT_INVALID" },
  );
  assert.throws(
    () =>
      parseCoordinationEnrollment(
        Buffer.alloc(
          MAX_COORDINATION_ENROLLMENT_BYTES + 1,
          0x61,
        ),
      ),
    { code: "COORDINATION_ENROLLMENT_INVALID" },
  );
});

test("converts hostile enrollment getters and proxies into fixed secret-free errors", () => {
  for (const hostile of [
    Object.defineProperty(enrollmentValue(), "role", {
      enumerable: true,
      get() {
        throw new Error("ENROLLMENT_SECRET_CANARY");
      },
    }),
    new Proxy(
      {},
      {
        ownKeys() {
          throw new Error("ENROLLMENT_PROXY_SECRET_CANARY");
        },
      },
    ),
  ]) {
    let error;
    try {
      verifyCoordinationEnrollment(hostile);
    } catch (caught) {
      error = caught;
    }
    assert.equal(
      error?.code,
      "COORDINATION_ENROLLMENT_INVALID",
    );
    assert.equal(
      error?.message,
      "Coordination enrollment validation failed.",
    );
    assert.doesNotMatch(
      `${error?.message}\n${error?.stack}`,
      /ENROLLMENT_(?:SECRET|PROXY_SECRET)_CANARY/,
    );
  }
});

test("pins the closed artifact policy and storage bounds", () => {
  assert.equal(MAX_RELAY_ARTIFACT_BYTES, 1_048_576);
  assert.equal(MAX_RELAY_PACKAGE_BYTES, 3_145_728);
  assert.equal(
    RELAY_PACKAGE_SCHEMA,
    "clockchain.bilateral-relay-package/v1",
  );
  assert.deepEqual(ARTIFACT_POLICIES, {
    "coordination-enrollment": { maximum: 65_536 },
    "coordination-receipt": { maximum: 65_536 },
    "failure-summary": { maximum: 16_384 },
    "identity-package": {
      maximum: 1_048_576,
      markerRequired: true,
    },
    "invitation-public-bundle": { maximum: 16_384 },
    "party-result-package": {
      maximum: 3_145_728,
      markerRequired: true,
    },
    "preflight-aggregate-report": {
      maximum: 1_048_576,
      markerRequired: true,
    },
    "preflight-participant-report": {
      maximum: 1_048_576,
      markerRequired: true,
    },
    "recovery-command-manifest": { maximum: 65_536 },
    "preflight-plan": { maximum: 65_536 },
    "preflight-public-key": { maximum: 65_536 },
    "signed-descriptor": { maximum: 1_048_576 },
    "token-commitment": { maximum: 65_536 },
  });
  assert.ok(Object.isFrozen(ARTIFACT_POLICIES));
  assert.ok(
    Object.values(ARTIFACT_POLICIES).every(Object.isFrozen),
  );
  assert.equal(
    COORDINATION_OWNER_LOCK_LIMITATION,
    "Node.js 22 provides no kernel advisory file lock; simultaneous removal of both hard-linked owner lease paths is outside this store's exclusion guarantee.",
  );
});

test("accepts only exact coordination enrollments and signed descriptors while other schemas fail closed", async () => {
  const bytes = signedDescriptorBytes();
  assert.deepEqual(
    await validateRelayArtifact({
      artifactType: "signed-descriptor",
      bytes,
      expectedDigest: sha256(bytes),
      secretCanaries: [],
    }),
    {
      artifactType: "signed-descriptor",
      byteLength: String(bytes.length),
      digest: sha256(bytes),
    },
  );

  const invalidSignature = JSON.parse(bytes.toString("utf8"));
  invalidSignature.operator.signature =
    `${invalidSignature.operator.signature.slice(0, -4)}AAAA`;
  const extraKey = JSON.parse(bytes.toString("utf8"));
  extraKey.untrusted = false;
  const incomplete = JSON.parse(bytes.toString("utf8"));
  delete incomplete.descriptor.amountOptions;
  for (const value of [
    invalidSignature,
    extraKey,
    incomplete,
  ]) {
    const hostileBytes = stableBytes(value);
    await assert.rejects(
      async () =>
        await validateRelayArtifact({
          artifactType: "signed-descriptor",
          bytes: hostileBytes,
          expectedDigest: sha256(hostileBytes),
          secretCanaries: [],
        }),
      { code: "RELAY_ARTIFACT_INVALID" },
    );
  }

  const exactEnrollment = enrollmentBytes();
  assert.deepEqual(
    await validateRelayArtifact({
      artifactType: "coordination-enrollment",
      bytes: exactEnrollment,
      expectedDigest: sha256(exactEnrollment),
      secretCanaries: [],
    }),
    {
      artifactType: "coordination-enrollment",
      byteLength: String(exactEnrollment.length),
      digest: sha256(exactEnrollment),
    },
  );
  const malformedEnrollment = enrollmentValue();
  malformedEnrollment.signature =
    `${malformedEnrollment.signature.slice(0, -4)}AAAA`;
  const malformedEnrollmentBytes = canonicalBytes(
    malformedEnrollment,
  );
  await assert.rejects(
    async () =>
      await validateRelayArtifact({
        artifactType: "coordination-enrollment",
        bytes: malformedEnrollmentBytes,
        expectedDigest: sha256(malformedEnrollmentBytes),
        secretCanaries: [],
      }),
    { code: "RELAY_ARTIFACT_INVALID" },
  );

  for (const [artifactType, candidate] of [
    [
      "coordination-receipt",
      {
        paymentMoved: false,
        schema:
          "clockchain.bilateral-coordination-receipt/v1",
        signature: "A".repeat(88),
      },
    ],
    [
      "failure-summary",
      {
        paymentMoved: false,
        schema: "clockchain.bilateral-failure-summary/v1",
        signature: "A".repeat(88),
      },
    ],
    [
      "identity-package",
      {
        files: [],
        paymentMoved: false,
        schema: RELAY_PACKAGE_SCHEMA,
      },
    ],
    [
      "invitation-public-bundle",
      {
        paymentMoved: false,
        schema:
          "clockchain.bilateral-invitation-public-bundle/v1",
        signature: "A".repeat(88),
      },
    ],
    [
      "party-result-package",
      {
        files: [],
        paymentMoved: false,
        schema: RELAY_PACKAGE_SCHEMA,
      },
    ],
    [
      "preflight-aggregate-report",
      {
        files: [],
        paymentMoved: false,
        schema: RELAY_PACKAGE_SCHEMA,
      },
    ],
    [
      "preflight-participant-report",
      {
        files: [],
        paymentMoved: false,
        schema: RELAY_PACKAGE_SCHEMA,
      },
    ],
    [
      "preflight-plan",
      {
        operator: { signature: "A".repeat(88) },
        plan: {
          paymentMoved: false,
          schema: "clockchain.bilateral-preflight-plan/v1",
        },
      },
    ],
  ]) {
    const extra = { ...candidate, extra: "untrusted" };
    const incomplete = structuredClone(candidate);
    if (Object.hasOwn(incomplete, "schema")) {
      delete incomplete.schema;
    } else if (Object.hasOwn(incomplete, "plan")) {
      delete incomplete.plan.schema;
    } else {
      delete incomplete.files;
    }
    for (const value of [candidate, extra, incomplete]) {
      const unsupportedBytes = stableBytes(value);
      await assert.rejects(
        async () =>
          await validateRelayArtifact({
            artifactType,
            bytes: unsupportedBytes,
            expectedDigest: sha256(unsupportedBytes),
            secretCanaries: [],
          }),
        { code: "RELAY_ARTIFACT_INVALID" },
        artifactType,
      );
    }
  }
});

test("stores a valid self-signed descriptor as non-authorizing content without trusting its embedded authority", async (t) => {
  const untrusted = generateKeyPairSync("ed25519");
  const bytes = signedDescriptorBytes({
    keyId: "untrusted-but-valid",
    privateKeyPem: untrusted.privateKey.export({
      format: "pem",
      type: "pkcs8",
    }),
  });
  const { store } = await storeFixture(t);
  const metadata = await store.putArtifact({
    artifactType: "signed-descriptor",
    bytes,
    expectedDigest: sha256(bytes),
    secretCanaries: [],
  });
  assert.deepEqual(Object.keys(metadata), [
    "artifactType",
    "byteLength",
    "digest",
  ]);
  assert.equal(Object.hasOwn(metadata, "trusted"), false);
  assert.equal(Object.hasOwn(metadata, "authorized"), false);
  assert.deepEqual(
    await store.getArtifact(metadata.digest),
    bytes,
  );
});

test("artifact validation accepts only exact own data inputs", async () => {
  const bytes = stableBytes({
    paymentMoved: false,
    schema: "clockchain.bilateral-coordination-enrollment/v1",
  });
  const base = {
    artifactType: "coordination-enrollment",
    bytes,
    expectedDigest: sha256(bytes),
    secretCanaries: [],
  };
  for (const input of [
    { ...base, extra: "x" },
    Object.assign(Object.create({ inherited: true }), base),
    Object.defineProperty({ ...base }, "artifactType", {
      enumerable: true,
      get() {
        throw new Error("must not invoke");
      },
    }),
  ]) {
    await assert.rejects(
      async () => await validateRelayArtifact(input),
      { code: "RELAY_ARTIFACT_INVALID" },
    );
  }
});

test("artifact validation and store opening convert hostile prototype traps into fixed secret-free errors", async () => {
  const artifactCanary =
    "ARTIFACT_PROXY_SECRET_CANARY";
  let artifactError;
  try {
    await validateRelayArtifact(
      new Proxy(
        {},
        {
          getPrototypeOf() {
            throw new Error(artifactCanary);
          },
        },
      ),
    );
  } catch (error) {
    artifactError = error;
  }
  assert.equal(
    artifactError?.code,
    "RELAY_ARTIFACT_INVALID",
  );
  assert.equal(
    artifactError?.message,
    "Relay artifact validation failed.",
  );
  assert.doesNotMatch(
    `${artifactError?.message}\n${artifactError?.stack}`,
    new RegExp(artifactCanary),
  );

  for (const [canary, input] of [
    [
      "OPEN_PROXY_SECRET_CANARY",
      new Proxy(
        {},
        {
          getPrototypeOf() {
            throw new Error("OPEN_PROXY_SECRET_CANARY");
          },
        },
      ),
    ],
    [
      "OPEN_FILESYSTEM_ACCESSOR_SECRET_CANARY",
      {
        fileSystem: Object.defineProperty(
          testFileSystem(),
          "open",
          {
            enumerable: true,
            get() {
              throw new Error(
                "OPEN_FILESYSTEM_ACCESSOR_SECRET_CANARY",
              );
            },
          },
        ),
        repositorySha: REPOSITORY_SHA,
        root: "/does-not-matter",
      },
    ],
  ]) {
    let error;
    try {
      await openCoordinationStore(input);
    } catch (caught) {
      error = caught;
    }
    assert.equal(
      error?.code,
      "COORDINATION_STORAGE_INVALID",
    );
    assert.equal(
      error?.message,
      "Coordination storage operation failed safely.",
    );
    assert.doesNotMatch(
      `${error?.message}\n${error?.stack}`,
      new RegExp(canary),
    );
  }
});

test("accepts exact signed preflight public keys and rejects wrong signature, key, SHA, role, extra keys, and canaries", async () => {
  const artifact = preflightPublicKeyArtifact();
  const bytes = stableBytes(artifact);
  assert.deepEqual(
    await validateRelayArtifact({
      artifactType: "preflight-public-key",
      bytes,
      expectedDigest: sha256(bytes),
      secretCanaries: [],
    }),
    {
      artifactType: "preflight-public-key",
      byteLength: String(bytes.length),
      digest: sha256(bytes),
    },
  );

  const wrongKey = generateKeyPairSync("ed25519")
    .publicKey.export({ format: "der", type: "spki" })
    .subarray(-32)
    .toString("base64");
  for (const hostile of [
    {
      ...artifact,
      signature: Buffer.alloc(64, 9).toString("base64"),
    },
    { ...artifact, publicKey: wrongKey },
    { ...artifact, repositorySha: "d".repeat(40) },
    { ...artifact, role: "payee" },
    { ...artifact, extra: "untrusted" },
  ]) {
    const hostileBytes = stableBytes(hostile);
    await assert.rejects(
      async () =>
        await validateRelayArtifact({
          artifactType: "preflight-public-key",
          bytes: hostileBytes,
          expectedDigest: sha256(hostileBytes),
          secretCanaries: [],
        }),
      { code: "RELAY_ARTIFACT_INVALID" },
    );
  }
  await assert.rejects(
    async () =>
      await validateRelayArtifact({
        artifactType: "preflight-public-key",
        bytes,
        expectedDigest: sha256(bytes),
        secretCanaries: [artifact.publicKey],
      }),
    { code: "RELAY_ARTIFACT_INVALID" },
  );
});

test("accepts exact signed token commitments and rejects wrong signature, key, SHA, role, extra keys, and canaries", async () => {
  const artifact = tokenCommitmentArtifact();
  const bytes = stableBytes(artifact);
  assert.deepEqual(
    await validateRelayArtifact({
      artifactType: "token-commitment",
      bytes,
      expectedDigest: sha256(bytes),
      secretCanaries: [],
    }),
    {
      artifactType: "token-commitment",
      byteLength: String(bytes.length),
      digest: sha256(bytes),
    },
  );

  const wrongKey = generateKeyPairSync("ed25519")
    .publicKey.export({ format: "der", type: "spki" })
    .subarray(-32)
    .toString("base64");
  for (const hostile of [
    {
      ...artifact,
      signature: Buffer.alloc(64, 9).toString("base64"),
    },
    { ...artifact, coordinationPublicKey: wrongKey },
    { ...artifact, repositorySha: "d".repeat(40) },
    { ...artifact, role: "payee" },
    { ...artifact, extra: "untrusted" },
  ]) {
    const hostileBytes = stableBytes(hostile);
    await assert.rejects(
      async () =>
        await validateRelayArtifact({
          artifactType: "token-commitment",
          bytes: hostileBytes,
          expectedDigest: sha256(hostileBytes),
          secretCanaries: [],
        }),
      { code: "RELAY_ARTIFACT_INVALID" },
    );
  }
  await assert.rejects(
    async () =>
      await validateRelayArtifact({
        artifactType: "token-commitment",
        bytes,
        expectedDigest: sha256(bytes),
        secretCanaries: [artifact.coordinationPublicKey],
      }),
    { code: "RELAY_ARTIFACT_INVALID" },
  );
});

test("returns deeply frozen normalized public token commitment facts", async () => {
  const artifact = tokenCommitmentArtifact();
  const bytes = stableBytes(artifact);
  const result = await validateRelayArtifactWithFacts({
    artifactType: "token-commitment",
    bytes,
    expectedDigest: sha256(bytes),
    secretCanaries: [],
  });

  assert.deepEqual(result, {
    artifactType: "token-commitment",
    byteLength: String(bytes.length),
    digest: sha256(bytes),
    facts: artifact,
  });
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.facts), true);
  assert.throws(() => {
    result.facts.role = "payee";
  }, TypeError);
});

test("validates canonical named artifacts and rejects digest or secret mismatch", async () => {
  const bytes = signedDescriptorBytes();
  const metadata = await validateRelayArtifact({
    artifactType: "signed-descriptor",
    bytes,
    expectedDigest: sha256(bytes),
    secretCanaries: ["cc_secret_canary_1234567890"],
  });
  assert.deepEqual(metadata, {
    artifactType: "signed-descriptor",
    byteLength: String(bytes.length),
    digest: sha256(bytes),
  });
  assert.ok(Object.isFrozen(metadata));

  await assert.rejects(
    async () =>
      await validateRelayArtifact({
        artifactType: "signed-descriptor",
        bytes,
        expectedDigest: "0".repeat(64),
        secretCanaries: [],
      }),
    { code: "RELAY_ARTIFACT_INVALID" },
  );
  const secretValue = JSON.parse(bytes.toString("utf8"));
  secretValue.descriptor.payer.displayName =
    "cc_secret_canary_1234567890";
  const secretBytes = stableBytes(secretValue);
  await assert.rejects(
    async () =>
      await validateRelayArtifact({
        artifactType: "signed-descriptor",
        bytes: secretBytes,
        expectedDigest: sha256(secretBytes),
        secretCanaries: ["cc_secret_canary_1234567890"],
      }),
    { code: "RELAY_ARTIFACT_INVALID" },
  );
});

test("rejects noncanonical JSON, archives, unknown types, private keys, and oversized artifacts", async () => {
  const cases = [
    {
      artifactType: "coordination-enrollment",
      bytes: Buffer.from(
        '{"schema":"clockchain.bilateral-coordination-enrollment/v1", "paymentMoved":false}',
      ),
    },
    {
      artifactType: "arbitrary-json",
      bytes: stableBytes({ paymentMoved: false, schema: "anything" }),
    },
    {
      artifactType: "coordination-enrollment",
      bytes: Buffer.from("PK\u0003\u0004archive"),
    },
    {
      artifactType: "coordination-enrollment",
      bytes: stableBytes({
        material:
          "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----",
        paymentMoved: false,
        schema:
          "clockchain.bilateral-coordination-enrollment/v1",
      }),
    },
    {
      artifactType: "coordination-enrollment",
      bytes: stableBytes({
        paymentMoved: false,
        privateKey: "short",
        schema:
          "clockchain.bilateral-coordination-enrollment/v1",
      }),
    },
    {
      artifactType: "coordination-enrollment",
      bytes: Buffer.alloc(65_537, 0x61),
    },
  ];
  for (const input of cases) {
    await assert.rejects(
      async () =>
        await validateRelayArtifact({
          ...input,
          expectedDigest: sha256(input.bytes),
          secretCanaries: [],
        }),
      { code: "RELAY_ARTIFACT_INVALID" },
    );
  }
});

test("rejects a noncanonical base64 pad-bit alias even when decoded package bytes and digests agree", async () => {
  const packageValue = JSON.parse(partyPackage().toString("utf8"));
  const file = packageValue.files.find(
    ({ name }) => name === "PARTY-RESULT.md",
  );
  const canonicalBase64 = file.contentBase64;
  const alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const padIndex = file.contentBase64.endsWith("==")
    ? file.contentBase64.length - 3
    : file.contentBase64.length - 2;
  const original = alphabet.indexOf(
    file.contentBase64[padIndex],
  );
  const aliasIndex =
    file.contentBase64.endsWith("==")
      ? (original & 0b110000) | 0b000001
      : (original & 0b111100) | 0b000001;
  file.contentBase64 =
    file.contentBase64.slice(0, padIndex) +
    alphabet[aliasIndex] +
    file.contentBase64.slice(padIndex + 1);
  assert.deepEqual(
    Buffer.from(file.contentBase64, "base64"),
    Buffer.from(canonicalBase64, "base64"),
  );
  const bytes = stableBytes(packageValue);
  await assert.rejects(
    async () =>
      await validateRelayArtifact({
        artifactType: "party-result-package",
        bytes,
        expectedDigest: sha256(bytes),
        secretCanaries: [],
      }),
    { code: "RELAY_ARTIFACT_INVALID" },
  );
});

function partyPackage({
  contentTransform,
  includeMarker = true,
  markerExtra = false,
  markerDigest,
  markdownPayload,
  namesTransform,
  extraFile = false,
} = {}) {
  const json = Buffer.from(
    `${JSON.stringify(
      {
        paymentMoved: false,
        schema: "clockchain.bilateral-party-result/v1",
      },
      null,
      2,
    )}\n`,
  );
  const markdown =
    markdownPayload ??
    Buffer.from("# Bilateral party result\n");
  const markerValue = {
    jsonSha256: markerDigest ?? sha256(json),
    markdownSha256: sha256(markdown),
    schema:
      "clockchain.bilateral-party-result-completion/v1",
  };
  if (markerExtra) {
    markerValue.extra = "x";
  }
  const marker = stableBytes(markerValue);
  let files = [
    [".party-result.complete.json", marker],
    ["PARTY-RESULT.md", markdown],
    ["party-result.json", json],
  ];
  if (!includeMarker) {
    files.shift();
  }
  if (extraFile) {
    files.push(["secret.txt", Buffer.from("no")]);
  }
  files = namesTransform?.(files) ?? files;
  return stableBytes({
    files: files.map(([name, bytes], index) => {
      const result = {
        byteLength: String(bytes.length),
        contentBase64: bytes.toString("base64"),
        name,
        sha256: sha256(bytes),
      };
      return contentTransform?.(result, index, bytes) ?? result;
    }),
    paymentMoved: false,
    schema: RELAY_PACKAGE_SCHEMA,
  });
}

async function producerPartyPackage(t) {
  const account = privateKeyToAccount(`0x${"11".repeat(32)}`);
  const sessionDigest = "cd".repeat(32);
  const head = {
    amount: { currency: "USD", moved: false, value: "100" },
    expirySeconds: "600",
    payee: { address: `0x${"22".repeat(20)}`, agentId: "9001" },
    payer: { address: account.address.toLowerCase(), agentId: "8677", reference: "eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:8677" },
    protocol: "clockchain.bilateral-authorization/v1",
    schema: "clockchain.bilateral-transition/v1",
    sessionDigest,
  };
  const proposal = { ...head, kind: "proposal", predecessor: null, sequence: "1" };
  const proposalTriple = { anchoredHash: sha256(canonicalBytes(proposal)), blockHeight: "1869000", kind: "proposal", ledgerId: "3f8a1c2e-9d4b-4a6c-8f2e-0123456789ab" };
  const acceptance = { ...head, decision: "ACCEPT", kind: "acceptance", predecessor: proposalTriple, sequence: "2" };
  const acceptanceTriple = { anchoredHash: sha256(canonicalBytes(acceptance)), blockHeight: "1869030", kind: "acceptance", ledgerId: "4a9b2d3f-0e5c-4b7d-9a3f-123456789abc" };
  const acknowledgment = { ...head, kind: "acknowledgment", outcome: "ACKNOWLEDGED", paymentMoved: false, predecessor: acceptanceTriple, proposal: proposalTriple, sequence: "3" };
  const messages = [proposal, acceptance, acknowledgment];
  const rawTimes = ["2026-07-24T20:00:00.100000001Z", "2026-07-24T20:00:31.204500000Z", "2026-07-24T20:01:02.309999999Z"];
  const times = [1784923200100, 1784923231204, 1784923262309];
  const ledgers = [proposalTriple.ledgerId, acceptanceTriple.ledgerId, "5b0c3e40-1f6d-4c8e-ab40-23456789abcd"];
  const heights = ["1869000", "1869030", "1869060"];
  const transitions = messages.map((message, index) => ({
    blockTimeMs: String(times[index]), blockTimeRaw: rawTimes[index],
    digest: sha256(canonicalBytes(message)), message,
    onChain: { anchoredHash: sha256(canonicalBytes(message)), blockHeight: heights[index], ledgerId: ledgers[index] },
    upperBoundMs: index === 0 ? null : String(times[index] + 1100),
  }));
  const result = {
    ackObserved: true, deadlineMs: String(times[0] + 600000), localVerdict: "LOCAL_OK", paymentMoved: false,
    poolHealth: { degradedAtSubmission: true, nodeParticipationPct: "0.0", totalNodes: "1.0" },
    promptSha256: "ef".repeat(32), protocolVersion: "1",
    rendezvous: { channel: "derived-reference-id", degradedAtSubmission: true, tenancy: "cross-client" },
    repositorySha: REPOSITORY_SHA, role: "payer", schema: PARTY_RESULT_SCHEMA, sessionDigest,
    signature: { address: account.address.toLowerCase(), algorithm: "eip191", signature: `0x${"00".repeat(65)}` },
    transitions,
  };
  result.signature.signature = await account.signMessage({
    message: { raw: partySignatureBytes({
      role: result.role,
      sessionDigest: result.sessionDigest,
      transitions: result.transitions,
    }) },
  });
  const directory = await mkdtemp(join(tmpdir(), "relay-party-package-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await writePartyResult({ directory, result });
  return relayPackage([
    [".party-result.complete.json", await readFile(join(directory, ".party-result.complete.json"))],
    ["PARTY-RESULT.md", await readFile(join(directory, "PARTY-RESULT.md"))],
    ["party-result.json", await readFile(join(directory, "party-result.json"))],
  ]);
}

test("rejects structurally incomplete party-result packages", async () => {
  const bytes = partyPackage();
  await assert.rejects(
    async () =>
      await validateRelayArtifact({
        artifactType: "party-result-package",
        bytes,
        expectedDigest: sha256(bytes),
        secretCanaries: [],
      }),
    { code: "RELAY_ARTIFACT_INVALID" },
  );
});

test("validates producer-written party result packages and signer recovery", async (t) => {
  const bytes = await producerPartyPackage(t);
  await assert.doesNotReject(validateRelayArtifact({
    artifactType: "party-result-package", bytes, expectedDigest: sha256(bytes), secretCanaries: [],
  }));
  const mutated = JSON.parse(bytes.toString("utf8"));
  const json = mutated.files.find((file) => file.name === "party-result.json");
  const party = JSON.parse(Buffer.from(json.contentBase64, "base64").toString("utf8"));
  party.signature.signature = `0x${"00".repeat(65)}`;
  const partyBytes = Buffer.from(`${JSON.stringify(party, null, 2)}\n`);
  json.byteLength = String(partyBytes.length);
  json.contentBase64 = partyBytes.toString("base64");
  json.sha256 = sha256(partyBytes);
  const markdown = mutated.files.find((file) => file.name === "PARTY-RESULT.md");
  const markdownBytes = Buffer.from(renderPartyResultMarkdown(party));
  markdown.byteLength = String(markdownBytes.length);
  markdown.contentBase64 = markdownBytes.toString("base64");
  markdown.sha256 = sha256(markdownBytes);
  const marker = mutated.files.find((file) => file.name === ".party-result.complete.json");
  const markerValue = JSON.parse(Buffer.from(marker.contentBase64, "base64").toString("utf8"));
  markerValue.jsonSha256 = json.sha256;
  markerValue.markdownSha256 = markdown.sha256;
  const markerBytes = Buffer.from(
    `${canonicalBytes(markerValue).toString("utf8")}\n`,
  );
  marker.byteLength = String(markerBytes.length);
  marker.contentBase64 = markerBytes.toString("base64");
  marker.sha256 = sha256(markerBytes);
  const hostile = stableBytes(mutated);
  await assert.rejects(validateRelayArtifact({
    artifactType: "party-result-package", bytes: hostile, expectedDigest: sha256(hostile), secretCanaries: [],
  }), { code: "RELAY_ARTIFACT_INVALID" });

  const highS = JSON.parse(bytes.toString("utf8"));
  const highSJson = highS.files.find((file) => file.name === "party-result.json");
  const highSParty = JSON.parse(Buffer.from(highSJson.contentBase64, "base64").toString("utf8"));
  const signature = highSParty.signature.signature;
  const order = BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
  const s = BigInt(`0x${signature.slice(66, 130)}`);
  highSParty.signature.signature = `0x${signature.slice(2, 66)}${(order - s).toString(16).padStart(64, "0")}${signature.slice(130) === "1b" ? "1c" : "1b"}`;
  const highSBytes = Buffer.from(`${JSON.stringify(highSParty, null, 2)}\n`);
  highSJson.byteLength = String(highSBytes.length);
  highSJson.contentBase64 = highSBytes.toString("base64");
  highSJson.sha256 = sha256(highSBytes);
  const highSMarkdown = highS.files.find((file) => file.name === "PARTY-RESULT.md");
  const highSMarkdownBytes = Buffer.from(renderPartyResultMarkdown(highSParty));
  highSMarkdown.byteLength = String(highSMarkdownBytes.length);
  highSMarkdown.contentBase64 = highSMarkdownBytes.toString("base64");
  highSMarkdown.sha256 = sha256(highSMarkdownBytes);
  assert.equal((await recoverMessageAddress({
    message: { raw: partySignatureBytes({
      role: highSParty.role,
      sessionDigest: highSParty.sessionDigest,
      transitions: highSParty.transitions,
    }) },
    signature: highSParty.signature.signature,
  })).toLowerCase(), highSParty.signature.address.toLowerCase());
  const highSMarker = highS.files.find((file) => file.name === ".party-result.complete.json");
  const highSMarkerValue = JSON.parse(Buffer.from(highSMarker.contentBase64, "base64").toString("utf8"));
  highSMarkerValue.jsonSha256 = highSJson.sha256;
  highSMarkerValue.markdownSha256 = highSMarkdown.sha256;
  const highSMarkerBytes = Buffer.from(`${canonicalBytes(highSMarkerValue).toString("utf8")}\n`);
  highSMarker.byteLength = String(highSMarkerBytes.length);
  highSMarker.contentBase64 = highSMarkerBytes.toString("base64");
  highSMarker.sha256 = sha256(highSMarkerBytes);
  const highSArtifact = stableBytes(highS);
  await assert.rejects(validateRelayArtifact({
    artifactType: "party-result-package", bytes: highSArtifact,
    expectedDigest: sha256(highSArtifact), secretCanaries: [],
  }), { code: "RELAY_ARTIFACT_INVALID" });
});

test("rejects incomplete, mismatched, unknown-file, and oversized packages", async () => {
  const cases = [
    partyPackage({ includeMarker: false }),
    partyPackage({ markerDigest: "e".repeat(64) }),
    partyPackage({ markerExtra: true }),
    partyPackage({ extraFile: true }),
    partyPackage({
      namesTransform(files) {
        return [files[1], files[0], files[2]];
      },
    }),
    partyPackage({
      namesTransform(files) {
        return [files[0], files[1], files[1]];
      },
    }),
    partyPackage({
      contentTransform(entry, index) {
        return index === 1
          ? { ...entry, byteLength: String(Number(entry.byteLength) + 1) }
          : entry;
      },
    }),
    partyPackage({
      contentTransform(entry, index) {
        return index === 1
          ? { ...entry, sha256: "0".repeat(64) }
          : entry;
      },
    }),
    partyPackage({
      contentTransform(entry, index) {
        return index === 1
          ? { ...entry, contentBase64: `${entry.contentBase64.slice(0, -2)}A=` }
          : entry;
      },
    }),
    Buffer.alloc(MAX_RELAY_PACKAGE_BYTES + 1, 0x61),
  ];
  for (const bytes of cases) {
    await assert.rejects(
      async () =>
        await validateRelayArtifact({
          artifactType: "party-result-package",
          bytes,
          expectedDigest: sha256(bytes),
          secretCanaries: [],
        }),
      { code: "RELAY_ARTIFACT_INVALID" },
    );
  }
});

test("rejects nested-only paymentMoved and package tar, token, or private-key content", async () => {
  const nestedOnly = stableBytes({
    payload: { paymentMoved: false },
    schema: "clockchain.bilateral-coordination-enrollment/v1",
  });
  await assert.rejects(
    async () =>
      await validateRelayArtifact({
        artifactType: "coordination-enrollment",
        bytes: nestedOnly,
        expectedDigest: sha256(nestedOnly),
        secretCanaries: [],
      }),
    { code: "RELAY_ARTIFACT_INVALID" },
  );

  for (const payload of [
    Buffer.concat([
      Buffer.alloc(257),
      Buffer.from("ustar"),
      Buffer.alloc(8),
    ]),
    Buffer.from("Bearer cc_abcdefghijklmnopqrstuvwxyz"),
    Buffer.from(
      "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----",
    ),
  ]) {
    const bytes = partyPackage({
      markdownPayload: payload,
    });
    await assert.rejects(
      async () =>
        await validateRelayArtifact({
          artifactType: "party-result-package",
          bytes,
          expectedDigest: sha256(bytes),
          secretCanaries: [],
        }),
      { code: "RELAY_ARTIFACT_INVALID" },
    );
  }
});

test("rejects oversized identity packages before parsing", async () => {
  const baseIdentity = {
    padding: "",
    paymentMoved: false,
    schema:
      "clockchain.bilateral-identity-registration/v1",
  };
  const baseLength = stableBytes(baseIdentity).length;
  const identity = stableBytes({
    ...baseIdentity,
    padding: "a".repeat(32_769 - baseLength),
  });
  assert.equal(identity.length, 32_769);
  const marker = stableBytes({
    fileSha256: sha256(identity),
    schema:
      "clockchain.bilateral-identity-registration-completion/v1",
  });
  const bytes = stableBytes({
    files: [
      [".identity.complete.json", marker],
      ["identity.json", identity],
    ].map(([name, content]) => ({
      byteLength: String(content.length),
      contentBase64: content.toString("base64"),
      name,
      sha256: sha256(content),
    })),
    paymentMoved: false,
    schema: RELAY_PACKAGE_SCHEMA,
  });
  await assert.rejects(
    async () =>
      await validateRelayArtifact({
        artifactType: "identity-package",
        bytes,
        expectedDigest: sha256(bytes),
        secretCanaries: [],
      }),
    { code: "RELAY_ARTIFACT_INVALID" },
  );
});

function recoveryManifest({
  command = "scripts/probe-bilateral-rendezvous.mjs",
  role = "payer",
  subjectRun = "release",
  reasonCode = "AMBIGUOUS_WRITE",
  arguments: argv,
} = {}) {
  const paths = ["/state/plan.json", "/state/token", "/state/private", "/state/output"];
  const argumentsForCommand = argv ?? (command === "scripts/probe-bilateral-rendezvous.mjs"
    ? ["participant", "--role", role, "--plan", paths[0], "--token-file", paths[1], "--participant-private-key", paths[2], "--output", paths[3]]
    : command === "scripts/register-bilateral-identity.mjs"
      ? ["--invitation", paths[0], "--output", paths[1], "--repository-sha", REPOSITORY_SHA, "--i-understand-this-writes-to-sepolia"]
      : ["--clockchain-token-file", paths[0], "--descriptor", paths[1], "--invitation", paths[2], "--output", paths[3], "--i-understand-this-writes-to-clockchain"]);
  return stableBytes({
    arguments: argumentsForCommand, command, paymentMoved: false, reasonCode,
    releaseId: RELEASE_ID, repositorySha: REPOSITORY_SHA, role,
    schema: "clockchain.bilateral-recovery-command-manifest/v1", sessionId: SESSION_ID,
    subjectRun,
  });
}

test("validates exact recovery manifests and terminal failure summaries", async () => {
  const recovery = recoveryManifest();
  const failure = stableBytes({
    eventKind: "TERMINAL_FAILURE",
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    role: "payer",
    schema: "clockchain.bilateral-failure-summary/v1",
    sessionId: SESSION_ID,
    subjectRun: "rehearsal",
    terminalCode: "FAILED",
  });
  for (const [artifactType, bytes] of [
    ["recovery-command-manifest", recovery],
    ["failure-summary", failure],
  ]) {
    assert.deepEqual(
      await validateRelayArtifact({
        artifactType,
        bytes,
        expectedDigest: sha256(bytes),
        secretCanaries: [],
      }),
      {
        artifactType,
        byteLength: String(bytes.length),
        digest: sha256(bytes),
      },
    );
  }
  for (const releaseId of [" release", "release ", "", "\nrelease"]) {
    const bytes = stableBytes({
      eventKind: "TERMINAL_FAILURE", paymentMoved: false, releaseId,
      repositorySha: REPOSITORY_SHA, role: "payer",
      schema: "clockchain.bilateral-failure-summary/v1", sessionId: SESSION_ID,
      subjectRun: "rehearsal", terminalCode: "FAILED",
    });
    await assert.rejects(validateRelayArtifact({
      artifactType: "failure-summary", bytes, expectedDigest: sha256(bytes), secretCanaries: [],
    }), { code: "RELAY_ARTIFACT_INVALID" });
  }
  for (const bytes of [
    recoveryManifest(),
    recoveryManifest({ command: "scripts/register-bilateral-identity.mjs", role: "payee", subjectRun: "rehearsal" }),
    recoveryManifest({ command: "bin/handshake-propose.mjs", role: "payer", subjectRun: "stakeholder" }),
    recoveryManifest({ command: "bin/handshake-accept.mjs", role: "payee", subjectRun: "stakeholder" }),
  ]) {
    await assert.doesNotReject(validateRelayArtifact({
      artifactType: "recovery-command-manifest", bytes, expectedDigest: sha256(bytes), secretCanaries: [],
    }));
  }
  for (const bytes of [
    recoveryManifest({ reasonCode: "FAILED" }),
    recoveryManifest({ subjectRun: "rehearsal" }),
    recoveryManifest({ command: "scripts/register-bilateral-identity.mjs", subjectRun: "release" }),
    recoveryManifest({ command: "bin/handshake-propose.mjs", role: "payee", subjectRun: "rehearsal" }),
    recoveryManifest({ command: "bin/handshake-accept.mjs", role: "payer", subjectRun: "rehearsal" }),
    recoveryManifest({ arguments: ["participant", "--role", "payer"] }),
    recoveryManifest({ arguments: ["participant", "--role", "payer", "--role", "payer", "--plan", "/state/plan.json", "--token-file", "/state/token", "--participant-private-key", "/state/private", "--output", "/state/output"] }),
    recoveryManifest({ arguments: ["participant", "--plan", "/state/plan.json", "--role", "payer", "--token-file", "/state/token", "--participant-private-key", "/state/private", "--output", "/state/output"] }),
    recoveryManifest({ arguments: ["participant", "--role", "payer", "--plan", "relative", "--token-file", "/state/token", "--participant-private-key", "/state/private", "--output", "/state/output"] }),
    recoveryManifest({ arguments: ["participant", "--role", "payee", "--plan", "/state/plan.json", "--token-file", "/state/token", "--participant-private-key", "/state/private", "--output", "/state/output"] }),
    recoveryManifest({ arguments: ["participant", "--role", "payer", "--plan", "/state/plan.json", "--token-file", "/state/token", "--participant-private-key", "/state/token", "--output", "/state/output"] }),
    recoveryManifest({ command: "scripts/register-bilateral-identity.mjs", role: "payer", subjectRun: "rehearsal", arguments: ["--invitation", "/state/invitation", "--output", "/state/output", "--repository-sha", "a".repeat(40), "--i-understand-this-writes-to-sepolia"] }),
    recoveryManifest({ arguments: ["participant", "--role", "payer", "--plan", "/state/plan.json", "--token-file", "/state/token", "--participant-private-key", "/state/private", "--output", "/state/output", "--extra"] }),
  ]) {
    await assert.rejects(validateRelayArtifact({
      artifactType: "recovery-command-manifest", bytes, expectedDigest: sha256(bytes), secretCanaries: [],
    }), { code: "RELAY_ARTIFACT_INVALID" });
  }
});

test("identity packages bind the frozen registration artifact shape", async () => {
  const identity = {
    address: `0x${"1".repeat(40)}`,
    agentId: "7",
    chainId: "11155111",
    displayName: "Iris",
    identityReference: "eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:7",
    metadata: { blockHeight: "2", transactionHash: `0x${"2".repeat(64)}` },
    paymentMoved: false,
    register: { blockHeight: "1", transactionHash: `0x${"3".repeat(64)}` },
    registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
    repositorySha: REPOSITORY_SHA,
    schema: "clockchain.bilateral-identity-registration/v1",
  };
  const identityBytes = stableBytes(identity);
  const marker = stableBytes({
    fileSha256: sha256(identityBytes),
    schema: "clockchain.bilateral-identity-registration-completion/v1",
  });
  const packageBytes = stableBytes({
    files: [[".identity.complete.json", marker], ["identity.json", identityBytes]].map(([name, content]) => ({
      byteLength: String(content.length), contentBase64: content.toString("base64"), name, sha256: sha256(content),
    })), paymentMoved: false, schema: RELAY_PACKAGE_SCHEMA,
  });
  await assert.doesNotReject(validateRelayArtifact({ artifactType: "identity-package", bytes: packageBytes, expectedDigest: sha256(packageBytes), secretCanaries: [] }));
  const producerCompatible = {
    ...identity,
    displayName: "Íris",
    metadata: { blockHeight: "2", transactionHash: `0x${"A".repeat(64)}` },
  };
  const producerCompatibleBytes = stableBytes(producerCompatible);
  const producerCompatibleMarker = stableBytes({
    fileSha256: sha256(producerCompatibleBytes),
    schema: "clockchain.bilateral-identity-registration-completion/v1",
  });
  const producerCompatiblePackage = relayPackage([
    [".identity.complete.json", producerCompatibleMarker],
    ["identity.json", producerCompatibleBytes],
  ]);
  await assert.doesNotReject(validateRelayArtifact({ artifactType: "identity-package", bytes: producerCompatiblePackage, expectedDigest: sha256(producerCompatiblePackage), secretCanaries: [] }));
  const hostile = { ...identity, chainId: "1" };
  const hostileIdentityBytes = stableBytes(hostile);
  const hostileMarker = stableBytes({ fileSha256: sha256(hostileIdentityBytes), schema: "clockchain.bilateral-identity-registration-completion/v1" });
  const hostileBytes = stableBytes({
    files: [[".identity.complete.json", hostileMarker], ["identity.json", hostileIdentityBytes]].map(([name, content]) => ({
      byteLength: String(content.length), contentBase64: content.toString("base64"), name, sha256: sha256(content),
    })), paymentMoved: false, schema: RELAY_PACKAGE_SCHEMA,
  });
  await assert.rejects(async () => await validateRelayArtifact({ artifactType: "identity-package", bytes: hostileBytes, expectedDigest: sha256(hostileBytes), secretCanaries: [] }), { code: "RELAY_ARTIFACT_INVALID" });
  for (const displayName of [" Iris", "Iris ", "Iris\n"]) {
    const invalidIdentity = { ...identity, displayName };
    const invalidIdentityBytes = stableBytes(invalidIdentity);
    const invalidIdentityMarker = stableBytes({ fileSha256: sha256(invalidIdentityBytes), schema: "clockchain.bilateral-identity-registration-completion/v1" });
    const invalidIdentityPackage = relayPackage([[".identity.complete.json", invalidIdentityMarker], ["identity.json", invalidIdentityBytes]]);
    await assert.rejects(validateRelayArtifact({ artifactType: "identity-package", bytes: invalidIdentityPackage, expectedDigest: sha256(invalidIdentityPackage), secretCanaries: [] }), { code: "RELAY_ARTIFACT_INVALID" });
  }
});

test("accepts a self-signed exact preflight plan envelope", async () => {
  const operator = generateKeyPairSync("ed25519");
  const plan = {
    digests: { payee: "b".repeat(64), payer: "a".repeat(64) },
    keys: {
      payee: probeKey("0123456789abcdef0123456789abcdef", "payee"),
      payer: probeKey("0123456789abcdef0123456789abcdef", "payer"),
    },
    nonce: "0123456789abcdef0123456789abcdef",
    participants: {
      payee: {
        coordinationPublicKey: PAYEE_PUBLIC_KEY,
        publicKey: PAYEE_PREFLIGHT_PUBLIC_KEY,
        tokenCommitment: tokenCommitmentArtifact({
          coordinationPublicKey: PAYEE_PUBLIC_KEY,
          privateKeyPem: payeeKeyPair.privateKey,
          role: "payee",
        }),
      },
      payer: {
        coordinationPublicKey: PUBLIC_KEY,
        publicKey: PREFLIGHT_PUBLIC_KEY,
        tokenCommitment: tokenCommitmentArtifact(),
      },
    },
    paymentMoved: false,
    protocol: "clockchain.bilateral-authorization/v1",
    protocolVersion: "1",
    repositorySha: REPOSITORY_SHA,
    schema: "clockchain.bilateral-preflight-plan/v1",
    writeBudget: "2",
  };
  const operatorPublicKey = operator.publicKey
    .export({ format: "der", type: "spki" })
    .subarray(-32)
    .toString("base64");
  const bytes = stableBytes({
    operator: {
      algorithm: "ed25519",
      keyId: "storage-test-operator",
      publicKey: operatorPublicKey,
      signature: sign(null, canonicalBytes(plan), operator.privateKey)
        .toString("base64"),
    },
    plan,
  });
  await assert.doesNotReject(validateRelayArtifact({
    artifactType: "preflight-plan",
    bytes,
    expectedDigest: sha256(bytes),
    secretCanaries: [],
  }));
  const reusedKeyPlan = structuredClone(plan);
  reusedKeyPlan.participants.payee.publicKey =
    reusedKeyPlan.participants.payer.coordinationPublicKey;
  const reusedKeyBytes = stableBytes({
    operator: {
      algorithm: "ed25519", keyId: "storage-test-operator", publicKey: operatorPublicKey,
      signature: sign(null, canonicalBytes(reusedKeyPlan), operator.privateKey).toString("base64"),
    },
    plan: reusedKeyPlan,
  });
  await assert.rejects(validateRelayArtifact({
    artifactType: "preflight-plan", bytes: reusedKeyBytes,
    expectedDigest: sha256(reusedKeyBytes), secretCanaries: [],
  }), { code: "RELAY_ARTIFACT_INVALID" });
  const operatorReusedPlan = structuredClone(plan);
  operatorReusedPlan.participants.payer.publicKey = operatorPublicKey;
  const operatorReusedBytes = stableBytes({
    operator: {
      algorithm: "ed25519", keyId: "storage-test-operator", publicKey: operatorPublicKey,
      signature: sign(null, canonicalBytes(operatorReusedPlan), operator.privateKey).toString("base64"),
    },
    plan: operatorReusedPlan,
  });
  await assert.rejects(validateRelayArtifact({
    artifactType: "preflight-plan", bytes: operatorReusedBytes,
    expectedDigest: sha256(operatorReusedBytes), secretCanaries: [],
  }), { code: "RELAY_ARTIFACT_INVALID" });
  const aliasPlan = JSON.parse(bytes.toString("utf8"));
  const canonicalSignature = aliasPlan.operator.signature;
  aliasPlan.operator.signature = base64PadBitAlias(canonicalSignature);
  assert.deepEqual(
    Buffer.from(aliasPlan.operator.signature, "base64"),
    Buffer.from(canonicalSignature, "base64"),
  );
  const aliasPlanBytes = stableBytes(aliasPlan);
  await assert.rejects(validateRelayArtifact({
    artifactType: "preflight-plan", bytes: aliasPlanBytes,
    expectedDigest: sha256(aliasPlanBytes), secretCanaries: [],
  }), { code: "RELAY_ARTIFACT_INVALID" });
});

function relayPackage(files) {
  return stableBytes({
    files: files.map(([name, content]) => ({
      byteLength: String(content.length),
      contentBase64: content.toString("base64"),
      name,
      sha256: sha256(content),
    })),
    paymentMoved: false,
    schema: RELAY_PACKAGE_SCHEMA,
  });
}

function preflightAnchor({ digest, key, ledgerId, blockHeight }) {
  return {
    anchoredHash: digest,
    assetReferenceId: key,
    blockHeight,
    ledgerId,
  };
}

function preflightReportFixtures() {
  const nonce = "0123456789abcdef0123456789abcdef";
  const payer = {
    digest: "a".repeat(64),
    key: probeKey(nonce, "payer"),
    ledgerId: "8f953393-86d0-4f99-9d6a-102f525fbecd",
    role: "payer",
  };
  const payee = {
    digest: "b".repeat(64),
    key: probeKey(nonce, "payee"),
    ledgerId: "9f953393-86d0-4f99-9d6a-102f525fbecd",
    role: "payee",
  };
  payer.write = preflightAnchor({ ...payer, blockHeight: "7" });
  payee.write = preflightAnchor({ ...payee, blockHeight: "8" });
  const observationFor = (peer) => ({
    conflict: false,
    digestAnchor: peer.write,
    digestResolved: true,
    finalAnchor: peer.write,
    finalVerified: true,
    peer: peer.role,
    referenceAnchor: peer.write,
    referenceResolved: true,
  });
  const participant = (self, peer) => {
    const report = {
      channel: "derived-reference-id",
      completedAtMs: "120000",
      deadlineAtMs: "120000",
      observations: [{
        channel: "ledger-height",
        code: "PREFLIGHT_READ_FAILED",
        observer: self.role,
      }],
      paymentMoved: false,
      peerObservation: observationFor(peer),
      planDigest: "d".repeat(64),
      rateLimits: [{
        channel: "digest-hash",
        code: "MCP_RATE_LIMIT",
        observer: self.role,
        retryAfterMs: "0",
        wireShape: "http-429",
      }],
      repositorySha: REPOSITORY_SHA,
      role: self.role,
      schema: "clockchain.bilateral-preflight-participant/v1",
      serializedCadenceMs: "20000",
      sleeps: ["20000"],
      startedAtMs: "100000",
      tokenCommitment: tokenCommitmentArtifact({
        coordinationPublicKey: self.role === "payer" ? PUBLIC_KEY : PAYEE_PUBLIC_KEY,
        privateKeyPem: self.role === "payer" ? PRIVATE_KEY_PEM : payeeKeyPair.privateKey,
        role: self.role,
      }),
      write: { ...self.write, digest: self.digest, key: self.key, role: self.role },
    };
    return {
      report,
      signature: {
      algorithm: "ed25519",
      role: self.role,
      value: sign(null, canonicalBytes(report), self.role === "payer" ? preflightKeyPair.privateKey : payeePreflightKeyPair.privateKey).toString("base64"),
    },
    };
  };
  const participantEnvelope = participant(payer, payee);
  const participantBytes = stableBytes(participantEnvelope);
  const participantMarker = stableBytes({
    fileSha256: sha256(participantBytes),
    schema: "clockchain.bilateral-preflight-participant-completion/v1",
  });
  const aggregateReport = {
      channel: "derived-reference-id",
      completedAtMs: "120001",
      directions: [
        { observer: "payer", peer: "payee", ...observationFor(payee) },
        { observer: "payee", peer: "payer", ...observationFor(payer) },
      ],
      outcome: "RENDEZVOUS_OK",
      paymentMoved: false,
      planDigest: "d".repeat(64),
      protocol: "clockchain.bilateral-authorization/v1",
      protocolVersion: "1",
      repositorySha: REPOSITORY_SHA,
      schema: "clockchain.bilateral-preflight/v2",
      scope: {
        separateCredentialsAttested: true,
        separateMachinesAttested: true,
      },
      tenancy: "cross-client",
      writes: [
        { ...payer.write, digest: payer.digest, key: payer.key, role: "payer" },
        { ...payee.write, digest: payee.digest, key: payee.key, role: "payee" },
      ],
  };
  const aggregateEnvelope = {
    report: aggregateReport,
    signature: {
      algorithm: "ed25519",
      keyId: "storage-test-operator",
      value: sign(null, canonicalBytes(aggregateReport), keyPair.privateKey).toString("base64"),
    },
  };
  const aggregateBytes = stableBytes(aggregateEnvelope);
  const aggregateMarker = stableBytes({
    fileSha256: sha256(aggregateBytes),
    schema: "clockchain.bilateral-preflight-completion/v1",
  });
  return {
    aggregate: relayPackage([
      [".preflight-report.complete.json", aggregateMarker],
      ["preflight-report.json", aggregateBytes],
    ]),
    participant: relayPackage([
      [".participant-report.complete.json", participantMarker],
      ["participant-report.json", participantBytes],
    ]),
  };
}

function resignPreflightEnvelope(envelope) {
  const privateKey = envelope.signature.role === "payer"
    ? preflightKeyPair.privateKey
    : envelope.signature.role === "payee"
      ? payeePreflightKeyPair.privateKey
      : keyPair.privateKey;
  envelope.signature.value = sign(null, canonicalBytes(envelope.report), privateKey)
    .toString("base64");
}

function mutatePreflightPackage(bytes, mutate, { resign = false } = {}) {
  const packageValue = JSON.parse(bytes.toString("utf8"));
  const [marker, report] = packageValue.files;
  const envelope = JSON.parse(
    Buffer.from(report.contentBase64, "base64").toString("utf8"),
  );
  mutate(envelope, packageValue);
  if (resign) resignPreflightEnvelope(envelope);
  const reportBytes = stableBytes(envelope);
  const markerValue = JSON.parse(
    Buffer.from(marker.contentBase64, "base64").toString("utf8"),
  );
  markerValue.fileSha256 = sha256(reportBytes);
  const markerBytes = stableBytes(markerValue);
  return relayPackage([
    [marker.name, markerBytes],
    [report.name, reportBytes],
  ]);
}

test("validates exact canonical preflight participant and aggregate report packages", async () => {
  const fixtures = preflightReportFixtures();
  for (const [artifactType, bytes] of [
    ["preflight-participant-report", fixtures.participant],
    ["preflight-aggregate-report", fixtures.aggregate],
  ]) {
    await assert.doesNotReject(validateRelayArtifact({
      artifactType,
      bytes,
      expectedDigest: sha256(bytes),
      secretCanaries: [],
    }), artifactType);
  }

  const completedAfterDeadline = mutatePreflightPackage(
    fixtures.participant,
    (envelope) => {
      envelope.report.completedAtMs = "130000";
      envelope.report.sleeps = ["1"];
    },
    { resign: true },
  );
  await assert.doesNotReject(validateRelayArtifact({
    artifactType: "preflight-participant-report",
    bytes: completedAfterDeadline,
    expectedDigest: sha256(completedAfterDeadline),
    secretCanaries: [],
  }));

  const conflictAfterFinalVerification = mutatePreflightPackage(
    fixtures.participant,
    (envelope) => {
      envelope.report.peerObservation.conflict = true;
      envelope.report.peerObservation.referenceAnchor = {
        ...envelope.report.peerObservation.referenceAnchor,
        blockHeight: "9",
      };
    },
    { resign: true },
  );
  await assert.doesNotReject(validateRelayArtifact({
    artifactType: "preflight-participant-report",
    bytes: conflictAfterFinalVerification,
    expectedDigest: sha256(conflictAfterFinalVerification),
    secretCanaries: [],
  }));

  const unresolvedFinalAggregate = mutatePreflightPackage(
    fixtures.aggregate,
    (envelope) => {
      envelope.report.channel = "mixed";
      envelope.report.outcome = "RENDEZVOUS_UNAVAILABLE";
      envelope.report.directions[1].finalVerified = false;
      envelope.report.directions[1].finalAnchor = null;
    },
    { resign: true },
  );
  await assert.doesNotReject(validateRelayArtifact({
    artifactType: "preflight-aggregate-report",
    bytes: unresolvedFinalAggregate,
    expectedDigest: sha256(unresolvedFinalAggregate),
    secretCanaries: [],
  }));
});

test("rejects hostile preflight report package semantics with fixed errors", async () => {
  const fixtures = preflightReportFixtures();
  const hostile = [
    ["preflight-participant-report", fixtures.participant, (envelope) => {
      envelope.report.channel = "unavailable";
    }],
    ["preflight-participant-report", fixtures.participant, (envelope) => {
      envelope.report.serializedCadenceMs = "1";
    }],
    ["preflight-participant-report", fixtures.participant, (envelope) => {
      envelope.report.peerObservation.finalAnchor = null;
    }],
    ["preflight-participant-report", fixtures.participant, (envelope) => {
      envelope.report.peerObservation.conflict = true;
    }],
    ["preflight-participant-report", fixtures.participant, (envelope) => {
      envelope.report.peerObservation.finalAnchor = { ...envelope.report.peerObservation.finalAnchor, blockHeight: "99" };
    }],
    ["preflight-participant-report", fixtures.participant, (envelope) => {
      envelope.report.write.assetReferenceId = "wrong";
    }],
    ["preflight-participant-report", fixtures.participant, (envelope) => {
      envelope.report.observations[0].code = "OTHER";
    }],
    ["preflight-participant-report", fixtures.participant, (envelope) => {
      envelope.report.rateLimits[0].wireShape = "typed-rate-limit";
    }],
    ["preflight-participant-report", fixtures.participant, (envelope) => {
      envelope.signature.role = "payee";
    }],
    ["preflight-aggregate-report", fixtures.aggregate, (envelope) => {
      envelope.report.directions.reverse();
    }],
    ["preflight-aggregate-report", fixtures.aggregate, (envelope) => {
      envelope.report.writes[1] = { ...envelope.report.writes[0], role: "payee" };
    }],
    ["preflight-aggregate-report", fixtures.aggregate, (envelope) => {
      envelope.report.writes[1] = {
        ...envelope.report.writes[1],
        ledgerId: envelope.report.writes[0].ledgerId,
        blockHeight: envelope.report.writes[0].blockHeight,
      };
    }],
    ["preflight-aggregate-report", fixtures.aggregate, (envelope) => {
      envelope.report.scope.separateMachinesAttested = false;
    }],
    ["preflight-aggregate-report", fixtures.aggregate, (envelope) => {
      envelope.report.directions[0].finalAnchor = null;
    }],
    ["preflight-aggregate-report", fixtures.aggregate, (envelope) => {
      envelope.signature.keyId = "not valid";
    }],
    ["preflight-aggregate-report", fixtures.aggregate, (envelope) => {
      envelope.report.unexpected = false;
    }],
  ];
  for (const [artifactType, original, mutate] of hostile) {
    const bytes = mutatePreflightPackage(original, mutate);
    await assert.rejects(
      async () => await validateRelayArtifact({
        artifactType,
        bytes,
        expectedDigest: sha256(bytes),
        secretCanaries: [],
      }),
      { code: "RELAY_ARTIFACT_INVALID" },
    );
  }
  for (const [artifactType, original] of [
    ["preflight-participant-report", fixtures.participant],
    ["preflight-aggregate-report", fixtures.aggregate],
  ]) {
    const bytes = mutatePreflightPackage(original, (envelope) => {
      const canonicalSignature = envelope.signature.value;
      envelope.signature.value = base64PadBitAlias(canonicalSignature);
      assert.deepEqual(
        Buffer.from(envelope.signature.value, "base64"),
        Buffer.from(canonicalSignature, "base64"),
      );
    });
    await assert.rejects(validateRelayArtifact({
      artifactType, bytes, expectedDigest: sha256(bytes), secretCanaries: [],
    }), { code: "RELAY_ARTIFACT_INVALID" });
  }
});

test("opens only an exact private nonsymlink state root", async (t) => {
  const nonPrivate = await privateRoot(t);
  await chmod(nonPrivate, 0o755);
  await assert.rejects(
    openCoordinationStore({
      repositorySha: REPOSITORY_SHA,
      root: nonPrivate,
    }),
    { code: "COORDINATION_STORAGE_INVALID" },
  );

  const target = await privateRoot(t);
  const link = `${target}-link`;
  await symlink(target, link);
  t.after(() => unlink(link).catch(() => {}));
  await assert.rejects(
    openCoordinationStore({
      repositorySha: REPOSITORY_SHA,
      root: link,
    }),
    { code: "COORDINATION_STORAGE_INVALID" },
  );
});

test("rejects unknown reused state and creates private metadata", async (t) => {
  const reused = await privateRoot(t);
  await writeFile(join(reused, "foreign"), "x", {
    mode: 0o600,
  });
  await assert.rejects(
    openCoordinationStore({
      repositorySha: REPOSITORY_SHA,
      root: reused,
    }),
    { code: "COORDINATION_STORAGE_INVALID" },
  );

  const { root, store } = await storeFixture(t);
  await register(store);
  for (const entry of await readdir(root)) {
    const metadata = await lstat(join(root, entry));
    if (metadata.isFile()) {
      assert.equal(metadata.mode & 0o777, 0o600);
      assert.equal(metadata.isSymbolicLink(), false);
    }
  }
});

test("rejects unknown or content-mismatched entries in a reused artifact tree", async (t) => {
  const unknownRoot = await privateRoot(t);
  const initial = await openCoordinationStore({
    repositorySha: REPOSITORY_SHA,
    root: unknownRoot,
  });
  await initial.close();
  await mkdir(join(unknownRoot, "artifacts", "zz"), {
    mode: 0o700,
  });
  await assert.rejects(
    openCoordinationStore({
      repositorySha: REPOSITORY_SHA,
      root: unknownRoot,
    }),
    { code: "COORDINATION_STORAGE_INVALID" },
  );

  const corruptRoot = await privateRoot(t);
  const store = await openCoordinationStore({
    repositorySha: REPOSITORY_SHA,
    root: corruptRoot,
  });
  const bytes = signedDescriptorBytes();
  const digest = sha256(bytes);
  await store.putArtifact({
    artifactType: "signed-descriptor",
    bytes,
    expectedDigest: digest,
    secretCanaries: [],
  });
  await store.close();
  await writeFile(
    join(
      corruptRoot,
      "artifacts",
      digest.slice(0, 2),
      digest,
    ),
    Buffer.from("replacement"),
    { mode: 0o600 },
  );
  await assert.rejects(
    openCoordinationStore({
      repositorySha: REPOSITORY_SHA,
      root: corruptRoot,
    }),
    { code: "COORDINATION_STORAGE_INVALID" },
  );
});

test("recovers only an exact pinned owner record whose PID is definitively dead", async (t) => {
  const root = await privateRoot(t);
  const first = await openCoordinationStore({
    repositorySha: REPOSITORY_SHA,
    root,
  });
  await first.close();
  const ownerPath = join(root, ".store-owner.json");
  await writeFile(
    ownerPath,
    stableBytes({
      pid: "99999999",
      schema: "clockchain.bilateral-store-owner/v1",
    }),
    { flag: "wx", mode: 0o600 },
  );
  const recovered = await openCoordinationStore({
    repositorySha: REPOSITORY_SHA,
    root,
  });
  await recovered.close();

  await writeFile(
    ownerPath,
    stableBytes({
      pid: String(process.pid),
      schema: "clockchain.bilateral-store-owner/v1",
    }),
    { flag: "wx", mode: 0o600 },
  );
  await assert.rejects(
    openCoordinationStore({
      repositorySha: REPOSITORY_SHA,
      root,
    }),
    { code: "COORDINATION_STORAGE_INVALID" },
  );
  await unlink(ownerPath);
});

test("consumes a scoped capability once and returns an identical retry", async (t) => {
  const { store } = await storeFixture(t);
  await register(store);
  const input = consumeInput({ scoped: true });
  const first = await store.consumeCapability(input);
  const retry = await store.consumeCapability(input);
  assert.deepEqual(retry, first);
  assert.deepEqual(first.receiptBytes, RECEIPT_BYTES);
  assert.deepEqual(
    first.enrollmentBytes,
    enrollmentBytes(),
  );
  assert.equal(first.capabilityDigest, sha256(RAW_CAPABILITY));
  assert.equal(
    first.enrollmentDigest,
    sha256(enrollmentBytes()),
  );
  assert.equal(
    Object.hasOwn(first, "capability"),
    false,
  );
});

test("atomically persists enrollment and invokes a randomized receipt factory once across retries and restart", async (t) => {
  const root = await privateRoot(t);
  const store = await openCoordinationStore({
    now: () => NOW_MS,
    repositorySha: REPOSITORY_SHA,
    root,
  });
  await register(store);
  const enrollment = enrollmentBytes();
  const enrollmentDigest = sha256(enrollment);
  let factoryCalls = 0;
  const receiptFactory = async (context) => {
    factoryCalls += 1;
    assert.deepEqual(Object.keys(context), [
      "capabilityDigest",
      "enrollmentDigest",
      "releaseId",
      "repositorySha",
      "role",
      "sessionId",
    ]);
    assert.equal(Object.isFrozen(context), true);
    assert.equal(
      Object.hasOwn(context, "capability"),
      false,
    );
    assert.equal(
      Object.hasOwn(context, "enrollmentBytes"),
      false,
    );
    assert.equal(
      context.capabilityDigest,
      sha256(RAW_CAPABILITY),
    );
    return receiptBytes({
      ...context,
      signature: Buffer.from(
        `randomized-${factoryCalls}`,
      ).toString("base64"),
    });
  };
  const input = consumeInput({
    enrollment,
    enrollmentDigest,
    receiptFactory,
    scoped: true,
  });
  const [first, concurrentRetry] = await Promise.all([
    store.consumeCapability(input),
    store.consumeCapability(input),
  ]);
  assert.equal(factoryCalls, 1);
  assert.deepEqual(concurrentRetry, first);
  assert.deepEqual(first.enrollmentBytes, enrollment);
  assert.equal(first.enrollmentDigest, enrollmentDigest);
  const conflictingEnrollment = enrollmentBytes({
    invitations: {
      rehearsal: {
        address: `0x${"3".repeat(40)}`,
        algorithm: "eip191",
        signature: `0x${"3".repeat(130)}`,
      },
      stakeholder: {
        address: `0x${"4".repeat(40)}`,
        algorithm: "eip191",
        signature: `0x${"4".repeat(130)}`,
      },
    },
  });
  await assert.rejects(
    store.consumeCapability(
      consumeInput({
        enrollment: conflictingEnrollment,
        receiptFactory,
      }),
    ),
    { code: "CAPABILITY_REPLAY" },
  );
  assert.equal(factoryCalls, 1);
  assert.deepEqual(
    await store.readEnrollment({
      role: "payer",
      sessionId: SESSION_ID,
    }),
    {
      bytes: enrollment,
      digest: enrollmentDigest,
      receiptBytes: first.receiptBytes,
    },
  );
  await store.close();

  const restarted = await openCoordinationStore({
    now: () => NOW_MS + 120_000,
    repositorySha: REPOSITORY_SHA,
    root,
  });
  t.after(() => restarted.close().catch(() => {}));
  const afterRestart = await restarted.consumeCapability({
    ...input,
    receiptFactory: async () => {
      factoryCalls += 1;
      throw new Error("must not be called");
    },
  });
  assert.equal(factoryCalls, 1);
  assert.deepEqual(afterRestart, first);
  const read = await restarted.readEnrollment({
    role: "payer",
    sessionId: SESSION_ID,
  });
  assert.equal(Object.isFrozen(read), true);
  read.bytes.fill(0);
  read.receiptBytes.fill(0);
  const reread = await restarted.readEnrollment({
    role: "payer",
    sessionId: SESSION_ID,
  });
  assert.deepEqual(
    reread.bytes,
    enrollment,
  );
  assert.deepEqual(reread.receiptBytes, first.receiptBytes);
});

test("fails factory exceptions and hostile returns generically without consuming the capability", async (t) => {
  const { store } = await storeFixture(t);
  await register(store);
  const secretCanary = "FACTORY_EXCEPTION_SECRET_CANARY";
  await assert.rejects(
    store.consumeCapability(
      consumeInput({
        receiptFactory: async () => {
          throw new Error(secretCanary);
        },
      }),
    ),
    (error) => {
      assert.equal(
        error.code,
        "COORDINATION_STORAGE_INVALID",
      );
      assert.equal(
        error.message,
        "Coordination storage operation failed safely.",
      );
      assert.doesNotMatch(
        `${error.message}\n${error.stack}`,
        new RegExp(secretCanary),
      );
      return true;
    },
  );
  const hostileCanary = "FACTORY_RETURN_SECRET_CANARY";
  await assert.rejects(
    store.consumeCapability(
      consumeInput({
        receiptFactory: async () =>
          new Proxy(Buffer.from("opaque"), {
            get(target, property, receiver) {
              if (property === "length") {
                throw new Error(hostileCanary);
              }
              return Reflect.get(
                target,
                property,
                receiver,
              );
            },
          }),
      }),
    ),
    (error) => {
      assert.equal(
        error.code,
        "COORDINATION_STORAGE_INVALID",
      );
      assert.equal(
        error.message,
        "Coordination storage operation failed safely.",
      );
      assert.doesNotMatch(
        `${error.message}\n${error.stack}`,
        new RegExp(hostileCanary),
      );
      return true;
    },
  );
  const consumed = await store.consumeCapability(
    consumeInput(),
  );
  assert.deepEqual(consumed.receiptBytes, RECEIPT_BYTES);
});

test("rejects conflicting, expired, wrong-scope, and invalid enrollment before receipt creation", async (t) => {
  const { store } = await storeFixture(t);
  let factoryCalls = 0;
  const receiptFactory = async (context) => {
    factoryCalls += 1;
    return receiptBytes(context);
  };
  await register(store, {
    capabilityDigest: sha256(Buffer.alloc(32, 0x33)),
    expiresAtMs: String(NOW_MS),
    sessionId:
      "7f953393-86d0-4f99-9d6a-102f525fbecd",
  });
  await assert.rejects(
    store.consumeCapability(
      consumeInput({
        capability: Buffer.alloc(32, 0x33),
        enrollment: enrollmentBytes({
          capability: Buffer.alloc(32, 0x33),
          sessionId:
            "7f953393-86d0-4f99-9d6a-102f525fbecd",
        }),
        receiptFactory,
      }),
    ),
    { code: "CAPABILITY_EXPIRED" },
  );
  await register(store);
  const exact = enrollmentBytes();
  await assert.rejects(
    store.consumeCapability(
      consumeInput({
        enrollment: exact,
        enrollmentDigest: "e".repeat(64),
        receiptFactory,
      }),
    ),
    { code: "COORDINATION_STORAGE_INVALID" },
  );
  const wrongScope = enrollmentBytes({
    releaseId: "release-b",
  });
  await assert.rejects(
    store.consumeCapability(
      consumeInput({
        enrollment: wrongScope,
        receiptFactory,
      }),
    ),
    { code: "COORDINATION_STORAGE_INVALID" },
  );
  const invalid = Buffer.from(exact);
  invalid[invalid.length - 2] ^= 1;
  await assert.rejects(
    store.consumeCapability(
      consumeInput({
        enrollment: invalid,
        receiptFactory,
      }),
    ),
    { code: "COORDINATION_STORAGE_INVALID" },
  );
  assert.equal(factoryCalls, 0);
  await assert.rejects(
    store.readEnrollment({
      role: "payer",
      sessionId: SESSION_ID,
    }),
    {
      code: "COORDINATION_ENROLLMENT_NOT_FOUND",
      message: "Coordination storage operation failed safely.",
    },
  );
});

test("requires every exact receipt key and rejects extra, nested, or evasively split content", async (t) => {
  const { store } = await storeFixture(t);
  await register(store);
  const exact = receiptValue();
  for (const key of Object.keys(exact)) {
    const missing = { ...exact };
    delete missing[key];
    await assertReceiptRejected(store, missing, {
      label: `missing ${key}`,
    });
  }

  const secretCanary = "RECEIPT_EXTRA_SECRET_CANARY";
  await assertReceiptRejected(
    store,
    {
      ...exact,
      note: secretCanary,
    },
    {
      label: "extra free-form key",
      secretCanary,
    },
  );
  await assertReceiptRejected(
    store,
    {
      ...exact,
      numericTrace: [0, ...RAW_CAPABILITY, 0],
    },
    { label: "embedded numeric capability subsequence" },
  );
  const base64url = RAW_CAPABILITY.toString("base64url");
  await assertReceiptRejected(
    store,
    {
      ...exact,
      signatureFragments: [
        base64url.slice(0, 21),
        base64url.slice(21),
      ],
    },
    { label: "split base64url capability" },
  );
});

test("binds the exact receipt schema and payload to the consume request and registered scope", async (t) => {
  const { store } = await storeFixture(t);
  await register(store);
  for (const [label, overrides] of [
    [
      "capability digest",
      { capabilityDigest: "e".repeat(64) },
    ],
    [
      "enrollment digest",
      { enrollmentDigest: "e".repeat(64) },
    ],
    ["payment moved", { paymentMoved: true }],
    ["release", { releaseId: "release-b" }],
    ["repository", { repositorySha: "e".repeat(40) }],
    ["role", { role: "payee" }],
    [
      "schema",
      {
        schema:
          "clockchain.bilateral-coordination-receipt/v2",
      },
    ],
    [
      "session",
      {
        sessionId:
          "7f953393-86d0-4f99-9d6a-102f525fbecd",
      },
    ],
  ]) {
    await assertReceiptRejected(
      store,
      receiptValue(overrides),
      { label },
    );
  }
});

test("rejects invalid certificate digests, signatures, and signature algorithms generically", async (t) => {
  const { store } = await storeFixture(t);
  await register(store);
  for (const [label, overrides] of [
    [
      "uppercase certificate digest",
      { certificateSha256: "D".repeat(64) },
    ],
    [
      "malformed certificate digest",
      { certificateSha256: "certificate-secret" },
    ],
    ["empty signature", { signature: "" }],
    ["malformed signature", { signature: "%%%" }],
    [
      "noncanonical signature",
      { signature: "AB==" },
    ],
    [
      "oversized signature",
      {
        signature: Buffer.alloc(1_025).toString(
          "base64",
        ),
      },
    ],
    [
      "unknown signature algorithm",
      { signatureAlgorithm: "Ed25519" },
    ],
  ]) {
    await assertReceiptRejected(
      store,
      receiptValue(overrides),
      {
        label,
        secretCanary:
          overrides.certificateSha256 ===
          "certificate-secret"
            ? "certificate-secret"
            : undefined,
      },
    );
  }
});

test("accepts the closed receipt signature algorithms and signature size boundaries", async (t) => {
  for (const [signatureAlgorithm, signature] of [
    ["ed25519", Buffer.from([0]).toString("base64")],
    [
      "ecdsa-sha256",
      Buffer.from("ecdsa-signature").toString("base64"),
    ],
    [
      "rsa-pss-sha256",
      Buffer.alloc(1_024, 0x5a).toString("base64"),
    ],
  ]) {
    const { store } = await storeFixture(t);
    await register(store);
    const bytes = receiptBytes({
      signature,
      signatureAlgorithm,
    });
    const consumed = await store.consumeCapability({
      ...consumeInput(),
      receiptFactory: async () => bytes,
    });
    assert.deepEqual(consumed.receiptBytes, bytes);
  }
});

test("fails closed on capability expiry, cross-role use, and conflicting replay", async (t) => {
  const { store } = await storeFixture(t);
  await register(store, {
    capabilityDigest: sha256(Buffer.alloc(32, 0x33)),
    expiresAtMs: String(NOW_MS),
    sessionId:
      "7f953393-86d0-4f99-9d6a-102f525fbecd",
  });
  await assert.rejects(
    store.consumeCapability(
      consumeInput({
        capability: Buffer.alloc(32, 0x33),
        enrollment: enrollmentBytes({
          capability: Buffer.alloc(32, 0x33),
          sessionId:
            "7f953393-86d0-4f99-9d6a-102f525fbecd",
        }),
      }),
    ),
    { code: "CAPABILITY_EXPIRED" },
  );

  await register(store);
  await assert.rejects(
    store.consumeCapability({
      ...consumeInput({ scoped: true }),
      role: "payee",
    }),
    { code: "CAPABILITY_SCOPE" },
  );

  await store.consumeCapability(consumeInput());
  const conflictingEnrollment = enrollmentBytes({
    invitations: {
      rehearsal: {
        address: `0x${"5".repeat(40)}`,
        algorithm: "eip191",
        signature: `0x${"5".repeat(130)}`,
      },
      stakeholder: {
        address: `0x${"6".repeat(40)}`,
        algorithm: "eip191",
        signature: `0x${"6".repeat(130)}`,
      },
    },
  });
  await assert.rejects(
    store.consumeCapability(
      consumeInput({
        enrollment: conflictingEnrollment,
      }),
    ),
    { code: "CAPABILITY_REPLAY" },
  );
});

test("classifies byte-different consumed enrollment as replay before trusting its claimed digest", async (t) => {
  const { store } = await storeFixture(t);
  await register(store);
  await store.consumeCapability(consumeInput());
  const conflictingEnrollment = enrollmentBytes({
    invitations: {
      rehearsal: {
        address: `0x${"7".repeat(40)}`,
        algorithm: "eip191",
        signature: `0x${"7".repeat(130)}`,
      },
      stakeholder: {
        address: `0x${"8".repeat(40)}`,
        algorithm: "eip191",
        signature: `0x${"8".repeat(130)}`,
      },
    },
  });
  let factoryCalls = 0;
  await assert.rejects(
    store.consumeCapability(
      consumeInput({
        enrollment: conflictingEnrollment,
        enrollmentDigest: "e".repeat(64),
        receiptFactory: async (context) => {
          factoryCalls += 1;
          return receiptBytes(context);
        },
      }),
    ),
    { code: "CAPABILITY_REPLAY" },
  );
  assert.equal(factoryCalls, 0);
});

test("rejects unbounded capability expiry decimals and hostile accessor inputs with fixed errors", async (t) => {
  const { store } = await storeFixture(t);
  await assert.rejects(
    register(store, {
      expiresAtMs: "9".repeat(10_000),
    }),
    { code: "COORDINATION_STORAGE_INVALID" },
  );
  const hostile = Object.defineProperty(
    {
      capabilityDigest: sha256(RAW_CAPABILITY),
      expiresAtMs: String(NOW_MS + 60_000),
      releaseId: RELEASE_ID,
      role: "payer",
      sessionId: SESSION_ID,
    },
    "role",
    {
      enumerable: true,
      get() {
        throw new Error("hostile-secret");
      },
    },
  );
  await assert.rejects(
    store.registerCapability(hostile),
    {
      code: "COORDINATION_STORAGE_INVALID",
      message: "Coordination storage operation failed safely.",
    },
  );
  await assert.rejects(
    store.consumeCapability(
      new Proxy(
        {},
        {
          ownKeys() {
            throw new Error("hostile-secret");
          },
        },
      ),
    ),
    {
      code: "COORDINATION_STORAGE_INVALID",
      message: "Coordination storage operation failed safely.",
    },
  );
});

test("rejects every supported raw capability representation in a receipt without echoing it", async (t) => {
  const { store } = await storeFixture(t);
  const capability = Buffer.from("~".repeat(32), "utf8");
  await register(store, {
    capabilityDigest: sha256(capability),
  });
  const base64 = capability.toString("base64");
  const base64url = capability.toString("base64url");
  const cases = [
    ["lowercase hex", capability.toString("hex")],
    ["uppercase hex", capability.toString("hex").toUpperCase()],
    ["padded base64", base64],
    ["unpadded base64", base64.replace(/=+$/, "")],
    ["padded base64url", `${base64url}=`],
    ["unpadded base64url", base64url],
    ["exact raw UTF-8 bytes", capability.toString("utf8")],
    ["JSON byte array", [...capability]],
  ];
  for (const [label, representation] of cases) {
    const enrollment = enrollmentBytes({ capability });
    const candidateReceipt = stableBytes({
      ...receiptValue({
        capability,
        enrollmentDigest: sha256(enrollment),
      }),
      note: representation,
    });
    const leaked = Array.isArray(representation)
      ? representation.join(",")
      : representation;
    await assert.rejects(
      store.consumeCapability({
        capability,
        enrollmentBytes: enrollment,
        enrollmentDigest: sha256(enrollment),
        receiptFactory: async () => candidateReceipt,
      }),
      (error) => {
        assert.equal(
          error.code,
          "COORDINATION_STORAGE_INVALID",
        );
        assert.equal(
          error.message,
          "Coordination storage operation failed safely.",
        );
        assert.equal(error.message.includes(leaked), false);
        return true;
      },
      label,
    );
  }
});

test("rejects private material and token or authorization content from capability receipts", async (t) => {
  const { store } = await storeFixture(t);
  await register(store);
  const cases = [
    ["private-key field", { privateKey: "short-secret" }],
    [
      "private PEM",
      {
        note:
          "-----BEGIN PRIVATE KEY-----\nZm9yYmlkZGVu\n-----END PRIVATE KEY-----",
      },
    ],
    ["secret field", { secret: "short-secret" }],
    ["token field", { token: "short-secret" }],
    [
      "authorization field",
      { authorization: "short-secret" },
    ],
    [
      "secret assignment",
      { note: "secret: abcdefghijklmnop" },
    ],
    [
      "token assignment",
      { note: "token=abcdefghijklmnop" },
    ],
    [
      "authorization assignment",
      { note: "authorization: abcdefghijklmnop" },
    ],
    [
      "bearer token",
      {
        note:
          "Bearer abcdefghijklmnopqrstuvwxyz012345",
      },
    ],
    [
      "Clockchain token",
      { note: "cc_abcdefghijklmnopqrstuvwxyz012345" },
    ],
  ];
  for (const [label, hostile] of cases) {
    const candidateReceipt = stableBytes({
      ...receiptValue(),
      ...hostile,
    });
    await assert.rejects(
      store.consumeCapability({
        ...consumeInput(),
        receiptFactory: async () => candidateReceipt,
      }),
      (error) => {
        assert.equal(
          error.code,
          "COORDINATION_STORAGE_INVALID",
        );
        assert.equal(
          error.message,
          "Coordination storage operation failed safely.",
        );
        assert.equal(
          error.message.includes("short-secret"),
          false,
        );
        assert.equal(
          error.message.includes("abcdefghijklmnop"),
          false,
        );
        return true;
      },
      label,
    );
  }
});

test("serializes concurrent capability consumption", async (t) => {
  const { store } = await storeFixture(t);
  await register(store);
  const exact = enrollmentBytes();
  const conflicting = enrollmentBytes({
    invitations: {
      rehearsal: {
        address: `0x${"7".repeat(40)}`,
        algorithm: "eip191",
        signature: `0x${"7".repeat(130)}`,
      },
      stakeholder: {
        address: `0x${"8".repeat(40)}`,
        algorithm: "eip191",
        signature: `0x${"8".repeat(130)}`,
      },
    },
  });
  const results = await Promise.allSettled([
    store.consumeCapability(
      consumeInput({ enrollment: exact }),
    ),
    store.consumeCapability(
      consumeInput({ enrollment: conflicting }),
    ),
  ]);
  assert.equal(
    results.filter(({ status }) => status === "fulfilled").length,
    1,
  );
  const rejection = results.find(
    ({ status }) => status === "rejected",
  );
  assert.equal(rejection.reason.code, "CAPABILITY_REPLAY");
});

test("rejects conflicting capability registration and preserves consumption across restart", async (t) => {
  const root = await privateRoot(t);
  const store = await openCoordinationStore({
    now: () => NOW_MS,
    repositorySha: REPOSITORY_SHA,
    root,
  });
  await register(store);
  assert.deepEqual(
    await register(store),
    await register(store),
  );
  await assert.rejects(
    register(store, { role: "payee" }),
    { code: "CAPABILITY_REPLAY" },
  );
  const input = consumeInput();
  const consumed = await store.consumeCapability(input);
  await store.close();

  const restarted = await openCoordinationStore({
    now: () => NOW_MS + 120_000,
    repositorySha: REPOSITORY_SHA,
    root,
  });
  t.after(() => restarted.close().catch(() => {}));
  assert.deepEqual(
    await restarted.consumeCapability(input),
    consumed,
  );
});

test("binds exactly one capability per session role and one release per session", async (t) => {
  const { store } = await storeFixture(t);
  await register(store);
  await assert.rejects(
    register(store, {
      capabilityDigest: sha256(Buffer.alloc(32, 0x44)),
    }),
    { code: "CAPABILITY_REPLAY" },
  );
  await assert.rejects(
    register(store, {
      capabilityDigest: sha256(Buffer.alloc(32, 0x55)),
      releaseId: "release-b",
      role: "payee",
    }),
    { code: "CAPABILITY_REPLAY" },
  );
});

test("appends and restarts from the authoritative event log", async (t) => {
  const root = await privateRoot(t);
  const firstStore = await openCoordinationStore({
    now: () => NOW_MS,
    repositorySha: REPOSITORY_SHA,
    root,
  });
  const event0 = event();
  await firstStore.appendEvent(event0);
  assert.deepEqual(
    await firstStore.readEvents({
      after: null,
      sessionId: SESSION_ID,
    }),
    [event0],
  );
  await firstStore.close();

  const restarted = await openCoordinationStore({
    now: () => NOW_MS,
    repositorySha: REPOSITORY_SHA,
    root,
  });
  t.after(() => restarted.close().catch(() => {}));
  assert.deepEqual(
    await restarted.readEvents({
      after: null,
      sessionId: SESSION_ID,
    }),
    [event0],
  );
  const view = await restarted.readReleaseView({
    sessionId: SESSION_ID,
  });
  assert.equal(view.paymentMoved, false);
  assert.equal(view.releaseId, RELEASE_ID);
  assert.equal(view.repositorySha, REPOSITORY_SHA);
  assert.deepEqual(view.events, [event0]);
});

test("rejects release-context divergence within one session even with a fresh valid digest", async (t) => {
  const { store } = await storeFixture(t);
  const event0 = event();
  await store.appendEvent(event0);
  const divergent = event({
    kind: "FUNDING_INPUTS_READY",
    previousEventDigest: event0.eventDigest,
    releaseId: "release-b",
    sequence: "1",
  });
  await assert.rejects(store.appendEvent(divergent), {
    code: "COORDINATION_STORAGE_INVALID",
  });
});

test("implements idempotent event retry and fail-closed sender sequencing", async (t) => {
  const { store } = await storeFixture(t);
  const event0 = event();
  assert.deepEqual(await store.appendEvent(event0), event0);
  assert.deepEqual(await store.appendEvent(event0), event0);

  const conflicting = event({
    kind: "FUNDING_INPUTS_READY",
    sequence: "0",
  });
  await assert.rejects(store.appendEvent(conflicting), {
    code: "EVENT_SEQUENCE_CONFLICT",
  });

  const gap = event({
    previousEventDigest: event0.eventDigest,
    sequence: "2",
  });
  await assert.rejects(store.appendEvent(gap), {
    code: "EVENT_SEQUENCE_GAP",
  });

  const broken = event({ sequence: "1" });
  await assert.rejects(store.appendEvent(broken), {
    code: "EVENT_CHAIN_DIVERGENCE",
  });
});

test("serializes concurrent identical event append and reads strictly after a known digest", async (t) => {
  const { store } = await storeFixture(t);
  const event0 = event();
  const [left, right] = await Promise.all([
    store.appendEvent(event0),
    store.appendEvent(event0),
  ]);
  assert.deepEqual(left, event0);
  assert.deepEqual(right, event0);
  const event1 = event({
    kind: "FUNDING_INPUTS_READY",
    previousEventDigest: event0.eventDigest,
    sequence: "1",
  });
  await store.appendEvent(event1);
  assert.deepEqual(
    await store.readEvents({
      after: event0.eventDigest,
      sessionId: SESSION_ID,
    }),
    [event1],
  );
  await assert.rejects(
    store.readEvents({
      after: "f".repeat(64),
      sessionId: SESSION_ID,
    }),
    { code: "COORDINATION_STORAGE_INVALID" },
  );
});

test("classifies a global digest reused across role, run, session, or release as replay", async (t) => {
  const { store } = await storeFixture(t);
  const event0 = event();
  await store.appendEvent(event0);
  for (const mutation of [
    { role: "payee" },
    { subjectRun: "rehearsal" },
    { sessionId: "9f953393-86d0-4f99-9d6a-102f525fbecd" },
    { releaseId: "release-b" },
    {
      previousEventDigest: event0.eventDigest,
      sequence: "1",
    },
  ]) {
    await assert.rejects(
      store.appendEvent({ ...structuredClone(event0), ...mutation }),
      { code: "EVENT_REPLAY" },
    );
  }
  assert.deepEqual(await store.readEvents({
    after: null,
    sessionId: SESSION_ID,
  }), [event0]);
});

test("conflicting concurrent sender events accept exactly one", async (t) => {
  const { store } = await storeFixture(t);
  const results = await Promise.allSettled([
    store.appendEvent(event()),
    store.appendEvent(event({
      kind: "FUNDING_INPUTS_READY",
    })),
  ]);
  assert.equal(
    results.filter(({ status }) => status === "fulfilled").length,
    1,
  );
  assert.equal(
    results.find(({ status }) => status === "rejected").reason.code,
    "EVENT_SEQUENCE_CONFLICT",
  );
});

test("rejects an event whose embedded digest does not match its signed body", async (t) => {
  const { store } = await storeFixture(t);
  const invalid = structuredClone(event());
  invalid.kind = "TOKEN_READY";
  await assert.rejects(store.appendEvent(invalid), {
    code: "COORDINATION_STORAGE_INVALID",
  });
});

test("rejects torn and noncanonical journal records on restart", async (t) => {
  for (const mutate of [
    (bytes) => Buffer.concat([bytes, Buffer.from([0, 0, 0])]),
    (bytes) => {
      const copy = Buffer.from(bytes);
      const brace = copy.indexOf(0x7b, 4);
      return Buffer.concat([
        copy.subarray(0, brace + 1),
        Buffer.from(" "),
        copy.subarray(brace + 1),
      ]);
    },
  ]) {
    const root = await privateRoot(t);
    const store = await openCoordinationStore({
      repositorySha: REPOSITORY_SHA,
      root,
    });
    await store.appendEvent(event());
    await store.close();
    const journalPath = join(root, "journal.log");
    await writeFile(journalPath, mutate(await readFile(journalPath)), {
      mode: 0o600,
    });
    await assert.rejects(
      openCoordinationStore({
        repositorySha: REPOSITORY_SHA,
        root,
      }),
      { code: "COORDINATION_STORAGE_INVALID" },
    );
  }
});

test("revalidates enrollment signatures, scope, and receipts from rehashed journal records", async (t) => {
  const exactEnrollment = enrollmentBytes();
  const invalidSignature = enrollmentValue();
  invalidSignature.signature =
    `${invalidSignature.signature.slice(0, -4)}AAAA`;
  for (const candidate of [
    {
      enrollment: canonicalBytes(invalidSignature),
      label: "enrollment signature",
    },
    {
      enrollment: enrollmentBytes({
        releaseId: "release-b",
      }),
      label: "enrollment scope",
    },
    {
      enrollment: exactEnrollment,
      invalidReceipt: true,
      label: "receipt",
    },
  ]) {
    const root = await privateRoot(t);
    const store = await openCoordinationStore({
      now: () => NOW_MS,
      repositorySha: REPOSITORY_SHA,
      root,
    });
    await register(store);
    await store.consumeCapability(consumeInput());
    await store.close();

    const journalPath = join(root, "journal.log");
    const records = decodeJournal(
      await readFile(journalPath),
    );
    assert.equal(records.length, 2, candidate.label);
    const enrollmentDigest = sha256(
      candidate.enrollment,
    );
    const receipt = candidate.invalidReceipt
      ? stableBytes({
          ...receiptValue({ enrollmentDigest }),
          paymentMoved: true,
        })
      : receiptBytes({ enrollmentDigest });
    const consumed = records[1];
    records[1] = withRecordDigest({
      ...consumed,
      payload: {
        ...consumed.payload,
        value: {
          ...consumed.payload.value,
          enrollmentBase64:
            candidate.enrollment.toString("base64"),
          enrollmentDigest,
          receiptBase64: receipt.toString("base64"),
          receiptDigest: sha256(receipt),
        },
      },
    });
    await writeFile(
      journalPath,
      encodeJournal(records),
      { mode: 0o600 },
    );
    await assert.rejects(
      openCoordinationStore({
        now: () => NOW_MS,
        repositorySha: REPOSITORY_SHA,
        root,
      }),
      {
        code: "COORDINATION_STORAGE_INVALID",
        message:
          "Coordination storage operation failed safely.",
      },
      candidate.label,
    );
  }
});

test("discards snapshot disagreement and rebuilds from the authoritative journal", async (t) => {
  const root = await privateRoot(t);
  const store = await openCoordinationStore({
    repositorySha: REPOSITORY_SHA,
    root,
  });
  await store.appendEvent(event());
  await store.close();
  const snapshotPath = join(root, "snapshot.json");
  const snapshot = JSON.parse(await readFile(snapshotPath, "utf8"));
  snapshot.stateDigest = "0".repeat(64);
  await writeFile(snapshotPath, stableBytes(snapshot), {
    mode: 0o600,
  });
  const reopened = await openCoordinationStore({
    repositorySha: REPOSITORY_SHA,
    root,
  });
  assert.deepEqual(
    await reopened.readEvents({
      after: null,
      sessionId: SESSION_ID,
    }),
    [event()],
  );
  await reopened.close();
  assert.notEqual(
    JSON.parse(
      await readFile(snapshotPath, "utf8"),
    ).stateDigest,
    "0".repeat(64),
  );
});

test("rebuilds a missing or crash-stale derived snapshot from the authoritative journal", async (t) => {
  for (const mode of ["missing", "stale"]) {
    const root = await privateRoot(t);
    const store = await openCoordinationStore({
      repositorySha: REPOSITORY_SHA,
      root,
    });
    const snapshotPath = join(root, "snapshot.json");
    const initialSnapshot = await readFile(snapshotPath);
    const event0 = event();
    await store.appendEvent(event0);
    await store.close();
    if (mode === "missing") {
      await unlink(snapshotPath);
    } else {
      await writeFile(snapshotPath, initialSnapshot, {
        mode: 0o600,
      });
    }
    const restarted = await openCoordinationStore({
      repositorySha: REPOSITORY_SHA,
      root,
    });
    assert.deepEqual(
      await restarted.readEvents({
        after: null,
        sessionId: SESSION_ID,
      }),
      [event0],
    );
    await restarted.close();
    assert.equal(
      JSON.parse(
        await readFile(snapshotPath, "utf8"),
      ).recordCount,
      "1",
    );
  }
});

test("discards any exact private crash-left derived snapshot temp before rebuilding", async (t) => {
  const root = await privateRoot(t);
  const store = await openCoordinationStore({
    repositorySha: REPOSITORY_SHA,
    root,
  });
  await store.appendEvent(event());
  await store.close();
  await writeFile(
    join(root, ".snapshot.tmp"),
    await readFile(join(root, "snapshot.json")),
    { flag: "wx", mode: 0o600 },
  );
  const restarted = await openCoordinationStore({
    repositorySha: REPOSITORY_SHA,
    root,
  });
  await restarted.close();
  await assert.rejects(
    lstat(join(root, ".snapshot.tmp")),
    { code: "ENOENT" },
  );

  await writeFile(
    join(root, ".snapshot.tmp"),
    Buffer.from("{}"),
    { flag: "wx", mode: 0o600 },
  );
  const recovered = await openCoordinationStore({
    repositorySha: REPOSITORY_SHA,
    root,
  });
  await recovered.close();
  await assert.rejects(
    lstat(join(root, ".snapshot.tmp")),
    { code: "ENOENT" },
  );
});

test("stores artifacts content-addressed with identical retry and reread hashing", async (t) => {
  const { root, store } = await storeFixture(t);
  const bytes = signedDescriptorBytes();
  const input = {
    artifactType: "signed-descriptor",
    bytes,
    expectedDigest: sha256(bytes),
    secretCanaries: ["absent-canary"],
  };
  const metadata = await store.putArtifact(input);
  assert.deepEqual(await store.putArtifact(input), metadata);
  assert.deepEqual(await store.getArtifact(metadata.digest), bytes);
  const path = join(
    root,
    "artifacts",
    metadata.digest.slice(0, 2),
    metadata.digest,
  );
  assert.equal((await stat(path)).mode & 0o777, 0o600);
});

test("rejects artifact replacement and duplicate digest with changed bytes", async (t) => {
  const { root, store } = await storeFixture(t);
  const bytes = signedDescriptorBytes();
  const digest = sha256(bytes);
  await store.putArtifact({
    artifactType: "signed-descriptor",
    bytes,
    expectedDigest: digest,
    secretCanaries: [],
  });
  const path = join(root, "artifacts", digest.slice(0, 2), digest);
  await unlink(path);
  await writeFile(path, Buffer.from("replacement"), {
    mode: 0o600,
  });
  await assert.rejects(store.getArtifact(digest), {
    code: "COORDINATION_STORAGE_INVALID",
  });

  await assert.rejects(
    store.putArtifact({
      artifactType: "signed-descriptor",
      bytes,
      expectedDigest: digest,
      secretCanaries: [],
    }),
    { code: "COORDINATION_STORAGE_INVALID" },
  );
});

test("rejects symlinked store files and root replacement", async (t) => {
  const root = await privateRoot(t);
  const store = await openCoordinationStore({
    repositorySha: REPOSITORY_SHA,
    root,
  });
  await store.close();
  const journal = join(root, "journal.log");
  await unlink(journal);
  await symlink("/dev/null", journal);
  await assert.rejects(
    openCoordinationStore({
      repositorySha: REPOSITORY_SHA,
      root,
    }),
    { code: "COORDINATION_STORAGE_INVALID" },
  );

  await unlink(journal);
  const replacement = await privateRoot(t);
  await rename(root, `${root}-old`);
  t.after(() => rm(`${root}-old`, { force: true, recursive: true }));
  await rename(replacement, root);
  await assert.rejects(store.readEvents({
    after: null,
    sessionId: SESSION_ID,
  }), {
    code: "COORDINATION_STORAGE_CLOSED",
  });
});

for (const operation of [
  "register",
  "consume",
  "enrollment",
  "append",
  "read",
  "put",
  "get",
]) {
  test(`detects live state-root replacement during ${operation}`, async (t) => {
    const root = await privateRoot(t);
    const moved = `${root}-moved-${operation}`;
    let armed = false;
    let fired = false;
    const fileSystem = testFileSystem({
      async lstat(path) {
        if (armed && !fired && path === root) {
          fired = true;
          await rename(root, moved);
          await mkdir(root, { mode: 0o700 });
        }
        return lstat(path);
      },
    });
    t.after(() => rm(moved, { force: true, recursive: true }));
    const store = await openCoordinationStore({
      fileSystem,
      now: () => NOW_MS,
      repositorySha: REPOSITORY_SHA,
      root,
    });
    t.after(() => store.close().catch(() => {}));
    const artifactBytes = signedDescriptorBytes();
    if (
      operation === "consume" ||
      operation === "enrollment"
    ) {
      await register(store);
    }
    if (operation === "enrollment") {
      await store.consumeCapability(consumeInput());
    }
    if (operation === "get") {
      await store.putArtifact({
        artifactType: "signed-descriptor",
        bytes: artifactBytes,
        expectedDigest: sha256(artifactBytes),
        secretCanaries: [],
      });
    }
    armed = true;
    const action = {
      append: () => store.appendEvent(event()),
      consume: () =>
        store.consumeCapability(consumeInput()),
      enrollment: () =>
        store.readEnrollment({
          role: "payer",
          sessionId: SESSION_ID,
        }),
      get: () => store.getArtifact(sha256(artifactBytes)),
      put: () =>
        store.putArtifact({
          artifactType: "signed-descriptor",
          bytes: artifactBytes,
          expectedDigest: sha256(artifactBytes),
          secretCanaries: [],
        }),
      read: () =>
        store.readEvents({
          after: null,
          sessionId: SESSION_ID,
        }),
      register: () => register(store),
    }[operation];
    await assert.rejects(action(), {
      code: "COORDINATION_STORAGE_INVALID",
    });
    assert.equal(fired, true);
  });
}

test("detects live artifact-directory replacement during put", async (t) => {
  const root = await privateRoot(t);
  const prefix = "ab";
  const prefixPath = join(root, "artifacts", prefix);
  const moved = `${prefixPath}-moved`;
  let armed = false;
  let fired = false;
  let prefixStats = 0;
  const fileSystem = testFileSystem({
    async lstat(path) {
      if (armed && path === prefixPath) {
        prefixStats += 1;
      }
      if (
        armed &&
        !fired &&
        path === prefixPath &&
        prefixStats === 2
      ) {
        fired = true;
        await rename(prefixPath, moved);
        await mkdir(prefixPath, { mode: 0o700 });
      }
      return lstat(path);
    },
  });
  const store = await openCoordinationStore({
    fileSystem,
    repositorySha: REPOSITORY_SHA,
    root,
  });
  t.after(() => store.close().catch(() => {}));
  await mkdir(prefixPath, { mode: 0o700 });
  let selected;
  for (let nonce = 0; ; nonce += 1) {
    selected = signedDescriptorBytes({
      keyId: `storage-test-${nonce}`,
    });
    if (sha256(selected).slice(0, 2) === prefix) {
      break;
    }
  }
  armed = true;
  await assert.rejects(
    store.putArtifact({
      artifactType: "signed-descriptor",
      bytes: selected,
      expectedDigest: sha256(selected),
      secretCanaries: [],
    }),
    { code: "COORDINATION_STORAGE_INVALID" },
  );
  assert.equal(fired, true);
});

test("detects live artifact-file replacement during get", async (t) => {
  const root = await privateRoot(t);
  let armedPath;
  let fired = false;
  const fileSystem = testFileSystem({
    async open(path, ...args) {
      if (armedPath === path && !fired) {
        fired = true;
        await unlink(path);
        await writeFile(path, "replacement", { mode: 0o600 });
      }
      return open(path, ...args);
    },
  });
  const store = await openCoordinationStore({
    fileSystem,
    repositorySha: REPOSITORY_SHA,
    root,
  });
  t.after(() => store.close().catch(() => {}));
  const bytes = signedDescriptorBytes();
  const digest = sha256(bytes);
  await store.putArtifact({
    artifactType: "signed-descriptor",
    bytes,
    expectedDigest: digest,
    secretCanaries: [],
  });
  armedPath = join(root, "artifacts", digest.slice(0, 2), digest);
  await assert.rejects(store.getArtifact(digest), {
    code: "COORDINATION_STORAGE_INVALID",
  });
  assert.equal(fired, true);
});

test("fails an append when journal fsync fails and poisons the open store", async (t) => {
  const root = await privateRoot(t);
  let failSync = false;
  const fileSystem = testFileSystem({
    async open(path, ...args) {
      const handle = await open(path, ...args);
      if (path !== join(root, "journal.log")) {
        return handle;
      }
      return handleFacade(handle, {
        async sync() {
          if (failSync) {
            throw new Error("injected");
          }
          return handle.sync();
        },
      });
    },
  });
  const store = await openCoordinationStore({
    fileSystem,
    repositorySha: REPOSITORY_SHA,
    root,
  });
  t.after(() => store.close().catch(() => {}));
  failSync = true;
  await assert.rejects(store.appendEvent(event()), {
    code: "COORDINATION_STORAGE_INVALID",
  });
  await assert.rejects(
    store.readEvents({
      after: null,
      sessionId: SESSION_ID,
    }),
    { code: "COORDINATION_STORAGE_INVALID" },
  );
});

test("rejects live journal pathname replacement after the record fsync", async (t) => {
  const root = await privateRoot(t);
  const journalPath = join(root, "journal.log");
  const movedPath = join(root, "journal.old");
  let armed = false;
  let fired = false;
  const fileSystem = testFileSystem({
    async open(path, ...args) {
      const handle = await open(path, ...args);
      if (path !== journalPath) {
        return handle;
      }
      return handleFacade(handle, {
        async sync() {
          await handle.sync();
          if (armed && !fired) {
            fired = true;
            await rename(journalPath, movedPath);
            await writeFile(journalPath, Buffer.alloc(0), {
              flag: "wx",
              mode: 0o600,
            });
          }
        },
      });
    },
  });
  const store = await openCoordinationStore({
    fileSystem,
    repositorySha: REPOSITORY_SHA,
    root,
  });
  t.after(() => store.close().catch(() => {}));
  armed = true;
  await assert.rejects(store.appendEvent(event()), {
    code: "COORDINATION_STORAGE_INVALID",
  });
  assert.equal(fired, true);
});

test("open-failure cleanup never unlinks an owner pathname in a replacement root", async (t) => {
  const root = await privateRoot(t);
  const moved = `${root}-original`;
  const sentinel = stableBytes({
    pid: "99999999",
    schema: "clockchain.bilateral-store-owner/v1",
  });
  let fired = false;
  const fileSystem = testFileSystem({
    async open(path, ...args) {
      if (
        !fired &&
        path === join(root, "metadata.json")
      ) {
        fired = true;
        await rename(root, moved);
        await mkdir(root, { mode: 0o700 });
        await writeFile(
          join(root, ".store-owner.json"),
          sentinel,
          { flag: "wx", mode: 0o600 },
        );
      }
      return open(path, ...args);
    },
  });
  t.after(() => rm(moved, { force: true, recursive: true }));
  await assert.rejects(
    openCoordinationStore({
      fileSystem,
      repositorySha: REPOSITORY_SHA,
      root,
    }),
    { code: "COORDINATION_STORAGE_INVALID" },
  );
  assert.equal(fired, true);
  assert.deepEqual(
    await readFile(join(root, ".store-owner.json")),
    sentinel,
  );
});

test("reports a durable close failure", async (t) => {
  const root = await privateRoot(t);
  let failClose = false;
  const fileSystem = testFileSystem({
    async open(path, ...args) {
      const handle = await open(path, ...args);
      if (path !== join(root, "journal.log")) {
        return handle;
      }
      return handleFacade(handle, {
        async close() {
          if (failClose) {
            failClose = false;
            await handle.close();
            throw new Error("injected");
          }
          return handle.close();
        },
      });
    },
  });
  const store = await openCoordinationStore({
    fileSystem,
    repositorySha: REPOSITORY_SHA,
    root,
  });
  failClose = true;
  await assert.rejects(store.close(), {
    code: "COORDINATION_STORAGE_INVALID",
  });
  await assert.rejects(store.close(), {
    code: "COORDINATION_STORAGE_INVALID",
  });
});

test("close is idempotent and all methods fail after close", async (t) => {
  const { store } = await storeFixture(t);
  await store.close();
  await store.close();
  await assert.rejects(
    store.readEvents({
      after: null,
      sessionId: SESSION_ID,
    }),
    { code: "COORDINATION_STORAGE_CLOSED" },
  );
  await assert.rejects(
    store.readEnrollment({
      role: "payer",
      sessionId: SESSION_ID,
    }),
    { code: "COORDINATION_STORAGE_CLOSED" },
  );
});

test("recovers exact private malformed snapshots and crash-left snapshot temporaries from the journal", async (t) => {
  const { root, store } = await storeFixture(t);
  await register(store);
  await store.close();

  await writeFile(
    join(root, "snapshot.json"),
    Buffer.from("{malformed"),
    { mode: 0o600 },
  );
  await writeFile(
    join(root, ".snapshot.tmp"),
    Buffer.from("partial-snapshot"),
    { mode: 0o600 },
  );

  const reopened = await openCoordinationStore({
    now: () => NOW_MS,
    repositorySha: REPOSITORY_SHA,
    root,
  });
  t.after(() => reopened.close().catch(() => {}));
  assert.deepEqual(await register(reopened), {
    capabilityDigest: sha256(RAW_CAPABILITY),
    expiresAtMs: String(NOW_MS + 60_000),
    releaseId: RELEASE_ID,
    role: "payer",
    sessionId: SESSION_ID,
  });
  await assert.rejects(
    lstat(join(root, ".snapshot.tmp")),
    { code: "ENOENT" },
  );
  const snapshot = JSON.parse(
    await readFile(join(root, "snapshot.json"), "utf8"),
  );
  assert.equal(snapshot.recordCount, "1");
});

test("recovers a journal-durable append after an interrupted snapshot write", async (t) => {
  const root = await privateRoot(t);
  let interruptSnapshot = false;
  let interrupted = false;
  const fileSystem = testFileSystem({
    async open(path, flags, mode) {
      const handle = await open(path, flags, mode);
      if (
        interruptSnapshot &&
        !interrupted &&
        path === join(root, ".snapshot.tmp")
      ) {
        return handleFacade(handle, {
          async writeFile(bytes) {
            interrupted = true;
            await handle.writeFile(
              bytes.subarray(0, Math.max(1, bytes.length >> 1)),
            );
            throw new Error("injected snapshot interruption");
          },
        });
      }
      return handleFacade(handle);
    },
  });
  const store = await openCoordinationStore({
    fileSystem,
    now: () => NOW_MS,
    repositorySha: REPOSITORY_SHA,
    root,
  });
  interruptSnapshot = true;
  await assert.rejects(register(store), {
    code: "COORDINATION_STORAGE_INVALID",
  });
  assert.equal(interrupted, true);
  await store.close().catch(() => {});

  const reopened = await openCoordinationStore({
    now: () => NOW_MS,
    repositorySha: REPOSITORY_SHA,
    root,
  });
  t.after(() => reopened.close().catch(() => {}));
  assert.deepEqual(await register(reopened), {
    capabilityDigest: sha256(RAW_CAPABILITY),
    expiresAtMs: String(NOW_MS + 60_000),
    releaseId: RELEASE_ID,
    role: "payer",
    sessionId: SESSION_ID,
  });
});

test("recovers every exact known initialization prefix after an injected crash", async (t) => {
  for (const stage of [
    "metadata",
    "journal-create",
    "journal",
    "artifacts",
    "snapshot",
  ]) {
    const root = await privateRoot(t);
    let injected = false;
    const fileSystem = testFileSystem({
      async mkdir(path, options) {
        const result = await mkdir(path, options);
        if (
          !injected &&
          stage === "artifacts" &&
          path === join(root, "artifacts")
        ) {
          injected = true;
          throw new Error("injected artifacts interruption");
        }
        return result;
      },
      async open(path, flags, mode) {
        const handle = await open(path, flags, mode);
        const create = (flags & fsConstants.O_EXCL) !== 0;
        const journalTruncate =
          path === join(root, "journal.log") &&
          !create &&
          (flags & fsConstants.O_APPEND) === 0;
        const targeted =
          (!injected &&
            stage === "metadata" &&
            create &&
            path === join(root, "metadata.json")) ||
          (!injected &&
            stage === "journal-create" &&
            create &&
            path === join(root, "journal.log")) ||
          (!injected &&
            stage === "journal" &&
            journalTruncate) ||
          (!injected &&
            stage === "snapshot" &&
            create &&
            path === join(root, "snapshot.json"));
        if (!targeted) {
          return handleFacade(handle);
        }
        return handleFacade(handle, {
          async sync() {
            await handle.sync();
            injected = true;
            throw new Error(`injected ${stage} interruption`);
          },
        });
      },
    });
    await assert.rejects(
      openCoordinationStore({
        fileSystem,
        repositorySha: REPOSITORY_SHA,
        root,
      }),
      { code: "COORDINATION_STORAGE_INVALID" },
      stage,
    );
    assert.equal(injected, true, stage);

    const recovered = await openCoordinationStore({
      repositorySha: REPOSITORY_SHA,
      root,
    });
    await recovered.close();
  }
});

test("rejects nonempty pre-snapshot artifact trees and never exposes their content", async (t) => {
  const bytes = Buffer.from("uncommitted artifact bytes");
  const digest = sha256(bytes);
  for (const hostile of [
    {
      label: "empty prefix directory",
      prepare: async (root) => {
        await mkdir(
          join(root, "artifacts", digest.slice(0, 2)),
          { mode: 0o700 },
        );
      },
    },
    {
      label: "content-addressed arbitrary bytes",
      prepare: async (root) => {
        const prefix = join(
          root,
          "artifacts",
          digest.slice(0, 2),
        );
        await mkdir(prefix, { mode: 0o700 });
        await writeFile(join(prefix, digest), bytes, {
          flag: "wx",
          mode: 0o600,
        });
      },
    },
  ]) {
    const root = await privateRoot(t);
    let injected = false;
    const fileSystem = testFileSystem({
      async open(path, flags, mode) {
        if (
          !injected &&
          path === join(root, "snapshot.json") &&
          (flags & fsConstants.O_EXCL) !== 0
        ) {
          injected = true;
          throw new Error("injected snapshot interruption");
        }
        return handleFacade(await open(path, flags, mode));
      },
    });
    await assert.rejects(
      openCoordinationStore({
        fileSystem,
        repositorySha: REPOSITORY_SHA,
        root,
      }),
      { code: "COORDINATION_STORAGE_INVALID" },
      hostile.label,
    );
    assert.equal(injected, true, hostile.label);
    await hostile.prepare(root);

    let exposedStore;
    t.after(() => exposedStore?.close().catch(() => {}));
    await assert.rejects(
      async () => {
        exposedStore = await openCoordinationStore({
          repositorySha: REPOSITORY_SHA,
          root,
        });
      },
      { code: "COORDINATION_STORAGE_INVALID" },
      hostile.label,
    );
    assert.equal(exposedStore, undefined, hostile.label);
  }
});

test("publishes artifacts only after a complete synced temporary write and recovers an interrupted retry", async (t) => {
  const root = await privateRoot(t);
  const bytes = signedDescriptorBytes();
  const digest = sha256(bytes);
  const temporary = `.${digest}.tmp`;
  let interruptArtifact = true;
  const fileSystem = testFileSystem({
    async open(path, flags, mode) {
      const handle = await open(path, flags, mode);
      if (
        interruptArtifact &&
        path.endsWith(`/${temporary}`)
      ) {
        return handleFacade(handle, {
          async writeFile(value) {
            interruptArtifact = false;
            await handle.writeFile(
              value.subarray(0, Math.max(1, value.length >> 1)),
            );
            throw new Error("injected artifact interruption");
          },
        });
      }
      return handleFacade(handle);
    },
  });
  const store = await openCoordinationStore({
    fileSystem,
    repositorySha: REPOSITORY_SHA,
    root,
  });
  await assert.rejects(
    store.putArtifact({
      artifactType: "signed-descriptor",
      bytes,
      expectedDigest: digest,
      secretCanaries: [],
    }),
    { code: "COORDINATION_STORAGE_INVALID" },
  );
  await assert.rejects(
    lstat(join(root, "artifacts", digest.slice(0, 2), digest)),
    { code: "ENOENT" },
  );
  await store.close().catch(() => {});

  const reopened = await openCoordinationStore({
    repositorySha: REPOSITORY_SHA,
    root,
  });
  t.after(() => reopened.close().catch(() => {}));
  await reopened.putArtifact({
    artifactType: "signed-descriptor",
    bytes,
    expectedDigest: digest,
    secretCanaries: [],
  });
  assert.deepEqual(await reopened.getArtifact(digest), bytes);
  await assert.rejects(
    lstat(
      join(
        root,
        "artifacts",
        digest.slice(0, 2),
        temporary,
      ),
    ),
    { code: "ENOENT" },
  );
});

test("owner pathname loss is detected and the surviving guard blocks another opener", async (t) => {
  const { root, store } = await storeFixture(t);
  await unlink(join(root, ".store-owner.json"));
  await assert.rejects(
    store.readReleaseView({ sessionId: SESSION_ID }),
    { code: "COORDINATION_STORAGE_INVALID" },
  );

  const moduleUrl = new URL(
    "../src/bilateral/coordination/storage.mjs",
    import.meta.url,
  ).href;
  const childSource = `
    import { openCoordinationStore } from ${JSON.stringify(moduleUrl)};
    try {
      const store = await openCoordinationStore({
        repositorySha: ${JSON.stringify(REPOSITORY_SHA)},
        root: ${JSON.stringify(root)},
      });
      await store.close();
      process.stdout.write("OPENED");
    } catch (error) {
      process.stdout.write(error?.code ?? "UNKNOWN");
    }
  `;
  const child = await import("node:child_process");
  const result = await new Promise((resolve, reject) => {
    child.execFile(
      process.execPath,
      ["--input-type=module", "--eval", childSource],
      { encoding: "utf8" },
      (error, stdout, stderr) => {
        if (error) {
          reject(error);
          return;
        }
        resolve({ stderr, stdout });
      },
    );
  });
  assert.equal(result.stdout, "COORDINATION_STORAGE_INVALID");
  assert.equal(result.stderr, "");
});

test("uses bounded handle reads instead of unbounded readFile calls", async (t) => {
  const root = await privateRoot(t);
  const created = await openCoordinationStore({
    repositorySha: REPOSITORY_SHA,
    root,
  });
  await created.close();

  let readCalls = 0;
  let readFileCalls = 0;
  const fileSystem = testFileSystem({
    async open(path, flags, mode) {
      const handle = await open(path, flags, mode);
      return handleFacade(handle, {
        async read(...arguments_) {
          readCalls += 1;
          return handle.read(...arguments_);
        },
        async readFile() {
          readFileCalls += 1;
          throw new Error("unbounded readFile is forbidden");
        },
      });
    },
  });
  const reopened = await openCoordinationStore({
    fileSystem,
    repositorySha: REPOSITORY_SHA,
    root,
  });
  await reopened.close();
  assert.ok(readCalls > 0);
  assert.equal(readFileCalls, 0);
});

test("an operation admitted before close completes while later operations reject", async (t) => {
  const { store } = await storeFixture(t);
  const admitted = register(store);
  const closing = store.close();
  assert.deepEqual(await admitted, {
    capabilityDigest: sha256(RAW_CAPABILITY),
    expiresAtMs: String(NOW_MS + 60_000),
    releaseId: RELEASE_ID,
    role: "payer",
    sessionId: SESSION_ID,
  });
  await closing;
  await assert.rejects(
    store.readReleaseView({ sessionId: SESSION_ID }),
    { code: "COORDINATION_STORAGE_CLOSED" },
  );
});

test("keeps hostile snapshot temporary path types fail-closed", async (t) => {
  for (const kind of ["symlink", "mode"]) {
    const root = await privateRoot(t);
    const store = await openCoordinationStore({
      repositorySha: REPOSITORY_SHA,
      root,
    });
    await store.close();
    const temporary = join(root, ".snapshot.tmp");
    if (kind === "symlink") {
      await symlink(join(root, "snapshot.json"), temporary);
    } else {
      await writeFile(temporary, Buffer.from("{}"), {
        mode: 0o644,
      });
    }
    await assert.rejects(
      openCoordinationStore({
        repositorySha: REPOSITORY_SHA,
        root,
      }),
      { code: "COORDINATION_STORAGE_INVALID" },
      kind,
    );
  }
});

test("recovers a fully verified artifact linked before an interrupted directory sync", async (t) => {
  const root = await privateRoot(t);
  const bytes = signedDescriptorBytes();
  const digest = sha256(bytes);
  const prefixPath = join(
    root,
    "artifacts",
    digest.slice(0, 2),
  );
  let linked = false;
  let interrupted = false;
  const fileSystem = testFileSystem({
    async link(from, to) {
      const result = await link(from, to);
      if (to === join(prefixPath, digest)) {
        linked = true;
      }
      return result;
    },
    async open(path, flags, mode) {
      const handle = await open(path, flags, mode);
      if (path !== prefixPath) {
        return handleFacade(handle);
      }
      return handleFacade(handle, {
        async sync() {
          await handle.sync();
          if (linked && !interrupted) {
            interrupted = true;
            throw new Error(
              "injected artifact publication interruption",
            );
          }
        },
      });
    },
  });
  const store = await openCoordinationStore({
    fileSystem,
    repositorySha: REPOSITORY_SHA,
    root,
  });
  await assert.rejects(
    store.putArtifact({
      artifactType: "signed-descriptor",
      bytes,
      expectedDigest: digest,
      secretCanaries: [],
    }),
    { code: "COORDINATION_STORAGE_INVALID" },
  );
  assert.equal(interrupted, true);
  await store.close().catch(() => {});

  const reopened = await openCoordinationStore({
    repositorySha: REPOSITORY_SHA,
    root,
  });
  t.after(() => reopened.close().catch(() => {}));
  assert.deepEqual(await reopened.getArtifact(digest), bytes);
  assert.deepEqual(
    await readdir(prefixPath),
    [digest],
  );
});

test("rejects same-inode growth using a maximum-plus-one read", async (t) => {
  const root = await privateRoot(t);
  const store = await openCoordinationStore({
    repositorySha: REPOSITORY_SHA,
    root,
  });
  await store.close();
  const metadataPath = join(root, "metadata.json");
  let grew = false;
  let maximumRequested = 0;
  const fileSystem = testFileSystem({
    async open(path, flags, mode) {
      const handle = await open(path, flags, mode);
      if (path !== metadataPath) {
        return handleFacade(handle);
      }
      return handleFacade(handle, {
        async read(buffer, offset, length, position) {
          maximumRequested = Math.max(
            maximumRequested,
            length,
          );
          if (!grew) {
            grew = true;
            await appendFile(
              metadataPath,
              Buffer.alloc(5_000, 0x61),
            );
          }
          return handle.read(
            buffer,
            offset,
            length,
            position,
          );
        },
      });
    },
  });
  await assert.rejects(
    openCoordinationStore({
      fileSystem,
      repositorySha: REPOSITORY_SHA,
      root,
    }),
    { code: "COORDINATION_STORAGE_INVALID" },
  );
  assert.equal(grew, true);
  assert.equal(maximumRequested, 4_097);
});

test("detects mutation immediately after the journal fsync and leaves the torn journal fail-closed", async (t) => {
  const root = await privateRoot(t);
  const journalPath = join(root, "journal.log");
  let armed = false;
  let mutated = false;
  const fileSystem = testFileSystem({
    async open(path, flags, mode) {
      const handle = await open(path, flags, mode);
      if (
        path !== journalPath ||
        (flags & fsConstants.O_APPEND) === 0
      ) {
        return handleFacade(handle);
      }
      return handleFacade(handle, {
        async sync() {
          await handle.sync();
          if (armed && !mutated) {
            mutated = true;
            await appendFile(
              journalPath,
              Buffer.from([0xff]),
            );
          }
        },
      });
    },
  });
  const store = await openCoordinationStore({
    fileSystem,
    repositorySha: REPOSITORY_SHA,
    root,
  });
  armed = true;
  await assert.rejects(register(store), {
    code: "COORDINATION_STORAGE_INVALID",
  });
  assert.equal(mutated, true);
  await store.close().catch(() => {});
  await assert.rejects(
    openCoordinationStore({
      repositorySha: REPOSITORY_SHA,
      root,
    }),
    { code: "COORDINATION_STORAGE_INVALID" },
  );
});

test("detects same-length journal mutation after fsync before acknowledging the append", async (t) => {
  const root = await privateRoot(t);
  const journalPath = join(root, "journal.log");
  let armed = false;
  let mutated = false;
  const fileSystem = testFileSystem({
    async open(path, flags, mode) {
      const handle = await open(path, flags, mode);
      if (
        path !== journalPath ||
        (flags & fsConstants.O_APPEND) === 0
      ) {
        return handleFacade(handle);
      }
      return handleFacade(handle, {
        async sync() {
          await handle.sync();
          if (armed && !mutated) {
            mutated = true;
            const mutator = await open(
              journalPath,
              fsConstants.O_RDWR,
            );
            try {
              const byte = Buffer.alloc(1);
              await mutator.read(byte, 0, 1, 8);
              byte[0] ^= 0x01;
              await mutator.write(byte, 0, 1, 8);
              await mutator.sync();
            } finally {
              await mutator.close();
            }
          }
        },
      });
    },
  });
  const store = await openCoordinationStore({
    fileSystem,
    repositorySha: REPOSITORY_SHA,
    root,
  });
  armed = true;
  await assert.rejects(register(store), {
    code: "COORDINATION_STORAGE_INVALID",
  });
  assert.equal(mutated, true);
  await store.close().catch(() => {});
  await assert.rejects(
    openCoordinationStore({
      repositorySha: REPOSITORY_SHA,
      root,
    }),
    { code: "COORDINATION_STORAGE_INVALID" },
  );
});

test("atomically journals a verified event with its exact verifier publication", async (t) => {
  const { root, store } = await storeFixture(t);
  const eventValue = event({
    digest: "a".repeat(64),
    kind: "VERIFICATION_PASSED",
    role: "operator",
    subjectRun: "rehearsal",
  });
  const publication = {
    paymentMoved: false,
    publicationDigest: eventValue.artifactDigest,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    schema: "clockchain.bilateral-verifier-publication/v1",
    sessionId: SESSION_ID,
    status: "VERIFICATION_PASSED",
    subjectRun: "rehearsal",
  };

  assert.deepEqual(
    await store.appendVerifiedEvent({ event: eventValue, publication }),
    eventValue,
  );
  assert.deepEqual(
    await store.appendVerifiedEvent({ event: eventValue, publication }),
    eventValue,
  );
  assert.deepEqual(
    await store.readVerifierPublication({
      sessionId: SESSION_ID,
      subjectRun: "rehearsal",
    }),
    publication,
  );
  await assert.rejects(
    store.appendVerifiedEvent({
      event: eventValue,
      publication: { ...publication, publicationDigest: "b".repeat(64) },
    }),
    { code: "COORDINATION_STORAGE_INVALID" },
  );
  await store.close();
  await assert.rejects(
    store.readVerifierPublication({
      sessionId: SESSION_ID,
      subjectRun: "rehearsal",
    }),
    { code: "COORDINATION_STORAGE_CLOSED" },
  );

  const restarted = await openCoordinationStore({
    now: () => NOW_MS,
    repositorySha: REPOSITORY_SHA,
    root,
  });
  t.after(() => restarted.close().catch(() => {}));
  assert.deepEqual(
    await restarted.readEvents({ after: null, sessionId: SESSION_ID }),
    [eventValue],
  );
  assert.deepEqual(
    await restarted.readVerifierPublication({
      sessionId: SESSION_ID,
      subjectRun: "rehearsal",
    }),
    publication,
  );
  const journal = await readFile(join(root, "journal.log"), "utf8");
  assert.equal(journal.includes("VERIFIED_EVENT_APPENDED"), true);
});
