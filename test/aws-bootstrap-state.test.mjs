import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  createHash,
  generateKeyPairSync,
  X509Certificate,
} from "node:crypto";
import {
  mkdtempSync,
  readFileSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  approveBootstrapClaimState,
  bootstrapStateClaim,
  consumeBootstrapClaim,
  createBootstrapState,
  expireBootstrapClaim,
  rejectBootstrapClaim,
  requestorBootstrapClaimFingerprint,
  sealBootstrapClaim,
  submitPayerBootstrapClaim,
  submitRequestorBootstrapClaim,
  validateBootstrapState,
} from "../src/bilateral/aws/bootstrap-state.mjs";
import {
  createPayerBootstrapKey,
  payerBootstrapClaimFingerprint,
  sshEd25519Fingerprint,
} from "../src/bilateral/local-mcp/payer-bootstrap-envelope.mjs";
import {
  createRequestorBootstrapKey,
} from "../src/bilateral/local-mcp/bootstrap-envelope.mjs";

const REPOSITORY_SHA = "abcdef0123456789abcdef0123456789abcdef01";
const RELEASE_ID = "release-aws-bootstrap";
const SESSION_ID = "22222222-2222-4222-8222-222222222222";
const NOW = 2_000_000_000_000;
const POLL_DIGEST = "a".repeat(64);
const BROKER_DIGEST = "b".repeat(64);

function certificatePem() {
  const root = mkdtempSync(join(tmpdir(), "aws-bootstrap-state-"));
  try {
    const certificatePath = join(root, "payer.crt");
    const privateKeyPath = join(root, "payer.key");
    execFileSync("openssl", [
      "req", "-x509", "-newkey", "ed25519",
      "-keyout", privateKeyPath,
      "-out", certificatePath,
      "-nodes", "-days", "1",
      "-subj", "/CN=payer.clockchain.network",
      "-addext", "subjectAltName=DNS:payer.clockchain.network",
    ], { stdio: "ignore" });
    return readFileSync(certificatePath, "utf8");
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
}

const CERTIFICATE_PEM = certificatePem();

function sshString(value) {
  const bytes = Buffer.from(value);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

function openSshPublicKey(pair) {
  const raw = pair.publicKey
    .export({ format: "der", type: "spki" })
    .subarray(-32);
  return `ssh-ed25519 ${Buffer.concat([
    sshString("ssh-ed25519"),
    sshString(raw),
  ]).toString("base64")}`;
}

function payerClaim(overrides = {}) {
  const bootstrap = createPayerBootstrapKey();
  const ssh = generateKeyPairSync("ed25519");
  const sshPublicKey = openSshPublicKey(ssh);
  return {
    claimNonce: "11111111-1111-4111-8111-111111111111",
    mcpTlsCertificatePem: CERTIFICATE_PEM,
    mcpTlsFingerprint: createHash("sha256")
      .update(new X509Certificate(CERTIFICATE_PEM).raw)
      .digest("hex"),
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    role: "payer",
    schema: "clockchain.payer-bootstrap-claim/v1",
    sessionId: SESSION_ID,
    sshPublicKey,
    sshPublicKeyFingerprint: sshEd25519Fingerprint(sshPublicKey),
    x25519PublicKey: bootstrap.publicKey,
    ...overrides,
  };
}

function requestorClaim(overrides = {}) {
  return {
    claimNonce: "33333333-3333-4333-8333-333333333333",
    paymentMoved: false,
    repositorySha: REPOSITORY_SHA,
    requestorPublicKey: createRequestorBootstrapKey().publicKey,
    ...overrides,
  };
}

function initialState() {
  return createBootstrapState({
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    schema: "clockchain.aws-bootstrap-state/v1",
    sessionId: SESSION_ID,
  });
}

test("moves one Payer claim through PENDING, APPROVED, SEALED, and CONSUMED", () => {
  const claim = payerClaim();
  const fingerprint = payerBootstrapClaimFingerprint(claim);
  const pending = submitPayerBootstrapClaim({
    authCapabilityDigest: POLL_DIGEST,
    claim,
    expectedRevision: "0",
    expiresAtMs: String(NOW + 60_000),
    nowMs: NOW,
    state: initialState(),
  });
  assert.equal(pending.revision, "1");
  assert.equal(bootstrapStateClaim({
    authCapabilityDigest: POLL_DIGEST,
    claimFingerprint: fingerprint,
    nowMs: NOW,
    state: pending,
  }).status, "PENDING");

  const approved = approveBootstrapClaimState({
    claimFingerprint: fingerprint,
    expectedRevision: "1",
    nowMs: NOW + 1,
    state: pending,
  });
  assert.equal(approved.claims[fingerprint].status, "APPROVED");

  const responseBytes = Buffer.from(JSON.stringify({
    claimFingerprint: fingerprint,
    paymentMoved: false,
    schema: "clockchain.payer-bootstrap-response/v1",
    status: "SEALED",
  }));
  const sealed = sealBootstrapClaim({
    claimFingerprint: fingerprint,
    expectedRevision: "2",
    nowMs: NOW + 2,
    responseBytes,
    state: approved,
  });
  assert.equal(sealed.claims[fingerprint].status, "SEALED");
  assert.equal(
    Buffer.from(
      bootstrapStateClaim({
        authCapabilityDigest: POLL_DIGEST,
        claimFingerprint: fingerprint,
        nowMs: NOW + 3,
        state: sealed,
      }).sealedResponseBase64,
      "base64",
    ).equals(responseBytes),
    true,
  );

  const consumed = consumeBootstrapClaim({
    authCapabilityDigest: POLL_DIGEST,
    claimFingerprint: fingerprint,
    expectedRevision: "3",
    nowMs: NOW + 4,
    state: sealed,
  });
  assert.equal(consumed.claims[fingerprint].status, "CONSUMED");
  assert.equal(consumed.paymentMoved, false);
  assert.deepEqual(
    consumeBootstrapClaim({
      authCapabilityDigest: POLL_DIGEST,
      claimFingerprint: fingerprint,
      expectedRevision: "4",
      nowMs: NOW + 5,
      state: consumed,
    }),
    consumed,
  );
});

test("keeps Requestor v1 claim bytes distinct and capability-authenticated", () => {
  const claim = requestorClaim();
  const pending = submitRequestorBootstrapClaim({
    authCapabilityDigest: BROKER_DIGEST,
    claim,
    expectedRevision: "0",
    expiresAtMs: String(NOW + 60_000),
    nowMs: NOW,
    releaseId: RELEASE_ID,
    sessionId: SESSION_ID,
    state: initialState(),
  });
  const [fingerprint] = Object.keys(pending.claims);
  const entry = bootstrapStateClaim({
    authCapabilityDigest: BROKER_DIGEST,
    claimFingerprint: fingerprint,
    nowMs: NOW,
    state: pending,
  });
  assert.equal(entry.role, "requestor");
  assert.deepEqual(entry.claim, claim);
  assert.throws(
    () => bootstrapStateClaim({
      authCapabilityDigest: POLL_DIGEST,
      claimFingerprint: fingerprint,
      nowMs: NOW,
      state: pending,
    }),
    /AWS bootstrap state failed safely/,
  );
});

test("supports PENDING to REJECTED and PENDING or APPROVED to EXPIRED", () => {
  for (const terminal of ["REJECTED", "EXPIRED_PENDING", "EXPIRED_APPROVED"]) {
    const claim = payerClaim({
      claimNonce:
        terminal === "REJECTED"
          ? "11111111-1111-4111-8111-111111111111"
          : terminal === "EXPIRED_PENDING"
            ? "22222222-2222-4222-8222-222222222222"
            : "33333333-3333-4333-8333-333333333333",
    });
    let state = submitPayerBootstrapClaim({
      authCapabilityDigest: POLL_DIGEST,
      claim,
      expectedRevision: "0",
      expiresAtMs: String(NOW + 10),
      nowMs: NOW,
      state: initialState(),
    });
    const fingerprint = Object.keys(state.claims)[0];
    if (terminal === "EXPIRED_APPROVED") {
      state = approveBootstrapClaimState({
        claimFingerprint: fingerprint,
        expectedRevision: "1",
        nowMs: NOW + 1,
        state,
      });
    }
    state = terminal === "REJECTED"
      ? rejectBootstrapClaim({
        claimFingerprint: fingerprint,
        expectedRevision: "1",
        nowMs: NOW + 1,
        state,
      })
      : expireBootstrapClaim({
        claimFingerprint: fingerprint,
        expectedRevision:
          terminal === "EXPIRED_APPROVED" ? "2" : "1",
        nowMs: NOW + 10,
        state,
      });
    assert.equal(
      state.claims[fingerprint].status,
      terminal === "REJECTED" ? "REJECTED" : "EXPIRED",
    );
    assert.equal(state.claims[fingerprint].paymentMoved, false);
  }
});

test("enforces revision, one role claim per session, single sealing, and byte-identical retry", () => {
  const claim = payerClaim();
  const pending = submitPayerBootstrapClaim({
    authCapabilityDigest: POLL_DIGEST,
    claim,
    expectedRevision: "0",
    expiresAtMs: String(NOW + 60_000),
    nowMs: NOW,
    state: initialState(),
  });
  assert.deepEqual(
    submitPayerBootstrapClaim({
      authCapabilityDigest: POLL_DIGEST,
      claim,
      expectedRevision: "1",
      expiresAtMs: String(NOW + 60_000),
      nowMs: NOW + 1,
      state: pending,
    }),
    pending,
  );
  for (const input of [
    { expectedRevision: "0", state: pending },
    {
      claim: payerClaim({
        claimNonce: "44444444-4444-4444-8444-444444444444",
      }),
      expectedRevision: "1",
      state: pending,
    },
    {
      claim: payerClaim({
        sessionId: "55555555-5555-4555-8555-555555555555",
      }),
      expectedRevision: "1",
      state: pending,
    },
  ]) {
    assert.throws(
      () => submitPayerBootstrapClaim({
        authCapabilityDigest: POLL_DIGEST,
        claim,
        expiresAtMs: String(NOW + 60_000),
        nowMs: NOW + 1,
        ...input,
      }),
      /AWS bootstrap state failed safely/,
    );
  }

  const fingerprint = Object.keys(pending.claims)[0];
  const approved = approveBootstrapClaimState({
    claimFingerprint: fingerprint,
    expectedRevision: "1",
    nowMs: NOW + 1,
    state: pending,
  });
  const bytes = Buffer.from(JSON.stringify({
    paymentMoved: false,
    status: "SEALED",
  }));
  const sealed = sealBootstrapClaim({
    claimFingerprint: fingerprint,
    expectedRevision: "2",
    nowMs: NOW + 2,
    responseBytes: bytes,
    state: approved,
  });
  assert.deepEqual(
    sealBootstrapClaim({
      claimFingerprint: fingerprint,
      expectedRevision: "3",
      nowMs: NOW + 3,
      responseBytes: bytes,
      state: sealed,
    }),
    sealed,
  );
  assert.throws(
    () => sealBootstrapClaim({
      claimFingerprint: fingerprint,
      expectedRevision: "3",
      nowMs: NOW + 3,
      responseBytes: Buffer.from('{"paymentMoved":false,"status":"CHANGED"}'),
      state: sealed,
    }),
    /AWS bootstrap state failed safely/,
  );
});

test("rejects malformed, expired, mismatched, moved-payment, and secret-bearing state inputs", () => {
  const claim = payerClaim();
  for (const override of [
    { authCapabilityDigest: "bad" },
    { claim: { ...claim, paymentMoved: true } },
    { claim: { ...claim, repositorySha: "b".repeat(40) } },
    { expiresAtMs: String(NOW) },
    { expectedRevision: "1" },
    { nowMs: -1 },
  ]) {
    assert.throws(
      () => submitPayerBootstrapClaim({
        authCapabilityDigest: POLL_DIGEST,
        claim,
        expectedRevision: "0",
        expiresAtMs: String(NOW + 60_000),
        nowMs: NOW,
        state: initialState(),
        ...override,
      }),
      /AWS bootstrap state failed safely/,
    );
  }
  assert.equal(
    JSON.stringify(
      submitPayerBootstrapClaim({
        authCapabilityDigest: POLL_DIGEST,
        claim,
        expectedRevision: "0",
        expiresAtMs: String(NOW + 60_000),
        nowMs: NOW,
        state: initialState(),
      }),
    ).includes("raw-capability"),
    false,
  );
});

test("validates a durable state snapshot without changing its canonical bytes", () => {
  const state = initialState();
  assert.deepEqual(validateBootstrapState(state), state);
  assert.throws(
    () => validateBootstrapState({
      ...state,
      extra: "not-authority",
    }),
    /AWS bootstrap state failed safely/,
  );
  assert.throws(
    () => createBootstrapState({
      paymentMoved: false,
      releaseId: RELEASE_ID,
      repositorySha: REPOSITORY_SHA,
      schema: "clockchain.aws-bootstrap-state/v1",
      sessionId:
        "22222222-2222-1222-8222-222222222222",
    }),
    /AWS bootstrap state failed safely/,
  );
});

test("rejects durable revision gaps and duplicate role claims", () => {
  const firstClaim = requestorClaim();
  const pending = submitRequestorBootstrapClaim({
    authCapabilityDigest: BROKER_DIGEST,
    claim: firstClaim,
    expectedRevision: "0",
    expiresAtMs: String(NOW + 60_000),
    nowMs: NOW,
    releaseId: RELEASE_ID,
    sessionId: SESSION_ID,
    state: initialState(),
  });
  for (const revision of ["0", "2"]) {
    assert.throws(
      () => validateBootstrapState({
        ...pending,
        revision,
      }),
      /AWS bootstrap state failed safely/,
    );
  }

  const firstFingerprint =
    requestorBootstrapClaimFingerprint(firstClaim);
  const secondClaim = requestorClaim({
    claimNonce:
      "44444444-4444-4444-8444-444444444444",
  });
  const secondFingerprint =
    requestorBootstrapClaimFingerprint(secondClaim);
  assert.throws(
    () => validateBootstrapState({
      ...pending,
      claims: {
        [firstFingerprint]:
          pending.claims[firstFingerprint],
        [secondFingerprint]: {
          ...pending.claims[firstFingerprint],
          claim: secondClaim,
          claimFingerprint: secondFingerprint,
        },
      },
    }),
    /AWS bootstrap state failed safely/,
  );
});
