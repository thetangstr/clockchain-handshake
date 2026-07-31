import assert from "node:assert/strict";
import { test } from "node:test";

import {
  parseRuntimeInput,
} from "../infra/aws/runtime/runtime-input.mjs";
import {
  buildCoordinatorRuntimeInput,
  buildFundingRuntimeInput,
  buildVerifierRuntimeInput,
} from "../infra/aws/runtime/operator-task-inputs.mjs";

const RELEASE_ID = "release-bd7662a5eeb41614";
const REPOSITORY_SHA =
  "abcdef0123456789abcdef0123456789abcdef01";
const SESSION_ID =
  "11111111-1111-4111-8111-111111111111";
const TREASURY_ADDRESS =
  "0x157a377e4181f3f87c7f6efed5ddc340ccc00dce";
const ATTEMPT_ID =
  "22222222-2222-4222-8222-222222222222";
const OPERATOR_RELEASE_ROOT =
  `/var/lib/clockchain/operator/releases/${RELEASE_ID}`;
const FUNDING_RECORD_ROOT =
  `/var/lib/clockchain/funding-record/releases/${RELEASE_ID}`;
const FUNDING_JOURNAL_ROOT =
  `/var/lib/clockchain/funding-journal/releases/${RELEASE_ID}`;
const EVIDENCE_ROOT =
  `/var/lib/clockchain/evidence/releases/${RELEASE_ID}`;
const VERIFIER_OUTPUT_ROOT =
  `/var/lib/clockchain/verifier-output/releases/${RELEASE_ID}`;

function coordinatorInput(overrides = {}) {
  return {
    clockchainTokenSecretArn:
      "arn:aws:secretsmanager:us-west-2:123456789012:secret:clockchain-token",
    operatorKeyId:
      "operator-key-release-bd7662a5eeb41614",
    operatorKeySecretArn:
      "arn:aws:secretsmanager:us-west-2:123456789012:secret:operator-key",
    paymentMoved: false,
    releaseId: RELEASE_ID,
    releaseRoot: OPERATOR_RELEASE_ROOT,
    relayUrl: "https://relay.clockchain.net:8443",
    repositorySha: REPOSITORY_SHA,
    rpcSecretArn:
      "arn:aws:secretsmanager:us-west-2:123456789012:secret:rpc-url",
    sessionId: SESSION_ID,
    tlsCertificatePath:
      `${OPERATOR_RELEASE_ROOT}/tls/relay-ca.pem`,
    tlsFingerprint: "b".repeat(64),
    ...overrides,
  };
}

function fundingInput(overrides = {}) {
  return {
    createdAt: "2026-07-31T00:00:00.000Z",
    expectedTreasuryAddress: TREASURY_ADDRESS,
    fundingRecordPath:
      `${FUNDING_RECORD_ROOT}/funding-record.json`,
    journalDirectory:
      `${FUNDING_JOURNAL_ROOT}/journal`,
    keystoreSecretArn:
      "arn:aws:secretsmanager:us-west-2:123456789012:secret:treasury-keystore",
    passwordSecretArn:
      "arn:aws:secretsmanager:us-west-2:123456789012:secret:treasury-password",
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    rpcSecretArn:
      "arn:aws:secretsmanager:us-west-2:123456789012:secret:rpc-url",
    sessionId: SESSION_ID,
    ...overrides,
  };
}

function verifierInput(overrides = {}) {
  return {
    actionAtMs: 2_000_000_000_000,
    attemptId: ATTEMPT_ID,
    attemptRoot:
      `${VERIFIER_OUTPUT_ROOT}/attempts/${ATTEMPT_ID}`,
    clockchainTokenSecretArn:
      "arn:aws:secretsmanager:us-west-2:123456789012:secret:clockchain-token",
    descriptorPath:
      `${EVIDENCE_ROOT}/rehearsal/descriptor.json`,
    evidenceDigest: "d".repeat(64),
    expectedRevision: 5,
    mandateDigest: "e".repeat(64),
    payerMandatePath:
      `${EVIDENCE_ROOT}/rehearsal/payer-mandate.json`,
    payeeResultsPath:
      `${EVIDENCE_ROOT}/payee/results`,
    payerResultsPath:
      `${EVIDENCE_ROOT}/payer/results`,
    paymentMoved: false,
    paymentRequestPath:
      `${EVIDENCE_ROOT}/rehearsal/payment-request.json`,
    publicationPath:
      `${VERIFIER_OUTPUT_ROOT}/public/verifier-publication.json`,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    requestDigest: "f".repeat(64),
    rpcSecretArn:
      "arn:aws:secretsmanager:us-west-2:123456789012:secret:rpc-url",
    sessionDigest: "a".repeat(64),
    sessionId: SESSION_ID,
    ...overrides,
  };
}

function assertCanonicalRuntimeInput(value) {
  const text = JSON.stringify(value);
  assert.deepEqual(
    parseRuntimeInput({
      AWS_RUNTIME_INPUT: text,
    }),
    value,
  );
  assert.equal(
    Object.getPrototypeOf(value),
    Object.prototype,
  );
  assert.deepEqual(
    Object.keys(value),
    [...Object.keys(value)].sort(),
  );
  assert.equal(text, JSON.stringify(JSON.parse(text)));
  assert.doesNotMatch(
    text,
    /raw-secret-canary|raw-token-canary|private-key-canary|capability-canary|invitation-canary|https:\/\/rpc\.secret/u,
  );
}

function reordered(value) {
  return Object.fromEntries(
    Object.entries(value).reverse(),
  );
}

function without(value, omittedKey) {
  return Object.fromEntries(
    Object.entries(value).filter(
      ([key]) => key !== omittedKey,
    ),
  );
}

function accessorClone(value, key) {
  const clone = { ...value };
  Object.defineProperty(clone, key, {
    enumerable: true,
    get() {
      assert.fail("builder must reject accessors before getter invocation");
    },
  });
  return clone;
}

function coercibleString(value, calls) {
  return {
    get toString() {
      calls.count += 1;
      return () => value;
    },
    valueOf() {
      calls.count += 1;
      return value;
    },
  };
}

test("builds exact canonical coordinator, funding, and verifier runtime inputs accepted by parseRuntimeInput", () => {
  const coordinator =
    buildCoordinatorRuntimeInput(
      coordinatorInput({
        clockchainTokenSecretArn:
          "arn:aws:secretsmanager:us-west-2:123456789012:secret:token-canary-secret",
      }),
    );
  assert.deepEqual(coordinator, {
    coordinator: {
      clockchainTokenSecretArn:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:token-canary-secret",
      operatorKeyId:
        "operator-key-release-bd7662a5eeb41614",
      operatorKeySecretArn:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:operator-key",
      releaseIdentity: {
        releaseId: RELEASE_ID,
        sessionId: SESSION_ID,
      },
      releaseRoot: OPERATOR_RELEASE_ROOT,
      relayUrl: "https://relay.clockchain.net:8443",
      repositorySha: REPOSITORY_SHA,
      rpcSecretArn:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:rpc-url",
      tlsCertificatePath:
        `${OPERATOR_RELEASE_ROOT}/tls/relay-ca.pem`,
      tlsFingerprint: "b".repeat(64),
    },
    paymentMoved: false,
    schema: "clockchain.aws-runtime-input/v1",
  });
  assertCanonicalRuntimeInput(coordinator);

  const funding = buildFundingRuntimeInput(
    fundingInput({
      keystoreSecretArn:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:secret-canary-keystore",
      passwordSecretArn:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:secret-canary-password",
    }),
  );
  assert.deepEqual(funding, {
    funding: {
      createdAt: "2026-07-31T00:00:00.000Z",
      expectedTreasuryAddress:
        TREASURY_ADDRESS,
      fundingRecordPath:
        `${FUNDING_RECORD_ROOT}/funding-record.json`,
      journalDirectory:
        `${FUNDING_JOURNAL_ROOT}/journal`,
      keystoreSecretArn:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:secret-canary-keystore",
      passwordSecretArn:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:secret-canary-password",
      repositorySha: REPOSITORY_SHA,
      rpcSecretArn:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:rpc-url",
    },
    paymentMoved: false,
    schema: "clockchain.aws-runtime-input/v1",
  });
  assertCanonicalRuntimeInput(funding);

  const verifier = buildVerifierRuntimeInput(
    verifierInput({
      clockchainTokenSecretArn:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:token-canary-secret",
    }),
  );
  assert.deepEqual(verifier, {
    paymentMoved: false,
    schema: "clockchain.aws-runtime-input/v1",
    verifier: {
      actionAtMs: 2_000_000_000_000,
      attemptId: ATTEMPT_ID,
      attemptRoot:
        `${VERIFIER_OUTPUT_ROOT}/attempts/${ATTEMPT_ID}`,
      clockchainTokenSecretArn:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:token-canary-secret",
      descriptorPath:
        `${EVIDENCE_ROOT}/rehearsal/descriptor.json`,
      evidenceDigest: "d".repeat(64),
      expectedRevision: 5,
      mandateDigest: "e".repeat(64),
      payerMandatePath:
        `${EVIDENCE_ROOT}/rehearsal/payer-mandate.json`,
      payeeResultsPath:
        `${EVIDENCE_ROOT}/payee/results`,
      payerResultsPath:
        `${EVIDENCE_ROOT}/payer/results`,
      paymentRequestPath:
        `${EVIDENCE_ROOT}/rehearsal/payment-request.json`,
      publicationPath:
        `${VERIFIER_OUTPUT_ROOT}/public/verifier-publication.json`,
      repositorySha: REPOSITORY_SHA,
      requestDigest: "f".repeat(64),
      rpcSecretArn:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:rpc-url",
      sessionDigest: "a".repeat(64),
    },
  });
  assertCanonicalRuntimeInput(verifier);
});

test("rejects unknown, reordered, accessor, proxy, sensitive, and scope-mismatched task inputs", () => {
  for (const [builder, input] of [
    [
      buildCoordinatorRuntimeInput,
      coordinatorInput(),
    ],
    [buildFundingRuntimeInput, fundingInput()],
    [buildVerifierRuntimeInput, verifierInput()],
  ]) {
    for (const candidate of [
      { ...input, z: "unknown" },
      reordered(input),
      accessorClone(input, "repositorySha"),
      new Proxy(input, {}),
      { ...input, paymentMoved: true },
      {
        ...input,
        releaseId:
          "release-0000000000000000",
      },
      {
        ...input,
        repositorySha: "a".repeat(39),
      },
      {
        ...input,
        sessionId:
          "77777777-7777-4777-8777-777777777777",
      },
      { ...input, token: "token-canary" },
      {
        ...input,
        privateKey: "private-key-canary",
      },
      {
        ...input,
        capability: "capability-canary",
      },
      {
        ...input,
        invitation: "invitation-canary",
      },
      { ...input, secret: "secret-canary" },
    ]) {
      assert.throws(
        () => builder(candidate),
        /AWS operator task input failed safely/,
      );
    }
  }
});

test("builders reject object-valued regex fields without string coercion hooks", () => {
  for (const [builder, input] of [
    [
      buildCoordinatorRuntimeInput,
      coordinatorInput,
    ],
    [buildFundingRuntimeInput, fundingInput],
    [buildVerifierRuntimeInput, verifierInput],
  ]) {
    const calls = { count: 0 };
    assert.throws(
      () =>
        builder(
          input({
            repositorySha: coercibleString(
              REPOSITORY_SHA,
              calls,
            ),
          }),
        ),
      /AWS operator task input failed safely/,
    );
    assert.equal(calls.count, 0);
  }

  const calls = { count: 0 };
  assert.throws(
    () =>
      buildFundingRuntimeInput(
        fundingInput({
          expectedTreasuryAddress:
            coercibleString(
              TREASURY_ADDRESS,
              calls,
            ),
        }),
      ),
    /AWS operator task input failed safely/,
  );
  assert.equal(calls.count, 0);
});

test("coordinator builder rejects unsafe typed production fields", () => {
  for (const candidate of [
    { ...coordinatorInput(), argv: ["--release-root", OPERATOR_RELEASE_ROOT] },
    {
      ...coordinatorInput(),
      operatorKeyId: "operator key",
    },
    {
      ...coordinatorInput(),
      operatorKeyId: "Operator-Key",
    },
    {
      ...coordinatorInput(),
      operatorKeyId: "-operator-key",
    },
    {
      ...coordinatorInput(),
      operatorKeyId: "operator-key-",
    },
    {
      ...coordinatorInput(),
      operatorKeyId: "a".repeat(65),
    },
    {
      ...coordinatorInput(),
      operatorKeySecretArn: "not-an-arn",
    },
    {
      ...coordinatorInput(),
      clockchainTokenSecretArn:
        "arn:aws:s3:::not-secrets-manager",
    },
    {
      ...coordinatorInput(),
      relayUrl: "http://relay.clockchain.net/control",
    },
    {
      ...coordinatorInput(),
      relayUrl:
        "https://relay.clockchain.net:8443?token=raw-token-canary",
    },
    {
      ...coordinatorInput(),
      relayUrl:
        "https://relay.clockchain.net:8443/path",
    },
    {
      ...coordinatorInput(),
      relayUrl:
        "https://relay.clockchain.net:8443#fragment",
    },
    {
      ...coordinatorInput(),
      relayUrl:
        "https://user:pass@relay.clockchain.net:8443",
    },
    {
      ...coordinatorInput(),
      relayUrl: "https://relay.clockchain.net",
    },
    {
      ...coordinatorInput(),
      relayUrl: "https://127.0.0.1:8443",
    },
    {
      ...coordinatorInput(),
      relayUrl: "https://[2001:db8::1]:8443",
    },
    {
      ...coordinatorInput(),
      relayUrl: "https://[::ffff:7f00:1]:8443",
    },
    {
      ...coordinatorInput(),
      tlsFingerprint: "B".repeat(64),
    },
  ]) {
    assert.throws(
      () => buildCoordinatorRuntimeInput(candidate),
      /AWS operator task input failed safely/,
    );
  }
});

test("coordinator builder permits only canonical public relay IP literals", () => {
  for (const relayUrl of [
    "https://8.8.8.8:8443",
    "https://[2606:4700:4700::1111]:8443",
  ]) {
    assert.equal(
      buildCoordinatorRuntimeInput(
        coordinatorInput({ relayUrl }),
      ).coordinator.relayUrl,
      relayUrl,
    );
  }

  for (const relayUrl of [
    "https://100.64.0.1:8443",
    "https://192.0.0.1:8443",
    "https://192.0.2.1:8443",
    "https://192.88.99.1:8443",
    "https://198.18.0.1:8443",
    "https://198.51.100.1:8443",
    "https://203.0.113.1:8443",
    "https://224.0.0.1:8443",
    "https://240.0.0.1:8443",
    "https://[100::1]:8443",
    "https://[2001::1]:8443",
    "https://[2002::1]:8443",
    "https://[ff02::1]:8443",
    "https://[::ffff:100.64.0.1]:8443",
    "https://[::ffff:c612:1]:8443",
  ]) {
    assert.throws(
      () =>
        buildCoordinatorRuntimeInput(
          coordinatorInput({ relayUrl }),
        ),
      /AWS operator task input failed safely/,
      relayUrl,
    );
  }
});

test("builders reject traversal, non-normalized paths, and root-prefix sibling tricks", () => {
  for (const candidate of [
    {
      builder: buildCoordinatorRuntimeInput,
      input: coordinatorInput({
        releaseRoot:
          `/var/lib/clockchain/operator/releases/${RELEASE_ID}/../${RELEASE_ID}`,
      }),
    },
    {
      builder: buildCoordinatorRuntimeInput,
      input: coordinatorInput({
        releaseRoot:
          `${OPERATOR_RELEASE_ROOT}/child`,
      }),
    },
    {
      builder: buildCoordinatorRuntimeInput,
      input: coordinatorInput({
        tlsCertificatePath: OPERATOR_RELEASE_ROOT,
      }),
    },
    {
      builder: buildCoordinatorRuntimeInput,
      input: coordinatorInput({
        tlsCertificatePath:
          `/var/lib/clockchain/operator/releases/${RELEASE_ID}-sibling/tls.pem`,
      }),
    },
    {
      builder: buildFundingRuntimeInput,
      input: fundingInput({
        fundingRecordPath:
          `/var/lib/clockchain/funding-record/releases/${RELEASE_ID}-sibling/record.json`,
      }),
    },
    {
      builder: buildFundingRuntimeInput,
      input: fundingInput({
        journalDirectory:
          `/var/lib/clockchain/funding-journal/releases/${RELEASE_ID}/../${RELEASE_ID}/journal`,
      }),
    },
    {
      builder: buildVerifierRuntimeInput,
      input: verifierInput({
        descriptorPath:
          `/var/lib/clockchain/evidence/releases/${RELEASE_ID}-sibling/descriptor.json`,
      }),
    },
    {
      builder: buildVerifierRuntimeInput,
      input: verifierInput({
        attemptRoot:
          `/var/lib/clockchain/verifier-output/releases/${RELEASE_ID}/attempts/${ATTEMPT_ID}/..`,
      }),
    },
    {
      builder: buildVerifierRuntimeInput,
      input: verifierInput({
        publicationPath:
          `/var/lib/clockchain/verifier-output/releases/${RELEASE_ID}-sibling/public.json`,
      }),
    },
  ]) {
    assert.throws(
      () => candidate.builder(candidate.input),
      /AWS operator task input failed safely/,
    );
  }
});

test("funding builder rejects caller-supplied raw secrets, paths, RPC URLs, and malformed fields", () => {
  for (const candidate of [
    { ...fundingInput(), keystorePath: "/tmp/key.json" },
    { ...fundingInput(), rpcUrlFile: "/tmp/rpc" },
    { ...fundingInput(), secretId: "password-secret" },
    {
      ...fundingInput(),
      rpcUrl: "https://rpc.secret",
    },
    {
      ...fundingInput(),
      expectedTreasuryAddress:
        "0x0000000000000000000000000000000000000000",
    },
    { ...fundingInput(), createdAt: "2026-07-31" },
    {
      ...fundingInput(),
      fundingRecordPath: "relative.json",
    },
    {
      ...fundingInput(),
      keystoreSecretArn: "not-an-arn",
    },
  ]) {
    assert.throws(
      () => buildFundingRuntimeInput(candidate),
      /AWS operator task input failed safely/,
    );
  }
});

test("verifier builder rejects raw runtime-only fields and missing, reordered, or malformed evidence", () => {
  for (const candidate of [
    { ...verifierInput(), taskArn: "arn:aws:ecs:us-west-2:123456789012:task/clockchain/11111111111111111111111111111111" },
    {
      ...verifierInput(),
      clockchainTokenFile: "/tmp/token",
    },
    { ...verifierInput(), rpcUrl: "https://rpc.secret" },
    { ...verifierInput(), rpcUrlFile: "/tmp/rpc" },
    {
      ...verifierInput(),
      evidenceDigest: undefined,
    },
    without(verifierInput(), "evidenceDigest"),
    reordered(verifierInput()),
    {
      ...verifierInput(),
      evidenceDigest: "D".repeat(64),
    },
    {
      ...verifierInput(),
      attemptRoot:
        `${VERIFIER_OUTPUT_ROOT}/attempts/not-the-attempt`,
    },
    {
      ...verifierInput(),
      publicationPath:
        `${VERIFIER_OUTPUT_ROOT}/attempts/${ATTEMPT_ID}/publication.json`,
    },
    { ...verifierInput(), expectedRevision: -1 },
    { ...verifierInput(), actionAtMs: 1.5 },
  ]) {
    assert.throws(
      () => buildVerifierRuntimeInput(candidate),
      /AWS operator task input failed safely/,
    );
  }
});
