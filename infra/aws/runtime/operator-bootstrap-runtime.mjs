const SHA40 = /^[0-9a-f]{40}$/;
const SHA64 = /^[0-9a-f]{64}$/;
const RELEASE = /^release-[0-9a-f]{16}$/;
const SESSION =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export class AwsOperatorBootstrapError extends Error {
  constructor() {
    super("AWS operator bootstrap failed safely.");
    this.name = "AwsOperatorBootstrapError";
    this.code = "AWS_OPERATOR_BOOTSTRAP_INVALID";
    this.category = "verification";
  }
}

function fail() {
  throw new AwsOperatorBootstrapError();
}

function input(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    !SHA64.test(value.claimFingerprint) ||
    value.paymentMoved !== false ||
    !RELEASE.test(value.releaseId) ||
    !SHA40.test(value.repositorySha) ||
    !["payer", "payee"].includes(value.role) ||
    !SESSION.test(value.sessionId)
  ) {
    fail();
  }
  return value;
}

function entryFor(state, expected) {
  if (
    state === null ||
    typeof state !== "object" ||
    Array.isArray(state) ||
    state.paymentMoved !== false ||
    state.releaseId !== expected.releaseId ||
    state.repositorySha !== expected.repositorySha ||
    state.sessionId !== expected.sessionId ||
    typeof state.revision !== "string" ||
    !/^(?:0|[1-9][0-9]*)$/.test(state.revision) ||
    state.claims === null ||
    typeof state.claims !== "object" ||
    Array.isArray(state.claims)
  ) {
    fail();
  }
  const entry = state.claims[expected.claimFingerprint];
  if (
    entry === null ||
    typeof entry !== "object" ||
    Array.isArray(entry) ||
    entry.claimFingerprint !== expected.claimFingerprint ||
    entry.paymentMoved !== false ||
    entry.releaseId !== expected.releaseId ||
    entry.role !== expected.role ||
    entry.sessionId !== expected.sessionId ||
    !["PENDING", "APPROVED", "SEALED"].includes(entry.status)
  ) {
    fail();
  }
  return { entry, state };
}

export async function approveAndSealAwsBootstrapClaim(
  value,
  dependencies = {},
) {
  try {
    const expected = input(value);
    const openBootstrap = dependencies.openBootstrap;
    const buildSealedResponse =
      dependencies.buildSealedResponse;
    const persistTunnelGrant =
      dependencies.persistTunnelGrant;
    const publishApprovedPayer =
      dependencies.publishApprovedPayer;
    if (
      typeof openBootstrap !== "function" ||
      typeof buildSealedResponse !== "function" ||
      typeof persistTunnelGrant !== "function" ||
      !(
        publishApprovedPayer === undefined ||
        typeof publishApprovedPayer === "function"
      )
    ) {
      fail();
    }
    const bootstrap = await openBootstrap(expected);
    if (
      bootstrap === null ||
      typeof bootstrap !== "object" ||
      typeof bootstrap.readState !== "function" ||
      typeof bootstrap.approveClaim !== "function" ||
      typeof bootstrap.sealClaim !== "function"
    ) {
      fail();
    }
    let current = entryFor(
      await bootstrap.readState(),
      expected,
    );
    if (current.entry.status === "SEALED") {
      if (
        expected.role === "payer"
      ) {
        if (
          typeof dependencies.assertTunnelGrant !== "function"
        ) {
          fail();
        }
        await dependencies.assertTunnelGrant(expected);
        if (publishApprovedPayer !== undefined) {
          await publishApprovedPayer({
            claim: current.entry.claim,
            claimFingerprint:
              expected.claimFingerprint,
            expiresAtMs:
              current.entry.expiresAtMs,
          });
        }
      }
      return Object.freeze({
        paymentMoved: false,
        status: "APPROVED",
      });
    }
    if (current.entry.status === "PENDING") {
      current = entryFor(
        await bootstrap.approveClaim({
          claimFingerprint: expected.claimFingerprint,
          expectedRevision: current.state.revision,
          paymentMoved: false,
        }),
        expected,
      );
      if (current.entry.status !== "APPROVED") fail();
    }
    const built = await buildSealedResponse({
      claim: current.entry.claim,
      claimFingerprint: expected.claimFingerprint,
      expiresAtMs: current.entry.expiresAtMs,
      role: expected.role,
    });
    if (
      built === null ||
      typeof built !== "object" ||
      Array.isArray(built) ||
      built.response?.paymentMoved !== false
    ) {
      fail();
    }
    if (expected.role === "payer") {
      if (built.tunnelGrant?.paymentMoved !== false) fail();
      await persistTunnelGrant(built.tunnelGrant);
    } else if (built.tunnelGrant !== null && built.tunnelGrant !== undefined) {
      fail();
    }
    const sealed = entryFor(
      await bootstrap.sealClaim({
        claimFingerprint: expected.claimFingerprint,
        expectedRevision: current.state.revision,
        paymentMoved: false,
        response: built.response,
      }),
      expected,
    );
    if (sealed.entry.status !== "SEALED") fail();
    if (
      expected.role === "payer" &&
      publishApprovedPayer !== undefined
    ) {
      await publishApprovedPayer({
        claim: sealed.entry.claim,
        claimFingerprint:
          expected.claimFingerprint,
        expiresAtMs:
          sealed.entry.expiresAtMs,
      });
    }
    return Object.freeze({
      paymentMoved: false,
      status: "APPROVED",
    });
  } catch (error) {
    if (error instanceof AwsOperatorBootstrapError) throw error;
    fail();
  }
}
