const COMMON_KEYS = Object.freeze([
  "paymentMoved",
  "releaseId",
  "repositorySha",
  "sessionId",
]);
const REQUIRED = Object.freeze([
  "abort",
  "activateTunnel",
  "approveAndSeal",
  "launch",
  "readExpectedClaimFingerprint",
  "readResult",
  "wait",
]);
const SHA40 = /^[0-9a-f]{40}$/;
const SHA64 = /^[0-9a-f]{64}$/;
const RELEASE =
  /^release-[0-9a-f]{16}$/;
const SESSION =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export class AwsOperatorTransitionsError extends Error {
  constructor() {
    super("AWS operator transitions failed safely.");
    this.name =
      "AwsOperatorTransitionsError";
    this.code =
      "AWS_OPERATOR_TRANSITIONS_INVALID";
    this.category = "verification";
  }
}

function fail() {
  throw new AwsOperatorTransitionsError();
}

function common(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    COMMON_KEYS.some(
      (key) => !Object.hasOwn(value, key),
    ) ||
    value.paymentMoved !== false ||
    !RELEASE.test(value.releaseId) ||
    !SHA40.test(value.repositorySha) ||
    !SESSION.test(value.sessionId)
  ) {
    fail();
  }
  return Object.freeze({
    paymentMoved: false,
    releaseId: value.releaseId,
    repositorySha:
      value.repositorySha,
    sessionId: value.sessionId,
  });
}

function sameScope(value, expected) {
  const observed = common(value);
  if (
    observed.releaseId !==
      expected.releaseId ||
    observed.repositorySha !==
      expected.repositorySha ||
    observed.sessionId !==
      expected.sessionId
  ) {
    fail();
  }
  return value;
}

function result(value, status) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    value.paymentMoved !== false ||
    value.status !== status
  ) {
    fail();
  }
  return value;
}

export function createAwsOperatorTransitions(
  value,
  dependencies = {},
) {
  try {
    const scope = common(value);
    if (
      dependencies === null ||
      typeof dependencies !== "object" ||
      Array.isArray(dependencies) ||
      REQUIRED.some(
        (name) =>
          typeof dependencies[name] !==
            "function",
      )
    ) {
      fail();
    }
    return Object.freeze({
      async abortSession(input) {
        sameScope(input, scope);
        return result(
          await dependencies.abort(input),
          "ABORTED",
        );
      },
      async approveBootstrapClaim(input) {
        sameScope(input, scope);
        if (
          !["payer", "payee"].includes(
            input.role,
          ) ||
          !SHA64.test(
            input.claimFingerprint,
          )
        ) {
          fail();
        }
        const approved = result(
          await dependencies
            .approveAndSeal(input),
          "APPROVED",
        );
        if (input.role === "payer") {
          await dependencies
            .activateTunnel(input);
        }
        return approved;
      },
      async createSession(input) {
        if (
          input?.paymentMoved !== false ||
          input.releaseId !==
            scope.releaseId ||
          input.repositorySha !==
            scope.repositorySha
        ) {
          fail();
        }
        return scope.sessionId;
      },
      async launchCoordinator(input) {
        sameScope(input, scope);
        return result(
          await dependencies.launch(
            "coordinator",
            input,
          ),
          "RUNNING",
        );
      },
      async launchFundingTask(input) {
        sameScope(input, scope);
        const launched = result(
          await dependencies.launch(
            "funding",
            input,
          ),
          "RUNNING",
        );
        await dependencies.wait(
          "funding",
          launched,
        );
        return result(
          await dependencies.readResult(
            "funding",
            input,
          ),
          "FUNDED",
        );
      },
      async launchVerifierTask(input) {
        sameScope(input, scope);
        const launched = result(
          await dependencies.launch(
            "verifier",
            input,
          ),
          "RUNNING",
        );
        await dependencies.wait(
          "verifier",
          launched,
        );
        const verified = result(
          await dependencies.readResult(
            "verifier",
            input,
          ),
          "VERIFICATION_PASSED",
        );
        if (
          !SHA64.test(
            verified.publicationDigest,
          )
        ) {
          fail();
        }
        return verified;
      },
      async readExpectedClaimFingerprint(
        input,
      ) {
        sameScope(
          {
            ...scope,
            ...input,
            paymentMoved: false,
          },
          scope,
        );
        const fingerprint =
          await dependencies
            .readExpectedClaimFingerprint(
              input,
            );
        if (
          !(
            fingerprint === null ||
            SHA64.test(fingerprint)
          )
        ) {
          fail();
        }
        return fingerprint;
      },
    });
  } catch (error) {
    if (
      error instanceof
      AwsOperatorTransitionsError
    ) {
      throw error;
    }
    fail();
  }
}
