import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPairSync } from "node:crypto";

import {
  COORDINATION_ENVELOPE_SCHEMA,
  createCoordinationEnvelope,
} from "../src/bilateral/coordination/envelope.mjs";
import {
  COORDINATION_EVENT_AUTHORITIES,
  COORDINATION_EVENT_KINDS,
  CoordinationLifecycleError,
  RELEASE_STATES,
  RUN_MODES,
  initialReleaseView,
  reduceReleaseEvent,
} from "../src/bilateral/coordination/lifecycle.mjs";

const RELEASE_ID = "release-a";
const REPOSITORY_SHA = "b".repeat(40);
const SESSION_ID = "0352cfc8-5393-40d0-828f-61a457fcdd03";
const INITIAL_KEYS = Object.freeze([
  "releaseId",
  "repositorySha",
  "sessionId",
]);
const VIEW_KEYS = Object.freeze([
  "facts",
  "paymentMoved",
  "releaseId",
  "repositorySha",
  "sessionId",
  "state",
]);
const FACT_KEYS = Object.freeze([
  "descriptorAccepted",
  "enrollmentConfirmed",
  "enrollmentReceipt",
  "fundingInputsReady",
  "identityPackageReady",
  "payerMandateReady",
  "paymentRequestReady",
  "paymentRequestMatched",
  "preflightParticipantReady",
  "preflightPlanReady",
  "recoveryAuthorized",
  "recoveryRequired",
  "releaseCompleted",
  "registered",
  "rolePackageReady",
  "roleStarted",
  "runDescriptorReady",
  "runStarted",
  "tokenReady",
  "verifierPublicationVerified",
  "verificationPassed",
  "waitForFunding",
]);
const ROLE_FACT_KEYS = Object.freeze(["payee", "payer"]);
const RUN_FACT_KEYS = Object.freeze([
  "rehearsal",
  "stakeholder",
]);
const RECOVERY_RUN_KEYS = Object.freeze([
  "rehearsal",
  "release",
  "stakeholder",
]);

const keys = Object.freeze(
  Object.fromEntries(
    ["operator", "payer", "payee", "unknown"].map((role) => {
      const { privateKey, publicKey } =
        generateKeyPairSync("ed25519");
      return [
        role,
        Object.freeze({
          privateKeyPem: privateKey.export({
            format: "pem",
            type: "pkcs8",
          }),
          publicKey: publicKey
            .export({ format: "der", type: "spki" })
            .subarray(-32)
            .toString("base64"),
          publicKeyId: `${role}-coordination-key`,
        }),
      ];
    }),
  ),
);

let nextSequence = 0;

function event(kind, role, subjectRun, overrides = {}) {
  const key = keys[role];
  return createCoordinationEnvelope({
    artifactDigest: null,
    kind,
    paymentMoved: false,
    previousEventDigest: null,
    privateKeyPem: key.privateKeyPem,
    publicKey: key.publicKey,
    publicKeyId: key.publicKeyId,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    role,
    schema: COORDINATION_ENVELOPE_SCHEMA,
    sequence: String(nextSequence++),
    sessionId: SESSION_ID,
    subjectRun,
    ...overrides,
  });
}

function initial(overrides = {}) {
  return initialReleaseView({
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
    ...overrides,
  });
}

function apply(view, kind, role, subjectRun, options) {
  const next = reduceReleaseEvent(
    view,
    event(kind, role, subjectRun),
    options === undefined
      ? { expectedPublicKey: keys[role].publicKey }
      : {
          expectedPublicKey: keys[role].publicKey,
          ...options,
        },
  );
  assert.equal(next.paymentMoved, false);
  return next;
}

function applyStakeholderOnly(view, kind, role, subjectRun, options = {}) {
  return apply(view, kind, role, subjectRun, {
    ...options,
    runMode: "aws-stakeholder-only",
  });
}

function toAddressesReady() {
  let view = initial();
  view = apply(
    view,
    "ENROLLMENT_CONFIRMED",
    "payer",
    "release",
  );
  view = apply(
    view,
    "ENROLLMENT_CONFIRMED",
    "payee",
    "release",
  );
  return view;
}

function toPreflightPassed() {
  let view = toAddressesReady();
  view = apply(
    view,
    "ENROLLMENT_RECEIPT",
    "operator",
    "release",
  );
  view = apply(
    view,
    "WAIT_FOR_FUNDING",
    "operator",
    "release",
  );
  view = apply(
    view,
    "FUNDING_INPUTS_READY",
    "payer",
    "release",
  );
  view = apply(
    view,
    "FUNDING_INPUTS_READY",
    "payee",
    "release",
  );
  view = apply(view, "TOKEN_READY", "payer", "release");
  view = apply(view, "TOKEN_READY", "payee", "release");
  view = apply(
    view,
    "PREFLIGHT_PLAN_READY",
    "operator",
    "release",
  );
  view = apply(
    view,
    "PREFLIGHT_PARTICIPANT_READY",
    "payer",
    "release",
  );
  return apply(
    view,
    "PREFLIGHT_PARTICIPANT_READY",
    "payee",
    "release",
  );
}

function toRunRunning(subjectRun) {
  let view =
    subjectRun === "rehearsal"
      ? toPreflightPassed()
      : toRehearsalVerified();
  const registerKind =
    subjectRun === "rehearsal"
      ? "REGISTER_REHEARSAL"
      : "REGISTER_STAKEHOLDER";
  const descriptorKind =
    subjectRun === "rehearsal"
      ? "REHEARSAL_DESCRIPTOR_READY"
      : "STAKEHOLDER_DESCRIPTOR_READY";
  const startKind =
    subjectRun === "rehearsal"
      ? "START_REHEARSAL"
      : "START_STAKEHOLDER";

  view = apply(
    view,
    registerKind,
    "operator",
    subjectRun,
  );
  view = apply(
    view,
    "IDENTITY_PACKAGE_READY",
    "payer",
    subjectRun,
  );
  view = apply(
    view,
    "IDENTITY_PACKAGE_READY",
    "payee",
    subjectRun,
  );
  view = apply(view, "PAYER_MANDATE_READY", "payer", subjectRun);
  view = apply(view, "PAYMENT_REQUEST_READY", "payee", subjectRun);
  view = apply(view, "PAYMENT_REQUEST_MATCHED", "payer", subjectRun);
  view = apply(
    view,
    descriptorKind,
    "operator",
    subjectRun,
  );
  view = apply(
    view,
    "DESCRIPTOR_ACCEPTED",
    "payer",
    subjectRun,
  );
  view = apply(
    view,
    "DESCRIPTOR_ACCEPTED",
    "payee",
    subjectRun,
  );
  return apply(view, startKind, "operator", subjectRun);
}

function toRunPackagesReady(subjectRun) {
  let view = toRunRunning(subjectRun);
  view = apply(
    view,
    "ROLE_STARTED",
    "payer",
    subjectRun,
  );
  view = apply(
    view,
    "ROLE_STARTED",
    "payee",
    subjectRun,
  );
  view = apply(
    view,
    "ROLE_PACKAGE_READY",
    "payer",
    subjectRun,
  );
  return apply(
    view,
    "ROLE_PACKAGE_READY",
    "payee",
    subjectRun,
  );
}

test("requires payer mandate, payee request, and payer match before a run descriptor", () => {
  let view = toPreflightPassed();
  view = apply(view, "REGISTER_REHEARSAL", "operator", "rehearsal");
  view = apply(view, "IDENTITY_PACKAGE_READY", "payer", "rehearsal");
  view = apply(view, "IDENTITY_PACKAGE_READY", "payee", "rehearsal");
  assertLifecycleError(() =>
    apply(view, "PAYER_MANDATE_READY", "payee", "rehearsal"),
  );
  assertLifecycleError(() =>
    apply(view, "PAYMENT_REQUEST_READY", "payer", "rehearsal"),
  );
  assertLifecycleError(() =>
    apply(view, "PAYMENT_REQUEST_MATCHED", "payee", "rehearsal"),
  );
  assert.throws(() => apply(view, "REHEARSAL_DESCRIPTOR_READY", "operator", "rehearsal"), CoordinationLifecycleError);
  view = apply(view, "PAYER_MANDATE_READY", "payer", "rehearsal");
  assert.throws(() => apply(view, "REHEARSAL_DESCRIPTOR_READY", "operator", "rehearsal"), CoordinationLifecycleError);
  view = apply(view, "PAYMENT_REQUEST_READY", "payee", "rehearsal");
  assert.throws(() => apply(view, "REHEARSAL_DESCRIPTOR_READY", "operator", "rehearsal"), CoordinationLifecycleError);
  view = apply(view, "PAYMENT_REQUEST_MATCHED", "payer", "rehearsal");
  assert.equal(apply(view, "REHEARSAL_DESCRIPTOR_READY", "operator", "rehearsal").facts.runDescriptorReady.rehearsal, true);
});

function toRehearsalVerified() {
  return apply(
    toRunPackagesReady("rehearsal"),
    "VERIFICATION_PASSED",
    "operator",
    "rehearsal",
    { verifierPublicationVerified: true },
  );
}

function assertLifecycleError(action) {
  assert.throws(action, (error) => {
    assert.ok(
      error instanceof CoordinationLifecycleError,
      `expected CoordinationLifecycleError, got ${error?.name}`,
    );
    assert.equal(
      error.code,
      "COORDINATION_LIFECYCLE_INVALID",
    );
    assert.equal(
      error.message,
      "Coordination lifecycle validation failed.",
    );
    assert.equal(error.category, "verification");
    assert.doesNotMatch(
      JSON.stringify({
        message: error.message,
        stack: error.stack,
      }),
      /release-secret|watcher-said-pass/,
    );
    return true;
  });
}

function assertDeepFrozen(value, seen = new Set()) {
  if (
    value === null ||
    (typeof value !== "object" &&
      typeof value !== "function") ||
    seen.has(value)
  ) {
    return;
  }
  seen.add(value);
  assert.equal(Object.isFrozen(value), true);
  for (const child of Object.values(value)) {
    assertDeepFrozen(child, seen);
  }
}

test("pins the closed release states and event authorities", () => {
  assert.deepEqual(RUN_MODES, [
    "local-two-run",
    "aws-stakeholder-only",
  ]);
  assert.equal(Object.isFrozen(RUN_MODES), true);
  assert.deepEqual(RELEASE_STATES, [
    "BOOTSTRAPPING",
    "ADDRESSES_READY",
    "FUNDING_READY",
    "PREFLIGHT_READY",
    "PREFLIGHT_PASSED",
    "REHEARSAL_IDENTITIES_READY",
    "REHEARSAL_DESCRIPTOR_READY",
    "REHEARSAL_RUNNING",
    "REHEARSAL_VERIFIED",
    "STAKEHOLDER_IDENTITIES_READY",
    "STAKEHOLDER_DESCRIPTOR_READY",
    "STAKEHOLDER_RUNNING",
    "STAKEHOLDER_VERIFIED",
    "COMPLETE",
    "ABORTED",
  ]);
  assert.equal(RELEASE_STATES.at(-1), "ABORTED");
  assert.deepEqual(COORDINATION_EVENT_AUTHORITIES, {
    COMPLETE_RELEASE: "operator",
    DESCRIPTOR_ACCEPTED: "role",
    ENROLLMENT_CONFIRMED: "role",
    FUNDING_INPUTS_READY: "role",
    IDENTITY_PACKAGE_READY: "role",
    PAYER_MANDATE_READY: "payer",
    PAYMENT_REQUEST_READY: "payee",
    PAYMENT_REQUEST_MATCHED: "payer",
    PREFLIGHT_PARTICIPANT_READY: "role",
    RECOVERY_REQUIRED: "role",
    ROLE_PACKAGE_READY: "role",
    ROLE_STARTED: "role",
    TERMINAL_FAILURE: "any",
    TOKEN_READY: "role",
    ENROLLMENT_RECEIPT: "operator",
    EXACT_RECOVERY_AUTHORIZATION: "operator",
    PREFLIGHT_PLAN_READY: "operator",
    REGISTER_REHEARSAL: "operator",
    REGISTER_STAKEHOLDER: "operator",
    REHEARSAL_DESCRIPTOR_READY: "operator",
    STAKEHOLDER_DESCRIPTOR_READY: "operator",
    START_REHEARSAL: "operator",
    START_STAKEHOLDER: "operator",
    TERMINAL_ABORT: "operator",
    VERIFICATION_FAILED: "operator",
    VERIFICATION_PASSED: "operator",
    WAIT_FOR_FUNDING: "operator",
  });
  assert.equal(
    COORDINATION_EVENT_AUTHORITIES.START_REHEARSAL,
    "operator",
  );
  assert.equal(Object.isFrozen(RELEASE_STATES), true);
  assert.equal(
    Object.isFrozen(COORDINATION_EVENT_AUTHORITIES),
    true,
  );
});

test("default local-two-run still requires rehearsal before stakeholder progression", () => {
  const view = toPreflightPassed();

  assertLifecycleError(() =>
    apply(
      view,
      "REGISTER_STAKEHOLDER",
      "operator",
      "stakeholder",
    ),
  );

  const registered = apply(
    view,
    "REGISTER_REHEARSAL",
    "operator",
    "rehearsal",
  );
  assert.equal(registered.state, "PREFLIGHT_PASSED");
  assert.equal(registered.facts.registered.rehearsal, true);
});

test("aws-stakeholder-only mode moves directly from preflight into stakeholder identities", () => {
  let view = toPreflightPassed();

  view = applyStakeholderOnly(
    view,
    "REGISTER_STAKEHOLDER",
    "operator",
    "stakeholder",
  );
  assert.equal(view.state, "PREFLIGHT_PASSED");
  assert.equal(view.facts.registered.stakeholder, true);
  assert.equal(view.facts.registered.rehearsal, false);
  assert.equal(view.facts.verificationPassed.rehearsal, false);
  assert.equal(view.facts.verifierPublicationVerified.rehearsal, false);

  view = applyStakeholderOnly(
    view,
    "IDENTITY_PACKAGE_READY",
    "payer",
    "stakeholder",
  );
  assert.equal(view.state, "PREFLIGHT_PASSED");
  assert.notEqual(view.state, "REHEARSAL_VERIFIED");
  assert.equal(view.facts.identityPackageReady.rehearsal.payer, false);
  assert.equal(view.facts.identityPackageReady.rehearsal.payee, false);
  assert.equal(view.facts.verificationPassed.rehearsal, false);
  assert.equal(view.facts.verifierPublicationVerified.rehearsal, false);

  view = applyStakeholderOnly(
    view,
    "IDENTITY_PACKAGE_READY",
    "payee",
    "stakeholder",
  );
  assert.equal(view.state, "STAKEHOLDER_IDENTITIES_READY");
});

test("aws-stakeholder-only mode rejects rehearsal-scoped events and malformed run modes", () => {
  const preflight = toPreflightPassed();

  assertLifecycleError(() =>
    applyStakeholderOnly(
      preflight,
      "REGISTER_REHEARSAL",
      "operator",
      "rehearsal",
    ),
  );
  assertLifecycleError(() =>
    apply(preflight, "REGISTER_STAKEHOLDER", "operator", "stakeholder", {
      runMode: "aws",
    }),
  );
  assertLifecycleError(() =>
    apply(preflight, "REGISTER_STAKEHOLDER", "operator", "stakeholder", {
      runMode: "aws-stakeholder-only",
      extra: true,
    }),
  );
});

test("exports a frozen canonical event-kind registry matching lifecycle authority", () => {
  assert.deepEqual(
    COORDINATION_EVENT_KINDS,
    Object.keys(COORDINATION_EVENT_AUTHORITIES),
  );
  assert.equal(Object.isFrozen(COORDINATION_EVENT_KINDS), true);
});

test("initialReleaseView has an exact deep-frozen detached shape", () => {
  const input = {
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
  };
  const view = initialReleaseView(input);

  assert.deepEqual(Object.keys(input), INITIAL_KEYS);
  assert.deepEqual(Object.keys(view), VIEW_KEYS);
  assert.equal(view.paymentMoved, false);
  assert.deepEqual(Object.keys(view.facts), FACT_KEYS);
  assert.deepEqual(
    Object.keys(view.facts.enrollmentConfirmed),
    ROLE_FACT_KEYS,
  );
  assert.deepEqual(
    Object.keys(view.facts.descriptorAccepted),
    RUN_FACT_KEYS,
  );
  assert.deepEqual(
    Object.keys(
      view.facts.descriptorAccepted.rehearsal,
    ),
    ROLE_FACT_KEYS,
  );
  assert.deepEqual(
    Object.keys(view.facts.recoveryRequired),
    RECOVERY_RUN_KEYS,
  );
  assert.deepEqual(
    Object.keys(
      view.facts.recoveryAuthorized.rehearsal,
    ),
    ROLE_FACT_KEYS,
  );
  assert.equal(view.state, "BOOTSTRAPPING");
  assert.equal(
    view.facts.enrollmentConfirmed.payer,
    false,
  );
  assert.equal(
    view.facts.identityPackageReady.stakeholder.payee,
    false,
  );
  assert.equal(
    view.facts.recoveryRequired.rehearsal.payer,
    null,
  );
  assert.equal(
    view.facts.recoveryAuthorized.rehearsal.payer,
    null,
  );
  assertDeepFrozen(view);

  input.releaseId = "changed";
  assert.equal(view.releaseId, RELEASE_ID);
});

test("rejects malformed initial contexts with a fixed typed error", () => {
  for (const value of [
    null,
    [],
    {},
    {
      releaseId: RELEASE_ID,
      repositorySha: REPOSITORY_SHA,
      sessionId: SESSION_ID,
      extra: "release-secret",
    },
    {
      releaseId: "",
      repositorySha: REPOSITORY_SHA,
      sessionId: SESSION_ID,
    },
    {
      releaseId: RELEASE_ID,
      repositorySha: "B".repeat(40),
      sessionId: SESSION_ID,
    },
    {
      releaseId: RELEASE_ID,
      repositorySha: REPOSITORY_SHA,
      sessionId:
        "0352cfc8-5393-40d0-028f-61a457fcdd03",
    },
  ]) {
    assertLifecycleError(() => initialReleaseView(value));
  }

  const accessor = {
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
  };
  Object.defineProperty(accessor, "releaseId", {
    enumerable: true,
    get() {
      throw new Error("release-secret");
    },
  });
  assertLifecycleError(() =>
    initialReleaseView(accessor),
  );
});

test("reduces the complete valid release sequence through COMPLETE", () => {
  let view = initial();

  view = apply(
    view,
    "ENROLLMENT_CONFIRMED",
    "payer",
    "release",
  );
  assert.equal(view.state, "BOOTSTRAPPING");
  const beforeSecondEnrollment = view;
  view = apply(
    view,
    "ENROLLMENT_CONFIRMED",
    "payee",
    "release",
  );
  assert.equal(view.state, "ADDRESSES_READY");
  assert.equal(
    beforeSecondEnrollment.facts.enrollmentConfirmed
      .payee,
    false,
  );

  view = apply(
    view,
    "ENROLLMENT_RECEIPT",
    "operator",
    "release",
  );
  view = apply(
    view,
    "WAIT_FOR_FUNDING",
    "operator",
    "release",
  );
  view = apply(
    view,
    "FUNDING_INPUTS_READY",
    "payer",
    "release",
  );
  view = apply(
    view,
    "FUNDING_INPUTS_READY",
    "payee",
    "release",
  );
  view = apply(view, "TOKEN_READY", "payer", "release");
  view = apply(view, "TOKEN_READY", "payee", "release");
  assert.equal(view.state, "FUNDING_READY");

  view = apply(
    view,
    "PREFLIGHT_PLAN_READY",
    "operator",
    "release",
  );
  assert.equal(view.state, "PREFLIGHT_READY");
  view = apply(
    view,
    "PREFLIGHT_PARTICIPANT_READY",
    "payer",
    "release",
  );
  view = apply(
    view,
    "PREFLIGHT_PARTICIPANT_READY",
    "payee",
    "release",
  );
  assert.equal(view.state, "PREFLIGHT_PASSED");

  view = apply(
    view,
    "REGISTER_REHEARSAL",
    "operator",
    "rehearsal",
  );
  view = apply(
    view,
    "IDENTITY_PACKAGE_READY",
    "payer",
    "rehearsal",
  );
  view = apply(
    view,
    "IDENTITY_PACKAGE_READY",
    "payee",
    "rehearsal",
  );
  assert.equal(
    view.state,
    "REHEARSAL_IDENTITIES_READY",
  );
  view = apply(view, "PAYER_MANDATE_READY", "payer", "rehearsal");
  view = apply(view, "PAYMENT_REQUEST_READY", "payee", "rehearsal");
  view = apply(view, "PAYMENT_REQUEST_MATCHED", "payer", "rehearsal");
  view = apply(
    view,
    "REHEARSAL_DESCRIPTOR_READY",
    "operator",
    "rehearsal",
  );
  assert.equal(
    view.state,
    "REHEARSAL_DESCRIPTOR_READY",
  );
  view = apply(
    view,
    "DESCRIPTOR_ACCEPTED",
    "payer",
    "rehearsal",
  );
  view = apply(
    view,
    "DESCRIPTOR_ACCEPTED",
    "payee",
    "rehearsal",
  );
  view = apply(
    view,
    "START_REHEARSAL",
    "operator",
    "rehearsal",
  );
  assert.equal(view.state, "REHEARSAL_RUNNING");
  view = apply(
    view,
    "ROLE_STARTED",
    "payer",
    "rehearsal",
  );
  view = apply(
    view,
    "ROLE_STARTED",
    "payee",
    "rehearsal",
  );
  view = apply(
    view,
    "ROLE_PACKAGE_READY",
    "payer",
    "rehearsal",
  );
  view = apply(
    view,
    "ROLE_PACKAGE_READY",
    "payee",
    "rehearsal",
  );
  view = apply(
    view,
    "VERIFICATION_PASSED",
    "operator",
    "rehearsal",
    { verifierPublicationVerified: true },
  );
  assert.equal(view.state, "REHEARSAL_VERIFIED");

  view = apply(
    view,
    "REGISTER_STAKEHOLDER",
    "operator",
    "stakeholder",
  );
  view = apply(
    view,
    "IDENTITY_PACKAGE_READY",
    "payer",
    "stakeholder",
  );
  view = apply(
    view,
    "IDENTITY_PACKAGE_READY",
    "payee",
    "stakeholder",
  );
  assert.equal(
    view.state,
    "STAKEHOLDER_IDENTITIES_READY",
  );
  view = apply(view, "PAYER_MANDATE_READY", "payer", "stakeholder");
  view = apply(view, "PAYMENT_REQUEST_READY", "payee", "stakeholder");
  view = apply(view, "PAYMENT_REQUEST_MATCHED", "payer", "stakeholder");
  view = apply(
    view,
    "STAKEHOLDER_DESCRIPTOR_READY",
    "operator",
    "stakeholder",
  );
  assert.equal(
    view.state,
    "STAKEHOLDER_DESCRIPTOR_READY",
  );
  view = apply(
    view,
    "DESCRIPTOR_ACCEPTED",
    "payer",
    "stakeholder",
  );
  view = apply(
    view,
    "DESCRIPTOR_ACCEPTED",
    "payee",
    "stakeholder",
  );
  view = apply(
    view,
    "START_STAKEHOLDER",
    "operator",
    "stakeholder",
  );
  assert.equal(view.state, "STAKEHOLDER_RUNNING");
  view = apply(
    view,
    "ROLE_STARTED",
    "payer",
    "stakeholder",
  );
  view = apply(
    view,
    "ROLE_STARTED",
    "payee",
    "stakeholder",
  );
  view = apply(
    view,
    "ROLE_PACKAGE_READY",
    "payer",
    "stakeholder",
  );
  view = apply(
    view,
    "ROLE_PACKAGE_READY",
    "payee",
    "stakeholder",
  );
  view = apply(
    view,
    "VERIFICATION_PASSED",
    "operator",
    "stakeholder",
    { verifierPublicationVerified: true },
  );

  assert.equal(view.state, "STAKEHOLDER_VERIFIED");
  assert.equal(view.facts.releaseCompleted, false);
  view = apply(
    view,
    "COMPLETE_RELEASE",
    "operator",
    "release",
  );
  assert.equal(view.state, "COMPLETE");
  assert.equal(view.paymentMoved, false);
  assert.equal(view.facts.releaseCompleted, true);
  assert.equal(
    view.facts.verificationPassed.stakeholder,
    true,
  );
  assert.equal(
    view.facts.verifierPublicationVerified
      .stakeholder,
    true,
  );
  assertDeepFrozen(view);
});

test("rejects every kind emitted by the wrong authority", () => {
  for (const [kind, authority] of Object.entries(
    COORDINATION_EVENT_AUTHORITIES,
  )) {
    if (authority === "any") {
      continue;
    }
    const role =
      authority === "operator" ? "payer" : "operator";
    const subjectRun =
      kind.includes("STAKEHOLDER")
        ? "stakeholder"
        : kind.includes("REHEARSAL")
          ? "rehearsal"
          : "release";
    assertLifecycleError(() =>
      reduceReleaseEvent(
        initial(),
        event(kind, role, subjectRun),
        { expectedPublicKey: keys[role].publicKey },
      ),
    );
  }
});

test("rejects unknown kinds and exact kind/run scope mismatches", () => {
  assertLifecycleError(() =>
    apply(
      initial(),
      "WATCHER_SAID_PASS",
      "operator",
      "release",
    ),
  );

  for (const [kind, role, wrongRun] of [
    ["ENROLLMENT_CONFIRMED", "payer", "rehearsal"],
    ["FUNDING_INPUTS_READY", "payer", "stakeholder"],
    ["TOKEN_READY", "payee", "rehearsal"],
    [
      "PREFLIGHT_PARTICIPANT_READY",
      "payee",
      "stakeholder",
    ],
    ["ENROLLMENT_RECEIPT", "operator", "rehearsal"],
    ["PREFLIGHT_PLAN_READY", "operator", "stakeholder"],
    ["REGISTER_REHEARSAL", "operator", "stakeholder"],
    [
      "REHEARSAL_DESCRIPTOR_READY",
      "operator",
      "release",
    ],
    ["START_REHEARSAL", "operator", "stakeholder"],
    ["REGISTER_STAKEHOLDER", "operator", "rehearsal"],
    [
      "STAKEHOLDER_DESCRIPTOR_READY",
      "operator",
      "release",
    ],
    ["START_STAKEHOLDER", "operator", "rehearsal"],
    ["VERIFICATION_PASSED", "operator", "release"],
    ["VERIFICATION_FAILED", "operator", "release"],
    ["COMPLETE_RELEASE", "operator", "stakeholder"],
  ]) {
    assertLifecycleError(() =>
      apply(initial(), kind, role, wrongRun),
    );
  }
});

test("rejects context mismatches and any paymentMoved value other than false", () => {
  const view = initial();
  for (const overrides of [
    { releaseId: "other-release" },
    { repositorySha: "c".repeat(40) },
    {
      sessionId:
        "1352cfc8-5393-40d0-828f-61a457fcdd03",
    },
  ]) {
    assertLifecycleError(() =>
      reduceReleaseEvent(
        view,
        event(
          "ENROLLMENT_CONFIRMED",
          "payer",
          "release",
          overrides,
        ),
        { expectedPublicKey: keys.payer.publicKey },
      ),
    );
  }

  const moved = structuredClone(
    event(
      "ENROLLMENT_CONFIRMED",
      "payer",
      "release",
    ),
  );
  moved.paymentMoved = true;
  assertLifecycleError(() =>
    reduceReleaseEvent(view, moved, {
      expectedPublicKey: keys.payer.publicKey,
    }),
  );
});

test("requires a trusted exact expected signer key on every reduction", () => {
  const payerEnrollment = event(
    "ENROLLMENT_CONFIRMED",
    "payer",
    "release",
  );

  assertLifecycleError(() =>
    reduceReleaseEvent(initial(), payerEnrollment),
  );
  assertLifecycleError(() =>
    reduceReleaseEvent(initial(), payerEnrollment, {}),
  );
  assertLifecycleError(() =>
    reduceReleaseEvent(initial(), payerEnrollment, {
      expectedPublicKey: keys.payer.publicKey,
      extra: true,
    }),
  );
  assertLifecycleError(() =>
    reduceReleaseEvent(initial(), payerEnrollment, {
      expectedPublicKey: keys.operator.publicKey,
    }),
  );
  assertLifecycleError(() =>
    reduceReleaseEvent(initial(), payerEnrollment, {
      expectedPublicKey: keys.unknown.publicKey,
    }),
  );

  const accepted = reduceReleaseEvent(
    initial(),
    payerEnrollment,
    { expectedPublicKey: keys.payer.publicKey },
  );
  assert.equal(
    accepted.facts.enrollmentConfirmed.payer,
    true,
  );
});

test("rejects forged operator events signed by payer or unknown keys", () => {
  const payerSignedOperatorEvent = event(
    "WAIT_FOR_FUNDING",
    "operator",
    "release",
    {
      privateKeyPem: keys.payer.privateKeyPem,
      publicKey: keys.payer.publicKey,
      publicKeyId: keys.payer.publicKeyId,
    },
  );
  const unknownSignedOperatorEvent = event(
    "WAIT_FOR_FUNDING",
    "operator",
    "release",
    {
      privateKeyPem: keys.unknown.privateKeyPem,
      publicKey: keys.unknown.publicKey,
      publicKeyId: keys.unknown.publicKeyId,
    },
  );

  for (const forged of [
    payerSignedOperatorEvent,
    unknownSignedOperatorEvent,
  ]) {
    assertLifecycleError(() =>
      reduceReleaseEvent(toAddressesReady(), forged, {
        expectedPublicKey: keys.operator.publicKey,
      }),
    );
  }
});

test("rejects reordered prerequisites and premature run starts", () => {
  assertLifecycleError(() =>
    apply(
      initial(),
      "WAIT_FOR_FUNDING",
      "operator",
      "release",
    ),
  );
  assertLifecycleError(() =>
    apply(initial(), "TOKEN_READY", "payer", "release"),
  );
  assertLifecycleError(() =>
    apply(
      toAddressesReady(),
      "PREFLIGHT_PLAN_READY",
      "operator",
      "release",
    ),
  );
  assertLifecycleError(() =>
    apply(
      toPreflightPassed(),
      "START_REHEARSAL",
      "operator",
      "rehearsal",
    ),
  );
  assertLifecycleError(() =>
    apply(
      toPreflightPassed(),
      "REGISTER_STAKEHOLDER",
      "operator",
      "stakeholder",
    ),
  );

  let view = toRunRunning("rehearsal");
  assertLifecycleError(() =>
    apply(
      view,
      "ROLE_PACKAGE_READY",
      "payer",
      "rehearsal",
    ),
  );
  view = apply(
    view,
    "ROLE_STARTED",
    "payer",
    "rehearsal",
  );
  assertLifecycleError(() =>
    apply(
      view,
      "VERIFICATION_PASSED",
      "operator",
      "rehearsal",
      { verifierPublicationVerified: true },
    ),
  );
});

test("rejects duplicate identity and role packages", () => {
  let identityView = toPreflightPassed();
  identityView = apply(
    identityView,
    "REGISTER_REHEARSAL",
    "operator",
    "rehearsal",
  );
  identityView = apply(
    identityView,
    "IDENTITY_PACKAGE_READY",
    "payer",
    "rehearsal",
  );
  assertLifecycleError(() =>
    apply(
      identityView,
      "IDENTITY_PACKAGE_READY",
      "payer",
      "rehearsal",
    ),
  );

  let packageView = toRunRunning("rehearsal");
  packageView = apply(
    packageView,
    "ROLE_STARTED",
    "payer",
    "rehearsal",
  );
  packageView = apply(
    packageView,
    "ROLE_STARTED",
    "payee",
    "rehearsal",
  );
  packageView = apply(
    packageView,
    "ROLE_PACKAGE_READY",
    "payer",
    "rehearsal",
  );
  assertLifecycleError(() =>
    apply(
      packageView,
      "ROLE_PACKAGE_READY",
      "payer",
      "rehearsal",
    ),
  );
});

test("VERIFICATION_PASSED trusts only an explicit publication fact", () => {
  const view = toRunPackagesReady("rehearsal");

  assertLifecycleError(() =>
    apply(
      view,
      "VERIFICATION_PASSED",
      "operator",
      "rehearsal",
    ),
  );
  for (const advisory of [
    { watcherStatus: "watcher-said-pass" },
    { relayStatus: "VERIFIED" },
    { coordinatorStatus: "VERIFIED" },
    {
      verifierPublicationVerified: true,
      watcherStatus: "watcher-said-pass",
    },
    { verifierPublicationVerified: false },
  ]) {
    assertLifecycleError(() =>
      apply(
        view,
        "VERIFICATION_PASSED",
        "operator",
        "rehearsal",
        advisory,
      ),
    );
  }

  const verified = apply(
    view,
    "VERIFICATION_PASSED",
    "operator",
    "rehearsal",
    { verifierPublicationVerified: true },
  );
  assert.equal(verified.state, "REHEARSAL_VERIFIED");
});

test("failure and abort events permanently map the release to ABORTED", () => {
  for (const [kind, role, subjectRun] of [
    ["TERMINAL_FAILURE", "payer", "release"],
    ["TERMINAL_FAILURE", "payee", "rehearsal"],
    ["TERMINAL_FAILURE", "operator", "stakeholder"],
    ["TERMINAL_ABORT", "operator", "release"],
    [
      "VERIFICATION_FAILED",
      "operator",
      "rehearsal",
    ],
    [
      "VERIFICATION_FAILED",
      "operator",
      "stakeholder",
    ],
  ]) {
    const aborted = apply(
      initial(),
      kind,
      role,
      subjectRun,
    );
    assert.equal(aborted.state, "ABORTED");
    assert.equal(aborted.paymentMoved, false);
  }

  const aborted = apply(
    initial(),
    "TERMINAL_ABORT",
    "operator",
    "release",
  );
  for (const [kind, authority] of Object.entries(
    COORDINATION_EVENT_AUTHORITIES,
  )) {
    const role =
      authority === "operator" ? "operator" : "payer";
    const subjectRun =
      kind.includes("STAKEHOLDER")
        ? "stakeholder"
        : kind.includes("REHEARSAL") ||
            kind.startsWith("VERIFICATION_")
          ? "rehearsal"
          : "release";
    assertLifecycleError(() =>
      apply(aborted, kind, role, subjectRun),
    );
  }
});

test("only an exact operator completion event can move STAKEHOLDER_VERIFIED to COMPLETE", () => {
  const stakeholderVerified = apply(
    toRunPackagesReady("stakeholder"),
    "VERIFICATION_PASSED",
    "operator",
    "stakeholder",
    { verifierPublicationVerified: true },
  );
  assert.equal(
    stakeholderVerified.state,
    "STAKEHOLDER_VERIFIED",
  );

  assertLifecycleError(() =>
    apply(
      toRehearsalVerified(),
      "COMPLETE_RELEASE",
      "operator",
      "release",
    ),
  );
  assertLifecycleError(() =>
    apply(
      stakeholderVerified,
      "COMPLETE_RELEASE",
      "payer",
      "release",
    ),
  );
  assertLifecycleError(() =>
    apply(
      stakeholderVerified,
      "COMPLETE_RELEASE",
      "operator",
      "stakeholder",
    ),
  );

  const complete = apply(
    stakeholderVerified,
    "COMPLETE_RELEASE",
    "operator",
    "release",
  );
  assert.equal(complete.state, "COMPLETE");
  assert.equal(complete.paymentMoved, false);
  assert.equal(complete.facts.releaseCompleted, true);
  assertLifecycleError(() =>
    apply(
      complete,
      "COMPLETE_RELEASE",
      "operator",
      "release",
    ),
  );
  assertLifecycleError(() =>
    apply(
      complete,
      "TERMINAL_FAILURE",
      "payer",
      "release",
    ),
  );
});

test("recovery authorization binds one exact digest to one role and run", () => {
  const payerDigest = "1".repeat(64);
  const payeeDigest = "2".repeat(64);
  const mismatchedDigest = "3".repeat(64);
  let view = toRunRunning("rehearsal");

  view = reduceReleaseEvent(
    view,
    event(
      "RECOVERY_REQUIRED",
      "payer",
      "rehearsal",
      { artifactDigest: payerDigest },
    ),
    { expectedPublicKey: keys.payer.publicKey },
  );
  assert.equal(
    view.facts.recoveryRequired.rehearsal.payer,
    payerDigest,
  );
  assert.equal(
    view.facts.recoveryAuthorized.rehearsal.payer,
    null,
  );
  assertLifecycleError(() =>
    reduceReleaseEvent(
      view,
      event(
        "EXACT_RECOVERY_AUTHORIZATION",
        "operator",
        "rehearsal",
        { artifactDigest: mismatchedDigest },
      ),
      { expectedPublicKey: keys.operator.publicKey },
    ),
  );
  assertLifecycleError(() =>
    reduceReleaseEvent(
      view,
      event(
        "EXACT_RECOVERY_AUTHORIZATION",
        "operator",
        "stakeholder",
        { artifactDigest: payerDigest },
      ),
      { expectedPublicKey: keys.operator.publicKey },
    ),
  );

  view = reduceReleaseEvent(
    view,
    event(
      "EXACT_RECOVERY_AUTHORIZATION",
      "operator",
      "rehearsal",
      { artifactDigest: payerDigest },
    ),
    { expectedPublicKey: keys.operator.publicKey },
  );
  assert.equal(
    view.facts.recoveryAuthorized.rehearsal.payer,
    payerDigest,
  );
  assert.equal(
    view.facts.recoveryAuthorized.rehearsal.payee,
    null,
  );
  assertLifecycleError(() =>
    reduceReleaseEvent(
      view,
      event(
        "EXACT_RECOVERY_AUTHORIZATION",
        "operator",
        "rehearsal",
        { artifactDigest: payerDigest },
      ),
      { expectedPublicKey: keys.operator.publicKey },
    ),
  );

  view = reduceReleaseEvent(
    view,
    event(
      "RECOVERY_REQUIRED",
      "payee",
      "rehearsal",
      { artifactDigest: payeeDigest },
    ),
    { expectedPublicKey: keys.payee.publicKey },
  );
  assert.equal(
    view.facts.recoveryRequired.rehearsal.payee,
    payeeDigest,
  );
  assert.equal(
    view.facts.recoveryAuthorized.rehearsal.payee,
    null,
  );
  assert.equal(
    view.facts.recoveryAuthorized.rehearsal.payer,
    payerDigest,
  );

  view = reduceReleaseEvent(
    view,
    event(
      "EXACT_RECOVERY_AUTHORIZATION",
      "operator",
      "rehearsal",
      { artifactDigest: payeeDigest },
    ),
    { expectedPublicKey: keys.operator.publicKey },
  );
  assert.equal(
    view.facts.recoveryAuthorized.rehearsal.payee,
    payeeDigest,
  );
});

test("recovery rejects missing digests and same-digest cross-role collisions", () => {
  const sharedDigest = "4".repeat(64);
  const running = toRunRunning("rehearsal");

  assertLifecycleError(() =>
    apply(
      running,
      "RECOVERY_REQUIRED",
      "payer",
      "rehearsal",
    ),
  );
  assertLifecycleError(() =>
    apply(
      running,
      "EXACT_RECOVERY_AUTHORIZATION",
      "operator",
      "rehearsal",
    ),
  );

  const payerRequested = reduceReleaseEvent(
    running,
    event(
      "RECOVERY_REQUIRED",
      "payer",
      "rehearsal",
      { artifactDigest: sharedDigest },
    ),
    { expectedPublicKey: keys.payer.publicKey },
  );
  assertLifecycleError(() =>
    reduceReleaseEvent(
      payerRequested,
      event(
        "RECOVERY_REQUIRED",
        "payee",
        "rehearsal",
        { artifactDigest: sharedDigest },
      ),
      { expectedPublicKey: keys.payee.publicKey },
    ),
  );
});

test("recovery request digests are globally single-use across the release", () => {
  const digest = "7".repeat(64);
  let outstanding = toRunRunning("rehearsal");
  outstanding = reduceReleaseEvent(
    outstanding,
    event(
      "RECOVERY_REQUIRED",
      "payer",
      "rehearsal",
      { artifactDigest: digest },
    ),
    { expectedPublicKey: keys.payer.publicKey },
  );

  for (const role of ["payer", "payee"]) {
    assertLifecycleError(() =>
      reduceReleaseEvent(
        outstanding,
        event(
          "RECOVERY_REQUIRED",
          role,
          "release",
          { artifactDigest: digest },
        ),
        { expectedPublicKey: keys[role].publicKey },
      ),
    );
  }

  let authorized = reduceReleaseEvent(
    outstanding,
    event(
      "EXACT_RECOVERY_AUTHORIZATION",
      "operator",
      "rehearsal",
      { artifactDigest: digest },
    ),
    { expectedPublicKey: keys.operator.publicKey },
  );
  for (const role of ["payer", "payee"]) {
    assertLifecycleError(() =>
      reduceReleaseEvent(
        authorized,
        event(
          "RECOVERY_REQUIRED",
          role,
          "release",
          { artifactDigest: digest },
        ),
        { expectedPublicKey: keys[role].publicKey },
      ),
    );
  }

  authorized = apply(
    authorized,
    "ROLE_STARTED",
    "payer",
    "rehearsal",
  );
  authorized = apply(
    authorized,
    "ROLE_STARTED",
    "payee",
    "rehearsal",
  );
  authorized = apply(
    authorized,
    "ROLE_PACKAGE_READY",
    "payer",
    "rehearsal",
  );
  authorized = apply(
    authorized,
    "ROLE_PACKAGE_READY",
    "payee",
    "rehearsal",
  );
  authorized = apply(
    authorized,
    "VERIFICATION_PASSED",
    "operator",
    "rehearsal",
    { verifierPublicationVerified: true },
  );
  authorized = apply(
    authorized,
    "REGISTER_STAKEHOLDER",
    "operator",
    "stakeholder",
  );
  authorized = apply(
    authorized,
    "IDENTITY_PACKAGE_READY",
    "payer",
    "stakeholder",
  );
  authorized = apply(
    authorized,
    "IDENTITY_PACKAGE_READY",
    "payee",
    "stakeholder",
  );
  authorized = apply(authorized, "PAYER_MANDATE_READY", "payer", "stakeholder");
  authorized = apply(authorized, "PAYMENT_REQUEST_READY", "payee", "stakeholder");
  authorized = apply(authorized, "PAYMENT_REQUEST_MATCHED", "payer", "stakeholder");
  authorized = apply(
    authorized,
    "STAKEHOLDER_DESCRIPTOR_READY",
    "operator",
    "stakeholder",
  );
  authorized = apply(
    authorized,
    "DESCRIPTOR_ACCEPTED",
    "payer",
    "stakeholder",
  );
  authorized = apply(
    authorized,
    "DESCRIPTOR_ACCEPTED",
    "payee",
    "stakeholder",
  );
  authorized = apply(
    authorized,
    "START_STAKEHOLDER",
    "operator",
    "stakeholder",
  );

  for (const role of ["payer", "payee"]) {
    assertLifecycleError(() =>
      reduceReleaseEvent(
        authorized,
        event(
          "RECOVERY_REQUIRED",
          role,
          "stakeholder",
          { artifactDigest: digest },
        ),
        { expectedPublicKey: keys[role].publicKey },
      ),
    );
  }
});

test("rejects malformed views and hostile accessor/prototype events", () => {
  const malformed = structuredClone(initial());
  malformed.facts.enrollmentConfirmed.payer = "true";
  assertLifecycleError(() =>
    reduceReleaseEvent(
      malformed,
      event(
        "ENROLLMENT_CONFIRMED",
        "payer",
        "release",
      ),
      { expectedPublicKey: keys.payer.publicKey },
    ),
  );

  const forgedRecovery = structuredClone(initial());
  forgedRecovery.facts.recoveryAuthorized.release.payer =
    "5".repeat(64);
  assertLifecycleError(() =>
    reduceReleaseEvent(
      forgedRecovery,
      event(
        "ENROLLMENT_CONFIRMED",
        "payer",
        "release",
      ),
      { expectedPublicKey: keys.payer.publicKey },
    ),
  );

  const collidedRecovery = structuredClone(initial());
  collidedRecovery.facts.recoveryRequired.release.payer =
    "6".repeat(64);
  collidedRecovery.facts.recoveryRequired.release.payee =
    "6".repeat(64);
  assertLifecycleError(() =>
    reduceReleaseEvent(
      collidedRecovery,
      event(
        "ENROLLMENT_CONFIRMED",
        "payer",
        "release",
      ),
      { expectedPublicKey: keys.payer.publicKey },
    ),
  );

  const inherited = Object.create(
    event(
      "ENROLLMENT_CONFIRMED",
      "payer",
      "release",
    ),
  );
  assertLifecycleError(() =>
    reduceReleaseEvent(initial(), inherited, {
      expectedPublicKey: keys.payer.publicKey,
    }),
  );

  const accessor = structuredClone(
    event(
      "ENROLLMENT_CONFIRMED",
      "payer",
      "release",
    ),
  );
  Object.defineProperty(accessor, "kind", {
    enumerable: true,
    get() {
      throw new Error("release-secret");
    },
  });
  assertLifecycleError(() =>
    reduceReleaseEvent(initial(), accessor, {
      expectedPublicKey: keys.payer.publicKey,
    }),
  );
});

test("rejects hostile paymentMoved views before reading event authority", () => {
  const base = initial();
  const missing = structuredClone(base);
  delete missing.paymentMoved;
  const moved = structuredClone(base);
  moved.paymentMoved = true;
  const nullMoved = structuredClone(base);
  nullMoved.paymentMoved = null;
  const stringMoved = structuredClone(base);
  stringMoved.paymentMoved = "false";
  const extra = structuredClone(base);
  extra.extra = false;
  const accessor = structuredClone(base);
  let paymentGetterCalls = 0;
  Object.defineProperty(accessor, "paymentMoved", {
    enumerable: true,
    get() {
      paymentGetterCalls += 1;
      return false;
    },
  });

  for (const currentView of [
    missing,
    moved,
    nullMoved,
    stringMoved,
    extra,
    accessor,
  ]) {
    let eventTouches = 0;
    const untouchedEvent = new Proxy({}, {
      getPrototypeOf() {
        eventTouches += 1;
        throw new Error("event authority must be unreachable");
      },
      ownKeys() {
        eventTouches += 1;
        throw new Error("event authority must be unreachable");
      },
    });
    assertLifecycleError(() =>
      reduceReleaseEvent(currentView, untouchedEvent, {}),
    );
    assert.equal(eventTouches, 0);
  }
  assert.equal(paymentGetterCalls, 0);
});

test("reducer returns a fresh frozen view without retaining caller objects", () => {
  const view = initial();
  const payerEnrollment = structuredClone(
    event(
      "ENROLLMENT_CONFIRMED",
      "payer",
      "release",
    ),
  );
  const next = reduceReleaseEvent(view, payerEnrollment, {
    expectedPublicKey: keys.payer.publicKey,
  });

  payerEnrollment.kind = "TERMINAL_FAILURE";
  assert.equal(
    next.facts.enrollmentConfirmed.payer,
    true,
  );
  assert.equal(view.facts.enrollmentConfirmed.payer, false);
  assert.equal(next.paymentMoved, false);
  assert.notEqual(next, view);
  assert.notEqual(next.facts, view.facts);
  assertDeepFrozen(next);
});
