import {
  verifyCoordinationEnvelope,
} from "./envelope.mjs";
import {
  MAX_CANONICAL_STRING_LENGTH,
} from "../canonical.mjs";

export const RELEASE_STATES = Object.freeze([
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

export const COORDINATION_EVENT_AUTHORITIES =
  Object.freeze({
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

export const COORDINATION_EVENT_KINDS = Object.freeze(
  Object.keys(COORDINATION_EVENT_AUTHORITIES),
);

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
const ENVELOPE_KEYS = Object.freeze([
  "artifactDigest",
  "eventDigest",
  "kind",
  "paymentMoved",
  "previousEventDigest",
  "releaseId",
  "repositorySha",
  "role",
  "schema",
  "sequence",
  "sessionId",
  "signature",
  "subjectRun",
]);
const SIGNATURE_KEYS = Object.freeze([
  "algorithm",
  "keyId",
  "publicKey",
  "value",
]);
const ROLE_KEYS = Object.freeze(["payee", "payer"]);
const RUN_KEYS = Object.freeze([
  "rehearsal",
  "stakeholder",
]);
const RECOVERY_RUN_KEYS = Object.freeze([
  "rehearsal",
  "release",
  "stakeholder",
]);
const REDUCTION_OPTIONS_KEYS = Object.freeze([
  "expectedPublicKey",
]);
const VERIFICATION_OPTIONS_KEYS = Object.freeze([
  "expectedPublicKey",
  "verifierPublicationVerified",
]);
const ROLES = Object.freeze(["payee", "payer"]);
const SUBJECT_RUNS = Object.freeze([
  "release",
  "rehearsal",
  "stakeholder",
]);
const REPOSITORY_SHA_PATTERN = /^[0-9a-f]{40}$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PRINTABLE_ASCII_PATTERN = /^[ -~]+$/;

const EVENT_RUNS = Object.freeze({
  COMPLETE_RELEASE: Object.freeze(["release"]),
  DESCRIPTOR_ACCEPTED: RUN_KEYS,
  ENROLLMENT_CONFIRMED: Object.freeze(["release"]),
  ENROLLMENT_RECEIPT: Object.freeze(["release"]),
  EXACT_RECOVERY_AUTHORIZATION: RECOVERY_RUN_KEYS,
  FUNDING_INPUTS_READY: Object.freeze(["release"]),
  IDENTITY_PACKAGE_READY: RUN_KEYS,
  PAYER_MANDATE_READY: RUN_KEYS,
  PAYMENT_REQUEST_READY: RUN_KEYS,
  PAYMENT_REQUEST_MATCHED: RUN_KEYS,
  PREFLIGHT_PARTICIPANT_READY: Object.freeze([
    "release",
  ]),
  PREFLIGHT_PLAN_READY: Object.freeze(["release"]),
  RECOVERY_REQUIRED: RECOVERY_RUN_KEYS,
  REGISTER_REHEARSAL: Object.freeze(["rehearsal"]),
  REGISTER_STAKEHOLDER: Object.freeze(["stakeholder"]),
  REHEARSAL_DESCRIPTOR_READY: Object.freeze([
    "rehearsal",
  ]),
  ROLE_PACKAGE_READY: RUN_KEYS,
  ROLE_STARTED: RUN_KEYS,
  STAKEHOLDER_DESCRIPTOR_READY: Object.freeze([
    "stakeholder",
  ]),
  START_REHEARSAL: Object.freeze(["rehearsal"]),
  START_STAKEHOLDER: Object.freeze(["stakeholder"]),
  TERMINAL_ABORT: SUBJECT_RUNS,
  TERMINAL_FAILURE: SUBJECT_RUNS,
  TOKEN_READY: Object.freeze(["release"]),
  VERIFICATION_FAILED: RUN_KEYS,
  VERIFICATION_PASSED: RUN_KEYS,
  WAIT_FOR_FUNDING: Object.freeze(["release"]),
});

export class CoordinationLifecycleError extends Error {
  constructor() {
    super("Coordination lifecycle validation failed.");
    this.name = new.target.name;
    this.category = "verification";
    this.code = "COORDINATION_LIFECYCLE_INVALID";
  }
}

function invalid() {
  throw new CoordinationLifecycleError();
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object") {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return (
    prototype === Object.prototype || prototype === null
  );
}

function readExactData(value, keys) {
  try {
    if (!isPlainObject(value)) {
      invalid();
    }
    const ownKeys = Reflect.ownKeys(value);
    if (
      ownKeys.length !== keys.length ||
      ownKeys.some(
        (key) =>
          typeof key !== "string" || !keys.includes(key),
      )
    ) {
      invalid();
    }
    const result = new Map();
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(
        value,
        key,
      );
      if (
        descriptor?.enumerable !== true ||
        !Object.hasOwn(descriptor, "value")
      ) {
        invalid();
      }
      result.set(key, descriptor.value);
    }
    return result;
  } catch (error) {
    if (error instanceof CoordinationLifecycleError) {
      throw error;
    }
    invalid();
  }
}

function assertBoolean(value) {
  if (typeof value !== "boolean") {
    invalid();
  }
  return value;
}

function assertNullableSha256(value) {
  if (
    value !== null &&
    (typeof value !== "string" ||
      !SHA256_PATTERN.test(value))
  ) {
    invalid();
  }
  return value;
}

function roleFacts(value) {
  const data = readExactData(value, ROLE_KEYS);
  return {
    payee: assertBoolean(data.get("payee")),
    payer: assertBoolean(data.get("payer")),
  };
}

function runRoleFacts(value) {
  const data = readExactData(value, RUN_KEYS);
  return {
    rehearsal: roleFacts(data.get("rehearsal")),
    stakeholder: roleFacts(data.get("stakeholder")),
  };
}

function runFacts(value) {
  const data = readExactData(value, RUN_KEYS);
  return {
    rehearsal: assertBoolean(data.get("rehearsal")),
    stakeholder: assertBoolean(data.get("stakeholder")),
  };
}

function roleDigestFacts(value) {
  const data = readExactData(value, ROLE_KEYS);
  return {
    payee: assertNullableSha256(data.get("payee")),
    payer: assertNullableSha256(data.get("payer")),
  };
}

function recoveryRoleDigestFacts(value) {
  const data = readExactData(value, RECOVERY_RUN_KEYS);
  return {
    rehearsal: roleDigestFacts(data.get("rehearsal")),
    release: roleDigestFacts(data.get("release")),
    stakeholder: roleDigestFacts(
      data.get("stakeholder"),
    ),
  };
}

function assertRecoveryBindings(required, authorized) {
  const requestDigests = new Set();
  for (const run of RECOVERY_RUN_KEYS) {
    for (const role of ROLES) {
      const requiredDigest = required[run][role];
      if (requiredDigest !== null) {
        if (requestDigests.has(requiredDigest)) {
          invalid();
        }
        requestDigests.add(requiredDigest);
      }
      if (
        authorized[run][role] !== null &&
        authorized[run][role] !== requiredDigest
      ) {
        invalid();
      }
    }
  }
}

function readFacts(value) {
  const data = readExactData(value, FACT_KEYS);
  const facts = {
    descriptorAccepted: runRoleFacts(
      data.get("descriptorAccepted"),
    ),
    enrollmentConfirmed: roleFacts(
      data.get("enrollmentConfirmed"),
    ),
    enrollmentReceipt: assertBoolean(
      data.get("enrollmentReceipt"),
    ),
    fundingInputsReady: roleFacts(
      data.get("fundingInputsReady"),
    ),
    identityPackageReady: runRoleFacts(
      data.get("identityPackageReady"),
    ),
    payerMandateReady: runFacts(data.get("payerMandateReady")),
    paymentRequestReady: runFacts(data.get("paymentRequestReady")),
    paymentRequestMatched: runFacts(data.get("paymentRequestMatched")),
    preflightParticipantReady: roleFacts(
      data.get("preflightParticipantReady"),
    ),
    preflightPlanReady: assertBoolean(
      data.get("preflightPlanReady"),
    ),
    recoveryAuthorized: recoveryRoleDigestFacts(
      data.get("recoveryAuthorized"),
    ),
    recoveryRequired: recoveryRoleDigestFacts(
      data.get("recoveryRequired"),
    ),
    releaseCompleted: assertBoolean(
      data.get("releaseCompleted"),
    ),
    registered: runFacts(data.get("registered")),
    rolePackageReady: runRoleFacts(
      data.get("rolePackageReady"),
    ),
    roleStarted: runRoleFacts(data.get("roleStarted")),
    runDescriptorReady: runFacts(
      data.get("runDescriptorReady"),
    ),
    runStarted: runFacts(data.get("runStarted")),
    tokenReady: roleFacts(data.get("tokenReady")),
    verifierPublicationVerified: runFacts(
      data.get("verifierPublicationVerified"),
    ),
    verificationPassed: runFacts(
      data.get("verificationPassed"),
    ),
    waitForFunding: assertBoolean(
      data.get("waitForFunding"),
    ),
  };
  assertRecoveryBindings(
    facts.recoveryRequired,
    facts.recoveryAuthorized,
  );
  return facts;
}

function emptyRoleFacts() {
  return {
    payee: false,
    payer: false,
  };
}

function emptyRunRoleFacts() {
  return {
    rehearsal: emptyRoleFacts(),
    stakeholder: emptyRoleFacts(),
  };
}

function emptyRunFacts() {
  return {
    rehearsal: false,
    stakeholder: false,
  };
}

function emptyRoleDigestFacts() {
  return {
    payee: null,
    payer: null,
  };
}

function emptyRecoveryRoleDigestFacts() {
  return {
    rehearsal: emptyRoleDigestFacts(),
    release: emptyRoleDigestFacts(),
    stakeholder: emptyRoleDigestFacts(),
  };
}

function emptyFacts() {
  return {
    descriptorAccepted: emptyRunRoleFacts(),
    enrollmentConfirmed: emptyRoleFacts(),
    enrollmentReceipt: false,
    fundingInputsReady: emptyRoleFacts(),
    identityPackageReady: emptyRunRoleFacts(),
    payerMandateReady: emptyRunFacts(),
    paymentRequestReady: emptyRunFacts(),
    paymentRequestMatched: emptyRunFacts(),
    preflightParticipantReady: emptyRoleFacts(),
    preflightPlanReady: false,
    recoveryAuthorized: emptyRecoveryRoleDigestFacts(),
    recoveryRequired: emptyRecoveryRoleDigestFacts(),
    releaseCompleted: false,
    registered: emptyRunFacts(),
    rolePackageReady: emptyRunRoleFacts(),
    roleStarted: emptyRunRoleFacts(),
    runDescriptorReady: emptyRunFacts(),
    runStarted: emptyRunFacts(),
    tokenReady: emptyRoleFacts(),
    verifierPublicationVerified: emptyRunFacts(),
    verificationPassed: emptyRunFacts(),
    waitForFunding: false,
  };
}

function deepFreeze(value) {
  for (const child of Object.values(value)) {
    if (child !== null && typeof child === "object") {
      deepFreeze(child);
    }
  }
  return Object.freeze(value);
}

function assertReleaseId(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > MAX_CANONICAL_STRING_LENGTH ||
    !PRINTABLE_ASCII_PATTERN.test(value) ||
    value.trim() !== value
  ) {
    invalid();
  }
  return value;
}

function assertRepositorySha(value) {
  if (
    typeof value !== "string" ||
    !REPOSITORY_SHA_PATTERN.test(value)
  ) {
    invalid();
  }
  return value;
}

function assertSessionId(value) {
  if (
    typeof value !== "string" ||
    !UUID_PATTERN.test(value)
  ) {
    invalid();
  }
  return value;
}

function both(roleValues) {
  return roleValues.payee && roleValues.payer;
}

function deriveState(facts) {
  if (!both(facts.enrollmentConfirmed)) {
    return "BOOTSTRAPPING";
  }
  if (
    !facts.enrollmentReceipt ||
    !facts.waitForFunding ||
    !both(facts.fundingInputsReady) ||
    !both(facts.tokenReady)
  ) {
    return "ADDRESSES_READY";
  }
  if (!facts.preflightPlanReady) {
    return "FUNDING_READY";
  }
  if (!both(facts.preflightParticipantReady)) {
    return "PREFLIGHT_READY";
  }
  if (
    !facts.registered.rehearsal ||
    !both(facts.identityPackageReady.rehearsal)
  ) {
    return "PREFLIGHT_PASSED";
  }
  if (!facts.runDescriptorReady.rehearsal) {
    return "REHEARSAL_IDENTITIES_READY";
  }
  if (!facts.runStarted.rehearsal) {
    return "REHEARSAL_DESCRIPTOR_READY";
  }
  if (
    !facts.verificationPassed.rehearsal ||
    !facts.verifierPublicationVerified.rehearsal
  ) {
    return "REHEARSAL_RUNNING";
  }
  if (
    !facts.registered.stakeholder ||
    !both(facts.identityPackageReady.stakeholder)
  ) {
    return "REHEARSAL_VERIFIED";
  }
  if (!facts.runDescriptorReady.stakeholder) {
    return "STAKEHOLDER_IDENTITIES_READY";
  }
  if (!facts.runStarted.stakeholder) {
    return "STAKEHOLDER_DESCRIPTOR_READY";
  }
  if (
    !facts.verificationPassed.stakeholder ||
    !facts.verifierPublicationVerified.stakeholder
  ) {
    return "STAKEHOLDER_RUNNING";
  }
  if (!facts.releaseCompleted) {
    return "STAKEHOLDER_VERIFIED";
  }
  return "COMPLETE";
}

function makeView({
  facts,
  releaseId,
  repositorySha,
  sessionId,
  state = deriveState(facts),
}) {
  return deepFreeze({
    facts,
    paymentMoved: false,
    releaseId,
    repositorySha,
    sessionId,
    state,
  });
}

function readView(value) {
  const data = readExactData(value, VIEW_KEYS);
  const facts = readFacts(data.get("facts"));
  const paymentMoved = data.get("paymentMoved");
  if (paymentMoved !== false) {
    invalid();
  }
  const releaseId = assertReleaseId(data.get("releaseId"));
  const repositorySha = assertRepositorySha(
    data.get("repositorySha"),
  );
  const sessionId = assertSessionId(data.get("sessionId"));
  const state = data.get("state");
  if (!RELEASE_STATES.includes(state)) {
    invalid();
  }
  if (
    state !== "ABORTED" &&
    state !== deriveState(facts)
  ) {
    invalid();
  }
  return {
    facts,
    paymentMoved,
    releaseId,
    repositorySha,
    sessionId,
    state,
  };
}

function readVerifiedEvent(
  event,
  view,
  expectedPublicKey,
) {
  const data = readExactData(event, ENVELOPE_KEYS);
  const role = data.get("role");
  const subjectRun = data.get("subjectRun");
  readExactData(data.get("signature"), SIGNATURE_KEYS);
  if (
    !["operator", ...ROLES].includes(role) ||
    !SUBJECT_RUNS.includes(subjectRun)
  ) {
    invalid();
  }
  try {
    return verifyCoordinationEnvelope(event, {
      expectedPublicKey,
      expectedReleaseId: view.releaseId,
      expectedRepositorySha: view.repositorySha,
      expectedRole: role,
      expectedSessionId: view.sessionId,
      expectedSubjectRun: subjectRun,
    });
  } catch {
    invalid();
  }
}

function assertAuthority(event) {
  const authority =
    COORDINATION_EVENT_AUTHORITIES[event.kind];
  if (
    authority === undefined ||
    (authority === "operator" &&
      event.role !== "operator") ||
    (authority === "role" && !ROLES.includes(event.role))
  ) {
    invalid();
  }
}

function assertRunScope(event) {
  if (!EVENT_RUNS[event.kind]?.includes(event.subjectRun)) {
    invalid();
  }
}

function assertUnused(value) {
  if (value) {
    invalid();
  }
}

function requireState(view, expected) {
  if (view.state !== expected) {
    invalid();
  }
}

function requireBoth(value) {
  if (!both(value)) {
    invalid();
  }
}

function recoveryDigestExists(facts, digest) {
  for (const run of RECOVERY_RUN_KEYS) {
    for (const role of ROLES) {
      if (
        facts.recoveryRequired[run][role] === digest ||
        facts.recoveryAuthorized[run][role] === digest
      ) {
        return true;
      }
    }
  }
  return false;
}

function readReductionOptions(options, kind) {
  const keys =
    kind === "VERIFICATION_PASSED"
      ? VERIFICATION_OPTIONS_KEYS
      : REDUCTION_OPTIONS_KEYS;
  const data = readExactData(options, keys);
  if (
    typeof data.get("expectedPublicKey") !== "string" ||
    (kind === "VERIFICATION_PASSED" &&
      data.get("verifierPublicationVerified") !== true)
  ) {
    invalid();
  }
  return data.get("expectedPublicKey");
}

export function initialReleaseView(input) {
  const data = readExactData(input, INITIAL_KEYS);
  return makeView({
    facts: emptyFacts(),
    releaseId: assertReleaseId(data.get("releaseId")),
    repositorySha: assertRepositorySha(
      data.get("repositorySha"),
    ),
    sessionId: assertSessionId(data.get("sessionId")),
  });
}

export function reduceReleaseEvent(
  currentView,
  unverifiedEvent,
  options,
) {
  const view = readView(currentView);
  if (
    view.state === "ABORTED" ||
    view.state === "COMPLETE"
  ) {
    invalid();
  }
  const eventData = readExactData(
    unverifiedEvent,
    ENVELOPE_KEYS,
  );
  const expectedPublicKey = readReductionOptions(
    options,
    eventData.get("kind"),
  );
  const event = readVerifiedEvent(
    unverifiedEvent,
    view,
    expectedPublicKey,
  );
  assertAuthority(event);
  assertRunScope(event);

  if (
    event.kind === "TERMINAL_FAILURE" ||
    event.kind === "TERMINAL_ABORT" ||
    event.kind === "VERIFICATION_FAILED"
  ) {
    return makeView({
      ...view,
      state: "ABORTED",
    });
  }

  const facts = view.facts;
  const role = event.role;
  const run = event.subjectRun;

  switch (event.kind) {
    case "ENROLLMENT_CONFIRMED": {
      requireState(view, "BOOTSTRAPPING");
      assertUnused(facts.enrollmentConfirmed[role]);
      facts.enrollmentConfirmed[role] = true;
      break;
    }
    case "ENROLLMENT_RECEIPT": {
      requireState(view, "ADDRESSES_READY");
      assertUnused(facts.enrollmentReceipt);
      facts.enrollmentReceipt = true;
      break;
    }
    case "WAIT_FOR_FUNDING": {
      requireState(view, "ADDRESSES_READY");
      if (!facts.enrollmentReceipt) {
        invalid();
      }
      assertUnused(facts.waitForFunding);
      facts.waitForFunding = true;
      break;
    }
    case "FUNDING_INPUTS_READY": {
      requireState(view, "ADDRESSES_READY");
      if (
        !facts.enrollmentReceipt ||
        !facts.waitForFunding
      ) {
        invalid();
      }
      assertUnused(facts.fundingInputsReady[role]);
      facts.fundingInputsReady[role] = true;
      break;
    }
    case "TOKEN_READY": {
      requireState(view, "ADDRESSES_READY");
      requireBoth(facts.fundingInputsReady);
      assertUnused(facts.tokenReady[role]);
      facts.tokenReady[role] = true;
      break;
    }
    case "PREFLIGHT_PLAN_READY": {
      requireState(view, "FUNDING_READY");
      assertUnused(facts.preflightPlanReady);
      facts.preflightPlanReady = true;
      break;
    }
    case "PREFLIGHT_PARTICIPANT_READY": {
      requireState(view, "PREFLIGHT_READY");
      assertUnused(facts.preflightParticipantReady[role]);
      facts.preflightParticipantReady[role] = true;
      break;
    }
    case "REGISTER_REHEARSAL": {
      requireState(view, "PREFLIGHT_PASSED");
      assertUnused(facts.registered.rehearsal);
      facts.registered.rehearsal = true;
      break;
    }
    case "REGISTER_STAKEHOLDER": {
      requireState(view, "REHEARSAL_VERIFIED");
      assertUnused(facts.registered.stakeholder);
      facts.registered.stakeholder = true;
      break;
    }
    case "IDENTITY_PACKAGE_READY": {
      if (!facts.registered[run]) {
        invalid();
      }
      requireState(
        view,
        run === "rehearsal"
          ? "PREFLIGHT_PASSED"
          : "REHEARSAL_VERIFIED",
      );
      assertUnused(facts.identityPackageReady[run][role]);
      facts.identityPackageReady[run][role] = true;
      break;
    }
    case "REHEARSAL_DESCRIPTOR_READY":
    case "STAKEHOLDER_DESCRIPTOR_READY": {
      const expectedState =
        run === "rehearsal"
          ? "REHEARSAL_IDENTITIES_READY"
          : "STAKEHOLDER_IDENTITIES_READY";
      requireState(view, expectedState);
      requireBoth(facts.identityPackageReady[run]);
      if (!facts.payerMandateReady[run] || !facts.paymentRequestReady[run] || !facts.paymentRequestMatched[run]) invalid();
      assertUnused(facts.runDescriptorReady[run]);
      facts.runDescriptorReady[run] = true;
      break;
    }
    case "PAYER_MANDATE_READY": {
      requireState(view, run === "rehearsal" ? "REHEARSAL_IDENTITIES_READY" : "STAKEHOLDER_IDENTITIES_READY");
      requireBoth(facts.identityPackageReady[run]);
      assertUnused(facts.payerMandateReady[run]);
      facts.payerMandateReady[run] = true;
      break;
    }
    case "PAYMENT_REQUEST_READY": {
      requireState(view, run === "rehearsal" ? "REHEARSAL_IDENTITIES_READY" : "STAKEHOLDER_IDENTITIES_READY");
      if (!facts.payerMandateReady[run]) invalid();
      assertUnused(facts.paymentRequestReady[run]);
      facts.paymentRequestReady[run] = true;
      break;
    }
    case "PAYMENT_REQUEST_MATCHED": {
      requireState(view, run === "rehearsal" ? "REHEARSAL_IDENTITIES_READY" : "STAKEHOLDER_IDENTITIES_READY");
      if (!facts.paymentRequestReady[run]) invalid();
      assertUnused(facts.paymentRequestMatched[run]);
      facts.paymentRequestMatched[run] = true;
      break;
    }
    case "DESCRIPTOR_ACCEPTED": {
      requireState(
        view,
        run === "rehearsal"
          ? "REHEARSAL_DESCRIPTOR_READY"
          : "STAKEHOLDER_DESCRIPTOR_READY",
      );
      if (!facts.runDescriptorReady[run]) {
        invalid();
      }
      assertUnused(facts.descriptorAccepted[run][role]);
      facts.descriptorAccepted[run][role] = true;
      break;
    }
    case "START_REHEARSAL":
    case "START_STAKEHOLDER": {
      requireState(
        view,
        run === "rehearsal"
          ? "REHEARSAL_DESCRIPTOR_READY"
          : "STAKEHOLDER_DESCRIPTOR_READY",
      );
      requireBoth(facts.descriptorAccepted[run]);
      assertUnused(facts.runStarted[run]);
      facts.runStarted[run] = true;
      break;
    }
    case "ROLE_STARTED": {
      requireState(
        view,
        run === "rehearsal"
          ? "REHEARSAL_RUNNING"
          : "STAKEHOLDER_RUNNING",
      );
      if (!facts.runStarted[run]) {
        invalid();
      }
      assertUnused(facts.roleStarted[run][role]);
      facts.roleStarted[run][role] = true;
      break;
    }
    case "ROLE_PACKAGE_READY": {
      requireState(
        view,
        run === "rehearsal"
          ? "REHEARSAL_RUNNING"
          : "STAKEHOLDER_RUNNING",
      );
      if (!facts.roleStarted[run][role]) {
        invalid();
      }
      assertUnused(facts.rolePackageReady[run][role]);
      facts.rolePackageReady[run][role] = true;
      break;
    }
    case "VERIFICATION_PASSED": {
      requireState(
        view,
        run === "rehearsal"
          ? "REHEARSAL_RUNNING"
          : "STAKEHOLDER_RUNNING",
      );
      requireBoth(facts.roleStarted[run]);
      requireBoth(facts.rolePackageReady[run]);
      assertUnused(facts.verificationPassed[run]);
      assertUnused(
        facts.verifierPublicationVerified[run],
      );
      facts.verificationPassed[run] = true;
      facts.verifierPublicationVerified[run] = true;
      break;
    }
    case "COMPLETE_RELEASE": {
      requireState(view, "STAKEHOLDER_VERIFIED");
      assertUnused(facts.releaseCompleted);
      facts.releaseCompleted = true;
      break;
    }
    case "RECOVERY_REQUIRED": {
      if (
        run === "rehearsal" &&
        !facts.runStarted.rehearsal
      ) {
        invalid();
      }
      if (
        run === "stakeholder" &&
        !facts.runStarted.stakeholder
      ) {
        invalid();
      }
      if (event.artifactDigest === null) {
        invalid();
      }
      assertUnused(facts.recoveryRequired[run][role]);
      if (recoveryDigestExists(facts, event.artifactDigest)) {
        invalid();
      }
      facts.recoveryRequired[run][role] =
        event.artifactDigest;
      break;
    }
    case "EXACT_RECOVERY_AUTHORIZATION": {
      if (event.artifactDigest === null) {
        invalid();
      }
      const matchingRoles = ROLES.filter(
        (candidateRole) =>
          facts.recoveryRequired[run][candidateRole] ===
            event.artifactDigest &&
          facts.recoveryAuthorized[run][candidateRole] ===
            null,
      );
      if (matchingRoles.length !== 1) {
        invalid();
      }
      facts.recoveryAuthorized[run][matchingRoles[0]] =
        event.artifactDigest;
      break;
    }
    default:
      invalid();
  }

  return makeView({
    facts,
    releaseId: view.releaseId,
    repositorySha: view.repositorySha,
    sessionId: view.sessionId,
  });
}
