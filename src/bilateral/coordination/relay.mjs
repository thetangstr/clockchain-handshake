import {
  createHash,
  createPublicKey,
  timingSafeEqual,
  verify,
} from "node:crypto";

import {
  recoverMessageAddress,
  toHex,
} from "viem";

import {
  canonicalizeReceiptEventValue,
} from "../../canonical.mjs";
import {
  canonicalBytes,
} from "../canonical.mjs";
import {
  payerMandateDigest,
  verifyPayerMandate,
} from "../payer-mandate.mjs";
import {
  paymentRequestDigest,
  verifyPaymentRequest,
} from "../payment-request.mjs";
import {
  operatorPublicKeyPath,
  dSession,
  publicKeyPemFromRawBase64,
  verifyDescriptorEnvelope,
} from "../descriptor.mjs";
import {
  validateRelayArtifact,
  validateRelayArtifactWithFacts,
} from "./artifact.mjs";
import {
  COORDINATION_ENROLLMENT_SET_SCHEMA,
  invitationProofPreimage,
  parseCoordinationEnrollment,
  parseCoordinationEnrollmentSet,
} from "./enrollment.mjs";
import {
  CAPABILITY_REGISTRATION_SCHEMA,
  verifyCapabilityRegistration,
} from "./capability-registration.mjs";
import {
  initialReleaseView,
  reduceReleaseEvent,
} from "./lifecycle.mjs";
import {
  COORDINATION_RECEIPT_SCHEMA,
  COORDINATION_RECEIPT_SIGNATURE_DOMAIN,
  createCoordinationReceipt,
  validateReceiptSigner,
  verifyCoordinationReceipt,
} from "./receipt.mjs";

export {
  COORDINATION_RECEIPT_SCHEMA,
  COORDINATION_RECEIPT_SIGNATURE_DOMAIN,
};
export const MAX_RELAY_REQUEST_BYTES = 65_536;
export const MAX_RELAY_WAIT_MS = 30_000;
export const VERIFIER_PUBLICATION_SCHEMA = "clockchain.bilateral-verifier-publication/v1";
export const VERIFIED_EVENT_SCHEMA = "clockchain.bilateral-verified-event/v1";
export const CAPABILITY_REGISTRATION_RECEIPT_SCHEMA =
  "clockchain.bilateral-capability-registration-receipt/v1";
export const ENROLLMENT_READINESS_SCHEMA =
  "clockchain.bilateral-enrollment-readiness/v1";

const SERVICE_KEYS = Object.freeze([
  "appendEvent",
  "appendVerifiedEvent",
  "bootstrap",
  "getArtifact",
  "putArtifact",
  "readPayerMandate",
  "readPaymentRequest",
  "readEnrollmentReadiness",
  "registerCapabilities",
  "readEnrollmentSet",
  "readEvents",
  "readSessionView",
  "readVerifierPublication",
  "submitPaymentRequest",
]);
const DEPENDENCY_KEYS = Object.freeze([
  "frozenRepositorySha",
  "now",
  "receiptSigner",
  "repositoryPublicKeyResolver",
  "store",
]);
const DEPENDENCY_KEYS_WITHOUT_NOW = Object.freeze(
  DEPENDENCY_KEYS.filter((key) => key !== "now"),
);
const STORE_METHODS = Object.freeze([
  "appendEvent",
  "appendVerifiedEvent",
  "consumeCapability",
  "getArtifact",
  "putArtifact",
  "putPayerMandate",
  "putPaymentRequest",
  "readEnrollment",
  "readPayerMandate",
  "readPaymentRequest",
  "readCapabilitySet",
  "readEvents",
  "readReleaseView",
  "readVerifierPublication",
  "registerCapabilitySet",
]);
const BOOTSTRAP_INPUT_KEYS = Object.freeze(["body"]);
const BOOTSTRAP_KEYS = Object.freeze([
  "capability",
  "enrollment",
]);
const APPEND_INPUT_KEYS = Object.freeze(["body"]);
const VERIFIED_WRAPPER_KEYS = Object.freeze(["event", "paymentMoved", "publication", "schema"]);
const PUBLICATION_KEYS = Object.freeze(["paymentMoved", "publicationDigest", "releaseId", "repositorySha", "schema", "sessionId", "status", "subjectRun"]);
const READ_VERIFIER_PUBLICATION_KEYS = Object.freeze([
  "sessionId",
  "subjectRun",
]);
const GET_ARTIFACT_KEYS = Object.freeze(["digest"]);
const PUT_ARTIFACT_KEYS = Object.freeze([
  "artifactType",
  "body",
  "expectedDigest",
]);
const READ_PAYER_MANDATE_KEYS = Object.freeze(["sessionId", "subjectRun"]);
const READ_PAYMENT_REQUEST_KEYS = Object.freeze(["requestId", "sessionId"]);
const SUBMIT_PAYMENT_REQUEST_KEYS = Object.freeze(["body", "sessionId"]);
const READ_ENROLLMENT_READINESS_KEYS = Object.freeze([
  "sessionId",
  "waitMs",
]);
const READ_ENROLLMENT_READINESS_KEYS_WITH_SIGNAL = Object.freeze([
  "sessionId",
  "signal",
  "waitMs",
]);

function verifierPublicationMatchesEvent(publication, event) {
  const claim = readExactData(publication, PUBLICATION_KEYS);
  return (
    claim.schema === VERIFIER_PUBLICATION_SCHEMA &&
    claim.paymentMoved === false &&
    claim.publicationDigest === event.artifactDigest &&
    claim.releaseId === event.releaseId &&
    claim.repositorySha === event.repositorySha &&
    claim.sessionId === event.sessionId &&
    claim.subjectRun === event.subjectRun &&
    claim.status === "VERIFICATION_PASSED"
  );
}

function readVerifierPublicationClaim(value, {
  repositorySha,
  sessionId,
  subjectRun,
}) {
  const claim = readExactData(value, PUBLICATION_KEYS);
  if (
    claim.schema !== VERIFIER_PUBLICATION_SCHEMA ||
    claim.paymentMoved !== false ||
    typeof claim.publicationDigest !== "string" ||
    !SHA256_PATTERN.test(claim.publicationDigest) ||
    typeof claim.releaseId !== "string" ||
    claim.releaseId.length === 0 ||
    claim.repositorySha !== repositorySha ||
    claim.sessionId !== sessionId ||
    claim.subjectRun !== subjectRun ||
    !["rehearsal", "stakeholder"].includes(claim.subjectRun) ||
    claim.status !== "VERIFICATION_PASSED"
  ) {
    invalid();
  }
  return Object.freeze(claim);
}
const READ_EVENTS_KEYS = Object.freeze([
  "after",
  "sessionId",
  "waitMs",
]);
const READ_EVENTS_KEYS_WITH_SIGNAL = Object.freeze([
  "after",
  "sessionId",
  "signal",
  "waitMs",
]);
const READ_SESSION_KEYS = Object.freeze(["sessionId"]);
const STORED_ENROLLMENT_KEYS = Object.freeze([
  "bytes",
  "digest",
  "receiptBytes",
]);
const DESCRIPTOR_VALIDATOR_KEYS = Object.freeze([
  "frozenRepositorySha",
  "readArtifact",
  "resolveOperatorPublicKey",
]);
const ARTIFACT_TRANSITION_VALIDATOR_KEYS = Object.freeze([
  "frozenRepositorySha",
  "readArtifact",
  "readEnrollment",
  "resolveOperatorPublicKey",
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
const ENVELOPE_SIGNATURE_KEYS = Object.freeze([
  "algorithm",
  "keyId",
  "publicKey",
  "value",
]);
const RELEASE_VIEW_KEYS = Object.freeze([
  "events",
  "paymentMoved",
  "releaseId",
  "repositorySha",
  "sessionId",
]);
const CONSUMPTION_KEYS = Object.freeze([
  "capabilityDigest",
  "enrollmentBytes",
  "enrollmentDigest",
  "receiptBytes",
]);
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const CAPABILITY_PATTERN = /^[0-9a-f]{64}$/;
const REPOSITORY_SHA_PATTERN = /^[0-9a-f]{40}$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DESCRIPTOR_EVENT_KINDS = new Set([
  "DESCRIPTOR_ACCEPTED",
  "REHEARSAL_DESCRIPTOR_READY",
  "STAKEHOLDER_DESCRIPTOR_READY",
]);
const ARTIFACT_EVENT_TYPES = Object.freeze({
  EXACT_RECOVERY_AUTHORIZATION: "recovery-command-manifest",
  IDENTITY_PACKAGE_READY: "identity-package",
  PREFLIGHT_PARTICIPANT_READY: "preflight-participant-report",
  PREFLIGHT_PLAN_READY: "preflight-plan",
  PAYER_MANDATE_READY: "payer-mandate",
  PAYMENT_REQUEST_READY: "payment-request",
  RECOVERY_REQUIRED: "recovery-command-manifest",
  REGISTER_REHEARSAL: "preflight-aggregate-report",
  ROLE_PACKAGE_READY: "party-result-package",
  TERMINAL_FAILURE: "failure-summary",
  TOKEN_READY: "token-commitment",
});

export class CoordinationRelayError extends Error {
  constructor(code = "COORDINATION_RELAY_INVALID") {
    super("Coordination relay operation failed safely.");
    this.name = new.target.name;
    this.category = "verification";
    this.code = /^COORDINATION_[A-Z_]+$/.test(code)
      ? code
      : "COORDINATION_RELAY_INVALID";
  }
}

function invalid(code) {
  throw new CoordinationRelayError(code);
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object") {
    return false;
  }
  try {
    const prototype = Object.getPrototypeOf(value);
    return (
      prototype === Object.prototype || prototype === null
    );
  } catch {
    return false;
  }
}

function readExactData(value, keys) {
  if (!isPlainObject(value)) {
    invalid();
  }
  let ownKeys;
  try {
    ownKeys = Reflect.ownKeys(value);
  } catch {
    invalid();
  }
  if (
    ownKeys.length !== keys.length ||
    ownKeys.some(
      (key) =>
        typeof key !== "string" || !keys.includes(key),
    )
  ) {
    invalid();
  }
  const result = Object.create(null);
  for (const key of keys) {
    let descriptor;
    try {
      descriptor = Object.getOwnPropertyDescriptor(value, key);
    } catch {
      invalid();
    }
    if (
      descriptor?.enumerable !== true ||
      !Object.hasOwn(descriptor, "value")
    ) {
      invalid();
    }
    Object.defineProperty(result, key, {
      enumerable: true,
      value: descriptor.value,
    });
  }
  return result;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function enrollmentContainsCapability(
  enrollmentBytes,
  enrollment,
  capability,
) {
  const text = enrollmentBytes.toString("utf8");
  const coordinationKey = Buffer.from(
    enrollment.coordinationKey.publicKey,
    "base64",
  );
  const preflightKey = Buffer.from(
    enrollment.preflightKey.publicKey,
    "base64",
  );
  return (
    text
      .toLowerCase()
      .includes(capability.toString("hex")) ||
    text.includes(capability.toString("base64")) ||
    text.includes(capability.toString("base64url")) ||
    timingSafeEqual(coordinationKey, capability) ||
    timingSafeEqual(preflightKey, capability)
  );
}

function assertSha256(value) {
  if (
    typeof value !== "string" ||
    !SHA256_PATTERN.test(value)
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

function stableBytes(value) {
  try {
    return Buffer.from(
      JSON.stringify(
        canonicalizeReceiptEventValue(value),
      ),
      "utf8",
    );
  } catch {
    invalid();
  }
}

function parseCanonicalBody(value, maximum) {
  if (
    !Buffer.isBuffer(value) ||
    value.length === 0 ||
    value.length > maximum
  ) {
    invalid();
  }
  try {
    const bytes = Buffer.from(value);
    const text = bytes.toString("utf8");
    if (Buffer.byteLength(text, "utf8") !== bytes.length) {
      invalid();
    }
    const parsed = JSON.parse(text);
    if (!canonicalBytes(parsed).equals(bytes)) {
      invalid();
    }
    return parsed;
  } catch (error) {
    if (error instanceof CoordinationRelayError) {
      throw error;
    }
    invalid();
  }
}

function parseStableCanonical(value, maximum) {
  if (
    !Buffer.isBuffer(value) ||
    value.length === 0 ||
    value.length > maximum
  ) {
    invalid();
  }
  try {
    const bytes = Buffer.from(value);
    const text = bytes.toString("utf8");
    if (Buffer.byteLength(text, "utf8") !== bytes.length) {
      invalid();
    }
    const parsed = JSON.parse(text);
    if (!stableBytes(parsed).equals(bytes)) {
      invalid();
    }
    return parsed;
  } catch (error) {
    if (error instanceof CoordinationRelayError) {
      throw error;
    }
    invalid();
  }
}

function guarded(action) {
  try {
    return action();
  } catch (error) {
    if (error instanceof CoordinationRelayError) {
      throw error;
    }
    invalid();
  }
}

async function guardedAsync(action) {
  try {
    return await action();
  } catch (error) {
    if (error instanceof CoordinationRelayError) {
      throw error;
    }
    invalid();
  }
}

function validateStore(store) {
  if (!isPlainObject(store)) {
    invalid();
  }
  for (const method of STORE_METHODS) {
    let descriptor;
    try {
      descriptor = Object.getOwnPropertyDescriptor(
        store,
        method,
      );
    } catch {
      invalid();
    }
    if (
      descriptor === undefined ||
      !Object.hasOwn(descriptor, "value") ||
      typeof descriptor.value !== "function"
    ) {
      invalid();
    }
  }
  return store;
}

async function verifyInvitationProofs(enrollment) {
  for (const run of ["rehearsal", "stakeholder"]) {
    const invitation = enrollment.invitations[run];
    let recovered;
    try {
      recovered = await recoverMessageAddress({
        message: {
          raw: toHex(
            invitationProofPreimage({
              address: invitation.address,
              capabilityDigest:
                enrollment.capabilityDigest,
              releaseId: enrollment.releaseId,
              repositorySha:
                enrollment.repositorySha,
              role: enrollment.role,
              run,
              sessionId: enrollment.sessionId,
            }),
          ),
        },
        signature: invitation.signature,
      });
    } catch {
      invalid();
    }
    if (recovered.toLowerCase() !== invitation.address) {
      invalid();
    }
  }
}

function assertDistinctEnrollments(left, right) {
  const keyIds = [
    left.coordinationKey.keyId,
    left.preflightKey.keyId,
    right.coordinationKey.keyId,
    right.preflightKey.keyId,
  ];
  const publicKeys = [
    left.coordinationKey.publicKey,
    left.preflightKey.publicKey,
    right.coordinationKey.publicKey,
    right.preflightKey.publicKey,
  ];
  const addresses = [
    left.invitations.rehearsal.address,
    left.invitations.stakeholder.address,
    right.invitations.rehearsal.address,
    right.invitations.stakeholder.address,
  ];
  if (
    new Set(keyIds).size !== keyIds.length ||
    new Set(publicKeys).size !== publicKeys.length ||
    new Set(addresses).size !== addresses.length
  ) {
    invalid();
  }
}

function readEnvelope(value) {
  const data = readExactData(value, ENVELOPE_KEYS);
  const signature = readExactData(
    data.signature,
    ENVELOPE_SIGNATURE_KEYS,
  );
  if (
    !["operator", "payee", "payer"].includes(data.role) ||
    typeof data.kind !== "string" ||
    typeof signature.keyId !== "string" ||
    typeof signature.publicKey !== "string"
  ) {
    invalid();
  }
  return {
    artifactDigest: data.artifactDigest,
    event: value,
    keyId: signature.keyId,
    kind: data.kind,
    publicKey: signature.publicKey,
    releaseId: data.releaseId,
    repositorySha: data.repositorySha,
    role: data.role,
    sessionId: assertSessionId(data.sessionId),
    subjectRun: data.subjectRun,
  };
}

function assertReleaseView(value, sessionId, repositorySha) {
  const data = readExactData(value, RELEASE_VIEW_KEYS);
  if (data.releaseId === null) {
    invalid("COORDINATION_SESSION_NOT_FOUND");
  }
  if (
    !Array.isArray(data.events) ||
    data.paymentMoved !== false ||
    typeof data.releaseId !== "string" ||
    data.releaseId.length === 0 ||
    data.repositorySha !== repositorySha ||
    data.sessionId !== sessionId
  ) {
    invalid();
  }
  return {
    events: [...data.events],
    releaseId: data.releaseId,
  };
}

function assertArtifactEventScope(envelope, artifactType, facts) {
  const scoped = (value) => {
    if (
      value.role !== envelope.role ||
      value.repositorySha !== envelope.repositorySha ||
      value.paymentMoved !== false
    ) {
      invalid();
    }
  };
  if (artifactType === "token-commitment") {
    scoped(facts);
  } else if (artifactType === "preflight-plan") {
    if (
      facts.plan.repositorySha !== envelope.repositorySha ||
      facts.plan.paymentMoved !== false ||
      facts.operator.keyId !== envelope.keyId
    ) {
      invalid();
    }
  } else if (artifactType === "preflight-participant-report") {
    scoped(facts.participantReport.report);
  } else if (artifactType === "preflight-aggregate-report") {
    const report = facts.aggregateReport.report;
    if (
      report.repositorySha !== envelope.repositorySha ||
      report.paymentMoved !== false ||
      report.outcome !== "RENDEZVOUS_OK"
    ) {
      invalid();
    }
  } else if (artifactType === "identity-package") {
    const identity = facts.identity;
    if (
      identity.repositorySha !== envelope.repositorySha ||
      identity.paymentMoved !== false
    ) {
      invalid();
    }
  } else if (artifactType === "party-result-package") {
    scoped(facts.partyResult);
  } else if (
    artifactType === "recovery-command-manifest" ||
    artifactType === "failure-summary"
  ) {
    if (
      facts.releaseId !== envelope.releaseId ||
      facts.repositorySha !== envelope.repositorySha ||
      (envelope.kind !== "EXACT_RECOVERY_AUTHORIZATION" &&
        facts.role !== envelope.role) ||
      facts.sessionId !== envelope.sessionId ||
      facts.subjectRun !== envelope.subjectRun ||
      facts.paymentMoved !== false
    ) {
      invalid();
    }
  }
}

function createArtifactTransitionShapeValidator(
  input,
  allowContextualArtifacts,
) {
  return guarded(() => {
    const data = readExactData(
      input,
      DESCRIPTOR_VALIDATOR_KEYS,
    );
    const frozenRepositorySha = assertRepositorySha(
      data.frozenRepositorySha,
    );
    if (
      typeof data.readArtifact !== "function" ||
      typeof data.resolveOperatorPublicKey !== "function"
    ) {
      invalid();
    }
    const bindings = {
      rehearsal: null,
      stakeholder: null,
    };

    async function validate(unverifiedEvent) {
      return guardedAsync(async () => {
        const envelope = readEnvelope(unverifiedEvent);
        if (!DESCRIPTOR_EVENT_KINDS.has(envelope.kind)) {
          const artifactType = ARTIFACT_EVENT_TYPES[envelope.kind];
          if (artifactType === undefined) {
            if (envelope.artifactDigest !== null) invalid();
            return null;
          }
          if (!allowContextualArtifacts) invalid();
          if (
            envelope.kind === "TERMINAL_FAILURE" &&
            envelope.artifactDigest === null
          ) {
            return null;
          }
          if (envelope.artifactDigest === null) invalid();
          const digest = assertSha256(envelope.artifactDigest);
          let artifact;
          try {
            artifact = await validateRelayArtifactWithFacts({
              artifactType,
              bytes: await data.readArtifact(digest),
              expectedDigest: digest,
              secretCanaries: [],
            });
          } catch {
            invalid();
          }
          assertArtifactEventScope(envelope, artifactType, artifact.facts);
          return artifact;
        }
        if (envelope.artifactDigest === null) {
          invalid();
        }
        const run =
          envelope.kind ===
            "REHEARSAL_DESCRIPTOR_READY" ||
          (
            envelope.kind === "DESCRIPTOR_ACCEPTED" &&
            envelope.subjectRun === "rehearsal"
          )
            ? "rehearsal"
            : envelope.kind ===
                "STAKEHOLDER_DESCRIPTOR_READY" ||
                (
                  envelope.kind ===
                    "DESCRIPTOR_ACCEPTED" &&
                  envelope.subjectRun === "stakeholder"
                )
              ? "stakeholder"
              : invalid();
        const readyKind =
          run === "rehearsal"
            ? "REHEARSAL_DESCRIPTOR_READY"
            : "STAKEHOLDER_DESCRIPTOR_READY";
        if (
          (
            envelope.kind === readyKind &&
            (
              envelope.role !== "operator" ||
              envelope.subjectRun !== run
            )
          ) ||
          (
            envelope.kind === "DESCRIPTOR_ACCEPTED" &&
            (
              !["payee", "payer"].includes(
                envelope.role,
              ) ||
              envelope.subjectRun !== run
            )
          )
        ) {
          invalid();
        }
        const digest = assertSha256(
          envelope.artifactDigest,
        );
        let artifact;
        try {
          artifact = await validateRelayArtifactWithFacts({
            artifactType: "signed-descriptor",
            bytes: await data.readArtifact(digest),
            expectedDigest: digest,
            secretCanaries: [],
          });
        } catch {
          invalid();
        }
        const descriptorEnvelope = artifact.facts;
        const descriptorData = readExactData(
          descriptorEnvelope,
          ["descriptor", "operator"],
        );
        const operatorData = readExactData(
          descriptorData.operator,
          [
            "algorithm",
            "keyId",
            "publicKey",
            "signature",
          ],
        );
        let expectedPublicKey;
        try {
          expectedPublicKey =
            await data.resolveOperatorPublicKey(
              operatorData.keyId,
            );
          verifyDescriptorEnvelope(descriptorEnvelope, {
            repositoryPublicKey:
              expectedPublicKey,
          });
        } catch {
          invalid();
        }
        if (
          descriptorData.descriptor.paymentMoved !== false ||
          descriptorData.descriptor.repositorySha !==
            frozenRepositorySha ||
          envelope.repositorySha !== frozenRepositorySha
        ) {
          invalid();
        }
        const candidate = Object.freeze({
          digest,
          operatorKeyId: operatorData.keyId,
          protocolSessionId:
            descriptorData.descriptor.sessionId,
        });
        if (envelope.kind === readyKind) {
          const otherRun =
            run === "rehearsal"
              ? "stakeholder"
              : "rehearsal";
          if (
            bindings[run] !== null ||
            operatorData.keyId !== envelope.keyId ||
            bindings[otherRun]?.protocolSessionId ===
              candidate.protocolSessionId
          ) {
            invalid();
          }
          bindings[run] = candidate;
          return Object.freeze({ ...candidate, facts: descriptorEnvelope });
        }
        const ready = bindings[run];
        if (
          ready === null ||
          candidate.digest !== ready.digest ||
          candidate.operatorKeyId !==
            ready.operatorKeyId ||
          candidate.protocolSessionId !==
            ready.protocolSessionId
        ) {
          invalid();
        }
        return Object.freeze({ ...candidate, facts: descriptorEnvelope });
      });
    }

    return Object.freeze({ validate });
  });
}

export function createDescriptorArtifactTransitionValidator(input) {
  return createArtifactTransitionShapeValidator(input, false);
}

function ed25519PublicKey(raw) {
  if (
    typeof raw !== "string" ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
      raw,
    )
  ) {
    invalid();
  }
  const bytes = Buffer.from(raw, "base64");
  if (bytes.length !== 32 || bytes.toString("base64") !== raw) {
    invalid();
  }
  try {
    return createPublicKey({
      format: "der",
      key: Buffer.concat([ED25519_SPKI_PREFIX, bytes]),
      type: "spki",
    });
  } catch {
    invalid();
  }
}

function sameCanonical(left, right) {
  try {
    return stableBytes(left).equals(stableBytes(right));
  } catch {
    invalid();
  }
}

export function createRelayArtifactTransitionValidator(input) {
  return guarded(() => {
    const data = readExactData(input, ARTIFACT_TRANSITION_VALIDATOR_KEYS);
    if (typeof data.readEnrollment !== "function") invalid();
    const artifactShapeValidator =
      createArtifactTransitionShapeValidator(
        {
          frozenRepositorySha: data.frozenRepositorySha,
          readArtifact: data.readArtifact,
          resolveOperatorPublicKey:
            data.resolveOperatorPublicKey,
        },
        true,
      );
    const tokens = Object.create(null);
    const participants = Object.create(null);
    const identities = {
      rehearsal: Object.create(null),
      stakeholder: Object.create(null),
    };
    const descriptors = {
      rehearsal: null,
      stakeholder: null,
    };
    const descriptorAccepted = {
      rehearsal: Object.create(null),
      stakeholder: Object.create(null),
    };
    const outstandingRecovery = new Map();
    let plan = null;

    async function enrollment(envelope) {
      try {
        const stored = await data.readEnrollment({
          role: envelope.role,
          sessionId: envelope.sessionId,
        });
        const value = parseCoordinationEnrollment(stored.bytes);
        if (
          value.role !== envelope.role ||
          value.releaseId !== envelope.releaseId ||
          value.sessionId !== envelope.sessionId ||
          value.repositorySha !== data.frozenRepositorySha ||
          value.paymentMoved !== false
        ) {
          invalid();
        }
        return value;
      } catch {
        invalid();
      }
    }
    async function validate(event) {
      return guardedAsync(async () => {
      const envelope = readEnvelope(event);
      if (envelope.kind === "VERIFICATION_PASSED") invalid();
      const result = await artifactShapeValidator.validate(event);
      const type = DESCRIPTOR_EVENT_KINDS.has(envelope.kind)
        ? "signed-descriptor"
        : ARTIFACT_EVENT_TYPES[envelope.kind];
      if (type === undefined || envelope.artifactDigest === null) return result;
      const digest = assertSha256(envelope.artifactDigest);
      const facts = result?.facts;
      if (facts === undefined) invalid();
      if (envelope.kind === "TOKEN_READY") {
        const enrolled = await enrollment(envelope);
        if (facts.coordinationPublicKey !== enrolled.coordinationKey.publicKey) invalid();
        if (tokens[envelope.role] !== undefined) invalid();
        tokens[envelope.role] = Object.freeze({ digest, facts });
      } else if (envelope.kind === "PREFLIGHT_PLAN_READY") {
        if (envelope.role !== "operator" || plan !== null || tokens.payer === undefined || tokens.payee === undefined) invalid();
        const pinned = await data.resolveOperatorPublicKey(facts.operator.keyId);
        if (facts.operator.publicKey !== pinned || facts.operator.keyId !== envelope.keyId) invalid();
        for (const role of ["payer", "payee"]) {
          const enrolled = await enrollment({ ...envelope, role });
          const participant = facts.plan.participants[role];
          if (participant.coordinationPublicKey !== enrolled.coordinationKey.publicKey || participant.publicKey !== enrolled.preflightKey.publicKey || !sameCanonical(participant.tokenCommitment, tokens[role].facts)) invalid();
        }
        plan = Object.freeze({ digest, planDigest: sha256(canonicalBytes(facts.plan)), facts });
      } else if (envelope.kind === "PREFLIGHT_PARTICIPANT_READY") {
        if (plan === null || participants[envelope.role] !== undefined) invalid();
        const report = facts.participantReport.report;
        const signature = facts.participantReport.signature;
        const enrolled = await enrollment(envelope);
        const planned = plan.facts.plan;
        if (report.planDigest !== plan.planDigest || !sameCanonical(report.tokenCommitment, tokens[envelope.role]?.facts) || report.write.digest !== planned.digests[envelope.role] || report.write.key !== planned.keys[envelope.role] || signature.role !== envelope.role || !verify(null, canonicalBytes(report), ed25519PublicKey(enrolled.preflightKey.publicKey), Buffer.from(signature.value, "base64"))) invalid();
        participants[envelope.role] = Object.freeze({ digest, report });
      } else if (envelope.kind === "REGISTER_REHEARSAL") {
        if (plan === null || participants.payer === undefined || participants.payee === undefined) invalid();
        const report = facts.aggregateReport.report;
        const signature = facts.aggregateReport.signature;
        const pinned = await data.resolveOperatorPublicKey(signature.keyId);
        if (signature.keyId !== envelope.keyId || report.planDigest !== plan.planDigest || !verify(null, canonicalBytes(report), ed25519PublicKey(pinned), Buffer.from(signature.value, "base64"))) invalid();
        for (const role of ["payer", "payee"]) {
          const index = role === "payer" ? 0 : 1;
          const write = report.writes[index];
          const direction = report.directions[index];
          const { observer, ...observation } = direction;
          if (!sameCanonical(write, participants[role].report.write) || observer !== role || direction.peer !== (role === "payer" ? "payee" : "payer") || !sameCanonical(observation, participants[role].report.peerObservation)) invalid();
        }
      } else if (envelope.kind === "IDENTITY_PACKAGE_READY") {
        if (!Object.hasOwn(identities, envelope.subjectRun)) invalid();
        const enrolled = await enrollment(envelope);
        const identity = facts.identity;
        if (identities[envelope.subjectRun][envelope.role] !== undefined || identity.address.toLowerCase() !== enrolled.invitations[envelope.subjectRun].address.toLowerCase()) invalid();
        identities[envelope.subjectRun][envelope.role] = identity;
      } else if (DESCRIPTOR_EVENT_KINDS.has(envelope.kind)) {
        const descriptor = facts.descriptor;
        const run = envelope.subjectRun;
        if (descriptor.payee.address.toLowerCase() !== identities[run].payee?.address.toLowerCase() || descriptor.payee.agentId !== identities[run].payee?.agentId || descriptor.payee.displayName !== identities[run].payee?.displayName || descriptor.payer.address.toLowerCase() !== identities[run].payer?.address.toLowerCase() || descriptor.payer.agentId !== identities[run].payer?.agentId || descriptor.payer.displayName !== identities[run].payer?.displayName) invalid();
        if (envelope.kind === "DESCRIPTOR_ACCEPTED") {
          if (
            descriptors[run] === null ||
            descriptors[run].digest !== digest ||
            descriptors[run].sessionDigest !== dSession(descriptor) ||
            descriptorAccepted[run][envelope.role] !== undefined
          ) invalid();
          descriptorAccepted[run][envelope.role] = true;
        } else {
          if (descriptors[run] !== null) invalid();
          descriptors[run] = Object.freeze({
            descriptor,
            digest,
            sessionDigest: dSession(descriptor),
          });
        }
      } else if (envelope.kind === "ROLE_PACKAGE_READY") {
        if (!Object.hasOwn(descriptors, envelope.subjectRun)) invalid();
        const descriptorContext = descriptors[envelope.subjectRun];
        const party = facts.partyResult;
        if (descriptorContext === null || descriptorAccepted[envelope.subjectRun][envelope.role] !== true) invalid();
        const descriptorParty = descriptorContext.descriptor[envelope.role];
        const transitionParty = party.transitions[0]?.message?.[envelope.role];
        if (
          party.role !== envelope.role ||
          party.repositorySha !== envelope.repositorySha ||
          party.localVerdict !== "LOCAL_OK" ||
          party.sessionDigest !== descriptorContext.sessionDigest ||
          party.promptSha256 !== descriptorContext.descriptor.promptSha256 ||
          party.signature.address.toLowerCase() !== descriptorParty.address.toLowerCase() ||
          transitionParty?.address?.toLowerCase() !== descriptorParty.address.toLowerCase() ||
          transitionParty?.agentId !== descriptorParty.agentId
        ) invalid();
      } else if (envelope.kind === "RECOVERY_REQUIRED") {
        const key = `${envelope.subjectRun}:${envelope.role}`;
        if (outstandingRecovery.has(key) || [...outstandingRecovery.values()].includes(digest)) invalid();
        outstandingRecovery.set(key, digest);
      } else if (envelope.kind === "EXACT_RECOVERY_AUTHORIZATION") {
        const key = `${envelope.subjectRun}:${facts.role}`;
        if (outstandingRecovery.get(key) !== digest) invalid();
        outstandingRecovery.delete(key);
      }
      return result;
      });
    }
    function readIdentityContext(value) {
      const data = readExactData(value, ["subjectRun"]);
      if (!Object.hasOwn(identities, data.subjectRun)) invalid();
      const context = identities[data.subjectRun];
      if (context.payer === undefined || context.payee === undefined) {
        invalid();
      }
      // Return a new deeply immutable snapshot; this is intentionally only a
      // validator capability, never a service or HTTP authority surface.
      return Object.freeze({
        payer: Object.freeze({ ...context.payer }),
        payee: Object.freeze({ ...context.payee }),
        subjectRun: data.subjectRun,
      });
    }
    return Object.freeze({ readIdentityContext, validate });
  });
}

export function createRelayService(input) {
  return guarded(() => {
    if (!isPlainObject(input)) {
      invalid();
    }
    const keys = Reflect.ownKeys(input);
    const expectedKeys = keys.includes("now")
      ? DEPENDENCY_KEYS
      : DEPENDENCY_KEYS_WITHOUT_NOW;
    const data = readExactData(input, expectedKeys);
    const frozenRepositorySha = assertRepositorySha(
      data.frozenRepositorySha,
    );
    const now = data.now ?? Date.now;
    if (
      typeof now !== "function" ||
      typeof data.repositoryPublicKeyResolver !==
        "function"
    ) {
      invalid();
    }
    const receiptSigner = validateReceiptSigner(
      data.receiptSigner,
    );
    const repositoryPublicKeyResolver =
      data.repositoryPublicKeyResolver;
    const store = validateStore(data.store);
    let mutationQueue = Promise.resolve();
    const sessionWaiters = new Map();
    const enrollmentWaiters = new Map();

    function serializeMutation(action) {
      const execute = () => guardedAsync(action);
      const result = mutationQueue.then(execute, execute);
      mutationQueue = result.catch(() => {});
      return result;
    }

    function notifySession(sessionId) {
      const waiters = sessionWaiters.get(sessionId);
      if (waiters === undefined) {
        return;
      }
      sessionWaiters.delete(sessionId);
      for (const resolve of waiters) {
        resolve();
      }
    }

    function waitForSession(
      sessionId,
      waitMs,
      signal,
    ) {
      let cancel;
      const promise = new Promise((resolve) => {
        const waiters =
          sessionWaiters.get(sessionId) ?? new Set();
        let timer;
        const complete = (error) => {
          clearTimeout(timer);
          signal?.removeEventListener(
            "abort",
            aborted,
          );
          waiters.delete(notified);
          if (waiters.size === 0) {
            sessionWaiters.delete(sessionId);
          }
          resolve(error !== undefined);
        };
        const aborted = () => {
          complete(new Error());
        };
        const notified = () => {
          complete();
        };
        cancel = notified;
        waiters.add(notified);
        sessionWaiters.set(sessionId, waiters);
        signal?.addEventListener(
          "abort",
          aborted,
          { once: true },
        );
        timer = setTimeout(notified, waitMs);
      });
      return Object.freeze({
        cancel,
        promise,
      });
    }

    function notifyEnrollmentReadiness(sessionId) {
      const waiters = enrollmentWaiters.get(sessionId);
      if (waiters === undefined) {
        return;
      }
      enrollmentWaiters.delete(sessionId);
      for (const resolve of waiters) {
        resolve("notified");
      }
    }

    function waitForEnrollmentReadiness(
      sessionId,
      waitMs,
      signal,
    ) {
      let cancel;
      const promise = new Promise((resolve) => {
        const waiters =
          enrollmentWaiters.get(sessionId) ?? new Set();
        let timer;
        const complete = (result) => {
          clearTimeout(timer);
          signal?.removeEventListener(
            "abort",
            aborted,
          );
          waiters.delete(notified);
          if (waiters.size === 0) {
            enrollmentWaiters.delete(sessionId);
          }
          resolve(result);
        };
        const aborted = () => {
          complete("aborted");
        };
        const notified = (result = "notified") => {
          complete(result);
        };
        cancel = () => complete("cancelled");
        waiters.add(notified);
        enrollmentWaiters.set(sessionId, waiters);
        signal?.addEventListener(
          "abort",
          aborted,
          { once: true },
        );
        timer = setTimeout(
          () => notified("timeout"),
          waitMs,
        );
      });
      return Object.freeze({
        cancel,
        promise,
      });
    }

    function enrollmentReadinessResult(sessionId, ready) {
      return Object.freeze({
        paymentMoved: false,
        ready,
        repositorySha: frozenRepositorySha,
        schema: ENROLLMENT_READINESS_SCHEMA,
        sessionId,
      });
    }

    async function enrollmentRoleExists(sessionId, role) {
      try {
        await store.readEnrollment({ role, sessionId });
        return true;
      } catch (error) {
        if (
          error?.code ===
          "COORDINATION_ENROLLMENT_NOT_FOUND"
        ) {
          return false;
        }
        invalid();
      }
    }

    async function enrollmentsReady(sessionId) {
      const payerReady = await enrollmentRoleExists(
        sessionId,
        "payer",
      );
      const payeeReady = await enrollmentRoleExists(
        sessionId,
        "payee",
      );
      return payerReady && payeeReady;
    }

    async function resolvedOperatorPublicKey(keyId) {
      let repositoryPath;
      let repositoryValue;
      try {
        repositoryPath = operatorPublicKeyPath(keyId);
        repositoryValue =
          await repositoryPublicKeyResolver(
            Object.freeze({
              keyId,
              repositoryPath,
              repositorySha: frozenRepositorySha,
            }),
          );
        if (
          typeof repositoryValue !== "string" ||
          repositoryValue.length === 0 ||
          repositoryValue.includes("\r")
        ) {
          invalid();
        }
        const rawPublicKey = repositoryValue.endsWith("\n")
          ? repositoryValue.slice(0, -1)
          : repositoryValue;
        if (
          rawPublicKey.length === 0 ||
          rawPublicKey.includes("\n")
        ) {
          invalid();
        }
        publicKeyPemFromRawBase64(rawPublicKey);
        return rawPublicKey;
      } catch {
        invalid();
      }
    }

    async function eventAuthority(event) {
      const envelope = readEnvelope(event);
      if (envelope.role === "operator") {
        return resolvedOperatorPublicKey(
          envelope.keyId,
        );
      }
      let stored;
      try {
        stored = await store.readEnrollment({
          role: envelope.role,
          sessionId: envelope.sessionId,
        });
      } catch {
        invalid();
      }
      let enrollment;
      try {
        enrollment = parseCoordinationEnrollment(
          stored.bytes,
        );
      } catch {
        invalid();
      }
      if (
        enrollment.paymentMoved !== false ||
        enrollment.releaseId !== envelope.releaseId ||
        enrollment.repositorySha !==
          envelope.repositorySha ||
        enrollment.repositorySha !==
          frozenRepositorySha ||
        enrollment.role !== envelope.role ||
        enrollment.sessionId !== envelope.sessionId ||
        envelope.keyId !==
          enrollment.coordinationKey.keyId ||
        envelope.publicKey !==
          enrollment.coordinationKey.publicKey
      ) {
        invalid();
      }
      return enrollment.coordinationKey.publicKey;
    }

    async function replaySession(sessionId) {
      let storedView;
      try {
        storedView = await store.readReleaseView({
          sessionId,
        });
      } catch {
        invalid();
      }
      const stored = assertReleaseView(
        storedView,
        sessionId,
        frozenRepositorySha,
      );
      let view = initialReleaseView({
        releaseId: stored.releaseId,
        repositorySha: frozenRepositorySha,
        sessionId,
      });
      const descriptorArtifacts =
        createRelayArtifactTransitionValidator({
          frozenRepositorySha,
          readArtifact: store.getArtifact,
          readEnrollment: store.readEnrollment,
          resolveOperatorPublicKey:
            resolvedOperatorPublicKey,
        });
      for (const event of stored.events) {
        const envelope = readEnvelope(event);
        const expectedPublicKey =
          await eventAuthority(event);
        if (envelope.kind !== "VERIFICATION_PASSED") await descriptorArtifacts.validate(event);
        if (
          envelope.kind === "PAYER_MANDATE_READY" ||
          envelope.kind === "PAYMENT_REQUEST_READY"
        ) {
          await validateIntentReadyEvent(event, {
            descriptorArtifacts,
            events: stored.events,
            view,
          });
        }
        try {
          const options = { expectedPublicKey };
          if (envelope.kind === "VERIFICATION_PASSED") {
            const claim = await store.readVerifierPublication({ sessionId: envelope.sessionId, subjectRun: envelope.subjectRun });
            if (claim === null || !verifierPublicationMatchesEvent(claim, event)) invalid();
            options.verifierPublicationVerified = true;
          }
          view = reduceReleaseEvent(
            view,
            event,
            options,
          );
        } catch {
          invalid();
        }
      }
      return {
        descriptorArtifacts,
        events: stored.events,
        view,
      };
    }

    async function verifiedMandate({
      bytes,
      identityContext,
      releaseId,
      sessionId,
      subjectRun,
    }) {
      const metadata = await validateRelayArtifactWithFacts({
        artifactType: "payer-mandate",
        bytes,
        expectedDigest: sha256(bytes),
        secretCanaries: [],
      });
      const mandate = metadata.facts.mandate;
      await verifyPayerMandate({
        envelope: metadata.facts,
        expected: {
          amount: mandate.amount,
          invoiceReferencePrefix: mandate.invoiceReferencePrefix,
          payer: { address: identityContext.payer.address.toLowerCase(), agentId: identityContext.payer.agentId },
          payee: { address: identityContext.payee.address.toLowerCase(), agentId: identityContext.payee.agentId },
          purpose: mandate.purpose,
          releaseId,
          repositorySha: frozenRepositorySha,
          sessionId,
          subjectRun,
          requestEndpoint: `/v1/sessions/${sessionId}/payment-requests`,
        },
        nowMs: now(),
      });
      return Object.freeze({
        envelope: metadata.facts,
        rawEnvelopeDigest: metadata.digest,
        semanticDigest: payerMandateDigest(metadata.facts),
      });
    }

    async function mandateForRun(replayed, sessionId, subjectRun, requireReadyEvent) {
      const binding = await store.readPayerMandate({ sessionId, subjectRun });
      if (binding === null) invalid();
      const identityContext = replayed.descriptorArtifacts.readIdentityContext({ subjectRun });
      const mandate = await verifiedMandate({
        bytes: binding.bytes,
        identityContext,
        releaseId: replayed.view.releaseId,
        sessionId,
        subjectRun,
      });
      if (binding.digest !== mandate.rawEnvelopeDigest) invalid();
      if (requireReadyEvent && !replayed.events.some((event) => {
        const envelope = readEnvelope(event);
        return envelope.kind === "PAYER_MANDATE_READY" && envelope.subjectRun === subjectRun && envelope.artifactDigest === binding.digest;
      })) invalid();
      return Object.freeze({ binding, identityContext, mandate });
    }

    async function validateIntentReadyEvent(event, replayed) {
      const envelope = readEnvelope(event);
      if (![
        "PAYER_MANDATE_READY",
        "PAYMENT_REQUEST_READY",
      ].includes(envelope.kind)) return null;
      if (!["rehearsal", "stakeholder"].includes(envelope.subjectRun) || envelope.artifactDigest === null) invalid();
      if (envelope.kind === "PAYER_MANDATE_READY") {
        const bytes = await store.getArtifact(envelope.artifactDigest);
        const identityContext = replayed.descriptorArtifacts.readIdentityContext({ subjectRun: envelope.subjectRun });
        const mandate = await verifiedMandate({ bytes, identityContext, releaseId: replayed.view.releaseId, sessionId: envelope.sessionId, subjectRun: envelope.subjectRun });
        if (mandate.rawEnvelopeDigest !== envelope.artifactDigest) invalid();
        return Object.freeze({ bytes, mandate, type: "mandate" });
      }
      const bytes = await store.getArtifact(envelope.artifactDigest);
      const parsed = parseCanonicalBody(bytes, MAX_RELAY_REQUEST_BYTES);
      const requestId = parsed?.request?.requestId;
      const matching = await store.readPaymentRequest({ requestId, sessionId: envelope.sessionId });
      if (matching === null || matching.digest !== envelope.artifactDigest || !matching.bytes.equals(bytes) || matching.subjectRun !== envelope.subjectRun) invalid();
      const context = await mandateForRun(replayed, envelope.sessionId, envelope.subjectRun, true);
      const verified = await verifyPaymentRequest({
        envelope: parsed,
        mandateEnvelope: context.mandate.envelope,
        expected: {
          amount: context.mandate.envelope.mandate.amount,
          invoiceReferencePrefix: context.mandate.envelope.mandate.invoiceReferencePrefix,
          payer: { address: context.identityContext.payer.address.toLowerCase(), agentId: context.identityContext.payer.agentId },
          payee: { address: context.identityContext.payee.address.toLowerCase(), agentId: context.identityContext.payee.agentId },
          purpose: context.mandate.envelope.mandate.purpose,
          releaseId: replayed.view.releaseId,
          repositorySha: frozenRepositorySha,
          sessionId: envelope.sessionId,
          subjectRun: envelope.subjectRun,
        }, nowMs: now(),
      });
      if (paymentRequestDigest(parsed) === null || verified.request.requestId !== requestId) invalid();
      return Object.freeze({ type: "request" });
    }

    async function registerCapabilities(value) {
      return serializeMutation(async () => {
        const inputData = readExactData(value, APPEND_INPUT_KEYS);
        const request = parseCanonicalBody(
          inputData.body,
          MAX_RELAY_REQUEST_BYTES,
        );
        if (
          !isPlainObject(request) ||
          request.schema !== CAPABILITY_REGISTRATION_SCHEMA ||
          typeof request.operatorKeyId !== "string"
        ) {
          invalid();
        }
        const operatorPublicKey = await resolvedOperatorPublicKey(
          request.operatorKeyId,
        );
        const registration = verifyCapabilityRegistration(request, {
          expectedOperatorKeyId: request.operatorKeyId,
          expectedOperatorPublicKey: operatorPublicKey,
          expectedRepositorySha: frozenRepositorySha,
        });
        const registrations = {
            payee: {
              ...registration.capabilities.payee,
              releaseId: registration.releaseId,
              role: "payee",
              sessionId: registration.sessionId,
            },
            payer: {
              ...registration.capabilities.payer,
              releaseId: registration.releaseId,
              role: "payer",
              sessionId: registration.sessionId,
            },
          };
        const registrationDigest = sha256(
          canonicalBytes(registrations),
        );
        const requestDigest = sha256(canonicalBytes(request));
        const existing = await store.readCapabilitySet({
          releaseId: registration.releaseId,
          sessionId: registration.sessionId,
        });
        if (existing === null) {
          verifyCapabilityRegistration(request, {
            expectedOperatorKeyId: request.operatorKeyId,
            expectedOperatorPublicKey: operatorPublicKey,
            expectedRepositorySha: frozenRepositorySha,
            nowMs: now(),
          });
        }
        const accepted = await store.registerCapabilitySet({
          registrationDigest,
          registrations,
          requestDigest,
        });
        const set = readExactData(accepted, [
          "registrationDigest",
          "registrations",
          "requestDigest",
        ]);
        if (
          set.registrationDigest !== registrationDigest ||
          set.requestDigest !== requestDigest ||
          !canonicalBytes(set.registrations).equals(
            canonicalBytes(registrations),
          )
        ) {
          invalid();
        }
        return Object.freeze({
          capabilities: registration.capabilities,
          paymentMoved: false,
          registrationDigest: set.registrationDigest,
          releaseId: registration.releaseId,
          repositorySha: frozenRepositorySha,
          schema: CAPABILITY_REGISTRATION_RECEIPT_SCHEMA,
          sessionId: registration.sessionId,
          requestDigest: set.requestDigest,
        });
      });
    }

    async function bootstrap(value) {
      return serializeMutation(async () => {
        const inputData = readExactData(
          value,
          BOOTSTRAP_INPUT_KEYS,
        );
        const wrapper = parseCanonicalBody(
          inputData.body,
          MAX_RELAY_REQUEST_BYTES,
        );
        const wrapperData = readExactData(
          wrapper,
          BOOTSTRAP_KEYS,
        );
        if (
          typeof wrapperData.capability !== "string" ||
          !CAPABILITY_PATTERN.test(
            wrapperData.capability,
          )
        ) {
          invalid();
        }
        const capability = Buffer.from(
          wrapperData.capability,
          "hex",
        );
        const enrollmentBytes = canonicalBytes(
          wrapperData.enrollment,
        );
        let enrollment;
        try {
          enrollment = parseCoordinationEnrollment(
            enrollmentBytes,
          );
        } catch {
          invalid();
        }
        if (
          enrollmentContainsCapability(
            enrollmentBytes,
            enrollment,
            capability,
          )
        ) {
          invalid();
        }
        if (
          enrollment.repositorySha !==
            frozenRepositorySha ||
          enrollment.paymentMoved !== false ||
          enrollment.capabilityDigest !==
            sha256(capability)
        ) {
          invalid();
        }
        await verifyInvitationProofs(enrollment);
        const otherRole =
          enrollment.role === "payer"
            ? "payee"
            : "payer";
        try {
          const otherStored =
            await store.readEnrollment({
              role: otherRole,
              sessionId: enrollment.sessionId,
            });
          const other = parseCoordinationEnrollment(
            otherStored.bytes,
          );
          assertDistinctEnrollments(enrollment, other);
        } catch (error) {
          if (
            error?.code !==
            "COORDINATION_ENROLLMENT_NOT_FOUND"
          ) {
            invalid();
          }
        }
        const enrollmentDigest = sha256(
          enrollmentBytes,
        );
        let consumed;
        try {
          consumed = await store.consumeCapability({
            capability,
            enrollmentBytes,
            enrollmentDigest,
            receiptFactory: async (context) =>
              createCoordinationReceipt({
                context,
                signer: receiptSigner,
              }),
          });
        } catch {
          invalid();
        }
        const consumption = readExactData(
          consumed,
          CONSUMPTION_KEYS,
        );
        if (
          consumption.capabilityDigest !==
            enrollment.capabilityDigest ||
          consumption.enrollmentDigest !==
            enrollmentDigest ||
          !Buffer.isBuffer(
            consumption.enrollmentBytes,
          ) ||
          !consumption.enrollmentBytes.equals(
            enrollmentBytes,
          )
        ) {
          invalid();
        }
        const receipt = await verifyCoordinationReceipt({
          bytes: consumption.receiptBytes,
          expected: {
            capabilityDigest:
              enrollment.capabilityDigest,
            enrollmentDigest,
            releaseId: enrollment.releaseId,
            repositorySha: enrollment.repositorySha,
            role: enrollment.role,
            sessionId: enrollment.sessionId,
          },
          verifier: receiptSigner,
        });
        notifyEnrollmentReadiness(enrollment.sessionId);
        return receipt;
      });
    }

    async function appendEvent(value) {
      return serializeMutation(async () => {
        const inputData = readExactData(
          value,
          APPEND_INPUT_KEYS,
        );
        const event = parseCanonicalBody(
          inputData.body,
          MAX_RELAY_REQUEST_BYTES,
        );
        const envelope = readEnvelope(event);
        if (
          event.repositorySha !== frozenRepositorySha ||
          event.paymentMoved !== false ||
          envelope.kind === "VERIFICATION_PASSED"
        ) {
          invalid();
        }
        const replayed = await replaySession(
          envelope.sessionId,
        );
        const known = replayed.events.find(
          (candidate) =>
            candidate.eventDigest ===
            event.eventDigest,
        );
        if (known !== undefined) {
          if (
            !canonicalBytes(known).equals(
              canonicalBytes(event),
            )
          ) {
            invalid();
          }
          return known;
        }
        const expectedPublicKey =
          await eventAuthority(event);
        await replayed.descriptorArtifacts.validate(
          event,
        );
        let mandateToPersist = null;
        if (envelope.kind === "PAYER_MANDATE_READY") {
          const bytes = await store.getArtifact(envelope.artifactDigest);
          const identityContext = replayed.descriptorArtifacts.readIdentityContext({ subjectRun: envelope.subjectRun });
          const mandate = await verifiedMandate({ bytes, identityContext, releaseId: replayed.view.releaseId, sessionId: envelope.sessionId, subjectRun: envelope.subjectRun });
          if (mandate.rawEnvelopeDigest !== envelope.artifactDigest) invalid();
          mandateToPersist = Object.freeze({ bytes, digest: mandate.rawEnvelopeDigest });
        } else if (envelope.kind === "PAYMENT_REQUEST_READY") {
          await validateIntentReadyEvent(event, replayed);
        }
        try {
          reduceReleaseEvent(
            replayed.view,
            event,
            { expectedPublicKey },
          );
        } catch {
          invalid();
        }
        if (mandateToPersist !== null) {
          await store.putPayerMandate({
            bytes: mandateToPersist.bytes,
            digest: mandateToPersist.digest,
            sessionId: envelope.sessionId,
            subjectRun: envelope.subjectRun,
          });
        }
        let accepted;
        try {
          accepted = await store.appendEvent(event);
        } catch {
          invalid();
        }
        notifySession(envelope.sessionId);
        return accepted;
      });
    }

    async function appendVerifiedEvent(value) {
      return serializeMutation(async () => {
        const input = readExactData(value, APPEND_INPUT_KEYS);
        const wrapper = readExactData(parseCanonicalBody(input.body, MAX_RELAY_REQUEST_BYTES), VERIFIED_WRAPPER_KEYS);
        if (wrapper.schema !== VERIFIED_EVENT_SCHEMA || wrapper.paymentMoved !== false) invalid();
        const event = wrapper.event;
        const envelope = readEnvelope(event);
        const claim = readExactData(wrapper.publication, PUBLICATION_KEYS);
        if (envelope.kind !== "VERIFICATION_PASSED" || envelope.role !== "operator" || event.paymentMoved !== false || envelope.artifactDigest === null || claim.repositorySha !== frozenRepositorySha || !verifierPublicationMatchesEvent(claim, event)) invalid();
        const replayed = await replaySession(envelope.sessionId);
        const existing = replayed.events.find((candidate) => candidate.eventDigest === event.eventDigest);
        if (existing !== undefined) {
          if (!canonicalBytes(existing).equals(canonicalBytes(event))) invalid();
          const durable = await store.readVerifierPublication({ sessionId: envelope.sessionId, subjectRun: envelope.subjectRun });
          if (durable === null || !canonicalBytes(durable).equals(canonicalBytes(claim))) invalid();
          return existing;
        }
        const expectedPublicKey = await eventAuthority(event);
        try { reduceReleaseEvent(replayed.view, event, { expectedPublicKey, verifierPublicationVerified: true }); } catch { invalid(); }
        let accepted;
        try { accepted = await store.appendVerifiedEvent({ event, publication: claim }); } catch { invalid(); }
        notifySession(envelope.sessionId);
        return accepted;
      });
    }

    async function putArtifact(value) {
      return guardedAsync(async () => {
        const data = readExactData(
          value,
          PUT_ARTIFACT_KEYS,
        );
        if (!Buffer.isBuffer(data.body)) {
          invalid();
        }
        return store.putArtifact({
          artifactType: data.artifactType,
          bytes: Buffer.from(data.body),
          expectedDigest: data.expectedDigest,
          secretCanaries: [],
        });
      });
    }

    async function getArtifact(value) {
      return guardedAsync(async () => {
        const data = readExactData(
          value,
          GET_ARTIFACT_KEYS,
        );
        return store.getArtifact(
          assertSha256(data.digest),
        );
      });
    }

    async function readPayerMandate(value) {
      return guardedAsync(async () => {
        const data = readExactData(value, READ_PAYER_MANDATE_KEYS);
        const sessionId = assertSessionId(data.sessionId);
        if (!["rehearsal", "stakeholder"].includes(data.subjectRun)) invalid();
        const replayed = await replaySession(sessionId);
        const context = await mandateForRun(replayed, sessionId, data.subjectRun, true);
        return Buffer.from(context.binding.bytes);
      });
    }

    async function submitPaymentRequest(value) {
      return serializeMutation(async () => {
        const data = readExactData(value, SUBMIT_PAYMENT_REQUEST_KEYS);
        const sessionId = assertSessionId(data.sessionId);
        const parsed = parseCanonicalBody(data.body, MAX_RELAY_REQUEST_BYTES);
        const replayed = await replaySession(sessionId);
        const subjectRun = parsed?.request?.subjectRun;
        if (!["rehearsal", "stakeholder"].includes(subjectRun)) invalid();
        const context = await mandateForRun(replayed, sessionId, subjectRun, true);
        const verified = await verifyPaymentRequest({
          envelope: parsed,
          mandateEnvelope: context.mandate.envelope,
          expected: {
            amount: context.mandate.envelope.mandate.amount,
            invoiceReferencePrefix: context.mandate.envelope.mandate.invoiceReferencePrefix,
            payer: { address: context.identityContext.payer.address.toLowerCase(), agentId: context.identityContext.payer.agentId },
            payee: { address: context.identityContext.payee.address.toLowerCase(), agentId: context.identityContext.payee.agentId },
            purpose: context.mandate.envelope.mandate.purpose,
            releaseId: replayed.view.releaseId,
            repositorySha: frozenRepositorySha,
            sessionId,
            subjectRun,
          }, nowMs: now(),
        });
        const bytes = Buffer.from(data.body);
        const rawEnvelopeDigest = sha256(bytes);
        await store.putPaymentRequest({
          bytes,
          digest: rawEnvelopeDigest,
          requestId: verified.request.requestId,
          sessionId,
          subjectRun,
        });
        return Object.freeze({
          paymentMoved: false,
          paymentRequestDigest: paymentRequestDigest(parsed),
          rawEnvelopeDigest,
          requestId: verified.request.requestId,
          sessionId,
          subjectRun,
        });
      });
    }

    async function readPaymentRequest(value) {
      return guardedAsync(async () => {
        const data = readExactData(value, READ_PAYMENT_REQUEST_KEYS);
        const sessionId = assertSessionId(data.sessionId);
        const requestId = assertSessionId(data.requestId);
        const replayed = await replaySession(sessionId);
        const stored = await store.readPaymentRequest({ requestId, sessionId });
        if (stored === null) invalid("COORDINATION_SESSION_NOT_FOUND");
        await mandateForRun(replayed, sessionId, stored.subjectRun, true);
        return Buffer.from(stored.bytes);
      });
    }

    async function readEvents(value) {
      return guardedAsync(async () => {
        let inputKeys;
        try {
          inputKeys = Reflect.ownKeys(value);
        } catch {
          invalid();
        }
        const data = readExactData(
          value,
          inputKeys.includes("signal")
            ? READ_EVENTS_KEYS_WITH_SIGNAL
            : READ_EVENTS_KEYS,
        );
        const sessionId = assertSessionId(
          data.sessionId,
        );
        const signal = data.signal ?? null;
        if (
          signal !== null &&
          (
            !(signal instanceof AbortSignal) ||
            Object.getPrototypeOf(signal) !==
              AbortSignal.prototype
          )
        ) {
          invalid();
        }
        const after =
          data.after === null
            ? null
            : assertSha256(data.after);
        if (
          !Number.isInteger(data.waitMs) ||
          data.waitMs < 0 ||
          data.waitMs > MAX_RELAY_WAIT_MS
        ) {
          invalid();
        }
        if (signal?.aborted === true) {
          invalid();
        }
        if (data.waitMs === 0) {
          const events = await store.readEvents({
            after,
            sessionId,
          });
          if (signal?.aborted === true) {
            invalid();
          }
          return events;
        }
        const waiter = waitForSession(
          sessionId,
          data.waitMs,
          signal,
        );
        try {
          let events = await store.readEvents({
            after,
            sessionId,
          });
          if (signal?.aborted === true) {
            invalid();
          }
          if (events.length > 0) {
            return events;
          }
          const aborted = await waiter.promise;
          if (
            aborted ||
            signal?.aborted === true
          ) {
            invalid();
          }
          events = await store.readEvents({
            after,
            sessionId,
          });
          if (signal?.aborted === true) {
            invalid();
          }
          return events;
        } finally {
          waiter.cancel();
        }
      });
    }

    async function readEnrollmentReadiness(value) {
      return guardedAsync(async () => {
        let inputKeys;
        try {
          inputKeys = Reflect.ownKeys(value);
        } catch {
          invalid();
        }
        const data = readExactData(
          value,
          inputKeys.includes("signal")
            ? READ_ENROLLMENT_READINESS_KEYS_WITH_SIGNAL
            : READ_ENROLLMENT_READINESS_KEYS,
        );
        const sessionId = assertSessionId(data.sessionId);
        const signal = data.signal ?? null;
        if (
          signal !== null &&
          (
            !(signal instanceof AbortSignal) ||
            Object.getPrototypeOf(signal) !==
              AbortSignal.prototype
          )
        ) {
          invalid();
        }
        if (
          !Number.isInteger(data.waitMs) ||
          data.waitMs < 0 ||
          data.waitMs > MAX_RELAY_WAIT_MS
        ) {
          invalid();
        }
        if (signal?.aborted === true) {
          invalid();
        }
        if (data.waitMs === 0) {
          const ready = await enrollmentsReady(sessionId);
          if (signal?.aborted === true) {
            invalid();
          }
          return enrollmentReadinessResult(
            sessionId,
            ready,
          );
        }
        const waiter = waitForEnrollmentReadiness(
          sessionId,
          data.waitMs,
          signal,
        );
        try {
          let ready = await enrollmentsReady(sessionId);
          if (signal?.aborted === true) {
            invalid();
          }
          if (ready) {
            return enrollmentReadinessResult(
              sessionId,
              true,
            );
          }
          const result = await waiter.promise;
          if (
            result === "aborted" ||
            signal?.aborted === true
          ) {
            invalid();
          }
          if (result === "timeout") {
            return enrollmentReadinessResult(
              sessionId,
              false,
            );
          }
          ready = await enrollmentsReady(sessionId);
          if (signal?.aborted === true) {
            invalid();
          }
          return enrollmentReadinessResult(
            sessionId,
            ready,
          );
        } finally {
          waiter.cancel();
        }
      });
    }

    async function readEnrollmentSet(value) {
      return guardedAsync(async () => {
        const data = readExactData(
          value,
          READ_SESSION_KEYS,
        );
        const sessionId = assertSessionId(
          data.sessionId,
        );
        const records = Object.create(null);
        const verifiedEnrollments =
          Object.create(null);
        for (const role of ["payee", "payer"]) {
          const stored = readExactData(
            await store.readEnrollment({
              role,
              sessionId,
            }),
            STORED_ENROLLMENT_KEYS,
          );
          if (
            !Buffer.isBuffer(stored.bytes) ||
            !Buffer.isBuffer(stored.receiptBytes)
          ) {
            invalid();
          }
          const enrollmentBytes = Buffer.from(
            stored.bytes,
          );
          const receiptBytes = Buffer.from(
            stored.receiptBytes,
          );
          const enrollment =
            parseCoordinationEnrollment(
              enrollmentBytes,
            );
          const enrollmentDigest =
            assertSha256(stored.digest);
          if (
            sha256(enrollmentBytes) !==
              enrollmentDigest ||
            enrollment.paymentMoved !== false ||
            enrollment.repositorySha !==
              frozenRepositorySha ||
            enrollment.role !== role ||
            enrollment.sessionId !== sessionId
          ) {
            invalid();
          }
          await verifyCoordinationReceipt({
            bytes: receiptBytes,
            expected: {
              capabilityDigest:
                enrollment.capabilityDigest,
              enrollmentDigest,
              releaseId: enrollment.releaseId,
              repositorySha:
                enrollment.repositorySha,
              role,
              sessionId,
            },
            verifier: receiptSigner,
          });
          verifiedEnrollments[role] = enrollment;
          records[role] = Object.freeze({
            enrollmentBase64:
              enrollmentBytes.toString("base64"),
            enrollmentDigest,
            receiptBase64:
              receiptBytes.toString("base64"),
          });
        }
        const releaseId =
          verifiedEnrollments.payer.releaseId;
        if (
          verifiedEnrollments.payee.releaseId !==
          releaseId
        ) {
          invalid();
        }
        return parseCoordinationEnrollmentSet(
          stableBytes({
            enrollments: {
              payee: records.payee,
              payer: records.payer,
            },
            paymentMoved: false,
            releaseId,
            repositorySha: frozenRepositorySha,
            schema:
              COORDINATION_ENROLLMENT_SET_SCHEMA,
            sessionId,
          }),
        );
      });
    }

    async function readSessionView(value) {
      return guardedAsync(async () => {
        const data = readExactData(
          value,
          READ_SESSION_KEYS,
        );
        return (
          await replaySession(
            assertSessionId(data.sessionId),
          )
        ).view;
      });
    }

    async function readVerifierPublication(value) {
      return guardedAsync(async () => {
        const data = readExactData(
          value,
          READ_VERIFIER_PUBLICATION_KEYS,
        );
        const sessionId = assertSessionId(data.sessionId);
        const subjectRun = data.subjectRun;
        if (!["rehearsal", "stakeholder"].includes(subjectRun)) {
          invalid();
        }
        let claim;
        try {
          claim = await store.readVerifierPublication({
            sessionId,
            subjectRun,
          });
        } catch {
          invalid();
        }
        if (claim === null) {
          return null;
        }
        return readVerifierPublicationClaim(claim, {
          repositorySha: frozenRepositorySha,
          sessionId,
          subjectRun,
        });
      });
    }

    const service = {
      appendEvent,
      appendVerifiedEvent,
      bootstrap,
      getArtifact,
      putArtifact,
      readPayerMandate,
      readPaymentRequest,
      readEnrollmentReadiness,
      registerCapabilities,
      readEnrollmentSet,
      readEvents,
      readSessionView,
      readVerifierPublication,
      submitPaymentRequest,
    };
    if (
      Object.keys(service).length !==
        SERVICE_KEYS.length ||
      !Object.keys(service).every((key) =>
        SERVICE_KEYS.includes(key),
      )
    ) {
      invalid();
    }
    void now;
    return Object.freeze(service);
  });
}
