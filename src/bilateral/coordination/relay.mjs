import {
  createHash,
  timingSafeEqual,
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
  operatorPublicKeyPath,
  publicKeyPemFromRawBase64,
  verifyDescriptorEnvelope,
} from "../descriptor.mjs";
import {
  validateRelayArtifact,
} from "./artifact.mjs";
import {
  COORDINATION_ENROLLMENT_SET_SCHEMA,
  invitationProofPreimage,
  parseCoordinationEnrollment,
  parseCoordinationEnrollmentSet,
} from "./enrollment.mjs";
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

const SERVICE_KEYS = Object.freeze([
  "appendEvent",
  "bootstrap",
  "getArtifact",
  "putArtifact",
  "readEnrollmentSet",
  "readEvents",
  "readSessionView",
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
  "consumeCapability",
  "getArtifact",
  "putArtifact",
  "readEnrollment",
  "readEvents",
  "readReleaseView",
]);
const BOOTSTRAP_INPUT_KEYS = Object.freeze(["body"]);
const BOOTSTRAP_KEYS = Object.freeze([
  "capability",
  "enrollment",
]);
const APPEND_INPUT_KEYS = Object.freeze(["body"]);
const GET_ARTIFACT_KEYS = Object.freeze(["digest"]);
const PUT_ARTIFACT_KEYS = Object.freeze([
  "artifactType",
  "body",
  "expectedDigest",
]);
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
const CAPABILITY_PATTERN = /^[0-9a-f]{64}$/;
const REPOSITORY_SHA_PATTERN = /^[0-9a-f]{40}$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DESCRIPTOR_EVENT_KINDS = new Set([
  "DESCRIPTOR_ACCEPTED",
  "REHEARSAL_DESCRIPTOR_READY",
  "STAKEHOLDER_DESCRIPTOR_READY",
]);
const UNSUPPORTED_ARTIFACT_EVENT_KINDS = new Set([
  "EXACT_RECOVERY_AUTHORIZATION",
  "IDENTITY_PACKAGE_READY",
  "PREFLIGHT_PARTICIPANT_READY",
  "PREFLIGHT_PLAN_READY",
  "RECOVERY_REQUIRED",
  "ROLE_PACKAGE_READY",
  "TOKEN_READY",
]);

export class CoordinationRelayError extends Error {
  constructor() {
    super("Coordination relay operation failed safely.");
    this.name = new.target.name;
    this.category = "verification";
    this.code = "COORDINATION_RELAY_INVALID";
  }
}

function invalid() {
  throw new CoordinationRelayError();
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

export function createDescriptorArtifactTransitionValidator(
  input,
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
        if (
          UNSUPPORTED_ARTIFACT_EVENT_KINDS.has(
            envelope.kind,
          )
        ) {
          invalid();
        }
        if (!DESCRIPTOR_EVENT_KINDS.has(envelope.kind)) {
          if (envelope.artifactDigest !== null) {
            invalid();
          }
          return null;
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
        let bytes;
        try {
          bytes = await data.readArtifact(digest);
          validateRelayArtifact({
            artifactType: "signed-descriptor",
            bytes,
            expectedDigest: digest,
            secretCanaries: [],
          });
        } catch {
          invalid();
        }
        let descriptorEnvelope;
        try {
          descriptorEnvelope = JSON.parse(
            bytes.toString("utf8"),
          );
        } catch {
          invalid();
        }
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
          return candidate;
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
        return candidate;
      });
    }

    return Object.freeze({ validate });
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
        createDescriptorArtifactTransitionValidator({
          frozenRepositorySha,
          readArtifact: store.getArtifact,
          resolveOperatorPublicKey:
            resolvedOperatorPublicKey,
        });
      for (const event of stored.events) {
        const envelope = readEnvelope(event);
        if (envelope.kind === "VERIFICATION_PASSED") {
          invalid();
        }
        const expectedPublicKey =
          await eventAuthority(event);
        await descriptorArtifacts.validate(event);
        try {
          view = reduceReleaseEvent(
            view,
            event,
            { expectedPublicKey },
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
        return verifyCoordinationReceipt({
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
        try {
          reduceReleaseEvent(
            replayed.view,
            event,
            { expectedPublicKey },
          );
        } catch {
          invalid();
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

    const service = {
      appendEvent,
      bootstrap,
      getArtifact,
      putArtifact,
      readEnrollmentSet,
      readEvents,
      readSessionView,
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
