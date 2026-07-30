import { createHash } from "node:crypto";

import { canonicalBytes } from "../canonical.mjs";

const DESCRIPTOR_SESSION_DOMAIN =
  "clockchain.bilateral-descriptor-session/v1\n";
const INPUT_KEYS = Object.freeze([
  "releaseId",
  "repositorySha",
  "sessionId",
  "subjectRun",
]);
const RELEASE_ID_PATTERN = /^[ -~]{1,256}$/;
const REPOSITORY_SHA_PATTERN = /^[0-9a-f]{40}$/;
const COORDINATION_SESSION_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const invalid = () => {
  throw new Error("Descriptor run session derivation failed safely.");
};

function exactInput(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    invalid();
  }
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== INPUT_KEYS.length ||
    ownKeys.some(
      (key) =>
        typeof key !== "string" || !INPUT_KEYS.includes(key),
    )
  ) {
    invalid();
  }
  const result = Object.create(null);
  for (const key of INPUT_KEYS) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor?.enumerable !== true ||
      !Object.hasOwn(descriptor, "value")
    ) {
      invalid();
    }
    result[key] = descriptor.value;
  }
  return result;
}

export function deriveDescriptorSessionId(input) {
  const {
    releaseId,
    repositorySha,
    sessionId,
    subjectRun,
  } = exactInput(input);
  if (
    typeof releaseId !== "string" ||
    !RELEASE_ID_PATTERN.test(releaseId) ||
    releaseId.trim() !== releaseId ||
    typeof repositorySha !== "string" ||
    !REPOSITORY_SHA_PATTERN.test(repositorySha) ||
    typeof sessionId !== "string" ||
    !COORDINATION_SESSION_ID_PATTERN.test(sessionId) ||
    (subjectRun !== "rehearsal" &&
      subjectRun !== "stakeholder")
  ) {
    invalid();
  }
  return createHash("sha256")
    .update(DESCRIPTOR_SESSION_DOMAIN, "ascii")
    .update(
      canonicalBytes({
        releaseId,
        repositorySha,
        sessionId,
        subjectRun,
      }),
    )
    .digest("hex")
    .slice(0, 32);
}
