import {
  createHash,
  createPublicKey,
  timingSafeEqual,
  verify,
} from "node:crypto";
import {
  isAbsolute,
  normalize,
} from "node:path";

import {
  canonicalizeReceiptEventValue,
} from "../../canonical.mjs";
import {
  REGISTRY_ADDRESS,
} from "../../constants.mjs";
import {
  SENSITIVE_KEY,
  assertSecretFree,
} from "../../redact.mjs";
import {
  verifyDescriptorEnvelope,
} from "../descriptor.mjs";
import {
  canonicalBytes,
} from "../canonical.mjs";
import {
  renderPartyResultMarkdown,
  partySignatureBytes,
  validatePartyResult,
} from "../evidence.mjs";
import {
  recoverMessageAddress,
} from "viem";
import {
  TERMINAL_FAILURE_CODES,
} from "../protocol.mjs";
import {
  parseCoordinationEnrollment,
} from "./enrollment.mjs";
import {
  verifyPreflightKeyEnrollment,
  verifyTokenCommitment,
} from "./preflight.mjs";
import {
  probeKey,
  REFID_PATTERN,
} from "../refid.mjs";
import { PAYER_MANDATE_ENVELOPE_SCHEMA, payerMandateDigest, payerMandateSigningBytes, validatePayerMandate } from "../payer-mandate.mjs";
import { PAYMENT_REQUEST_ENVELOPE_SCHEMA, paymentRequestDigest, paymentRequestSigningBytes, validatePaymentRequest } from "../payment-request.mjs";

export const MAX_RELAY_ARTIFACT_BYTES = 1_048_576;
export const MAX_RELAY_PACKAGE_BYTES = 3_145_728;
export const RELAY_PACKAGE_SCHEMA =
  "clockchain.bilateral-relay-package/v1";

export const ARTIFACT_POLICIES = Object.freeze({
  "coordination-enrollment": Object.freeze({
    maximum: 65_536,
  }),
  "coordination-receipt": Object.freeze({
    maximum: 65_536,
  }),
  "payer-mandate": Object.freeze({ maximum: 65_536 }),
  "payment-request": Object.freeze({ maximum: 65_536 }),
  "failure-summary": Object.freeze({
    maximum: 16_384,
  }),
  "identity-package": Object.freeze({
    maximum: 1_048_576,
    markerRequired: true,
  }),
  "invitation-public-bundle": Object.freeze({
    maximum: 16_384,
  }),
  "party-result-package": Object.freeze({
    maximum: 3_145_728,
    markerRequired: true,
  }),
  "preflight-aggregate-report": Object.freeze({
    maximum: 1_048_576,
    markerRequired: true,
  }),
  "preflight-participant-report": Object.freeze({
    maximum: 1_048_576,
    markerRequired: true,
  }),
  "recovery-command-manifest": Object.freeze({
    maximum: 65_536,
  }),
  "preflight-plan": Object.freeze({
    maximum: 65_536,
  }),
  "preflight-public-key": Object.freeze({
    maximum: 65_536,
  }),
  "signed-descriptor": Object.freeze({
    maximum: 1_048_576,
  }),
  "token-commitment": Object.freeze({
    maximum: 65_536,
  }),
});

const INPUT_KEYS = Object.freeze([
  "artifactType",
  "bytes",
  "expectedDigest",
  "secretCanaries",
]);
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const PRIVATE_MATERIAL_PATTERN =
  /-----BEGIN (?:EC |OPENSSH |RSA )?PRIVATE KEY-----|(?:private.?key|secret|token|authorization|invite.?code|ciphertext)\s*["']?\s*[:=]\s*["']?[A-Za-z0-9+/_-]{16,}/i;
const ARCHIVE_PREFIXES = Object.freeze([
  Buffer.from([0x1f, 0x8b]),
  Buffer.from([0x50, 0x4b, 0x03, 0x04]),
  Buffer.from([0x50, 0x4b, 0x05, 0x06]),
  Buffer.from([0x50, 0x4b, 0x07, 0x08]),
]);
const MAX_CANARIES = 64;
const MAX_CANARY_BYTES = 8_192;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const TRANSACTION_PATTERN = /^0x[0-9a-f]{64}$/i;
const IDENTITY_REGISTRY_ADDRESS = REGISTRY_ADDRESS.toLowerCase();
const RECOVERY_COMMANDS = new Set([
  "scripts/probe-bilateral-rendezvous.mjs",
  "scripts/register-bilateral-identity.mjs",
  "bin/handshake-propose.mjs",
  "bin/handshake-accept.mjs",
]);
const ED25519_SPKI_PREFIX = Buffer.from(
  "302a300506032b6570032100",
  "hex",
);
const BASE64_PATTERN =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const SECP256K1_ORDER = BigInt(
  "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
);
const SECP256K1_HALF_ORDER = SECP256K1_ORDER / 2n;
const PREFLIGHT_PLAN_SCHEMA =
  "clockchain.bilateral-preflight-plan/v1";
const PREFLIGHT_CADENCE_MS = "20000";
// Recorded preflight timings must tolerate slow testnet confirmation during
// staggered stakeholder demos; align with the 30-minute discovery expiry.
const MAX_PREFLIGHT_DURATION_MS = 1_800_000;
const MAX_PREFLIGHT_ROUNDS = 25;
const OBSERVATION_CHANNELS = new Set([
  "derived-reference-id", "digest-hash", "cross-channel", "ledger-height",
]);
const OBSERVATION_CODES = new Set([
  "MALFORMED_SEARCH", "DUPLICATE", "BINDING_MISMATCH", "PREFLIGHT_READ_FAILED",
]);
const RATE_LIMIT_CODES = new Set([
  "MCP_RATE_LIMITED_BODY", "MCP_RATE_LIMIT", "MCP_RATE_LIMITED",
]);
const RATE_LIMIT_WIRES = new Set([
  "body-rate_limited", "http-429", "typed-rate-limit",
]);

export class RelayArtifactError extends Error {
  constructor() {
    super("Relay artifact validation failed.");
    this.name = new.target.name;
    this.category = "verification";
    this.code = "RELAY_ARTIFACT_INVALID";
  }
}

function invalid() {
  throw new RelayArtifactError();
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
  return Object.freeze(result);
}

function canonicalJsonBytes(value) {
  try {
    return Buffer.from(
      JSON.stringify(canonicalizeReceiptEventValue(value)),
      "utf8",
    );
  } catch {
    invalid();
  }
}

function parseCanonicalJson(bytes) {
  let parsed;
  try {
    const text = bytes.toString("utf8");
    if (Buffer.byteLength(text, "utf8") !== bytes.length) {
      invalid();
    }
    parsed = JSON.parse(text);
    if (!canonicalJsonBytes(parsed).equals(bytes)) {
      invalid();
    }
    return parsed;
  } catch (error) {
    if (error instanceof RelayArtifactError) {
      throw error;
    }
    invalid();
  }
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function normalizeCanaries(value) {
  if (
    !Array.isArray(value) ||
    value.length > MAX_CANARIES ||
    Reflect.ownKeys(value).length !== value.length + 1
  ) {
    invalid();
  }
  const result = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(
      value,
      String(index),
    );
    if (
      descriptor?.enumerable !== true ||
      !Object.hasOwn(descriptor, "value") ||
      typeof descriptor.value !== "string" ||
      descriptor.value.length === 0 ||
      Buffer.byteLength(descriptor.value, "utf8") >
        MAX_CANARY_BYTES
    ) {
      invalid();
    }
    result.push(descriptor.value);
  }
  return Object.freeze(result);
}

function assertDigest(expectedDigest, bytes) {
  if (
    typeof expectedDigest !== "string" ||
    !SHA256_PATTERN.test(expectedDigest)
  ) {
    invalid();
  }
  const actual = sha256(bytes);
  if (
    !timingSafeEqual(
      Buffer.from(expectedDigest, "ascii"),
      Buffer.from(actual, "ascii"),
    )
  ) {
    invalid();
  }
  return actual;
}

function assertNotArchive(bytes) {
  if (
    ARCHIVE_PREFIXES.some(
      (prefix) =>
        bytes.length >= prefix.length &&
        bytes.subarray(0, prefix.length).equals(prefix),
    ) ||
    (bytes.length >= 262 &&
      bytes.subarray(257, 262).toString("ascii") === "ustar")
  ) {
    invalid();
  }
}

function assertSafeBytes(bytes, parsed, canaries) {
  try {
    const text = bytes.toString("utf8");
    if (
      Buffer.byteLength(text, "utf8") !== bytes.length ||
      PRIVATE_MATERIAL_PATTERN.test(text)
    ) {
      invalid();
    }
    assertSecretFree(text, canaries);
    assertNoForbiddenKeys(parsed);
  } catch (error) {
    if (error instanceof RelayArtifactError) {
      throw error;
    }
    invalid();
  }
}

function assertNoForbiddenKeys(value) {
  const seen = new Set();
  let remaining = 4_096;
  function visit(entry, depth) {
    if (
      entry === null ||
      typeof entry !== "object" ||
      seen.has(entry)
    ) {
      return;
    }
    if (depth > 64 || remaining === 0) {
      invalid();
    }
    remaining -= 1;
    seen.add(entry);
    if (Array.isArray(entry)) {
      for (const item of entry) {
        visit(item, depth + 1);
      }
      return;
    }
    if (!isPlainObject(entry)) {
      invalid();
    }
    for (const key of Reflect.ownKeys(entry)) {
      const descriptor = Object.getOwnPropertyDescriptor(
        entry,
        key,
      );
      if (
        typeof key !== "string" ||
        descriptor?.enumerable !== true ||
        !Object.hasOwn(descriptor, "value") ||
        (SENSITIVE_KEY.test(key) &&
          !["tokenCommitment", "tokenCommitments", "tokenSha256"].includes(
            key,
          ))
      ) {
        invalid();
      }
      visit(descriptor.value, depth + 1);
    }
  }
  visit(value, 1);
}

function validateSignedDescriptor(bytes, parsed, canaries) {
  assertSafeBytes(bytes, parsed, canaries);
  let publicKey;
  try {
    const operator = readExactData(parsed, [
      "descriptor",
      "operator",
    ]).operator;
    publicKey = readExactData(operator, [
      "algorithm",
      "keyId",
      "publicKey",
      "signature",
    ]).publicKey;
    verifyDescriptorEnvelope(parsed, {
      repositoryPublicKey: publicKey,
    });
  } catch {
    invalid();
  }
}

function validateCoordinationEnrollment(
  bytes,
  parsed,
  canaries,
) {
  assertSafeBytes(bytes, parsed, canaries);
  try {
    parseCoordinationEnrollment(bytes);
  } catch {
    invalid();
  }
}

function validatePreflightPublicKey(
  bytes,
  parsed,
  canaries,
) {
  assertSafeBytes(bytes, parsed, canaries);
  try {
    verifyPreflightKeyEnrollment(parsed, {
      repositorySha: parsed.repositorySha,
      role: parsed.role,
    });
  } catch {
    invalid();
  }
}

function validateTokenCommitment(
  bytes,
  parsed,
  canaries,
) {
  assertSafeBytes(bytes, parsed, canaries);
  try {
    verifyTokenCommitment(parsed, {
      coordinationPublicKey:
        parsed.coordinationPublicKey,
      repositorySha: parsed.repositorySha,
      role: parsed.role,
      tokenSha256: parsed.tokenSha256,
    });
  } catch {
    invalid();
  }
}

function validateRecoveryManifest(bytes, parsed, canaries) {
  assertSafeBytes(bytes, parsed, canaries);
  const data = readExactData(parsed, [
    "arguments", "command", "paymentMoved", "reasonCode", "releaseId",
    "repositorySha", "role", "schema", "sessionId", "subjectRun",
  ]);
  if (
    data.schema !== "clockchain.bilateral-recovery-command-manifest/v1" ||
    data.paymentMoved !== false || !RECOVERY_COMMANDS.has(data.command) ||
    data.reasonCode !== "AMBIGUOUS_WRITE" ||
    !isReleaseId(data.releaseId) ||
    !/^[0-9a-f]{40}$/.test(data.repositorySha) ||
    !["payer", "payee"].includes(data.role) ||
    !UUID_PATTERN.test(data.sessionId) ||
    !["release", "rehearsal", "stakeholder"].includes(data.subjectRun) ||
    !Array.isArray(data.arguments) || data.arguments.length > 32 ||
    Reflect.ownKeys(data.arguments).length !== data.arguments.length + 1
  ) invalid();
  for (let index = 0; index < data.arguments.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(data.arguments, String(index));
    if (!descriptor || !Object.hasOwn(descriptor, "value") ||
      typeof descriptor.value !== "string" || !/^[ -~]{1,4096}$/.test(descriptor.value)) invalid();
  }
  validateRecoveryCommand(data);
}

function assertRecoveryPath(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 4096 ||
    !/^[ -~]+$/.test(value) || !isAbsolute(value) || value === "/" ||
    normalize(value) !== value) invalid();
  return value;
}

function validateRecoveryCommand(data) {
  const { arguments: args, command, repositorySha, role, subjectRun } = data;
  let expected;
  let paths;
  if (command === "scripts/probe-bilateral-rendezvous.mjs") {
    if (subjectRun !== "release") invalid();
    expected = ["participant", "--role", role, "--plan", null, "--token-file", null,
      "--participant-private-key", null, "--output", null];
    paths = [4, 6, 8, 10];
  } else if (command === "scripts/register-bilateral-identity.mjs") {
    if (! ["rehearsal", "stakeholder"].includes(subjectRun)) invalid();
    expected = ["--invitation", null, "--output", null, "--repository-sha", repositorySha,
      "--i-understand-this-writes-to-sepolia"];
    paths = [1, 3];
  } else if (command === "bin/handshake-propose.mjs") {
    if (role !== "payer" || !["rehearsal", "stakeholder"].includes(subjectRun)) invalid();
    expected = ["--clockchain-token-file", null, "--descriptor", null, "--invitation", null,
      "--output", null, "--i-understand-this-writes-to-clockchain"];
    paths = [1, 3, 5, 7];
  } else if (command === "bin/handshake-accept.mjs") {
    if (role !== "payee" || !["rehearsal", "stakeholder"].includes(subjectRun)) invalid();
    expected = ["--clockchain-token-file", null, "--descriptor", null, "--invitation", null,
      "--output", null, "--i-understand-this-writes-to-clockchain"];
    paths = [1, 3, 5, 7];
  } else invalid();
  if (args.length !== expected.length || expected.some((value, index) =>
    value !== null && args[index] !== value)) invalid();
  const pathValues = paths.map((index) => assertRecoveryPath(args[index]));
  if (new Set(pathValues).size !== pathValues.length) invalid();
}

function validateFailureSummary(bytes, parsed, canaries) {
  assertSafeBytes(bytes, parsed, canaries);
  const data = readExactData(parsed, [
    "eventKind", "paymentMoved", "releaseId", "repositorySha", "role",
    "schema", "sessionId", "subjectRun", "terminalCode",
  ]);
  if (
    data.schema !== "clockchain.bilateral-failure-summary/v1" ||
    data.eventKind !== "TERMINAL_FAILURE" || data.paymentMoved !== false ||
    !isReleaseId(data.releaseId) ||
    !/^[0-9a-f]{40}$/.test(data.repositorySha) ||
    !["operator", "payer", "payee"].includes(data.role) ||
    !UUID_PATTERN.test(data.sessionId) ||
    !["release", "rehearsal", "stakeholder"].includes(data.subjectRun) ||
    !TERMINAL_FAILURE_CODES.includes(data.terminalCode)
  ) invalid();
}

function isReleaseId(value) {
  return typeof value === "string" && value.length >= 1 && value.length <= 256 &&
    value.trim() === value && /^[ -~]+$/.test(value);
}

function parsePackage(parsed, names) {
  const wrapper = readExactData(parsed, ["files", "paymentMoved", "schema"]);
  if (wrapper.paymentMoved !== false || wrapper.schema !== RELAY_PACKAGE_SCHEMA ||
    !Array.isArray(wrapper.files) || wrapper.files.length !== names.length ||
    Reflect.ownKeys(wrapper.files).length !== wrapper.files.length + 1) invalid();
  const files = new Map();
  let packageBytes = 0;
  for (let index = 0; index < names.length; index += 1) {
    const entry = readExactData(wrapper.files[index], ["byteLength", "contentBase64", "name", "sha256"]);
    if (entry.name !== names[index] || !DECIMAL_PATTERN.test(entry.byteLength) ||
      !SHA256_PATTERN.test(entry.sha256) || typeof entry.contentBase64 !== "string") invalid();
    const content = Buffer.from(entry.contentBase64, "base64");
    if (content.toString("base64") !== entry.contentBase64 ||
      String(content.length) !== entry.byteLength || sha256(content) !== entry.sha256) invalid();
    packageBytes += content.length;
    if (packageBytes > MAX_RELAY_PACKAGE_BYTES) invalid();
    files.set(entry.name, content);
  }
  const marker = names[0] === ".party-result.complete.json"
    ? null
    : parseCanonicalJson(files.get(names[0]));
  return { files, marker };
}

function validateIdentityPackage(bytes, parsed, canaries) {
  assertSafeBytes(bytes, parsed, canaries);
  const { files, marker } = parsePackage(parsed,
    [".identity.complete.json", "identity.json"]);
  if (!Object.is(readExactData(marker, ["fileSha256", "schema"]).schema,
    "clockchain.bilateral-identity-registration-completion/v1") ||
    marker.fileSha256 !== sha256(files.get("identity.json"))) invalid();
  const identity = parseCanonicalJson(files.get("identity.json"));
  assertSafeBytes(files.get("identity.json"), identity, canaries);
  const data = readExactData(identity, ["address", "agentId", "chainId", "displayName", "identityReference", "metadata", "paymentMoved", "register", "registryAddress", "repositorySha", "schema"]);
  if (data.schema !== "clockchain.bilateral-identity-registration/v1" || data.paymentMoved !== false ||
    !ADDRESS_PATTERN.test(data.address) || !DECIMAL_PATTERN.test(data.agentId) ||
    data.chainId !== "11155111" || data.registryAddress !== IDENTITY_REGISTRY_ADDRESS ||
    data.identityReference !== `eip155:11155111:${REGISTRY_ADDRESS}:${data.agentId}` ||
    typeof data.displayName !== "string" || data.displayName.length < 1 ||
    data.displayName.length > 128 || data.displayName.trim() !== data.displayName ||
    /[\u0000-\u001f\u007f-\u009f]/u.test(data.displayName) ||
    !/^[0-9a-f]{40}$/.test(data.repositorySha)) invalid();
  for (const record of [data.metadata, data.register]) {
    const fields = readExactData(record, ["blockHeight", "transactionHash"]);
    if (!DECIMAL_PATTERN.test(fields.blockHeight) || !TRANSACTION_PATTERN.test(fields.transactionHash)) invalid();
  }
}

async function validatePartyPackage(bytes, parsed, canaries) {
  assertSafeBytes(bytes, parsed, canaries);
  const { files } = parsePackage(parsed,
    [".party-result.complete.json", "PARTY-RESULT.md", "party-result.json"]);
  let marker;
  try {
    const markerBytes = files.get(".party-result.complete.json");
    const markerText = markerBytes.toString("utf8");
    if (Buffer.byteLength(markerText, "utf8") !== markerBytes.length ||
      !markerText.endsWith("\n")) invalid();
    marker = JSON.parse(markerText);
    if (`${canonicalBytes(marker).toString("utf8")}\n` !== markerText) invalid();
  } catch (error) {
    if (error instanceof RelayArtifactError) throw error;
    invalid();
  }
  const completion = readExactData(marker, ["jsonSha256", "markdownSha256", "schema"]);
  const json = files.get("party-result.json");
  const markdown = files.get("PARTY-RESULT.md");
  if (completion.schema !== "clockchain.bilateral-party-result-completion/v1" ||
    completion.jsonSha256 !== sha256(json) || completion.markdownSha256 !== sha256(markdown)) invalid();
  let party;
  try {
    const text = json.toString("utf8");
    if (Buffer.byteLength(text, "utf8") !== json.length) invalid();
    party = JSON.parse(text);
  } catch (error) {
    if (error instanceof RelayArtifactError) throw error;
    invalid();
  }
  try {
    assertSecretFree(json.toString("utf8"), canaries);
    assertSecretFree(markdown.toString("utf8"), canaries);
    validatePartyResult(party);
    if (`${JSON.stringify(JSON.parse(canonicalBytes(party).toString("utf8")), null, 2)}\n` !== json.toString("utf8") ||
      renderPartyResultMarkdown(party) !== markdown.toString("utf8")) invalid();
    const signatureHex = party.signature.signature;
    const r = BigInt(`0x${signatureHex.slice(2, 66)}`);
    const s = BigInt(`0x${signatureHex.slice(66, 130)}`);
    const v = signatureHex.slice(130);
    if (r === 0n || r >= SECP256K1_ORDER || s === 0n ||
      s > SECP256K1_HALF_ORDER || !["1b", "1c"].includes(v)) invalid();
    const recovered = await recoverMessageAddress({
      message: { raw: partySignatureBytes({
        role: party.role,
        sessionDigest: party.sessionDigest,
        transitions: party.transitions,
      }) },
      signature: party.signature.signature,
    });
    if (recovered.toLowerCase() !== party.signature.address.toLowerCase()) invalid();
  } catch { invalid(); }
}

function rawEd25519PublicKey(value) {
  if (
    typeof value !== "string" ||
    !BASE64_PATTERN.test(value)
  ) {
    invalid();
  }
  const raw = Buffer.from(value, "base64");
  if (raw.length !== 32 || raw.toString("base64") !== value) {
    invalid();
  }
  try {
    return createPublicKey({
      format: "der",
      key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
      type: "spki",
    });
  } catch {
    invalid();
  }
}

function validatePreflightPlan(bytes, parsed, canaries) {
  assertSafeBytes(bytes, parsed, canaries);
  const envelope = readExactData(parsed, ["operator", "plan"]);
  const operator = readExactData(envelope.operator, [
    "algorithm", "keyId", "publicKey", "signature",
  ]);
  const plan = readExactData(envelope.plan, [
    "digests", "keys", "nonce", "participants", "paymentMoved",
    "protocol", "protocolVersion", "repositorySha", "schema",
    "writeBudget",
  ]);
  if (
    operator.algorithm !== "ed25519" ||
    !/^[a-z0-9][a-z0-9-]{0,63}$/.test(operator.keyId) ||
    plan.schema !== PREFLIGHT_PLAN_SCHEMA ||
    plan.protocol !== "clockchain.bilateral-authorization/v1" ||
    plan.protocolVersion !== "1" || plan.paymentMoved !== false ||
    plan.writeBudget !== "2" || !/^[0-9a-f]{40}$/.test(plan.repositorySha) ||
    !/^[0-9a-f]{32}$/.test(plan.nonce) ||
    !BASE64_PATTERN.test(operator.signature) ||
    Buffer.from(operator.signature, "base64").length !== 64 ||
    Buffer.from(operator.signature, "base64").toString("base64") !== operator.signature
  ) invalid();
  const digests = readExactData(plan.digests, ["payee", "payer"]);
  const keys = readExactData(plan.keys, ["payee", "payer"]);
  const participants = readExactData(plan.participants, ["payee", "payer"]);
  for (const role of ["payer", "payee"]) {
    const participant = readExactData(participants[role], [
      "coordinationPublicKey", "publicKey", "tokenCommitment",
    ]);
    if (
      !SHA256_PATTERN.test(digests[role]) ||
      keys[role] !== probeKey(plan.nonce, role) ||
      participant.publicKey === participant.coordinationPublicKey
    ) invalid();
    rawEd25519PublicKey(participant.publicKey);
    rawEd25519PublicKey(participant.coordinationPublicKey);
    try {
      verifyTokenCommitment(participant.tokenCommitment, {
        coordinationPublicKey: participant.coordinationPublicKey,
        repositorySha: plan.repositorySha,
        role,
      });
    } catch {
      invalid();
    }
  }
  const participantKeys = [
    participants.payer.publicKey,
    participants.payer.coordinationPublicKey,
    participants.payee.publicKey,
    participants.payee.coordinationPublicKey,
  ];
  if (digests.payer === digests.payee || keys.payer === keys.payee ||
    new Set(participantKeys).size !== participantKeys.length) invalid();
  const publicKey = rawEd25519PublicKey(operator.publicKey);
  if (new Set([operator.publicKey, ...participantKeys]).size !== 5) invalid();
  try {
    if (!verify(null, canonicalBytes(plan), publicKey,
      Buffer.from(operator.signature, "base64"))) invalid();
  } catch {
    invalid();
  }
}

function assertDenseArray(value) {
  if (
    !Array.isArray(value) ||
    Reflect.ownKeys(value).length !== value.length + 1
  ) invalid();
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (
      descriptor?.enumerable !== true ||
      !Object.hasOwn(descriptor, "value")
    ) invalid();
  }
}

function decimal(value) {
  if (typeof value !== "string" || !DECIMAL_PATTERN.test(value) || value.length > 16) invalid();
  const number = Number(value);
  if (!Number.isSafeInteger(number)) invalid();
  return number;
}

function canonicalAnchor(value, expected = {}) {
  const anchor = readExactData(value, [
    "anchoredHash", "assetReferenceId", "blockHeight", "ledgerId",
  ]);
  if (
    !SHA256_PATTERN.test(anchor.anchoredHash) ||
    typeof anchor.assetReferenceId !== "string" ||
    !REFID_PATTERN.test(anchor.assetReferenceId) ||
    typeof anchor.blockHeight !== "string" ||
    !DECIMAL_PATTERN.test(anchor.blockHeight) ||
    !UUID_PATTERN.test(anchor.ledgerId) ||
    (expected.digest !== undefined && anchor.anchoredHash !== expected.digest) ||
    (expected.key !== undefined && anchor.assetReferenceId !== expected.key)
  ) invalid();
  return anchor;
}

function sameAnchor(left, right) {
  return left.anchoredHash === right.anchoredHash &&
    left.assetReferenceId === right.assetReferenceId &&
    left.blockHeight === right.blockHeight && left.ledgerId === right.ledgerId;
}

function validateUniqueArray(value, limit, validate) {
  assertDenseArray(value);
  if (value.length > limit) invalid();
  const seen = new Set();
  for (const entry of value) {
    const canonical = JSON.stringify(entry);
    if (seen.has(canonical)) invalid();
    seen.add(canonical);
    validate(entry);
  }
}

function validatePeerObservation(value, peer) {
  const observation = readExactData(value, [
    "conflict", "digestAnchor", "digestResolved", "finalAnchor",
    "finalVerified", "peer", "referenceAnchor", "referenceResolved",
  ]);
  if (
    observation.peer !== peer || typeof observation.conflict !== "boolean" ||
    typeof observation.digestResolved !== "boolean" ||
    typeof observation.finalVerified !== "boolean" ||
    typeof observation.referenceResolved !== "boolean"
  ) invalid();
  for (const [resolved, anchor] of [
    [observation.digestResolved, observation.digestAnchor],
    [observation.referenceResolved, observation.referenceAnchor],
    [observation.finalVerified, observation.finalAnchor],
  ]) {
    if (resolved !== (anchor !== null)) invalid();
    if (anchor !== null) canonicalAnchor(anchor);
  }
  const resolved = [
    observation.digestResolved ? observation.digestAnchor : null,
    observation.referenceResolved ? observation.referenceAnchor : null,
  ].filter((anchor) => anchor !== null);
  const anchorsConflict = resolved.length === 2 && !sameAnchor(resolved[0], resolved[1]);
  if (observation.conflict !== anchorsConflict) invalid();
  if (observation.finalVerified && (
    resolved.length === 0 || !resolved.some((anchor) => sameAnchor(anchor, observation.finalAnchor))
  )) invalid();
  return observation;
}

function participantChannel(observation) {
  if (observation.finalVerified && observation.referenceResolved) {
    return "derived-reference-id";
  }
  if (observation.finalVerified && observation.digestResolved) return "digest-hash";
  if (observation.referenceResolved || observation.digestResolved) return "mixed";
  return "unavailable";
}

function validateParticipantReport(report, signature) {
  const participant = readExactData(report, [
    "channel", "completedAtMs", "deadlineAtMs", "observations",
    "paymentMoved", "peerObservation", "planDigest", "rateLimits",
    "repositorySha", "role", "schema", "serializedCadenceMs", "sleeps",
    "startedAtMs", "tokenCommitment", "write",
  ]);
  if (
    participant.schema !== "clockchain.bilateral-preflight-participant/v1" ||
    !["payer", "payee"].includes(participant.role) ||
    participant.role !== signature.role || participant.paymentMoved !== false ||
    !SHA256_PATTERN.test(participant.planDigest) ||
    !/^[0-9a-f]{40}$/.test(participant.repositorySha) ||
    participant.serializedCadenceMs !== PREFLIGHT_CADENCE_MS
  ) invalid();
  const started = decimal(participant.startedAtMs);
  const completed = decimal(participant.completedAtMs);
  const deadline = decimal(participant.deadlineAtMs);
  if (started > deadline || completed < started || deadline - started > MAX_PREFLIGHT_DURATION_MS) invalid();
  const write = readExactData(participant.write, [
    "anchoredHash", "assetReferenceId", "blockHeight", "digest", "key",
    "ledgerId", "role",
  ]);
  if (
    write.role !== participant.role || !SHA256_PATTERN.test(write.digest) ||
    typeof write.key !== "string" || !REFID_PATTERN.test(write.key)
  ) invalid();
  canonicalAnchor({
    anchoredHash: write.anchoredHash,
    assetReferenceId: write.assetReferenceId,
    blockHeight: write.blockHeight,
    ledgerId: write.ledgerId,
  }, { digest: write.digest, key: write.key });
  try {
    verifyTokenCommitment(participant.tokenCommitment, {
      coordinationPublicKey: participant.tokenCommitment.coordinationPublicKey,
      repositorySha: participant.repositorySha,
      role: participant.role,
      tokenSha256: participant.tokenCommitment.tokenSha256,
    });
  } catch { invalid(); }
  const observation = validatePeerObservation(participant.peerObservation,
    participant.role === "payer" ? "payee" : "payer");
  if (participant.channel !== participantChannel(observation)) invalid();
  validateUniqueArray(participant.observations, MAX_PREFLIGHT_ROUNDS * 4, (entry) => {
    const fields = readExactData(entry, ["channel", "code", "observer"]);
    if (!OBSERVATION_CHANNELS.has(fields.channel) ||
      !OBSERVATION_CODES.has(fields.code) || fields.observer !== participant.role) invalid();
  });
  validateUniqueArray(participant.rateLimits, MAX_PREFLIGHT_ROUNDS * 3, (entry) => {
    const fields = readExactData(entry, [
      "channel", "code", "observer", "retryAfterMs", "wireShape",
    ]);
    if (!OBSERVATION_CHANNELS.has(fields.channel) || !RATE_LIMIT_CODES.has(fields.code) ||
      !RATE_LIMIT_WIRES.has(fields.wireShape) || fields.observer !== participant.role ||
      !(fields.retryAfterMs === null || (typeof fields.retryAfterMs === "string" && decimal(fields.retryAfterMs) >= 0)) ||
      (fields.code === "MCP_RATE_LIMITED_BODY" && fields.wireShape !== "body-rate_limited") ||
      (fields.code === "MCP_RATE_LIMIT" && fields.wireShape !== "http-429") ||
      (fields.code === "MCP_RATE_LIMITED" && fields.wireShape !== "typed-rate-limit")) invalid();
  });
  validateUniqueArray(participant.sleeps, MAX_PREFLIGHT_ROUNDS - 1, (entry) => {
    if (typeof entry !== "string" || decimal(entry) <= 0 || decimal(entry) > MAX_PREFLIGHT_DURATION_MS) invalid();
  });
  return { observation, write };
}

function aggregateChannel(directions) {
  if (directions.every(({ finalVerified, referenceResolved }) =>
    finalVerified && referenceResolved)) return "derived-reference-id";
  if (directions.every(({ digestResolved, finalVerified }) =>
    digestResolved && finalVerified)) return "digest-hash";
  if (directions.some(({ referenceResolved, digestResolved }) => referenceResolved || digestResolved)) return "mixed";
  return "unavailable";
}

function validatePreflightReportPackage(bytes, parsed, canaries, type) {
  assertSafeBytes(bytes, parsed, canaries);
  const participant = type === "preflight-participant-report";
  const names = participant
    ? [".participant-report.complete.json", "participant-report.json"]
    : [".preflight-report.complete.json", "preflight-report.json"];
  const markerSchema = participant
    ? "clockchain.bilateral-preflight-participant-completion/v1"
    : "clockchain.bilateral-preflight-completion/v1";
  const { files, marker } = parsePackage(parsed, names);
  const completion = readExactData(marker, ["fileSha256", "schema"]);
  const reportBytes = files.get(names[1]);
  if (completion.schema !== markerSchema ||
    completion.fileSha256 !== sha256(reportBytes)) invalid();
  const envelope = parseCanonicalJson(reportBytes);
  assertSafeBytes(reportBytes, envelope, canaries);
  const outer = readExactData(envelope, ["report", "signature"]);
  const signature = readExactData(outer.signature, participant
    ? ["algorithm", "role", "value"]
    : ["algorithm", "keyId", "value"]);
  if (signature.algorithm !== "ed25519" ||
    !BASE64_PATTERN.test(signature.value) ||
    Buffer.from(signature.value, "base64").length !== 64 ||
    Buffer.from(signature.value, "base64").toString("base64") !== signature.value ||
    (participant && !["payer", "payee"].includes(signature.role)) ||
    (!participant && !/^[a-z0-9][a-z0-9-]{0,63}$/.test(signature.keyId))) invalid();
  const report = participant
    ? readExactData(outer.report, [
      "channel", "completedAtMs", "deadlineAtMs", "observations",
      "paymentMoved", "peerObservation", "planDigest", "rateLimits",
      "repositorySha", "role", "schema", "serializedCadenceMs", "sleeps",
      "startedAtMs", "tokenCommitment", "write",
    ])
    : readExactData(outer.report, [
      "channel", "completedAtMs", "directions", "outcome", "paymentMoved",
      "planDigest", "protocol", "protocolVersion", "repositorySha", "schema",
      "scope", "tenancy", "writes",
    ]);
  if (participant) {
    validateParticipantReport(report, signature);
  } else {
    const scope = readExactData(report.scope, [
      "separateCredentialsAttested", "separateMachinesAttested",
    ]);
    if (
      report.paymentMoved !== false || report.schema !== "clockchain.bilateral-preflight/v2" ||
      report.protocol !== "clockchain.bilateral-authorization/v1" || report.protocolVersion !== "1" ||
      !SHA256_PATTERN.test(report.planDigest) || !/^[0-9a-f]{40}$/.test(report.repositorySha) ||
      !["RENDEZVOUS_OK", "RENDEZVOUS_UNAVAILABLE"].includes(report.outcome) ||
      typeof scope.separateCredentialsAttested !== "boolean" ||
      typeof scope.separateMachinesAttested !== "boolean" ||
      report.tenancy !== (scope.separateCredentialsAttested && scope.separateMachinesAttested ? "cross-client" : "unknown")
    ) invalid();
    decimal(report.completedAtMs);
    assertDenseArray(report.directions);
    assertDenseArray(report.writes);
    if (report.directions.length !== 2 || report.writes.length !== 2) invalid();
    const directions = report.directions.map((entry, index) => {
      const direction = readExactData(entry, [
        "conflict", "digestAnchor", "digestResolved", "finalAnchor", "finalVerified",
        "observer", "peer", "referenceAnchor", "referenceResolved",
      ]);
      const observer = index === 0 ? "payer" : "payee";
      if (direction.observer !== observer) invalid();
      const { observer: ignored, ...observation } = direction;
      return validatePeerObservation(
        observation,
        observer === "payer" ? "payee" : "payer",
      );
    });
    const writes = report.writes.map((entry, index) => {
      const write = readExactData(entry, [
        "anchoredHash", "assetReferenceId", "blockHeight", "digest", "key", "ledgerId", "role",
      ]);
      const role = index === 0 ? "payer" : "payee";
      if (write.role !== role || !SHA256_PATTERN.test(write.digest) ||
        typeof write.key !== "string" || !REFID_PATTERN.test(write.key)) invalid();
      canonicalAnchor({
        anchoredHash: write.anchoredHash,
        assetReferenceId: write.assetReferenceId,
        blockHeight: write.blockHeight,
        ledgerId: write.ledgerId,
      }, { digest: write.digest, key: write.key });
      return write;
    });
    if (writes[0].ledgerId === writes[1].ledgerId &&
      writes[0].blockHeight === writes[1].blockHeight ||
      sameAnchor(writes[0], writes[1]) || writes[0].digest === writes[1].digest ||
      writes[0].key === writes[1].key) invalid();
    for (let index = 0; index < 2; index += 1) {
      const opposite = writes[index === 0 ? 1 : 0];
      for (const [resolved, anchor] of [
        [directions[index].digestResolved, directions[index].digestAnchor],
        [directions[index].referenceResolved, directions[index].referenceAnchor],
        [directions[index].finalVerified, directions[index].finalAnchor],
      ]) if (resolved && !sameAnchor(anchor, opposite)) invalid();
    }
    if (report.channel !== aggregateChannel(directions)) invalid();
    const success = scope.separateCredentialsAttested && scope.separateMachinesAttested &&
      directions.every((direction) => direction.referenceResolved && direction.finalVerified && !direction.conflict);
    if ((report.outcome === "RENDEZVOUS_OK") !== success) invalid();
  }
}

async function validateRelayArtifactInternal(input) {
  try {
    const data = readExactData(input, INPUT_KEYS);
    const policy = ARTIFACT_POLICIES[data.artifactType];
    if (
      policy === undefined ||
      !Buffer.isBuffer(data.bytes) ||
      data.bytes.length === 0 ||
      data.bytes.length > policy.maximum
    ) {
      invalid();
    }
    const bytes = Buffer.from(data.bytes);
    const canaries = normalizeCanaries(data.secretCanaries);
    assertNotArchive(bytes);
    const digest = assertDigest(
      data.expectedDigest,
      bytes,
    );
    const parsed = parseCanonicalJson(bytes);
    if (
      data.artifactType === "coordination-enrollment"
    ) {
      validateCoordinationEnrollment(
        bytes,
        parsed,
        canaries,
      );
    } else if (data.artifactType === "payer-mandate") {
      readExactData(parsed, ["mandate", "schema", "signature"]);
      validatePayerMandate(parsed.mandate);
      payerMandateDigest(parsed);
      if (parsed.schema !== PAYER_MANDATE_ENVELOPE_SCHEMA || parsed.signature?.algorithm !== "eip191" || parsed.signature.address !== parsed.mandate.payer.address) invalid();
      const recovered = await recoverMessageAddress({ message: { raw: payerMandateSigningBytes(parsed.mandate) }, signature: parsed.signature.value });
      if (recovered.toLowerCase() !== parsed.mandate.payer.address) invalid();
    } else if (data.artifactType === "payment-request") {
      readExactData(parsed, ["request", "schema", "signature"]);
      validatePaymentRequest(parsed.request);
      paymentRequestDigest(parsed);
      if (parsed.schema !== PAYMENT_REQUEST_ENVELOPE_SCHEMA || parsed.signature?.algorithm !== "eip191" || parsed.signature.address !== parsed.request.payee.address) invalid();
      const recovered = await recoverMessageAddress({ message: { raw: paymentRequestSigningBytes(parsed.request) }, signature: parsed.signature.value });
      if (recovered.toLowerCase() !== parsed.request.payee.address) invalid();
    } else if (
      data.artifactType === "signed-descriptor"
    ) {
      validateSignedDescriptor(bytes, parsed, canaries);
    } else if (
      data.artifactType === "preflight-public-key"
    ) {
      validatePreflightPublicKey(
        bytes,
        parsed,
        canaries,
      );
    } else if (
      data.artifactType === "token-commitment"
    ) {
      validateTokenCommitment(
        bytes,
        parsed,
        canaries,
      );
    } else if (data.artifactType === "recovery-command-manifest") {
      validateRecoveryManifest(bytes, parsed, canaries);
    } else if (data.artifactType === "failure-summary") {
      validateFailureSummary(bytes, parsed, canaries);
    } else if (data.artifactType === "identity-package") {
      validateIdentityPackage(bytes, parsed, canaries);
    } else if (data.artifactType === "party-result-package") {
      await validatePartyPackage(bytes, parsed, canaries);
    } else if (data.artifactType === "preflight-plan") {
      validatePreflightPlan(bytes, parsed, canaries);
    } else if (
      data.artifactType === "preflight-participant-report" ||
      data.artifactType === "preflight-aggregate-report"
    ) {
      validatePreflightReportPackage(
        bytes,
        parsed,
        canaries,
        data.artifactType,
      );
    } else {
      // The allowlist reserves protocol artifact names and limits.
      // Publication remains disabled until a repository-owned exact
      // schema and trust validator is available for that type.
      invalid();
    }
    return Object.freeze({
      artifactType: data.artifactType,
      byteLength: String(bytes.length),
      digest,
      parsed,
    });
  } catch (error) {
    if (error instanceof RelayArtifactError) {
      throw error;
    }
    invalid();
  }
}

function deepFreeze(value) {
  if (
    value !== null &&
    typeof value === "object" &&
    !Object.isFrozen(value)
  ) {
    for (const child of Object.values(value)) {
      deepFreeze(child);
    }
    Object.freeze(value);
  }
  return value;
}

function parseValidatedPackageJson(parsed, names, filename) {
  const { files } = parsePackage(parsed, names);
  try {
    return JSON.parse(files.get(filename).toString("utf8"));
  } catch {
    invalid();
  }
}

function normalizedFacts(artifactType, parsed) {
  if (artifactType === "identity-package") {
    return Object.freeze({
      identity: parseValidatedPackageJson(
        parsed,
        [".identity.complete.json", "identity.json"],
        "identity.json",
      ),
    });
  }
  if (artifactType === "preflight-participant-report") {
    return Object.freeze({
      participantReport: parseValidatedPackageJson(
        parsed,
        [".participant-report.complete.json", "participant-report.json"],
        "participant-report.json",
      ),
    });
  }
  if (artifactType === "preflight-aggregate-report") {
    return Object.freeze({
      aggregateReport: parseValidatedPackageJson(
        parsed,
        [".preflight-report.complete.json", "preflight-report.json"],
        "preflight-report.json",
      ),
    });
  }
  if (artifactType === "party-result-package") {
    return Object.freeze({
      partyResult: parseValidatedPackageJson(
        parsed,
        [
          ".party-result.complete.json",
          "PARTY-RESULT.md",
          "party-result.json",
        ],
        "party-result.json",
      ),
    });
  }
  return parsed;
}

export async function validateRelayArtifact(input) {
  const result = await validateRelayArtifactInternal(input);
  return Object.freeze({
    artifactType: result.artifactType,
    byteLength: result.byteLength,
    digest: result.digest,
  });
}

// This sibling shares the exact snapshotted parser and validators above. It
// deliberately never rereads caller-owned bytes after an async validator.
export async function validateRelayArtifactWithFacts(input) {
  try {
    const result = await validateRelayArtifactInternal(input);
    const facts = deepFreeze(normalizedFacts(result.artifactType, result.parsed));
    return Object.freeze({
      artifactType: result.artifactType,
      byteLength: result.byteLength,
      digest: result.digest,
      facts,
    });
  } catch (error) {
    if (error instanceof RelayArtifactError) {
      throw error;
    }
    invalid();
  }
}
