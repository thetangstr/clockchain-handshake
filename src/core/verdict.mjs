import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { join } from "node:path";
import { types } from "node:util";

import { recoverMessageAddress } from "viem";

import {
  deadlineMs,
  isWithinDeadline,
  liveUpperBoundMs,
  parseBlockTime,
  verifierUpperBoundMs,
} from "./blocktime.mjs";
import { canonicalBytes } from "./canonical.mjs";
import {
  dSession,
  operatorPublicKeyPath,
  verifyDescriptorEnvelope,
} from "./descriptor.mjs";
import {
  payerMandateDigest,
} from "./payer-mandate.mjs";
import {
  paymentRequestDigest,
  verifyPaymentRequest,
} from "./payment-request.mjs";
import {
  partySignatureBytes,
  renderPartyResultMarkdown,
  validatePartyResult,
} from "./evidence.mjs";
import {
  authoritativeTriple,
  buildAcceptance,
  buildAcknowledgment,
  transitionDigest,
} from "./messages.mjs";
import {
  ProtocolFailureError,
  recoverAnchoredProposal,
  verifyTransition,
} from "./protocol.mjs";
import { sessionKey } from "./refid.mjs";
import {
  McpNetworkError,
  McpRateLimitedError,
} from "./clockchain.mjs";
import { assertSecretFree } from "./redact.mjs";

export const VERDICT_SCHEMA =
  "clockchain.bilateral-authorization-verdict/v2";
export const VERDICT_KEYS = Object.freeze([
  "mandateDigest",
  "outcome",
  "paymentMoved",
  "promptSha256",
  "protocolVersion",
  "repositorySha",
  "requestDigest",
  "schema",
  "sessionDigest",
  "transitions",
]);
export const VERDICT_TRANSITION_KEYS = Object.freeze([
  "anchoredHash",
  "blockHeight",
  "blockTimeRaw",
  "digest",
  "kind",
  "ledgerId",
  "upperBoundMs",
]);

const COMPLETION_MARKER_SCHEMA =
  "clockchain.bilateral-party-result-completion/v1";
const COMPLETION_MARKER_KEYS = Object.freeze([
  "jsonSha256",
  "markdownSha256",
  "schema",
]);
const INPUT_KEYS = new Set([
  "canaries",
  "clockchain",
  "descriptorEnvelope",
  "fileSystem",
  "mandateEnvelope",
  "ownerOf",
  "payeeDirectory",
  "payerDirectory",
  "requestEnvelope",
  "repositoryPublicKeyResolver",
]);
const REQUIRED_INPUT_KEYS = Object.freeze([
  "clockchain",
  "descriptorEnvelope",
  "mandateEnvelope",
  "ownerOf",
  "payeeDirectory",
  "payerDirectory",
  "requestEnvelope",
  "repositoryPublicKeyResolver",
]);
const CLOCKCHAIN_METHODS = Object.freeze([
  "generateAuditTrail",
  "getBlock",
  "resolveAgent",
  "searchActions",
  "verifyCrossParty",
]);
const HASH_PATTERN = /^[0-9a-f]{64}$/;
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/i;
const MAX_DESCRIPTOR_OBJECTS = 256;
const MAX_DESCRIPTOR_DEPTH = 32;
const MAX_MARKER_BYTES = 2048;
const MAX_JSON_BYTES = 1024 * 1024;
const MAX_MARKDOWN_BYTES = 2 * 1024 * 1024;
const DEFAULT_FILE_SYSTEM = Object.freeze({ lstat, open });
const PARTY_RESULT_FILES = Object.freeze({
  json: "party-result.json",
  markdown: "PARTY-RESULT.md",
  marker: ".party-result.complete.json",
});
const VERDICT_COMPLETION_MARKER_SCHEMA =
  "clockchain.bilateral-authorization-verdict-completion/v2";
const VERDICT_COMPLETION_MARKER_KEYS = Object.freeze([
  "jsonSha256",
  "markdownSha256",
  "schema",
]);
const VERDICT_PUBLICATION_INPUT_KEYS = Object.freeze([
  "mandateDigest",
  "outputDirectory",
  "repositorySha",
  "requestDigest",
  "sessionDigest",
]);
const VERDICT_PUBLICATION_FILES = Object.freeze({
  json: "bilateral-verdict.json",
  markdown: "BILATERAL-VERDICT.md",
  marker: ".bilateral-verdict.complete.json",
});

export class BilateralVerdictError extends Error {
  constructor(terminalCode = "FAILED") {
    super("Independent bilateral authorization verification failed closed.");
    this.name = new.target.name;
    this.category = "verification";
    this.code = `BILATERAL_VERDICT_${terminalCode}`;
    this.terminalCode = terminalCode;
  }
}

function fail(terminalCode = "FAILED") {
  throw new BilateralVerdictError(terminalCode);
}

function isPlainObject(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    types.isProxy(value)
  ) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function ownData(value, key) {
  const property = Object.getOwnPropertyDescriptor(value, key);
  if (
    property?.enumerable !== true ||
    !Object.hasOwn(property, "value")
  ) {
    fail();
  }
  return property.value;
}

function hasExactKeys(value, expectedKeys) {
  if (!isPlainObject(value)) {
    return false;
  }
  const keys = Reflect.ownKeys(value);
  return (
    keys.length === expectedKeys.length &&
    keys.every(
      (key) =>
        typeof key === "string" &&
        expectedKeys.includes(key) &&
        Object.getOwnPropertyDescriptor(value, key)?.enumerable ===
          true &&
        Object.hasOwn(
          Object.getOwnPropertyDescriptor(value, key),
          "value",
        ),
    )
  );
}

function snapshotValue(value, state, depth) {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (
    typeof value !== "object" ||
    types.isProxy(value) ||
    depth > MAX_DESCRIPTOR_DEPTH ||
    state.remaining === 0 ||
    state.ancestors.has(value)
  ) {
    fail();
  }
  state.remaining -= 1;
  state.ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const lengthProperty =
        Object.getOwnPropertyDescriptor(value, "length");
      const length = lengthProperty?.value;
      if (
        !lengthProperty ||
        lengthProperty.enumerable ||
        !Object.hasOwn(lengthProperty, "value") ||
        !Number.isSafeInteger(length) ||
        length < 0 ||
        length > 16 ||
        Reflect.ownKeys(value).length !== length + 1
      ) {
        fail();
      }
      const result = new Array(length);
      for (let index = 0; index < length; index += 1) {
        result[index] = snapshotValue(
          ownData(value, String(index)),
          state,
          depth + 1,
        );
      }
      return Object.freeze(result);
    }
    if (!isPlainObject(value)) {
      fail();
    }
    const result = Object.create(null);
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== "string") {
        fail();
      }
      result[key] = snapshotValue(
        ownData(value, key),
        state,
        depth + 1,
      );
    }
    return Object.freeze(result);
  } finally {
    state.ancestors.delete(value);
  }
}

function detachedSnapshot(value) {
  return snapshotValue(
    value,
    {
      ancestors: new Set(),
      remaining: MAX_DESCRIPTOR_OBJECTS,
    },
    1,
  );
}

function validateCanaries(value) {
  if (
    !Array.isArray(value) ||
    types.isProxy(value) ||
    value.length > 32
  ) {
    fail();
  }
  const result = [];
  for (let index = 0; index < value.length; index += 1) {
    const entry = ownData(value, String(index));
    if (
      typeof entry !== "string" ||
      entry.length === 0 ||
      Buffer.byteLength(entry, "utf8") > 4096
    ) {
      fail();
    }
    result.push(entry);
  }
  return Object.freeze(result);
}

function callableDataMethod(value, key) {
  if (!isPlainObject(value)) {
    fail();
  }
  const method = ownData(value, key);
  if (typeof method !== "function" || types.isProxy(method)) {
    fail();
  }
  return method;
}

function validateInput(input) {
  if (!isPlainObject(input)) {
    fail();
  }
  const keys = Reflect.ownKeys(input);
  if (
    keys.some(
      (key) =>
        typeof key !== "string" || !INPUT_KEYS.has(key),
    ) ||
    !REQUIRED_INPUT_KEYS.every((key) => keys.includes(key))
  ) {
    fail();
  }
  const suppliedClockchain = ownData(input, "clockchain");
  const clockchainMethods = {};
  for (const method of CLOCKCHAIN_METHODS) {
    clockchainMethods[method] = callableDataMethod(
      suppliedClockchain,
      method,
    ).bind(suppliedClockchain);
  }
  const clockchain = Object.freeze(clockchainMethods);
  const ownerOf = ownData(input, "ownerOf");
  const repositoryPublicKeyResolver = ownData(
    input,
    "repositoryPublicKeyResolver",
  );
  if (
    typeof ownerOf !== "function" ||
    typeof repositoryPublicKeyResolver !== "function"
  ) {
    fail();
  }
  const payerDirectory = ownData(input, "payerDirectory");
  const payeeDirectory = ownData(input, "payeeDirectory");
  if (
    typeof payerDirectory !== "string" ||
    payerDirectory.length === 0 ||
    payerDirectory.length > 4096 ||
    payerDirectory.includes("\0") ||
    typeof payeeDirectory !== "string" ||
    payeeDirectory.length === 0 ||
    payeeDirectory.length > 4096 ||
    payeeDirectory.includes("\0") ||
    payerDirectory === payeeDirectory
  ) {
    fail();
  }
  let fileSystem = DEFAULT_FILE_SYSTEM;
  if (keys.includes("fileSystem")) {
    const supplied = ownData(input, "fileSystem");
    fileSystem = Object.freeze({
      open: callableDataMethod(supplied, "open"),
    });
  }
  const canaries = keys.includes("canaries")
    ? validateCanaries(ownData(input, "canaries"))
    : Object.freeze([]);
  return Object.freeze({
    canaries,
    clockchain,
    descriptorEnvelope: detachedSnapshot(
      ownData(input, "descriptorEnvelope"),
    ),
    fileSystem,
    mandateEnvelope: detachedSnapshot(
      ownData(input, "mandateEnvelope"),
    ),
    ownerOf,
    payeeDirectory,
    payerDirectory,
    requestEnvelope: detachedSnapshot(
      ownData(input, "requestEnvelope"),
    ),
    repositoryPublicKeyResolver,
  });
}

function sameStat(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.nlink === right.nlink &&
    left.uid === right.uid &&
    left.gid === right.gid &&
    left.rdev === right.rdev &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs
  );
}

async function readAtMost(handle, maxBytes) {
  const bytes = Buffer.alloc(maxBytes + 1);
  let offset = 0;
  while (offset < bytes.length) {
    const result = await handle.read(
      bytes,
      offset,
      bytes.length - offset,
      offset,
    );
    if (
      result === null ||
      typeof result !== "object" ||
      !Number.isSafeInteger(result.bytesRead) ||
      result.bytesRead < 0 ||
      result.bytesRead > bytes.length - offset
    ) {
      fail();
    }
    if (result.bytesRead === 0) {
      break;
    }
    offset += result.bytesRead;
  }
  return bytes.subarray(0, offset);
}

async function readBoundedRegularFile(
  fileSystem,
  path,
  maxBytes,
  validateMetadata = () => true,
) {
  let handle;
  let closeFailed = false;
  try {
    handle = await fileSystem.open(
      path,
      constants.O_RDONLY |
        (constants.O_NOFOLLOW ?? 0) |
        (constants.O_NONBLOCK ?? 0),
    );
    if (
      handle === null ||
      typeof handle !== "object" ||
      typeof handle.stat !== "function" ||
      typeof handle.read !== "function" ||
      typeof handle.close !== "function"
    ) {
      fail();
    }
    const before = await handle.stat();
    if (
      typeof before?.isFile !== "function" ||
      !before.isFile() ||
      !Number.isSafeInteger(before.size) ||
      before.size < 0 ||
      before.size > maxBytes ||
      !validateMetadata(before)
    ) {
      fail();
    }
    const bytes = await readAtMost(handle, maxBytes);
    const after = await handle.stat();
    if (
      !Buffer.isBuffer(bytes) ||
      bytes.length > maxBytes ||
      bytes.length !== before.size ||
      !sameStat(before, after) ||
      !validateMetadata(after)
    ) {
      fail();
    }
    return bytes;
  } catch (error) {
    if (error instanceof BilateralVerdictError) {
      throw error;
    }
    fail();
  } finally {
    if (handle !== undefined) {
      try {
        await handle.close();
      } catch {
        closeFailed = true;
      }
    }
    if (closeFailed) {
      fail();
    }
  }
}

function hasStablePosixMetadata(metadata) {
  return [
    metadata?.dev,
    metadata?.ino,
    metadata?.mode,
    metadata?.nlink,
    metadata?.uid,
    metadata?.gid,
    metadata?.rdev,
  ].every(Number.isSafeInteger);
}

function isCurrentUserPrivate(metadata, mode, nlink) {
  if (!hasStablePosixMetadata(metadata)) {
    return false;
  }
  if (process.platform === "win32") {
    return true;
  }
  return (
    (metadata.mode & 0o777) === mode &&
    metadata.nlink === nlink &&
    (
      typeof process.getuid !== "function" ||
      metadata.uid === process.getuid()
    )
  );
}

function isPrivatePublicationDirectory(metadata) {
  return (
    typeof metadata?.isDirectory === "function" &&
    metadata.isDirectory() &&
    isCurrentUserPrivate(metadata, 0o700, metadata.nlink)
  );
}

function isPrivatePublicationFile(metadata) {
  return (
    typeof metadata?.isFile === "function" &&
    metadata.isFile() &&
    isCurrentUserPrivate(metadata, 0o600, 1)
  );
}

async function openPinnedPublicationDirectory(fileSystem, path) {
  let handle;
  try {
    const metadata = await fileSystem.lstat(path);
    if (!isPrivatePublicationDirectory(metadata)) {
      fail();
    }
    handle = await fileSystem.open(
      path,
      constants.O_RDONLY |
        (constants.O_DIRECTORY ?? 0) |
        (constants.O_NOFOLLOW ?? 0),
    );
    if (
      handle === null ||
      typeof handle !== "object" ||
      typeof handle.stat !== "function" ||
      typeof handle.close !== "function"
    ) {
      fail();
    }
    const openedMetadata = await handle.stat();
    if (
      !isPrivatePublicationDirectory(openedMetadata) ||
      !sameStat(metadata, openedMetadata)
    ) {
      fail();
    }
    return { handle, metadata };
  } catch (error) {
    if (handle !== undefined) {
      try {
        await handle.close();
      } catch {
        fail();
      }
    }
    if (error instanceof BilateralVerdictError) {
      throw error;
    }
    fail();
  }
}

async function assertPinnedPublicationDirectory(
  fileSystem,
  path,
  handle,
  metadata,
) {
  const current = await fileSystem.lstat(path);
  const opened = await handle.stat();
  if (
    !isPrivatePublicationDirectory(current) ||
    !isPrivatePublicationDirectory(opened) ||
    !sameStat(metadata, current) ||
    !sameStat(metadata, opened)
  ) {
    fail();
  }
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function publishedVerdictDigest(json, markdown, marker) {
  return sha256(canonicalBytes({
    jsonSha256: sha256(json),
    markdownSha256: sha256(markdown),
    markerSha256: sha256(marker),
  }));
}

function publisherVerdictBytes(verdict) {
  const published = {};
  for (const key of VERDICT_KEYS) {
    published[key] =
      key === "transitions"
        ? verdict.transitions.map((transition) => {
          const publishedTransition = {};
          for (const transitionKey of VERDICT_TRANSITION_KEYS) {
            publishedTransition[transitionKey] = transition[transitionKey];
          }
          return publishedTransition;
        })
        : verdict[key];
  }
  return Buffer.from(`${JSON.stringify(published, null, 2)}\n`, "utf8");
}

function parseMarker(bytes, canaries) {
  let marker;
  try {
    const text = bytes.toString("utf8");
    assertSecretFree(text, canaries);
    marker = JSON.parse(text);
    if (
      !hasExactKeys(marker, COMPLETION_MARKER_KEYS) ||
      marker.schema !== COMPLETION_MARKER_SCHEMA ||
      typeof marker.jsonSha256 !== "string" ||
      !HASH_PATTERN.test(marker.jsonSha256) ||
      typeof marker.markdownSha256 !== "string" ||
      !HASH_PATTERN.test(marker.markdownSha256) ||
      `${canonicalBytes(marker).toString("utf8")}\n` !== text
    ) {
      fail();
    }
    return marker;
  } catch (error) {
    if (error instanceof BilateralVerdictError) {
      throw error;
    }
    fail();
  }
}

async function loadPartyPackages(
  fileSystem,
  payerDirectory,
  payeeDirectory,
  canaries,
) {
  const directories = [payerDirectory, payeeDirectory];
  const markers = [];
  for (const directory of directories) {
    const bytes = await readBoundedRegularFile(
      fileSystem,
      join(directory, PARTY_RESULT_FILES.marker),
      MAX_MARKER_BYTES,
    );
    markers.push(parseMarker(bytes, canaries));
  }

  const artifacts = [];
  for (let index = 0; index < directories.length; index += 1) {
    const directory = directories[index];
    const json = await readBoundedRegularFile(
      fileSystem,
      join(directory, PARTY_RESULT_FILES.json),
      MAX_JSON_BYTES,
    );
    const markdown = await readBoundedRegularFile(
      fileSystem,
      join(directory, PARTY_RESULT_FILES.markdown),
      MAX_MARKDOWN_BYTES,
    );
    if (
      sha256(json) !== markers[index].jsonSha256 ||
      sha256(markdown) !== markers[index].markdownSha256
    ) {
      fail();
    }
    artifacts.push({ json, markdown });
  }

  return artifacts.map(({ json, markdown }) => {
    try {
      const jsonText = json.toString("utf8");
      const markdownText = markdown.toString("utf8");
      assertSecretFree(jsonText, canaries);
      assertSecretFree(markdownText, canaries);
      const party = JSON.parse(jsonText);
      assertSecretFree(party, canaries);
      validatePartyResult(party);
      const canonical = JSON.parse(
        canonicalBytes(party).toString("utf8"),
      );
      if (
        `${JSON.stringify(canonical, null, 2)}\n` !== jsonText ||
        renderPartyResultMarkdown(party) !== markdownText
      ) {
        fail();
      }
      return party;
    } catch (error) {
      if (error instanceof BilateralVerdictError) {
        throw error;
      }
      fail();
    }
  });
}

function plainField(value, key) {
  if (!isPlainObject(value)) {
    fail();
  }
  return ownData(value, key);
}

function liveProposalDigest(searchResult) {
  if (!Array.isArray(searchResult)) {
    fail();
  }
  if (searchResult.length === 0) {
    fail("EXPIRED");
  }
  if (searchResult.length !== 1) {
    fail("DUPLICATE");
  }
  const digest = plainField(
    ownData(searchResult, "0"),
    "assetHash",
  );
  if (typeof digest !== "string" || !HASH_PATTERN.test(digest)) {
    fail();
  }
  return digest;
}

function triple(kind, verified) {
  return authoritativeTriple({
    anchoredHash: verified.anchoredHash,
    blockHeight: verified.blockHeight,
    kind,
    ledgerId: verified.ledgerId,
  });
}

function normalizeProtocolError(error) {
  if (error instanceof McpRateLimitedError) {
    fail("RATE_BLOCKED");
  }
  if (
    error instanceof ProtocolFailureError &&
    typeof error.terminalCode === "string"
  ) {
    fail(error.terminalCode);
  }
  if (error instanceof BilateralVerdictError) {
    throw error;
  }
  fail();
}

async function verifyLiveTransitions(clockchain, descriptor) {
  const sessionDigest = dSession(descriptor);
  let proposalDigest;
  try {
    proposalDigest = liveProposalDigest(
      await clockchain.searchActions({
        asset_reference_id: sessionKey(
          sessionDigest,
          "proposal",
        ),
      }),
    );
  } catch (error) {
    normalizeProtocolError(error);
  }

  let proposal;
  let verifiedProposal;
  let acceptance;
  let verifiedAcceptance;
  let acknowledgment;
  let verifiedAcknowledgment;
  try {
    proposal = recoverAnchoredProposal({
      anchoredHash: proposalDigest,
      descriptor,
      sessionDigest,
    });
    verifiedProposal = await verifyTransition({
      client: clockchain,
      message: proposal,
      referenceId: sessionKey(sessionDigest, "proposal"),
    });
    const proposalTriple = triple(
      "proposal",
      verifiedProposal,
    );
    acceptance = buildAcceptance({
      proposal,
      proposalTriple,
    });
    verifiedAcceptance = await verifyTransition({
      client: clockchain,
      message: acceptance,
      referenceId: sessionKey(sessionDigest, "acceptance"),
    });
    acknowledgment = buildAcknowledgment({
      acceptance,
      acceptanceTriple: triple(
        "acceptance",
        verifiedAcceptance,
      ),
      proposalTriple,
    });
    verifiedAcknowledgment = await verifyTransition({
      client: clockchain,
      message: acknowledgment,
      referenceId: sessionKey(
        sessionDigest,
        "acknowledgment",
      ),
    });
  } catch (error) {
    normalizeProtocolError(error);
  }

  return [
    { message: proposal, verified: verifiedProposal },
    { message: acceptance, verified: verifiedAcceptance },
    {
      message: acknowledgment,
      verified: verifiedAcknowledgment,
    },
  ];
}

async function auditTransitions(clockchain, sessionDigest) {
  for (const kind of [
    "proposal",
    "acceptance",
    "acknowledgment",
  ]) {
    const referenceId = sessionKey(sessionDigest, kind);
    let audit;
    try {
      audit = await clockchain.generateAuditTrail({
        asset_reference_id: referenceId,
      });
    } catch {
      fail();
    }
    if (
      plainField(audit, "count") !== "1" ||
      (
        Object.hasOwn(audit, "assetReferenceId") &&
        plainField(audit, "assetReferenceId") !== referenceId
      )
    ) {
      fail("DUPLICATE");
    }
  }
}

async function verifierUpperBound(
  clockchain,
  verified,
) {
  const nextHeight = String(BigInt(verified.blockHeight) + 1n);
  try {
    const nextBlock = await clockchain.getBlock({
      height: nextHeight,
    });
    if (plainField(nextBlock, "blockHeight") !== nextHeight) {
      fail("BINDING_MISMATCH");
    }
    const nextBlockTimeMs = parseBlockTime(
      plainField(nextBlock, "blockTime"),
    );
    if (nextBlockTimeMs <= verified.blockTimeMs) {
      fail("ANCHOR_UNVERIFIED");
    }
    return verifierUpperBoundMs(nextBlockTimeMs);
  } catch (error) {
    if (
      error instanceof BilateralVerdictError
    ) {
      throw error;
    }
    if (error instanceof McpNetworkError) {
      return liveUpperBoundMs(verified.blockTimeMs);
    }
    fail("ANCHOR_UNVERIFIED");
  }
}

function canonicalEqual(left, right) {
  try {
    return canonicalBytes({ value: left }).equals(
      canonicalBytes({ value: right }),
    );
  } catch {
    return false;
  }
}

function assertPackagesMatch(
  payer,
  payee,
  descriptor,
  sessionDigest,
  live,
) {
  for (const [party, role] of [
    [payer, "payer"],
    [payee, "payee"],
  ]) {
    const transitionCount = party.transitions.length;
    const hasRequiredPrefix =
      role === "payer"
        ? transitionCount === 3
        : transitionCount === 2 || transitionCount === 3;
    if (
      party.role !== role ||
      party.localVerdict !== "LOCAL_OK" ||
      party.paymentMoved !== false ||
      !hasRequiredPrefix ||
      party.ackObserved !== (transitionCount === 3) ||
      party.sessionDigest !== sessionDigest ||
      party.repositorySha !== descriptor.repositorySha ||
      party.promptSha256 !== descriptor.promptSha256 ||
      party.protocolVersion !== descriptor.protocolVersion
    ) {
      fail();
    }
    for (let index = 0; index < transitionCount; index += 1) {
      const entry = party.transitions[index];
      const expected = live[index];
      if (
        !canonicalEqual(entry.message, expected.message) ||
        entry.digest !== transitionDigest(expected.message) ||
        entry.onChain.anchoredHash !==
          expected.verified.anchoredHash ||
        entry.onChain.blockHeight !==
          expected.verified.blockHeight ||
        entry.onChain.ledgerId !==
          expected.verified.ledgerId ||
        entry.blockTimeRaw !==
          expected.verified.blockTimeRaw ||
        entry.blockTimeMs !==
          String(expected.verified.blockTimeMs)
      ) {
        fail("BINDING_MISMATCH");
      }
    }
  }
}

async function verifyIdentity(
  clockchain,
  ownerOf,
  descriptor,
  party,
  packageResult,
  sessionDigest,
) {
  let recovered;
  let resolved;
  let directOwner;
  try {
    recovered = await recoverMessageAddress({
      message: {
        raw: partySignatureBytes({
          role: party.role,
          sessionDigest,
          transitions: packageResult.transitions,
        }),
      },
      signature: packageResult.signature.signature,
    });
    resolved = await clockchain.resolveAgent(party.agentId);
    directOwner = await ownerOf({
      agentId: party.agentId,
      chainId: descriptor.chainId,
      registry: descriptor.registry,
    });
  } catch {
    fail();
  }
  const resolvedOwner = plainField(resolved, "owner");
  const expected = party.address.toLowerCase();
  if (
    typeof recovered !== "string" ||
    !ADDRESS_PATTERN.test(recovered) ||
    recovered.toLowerCase() !== expected ||
    packageResult.signature.address.toLowerCase() !== expected ||
    typeof resolvedOwner !== "string" ||
    !ADDRESS_PATTERN.test(resolvedOwner) ||
    resolvedOwner.toLowerCase() !== expected ||
    typeof directOwner !== "string" ||
    !ADDRESS_PATTERN.test(directOwner) ||
    directOwner.toLowerCase() !== expected
  ) {
    fail();
  }
  return expected;
}

function selectedIntentAmount(proposal) {
  if (
    proposal?.amount?.moved !== false ||
    typeof proposal.amount.currency !== "string" ||
    typeof proposal.amount.value !== "string"
  ) {
    fail();
  }
  return Object.freeze({
    currency: proposal.amount.currency,
    value: proposal.amount.value,
  });
}

function descriptorIntentAmount(descriptor, mandate) {
  const matches = descriptor.amountOptions.filter(
    (amount) =>
      amount.currency === mandate.amount.currency &&
      amount.value === mandate.amount.value,
  );
  if (matches.length !== 1) {
    fail();
  }
  return Object.freeze({
    currency: matches[0].currency,
    value: matches[0].value,
  });
}

function mandateExpectedContext(descriptor, mandateEnvelope) {
  const mandate = mandateEnvelope.mandate;
  if (
    mandate.payer.address !== descriptor.payer.address ||
    mandate.payer.agentId !== descriptor.payer.agentId ||
    mandate.payee.address !== descriptor.payee.address ||
    mandate.payee.agentId !== descriptor.payee.agentId ||
    mandate.repositorySha !== descriptor.repositorySha
  ) {
    fail();
  }
  return Object.freeze({
    amount: descriptorIntentAmount(descriptor, mandate),
    intakeDigest: mandate.intakeDigest,
    intakeRequestId: mandate.intakeRequestId,
    invoiceReferencePrefix: mandate.invoiceReferencePrefix,
    payee: Object.freeze({
      address: descriptor.payee.address,
      agentId: descriptor.payee.agentId,
    }),
    payer: Object.freeze({
      address: descriptor.payer.address,
      agentId: descriptor.payer.agentId,
    }),
    purpose: mandate.purpose,
    releaseId: mandate.releaseId,
    repositorySha: descriptor.repositorySha,
    requestEndpoint: mandate.requestEndpoint,
    sessionId: mandate.sessionId,
    subjectRun: mandate.subjectRun,
  });
}

async function verifyCommercialIntentPolicy(
  descriptor,
  mandateEnvelope,
  requestEnvelope,
) {
  const expected = mandateExpectedContext(
    descriptor,
    mandateEnvelope,
  );
  const { requestEndpoint: _requestEndpoint, ...requestExpected } =
    expected;
  const verifiedRequest = await verifyPaymentRequest({
    envelope: requestEnvelope,
    mandateEnvelope,
    expected: requestExpected,
    nowMs: Number(requestEnvelope.request.createdAtMs),
  });
  return Object.freeze({
    amount: expected.amount,
    mandateExpiresAtMs: mandateEnvelope.mandate.expiresAtMs,
    mandateIssuedAtMs: mandateEnvelope.mandate.issuedAtMs,
    requestCreatedAtMs: verifiedRequest.request.createdAtMs,
    requestExpiresAtMs: verifiedRequest.request.expiresAtMs,
  });
}

function verifyCommercialIntentAtAnchor(policy, proposal, nowMs) {
  const amount = selectedIntentAmount(proposal);
  if (
    amount.currency !== policy.amount.currency ||
    amount.value !== policy.amount.value ||
    !Number.isSafeInteger(nowMs) ||
    nowMs < 0
  ) {
    fail();
  }
  const anchorTime = BigInt(nowMs);
  if (
    anchorTime < BigInt(policy.mandateIssuedAtMs) ||
    anchorTime >= BigInt(policy.mandateExpiresAtMs) ||
    anchorTime < BigInt(policy.requestCreatedAtMs) ||
    anchorTime >= BigInt(policy.requestExpiresAtMs)
  ) {
    fail("EXPIRED");
  }
}

function createVerdict(descriptor, sessionDigest, live, bounds) {
  const transitions = live.map(
    ({ message, verified }, index) =>
      Object.freeze({
        anchoredHash: verified.anchoredHash,
        blockHeight: verified.blockHeight,
        blockTimeRaw: verified.blockTimeRaw,
        digest: transitionDigest(message),
        kind: message.kind,
        ledgerId: verified.ledgerId,
        upperBoundMs:
          index === 0 ? null : String(bounds[index]),
      }),
  );
  return Object.freeze({
    mandateDigest: descriptor.mandateDigest,
    outcome: "AUTHORIZED",
    paymentMoved: false,
    promptSha256: descriptor.promptSha256,
    protocolVersion: descriptor.protocolVersion,
    repositorySha: descriptor.repositorySha,
    requestDigest: descriptor.requestDigest,
    schema: VERDICT_SCHEMA,
    sessionDigest,
    transitions: Object.freeze(transitions),
  });
}

export async function verifyBilateralAuthorization(input) {
  try {
    const snapshot = validateInput(input);
    const descriptor = snapshot.descriptorEnvelope.descriptor;
    if (
      descriptor.mandateDigest !==
        payerMandateDigest(snapshot.mandateEnvelope) ||
      descriptor.requestDigest !==
        paymentRequestDigest(snapshot.requestEnvelope)
    ) {
      fail();
    }
    const operator = snapshot.descriptorEnvelope.operator;
    const repositoryPath = operatorPublicKeyPath(operator.keyId);
    const repositoryPublicKey =
      await snapshot.repositoryPublicKeyResolver({
        keyId: operator.keyId,
        repositoryPath,
        repositorySha: descriptor.repositorySha,
      });
    if (typeof repositoryPublicKey !== "string") {
      fail();
    }
    const verifiedEnvelope = verifyDescriptorEnvelope(
      snapshot.descriptorEnvelope,
      {
        repositoryPublicKey: repositoryPublicKey.trim(),
      },
    );
    const sessionDigest = dSession(descriptor);
    if (
      verifiedEnvelope.dSession !== sessionDigest ||
      descriptor.paymentMoved !== false
    ) {
      fail();
    }
    const commercialIntent = await verifyCommercialIntentPolicy(
      descriptor,
      snapshot.mandateEnvelope,
      snapshot.requestEnvelope,
    );

    const [payer, payee] = await loadPartyPackages(
      snapshot.fileSystem,
      snapshot.payerDirectory,
      snapshot.payeeDirectory,
      snapshot.canaries,
    );

    const live = await verifyLiveTransitions(
      snapshot.clockchain,
      descriptor,
    );
    verifyCommercialIntentAtAnchor(
      commercialIntent,
      live[0].message,
      live[0].verified.blockTimeMs,
    );
    assertPackagesMatch(
      payer,
      payee,
      descriptor,
      sessionDigest,
      live,
    );
    await auditTransitions(snapshot.clockchain, sessionDigest);

    const ledgerIds = live.map(
      ({ verified }) => verified.ledgerId,
    );
    const heights = live.map(
      ({ verified }) => BigInt(verified.blockHeight),
    );
    if (
      new Set(ledgerIds).size !== 3 ||
      !(heights[0] < heights[1] && heights[1] < heights[2])
    ) {
      fail();
    }

    const deadline = deadlineMs(live[0].verified.blockTimeMs);
    const bounds = [
      null,
      await verifierUpperBound(
        snapshot.clockchain,
        live[1].verified,
      ),
      await verifierUpperBound(
        snapshot.clockchain,
        live[2].verified,
      ),
    ];
    if (
      !isWithinDeadline(bounds[1], deadline) ||
      !isWithinDeadline(bounds[2], deadline)
    ) {
      fail("EXPIRED");
    }

    const payerOwner = await verifyIdentity(
      snapshot.clockchain,
      snapshot.ownerOf,
      descriptor,
      descriptor.payer,
      payer,
      sessionDigest,
    );
    const payeeOwner = await verifyIdentity(
      snapshot.clockchain,
      snapshot.ownerOf,
      descriptor,
      descriptor.payee,
      payee,
      sessionDigest,
    );
    if (payerOwner === payeeOwner) {
      fail();
    }
    return createVerdict(
      descriptor,
      sessionDigest,
      live,
      bounds,
    );
  } catch (error) {
    if (error instanceof BilateralVerdictError) {
      throw error;
    }
    fail();
  }
}

function validateVerdict(verdict) {
  if (
    !hasExactKeys(verdict, VERDICT_KEYS) ||
    verdict.schema !== VERDICT_SCHEMA ||
    verdict.outcome !== "AUTHORIZED" ||
    verdict.paymentMoved !== false ||
    typeof verdict.mandateDigest !== "string" ||
    !HASH_PATTERN.test(verdict.mandateDigest) ||
    typeof verdict.promptSha256 !== "string" ||
    !HASH_PATTERN.test(verdict.promptSha256) ||
    typeof verdict.repositorySha !== "string" ||
    !/^[0-9a-f]{40}$/.test(verdict.repositorySha) ||
    typeof verdict.requestDigest !== "string" ||
    !HASH_PATTERN.test(verdict.requestDigest) ||
    verdict.protocolVersion !== "1" ||
    typeof verdict.sessionDigest !== "string" ||
    !HASH_PATTERN.test(verdict.sessionDigest) ||
    !Array.isArray(verdict.transitions) ||
    verdict.transitions.length !== 3 ||
    verdict.transitions.some(
      (entry) =>
        !hasExactKeys(entry, VERDICT_TRANSITION_KEYS) ||
        entry.anchoredHash !== entry.digest ||
        typeof entry.kind !== "string" ||
        typeof entry.ledgerId !== "string" ||
        typeof entry.blockHeight !== "string" ||
        typeof entry.blockTimeRaw !== "string" ||
        (
          entry.upperBoundMs !== null &&
          typeof entry.upperBoundMs !== "string"
        ),
    )
  ) {
    fail();
  }
}

function parsePublishedVerdictMarker(bytes) {
  try {
    const text = bytes.toString("utf8");
    const marker = JSON.parse(text);
    if (
      !hasExactKeys(marker, VERDICT_COMPLETION_MARKER_KEYS) ||
      marker.schema !== VERDICT_COMPLETION_MARKER_SCHEMA ||
      typeof marker.jsonSha256 !== "string" ||
      !HASH_PATTERN.test(marker.jsonSha256) ||
      typeof marker.markdownSha256 !== "string" ||
      !HASH_PATTERN.test(marker.markdownSha256) ||
      `${canonicalBytes(marker).toString("utf8")}\n` !== text
    ) {
      fail();
    }
    return marker;
  } catch (error) {
    if (error instanceof BilateralVerdictError) {
      throw error;
    }
    fail();
  }
}

function exactPublishedVerdictInput(input) {
  if (!hasExactKeys(input, VERDICT_PUBLICATION_INPUT_KEYS)) {
    fail();
  }
  const outputDirectory = ownData(input, "outputDirectory");
  const mandateDigest = ownData(input, "mandateDigest");
  const repositorySha = ownData(input, "repositorySha");
  const requestDigest = ownData(input, "requestDigest");
  const sessionDigest = ownData(input, "sessionDigest");
  if (
    typeof outputDirectory !== "string" ||
    outputDirectory.length === 0 ||
    typeof mandateDigest !== "string" ||
    !HASH_PATTERN.test(mandateDigest) ||
    typeof repositorySha !== "string" ||
    !/^[0-9a-f]{40}$/.test(repositorySha) ||
    typeof requestDigest !== "string" ||
    !HASH_PATTERN.test(requestDigest) ||
    typeof sessionDigest !== "string" ||
    !HASH_PATTERN.test(sessionDigest)
  ) {
    fail();
  }
  return {
    mandateDigest,
    outputDirectory,
    repositorySha,
    requestDigest,
    sessionDigest,
  };
}

export async function validatePublishedBilateralVerdict(input) {
  let directoryHandle;
  try {
    const expected = exactPublishedVerdictInput(input);
    const directory = await openPinnedPublicationDirectory(
      DEFAULT_FILE_SYSTEM,
      expected.outputDirectory,
    );
    directoryHandle = directory.handle;
    const marker = await readBoundedRegularFile(
      DEFAULT_FILE_SYSTEM,
      join(expected.outputDirectory, VERDICT_PUBLICATION_FILES.marker),
      MAX_MARKER_BYTES,
      isPrivatePublicationFile,
    );
    const json = await readBoundedRegularFile(
      DEFAULT_FILE_SYSTEM,
      join(expected.outputDirectory, VERDICT_PUBLICATION_FILES.json),
      MAX_JSON_BYTES,
      isPrivatePublicationFile,
    );
    const markdown = await readBoundedRegularFile(
      DEFAULT_FILE_SYSTEM,
      join(expected.outputDirectory, VERDICT_PUBLICATION_FILES.markdown),
      MAX_MARKDOWN_BYTES,
      isPrivatePublicationFile,
    );
    const completion = parsePublishedVerdictMarker(marker);
    if (
      sha256(json) !== completion.jsonSha256 ||
      sha256(markdown) !== completion.markdownSha256
    ) {
      fail();
    }
    const verdictText = json.toString("utf8");
    const markdownText = markdown.toString("utf8");
    assertSecretFree(verdictText);
    assertSecretFree(markdownText);
    const verdict = JSON.parse(verdictText);
    validateVerdict(verdict);
    if (
      !publisherVerdictBytes(verdict).equals(json) ||
      verdict.mandateDigest !== expected.mandateDigest ||
      verdict.repositorySha !== expected.repositorySha ||
      verdict.requestDigest !== expected.requestDigest ||
      verdict.sessionDigest !== expected.sessionDigest ||
      verdict.paymentMoved !== false ||
      renderBilateralVerdictMarkdown(verdict) !== markdownText
    ) {
      fail();
    }
    await assertPinnedPublicationDirectory(
      DEFAULT_FILE_SYSTEM,
      expected.outputDirectory,
      directoryHandle,
      directory.metadata,
    );
    await directoryHandle.close();
    directoryHandle = undefined;
    return Object.freeze({
      publicationDigest: publishedVerdictDigest(json, markdown, marker),
      status: "VERIFICATION_PASSED",
    });
  } catch (error) {
    if (error instanceof BilateralVerdictError) {
      throw error;
    }
    fail();
  } finally {
    if (directoryHandle !== undefined) {
      try {
        await directoryHandle.close();
      } catch {
        fail();
      }
    }
  }
}

export function renderBilateralVerdictMarkdown(verdict) {
  validateVerdict(verdict);
  return [
    "# Bilateral Payment Authorization Verdict",
    "",
    `- Outcome: \`${verdict.outcome}\``,
    "- Payment moved: no",
    `- Payer mandate digest: \`${verdict.mandateDigest}\``,
    `- Payment request digest: \`${verdict.requestDigest}\``,
    `- Session digest: \`${verdict.sessionDigest}\``,
    `- Repository SHA: \`${verdict.repositorySha}\``,
    `- Prompt SHA-256: \`${verdict.promptSha256}\``,
    "",
    "```json",
    JSON.stringify(verdict, null, 2),
    "```",
    "",
  ].join("\n");
}
