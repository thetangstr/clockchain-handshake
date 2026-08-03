import { McpRateLimitedError } from "../../src/core/clockchain.mjs";

const BASE_HEIGHT = 3375600;
const BASE_TIME_MS = 1784923200000;
const DEFAULT_PROPOSER =
  "0x1111111111111111111111111111111111111111";

function cloneWithDescriptors(value, seen = new Map()) {
  if (value === null || typeof value !== "object") {
    return value;
  }
  if (seen.has(value)) {
    return seen.get(value);
  }
  const clone = Array.isArray(value)
    ? []
    : Object.create(Object.getPrototypeOf(value));
  seen.set(value, clone);
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (Object.hasOwn(descriptor, "value")) {
      descriptor.value = cloneWithDescriptors(descriptor.value, seen);
    }
    Object.defineProperty(clone, key, descriptor);
  }
  return clone;
}

function cloned(value) {
  return cloneWithDescriptors(value);
}

function mutateDetached(value, hook) {
  const detached = cloned(value);
  const result = hook === undefined ? detached : hook(detached);
  return cloned(result === undefined ? detached : result);
}

function exactKeys(value, expected) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype &&
    Object.keys(value).length === expected.length &&
    expected.every((key) => Object.hasOwn(value, key))
  );
}

function ledgerIdFor(index) {
  return `00000000-0000-4000-8000-${index
    .toString(16)
    .padStart(12, "0")}`;
}

function blockTimeFor(index) {
  const milliseconds = BASE_TIME_MS + index * 1100;
  return new Date(milliseconds)
    .toISOString()
    .replace(/\.(\d{3})Z$/, ".$1123456Z");
}

export class FakeClockchainError extends Error {
  constructor(message, code = "FAKE_CLOCKCHAIN") {
    super(message);
    this.name = "FakeClockchainError";
    this.code = code;
  }
}

export function createFakeBilateralClockchain(options = {}) {
  const baseHeight = options.baseHeight ?? BASE_HEIGHT;
  if (
    !Number.isSafeInteger(baseHeight) ||
    baseHeight < 0 ||
    baseHeight >= Number.MAX_SAFE_INTEGER
  ) {
    throw new FakeClockchainError(
      "The deterministic base height is invalid.",
      "FAKE_HEIGHT_INVALID",
    );
  }
  if (
    options.auditCount !== undefined &&
    (
      !Number.isSafeInteger(options.auditCount) ||
      options.auditCount < 0
    )
  ) {
    throw new FakeClockchainError(
      "The deterministic audit count is invalid.",
      "FAKE_AUDIT_INVALID",
    );
  }
  const records = [];
  const agents = new Map();
  const blocks = new Map();
  const observedCalls = {
    generateAuditTrail: [],
    getBlock: [],
    logAction: [],
    resolveAgent: [],
    searchActions: [],
    verifyCrossParty: [],
  };
  const observedSequence = [];
  let writeCount = 0;

  function recordCall(name, args) {
    const detachedArgs = cloned(args);
    observedCalls[name].push(detachedArgs);
    observedSequence.push({ args: cloned(detachedArgs), name });
  }

  function maybeThrowWrite(stage) {
    if (options.refuseWrite === true && stage === "before-storage") {
      throw new FakeClockchainError(
        "The deterministic write was refused.",
        "FAKE_WRITE_REFUSED",
      );
    }
    if (options.ambiguousWrite === stage) {
      throw new FakeClockchainError(
        "The deterministic write outcome is ambiguous.",
        "FAKE_AMBIGUOUS_WRITE",
      );
    }
  }

  const fake = {
    get calls() {
      return cloned(observedCalls);
    },
    get callSequence() {
      return cloned(observedSequence);
    },

    registerAgent(agent) {
      if (
        !exactKeys(agent, ["agentId", "owner", "status"]) ||
        typeof agent.agentId !== "string"
      ) {
        throw new FakeClockchainError(
          "The deterministic agent fixture is invalid.",
          "FAKE_AGENT_INVALID",
        );
      }
      agents.set(agent.agentId, cloned(agent));
    },

    async logAction(args) {
      recordCall("logAction", args);
      maybeThrowWrite("before-storage");
      if (
        args === null ||
        typeof args !== "object" ||
        Array.isArray(args) ||
        typeof args.asset_reference_id !== "string" ||
        typeof args.asset_hash !== "string" ||
        args.hash_type !== "SHA-256"
      ) {
        throw new FakeClockchainError(
          "The deterministic write arguments are invalid.",
          "FAKE_WRITE_INVALID",
        );
      }
      writeCount += 1;
      const ledgerId = ledgerIdFor(writeCount);
      const blockHeight = String(baseHeight + writeCount);
      const blockTime = blockTimeFor(writeCount);
      records.push({
        assetHash: args.asset_hash,
        assetReferenceId: args.asset_reference_id,
        blockHeight,
        hashType: args.hash_type,
        ledgerId,
      });
      blocks.set(blockHeight, {
        blockHeight,
        blockTime,
        proposerAddress: options.proposerAddress ?? DEFAULT_PROPOSER,
      });
      maybeThrowWrite("after-storage");
      return { blockHeight, ledgerId };
    },

    async searchActions(args) {
      recordCall("searchActions", args);
      if (!exactKeys(args, ["asset_reference_id"])) {
        throw new FakeClockchainError(
          "The deterministic search arguments are invalid.",
          "FAKE_SEARCH_INVALID",
        );
      }
      if (options.rateLimitSearch === true) {
        throw new McpRateLimitedError(
          "The deterministic search was rate limited.",
          { retryAfterMs: 20000 },
        );
      }
      if (options.rateLimitBody === true) {
        return { error: "rate_limited", retry_after_seconds: 20 };
      }
      if (options.nonArraySearch === true) {
        return { records: [] };
      }
      let matches = options.missingRecords === true
        ? []
        : records.filter(
            (record) =>
              record.assetReferenceId === args.asset_reference_id,
          );
      if (options.duplicateSearch === true && matches.length === 1) {
        matches = [matches[0], matches[0]];
      }
      return mutateDetached(matches, options.mutateSearch);
    },

    async verifyCrossParty(args) {
      recordCall("verifyCrossParty", args);
      if (
        args === null ||
        typeof args !== "object" ||
        Array.isArray(args)
      ) {
        throw new FakeClockchainError(
          "The deterministic cross-party arguments are invalid.",
          "FAKE_CROSS_PARTY_INVALID",
        );
      }
      const record = records.find(
        (candidate) => candidate.ledgerId === args.ledgerId,
      );
      const onChain =
        record === undefined ||
        record.blockHeight !== String(args.blockHeight)
          ? {
              assetReferenceId: record?.assetReferenceId ?? null,
              anchoredHash: record?.assetHash ?? null,
              blockHeight: String(args.blockHeight),
              keyless: false,
              ledgerId: args.ledgerId,
              verifiedAgainst: "none",
            }
          : {
              assetReferenceId: record.assetReferenceId,
              anchoredHash: record.assetHash,
              blockHeight: record.blockHeight,
              keyless: true,
              ledgerId: record.ledgerId,
              verifiedAgainst: "on-chain block",
            };
      return mutateDetached({ onChain }, options.mutateCrossParty);
    },

    async getBlock(args) {
      recordCall("getBlock", args);
      if (!exactKeys(args, ["height"])) {
        throw new FakeClockchainError(
          "The deterministic block arguments are invalid.",
          "FAKE_BLOCK_INVALID",
        );
      }
      const height = String(args.height);
      if (options.missingBlocks === true || !blocks.has(height)) {
        throw new FakeClockchainError(
          "The deterministic block is unavailable.",
          "FAKE_BLOCK_UNAVAILABLE",
        );
      }
      return mutateDetached(blocks.get(height), options.mutateBlock);
    },

    async resolveAgent(agentId) {
      recordCall("resolveAgent", agentId);
      const agent = agents.get(String(agentId));
      if (agent === undefined) {
        return { agentId: String(agentId), status: "unknown" };
      }
      const resolved = cloned(agent);
      if (options.inactiveIdentity === true) {
        resolved.status = "inactive";
      }
      if (typeof options.mismatchedIdentityOwner === "string") {
        resolved.owner = options.mismatchedIdentityOwner;
      }
      return resolved;
    },

    async generateAuditTrail(args) {
      recordCall("generateAuditTrail", args);
      if (!exactKeys(args, ["asset_reference_id"])) {
        throw new FakeClockchainError(
          "The deterministic audit arguments are invalid.",
          "FAKE_AUDIT_INVALID",
        );
      }
      const count =
        options.auditCount ??
        records.filter(
          (record) =>
            record.assetReferenceId === args.asset_reference_id,
        ).length;
      return {
        assetReferenceId: args.asset_reference_id,
        count: String(count),
      };
    },

    verifyPackage() {
      throw new FakeClockchainError("verifyPackage must not be called.");
    },
    verifyAsset() {
      throw new FakeClockchainError("verifyAsset must not be called.");
    },
    buildEvidencePackage() {
      throw new FakeClockchainError(
        "buildEvidencePackage must not be called.",
      );
    },
    getValidation() {
      throw new FakeClockchainError("getValidation must not be called.");
    },
    getTime() {
      throw new FakeClockchainError("getTime must not be called.");
    },
    getTimestamp() {
      throw new FakeClockchainError("getTimestamp must not be called.");
    },
    getLogEntry() {
      throw new FakeClockchainError("getLogEntry must not be called.");
    },
  };

  return fake;
}
