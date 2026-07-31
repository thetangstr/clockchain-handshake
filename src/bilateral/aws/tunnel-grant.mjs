import { types } from "node:util";

import {
  payerBootstrapClaimFingerprint,
  sshEd25519Fingerprint,
  validatePayerBootstrapClaim,
} from "../local-mcp/payer-bootstrap-envelope.mjs";

export const PAYER_CLAIM_APPROVAL_SCHEMA =
  "clockchain.payer-claim-approval/v1";
export const PAYER_TUNNEL_GRANT_SCHEMA =
  "clockchain.payer-tunnel-grant/v1";
export const PAYER_TUNNEL_TOMBSTONE_SCHEMA =
  "clockchain.payer-tunnel-tombstone/v1";

const APPROVED_KEYS = Object.freeze([
  "approvedAtMs",
  "claim",
  "claimFingerprint",
  "paymentMoved",
  "publicMcpHostname",
  "publicMcpPort",
  "schema",
  "status",
  "tunnelPort",
]);
const ACTIVE_KEYS = Object.freeze([
  "claim",
  "claimFingerprint",
  "connectionSequence",
  "connectionStatus",
  "createdAtMs",
  "expiresAtMs",
  "lastConnectionAtMs",
  "paymentMoved",
  "publicMcpHostname",
  "publicMcpPort",
  "schema",
  "status",
  "tunnelPort",
]);
const TOMBSTONE_KEYS = Object.freeze([
  "claimFingerprint",
  "expiresAtMs",
  "paymentMoved",
  "publicMcpHostname",
  "publicMcpPort",
  "releaseId",
  "repositorySha",
  "schema",
  "sessionId",
  "status",
  "terminalAtMs",
  "terminalReason",
  "tunnelPort",
]);
const CONSUME_INPUT_KEYS = Object.freeze([
  "claim",
  "consumeClaimFingerprint",
  "expectedClaimFingerprint",
  "expectedReleaseId",
  "expectedRepositorySha",
  "expectedSessionId",
  "nowMs",
  "publicMcpHostname",
  "publicMcpPort",
  "tunnelPort",
]);
const CREATE_INPUT_KEYS = Object.freeze([
  "approved",
  "expiresAtMs",
]);
const CONNECTION_INPUT_KEYS = Object.freeze([
  "activeGrant",
  "connectionFingerprint",
  "nowMs",
]);
const TOMBSTONE_INPUT_KEYS = Object.freeze([
  "activeGrant",
  "nowMs",
  "reason",
]);
const RENDER_INPUT_KEYS = Object.freeze([
  "sshPublicKey",
]);
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const HOSTNAME_PATTERN =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const FINGERPRINT_PATTERN =
  /^SHA256:[A-Za-z0-9+/]{43}$/;
const TERMINAL_REASONS = new Set([
  "SUCCESS",
  "FAILURE",
  "ABORT",
  "EXPIRED",
]);

export class TunnelGrantError extends Error {
  constructor() {
    super("Tunnel grant validation failed safely.");
    this.name = "TunnelGrantError";
    this.code = "TUNNEL_GRANT_INVALID";
    this.category = "verification";
  }
}

function invalid() {
  throw new TunnelGrantError();
}

function sanitize(error) {
  if (error instanceof TunnelGrantError) throw error;
  invalid();
}

function exactObject(value, keys) {
  try {
    if (
      value === null ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      types.isProxy(value) ||
      ![Object.prototype, null].includes(
        Object.getPrototypeOf(value),
      )
    ) {
      invalid();
    }
    const ownKeys = Reflect.ownKeys(value);
    if (
      ownKeys.length !== keys.length ||
      keys.some((key, index) => ownKeys[index] !== key)
    ) {
      invalid();
    }
    const result = Object.create(null);
    for (const key of keys) {
      const descriptor =
        Object.getOwnPropertyDescriptor(value, key);
      if (
        descriptor?.enumerable !== true ||
        !Object.hasOwn(descriptor, "value")
      ) {
        invalid();
      }
      result[key] = descriptor.value;
    }
    return result;
  } catch (error) {
    sanitize(error);
  }
}

function now(value) {
  if (
    !Number.isSafeInteger(value) ||
    value < 0
  ) {
    invalid();
  }
  return value;
}

function timestamp(value) {
  if (
    typeof value !== "string" ||
    !/^(?:0|[1-9][0-9]*)$/.test(value) ||
    BigInt(value) > BigInt(Number.MAX_SAFE_INTEGER)
  ) {
    invalid();
  }
  return value;
}

function counter(value) {
  timestamp(value);
  return value;
}

function hostname(value) {
  if (
    typeof value !== "string" ||
    !HOSTNAME_PATTERN.test(value)
  ) {
    invalid();
  }
  return value;
}

function claimSnapshot(value) {
  try {
    return validatePayerBootstrapClaim(value);
  } catch {
    invalid();
  }
}

function approvedSnapshot(value) {
  const approved = exactObject(value, APPROVED_KEYS);
  const claim = claimSnapshot(approved.claim);
  timestamp(approved.approvedAtMs);
  if (
    approved.claimFingerprint !==
      payerBootstrapClaimFingerprint(claim) ||
    approved.paymentMoved !== false ||
    approved.publicMcpPort !== 9443 ||
    approved.schema !== PAYER_CLAIM_APPROVAL_SCHEMA ||
    approved.status !== "APPROVED" ||
    approved.tunnelPort !== 443
  ) {
    invalid();
  }
  hostname(approved.publicMcpHostname);
  return Object.freeze({
    ...approved,
    claim,
  });
}

function activeSnapshot(value) {
  const grant = exactObject(value, ACTIVE_KEYS);
  const claim = claimSnapshot(grant.claim);
  timestamp(grant.createdAtMs);
  timestamp(grant.expiresAtMs);
  counter(grant.connectionSequence);
  if (grant.lastConnectionAtMs !== null) {
    timestamp(grant.lastConnectionAtMs);
  }
  if (
    grant.claimFingerprint !==
      payerBootstrapClaimFingerprint(claim) ||
    !["IDLE", "CONNECTED"].includes(
      grant.connectionStatus,
    ) ||
    grant.paymentMoved !== false ||
    grant.publicMcpPort !== 9443 ||
    grant.schema !== PAYER_TUNNEL_GRANT_SCHEMA ||
    grant.status !== "ACTIVE" ||
    grant.tunnelPort !== 443 ||
    Number(grant.expiresAtMs) <=
      Number(grant.createdAtMs)
  ) {
    invalid();
  }
  hostname(grant.publicMcpHostname);
  if (
    grant.connectionStatus === "IDLE" &&
    grant.connectionSequence === "0" &&
    grant.lastConnectionAtMs !== null
  ) {
    invalid();
  }
  if (
    grant.connectionStatus === "CONNECTED" &&
    grant.lastConnectionAtMs === null
  ) {
    invalid();
  }
  return Object.freeze({
    ...grant,
    claim,
  });
}

function connectionFingerprint(value) {
  if (
    typeof value !== "string" ||
    !FINGERPRINT_PATTERN.test(value)
  ) {
    invalid();
  }
  return value;
}

export function consumePayerClaim(input) {
  try {
    const data = exactObject(
      input,
      CONSUME_INPUT_KEYS,
    );
    const claim = claimSnapshot(data.claim);
    const claimFingerprint =
      payerBootstrapClaimFingerprint(claim);
    now(data.nowMs);
    hostname(data.publicMcpHostname);
    if (
      !SHA256_PATTERN.test(
        data.expectedClaimFingerprint,
      ) ||
      claimFingerprint !==
        data.expectedClaimFingerprint ||
      claim.releaseId !== data.expectedReleaseId ||
      claim.repositorySha !==
        data.expectedRepositorySha ||
      claim.sessionId !== data.expectedSessionId ||
      data.publicMcpPort !== 9443 ||
      data.tunnelPort !== 443 ||
      typeof data.consumeClaimFingerprint !==
        "function"
    ) {
      invalid();
    }
    if (
      data.consumeClaimFingerprint(
        claimFingerprint,
      ) !== true
    ) {
      invalid();
    }
    return Object.freeze({
      approvedAtMs: String(data.nowMs),
      claim,
      claimFingerprint,
      paymentMoved: false,
      publicMcpHostname: data.publicMcpHostname,
      publicMcpPort: 9443,
      schema: PAYER_CLAIM_APPROVAL_SCHEMA,
      status: "APPROVED",
      tunnelPort: 443,
    });
  } catch (error) {
    sanitize(error);
  }
}

export function createTunnelGrant(input) {
  try {
    const data = exactObject(
      input,
      CREATE_INPUT_KEYS,
    );
    const approved = approvedSnapshot(data.approved);
    timestamp(data.expiresAtMs);
    if (
      Number(data.expiresAtMs) <=
      Number(approved.approvedAtMs)
    ) {
      invalid();
    }
    return Object.freeze({
      claim: approved.claim,
      claimFingerprint: approved.claimFingerprint,
      connectionSequence: "0",
      connectionStatus: "IDLE",
      createdAtMs: approved.approvedAtMs,
      expiresAtMs: data.expiresAtMs,
      lastConnectionAtMs: null,
      paymentMoved: false,
      publicMcpHostname:
        approved.publicMcpHostname,
      publicMcpPort: 9443,
      schema: PAYER_TUNNEL_GRANT_SCHEMA,
      status: "ACTIVE",
      tunnelPort: 443,
    });
  } catch (error) {
    sanitize(error);
  }
}

export function authorizeTunnelConnection(input) {
  try {
    const data = exactObject(
      input,
      CONNECTION_INPUT_KEYS,
    );
    const grant = activeSnapshot(data.activeGrant);
    now(data.nowMs);
    connectionFingerprint(
      data.connectionFingerprint,
    );
    if (
      data.nowMs >= Number(grant.expiresAtMs) ||
      grant.connectionStatus !== "IDLE" ||
      Number(grant.connectionSequence) >=
        Number.MAX_SAFE_INTEGER ||
      data.connectionFingerprint !==
        grant.claim.sshPublicKeyFingerprint
    ) {
      invalid();
    }
    return Object.freeze({
      ...grant,
      connectionSequence: String(
        Number(grant.connectionSequence) + 1,
      ),
      connectionStatus: "CONNECTED",
      lastConnectionAtMs: String(data.nowMs),
    });
  } catch (error) {
    sanitize(error);
  }
}

export function disconnectTunnelConnection(input) {
  try {
    const data = exactObject(
      input,
      CONNECTION_INPUT_KEYS,
    );
    const grant = activeSnapshot(data.activeGrant);
    now(data.nowMs);
    connectionFingerprint(
      data.connectionFingerprint,
    );
    if (
      data.nowMs >= Number(grant.expiresAtMs) ||
      grant.connectionStatus !== "CONNECTED" ||
      data.connectionFingerprint !==
        grant.claim.sshPublicKeyFingerprint ||
      data.nowMs <
        Number(grant.lastConnectionAtMs)
    ) {
      invalid();
    }
    return Object.freeze({
      ...grant,
      connectionStatus: "IDLE",
    });
  } catch (error) {
    sanitize(error);
  }
}

export function tombstoneTunnelGrant(input) {
  try {
    const data = exactObject(
      input,
      TOMBSTONE_INPUT_KEYS,
    );
    const grant = activeSnapshot(data.activeGrant);
    now(data.nowMs);
    if (!TERMINAL_REASONS.has(data.reason)) {
      invalid();
    }
    const expired =
      data.nowMs >= Number(grant.expiresAtMs);
    if (
      (data.reason === "EXPIRED") !== expired ||
      data.nowMs < Number(grant.createdAtMs)
    ) {
      invalid();
    }
    return Object.freeze({
      claimFingerprint: grant.claimFingerprint,
      expiresAtMs: grant.expiresAtMs,
      paymentMoved: false,
      publicMcpHostname: grant.publicMcpHostname,
      publicMcpPort: 9443,
      releaseId: grant.claim.releaseId,
      repositorySha: grant.claim.repositorySha,
      schema: PAYER_TUNNEL_TOMBSTONE_SCHEMA,
      sessionId: grant.claim.sessionId,
      status: "TOMBSTONED",
      terminalAtMs: String(data.nowMs),
      terminalReason: data.reason,
      tunnelPort: 443,
    });
  } catch (error) {
    sanitize(error);
  }
}

export function renderRestrictedAuthorizedKey(input) {
  try {
    const data = exactObject(
      input,
      RENDER_INPUT_KEYS,
    );
    sshEd25519Fingerprint(data.sshPublicKey);
    const parts = data.sshPublicKey.split(" ");
    if (parts.length !== 2) invalid();
    return (
      "restrict,port-forwarding," +
      "permitlisten=\"0.0.0.0:9443\" " +
      `ssh-ed25519 ${parts[1]} clockchain-payer`
    );
  } catch (error) {
    sanitize(error);
  }
}
