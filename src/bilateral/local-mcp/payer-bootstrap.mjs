import {
  createHash,
  X509Certificate,
} from "node:crypto";
import { resolve } from "node:path";
import { types } from "node:util";

import {
  payerBootstrapClaimFingerprint,
  sshEd25519Fingerprint,
  validatePayerBootstrapClaim,
} from "./payer-bootstrap-envelope.mjs";

const INPUT_KEYS = Object.freeze([
  "discoveryUrl",
  "stateRoot",
]);
const REQUIRED_DEPENDENCIES = Object.freeze([
  "createMcpTlsIdentity",
  "createSshIdentity",
  "createX25519Key",
  "inspectPrerequisites",
  "pollApprovedPackage",
  "preparePrivateState",
  "randomUUID",
  "startPayerSupervisor",
  "startRestrictedTunnel",
  "submitPayerClaim",
  "verifyAndOpenPackage",
  "verifyCleanDetachedRelease",
  "verifySignedDiscovery",
  "waitForTerminalLocalStatus",
  "writePrivateLaunchMaterial",
  "writeStatus",
  "zeroizeBootstrapSecrets",
]);
const OPTIONAL_DEPENDENCIES = Object.freeze([
  "installSignalHandlers",
  "revokeTunnelGrant",
  "stopPayerSupervisor",
  "stopRestrictedTunnel",
]);
const SHA40_PATTERN = /^[0-9a-f]{40}$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const UUID_V4_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PUBLIC_ROLE_STATUSES = new Set([
  "PAYER_MCP_READY",
  "PROPOSED",
  "ACKNOWLEDGED",
]);

export class PayerBootstrapError extends Error {
  constructor() {
    super("Payer bootstrap failed safely.");
    this.name = "PayerBootstrapError";
    this.code = "PAYER_BOOTSTRAP_FAILED";
    this.category = "verification";
  }
}

function invalid() {
  throw new PayerBootstrapError();
}

function sanitize(error) {
  if (error instanceof PayerBootstrapError) throw error;
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
      keys.some((key) => !ownKeys.includes(key))
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

function dependenciesSnapshot(value) {
  try {
    if (
      value === null ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      types.isProxy(value) ||
      Object.getPrototypeOf(value) !== Object.prototype
    ) {
      invalid();
    }
    const allowed = new Set([
      ...REQUIRED_DEPENDENCIES,
      ...OPTIONAL_DEPENDENCIES,
    ]);
    const keys = Reflect.ownKeys(value);
    if (
      keys.some((key) =>
        typeof key !== "string" || !allowed.has(key)) ||
      REQUIRED_DEPENDENCIES.some((key) =>
        !keys.includes(key))
    ) {
      invalid();
    }
    const result = Object.create(null);
    for (const key of keys) {
      const descriptor =
        Object.getOwnPropertyDescriptor(value, key);
      if (
        descriptor?.enumerable !== true ||
        !Object.hasOwn(descriptor, "value") ||
        typeof descriptor.value !== "function" ||
        types.isProxy(descriptor.value)
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

function httpsUrl(value) {
  if (typeof value !== "string") invalid();
  let url;
  try {
    url = new URL(value);
  } catch {
    invalid();
  }
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== ""
  ) {
    invalid();
  }
  return url.href;
}

function stateRoot(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    resolve(value) !== value ||
    value === "/"
  ) {
    invalid();
  }
  return value;
}

function releaseProof(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    value.clean !== true ||
    value.detached !== true ||
    !SHA40_PATTERN.test(value.repositorySha)
  ) {
    invalid();
  }
  return value.repositorySha;
}

function discoverySnapshot(value, repositorySha) {
  if (
    value === null ||
    typeof value !== "object" ||
    value.paymentMoved !== false ||
    value.repositorySha !== repositorySha ||
    value.schema !==
      "clockchain.payer-bootstrap-discovery/v1" ||
    value.publicMcpPort !== 9443 ||
    value.tunnelPort !== 443 ||
    typeof value.releaseId !== "string" ||
    value.releaseId.length === 0 ||
    typeof value.sessionId !== "string" ||
    typeof value.payerClaimUrl !== "string" ||
    typeof value.publicMcpHostname !== "string" ||
    typeof value.tunnelHost !== "string"
  ) {
    invalid();
  }
  httpsUrl(value.payerClaimUrl);
  sshEd25519Fingerprint(value.tunnelHostPublicKey);
  if (
    sshEd25519Fingerprint(
      value.tunnelHostPublicKey,
    ) !== value.tunnelHostKeyFingerprint
  ) {
    invalid();
  }
  return Object.freeze({ ...value });
}

function x25519Snapshot(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    typeof value.publicKey !== "string" ||
    value.privateKey === undefined
  ) {
    invalid();
  }
  return value;
}

function sshSnapshot(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    typeof value.privateKeyPath !== "string" ||
    resolve(value.privateKeyPath) !==
      value.privateKeyPath ||
    sshEd25519Fingerprint(value.publicKey) !==
      value.fingerprint
  ) {
    invalid();
  }
  return value;
}

function tlsSnapshot(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    typeof value.certificatePem !== "string" ||
    typeof value.privateKeyPath !== "string" ||
    resolve(value.privateKeyPath) !==
      value.privateKeyPath
  ) {
    invalid();
  }
  let fingerprint;
  try {
    fingerprint = createHash("sha256")
      .update(
        new X509Certificate(
          value.certificatePem,
        ).raw,
      )
      .digest("hex");
  } catch {
    invalid();
  }
  if (fingerprint !== value.fingerprint) invalid();
  return value;
}

function submissionSnapshot(value, claim) {
  if (
    value === null ||
    typeof value !== "object" ||
    value.claimFingerprint !==
      payerBootstrapClaimFingerprint(claim) ||
    !SHA256_PATTERN.test(value.claimFingerprint) ||
    typeof value.pollCapability !== "string" ||
    value.pollCapability.length === 0 ||
    value.pollCapability.length > 1024
  ) {
    invalid();
  }
  return value;
}

function openedPackageSnapshot(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    value.paymentMoved !== false ||
    typeof value.bootstrapBrokerCapability !==
      "string" ||
    value.bootstrapBrokerCapability.length === 0 ||
    typeof value.bootstrapBrokerUrl !== "string" ||
    !Buffer.isBuffer(value.launchManifestBytes) ||
    !Buffer.isBuffer(value.tunnelGrantBytes)
  ) {
    invalid();
  }
  httpsUrl(value.bootstrapBrokerUrl);
  try {
    JSON.parse(
      value.launchManifestBytes.toString("utf8"),
    );
  } catch {
    invalid();
  }
  let tunnelGrant;
  try {
    tunnelGrant = JSON.parse(
      value.tunnelGrantBytes.toString("utf8"),
    );
  } catch {
    invalid();
  }
  if (tunnelGrant?.paymentMoved !== false) invalid();
  return value;
}

function publicStatus(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    value.paymentMoved !== false ||
    !PUBLIC_ROLE_STATUSES.has(value.status)
  ) {
    invalid();
  }
  return Object.freeze({
    paymentMoved: false,
    status: value.status,
  });
}

async function stopSafely(callback, handle) {
  if (
    handle !== null &&
    typeof callback === "function"
  ) {
    try {
      await callback(handle);
    } catch {
      // Cleanup errors cannot replace the fixed verdict.
    }
  }
}

export async function runPayerBootstrap(
  input,
  dependencyInput,
) {
  let dependencies;
  let x25519 = null;
  let ssh = null;
  let tls = null;
  let submission = null;
  let opened = null;
  let tunnel = null;
  let supervisor = null;
  let result;
  let aborted = false;
  let removeSignalHandlers = null;
  try {
    const data = exactObject(input, INPUT_KEYS);
    dependencies =
      dependenciesSnapshot(dependencyInput);
    const discoveryUrl = httpsUrl(
      data.discoveryUrl,
    );
    const root = stateRoot(data.stateRoot);
    if (
      typeof dependencies.installSignalHandlers ===
      "function"
    ) {
      removeSignalHandlers =
        dependencies.installSignalHandlers(() => {
          aborted = true;
        });
      if (
        typeof removeSignalHandlers !== "function"
      ) {
        invalid();
      }
    }
    const assertActive = () => {
      if (aborted) invalid();
    };

    const prerequisites =
      await dependencies.inspectPrerequisites({
        role: "payer",
      });
    assertActive();
    const repositorySha = releaseProof(
      await dependencies.verifyCleanDetachedRelease({
        prerequisites,
      }),
    );
    assertActive();
    const discovery = discoverySnapshot(
      await dependencies.verifySignedDiscovery({
        discoveryUrl,
        prerequisites,
        repositorySha,
      }),
      repositorySha,
    );
    assertActive();
    const privateState =
      await dependencies.preparePrivateState({
        stateRoot: root,
      });
    assertActive();
    if (
      privateState?.stateRoot !== root
    ) {
      invalid();
    }
    x25519 = x25519Snapshot(
      await dependencies.createX25519Key({
        privateState,
      }),
    );
    assertActive();
    ssh = sshSnapshot(
      await dependencies.createSshIdentity({
        privateState,
      }),
    );
    assertActive();
    tls = tlsSnapshot(
      await dependencies.createMcpTlsIdentity({
        hostname: discovery.publicMcpHostname,
        privateState,
      }),
    );
    assertActive();
    const claimNonce = dependencies.randomUUID();
    if (!UUID_V4_PATTERN.test(claimNonce)) invalid();
    const claim = validatePayerBootstrapClaim({
      claimNonce,
      mcpTlsCertificatePem: tls.certificatePem,
      mcpTlsFingerprint: tls.fingerprint,
      paymentMoved: false,
      releaseId: discovery.releaseId,
      repositorySha,
      role: "payer",
      schema: "clockchain.payer-bootstrap-claim/v1",
      sessionId: discovery.sessionId,
      sshPublicKey: ssh.publicKey,
      sshPublicKeyFingerprint: ssh.fingerprint,
      x25519PublicKey: x25519.publicKey,
    });
    submission = submissionSnapshot(
      await dependencies.submitPayerClaim({
        claim,
        payerClaimUrl: discovery.payerClaimUrl,
      }),
      claim,
    );
    assertActive();
    dependencies.writeStatus({
      claimFingerprint: submission.claimFingerprint,
      paymentMoved: false,
      status: "PAYER_CLAIM_PENDING",
    });
    const approved =
      await dependencies.pollApprovedPackage({
        claim,
        claimFingerprint:
          submission.claimFingerprint,
        expiresAtMs: discovery.expiresAtMs,
        payerClaimUrl: discovery.payerClaimUrl,
        pollCapability:
          submission.pollCapability,
      });
    assertActive();
    opened = openedPackageSnapshot(
      await dependencies.verifyAndOpenPackage({
        approved,
        claim,
        discovery,
        payerPrivateKey: x25519.privateKey,
      }),
    );
    assertActive();
    const paths =
      await dependencies.writePrivateLaunchMaterial({
        discovery,
        openedPackage: opened,
        privateState,
        sshIdentity: ssh,
        tlsIdentity: tls,
      });
    assertActive();
    tunnel =
      await dependencies.startRestrictedTunnel({
        discovery,
        paths,
        sshIdentity: ssh,
      });
    assertActive();
    supervisor =
      await dependencies.startPayerSupervisor({
        discovery,
        paths,
        stateRoot: root,
        tlsIdentity: tls,
      });
    assertActive();
    result =
      await dependencies.waitForTerminalLocalStatus({
        discovery,
        supervisor,
        tunnel,
        writeStatus(value) {
          dependencies.writeStatus(
            publicStatus(value),
          );
        },
      });
    assertActive();
    if (
      result?.paymentMoved !== false ||
      result.status !== "COMPLETED"
    ) {
      invalid();
    }
    const publicResult = Object.freeze({
      paymentMoved: false,
      status: "COMPLETED",
    });
    dependencies.writeStatus(publicResult);
    return publicResult;
  } catch (error) {
    if (dependencies?.writeStatus) {
      try {
        dependencies.writeStatus({
          paymentMoved: false,
          status: "PAYER_BOOTSTRAP_FAILED",
        });
      } catch {
        // The fixed local error below remains authoritative.
      }
    }
    if (
      submission !== null &&
      typeof dependencies?.revokeTunnelGrant ===
        "function"
    ) {
      try {
        await dependencies.revokeTunnelGrant({
          claimFingerprint:
            submission.claimFingerprint,
          paymentMoved: false,
        });
      } catch {
        // Cleanup errors cannot replace the fixed verdict.
      }
    }
    sanitize(error);
  } finally {
    await stopSafely(
      dependencies?.stopPayerSupervisor,
      supervisor,
    );
    await stopSafely(
      dependencies?.stopRestrictedTunnel,
      tunnel,
    );
    if (
      typeof dependencies?.zeroizeBootstrapSecrets ===
      "function"
    ) {
      try {
        await dependencies.zeroizeBootstrapSecrets({
          openedPackage: opened,
          pollCapability:
            submission?.pollCapability ?? null,
          x25519PrivateKey:
            x25519?.privateKey ?? null,
        });
      } catch {
        // Zeroization is attempted on every exit path.
      }
    }
    if (removeSignalHandlers !== null) {
      try {
        removeSignalHandlers();
      } catch {
        // Listener cleanup cannot replace the fixed verdict.
      }
    }
  }
  invalid();
}
