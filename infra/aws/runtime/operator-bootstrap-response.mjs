import {
  createPrivateKey,
  sign,
} from "node:crypto";

import {
  canonicalizeReceiptEventValue,
} from "../../../src/canonical.mjs";
import {
  consumePayerClaim,
  createTunnelGrant,
} from "../../../src/bilateral/aws/tunnel-grant.mjs";
import {
  requestorBootstrapClaimFingerprint,
} from "../../../src/bilateral/aws/bootstrap-state.mjs";
import {
  validateLaunchManifest,
} from "../../../src/bilateral/coordination/manifest.mjs";
import {
  sealRequestorBootstrapManifest,
} from "../../../src/bilateral/local-mcp/bootstrap-envelope.mjs";
import {
  payerBootstrapClaimFingerprint,
  sealSignedPayerBootstrapPackage,
} from "../../../src/bilateral/local-mcp/payer-bootstrap-envelope.mjs";

const SHA40 = /^[0-9a-f]{40}$/;
const SHA64 = /^[0-9a-f]{64}$/;
const RELEASE = /^release-[0-9a-f]{16}$/;
const SESSION =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export class AwsOperatorBootstrapResponseError extends Error {
  constructor() {
    super("AWS operator bootstrap response failed safely.");
    this.name = "AwsOperatorBootstrapResponseError";
    this.code = "AWS_OPERATOR_BOOTSTRAP_RESPONSE_INVALID";
    this.category = "verification";
  }
}

function fail() {
  throw new AwsOperatorBootstrapResponseError();
}

function canonicalBytes(value) {
  return Buffer.from(
    JSON.stringify(
      canonicalizeReceiptEventValue(value),
    ),
    "utf8",
  );
}

function manifest(bytes, role, config) {
  if (
    !Buffer.isBuffer(bytes) ||
    bytes.length === 0 ||
    bytes.length > 131_072
  ) {
    fail();
  }
  let parsed;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch {
    fail();
  }
  if (!canonicalBytes(parsed).equals(bytes)) fail();
  let checked;
  try {
    checked = validateLaunchManifest(parsed);
  } catch {
    fail();
  }
  if (
    checked.role !== role ||
    checked.releaseId !== config.releaseId ||
    checked.repositorySha !== config.repositorySha ||
    checked.sessionId !== config.sessionId ||
    checked.operatorKeyId !== config.operatorKeyId ||
    Number(checked.expiresAtMs) <= config.nowMs
  ) {
    fail();
  }
  return { bytes, manifest: checked };
}

function config(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    typeof value.bootstrapBrokerCapability !== "string" ||
    !SHA64.test(value.bootstrapBrokerCapability) ||
    typeof value.bootstrapBrokerUrl !== "string" ||
    typeof value.operatorKeyId !== "string" ||
    value.operatorKeyId.length === 0 ||
    typeof value.operatorPrivateKeyPem !== "string" ||
    !Number.isSafeInteger(value.nowMs) ||
    value.nowMs < 0 ||
    !RELEASE.test(value.releaseId) ||
    !SHA40.test(value.repositorySha) ||
    !SESSION.test(value.sessionId) ||
    typeof value.publicMcpHostname !== "string"
  ) {
    fail();
  }
  let url;
  let operatorPrivateKey;
  try {
    url = new URL(value.bootstrapBrokerUrl);
    operatorPrivateKey = createPrivateKey(
      value.operatorPrivateKeyPem,
    );
  } catch {
    fail();
  }
  if (
    operatorPrivateKey.asymmetricKeyType !== "ed25519" ||
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== "" ||
    !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(value.publicMcpHostname)
  ) {
    fail();
  }
  return Object.freeze({
    ...value,
    operatorPrivateKey,
  });
}

function signature(unsigned, privateKey) {
  return sign(
    null,
    canonicalBytes(unsigned),
    privateKey,
  ).toString("base64");
}

export function buildAwsBootstrapSealedResponse(
  value,
) {
  try {
    const active = config(value.config);
    const role = value.role;
    if (
      !["payer", "payee"].includes(role) ||
      !SHA64.test(value.claimFingerprint) ||
      typeof value.expiresAtMs !== "string" ||
      !/^(?:0|[1-9][0-9]*)$/.test(value.expiresAtMs)
    ) {
      fail();
    }
    const manifestInput = manifest(
      role === "payer"
        ? value.payerLaunchManifestBytes
        : value.payeeLaunchManifestBytes,
      role,
      active,
    );
    const expiresAtMs = String(
      Math.min(
        Number(value.expiresAtMs),
        Number(manifestInput.manifest.expiresAtMs),
      ),
    );
    if (Number(expiresAtMs) <= active.nowMs) fail();
    const privateKey = active.operatorPrivateKey;
    if (role === "payer") {
      if (
        payerBootstrapClaimFingerprint(value.claim) !==
        value.claimFingerprint
      ) {
        fail();
      }
      const approved = consumePayerClaim({
        claim: value.claim,
        consumeClaimFingerprint: () => true,
        expectedClaimFingerprint: value.claimFingerprint,
        expectedReleaseId: active.releaseId,
        expectedRepositorySha: active.repositorySha,
        expectedSessionId: active.sessionId,
        nowMs: active.nowMs,
        publicMcpHostname: active.publicMcpHostname,
        publicMcpPort: 9443,
        tunnelPort: 443,
      });
      const tunnelGrant = createTunnelGrant({
        approved,
        expiresAtMs,
      });
      const packageResponse =
        sealSignedPayerBootstrapPackage({
          bootstrapBrokerCapability:
            active.bootstrapBrokerCapability,
          bootstrapBrokerUrl:
            active.bootstrapBrokerUrl,
          claim: value.claim,
          expiresAtMs,
          launchManifestBytes:
            manifestInput.bytes,
          operatorKeyId:
            active.operatorKeyId,
          signer: (bytes) =>
            sign(null, bytes, privateKey).toString("base64"),
          tunnelGrantBytes:
            canonicalBytes(tunnelGrant),
        });
      return Object.freeze({
        response: Object.freeze({
          claimFingerprint: value.claimFingerprint,
          packageResponse,
          paymentMoved: false,
          status: "SEALED",
        }),
        tunnelGrant,
      });
    }
    if (
      requestorBootstrapClaimFingerprint(value.claim) !==
      value.claimFingerprint
    ) {
      fail();
    }
    const context = Object.freeze({
      claimNonce: value.claim.claimNonce,
      paymentMoved: false,
      releaseId: active.releaseId,
      repositorySha: active.repositorySha,
      sessionId: active.sessionId,
    });
    const envelope = sealRequestorBootstrapManifest({
      context,
      manifestBytes: manifestInput.bytes,
      requestorPublicKey: value.claim.requestorPublicKey,
    });
    const unsigned = Object.freeze({
      claimFingerprint: value.claimFingerprint,
      context,
      envelope,
      paymentMoved: false,
      repositorySha: active.repositorySha,
      schema: "clockchain.requestor-bootstrap-broker-response/v1",
      status: "SEALED",
    });
    const response = Object.freeze({
      claimFingerprint: unsigned.claimFingerprint,
      context: unsigned.context,
      envelope: unsigned.envelope,
      paymentMoved: false,
      repositorySha: unsigned.repositorySha,
      schema: unsigned.schema,
      signature: Object.freeze({
        algorithm: "ed25519",
        keyId: active.operatorKeyId,
        value: signature(unsigned, privateKey),
      }),
      status: "SEALED",
    });
    return Object.freeze({
      response,
      tunnelGrant: null,
    });
  } catch (error) {
    if (error instanceof AwsOperatorBootstrapResponseError) throw error;
    fail();
  }
}
