#!/usr/bin/env node

import {
  createHash,
  X509Certificate,
} from "node:crypto";
import { types } from "node:util";

import {
  appendPublicRunIndex,
  createImmutableRunSummary,
  publicArtifactKeys,
} from "../src/bilateral/aws/public-history.mjs";
import {
  observePublicMonitorSnapshot,
} from "../src/bilateral/coordination/public-monitor.mjs";
import {
  parsePayerBootstrapDiscoveryWire,
} from "./publish-payer-bootstrap-discovery.mjs";
import {
  parseRequestorDiscoveryWire,
  REQUESTOR_DISCOVERY_SCHEMA,
} from "./publish-requestor-discovery.mjs";

const INPUT_KEYS = Object.freeze([
  "certificateFingerprint",
  "completedAtMs",
  "imageDigest",
  "releaseId",
  "repositorySha",
  "secretCanaries",
  "sessionId",
  "snapshot",
  "verifierPublicationValidated",
]);
const GATE_KEYS = Object.freeze([
  "payerClaimApproved",
  "payerDiscoveryReady",
  "payerMcpReady",
  "requestorDiscoveryReady",
  "runStarted",
  "tunnelTlsHealthy",
]);
const STAGED_KEYS = Object.freeze([
  "body",
  "contentType",
]);
const SHA40 = /^[0-9a-f]{40}$/;
const SHA64 = /^[0-9a-f]{64}$/;
const RELEASE_ID =
  /^release-[0-9a-f]{16}$/;
const SESSION_ID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const IMAGE_DIGEST =
  /^[0-9]{12}\.dkr\.ecr\.[a-z]{2}-[a-z]+-[1-9]\.amazonaws\.com\/[a-z0-9][a-z0-9._/-]{0,254}@sha256:[0-9a-f]{64}$/;
const ETAG = /^"[!-~]{1,1024}"$/;

export class AwsPublicMonitorPublicationError extends Error {
  constructor() {
    super(
      "AWS public monitor publication failed safely.",
    );
    this.name =
      "AwsPublicMonitorPublicationError";
    this.code =
      "AWS_PUBLIC_MONITOR_PUBLICATION_FAILED";
    this.category = "verification";
  }
}

function fail() {
  throw new AwsPublicMonitorPublicationError();
}

function plain(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    !types.isProxy(value) &&
    Object.getPrototypeOf(value) ===
      Object.prototype
  );
}

function exact(value, keys) {
  if (!plain(value)) fail();
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== keys.length ||
    keys.some((key) => !ownKeys.includes(key))
  ) {
    fail();
  }
  for (const key of keys) {
    const descriptor =
      Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor?.enumerable !== true ||
      !Object.hasOwn(descriptor, "value")
    ) {
      fail();
    }
  }
  return value;
}

function inputSnapshot(value) {
  const input = exact(value, INPUT_KEYS);
  if (
    !(
      input.certificateFingerprint === null ||
      SHA64.test(input.certificateFingerprint)
    ) ||
    !IMAGE_DIGEST.test(input.imageDigest) ||
    !RELEASE_ID.test(input.releaseId) ||
    !SHA40.test(input.repositorySha) ||
    !SESSION_ID.test(input.sessionId) ||
    !Array.isArray(input.secretCanaries) ||
    input.secretCanaries.some(
      (canary) =>
        typeof canary !== "string" ||
        canary.length === 0,
    ) ||
    !(
      input.completedAtMs === null ||
      (
        Number.isSafeInteger(
          input.completedAtMs,
        ) &&
        input.completedAtMs >= 0
      )
    ) ||
    typeof input
      .verifierPublicationValidated !==
      "boolean"
  ) {
    fail();
  }
  return input;
}

function publicationGate(value) {
  const gate = exact(value, GATE_KEYS);
  if (
    GATE_KEYS.some(
      (key) =>
        typeof gate[key] !== "boolean",
    )
  ) {
    fail();
  }
  return gate;
}

function stagedObject(value, contentType) {
  const staged = exact(value, STAGED_KEYS);
  if (
    typeof staged.body !== "string" ||
    staged.body.length === 0 ||
    Buffer.byteLength(
      staged.body,
      "utf8",
    ) > 65_536 ||
    staged.contentType !== contentType
  ) {
    fail();
  }
  return staged;
}

function secretFree(value, canaries) {
  const text =
    typeof value === "string"
      ? value
      : JSON.stringify(value);
  if (
    canaries.some((canary) =>
      text.includes(canary))
  ) {
    fail();
  }
}

function putResult(value) {
  if (
    !plain(value) ||
    typeof value.etag !== "string" ||
    !ETAG.test(value.etag) ||
    (
      Object.hasOwn(value, "versionId") &&
      (
        typeof value.versionId !==
          "string" ||
        value.versionId.length === 0 ||
        value.versionId.length > 1024
      )
    )
  ) {
    fail();
  }
  return value;
}

function jsonBody(value, canaries) {
  secretFree(value, canaries);
  return `${JSON.stringify(value)}\n`;
}

function defaultPublicObjectUrl(key) {
  return `https://clockchain-research.vercel.app/handshake/${key}`;
}

async function defaultValidatePayer({
  body,
  input,
}) {
  const discovery =
    parsePayerBootstrapDiscoveryWire(body);
  if (
    discovery.schema !==
      "clockchain.payer-bootstrap-discovery/v1" ||
    discovery.paymentMoved !== false ||
    discovery.imageDigest !==
      input.imageDigest ||
    discovery.releaseId !==
      input.releaseId ||
    discovery.repositorySha !==
      input.repositorySha ||
    discovery.sessionId !==
      input.sessionId
  ) {
    fail();
  }
}

async function defaultValidateRequestor({
  body,
  input,
}) {
  const discovery =
    parseRequestorDiscoveryWire(body);
  if (
    discovery.schema !==
      REQUESTOR_DISCOVERY_SCHEMA ||
    discovery.paymentMoved !== false ||
    discovery.imageDigest !==
      input.imageDigest ||
    discovery.releaseId !==
      input.releaseId ||
    discovery.repositorySha !==
      input.repositorySha ||
    discovery.sessionId !==
      input.sessionId ||
    discovery.certificateFingerprint !==
      input.certificateFingerprint ||
    discovery.runMode !==
      "aws-stakeholder-only"
  ) {
    fail();
  }
}

async function defaultValidateCertificate({
  body,
  certificateFingerprint,
}) {
  const actual = createHash("sha256")
    .update(new X509Certificate(body).raw)
    .digest("hex");
  if (actual !== certificateFingerprint) {
    fail();
  }
}

async function putPublicObject(
  active,
  records,
  input,
) {
  secretFree(input.body, active.canaries);
  const result = putResult(
    await active.putObject(input),
  );
  records.push(Object.freeze({
    etag: result.etag,
    key: input.key,
    versionId:
      result.versionId ?? null,
  }));
}

export async function publishAwsPublicMonitor(
  value,
  dependencies = {},
) {
  try {
    const input = inputSnapshot(value);
    const required = [
      "putObject",
      "readIndex",
      "readPublicationGate",
      "readStagedPublicObject",
      "writePublicationRecord",
    ];
    if (
      !plain(dependencies) ||
      required.some(
        (name) =>
          typeof dependencies[name] !==
            "function",
      )
    ) {
      fail();
    }
    const active = {
      canaries: input.secretCanaries,
      publicObjectUrl:
        dependencies.publicObjectUrl ??
        defaultPublicObjectUrl,
      putObject: dependencies.putObject,
      readIndex: dependencies.readIndex,
      readPublicationGate:
        dependencies.readPublicationGate,
      readStagedPublicObject:
        dependencies.readStagedPublicObject,
      validateStagedCertificate:
        dependencies
          .validateStagedCertificate ??
        defaultValidateCertificate,
      validateStagedPayerDiscovery:
        dependencies
          .validateStagedPayerDiscovery ??
        defaultValidatePayer,
      validateStagedRequestorDiscovery:
        dependencies
          .validateStagedRequestorDiscovery ??
        defaultValidateRequestor,
      writePublicationRecord:
        dependencies.writePublicationRecord,
    };
    if (
      Object.values(active).some(
        (entry) =>
          entry === undefined ||
          entry === null,
      ) ||
      typeof active.publicObjectUrl !==
        "function" ||
      typeof active
        .validateStagedCertificate !==
        "function" ||
      typeof active
        .validateStagedPayerDiscovery !==
        "function" ||
      typeof active
        .validateStagedRequestorDiscovery !==
        "function"
    ) {
      fail();
    }
    const publishedAtMs = Number(
      input.snapshot?.publishedAtMs,
    );
    const snapshot =
      observePublicMonitorSnapshot(
        input.snapshot,
        { nowMs: publishedAtMs },
      );
    secretFree(
      snapshot,
      input.secretCanaries,
    );
    if (
      (
        snapshot.runStatus === "VERIFIED"
      ) !==
        input.verifierPublicationValidated ||
      (
        input.completedAtMs === null &&
        ["VERIFIED", "FAILED", "EXPIRED"]
          .includes(snapshot.runStatus)
      ) ||
      (
        input.completedAtMs !== null &&
        !["VERIFIED", "FAILED", "EXPIRED"]
          .includes(snapshot.runStatus)
      ) ||
      (
        snapshot.runStatus === "VERIFIED" &&
        input.certificateFingerprint === null
      )
    ) {
      fail();
    }
    const keys = input.certificateFingerprint === null
      ? Object.freeze({
          certificate: null,
          index: "runs/index.json",
          latest: "latest.json",
          payerDiscovery: "discoveries/payer.json",
          requestorDiscovery: "discoveries/requestor.json",
          summary: `runs/${snapshot.runId}.json`,
        })
      : publicArtifactKeys({
          certificateFingerprint:
            input.certificateFingerprint,
          runId: snapshot.runId,
        });
    const records = [];
    await putPublicObject(
      active,
      records,
      {
        body: jsonBody(
          snapshot,
          input.secretCanaries,
        ),
        cacheControl: "no-store,max-age=0",
        contentType: "application/json",
        key: keys.latest,
      },
    );

    const gate = publicationGate(
      await active.readPublicationGate({
        releaseId: input.releaseId,
        sessionId: input.sessionId,
      }),
    );
    if (
      gate.runStarted &&
      gate.payerDiscoveryReady
    ) {
      const payer = stagedObject(
        await active.readStagedPublicObject(
          "payerDiscovery",
        ),
        "application/json",
      );
      secretFree(
        payer.body,
        input.secretCanaries,
      );
      await active
        .validateStagedPayerDiscovery({
          body: payer.body,
          input,
        });
      await putPublicObject(
        active,
        records,
        {
          body: payer.body,
          cacheControl:
            "no-store,max-age=0",
          contentType: payer.contentType,
          key: keys.payerDiscovery,
        },
      );
    }

    if (
      gate.payerClaimApproved &&
      gate.payerMcpReady &&
      gate.requestorDiscoveryReady &&
      gate.tunnelTlsHealthy
    ) {
      if (
        input.certificateFingerprint === null ||
        keys.certificate === null
      ) {
        fail();
      }
      const certificate = stagedObject(
        await active.readStagedPublicObject(
          "certificate",
        ),
        "application/x-pem-file",
      );
      const requestor = stagedObject(
        await active.readStagedPublicObject(
          "requestorDiscovery",
        ),
        "application/json",
      );
      secretFree(
        certificate.body,
        input.secretCanaries,
      );
      secretFree(
        requestor.body,
        input.secretCanaries,
      );
      await active
        .validateStagedCertificate({
          body: certificate.body,
          certificateFingerprint:
            input.certificateFingerprint,
        });
      await active
        .validateStagedRequestorDiscovery({
          body: requestor.body,
          input,
        });
      await putPublicObject(
        active,
        records,
        {
          body: certificate.body,
          cacheControl:
            "no-store,max-age=0",
          contentType:
            certificate.contentType,
          key: keys.certificate,
        },
      );
      await putPublicObject(
        active,
        records,
        {
          body: requestor.body,
          cacheControl:
            "no-store,max-age=0",
          contentType:
            requestor.contentType,
          key: keys.requestorDiscovery,
        },
      );
    }

    if (input.completedAtMs !== null) {
      const summary =
        createImmutableRunSummary({
          completedAtMs:
            input.completedAtMs,
          projection: snapshot,
          secretCanaries:
            input.secretCanaries,
          summaryUrl:
            active.publicObjectUrl(
              keys.summary,
            ),
          verifierPublicationValidated:
            input
              .verifierPublicationValidated,
        });
      await putPublicObject(
        active,
        records,
        {
          body: jsonBody(
            summary,
            input.secretCanaries,
          ),
          cacheControl:
            "public,max-age=31536000,immutable",
          contentType: "application/json",
          ifNoneMatch: "*",
          key: keys.summary,
        },
      );
      const current = await active.readIndex();
      let index = null;
      let etag = null;
      if (current !== null) {
        const stored = exact(current, [
          "body",
          "etag",
        ]);
        if (
          typeof stored.body !== "string" ||
          typeof stored.etag !== "string" ||
          !ETAG.test(stored.etag)
        ) {
          fail();
        }
        index = JSON.parse(stored.body);
        if (
          `${JSON.stringify(index)}\n` !==
          stored.body
        ) {
          fail();
        }
        etag = stored.etag;
      }
      const updated = appendPublicRunIndex({
        index,
        summary,
        updatedAtMs:
          input.completedAtMs,
      });
      await putPublicObject(
        active,
        records,
        {
          body: jsonBody(
            updated,
            input.secretCanaries,
          ),
          cacheControl:
            "no-store,max-age=0",
          contentType: "application/json",
          ...(etag === null
            ? { ifNoneMatch: "*" }
            : { ifMatch: etag }),
          key: keys.index,
        },
      );
    }

    const record = Object.freeze({
      objects: Object.freeze(records),
      paymentMoved: false,
      publishedAtMs:
        snapshot.publishedAtMs,
      runId: snapshot.runId,
      schema:
        "clockchain.aws-publication-record/v1",
    });
    secretFree(
      record,
      input.secretCanaries,
    );
    await active.writePublicationRecord(
      record,
    );
    return Object.freeze({
      objectCount: records.length,
      paymentMoved: false,
      runId: snapshot.runId,
      status: "PUBLISHED",
    });
  } catch (error) {
    if (
      error instanceof
      AwsPublicMonitorPublicationError
    ) {
      throw error;
    }
    fail();
  }
}
