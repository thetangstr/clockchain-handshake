#!/usr/bin/env node

import { join, resolve } from "node:path";
import { types } from "node:util";

import {
  createHeartbeatOwnerLease,
} from "../src/bilateral/aws/efs-lease.mjs";

export const AWS_COORDINATOR_PROJECTION_SCHEMA =
  "clockchain.aws-coordinator-projection/v1";

const SHA40 = /^[0-9a-f]{40}$/;
const RELEASE_ID =
  /^release-[0-9a-f]{16}$/;
const SESSION_ID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const GATED_STATES = Object.freeze({
  STAKEHOLDER_PACKAGES_READY: "stakeholder",
});
const COORDINATOR_STATES = new Set([
  "BOOTSTRAPPING",
  "ADDRESSES_READY",
  "FUNDING_READY",
  "PREFLIGHT_PASSED",
  "REHEARSAL_IDENTITIES_READY",
  "REHEARSAL_DESCRIPTOR_READY",
  "REHEARSAL_PACKAGES_READY",
  "REHEARSAL_VERIFIED",
  "STAKEHOLDER_IDENTITIES_READY",
  "STAKEHOLDER_DESCRIPTOR_READY",
  "STAKEHOLDER_PACKAGES_READY",
  "STAKEHOLDER_VERIFIED",
  "COMPLETE",
]);

export class AwsCoordinatorAdapterError extends Error {
  constructor() {
    super("AWS coordinator adapter failed safely.");
    this.name = "AwsCoordinatorAdapterError";
    this.code = "AWS_COORDINATOR_ADAPTER_INVALID";
    this.category = "verification";
  }
}

function invalid() {
  throw new AwsCoordinatorAdapterError();
}

function sanitize(error) {
  if (
    error instanceof AwsCoordinatorAdapterError
  ) {
    throw error;
  }
  invalid();
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

function mount(value, expected) {
  if (
    !plain(value) ||
    Reflect.ownKeys(value).length !== 3 ||
    typeof value.path !== "string" ||
    resolve(value.path) !== value.path ||
    value.purpose !== expected.purpose ||
    value.readOnly !== expected.readOnly
  ) {
    invalid();
  }
  return value;
}

function releaseScope(value, repositorySha) {
  if (
    !plain(value) ||
    value.paymentMoved !== false ||
    !RELEASE_ID.test(value.releaseId) ||
    value.repositorySha !== repositorySha ||
    !SESSION_ID.test(value.sessionId) ||
    !COORDINATOR_STATES.has(value.state)
  ) {
    invalid();
  }
  return value;
}

function verifyAction(value, release, subjectRun) {
  if (
    !plain(value) ||
    Reflect.ownKeys(value).length !== 6 ||
    value.action !== "VERIFY" ||
    !Number.isSafeInteger(
      value.expectedRevision,
    ) ||
    value.expectedRevision < 0 ||
    value.releaseId !== release.releaseId ||
    value.repositorySha !==
      release.repositorySha ||
    value.sessionId !== release.sessionId ||
    value.subjectRun !== subjectRun
  ) {
    invalid();
  }
  return Object.freeze({ ...value });
}

function projection(release, status) {
  return Object.freeze({
    paymentMoved: false,
    releaseId: release.releaseId,
    repositorySha: release.repositorySha,
    schema: AWS_COORDINATOR_PROJECTION_SCHEMA,
    sessionId: release.sessionId,
    state: release.state,
    status,
  });
}

export async function runAwsCoordinatorCycle({
  config,
  createRuntime,
  loadRelease,
  mounts,
  ownerLease,
  readVerifyAction,
  readVerifierPublication,
  runStep,
  verifierLauncher,
  writeProjection,
} = {}) {
  let leaseHandle;
  let result;
  let failure;
  try {
    if (
      !plain(config) ||
      !plain(config.releaseRoot) ||
      typeof config.releaseRoot.path !== "string" ||
      !SHA40.test(config.repositorySha) ||
      !Array.isArray(mounts) ||
      mounts.length !== 3 ||
      typeof createRuntime !== "function" ||
      typeof loadRelease !== "function" ||
      !plain(ownerLease) ||
      typeof ownerLease.acquire !== "function" ||
      (
        typeof readVerifyAction !== "function" &&
        typeof readVerifierPublication !== "function"
      ) ||
      typeof runStep !== "function" ||
      verifierLauncher !== undefined ||
      typeof writeProjection !== "function"
    ) {
      invalid();
    }
    const operatorMount = mount(mounts[0], {
      purpose: "operator-state",
      readOnly: false,
    });
    const verdictMount = mount(mounts[1], {
      purpose: "verifier-evidence",
      readOnly: false,
    });
    const outputMount = mount(mounts[2], {
      purpose: "verdict-output",
      readOnly: true,
    });
    if (
      config.releaseRoot.path !==
        operatorMount.path &&
      !config.releaseRoot.path.startsWith(
        `${operatorMount.path}/`,
      )
    ) {
      invalid();
    }
    if (
      verdictMount.path !== "/var/lib/clockchain/evidence" ||
      outputMount.path !== "/var/lib/clockchain/verifier-output"
    ) {
      invalid();
    }
    const heartbeatLease =
      createHeartbeatOwnerLease({
        intervalMs: 10_000,
        lease: ownerLease,
      });
    leaseHandle = await heartbeatLease.acquire({
      root: config.releaseRoot.path,
    });
    if (
      !plain(leaseHandle) ||
      typeof leaseHandle.assertCurrent !==
        "function" ||
      typeof leaseHandle.release !== "function"
    ) {
      invalid();
    }
    await leaseHandle.assertCurrent();
    const release = releaseScope(
      await loadRelease(config),
      config.repositorySha,
    );
    const subjectRun = GATED_STATES[release.state];
    let verifierAction;
    let verifierPublication;
    if (subjectRun !== undefined) {
      const preparationRuntime = createRuntime({
        runMode: "aws-stakeholder-only",
        verifierEvidenceRoot: verdictMount.path,
        verifierOutputRoot: outputMount.path,
      });
      if (
        !plain(preparationRuntime) ||
        typeof preparationRuntime.prepareVerifierHandoff !== "function" ||
        typeof readVerifyAction !== "function" ||
        typeof readVerifierPublication !== "function"
      ) {
        invalid();
      }
      const handoff = await preparationRuntime.prepareVerifierHandoff({
        releaseId: release.releaseId,
        repositorySha: release.repositorySha,
        sessionId: release.sessionId,
        subjectRun,
      });
      const candidate = await readVerifyAction({
        releaseId: release.releaseId,
        repositorySha: release.repositorySha,
        sessionId: release.sessionId,
        subjectRun,
      });
      if (candidate === null) {
        await writeProjection(
          projection(
            release,
            "WAITING_FOR_OPERATOR_VERIFY",
          ),
        );
        result = Object.freeze({ ...release });
      } else {
        verifierAction = verifyAction(
          candidate,
          release,
          subjectRun,
        );
        const publication = await readVerifierPublication({
          expectedRevision: verifierAction.expectedRevision,
          handoff,
          releaseId: release.releaseId,
          repositorySha: release.repositorySha,
          sessionId: release.sessionId,
          subjectRun,
        });
        if (publication === null) {
          await writeProjection(
            projection(
              release,
              "WAITING_FOR_OPERATOR_VERIFY",
            ),
          );
          result = Object.freeze({ ...release });
        } else {
          verifierPublication = publication;
        }
      }
    }
    if (result === undefined) {
      const runtimeInput = {
        runMode: "aws-stakeholder-only",
        verifierEvidenceRoot: verdictMount.path,
        verifierOutputRoot: outputMount.path,
        ...(verifierAction === undefined
          ? {}
          : { verifierAction }),
        ...(verifierPublication === undefined
          ? {}
          : { verifierPublication }),
      };
      const runtime = createRuntime(runtimeInput);
      const advanced = releaseScope(
        await runStep({ release, runtime }),
        config.repositorySha,
      );
      if (
        advanced.releaseId !== release.releaseId ||
        advanced.sessionId !== release.sessionId
      ) {
        invalid();
      }
      await writeProjection(
        projection(advanced, "ADVANCED"),
      );
      result = Object.freeze({ ...advanced });
    }
  } catch (error) {
    failure = error;
  }
  if (leaseHandle !== undefined) {
    let leaseFailure;
    try {
      await leaseHandle.assertCurrent();
    } catch (error) {
      leaseFailure = error;
    }
    try {
      await leaseHandle.release();
    } catch (error) {
      leaseFailure ??= error;
    }
    failure ??= leaseFailure;
  }
  if (failure !== undefined) {
    sanitize(failure);
  }
  return result;
}
