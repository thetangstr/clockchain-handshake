#!/usr/bin/env node

import { resolve } from "node:path";
import { types } from "node:util";

import {
  createHeartbeatOwnerLease,
} from "../src/bilateral/aws/efs-lease.mjs";

export class AwsRelayAdapterError extends Error {
  constructor() {
    super("AWS relay adapter failed safely.");
    this.name = "AwsRelayAdapterError";
    this.code = "AWS_RELAY_ADAPTER_INVALID";
    this.category = "verification";
  }
}

function invalid() {
  throw new AwsRelayAdapterError();
}

function sanitize(error) {
  if (error instanceof AwsRelayAdapterError) {
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

function exactMount(value) {
  if (
    !plain(value) ||
    Reflect.ownKeys(value).length !== 3 ||
    !Object.hasOwn(value, "path") ||
    !Object.hasOwn(value, "purpose") ||
    !Object.hasOwn(value, "readOnly") ||
    typeof value.path !== "string" ||
    resolve(value.path) !== value.path ||
    value.purpose !== "relay-state" ||
    value.readOnly !== false
  ) {
    invalid();
  }
  return value;
}

function statePath(argv) {
  if (
    !Array.isArray(argv) ||
    argv.some((value) =>
      typeof value !== "string")
  ) {
    invalid();
  }
  const indexes = argv.flatMap((value, index) =>
    value === "--state" ? [index] : []);
  if (
    indexes.length !== 1 ||
    indexes[0] === argv.length - 1
  ) {
    invalid();
  }
  return argv[indexes[0] + 1];
}

export async function runAwsRelay({
  argv,
  mount,
  ownerLease,
  provenanceProvider,
  relayMain,
} = {}) {
  try {
    const assignedMount = exactMount(mount);
    if (
      statePath(argv) !== assignedMount.path ||
      !plain(ownerLease) ||
      typeof ownerLease.acquire !== "function" ||
      !plain(provenanceProvider) ||
      typeof provenanceProvider.assertRepository !==
        "function" ||
      typeof provenanceProvider.verify !== "function" ||
      typeof relayMain !== "function"
    ) {
      invalid();
    }
    return await relayMain(argv, {
      ownerLease: createHeartbeatOwnerLease({
        intervalMs: 10_000,
        lease: ownerLease,
      }),
      provenanceProvider,
    });
  } catch (error) {
    sanitize(error);
  }
}
