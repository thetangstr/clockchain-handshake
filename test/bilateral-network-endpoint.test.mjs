import assert from "node:assert/strict";
import { test } from "node:test";

import {
  createResolvedLookup,
  resolvePublicEndpoint,
  validatePublicAddress,
  validatePublicEndpoint,
} from "../src/bilateral/network-endpoint.mjs";

const HTTPS_OPTIONS = Object.freeze({
  allowedPaths: Object.freeze(["/mcp"]),
  defaultPort: 9443,
  protocols: Object.freeze(["https:"]),
});

test("validates exact canonical public DNS, IPv4, and IPv6 endpoints", () => {
  assert.deepEqual(
    validatePublicEndpoint("https://payer.example.net:9443/mcp", HTTPS_OPTIONS),
    {
      hostname: "payer.example.net",
      path: "/mcp",
      port: 9443,
      protocol: "https:",
      url: "https://payer.example.net:9443/mcp",
    },
  );
  assert.deepEqual(
    validatePublicEndpoint("https://8.8.8.8:9443/mcp", HTTPS_OPTIONS),
    {
      hostname: "8.8.8.8",
      path: "/mcp",
      port: 9443,
      protocol: "https:",
      url: "https://8.8.8.8:9443/mcp",
    },
  );
  assert.deepEqual(
    validatePublicEndpoint("https://[2606:4700:4700::1111]:9443/mcp", HTTPS_OPTIONS),
    {
      hostname: "2606:4700:4700::1111",
      path: "/mcp",
      port: 9443,
      protocol: "https:",
      url: "https://[2606:4700:4700::1111]:9443/mcp",
    },
  );
});

test("rejects local, ambiguous, private, and noncanonical endpoints", () => {
  for (const value of [
    "https://localhost:9443/mcp",
    "https://payer.localhost:9443/mcp",
    "https://payer.local:9443/mcp",
    "https://*.example.net:9443/mcp",
    "https://payer.example.net.:9443/mcp",
    "https://user@payer.example.net:9443/mcp",
    "https://payer.example.net:9443/mcp#fragment",
    "https://payer.example.net:9443/mcp?query=1",
    "https://payer.example.net:09443/mcp",
    "https://payer.example.net:9444/mcp",
    "https://payer.example.net:9443//mcp",
    "https://payer.example.net:9443/mcp/",
    "https://10.0.0.1:9443/mcp",
    "https://169.254.1.1:9443/mcp",
    "https://192.88.99.1:9443/mcp",
    "https://224.0.0.1:9443/mcp",
    "https://[fc00::1]:9443/mcp",
    "https://[fe80::1]:9443/mcp",
    "https://[ff02::1]:9443/mcp",
    "https://[2001::1]:9443/mcp",
    "https://[2002:a00::1]:9443/mcp",
  ]) {
    assert.throws(
      () => validatePublicEndpoint(value, HTTPS_OPTIONS),
      /Public endpoint validation failed safely/,
      value,
    );
  }
});

test("permits only loopback and IANA documentation addresses under the explicit test gate", () => {
  const options = { ...HTTPS_OPTIONS, allowTestAddresses: true };
  for (const value of [
    "https://127.0.0.1:9443/mcp",
    "https://192.0.2.10:9443/mcp",
    "https://198.51.100.10:9443/mcp",
    "https://203.0.113.10:9443/mcp",
    "https://[::1]:9443/mcp",
    "https://[2001:db8::10]:9443/mcp",
  ]) {
    assert.doesNotThrow(() => validatePublicEndpoint(value, options), value);
  }
  for (const value of [
    "https://10.0.0.1:9443/mcp",
    "https://172.16.0.1:9443/mcp",
    "https://192.168.0.1:9443/mcp",
    "https://[fc00::1]:9443/mcp",
  ]) {
    assert.throws(
      () => validatePublicEndpoint(value, options),
      /Public endpoint validation failed safely/,
      value,
    );
  }
});

test("fails closed when any DNS answer is not public", async () => {
  const endpoint = validatePublicEndpoint(
    "https://payer.example.net:9443/mcp",
    HTTPS_OPTIONS,
  );
  await assert.rejects(
    resolvePublicEndpoint(endpoint, {
      async lookup() {
        return [
          { address: "8.8.8.8", family: 4 },
          { address: "10.0.0.10", family: 4 },
        ];
      },
    }),
    /Public endpoint validation failed safely/,
  );
  const resolved = await resolvePublicEndpoint(endpoint, {
    async lookup() {
      return [
        { address: "2606:4700:4700::1111", family: 6 },
        { address: "8.8.8.8", family: 4 },
      ];
    },
  });
  assert.deepEqual(resolved.addresses, [
    { address: "2606:4700:4700::1111", family: 6 },
    { address: "8.8.8.8", family: 4 },
  ]);
});

test("builds a lookup pinned to the validated DNS answers", async () => {
  const endpoint = validatePublicEndpoint(
    "https://payer.example.net:9443/mcp",
    HTTPS_OPTIONS,
  );
  const resolved = await resolvePublicEndpoint(endpoint, {
    async lookup() {
      return [{ address: "8.8.8.8", family: 4 }];
    },
  });
  const lookup = createResolvedLookup(resolved);
  assert.deepEqual(
    await new Promise((resolve, reject) => {
      lookup("payer.example.net", { all: true }, (error, addresses) => {
        if (error) reject(error);
        else resolve(addresses);
      });
    }),
    [{ address: "8.8.8.8", family: 4 }],
  );
  await assert.rejects(
    new Promise((resolve, reject) => {
      lookup("other.example.net", { all: true }, (error, addresses) => {
        if (error) reject(error);
        else resolve(addresses);
      });
    }),
    /Public endpoint validation failed safely/,
  );
});

test("rejects malformed address records and hostile resolution dependencies", async () => {
  assert.throws(
    () => validatePublicAddress("not-an-address"),
    /Public endpoint validation failed safely/,
  );
  const endpoint = validatePublicEndpoint(
    "https://payer.example.net:9443/mcp",
    HTTPS_OPTIONS,
  );
  for (const lookup of [
    async () => [],
    async () => [{ address: "8.8.8.8", family: 6 }],
    async () => [{ address: "8.8.8.8", family: 4, extra: true }],
    async () => {
      throw new Error("resolver detail must not escape");
    },
  ]) {
    await assert.rejects(
      resolvePublicEndpoint(endpoint, { lookup }),
      (error) =>
        error.message === "Public endpoint validation failed safely." &&
        !error.message.includes("resolver detail"),
    );
  }
});
