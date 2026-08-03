import { parseArgs } from "node:util";

import { createPublicClient, http, parseEther } from "viem";

import {
  createMcpClient,
  mintDemoToken,
} from "../src/core/clockchain.mjs";
import { RPC_URL } from "../src/core/constants.mjs";
import { createRelayClient } from "../src/relay/client.mjs";

// Session-start gate (Critic MUST 5): the two-regime deadline
// statement only admits runs in the healthy regime. Median of five
// get_block reads under the median bound AND the p95 under its bound,
// sampled at run start; Sepolia RPC reachable; treasury funded; relay
// healthy. Any failure stops the run before identities exist.

export const PREFLIGHT_SAMPLES = 5;
export const PREFLIGHT_MEDIAN_BOUND_MS = 1_500;
export const PREFLIGHT_P95_BOUND_MS = 4_000;
export const PREFLIGHT_TREASURY_MIN_WEI = parseEther("0.05");

export class PreflightError extends Error {
  constructor(code) {
    super(`Preflight gate failure: ${code}`);
    this.name = "PreflightError";
    this.code = code;
  }
}

function gateFailure(code) {
  throw new PreflightError(code);
}

function percentile(sorted, fraction) {
  const index = Math.min(
    sorted.length - 1,
    Math.ceil(sorted.length * fraction) - 1,
  );
  return sorted[index];
}

export async function runPreflight({
  relayUrl,
  treasuryAddress,
  rpcUrl = RPC_URL,
  clockchain,
  publicClient,
  now = () => performance.now(),
}) {
  if (
    typeof relayUrl !== "string" ||
    typeof treasuryAddress !== "string" ||
    !/^0x[0-9a-fA-F]{40}$/.test(treasuryAddress)
  ) {
    gateFailure("PREFLIGHT_INPUT");
  }

  const relay = createRelayClient({ relayUrl });
  try {
    await relay.healthz();
  } catch {
    gateFailure("RELAY_UNHEALTHY");
  }

  const chain =
    publicClient ?? createPublicClient({ transport: http(rpcUrl) });
  let treasuryBalanceWei;
  try {
    treasuryBalanceWei = await chain.getBalance({
      address: treasuryAddress,
    });
  } catch {
    gateFailure("RPC_UNAVAILABLE");
  }
  if (treasuryBalanceWei < PREFLIGHT_TREASURY_MIN_WEI) {
    gateFailure("TREASURY_LOW");
  }

  let client = clockchain;
  if (client === undefined) {
    const token = await mintDemoToken({});
    client = createMcpClient({ token });
  }
  const samples = [];
  for (let index = 0; index < PREFLIGHT_SAMPLES; index += 1) {
    const started = now();
    try {
      await client.getBlock({ height: "latest" });
    } catch {
      gateFailure("CLOCKCHAIN_UNAVAILABLE");
    }
    const elapsed = now() - started;
    if (!Number.isFinite(elapsed) || elapsed < 0) {
      gateFailure("PREFLIGHT_CLOCK");
    }
    samples.push(elapsed);
  }
  samples.sort((left, right) => left - right);
  const medianMs = percentile(samples, 0.5);
  const p95Ms = percentile(samples, 0.95);
  if (medianMs >= PREFLIGHT_MEDIAN_BOUND_MS) {
    gateFailure("LATENCY_MEDIAN");
  }
  if (p95Ms >= PREFLIGHT_P95_BOUND_MS) {
    gateFailure("LATENCY_P95");
  }

  return Object.freeze({
    medianMs,
    p95Ms,
    paymentMoved: false,
    relayOk: true,
    samplesMs: Object.freeze([...samples]),
    treasuryBalanceWei: treasuryBalanceWei.toString(10),
  });
}

const invokedAsScript =
  process.argv[1] !== undefined &&
  process.argv[1].endsWith("preflight.mjs");

if (invokedAsScript) {
  const { values } = parseArgs({
    options: {
      relay: { type: "string" },
      treasury: { type: "string" },
    },
    strict: true,
  });
  runPreflight({
    relayUrl: values.relay,
    treasuryAddress: values.treasury,
  }).then(
    (result) => {
      process.stdout.write(
        `PREFLIGHT_PASSED ${JSON.stringify(result)}\n`,
      );
    },
    (error) => {
      const code =
        error instanceof PreflightError ? error.code : "FAILED";
      process.stderr.write(`PREFLIGHT_FAILED ${code}\n`);
      process.exitCode = 1;
    },
  );
}
