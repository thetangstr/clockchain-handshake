#!/usr/bin/env node

// Relay server CLI. The relay is dumb by design: shape validation,
// a journaled append-only session log, and long-poll fan-out. All
// authority lives in the signed artifacts and chain reads.

import { parseArgs } from "node:util";

import { createRelayServer } from "../src/relay/server.mjs";

const { values } = parseArgs({
  options: {
    host: { type: "string", default: "127.0.0.1" },
    port: { type: "string", default: "0" },
    state: { type: "string" },
  },
  strict: true,
});

if (
  typeof values.state !== "string" ||
  !values.state.startsWith("/") ||
  !/^[0-9]+$/.test(values.port)
) {
  process.stderr.write(
    "usage: serve-relay.mjs --state <dir> [--port <n>] [--host <h>]\n",
  );
  process.exitCode = 2;
} else {
  const server = createRelayServer({
    host: values.host,
    port: Number(values.port),
    stateDir: values.state,
  });
  const address = await server.listen();
  const url =
    `http://${address.address}:${address.port}`;
  process.stdout.write(`RELAY_LISTENING ${url}\n`);
  const shutdown = () => {
    server.close().then(() => {
      process.exitCode = 0;
    });
  };
  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);
}
