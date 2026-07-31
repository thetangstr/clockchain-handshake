#!/usr/bin/env node

import {
  main,
  relayReadinessLine,
} from "../../bin/handshake-relay.mjs";

let running;
let closing;
let signalReceived = false;

async function close() {
  signalReceived = true;
  if (running === undefined) return;
  closing ??= running.close();
  await closing;
}

function onSignal() {
  void close().catch(() => {
    process.exitCode = 1;
  });
}

process.once("SIGINT", onSignal);
process.once("SIGTERM", onSignal);

main(
  process.argv.slice(2),
  { allowTestAddresses: true },
).then(async (value) => {
  running = value;
  process.stdout.write(
    relayReadinessLine(running),
  );
  if (signalReceived) await close();
}).catch(() => {
  process.stderr.write(
    "TEST_RELAY_STARTUP_INVALID\n",
  );
  process.exitCode = 1;
});
