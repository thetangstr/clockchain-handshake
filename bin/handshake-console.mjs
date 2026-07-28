#!/usr/bin/env node
import { createConsoleServer } from "../src/bilateral/coordination/console-server.mjs";
import { buildConsoleProjection } from "../src/bilateral/coordination/console-projection.mjs";

const values = process.argv.slice(2); if (values.length !== 0) throw new Error("Console accepts no evidence or secret arguments.");
const server = createConsoleServer({ projection: () => buildConsoleProjection({}) });
server.listen(8787, "127.0.0.1", () => process.stdout.write("Handshake console listening on loopback.\n"));
