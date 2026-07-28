#!/usr/bin/env node
import { createConsoleServer } from "../src/bilateral/coordination/console-server.mjs";
import { createStateRootProjection } from "../src/bilateral/coordination/console-server.mjs";
import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync } from "node:fs";

export function parseConsoleArguments(argv) {
  const allowed = new Set(["--allow-lan", "--host", "--port", "--state-root", "--tls-certificate", "--tls-key"]); const values = Object.create(null);
  for (let index = 0; index < argv.length; index += 1) { const flag = argv[index]; if (!allowed.has(flag) || Object.hasOwn(values, flag)) throw new Error("Console arguments failed safely."); if (flag === "--allow-lan") { values[flag] = true; continue; } const value = argv[++index]; if (typeof value !== "string" || value.length === 0 || value.includes("\0")) throw new Error("Console arguments failed safely."); values[flag] = value; }
  if (typeof values["--state-root"] !== "string") throw new Error("Console arguments failed safely."); const host = values["--host"] ?? "127.0.0.1"; const port = Number(values["--port"] ?? "8787"); if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error("Console arguments failed safely."); const lan = host !== "127.0.0.1" && host !== "::1" && host !== "localhost";
  if (lan && (!values["--allow-lan"] || !values["--tls-certificate"] || !values["--tls-key"])) throw new Error("Console arguments failed safely."); if (!lan && (values["--allow-lan"] || values["--tls-certificate"] || values["--tls-key"])) throw new Error("Console arguments failed safely.");
  return Object.freeze({ allowLan: lan, host, port, stateRoot: values["--state-root"], tlsCertificate: values["--tls-certificate"] ?? null, tlsKey: values["--tls-key"] ?? null });
}
function privateTlsFile(stat) { return stat.isFile() && !stat.isSymbolicLink() && stat.uid === process.getuid() && (stat.mode & 0o777) === 0o600 && stat.size > 0 && stat.size <= 1024 * 1024; }
function sameIdentity(left, right) { return left.dev === right.dev && left.ino === right.ino && left.uid === right.uid && left.mode === right.mode; }
export function readConsoleTlsInput(path) {
  const before = lstatSync(path); if (!privateTlsFile(before)) throw new Error("Console TLS failed safely.");
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  let bytes, opened;
  try { opened = fstatSync(fd); bytes = readFileSync(fd); } finally { closeSync(fd); }
  const after = lstatSync(path);
  if (!privateTlsFile(opened) || !privateTlsFile(after) || !sameIdentity(before, opened) || !sameIdentity(before, after) || before.size !== opened.size || before.size !== after.size || before.mtimeMs !== opened.mtimeMs || before.mtimeMs !== after.mtimeMs) throw new Error("Console TLS failed safely.");
  return bytes;
}
if (import.meta.url === new URL(process.argv[1], "file:").href) { const options = parseConsoleArguments(process.argv.slice(2)); const tls = options.allowLan ? { cert: readConsoleTlsInput(options.tlsCertificate), key: readConsoleTlsInput(options.tlsKey) } : null; const server = createConsoleServer({ projection: createStateRootProjection({ stateRoot: options.stateRoot }), tls }); server.listen(options.port, options.host, () => process.stdout.write("Handshake console listening.\n")); }
