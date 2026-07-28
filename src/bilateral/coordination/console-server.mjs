import { createServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { constants, lstatSync, fstatSync, openSync, readFileSync, closeSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { buildConsoleProjection } from "./console-projection.mjs";

const assets = new URL("./console/", import.meta.url);
const headers = Object.freeze({ "Cache-Control": "no-store", "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'", "X-Content-Type-Options": "nosniff" });
const routes = Object.freeze({ "/": ["index.html", "text/html; charset=utf-8"], "/assets/app.js": ["app.js", "application/javascript; charset=utf-8"], "/assets/styles.css": ["styles.css", "text/css; charset=utf-8"] });
function fail() { throw new Error("Console server failed safely."); }
function privateFile(stat) { return stat.isFile() && !stat.isSymbolicLink() && stat.uid === process.getuid() && (stat.mode & 0o777) === 0o600 && stat.size > 0 && stat.size <= 65536; }
function sameIdentity(left, right) { return left.dev === right.dev && left.ino === right.ino && left.uid === right.uid && left.mode === right.mode; }
export function createStateRootProjection({ stateRoot }) {
  if (typeof stateRoot !== "string" || stateRoot.length === 0) fail();
  const root = lstatSync(stateRoot); if (!root.isDirectory() || root.isSymbolicLink() || root.uid !== process.getuid() || (root.mode & 0o777) !== 0o700) fail(); const rootFd = openSync(stateRoot, constants.O_RDONLY | constants.O_DIRECTORY | (constants.O_NOFOLLOW ?? 0)); const openedRoot = fstatSync(rootFd); const sameRoot = (next) => next.isDirectory() && !next.isSymbolicLink() && sameIdentity(root, next) && sameIdentity(root, openedRoot);
  if (!sameRoot(openedRoot)) { closeSync(rootFd); fail(); }
  const path = join(stateRoot, "console-state.json");
  return () => {
    if (!sameRoot(lstatSync(stateRoot)) || !sameRoot(fstatSync(rootFd))) fail(); const before = lstatSync(path); if (!privateFile(before)) fail(); const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0)); let bytes; let opened; try { opened = fstatSync(fd); bytes = readFileSync(fd); } finally { closeSync(fd); }
    const after = lstatSync(path); if (!sameRoot(lstatSync(stateRoot)) || !sameRoot(fstatSync(rootFd)) || !privateFile(after) || !privateFile(opened) || !sameIdentity(before, opened) || before.size !== opened.size || before.mtimeMs !== opened.mtimeMs || !sameIdentity(before, after) || before.size !== after.size || before.mtimeMs !== after.mtimeMs || !bytes.equals(Buffer.from(`${JSON.stringify(JSON.parse(bytes.toString("utf8")))}\n`))) fail();
    let value; try { value = JSON.parse(bytes.toString("utf8")); } catch { fail(); }
    const keys = ["lifecycleView", "mandate", "nowMs", "request", "verifierPublication", "watcherSnapshot"];
    if (!value || Object.keys(value).length !== keys.length || keys.some((key) => !Object.hasOwn(value, key))) fail();
    return buildConsoleProjection(value);
  };
}
export function createConsoleServer({ projection, tls = null }) {
  if (typeof projection !== "function") throw new Error("Console server failed safely.");
  const handler = async (request, response) => {
    const method = request.method; let path; try { if (typeof request.url !== "string" || request.url.length > 2048) { response.writeHead(414, headers).end(); return; } path = new URL(request.url, "http://localhost").pathname; } catch { response.writeHead(400, headers).end(); return; }
    if (!Number.isSafeInteger(request.rawHeaders.join("").length) || request.rawHeaders.join("").length > 8192) { response.writeHead(431, headers).end(); return; }
    if (method !== "GET") { response.writeHead(405, { ...headers, Allow: "GET" }).end(); return; }
    if (path === "/v1/console/session") { let body; try { body = Buffer.from(JSON.stringify(projection())); } catch { response.writeHead(500, headers).end(); return; } response.writeHead(200, { ...headers, "Content-Type": "application/json; charset=utf-8" }); response.end(body); return; }
    const route = routes[path]; if (!route) { response.writeHead(404, headers).end(); return; }
    try { const body = await readFile(fileURLToPath(new URL(route[0], assets))); response.writeHead(200, { ...headers, "Content-Type": route[1] }); response.end(body); } catch { response.writeHead(500, headers).end(); }
  };
  if (tls === null) return createServer(handler);
  if (!tls || !Buffer.isBuffer(tls.cert) || !Buffer.isBuffer(tls.key)) fail();
  return createHttpsServer({ cert: tls.cert, key: tls.key, minVersion: "TLSv1.3" }, handler);
}
