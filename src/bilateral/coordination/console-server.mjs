import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const assets = new URL("./console/", import.meta.url);
const headers = Object.freeze({ "Cache-Control": "no-store", "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'", "X-Content-Type-Options": "nosniff" });
const routes = Object.freeze({ "/": ["index.html", "text/html; charset=utf-8"], "/assets/app.js": ["app.js", "application/javascript; charset=utf-8"], "/assets/styles.css": ["styles.css", "text/css; charset=utf-8"] });
export function createConsoleServer({ projection }) {
  if (typeof projection !== "function") throw new Error("Console server failed safely.");
  return createServer(async (request, response) => {
    const method = request.method; const path = new URL(request.url, "http://localhost").pathname;
    if (!Number.isSafeInteger(request.rawHeaders.join("").length) || request.rawHeaders.join("").length > 8192) { response.writeHead(431, headers).end(); return; }
    if (!["GET", "HEAD"].includes(method)) { response.writeHead(405, { ...headers, Allow: "GET, HEAD" }).end(); return; }
    if (path === "/v1/console/session") { let body; try { body = Buffer.from(JSON.stringify(projection())); } catch { response.writeHead(500, headers).end(); return; } response.writeHead(200, { ...headers, "Content-Type": "application/json; charset=utf-8" }); if (method === "GET") response.end(body); else response.end(); return; }
    const route = routes[path]; if (!route) { response.writeHead(404, headers).end(); return; }
    try { const body = await readFile(fileURLToPath(new URL(route[0], assets))); response.writeHead(200, { ...headers, "Content-Type": route[1] }); if (method === "GET") response.end(body); else response.end(); } catch { response.writeHead(500, headers).end(); }
  });
}
