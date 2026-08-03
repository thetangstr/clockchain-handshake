import {
  appendFileSync,
  mkdirSync,
  readdirSync,
  readFileSync,
} from "node:fs";
import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { join } from "node:path";
import { types } from "node:util";

// The dumb relay. It validates size, shape, and session only — never
// signatures (P1: authority lives in signatures and chain receipts, and
// consumers verify both themselves). Every mutation is journaled
// synchronously before the response, so a kill -9 loses nothing the
// relay already acknowledged, and restart re-reads the journals.

export const MAX_MESSAGE_BYTES = 262_144;
export const MAX_DISCOVERY_BYTES = 65_536;
export const MAX_VERDICT_BYTES = 262_144;
export const MAX_STATUS_BYTES = 65_536;
export const MAX_EVIDENCE_JSON_BYTES = 1_048_576;
export const MAX_EVIDENCE_MARKDOWN_BYTES = 2_097_152;
export const MAX_EVIDENCE_MARKER_BYTES = 2_048;
export const MAX_EVIDENCE_TOTAL_BYTES =
  MAX_EVIDENCE_JSON_BYTES +
  MAX_EVIDENCE_MARKDOWN_BYTES +
  MAX_EVIDENCE_MARKER_BYTES;
export const MAX_POLL_WAIT_MS = 30_000;
export const MAX_BODY_BYTES = MAX_EVIDENCE_TOTAL_BYTES + 1_024;

const SESSION_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MESSAGE_ROLES = Object.freeze(["operator", "payee", "payer"]);
const EVIDENCE_ROLES = Object.freeze(["payee", "payer"]);
const STATUS_ROLES = Object.freeze(["operator", "payee", "payer"]);
const HEX_PATTERN = /^[0-9a-f]+$/;
const PRINTABLE_PATTERN = /^[ -~]+$/;

export class RelayRequestError extends Error {
  constructor(status, code) {
    super(`Relay request failed: ${code}`);
    this.name = "RelayRequestError";
    this.status = status;
    this.code = code;
  }
}

function badRequest(code = "BAD_REQUEST") {
  return new RelayRequestError(400, code);
}

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    !types.isProxy(value) &&
    (
      Object.getPrototypeOf(value) === Object.prototype ||
      Object.getPrototypeOf(value) === null
    )
  );
}

function exactKeys(value, keys) {
  if (!isPlainObject(value)) return false;
  const own = Object.keys(value);
  return (
    own.length === keys.length &&
    keys.every((key) => own.includes(key))
  );
}

function printable(value, max) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= max &&
    PRINTABLE_PATTERN.test(value)
  );
}

function validateSessionId(sessionId) {
  if (
    typeof sessionId !== "string" ||
    !SESSION_ID_PATTERN.test(sessionId)
  ) {
    throw badRequest("BAD_SESSION_ID");
  }
  return sessionId;
}

function validateSessionRegistration(body) {
  if (
    !exactKeys(body, [
      "senderKey",
      "sessionId",
      "sig",
      "subjectRun",
    ]) ||
    !printable(body.senderKey, 128) ||
    !printable(body.sig, 256) ||
    !["rehearsal", "stakeholder"].includes(body.subjectRun)
  ) {
    throw badRequest("BAD_SESSION_SHAPE");
  }
  validateSessionId(body.sessionId);
  return {
    senderKey: body.senderKey,
    sessionId: body.sessionId,
    sig: body.sig,
    subjectRun: body.subjectRun,
  };
}

function validateMessageEnvelope(body) {
  if (
    !exactKeys(body, [
      "body",
      "kind",
      "role",
      "senderKey",
      "seq",
      "sessionId",
      "sig",
    ]) ||
    !MESSAGE_ROLES.includes(body.role) ||
    !printable(body.kind, 64) ||
    !printable(body.senderKey, 128) ||
    !printable(body.sig, 256) ||
    typeof body.seq !== "number" ||
    !Number.isSafeInteger(body.seq) ||
    body.seq < 0 ||
    !isPlainObject(body.body) ||
    Buffer.byteLength(JSON.stringify(body.body), "utf8") >
      MAX_MESSAGE_BYTES
  ) {
    throw badRequest("BAD_MESSAGE_SHAPE");
  }
  validateSessionId(body.sessionId);
  return {
    body: body.body,
    kind: body.kind,
    role: body.role,
    senderKey: body.senderKey,
    seq: body.seq,
    sessionId: body.sessionId,
    sig: body.sig,
  };
}

function validateEvidenceTriple(body) {
  if (
    !exactKeys(body, ["json", "markdown", "marker"]) ||
    typeof body.json !== "string" ||
    typeof body.markdown !== "string" ||
    typeof body.marker !== "string" ||
    Buffer.byteLength(body.json, "utf8") >
      MAX_EVIDENCE_JSON_BYTES ||
    Buffer.byteLength(body.markdown, "utf8") >
      MAX_EVIDENCE_MARKDOWN_BYTES ||
    Buffer.byteLength(body.marker, "utf8") >
      MAX_EVIDENCE_MARKER_BYTES
  ) {
    throw badRequest("BAD_EVIDENCE_SHAPE");
  }
  return {
    json: body.json,
    markdown: body.markdown,
    marker: body.marker,
  };
}

function validateSignedDocument(body, bytes, code) {
  if (
    !isPlainObject(body) ||
    Buffer.byteLength(JSON.stringify(body), "utf8") > bytes
  ) {
    throw badRequest(code);
  }
  return body;
}

function emptySession(sessionId, subjectRun) {
  return {
    sessionId,
    subjectRun,
    discovery: null,
    verdict: null,
    roles: new Map(),
    messages: [],
    evidence: new Map(),
    status: new Map(),
  };
}

function envelopeEquals(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function createSessionStore({ stateDir }) {
  mkdirSync(stateDir, { recursive: true });
  const sessions = new Map();

  function journalPath(sessionId) {
    return join(stateDir, `${sessionId}.jsonl`);
  }

  function appendJournal(sessionId, entry) {
    appendFileSync(
      journalPath(sessionId),
      `${JSON.stringify(entry)}\n`,
      { encoding: "utf8" },
    );
  }

  function applyEntry(entry) {
    const session = sessions.get(entry.sessionId);
    if (session === undefined) {
      throw badRequest("UNKNOWN_SESSION");
    }
    switch (entry.type) {
      case "discovery":
        session.discovery = entry.document;
        return;
      case "verdict":
        session.verdict = entry.document;
        return;
      case "message":
        if (!session.roles.has(entry.envelope.role)) {
          session.roles.set(
            entry.envelope.role,
            entry.envelope.senderKey,
          );
        }
        session.messages.push(entry.envelope);
        return;
      case "evidence":
        session.evidence.set(entry.role, entry.triple);
        return;
      case "status":
        session.status.set(entry.role, entry.status);
        return;
      default:
        throw badRequest();
    }
  }

  function replay() {
    for (const file of readdirSync(stateDir).sort()) {
      if (!file.endsWith(".jsonl")) continue;
      const lines = readFileSync(
        join(stateDir, file),
        "utf8",
      ).split("\n");
      for (const line of lines) {
        if (line === "") continue;
        const entry = JSON.parse(line);
        if (entry.type === "session") {
          if (!sessions.has(entry.sessionId)) {
            sessions.set(
              entry.sessionId,
              emptySession(
                entry.sessionId,
                entry.subjectRun,
              ),
            );
          }
          continue;
        }
        applyEntry(entry);
      }
    }
  }

  replay();

  return {
    get(sessionId) {
      return sessions.get(sessionId);
    },

    registerSession(registration) {
      const existing = sessions.get(registration.sessionId);
      if (existing !== undefined) {
        if (existing.subjectRun !== registration.subjectRun) {
          throw new RelayRequestError(409, "SESSION_CONFLICT");
        }
        return false;
      }
      sessions.set(
        registration.sessionId,
        emptySession(
          registration.sessionId,
          registration.subjectRun,
        ),
      );
      appendJournal(registration.sessionId, {
        type: "session",
        sessionId: registration.sessionId,
        subjectRun: registration.subjectRun,
        senderKey: registration.senderKey,
        sig: registration.sig,
      });
      return true;
    },

    appendMessage(envelope) {
      const session = sessions.get(envelope.sessionId);
      if (session === undefined) {
        throw badRequest("UNKNOWN_SESSION");
      }
      const boundKey = session.roles.get(envelope.role);
      if (boundKey === undefined) {
        session.roles.set(envelope.role, envelope.senderKey);
      } else if (boundKey !== envelope.senderKey) {
        throw new RelayRequestError(409, "ROLE_ALREADY_BOUND");
      }
      const prior = session.messages.find(
        (message) =>
          message.role === envelope.role &&
          message.seq === envelope.seq,
      );
      if (prior !== undefined) {
        if (!envelopeEquals(prior, envelope)) {
          throw new RelayRequestError(409, "MESSAGE_CONFLICT");
        }
        return session.messages.length;
      }
      session.messages.push(envelope);
      appendJournal(envelope.sessionId, {
        type: "message",
        sessionId: envelope.sessionId,
        envelope,
      });
      return session.messages.length;
    },

    putDiscovery(sessionId, document) {
      const session = sessions.get(sessionId);
      if (session === undefined) {
        throw badRequest("UNKNOWN_SESSION");
      }
      if (session.discovery !== null) {
        if (
          JSON.stringify(session.discovery) !==
          JSON.stringify(document)
        ) {
          throw new RelayRequestError(409, "DISCOVERY_CONFLICT");
        }
        return false;
      }
      session.discovery = document;
      appendJournal(sessionId, {
        type: "discovery",
        sessionId,
        document,
      });
      return true;
    },

    putVerdict(sessionId, document) {
      const session = sessions.get(sessionId);
      if (session === undefined) {
        throw badRequest("UNKNOWN_SESSION");
      }
      if (session.verdict !== null) {
        if (
          JSON.stringify(session.verdict) !==
          JSON.stringify(document)
        ) {
          throw new RelayRequestError(409, "VERDICT_CONFLICT");
        }
        return false;
      }
      session.verdict = document;
      appendJournal(sessionId, {
        type: "verdict",
        sessionId,
        document,
      });
      return true;
    },

    putEvidence(sessionId, role, triple) {
      const session = sessions.get(sessionId);
      if (session === undefined) {
        throw badRequest("UNKNOWN_SESSION");
      }
      const existing = session.evidence.get(role);
      if (existing !== undefined) {
        if (
          JSON.stringify(existing) !== JSON.stringify(triple)
        ) {
          throw new RelayRequestError(409, "EVIDENCE_CONFLICT");
        }
        return false;
      }
      session.evidence.set(role, triple);
      appendJournal(sessionId, {
        type: "evidence",
        sessionId,
        role,
        triple,
      });
      return true;
    },

    putStatus(sessionId, role, status) {
      const session = sessions.get(sessionId);
      if (session === undefined) {
        throw badRequest("UNKNOWN_SESSION");
      }
      session.status.set(role, status);
      appendJournal(sessionId, {
        type: "status",
        sessionId,
        role,
        status,
      });
    },
  };
}

function readBody(request, cap) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    request.on("data", (chunk) => {
      total += chunk.length;
      if (total > cap) {
        reject(new RelayRequestError(413, "PAYLOAD_TOO_LARGE"));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => {
      resolve(Buffer.concat(chunks).toString("utf8"));
    });
    request.on("error", () => {
      reject(badRequest());
    });
  });
}

async function readJsonBody(request, cap) {
  const raw = await readBody(request, cap);
  if (raw.length === 0) {
    throw badRequest("EMPTY_BODY");
  }
  try {
    return JSON.parse(raw);
  } catch {
    throw badRequest("BAD_JSON");
  }
}

function sendJson(response, status, payload) {
  const body = `${JSON.stringify(payload)}\n`;
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
  });
  response.end(body);
}

export function createRelayServer(options = {}) {
  const {
    host = "127.0.0.1",
    port = 0,
    stateDir,
    tls = undefined,
  } = options;
  if (typeof stateDir !== "string" || stateDir.length === 0) {
    throw new RelayRequestError(500, "STATE_DIR_REQUIRED");
  }
  const store = createSessionStore({ stateDir });
  const waiters = new Set();

  function notifyWaiters(sessionId) {
    for (const waiter of [...waiters]) {
      if (waiter.sessionId === sessionId) {
        waiter.fire();
      }
    }
  }

  function snapshotFor(session) {
    return {
      sessionId: session.sessionId,
      subjectRun: session.subjectRun,
      discoveryPublished: session.discovery !== null,
      paymentMoved: false,
      roles: Object.fromEntries(
        [...session.status.entries()].map(
          ([role, status]) => [role, status],
        ),
      ),
      verdict: session.verdict,
    };
  }

  async function route(request, response) {
    const url = new URL(
      request.url ?? "/",
      "http://relay.invalid",
    );
    const parts = url.pathname.split("/").filter(Boolean);
    const method = request.method;

    if (
      method === "GET" &&
      url.pathname === "/healthz"
    ) {
      sendJson(response, 200, { ok: true });
      return;
    }

    if (
      method === "POST" &&
      url.pathname === "/v1/sessions"
    ) {
      const registration = validateSessionRegistration(
        await readJsonBody(request, MAX_DISCOVERY_BYTES),
      );
      const created = store.registerSession(registration);
      sendJson(response, created ? 201 : 200, {
        sessionId: registration.sessionId,
      });
      return;
    }

    if (parts[0] === "v1" && parts[1] === "sessions") {
      const sessionId = validateSessionId(parts[2]);
      const sub = parts[3];

      if (method === "POST" && sub === "messages") {
        const envelope = validateMessageEnvelope(
          await readJsonBody(request, MAX_BODY_BYTES),
        );
        if (envelope.sessionId !== sessionId) {
          throw badRequest("SESSION_MISMATCH");
        }
        const count = store.appendMessage(envelope);
        notifyWaiters(sessionId);
        sendJson(response, 200, {
          delivered: count - 1,
        });
        return;
      }

      if (method === "GET" && sub === "messages") {
        const session = store.get(sessionId);
        if (session === undefined) {
          throw badRequest("UNKNOWN_SESSION");
        }
        const afterRaw = url.searchParams.get("after") ?? "0";
        const waitRaw = url.searchParams.get("waitMs") ?? "0";
        if (
          !/^(0|[1-9][0-9]*)$/.test(afterRaw) ||
          !/^(0|[1-9][0-9]*)$/.test(waitRaw)
        ) {
          throw badRequest("BAD_QUERY");
        }
        const after = Number(afterRaw);
        const waitMs = Math.min(
          Number(waitRaw),
          MAX_POLL_WAIT_MS,
        );
        const collect = () =>
          session.messages
            .map((envelope, index) => ({ envelope, index }))
            .filter(({ index }) => index >= after)
            .map(({ envelope, index }) => ({
              index,
              ...envelope,
            }));
        let messages = collect();
        if (messages.length === 0 && waitMs > 0) {
          messages = await new Promise((resolve) => {
            const timer = setTimeout(() => {
              waiters.delete(waiter);
              resolve(collect());
            }, waitMs);
            const waiter = {
              sessionId,
              fire: () => {
                clearTimeout(timer);
                waiters.delete(waiter);
                resolve(collect());
              },
            };
            waiters.add(waiter);
          });
        }
        sendJson(response, 200, {
          messages,
          next: after + messages.length,
        });
        return;
      }

      if (sub === "evidence" && parts.length === 5) {
        const role = parts[4];
        if (!EVIDENCE_ROLES.includes(role)) {
          throw badRequest("BAD_ROLE");
        }
        if (method === "PUT") {
          const triple = validateEvidenceTriple(
            await readJsonBody(request, MAX_BODY_BYTES),
          );
          const stored = store.putEvidence(
            sessionId,
            role,
            triple,
          );
          notifyWaiters(sessionId);
          sendJson(response, stored ? 201 : 200, {
            stored,
          });
          return;
        }
        if (method === "GET") {
          const session = store.get(sessionId);
          if (session === undefined) {
            throw badRequest("UNKNOWN_SESSION");
          }
          const triple = session.evidence.get(role);
          if (triple === undefined) {
            throw new RelayRequestError(404, "NO_EVIDENCE");
          }
          sendJson(response, 200, triple);
          return;
        }
      }

      if (sub === "verdict") {
        if (method === "PUT") {
          const document = validateSignedDocument(
            await readJsonBody(request, MAX_VERDICT_BYTES),
            MAX_VERDICT_BYTES,
            "BAD_VERDICT_SHAPE",
          );
          const stored = store.putVerdict(sessionId, document);
          notifyWaiters(sessionId);
          sendJson(response, stored ? 201 : 200, {
            stored,
          });
          return;
        }
      }

      if (sub === "status" && parts.length === 5) {
        const role = parts[4];
        if (!STATUS_ROLES.includes(role)) {
          throw badRequest("BAD_ROLE");
        }
        if (method === "PUT") {
          const status = validateSignedDocument(
            await readJsonBody(request, MAX_STATUS_BYTES),
            MAX_STATUS_BYTES,
            "BAD_STATUS_SHAPE",
          );
          store.putStatus(sessionId, role, status);
          notifyWaiters(sessionId);
          sendJson(response, 200, { stored: true });
          return;
        }
      }

      if (method === "GET" && sub === "snapshot") {
        const session = store.get(sessionId);
        if (session === undefined) {
          throw badRequest("UNKNOWN_SESSION");
        }
        sendJson(response, 200, snapshotFor(session));
        return;
      }
    }

    if (
      parts[0] === "v1" &&
      parts[1] === "discovery" &&
      parts.length === 3
    ) {
      const sessionId = validateSessionId(parts[2]);
      if (method === "PUT") {
        const document = validateSignedDocument(
          await readJsonBody(request, MAX_DISCOVERY_BYTES),
          MAX_DISCOVERY_BYTES,
          "BAD_DISCOVERY_SHAPE",
        );
        const stored = store.putDiscovery(
          sessionId,
          document,
        );
        notifyWaiters(sessionId);
        sendJson(response, stored ? 201 : 200, { stored });
        return;
      }
      if (method === "GET") {
        const session = store.get(sessionId);
        if (
          session === undefined ||
          session.discovery === null
        ) {
          throw new RelayRequestError(404, "NO_DISCOVERY");
        }
        sendJson(response, 200, session.discovery);
        return;
      }
    }

    throw new RelayRequestError(404, "NOT_FOUND");
  }

  const listener = (request, response) => {
    route(request, response).catch((error) => {
      if (error instanceof RelayRequestError) {
        sendJson(response, error.status, {
          error: { code: error.code },
        });
        return;
      }
      sendJson(response, 500, {
        error: { code: "INTERNAL" },
      });
    });
  };
  const server =
    tls === undefined
      ? createHttpServer(listener)
      : createHttpsServer(tls, listener);

  return {
    listen() {
      return new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(port, host, () => {
          resolve(server.address());
        });
      });
    },
    close() {
      for (const waiter of waiters) {
        waiter.fire();
      }
      waiters.clear();
      return new Promise((resolve) => {
        server.close(() => resolve());
      });
    },
  };
}
