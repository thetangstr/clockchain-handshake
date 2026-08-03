import { types } from "node:util";

// Relay client. All connectivity is outbound HTTPS (or loopback HTTP in
// local runs). Failure mapping is deliberate: an unreachable or
// misbehaving relay is RENDEZVOUS_UNAVAILABLE, a 429 is RATE_BLOCKED,
// and a 409 surfaces the relay's own named conflict code (for example
// ROLE_ALREADY_BOUND). Everything else fails closed as
// RENDEZVOUS_UNAVAILABLE; the relay is never authoritative.

export const RELAY_REQUEST_TIMEOUT_MS = 10_000;
export const RELAY_LONG_POLL_SLACK_MS = 5_000;

export class RelayClientError extends Error {
  constructor(code, status) {
    super(`Relay call failed: ${code}`);
    this.name = "RelayClientError";
    this.code = code;
    this.status = status;
  }
}

function rendezvousUnavailable() {
  return new RelayClientError("RENDEZVOUS_UNAVAILABLE", 0);
}

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    !types.isProxy(value)
  );
}

function checkedBaseUrl(relayUrl) {
  if (typeof relayUrl !== "string") {
    throw new RelayClientError("BAD_RELAY_URL", 0);
  }
  let parsed;
  try {
    parsed = new URL(relayUrl);
  } catch {
    throw new RelayClientError("BAD_RELAY_URL", 0);
  }
  if (
    parsed.protocol !== "https:" &&
    !(
      parsed.protocol === "http:" &&
      (parsed.hostname === "127.0.0.1" ||
        parsed.hostname === "localhost" ||
        parsed.hostname === "::1")
    )
  ) {
    throw new RelayClientError("BAD_RELAY_URL", 0);
  }
  return relayUrl.replace(/\/+$/, "");
}

export function createRelayClient({ relayUrl, fetchImpl }) {
  const base = checkedBaseUrl(relayUrl);
  const activeFetch =
    fetchImpl === undefined ? fetch : fetchImpl;
  if (typeof activeFetch !== "function") {
    throw new RelayClientError("BAD_RELAY_URL", 0);
  }

  async function call(method, path, body, timeoutMs) {
    const controller = new AbortController();
    const timer = setTimeout(
      () => controller.abort(),
      timeoutMs ?? RELAY_REQUEST_TIMEOUT_MS,
    );
    let response;
    try {
      response = await activeFetch(`${base}${path}`, {
        method,
        headers:
          body === undefined
            ? { accept: "application/json" }
            : {
                "accept": "application/json",
                "content-type": "application/json",
              },
        body:
          body === undefined
            ? undefined
            : JSON.stringify(body),
        signal: controller.signal,
      });
    } catch {
      throw rendezvousUnavailable();
    } finally {
      clearTimeout(timer);
    }
    let payload;
    try {
      payload = await response.json();
    } catch {
      throw rendezvousUnavailable();
    }
    if (response.status === 429) {
      throw new RelayClientError("RATE_BLOCKED", 429);
    }
    if (response.status === 409) {
      const code =
        isPlainObject(payload) &&
        isPlainObject(payload.error) &&
        typeof payload.error.code === "string"
          ? payload.error.code
          : "CONFLICT";
      throw new RelayClientError(code, 409);
    }
    if (!response.ok) {
      const code =
        isPlainObject(payload) &&
        isPlainObject(payload.error) &&
        typeof payload.error.code === "string"
          ? payload.error.code
          : "RENDEZVOUS_UNAVAILABLE";
      throw new RelayClientError(code, response.status);
    }
    return payload;
  }

  const encode = encodeURIComponent;

  return {
    healthz() {
      return call("GET", "/healthz");
    },

    createSession(registration) {
      return call("POST", "/v1/sessions", registration);
    },

    sendMessage(envelope) {
      return call(
        "POST",
        `/v1/sessions/${encode(envelope.sessionId)}/messages`,
        envelope,
      );
    },

    pollMessages({ sessionId, after = 0, waitMs = 0 }) {
      const timeout =
        waitMs > 0
          ? waitMs + RELAY_LONG_POLL_SLACK_MS
          : undefined;
      return call(
        "GET",
        `/v1/sessions/${encode(sessionId)}/messages?after=${after}&waitMs=${waitMs}`,
        undefined,
        timeout,
      );
    },

    putDiscovery(sessionId, document) {
      return call(
        "PUT",
        `/v1/discovery/${encode(sessionId)}`,
        document,
      );
    },

    getDiscovery(sessionId) {
      return call(
        "GET",
        `/v1/discovery/${encode(sessionId)}`,
      );
    },

    putEvidence(sessionId, role, triple) {
      return call(
        "PUT",
        `/v1/sessions/${encode(sessionId)}/evidence/${encode(role)}`,
        triple,
      );
    },

    getEvidence(sessionId, role) {
      return call(
        "GET",
        `/v1/sessions/${encode(sessionId)}/evidence/${encode(role)}`,
      );
    },

    putVerdict(sessionId, document) {
      return call(
        "PUT",
        `/v1/sessions/${encode(sessionId)}/verdict`,
        document,
      );
    },

    putStatus(sessionId, role, status) {
      return call(
        "PUT",
        `/v1/sessions/${encode(sessionId)}/status/${encode(role)}`,
        status,
      );
    },

    getSnapshot(sessionId) {
      return call(
        "GET",
        `/v1/sessions/${encode(sessionId)}/snapshot`,
      );
    },
  };
}
