import { createHash } from "node:crypto";

import {
  observeImmutableRunSummary,
} from "./public-history.mjs";

const EMAIL =
  /^(?=.{3,254}$)[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;
const RUN_ID = /^run-[0-9a-f]{16}$/;
const CLAIM_RESULTS = new Set([
  "CLAIMED",
  "IN_PROGRESS",
  "SENT",
]);

export const RECEIPT_EMAIL_PATH =
  "/receipt-email";

function digest(value) {
  return createHash("sha256")
    .update(value, "utf8")
    .digest("hex");
}

function escapeHtml(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function reply(
  statusCode,
  status,
  allowedOrigin,
) {
  return Object.freeze({
    body: JSON.stringify({
      paymentMoved: false,
      status,
    }),
    headers: Object.freeze({
      "access-control-allow-origin":
        allowedOrigin,
      "content-type": "application/json",
    }),
    statusCode,
  });
}

function request(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Reflect.ownKeys(value).length !== 2 ||
    !Object.hasOwn(value, "email") ||
    !Object.hasOwn(value, "runId") ||
    typeof value.email !== "string" ||
    !EMAIL.test(value.email) ||
    typeof value.runId !== "string" ||
    !RUN_ID.test(value.runId)
  ) {
    throw new Error("invalid");
  }
  return Object.freeze({
    email: value.email.toLowerCase(),
    runId: value.runId,
  });
}

export function renderVerifiedReceiptEmail(
  value,
) {
  const summary =
    observeImmutableRunSummary(value);
  if (
    summary.runStatus !== "VERIFIED" ||
    summary.paymentMoved !== false ||
    summary.anchors.length !== 3
  ) {
    throw new Error("not ready");
  }
  const cards = summary.anchors
    .map(
      (anchor) => `
        <section style="border:1px solid #d5d9e0;border-radius:12px;margin:16px 0;padding:18px">
          <h2 style="margin:0 0 12px">${escapeHtml(anchor.signerRole)} — ${escapeHtml(anchor.kind)}</h2>
          <p><strong>Ledger ID:</strong> <code>${escapeHtml(anchor.ledgerId)}</code></p>
          <p><strong>Block:</strong> ${escapeHtml(anchor.block)}</p>
          <p><strong>Cardinality:</strong> Exactly 1</p>
          <p><a href="${escapeHtml(anchor.explorerUrl)}" rel="noopener noreferrer">Open independent proof</a></p>
        </section>`,
    )
    .join("");
  const textCards = summary.anchors
    .map(
      (anchor) =>
        `${anchor.signerRole} — ${anchor.kind}\nLedger ID: ${anchor.ledgerId}\nBlock: ${anchor.block}\nCardinality: Exactly 1\n${anchor.explorerUrl}`,
    )
    .join("\n\n");
  return Object.freeze({
    html: `<!doctype html><html lang="en"><body style="font-family:system-ui,sans-serif;color:#18202a;line-height:1.5"><main style="margin:auto;max-width:680px;padding:32px"><h1>Clockchain Handshake Receipt</h1><p>Fresh aggregate verification confirmed all three independently verifiable anchors for <code>${escapeHtml(summary.runId)}</code>.</p>${cards}<p><strong>No represented payment moved.</strong></p><p>Sepolia testnet, single validator, no settlement.</p></main></body></html>`,
    subject:
      `Clockchain Handshake Receipt — ${summary.runId}`,
    text:
      `Clockchain Handshake Receipt\n\nFresh aggregate verification confirmed all three independently verifiable anchors for ${summary.runId}.\n\n${textCards}\n\nNo represented payment moved.\nSepolia testnet, single validator, no settlement.`,
  });
}

export function createReceiptEmailHandler(
  dependencies,
) {
  const {
    allowedOrigin,
    claimDelivery,
    completeDelivery,
    failDelivery,
    fromEmail,
    readSummary,
    sendEmail,
  } = dependencies ?? {};
  if (
    typeof allowedOrigin !== "string" ||
    typeof claimDelivery !== "function" ||
    typeof completeDelivery !== "function" ||
    typeof failDelivery !== "function" ||
    typeof fromEmail !== "string" ||
    !EMAIL.test(fromEmail) ||
    typeof readSummary !== "function" ||
    typeof sendEmail !== "function"
  ) {
    throw new TypeError(
      "Receipt email dependencies are invalid.",
    );
  }

  return async function handle(input) {
    if (
      input?.httpMethod !== "POST" ||
      input?.path !== RECEIPT_EMAIL_PATH ||
      input?.headers?.origin !==
        allowedOrigin ||
      input?.headers?.["content-type"] !==
        "application/json" ||
      typeof input.body !== "string" ||
      Buffer.byteLength(input.body, "utf8") >
        2_048
    ) {
      return reply(
        400,
        "RECEIPT_EMAIL_INVALID",
        allowedOrigin,
      );
    }

    let parsed;
    try {
      parsed = request(JSON.parse(input.body));
    } catch {
      return reply(
        400,
        "RECEIPT_EMAIL_INVALID",
        allowedOrigin,
      );
    }

    let message;
    try {
      const summary =
        observeImmutableRunSummary(
          await readSummary(parsed.runId),
        );
      if (summary.runId !== parsed.runId) {
        throw new Error("run mismatch");
      }
      message =
        renderVerifiedReceiptEmail(summary);
    } catch {
      return reply(
        409,
        "RECEIPT_NOT_READY",
        allowedOrigin,
      );
    }

    const deliveryId = digest(
      `${parsed.runId}\0${parsed.email}`,
    );
    let claim;
    try {
      claim = await claimDelivery({
        deliveryId,
        recipientDigest: digest(parsed.email),
        runId: parsed.runId,
      });
    } catch {
      return reply(
        502,
        "RECEIPT_EMAIL_FAILED",
        allowedOrigin,
      );
    }
    if (!CLAIM_RESULTS.has(claim)) {
      return reply(
        502,
        "RECEIPT_EMAIL_FAILED",
        allowedOrigin,
      );
    }
    if (claim !== "CLAIMED") {
      return reply(
        202,
        "RECEIPT_EMAIL_ACCEPTED",
        allowedOrigin,
      );
    }

    try {
      await sendEmail({
        fromEmail,
        html: message.html,
        subject: message.subject,
        text: message.text,
        toEmail: parsed.email,
      });
    } catch {
      try {
        await failDelivery({ deliveryId });
      } catch {
        // The bounded response intentionally hides delivery-state details.
      }
      return reply(
        502,
        "RECEIPT_EMAIL_FAILED",
        allowedOrigin,
      );
    }

    try {
      await completeDelivery({ deliveryId });
    } catch {
      return reply(
        502,
        "RECEIPT_EMAIL_FAILED",
        allowedOrigin,
      );
    }
    return reply(
      202,
      "RECEIPT_EMAIL_ACCEPTED",
      allowedOrigin,
    );
  };
}
