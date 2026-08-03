import assert from "node:assert/strict";
import test from "node:test";

import { canonicalBytes } from "../src/core/canonical.mjs";
import {
  CatalogError,
  createMessenger,
  exactlyOneFrom,
} from "../src/roles/catalog.mjs";

function fakeRelay(sent = []) {
  return {
    sendMessage: async (envelope) => {
      sent.push(envelope);
    },
  };
}

test(
  "messenger signs a canonical preimage with a decimal-string seq",
  async () => {
    const sent = [];
    const preimages = [];
    const messenger = createMessenger({
      relay: fakeRelay(sent),
      role: "payer",
      senderKey: "payer-key",
      sessionId: "session-1",
      sign: async (bytes) => {
        preimages.push(Buffer.from(bytes).toString("utf8"));
        return "c2ln";
      },
    });
    await messenger.send("mandate-published", { note: "hello" });
    await messenger.send("party-ready", { note: "again" });

    assert.equal(sent.length, 2);
    assert.equal(sent[0].seq, 0);
    assert.equal(sent[1].seq, 1);
    // The preimage must match canonicalBytes of the same fields with
    // the sequence as a decimal string (numbers are banned from
    // canonical preimages).
    const expected = Buffer.from(
      canonicalBytes({
        body: { note: "hello" },
        kind: "mandate-published",
        role: "payer",
        seq: "0",
        sessionId: "session-1",
      }),
    ).toString("utf8");
    assert.equal(preimages[0], expected);
  },
);

test("messenger adopts prior sequence numbers on restart", async () => {
  const sent = [];
  const messenger = createMessenger({
    relay: fakeRelay(sent),
    role: "payee",
    senderKey: "payee-key",
    sessionId: "session-1",
    sign: async () => "c2ln",
  });
  messenger.adoptPrior([
    { kind: "party-ready", role: "payee", seq: 3 },
    { kind: "party-ready", role: "payer", seq: 9 },
    { kind: "identity-announce", role: "payee", seq: 1 },
  ]);
  await messenger.send("payment-request-signed", {});
  assert.equal(sent[0].seq, 4);
});

test(
  "exactlyOneFrom fails closed on divergent duplicates",
  () => {
    const messages = [
      { body: { address: "a" }, kind: "k", role: "payer" },
      { body: { address: "a" }, kind: "k", role: "payer" },
    ];
    assert.equal(
      exactlyOneFrom(messages, "k", "payer"),
      messages[0],
    );
    assert.equal(exactlyOneFrom([], "k", "payer"), null);
    assert.throws(
      () =>
        exactlyOneFrom(
          [
            ...messages,
            { body: { address: "b" }, kind: "k", role: "payer" },
          ],
          "k",
          "payer",
        ),
      (error) => {
        assert.ok(error instanceof CatalogError);
        assert.equal(error.code, "DUPLICATE");
        return true;
      },
    );
  },
);
