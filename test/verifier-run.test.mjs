import assert from "node:assert/strict";
import {
  createPublicKey,
  generateKeyPairSync,
  verify as cryptoVerify,
} from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { canonicalBytes } from "../src/core/canonical.mjs";
import { BilateralVerdictError } from "../src/core/verdict.mjs";
import {
  main,
  runVerification,
  VERDICT_DOCUMENT_SCHEMA,
} from "../src/verifier/run.mjs";
import {
  buildFixture,
  captureStdout,
  KEY_ID,
  RELAY_SESSION_ID,
} from "./helpers/bilateral-fixture.mjs";

function baseInput(harness) {
  return {
    clockchain: harness.clockchain,
    operatorKeyId: KEY_ID,
    operatorPrivateKeyPem: harness.operatorPrivateKeyPem,
    ownerOf: harness.ownerOf,
    relay: harness.relay,
    repositoryPublicKeyResolver: async () =>
      harness.repositoryPublicKey,
    sessionId: RELAY_SESSION_ID,
    subjectRun: harness.subjectRun,
  };
}

async function snapshotVerdict(harness) {
  const response = await fetch(
    `${harness.relayUrl}/v1/sessions/${RELAY_SESSION_ID}/snapshot`,
  );
  assert.equal(response.status, 200);
  const snapshot = await response.json();
  return snapshot.verdict;
}

test(
  "stakeholder happy path publishes a signed verdict",
  async (t) => {
    const harness = await buildFixture(t);
    const stdout = captureStdout();
    const code = await main(
      [
        "--session",
        RELAY_SESSION_ID,
        "--relay",
        harness.relayUrl,
        "--state",
        harness.stateDir,
        "--key-id",
        KEY_ID,
        "--subject-run",
        "stakeholder",
      ],
      {
        clockchain: harness.clockchain,
        ownerOf: harness.ownerOf,
        repoRoot: harness.repoRoot,
        stdout,
      },
    );
    assert.equal(code, 0);
    assert.equal(stdout.lines.length, 1);
    assert.match(
      stdout.lines[0],
      /^VERDICT_PUBLISHED AUTHORIZED session=/,
    );

    const document = await snapshotVerdict(harness);
    assert.equal(document.schema, VERDICT_DOCUMENT_SCHEMA);
    assert.equal(document.sessionId, RELAY_SESSION_ID);
    assert.equal(document.signature.algorithm, "ed25519");
    assert.equal(document.signature.keyId, KEY_ID);
    assert.equal(
      document.signature.publicKey,
      harness.repositoryPublicKey,
    );
    assert.equal(document.verdict.outcome, "AUTHORIZED");
    assert.equal(document.verdict.paymentMoved, false);
    assert.equal(document.verdict.transitions.length, 3);
    assert.equal(
      document.verdict.sessionDigest,
      harness.sessionDigest,
    );

    const publicKey = createPublicKey(
      harness.operatorPublicKeyPem,
    );
    assert.equal(
      cryptoVerify(
        null,
        canonicalBytes(document.verdict),
        publicKey,
        Buffer.from(document.signature.value, "base64"),
      ),
      true,
    );
    const otherKey = generateKeyPairSync(
      "ed25519",
    ).publicKey;
    assert.equal(
      cryptoVerify(
        null,
        canonicalBytes(document.verdict),
        otherKey,
        Buffer.from(document.signature.value, "base64"),
      ),
      false,
    );

    const written = JSON.parse(
      await readFile(
        join(harness.stateDir, "verdict.json"),
        "utf8",
      ),
    );
    assert.deepEqual(written, JSON.parse(JSON.stringify(document)));
    const markdown = await readFile(
      join(harness.stateDir, "verdict.md"),
      "utf8",
    );
    assert.match(markdown, /AUTHORIZED/);
  },
);

test(
  "rehearsal sub-run publishes a rehearsal result",
  async (t) => {
    const harness = await buildFixture(t, {
      subjectRun: "rehearsal",
    });
    const stdout = captureStdout();
    const code = await main(
      [
        "--session",
        RELAY_SESSION_ID,
        "--relay",
        harness.relayUrl,
        "--state",
        harness.stateDir,
        "--key-id",
        KEY_ID,
        "--subject-run",
        "rehearsal",
      ],
      {
        clockchain: harness.clockchain,
        ownerOf: harness.ownerOf,
        repoRoot: harness.repoRoot,
        stdout,
      },
    );
    assert.equal(code, 0);
    assert.match(
      stdout.lines[0],
      /^VERDICT_PUBLISHED REHEARSAL_PASSED session=/,
    );
    const document = await snapshotVerdict(harness);
    assert.equal(
      document.verdict.outcome,
      "REHEARSAL_PASSED",
    );
    await assert.rejects(
      readFile(join(harness.stateDir, "verdict.md"), "utf8"),
    );
  },
);

test(
  "a later slot anchored without its predecessor fails closed as REORDERED",
  async (t) => {
    const harness = await buildFixture(t, {
      anchors: "reordered",
    });
    await assert.rejects(
      runVerification(baseInput(harness)),
      (error) => {
        assert.ok(error instanceof BilateralVerdictError);
        assert.equal(error.terminalCode, "REORDERED");
        return true;
      },
    );
    assert.equal(await snapshotVerdict(harness), null);
  },
);

test(
  "an unanchored session fails closed as MISSING",
  async (t) => {
    const harness = await buildFixture(t, {
      anchors: "none",
    });
    await assert.rejects(
      runVerification(baseInput(harness)),
      (error) => {
        assert.ok(error instanceof BilateralVerdictError);
        assert.equal(error.terminalCode, "MISSING");
        return true;
      },
    );
  },
);

test(
  "absent party evidence fails closed as MISSING",
  async (t) => {
    const harness = await buildFixture(t, {
      evidence: false,
    });
    await assert.rejects(
      runVerification(baseInput(harness)),
      (error) => {
        assert.ok(error instanceof BilateralVerdictError);
        assert.equal(error.terminalCode, "MISSING");
        return true;
      },
    );
  },
);

test(
  "an absent descriptor artifact fails closed as MISSING",
  async (t) => {
    const harness = await buildFixture(t, {
      descriptorMessage: false,
    });
    await assert.rejects(
      runVerification(baseInput(harness)),
      (error) => {
        assert.ok(error instanceof BilateralVerdictError);
        assert.equal(error.terminalCode, "MISSING");
        return true;
      },
    );
  },
);

test(
  "divergent duplicate mandate artifacts fail closed as DUPLICATE",
  async (t) => {
    const harness = await buildFixture(t, {
      duplicateMandate: true,
    });
    await assert.rejects(
      runVerification(baseInput(harness)),
      (error) => {
        assert.ok(error instanceof BilateralVerdictError);
        assert.equal(error.terminalCode, "DUPLICATE");
        return true;
      },
    );
  },
);

test(
  "republishing an identical verdict is idempotent",
  async (t) => {
    const harness = await buildFixture(t);
    const first = await runVerification(baseInput(harness));
    assert.equal(first.republished, false);
    const second = await runVerification(baseInput(harness));
    assert.equal(second.republished, true);
    assert.deepEqual(
      JSON.parse(JSON.stringify(second.document)),
      JSON.parse(JSON.stringify(first.document)),
    );
  },
);

test("usage failures exit 2", async () => {
  const stdout = captureStdout();
  assert.equal(await main([], { stdout }), 2);
  assert.match(stdout.lines[0], /^usage: run\.mjs/);

  const badSubject = captureStdout();
  assert.equal(
    await main(
      [
        "--session",
        RELAY_SESSION_ID,
        "--relay",
        "http://127.0.0.1:1",
        "--state",
        "/tmp/verifier-run-unused",
        "--key-id",
        KEY_ID,
        "--subject-run",
        "practice",
      ],
      { stdout: badSubject },
    ),
    2,
  );

  const badKey = captureStdout();
  assert.equal(
    await main(
      [
        "--session",
        RELAY_SESSION_ID,
        "--relay",
        "http://127.0.0.1:1",
        "--state",
        "/tmp/verifier-run-unused",
        "--key-id",
        "../escape",
        "--subject-run",
        "stakeholder",
      ],
      { stdout: badKey },
    ),
    2,
  );
});
