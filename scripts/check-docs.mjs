#!/usr/bin/env node

import {
  lstat,
  readFile,
  realpath,
} from "node:fs/promises";
import {
  dirname,
  isAbsolute,
  relative,
  resolve,
} from "node:path";
import {
  fileURLToPath,
  pathToFileURL,
} from "node:url";

import { FAILURE_EXIT_CODES } from "../bin/handshake-demo.mjs";

const PUBLIC_DOCUMENTS = Object.freeze([
  "README.md",
  "DEMO.md",
  "prompts/run-turnkey-demo.md",
]);
const BILATERAL_PUBLIC_DOCUMENTS = Object.freeze([
  "prompts/run-requestor-bilateral-demo.md",
  "prompts/run-payer-bilateral-demo.md",
  "docs/runbooks/bilateral-demo-quick-start.md",
  "docs/runbooks/bilateral-demo-day.md",
  "docs/runbooks/bilateral-demo-live-handoff.md",
]);
const BILATERAL_COMPATIBILITY_DOCUMENTS = Object.freeze([
]);
const BILATERAL_SUPPORTING_DOCUMENTS = Object.freeze([
  "docs/runbooks/payer-mcp-external-relay.md",
]);
const SUPPORTING_DOCUMENTS = Object.freeze([
  "invites/README.md",
]);
const REQUIRED_REPOSITORY_FILES = Object.freeze([
  "package.json",
  "bin/handshake-demo.mjs",
  "invites/README.md",
]);
const REQUIRED_LINKS = Object.freeze({
  "README.md": Object.freeze([
    "DEMO.md",
    "DEMO.md#failure-codes",
    "prompts/run-turnkey-demo.md",
    "prompts/run-requestor-bilateral-demo.md",
    "prompts/run-payer-bilateral-demo.md",
    "docs/runbooks/bilateral-demo-quick-start.md",
    "docs/runbooks/bilateral-demo-day.md",
    "invites/README.md",
    "https://clockchain-research.vercel.app/handshake/run",
  ]),
  "DEMO.md": Object.freeze([
    "README.md",
    "prompts/run-turnkey-demo.md",
    "invites/README.md",
  ]),
  "prompts/run-requestor-bilateral-demo.md": Object.freeze([]),
  "prompts/run-payer-bilateral-demo.md": Object.freeze([]),
  "docs/runbooks/bilateral-demo-quick-start.md": Object.freeze([
    "../../README.md",
    "../../docs/runbooks/bilateral-demo-day.md",
    "../../prompts/run-requestor-bilateral-demo.md",
    "../../prompts/run-payer-bilateral-demo.md",
    "./payer-mcp-external-relay.md",
    "https://clockchain-research.vercel.app/handshake/run",
  ]),
  "docs/runbooks/bilateral-demo-day.md": Object.freeze([
    "../../README.md",
    "./bilateral-demo-quick-start.md",
    "../../prompts/run-requestor-bilateral-demo.md",
    "../../prompts/run-payer-bilateral-demo.md",
    "./payer-mcp-external-relay.md",
    "https://clockchain-research.vercel.app/handshake/run",
  ]),
  "docs/runbooks/bilateral-demo-live-handoff.md": Object.freeze([
    "./bilateral-demo-day.md",
    "./bilateral-demo-quick-start.md",
    "../../prompts/run-requestor-bilateral-demo.md",
    "../../prompts/run-payer-bilateral-demo.md",
    "./payer-mcp-external-relay.md",
    "https://clockchain-research.vercel.app/handshake/run",
  ]),
  "docs/runbooks/payer-mcp-external-relay.md": Object.freeze([]),
});
const FAILURE_CODE_DOCUMENT = "DEMO.md";
const FAILURE_CODE_ROW_PATTERN =
  /^\|[ \t]*`(HANDSHAKE_[A-Z0-9_]+)`[ \t]*\|[^|\r\n]*\|[ \t]*(\d{1,3})[ \t]*\|[^|\r\n]*\|[ \t]*$/gm;
const OFFICIAL_REGISTRY =
  "0x8004A818BFB912233c491871b3d84c89A494BD9e";
const OFFICIAL_REPOSITORY =
  "https://github.com/thetangstr/clockchain-handshake.git";
const RETIRED_LIVE_HANDOFF_RELEASE_SHA =
  "034cdbe4bff8999819d3834f94da5286470b8a99";
const LIVE_HANDOFF_HELPER_URL =
  "https://clockchain-research.vercel.app/handshake/run";
const LIVE_HANDOFF_TREASURY_ADDRESS =
  "0x157a377e4181f3f87c7f6efed5ddc340ccc00dce";
const FORBIDDEN_PRESENT_CAPABILITIES = Object.freeze([
  "court-grade",
  "trustless",
  "mainnet",
  "consensus-secure",
  "permissionless",
]);
const CONTEXTUAL_PRESENT_CAPABILITIES = Object.freeze([
  "production-ready",
  "multi-validator",
]);
// Supporting documents are held to exactly the public ban list. An earlier
// narrower list was justified by a claim that bare "mainnet" would trip the
// honest "hold no mainnet assets" line; that justification was false, because
// the negation vocabulary already protects it. Keep these at parity.
const SUPPORTING_PRESENT_CAPABILITIES =
  FORBIDDEN_PRESENT_CAPABILITIES;
// A bare \bmoney\b match rejected honest disclaimers such as "Money is not
// involved." and "Money movement is out of scope." while its diagnostic
// claimed the document asserted movement. Require an asserted movement.
const MONEY_MOVEMENT_PATTERN =
  /\bmoney\b(?:[ \t]+\w+){0,2}?[ \t]+(?:moves?|moved|moving|flows?|flowed|flowing|transfers?|transferred|changes[ \t]+hands|changed[ \t]+hands)\b|\b(?:moves?|moved|moving|transfers?|transferred|sends?|sent|sending)\b(?:[ \t]+\w+){0,2}?[ \t]+money\b/gi;
const SUPPORTING_REQUIRED_DISCLOSURES = Object.freeze([
  Object.freeze({
    label: "disposable testnet identities",
    pattern: /\bdisposable testnet identities\b/i,
  }),
  Object.freeze({
    label: "no mainnet assets",
    pattern: /\bno mainnet assets\b/i,
  }),
  Object.freeze({
    label: "no scenario money",
    pattern: /\bno scenario money\b/i,
  }),
]);
const CLAIM_BOUNDARY_PATTERN =
  /[.!?;,:]+|\b(?:but|yet|however|although|though|while|whereas|and|because|since)\b/gi;
// "neither"/"nor" are limitation words: "neither X nor Y" negates both sides,
// and both sides live in one claim segment because neither word is a claim
// boundary. Widening this vocabulary is only safe because every existing
// forbidden claim is re-proved to still fail in test/docs.test.mjs.
const EXPLICIT_LIMITATION_PATTERN =
  /\b(?:no|nor|neither|never|cannot|can't|isn't|aren't|wasn't|weren't|doesn't|don't|didn't|won't|wouldn't|couldn't|shouldn't|mustn't|not(?!\s+only))\b|\b(?:is|are|was|were|does|do|did|will|would|can|could|should|must|has|have|had)\s+not(?!\s+only)\b/i;
const TOKEN_BOUNDARY_PATTERN =
  /[\s`"'()[\]{}<>,;!?/]/;
const TOKEN_EXTENSION_PATTERN =
  /[a-z0-9_.:/-]/i;
const EXTERNAL_LINK_PATTERN =
  /^(?:[a-z][a-z+.-]*:|\/\/)/i;
const MARKDOWN_LINK_PATTERN =
  /!?\[[^\]]*]\(\s*(?:<([^>]+)>|([^\s)]+))(?:\s+["'][^"']*["'])?\s*\)/g;
const MARKDOWN_REFERENCE_DEFINITION_PATTERN =
  /^ {0,3}\[[^\]\r\n]+]:[ \t]*(?:<([^>\r\n]+)>|([^\s\r\n]+))(?:[ \t]+(?:"[^"]*"|'[^']*'|\([^)]*\)))?[ \t]*$/gm;
const DEFAULT_ROOT_DIRECTORY = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "..",
);
const DEMO_SAFETY_SECTION = `This is an Ethereum Sepolia and Clockchain® single-validator testnet exercise.
No money moves. Do not install or use AgentDash. It is not mainnet, court-grade,
consensus-secure, or trustless.`;
const PROMPT_SAFETY_SECTION = `Work in a new temporary directory. Do not inspect or modify my current project.
Do not install or use AgentDash. Do not invent success states.

This is an Ethereum Sepolia and Clockchain® single-validator testnet exercise.
No money moves. It is not mainnet, court-grade, consensus-secure, or trustless.`;
const README_SAFETY_SECTION = `The exercise runs on Ethereum Sepolia and a Clockchain® single-validator testnet.
No money moves. Do not install or use AgentDash. This exercise is not mainnet,
court-grade, consensus-secure, or trustless.`;
const BILATERAL_SAFETY_SECTION = `This is an Ethereum Sepolia and Clockchain® single-validator testnet exercise.
No money moves. Do not install or use AgentDash. Do not invent success states.
It is not mainnet, court-grade, consensus-secure, trustless, production-ready,
or multi-validator. Every protocol and verdict artifact preserves paymentMoved: false.`;
const BILATERAL_PROMPT_SAFETY_SECTION = `This is an Ethereum Sepolia and Clockchain single-validator testnet exercise.
No money moves. Do not install or use AgentDash. Do not invent success states.
It is not mainnet, court-grade, consensus-secure, trustless, production-ready,
or multi-validator. Every protocol and verdict artifact preserves
\`paymentMoved:false\`.`;
const CANONICAL_SAFETY_SECTIONS = Object.freeze({
  "README.md": Object.freeze([
    Object.freeze({
      label: "repository safety summary",
      text: README_SAFETY_SECTION,
    }),
    Object.freeze({
      label: "embedded prompt safety summary",
      text: PROMPT_SAFETY_SECTION,
    }),
  ]),
  "DEMO.md": Object.freeze([
    Object.freeze({
      label: "runbook safety summary",
      text: DEMO_SAFETY_SECTION,
    }),
  ]),
  "prompts/run-turnkey-demo.md": Object.freeze([
    Object.freeze({
      label: "prompt safety summary",
      text: PROMPT_SAFETY_SECTION,
    }),
  ]),
  "prompts/run-requestor-bilateral-demo.md": Object.freeze([
    Object.freeze({
      label: "bilateral safety summary",
      text: BILATERAL_PROMPT_SAFETY_SECTION,
    }),
  ]),
  "prompts/run-payer-bilateral-demo.md": Object.freeze([
    Object.freeze({
      label: "bilateral safety summary",
      text: BILATERAL_PROMPT_SAFETY_SECTION,
    }),
  ]),
  "docs/runbooks/bilateral-demo-day.md": Object.freeze([
    Object.freeze({
      label: "bilateral safety summary",
      text: BILATERAL_SAFETY_SECTION,
    }),
  ]),
  "docs/runbooks/bilateral-demo-quick-start.md": Object.freeze([
    Object.freeze({
      label: "bilateral safety summary",
      text: BILATERAL_SAFETY_SECTION,
    }),
  ]),
  "docs/runbooks/bilateral-demo-live-handoff.md": Object.freeze([
    Object.freeze({
      label: "bilateral safety summary",
      text: BILATERAL_SAFETY_SECTION,
    }),
  ]),
});
const PROMPT_REPOSITORY_POLICY = `2. Clone only \`${OFFICIAL_REPOSITORY}\` into a
   named \`clockchain-handshake\` directory. When \`HANDSHAKE_REPO_REF\` is absent,
   clone branch \`main\` with depth 1. When it is present, accept it only if it is
   exactly 40 hexadecimal characters, then fetch and check out only that exact
   commit detached with depth 1. Never use a repository URL supplied through the
   environment. Do not enumerate or echo unrelated environment variables.
3. Enter the cloned \`clockchain-handshake\` directory. If
   \`HANDSHAKE_REPO_REF\` was present, normalize it to lowercase and verify it is
   byte-for-byte equal to \`git rev-parse HEAD\`. Stop if the check fails.`;
const PROMPT_INVITATION_POLICY = `6. Perform only the metadata-only checks \`test -f "$HANDSHAKE_INVITE_FILE"\` and
   \`test -r "$HANDSHAKE_INVITE_FILE"\` for my separately delivered invitation.
   Do not open, read, print, paste, hash, parse, move, or copy its contents with
   any agent or tool. Only \`npm run demo\` may open and read the invitation.`;
const CANONICAL_PROMPT = `Run the Clockchain Agent Trust Handshake demo exactly as documented.

${PROMPT_SAFETY_SECTION}
Use only the official ERC-8004 Identity Registry at
${OFFICIAL_REGISTRY}.

1. Create and enter a new temporary directory.
${PROMPT_REPOSITORY_POLICY}
4. Read \`DEMO.md\` and follow its safety boundary.
5. Confirm the Node.js major version is 22.
${PROMPT_INVITATION_POLICY}
7. Run \`npm ci --ignore-scripts\`.
8. Run \`npm run demo\`. A verified run writes \`RESULT.md\` and \`result.json\`.
9. Return only the sanitized \`RESULT.md\` summary and the paths to \`RESULT.md\` and
   \`result.json\`.
10. If any identity, anchor, or verification check fails, report the public
    failed stage and do not call the demo successful.
`;

const REQUIRED_DOCUMENT_PATTERNS = Object.freeze([
  Object.freeze({
    label: "Clockchain®",
    pattern: /Clockchain®/,
  }),
  Object.freeze({
    label: OFFICIAL_REGISTRY,
    pattern: new RegExp(OFFICIAL_REGISTRY, "i"),
  }),
  Object.freeze({
    label: "npm run demo",
    token: "npm run demo",
  }),
  Object.freeze({
    label: "RESULT.md",
    token: "RESULT.md",
  }),
  Object.freeze({
    label: "result.json",
    token: "result.json",
  }),
]);
const CANONICAL_DOCUMENT_TOKENS = Object.freeze(
  REQUIRED_DOCUMENT_PATTERNS.filter(
    (requirement) => requirement.token !== undefined,
  ),
);
const BILATERAL_COMMON_REQUIREMENTS = Object.freeze([
  Object.freeze({
    label: "immutable repository SHA",
    pattern: /\bimmutable repository SHA\b/i,
  }),
  Object.freeze({
    label: "runner/operator boundary",
    pattern:
      /\brunner local (?:state|success) is not operator authorization\b|\bcannot declare authorization\b/i,
  }),
  Object.freeze({
    label: "honest reconstruction claim",
    pattern:
      /\bFor\s+a\s+session\s+that\s+the\s+fresh\s+aggregate\s+verifier\s+marks\s+`AUTHORIZED`,\s+the\s+verified\s+evidence\s+establishes\s+that\s+Requestor\s+followed\s+Payer's\s+signed\s+mandate,\s+Payer\s+anchored\s+`PROPOSED`\s+and\s+`ACKNOWLEDGED`,\s+and\s+Requestor\s+anchored\s+`ACCEPTED`\./i,
  }),
  Object.freeze({
    label: "honest reconstruction claim: no downloaded message bytes",
    pattern:
      /\bThe protocol does not download message bytes from Clockchain\.|\bcommercial-intent evidence, not\s+authorization anchors\b/i,
  }),
  Object.freeze({
    label: "Payer-owned MCP intake",
    pattern:
      /\bPayer-owned TLS MCP `\/mcp` endpoint for payment intake\b[\s\S]*\bhosted Clockchain MCP server\s+is\s+not\s+used\s+for\s+`request_payment`/i,
  }),
]);
const PAYER_ROLE_COMMAND = `node bin/handshake-propose.mjs \\
  --descriptor "$BILATERAL_DESCRIPTOR_FILE" \\
  --invitation "$PAYER_INVITATION_FILE" \\
  --clockchain-token-file "$PAYER_CLOCKCHAIN_TOKEN_FILE" \\
  --output "$PAYER_RESULT_DIR" \\
  --i-understand-this-writes-to-clockchain`;
const REQUESTOR_ROLE_COMMAND = `node bin/handshake-accept.mjs \\
  --descriptor "$BILATERAL_DESCRIPTOR_FILE" \\
  --invitation "$REQUESTOR_INVITATION_FILE" \\
  --clockchain-token-file "$REQUESTOR_CLOCKCHAIN_TOKEN_FILE" \\
  --output "$REQUESTOR_RESULT_DIR" \\
  --i-understand-this-writes-to-clockchain`;
const INVITATION_CREATION_COMMAND = `node scripts/create-invitations.mjs \\
  --output-public "$INVITATION_PUBLIC_DIR" \\
  --output-secret "$INVITATION_SECRET_DIR" \\
  --ids "requestor-rehearsal,payer-rehearsal,requestor-stakeholder,payer-stakeholder" \\
  --names "Requestor Rehearsal,Payer Rehearsal,Requestor Stakeholder,Payer Stakeholder"`;
const REQUESTOR_TOKEN_COMMAND = `node scripts/mint-bilateral-token.mjs \\
  --role payee \\
  --output "$REQUESTOR_CLOCKCHAIN_TOKEN_FILE" \\
  --repository-sha "$BILATERAL_REPOSITORY_SHA"`;
const PAYER_TOKEN_COMMAND = `node scripts/mint-bilateral-token.mjs \\
  --role payer \\
  --output "$PAYER_CLOCKCHAIN_TOKEN_FILE" \\
  --repository-sha "$BILATERAL_REPOSITORY_SHA"`;
const OPERATOR_TOKEN_COMMAND = `node scripts/mint-bilateral-token.mjs \\
  --role operator \\
  --output "$OPERATOR_CLOCKCHAIN_TOKEN_FILE" \\
  --repository-sha "$BILATERAL_REPOSITORY_SHA"`;
const REQUESTOR_REGISTRATION_COMMAND = `node scripts/register-bilateral-identity.mjs \\
  --invitation "$REQUESTOR_INVITATION_FILE" \\
  --output "$REQUESTOR_REGISTRATION_DIR" \\
  --repository-sha "$BILATERAL_REPOSITORY_SHA" \\
  --i-understand-this-writes-to-sepolia`;
const PAYER_REGISTRATION_COMMAND = `node scripts/register-bilateral-identity.mjs \\
  --invitation "$PAYER_INVITATION_FILE" \\
  --output "$PAYER_REGISTRATION_DIR" \\
  --repository-sha "$BILATERAL_REPOSITORY_SHA" \\
  --i-understand-this-writes-to-sepolia`;
const PREFLIGHT_PREPARE_COMMAND = `node scripts/probe-bilateral-rendezvous.mjs prepare \\
  --operator-private-key "$OPERATOR_PRIVATE_KEY_FILE" \\
  --operator-key-id "$OPERATOR_KEY_ID" \\
  --repository-sha "$BILATERAL_REPOSITORY_SHA" \\
  --output "$PREFLIGHT_PREP_DIR"`;
const REQUESTOR_PREFLIGHT_COMMAND = `node scripts/probe-bilateral-rendezvous.mjs participant \\
  --role payee \\
  --plan "$PREFLIGHT_PLAN_FILE" \\
  --token-file "$REQUESTOR_CLOCKCHAIN_TOKEN_FILE" \\
  --participant-private-key "$REQUESTOR_PREFLIGHT_PRIVATE_KEY_FILE" \\
  --output "$REQUESTOR_PREFLIGHT_RESULT_DIR"`;
const PAYER_PREFLIGHT_COMMAND = `node scripts/probe-bilateral-rendezvous.mjs participant \\
  --role payer \\
  --plan "$PREFLIGHT_PLAN_FILE" \\
  --token-file "$PAYER_CLOCKCHAIN_TOKEN_FILE" \\
  --participant-private-key "$PAYER_PREFLIGHT_PRIVATE_KEY_FILE" \\
  --output "$PAYER_PREFLIGHT_RESULT_DIR"`;
const PREFLIGHT_AGGREGATE_COMMAND = `node scripts/probe-bilateral-rendezvous.mjs aggregate \\
  --plan "$PREFLIGHT_PLAN_FILE" \\
  --payer-report-dir "$PAYER_PREFLIGHT_RESULT_DIR" \\
  --payee-report-dir "$REQUESTOR_PREFLIGHT_RESULT_DIR" \\
  --operator-private-key "$OPERATOR_PRIVATE_KEY_FILE" \\
  --output "$PREFLIGHT_AGGREGATE_DIR" \\
  --attest-separate-credentials \\
  --attest-separate-machines`;
const PROMPT_HASH_COMMAND =
  `node scripts/hash-bilateral-prompts.mjs --repository-sha "$BILATERAL_REPOSITORY_SHA"`;
const OPERATOR_KEYGEN_COMMAND =
  `node scripts/create-session.mjs keygen --key-id "$OPERATOR_KEY_ID"`;
const SESSION_CREATE_COMMAND = `node scripts/create-session.mjs create \\
  --amounts "USD:100" \\
  --key-id "$OPERATOR_KEY_ID" \\
  --output "$BILATERAL_DESCRIPTOR_FILE" \\
  --payer-address "$PAYER_ADDRESS" \\
  --payer-agent-id "$PAYER_AGENT_ID" \\
  --payer-name "$PAYER_DISPLAY_NAME" \\
  --payee-address "$REQUESTOR_ADDRESS" \\
  --payee-agent-id "$REQUESTOR_AGENT_ID" \\
  --payee-name "$REQUESTOR_DISPLAY_NAME" \\
  --prompt-sha256 "$BILATERAL_PROMPT_SHA256" \\
  --repository-sha "$BILATERAL_REPOSITORY_SHA"`;
const WATCHER_COMMAND = `node scripts/watch-bilateral-session.mjs \\
  --descriptor-file "$BILATERAL_DESCRIPTOR_FILE" \\
  --token-file "$OPERATOR_CLOCKCHAIN_TOKEN_FILE"`;
const VERIFIER_COMMAND = `node scripts/verify-bilateral-results.mjs \\
  --clockchain-token-file "$OPERATOR_CLOCKCHAIN_TOKEN_FILE" \\
  --descriptor "$BILATERAL_DESCRIPTOR_FILE" \\
  --output "$VERDICT_OUTPUT_DIR" \\
  --payer-results "$PAYER_TRANSFERRED_RESULT_DIR" \\
  --payee-results "$REQUESTOR_TRANSFERRED_RESULT_DIR" \\
  --rpc-url "$SEPOLIA_RPC_URL"`;
const FUNDING_COMMAND = `npm run bilateral:fund -- \\
  --funding-record "$FUNDING_RECORD_FILE" \\
  --journal-directory "$FUNDING_JOURNAL_DIR" \\
  --keystore "$SEPOLIA_TREASURY_KEYSTORE" \\
  --rpc-url-file "$SEPOLIA_RPC_URL_FILE"`;
const FUNDING_JOURNAL_PREP_COMMAND =
  'install -d -m 0700 "$FUNDING_JOURNAL_DIR"';
const RELAY_COMMAND = `npm run bilateral:relay -- \\
  --host "\${RELAY_LISTEN_HOST:-$RELAY_ADVERTISED_IP}" \\
  --port "$RELAY_PORT" \\
  --repository-sha "$BILATERAL_REPOSITORY_SHA" \\
  --state "$BILATERAL_RELEASE_ROOT/relay-state" \\
  --tls-certificate "$RELAY_TLS_CERTIFICATE" \\
  --tls-private-key "$RELAY_TLS_PRIVATE_KEY"`;
const COORDINATOR_COMMAND = `npm run bilateral:coordinator -- \\
  --clockchain-token-file "$OPERATOR_CLOCKCHAIN_TOKEN_FILE" \\
  --operator-key-id "$OPERATOR_KEY_ID" \\
  --operator-private-key "$OPERATOR_PRIVATE_KEY_FILE" \\
  --release-root "$BILATERAL_RELEASE_ROOT" \\
  --relay-url "https://$RELAY_ADVERTISED_IP:$RELAY_PORT" \\
  --repository-sha "$BILATERAL_REPOSITORY_SHA" \\
  --rpc-url-file "$SEPOLIA_RPC_URL_FILE" \\
  --tls-certificate "$RELAY_TLS_CERTIFICATE" \\
  --tls-fingerprint "$RELAY_TLS_FINGERPRINT"`;
const CONSOLE_COMMAND = `npm run bilateral:console -- \\
  --state-root "$BILATERAL_RELEASE_ROOT"`;
const PAYER_SUPERVISOR_COMMAND = `npm run bilateral:supervisor -- \\
  --launch-manifest "$PAYER_LAUNCH_MANIFEST" \\
  --state "$PAYER_SUPERVISOR_STATE" \\
  --payer-mcp-host "$PAYER_MCP_HOST" \\
  --payer-mcp-port "$PAYER_MCP_PORT" \\
  --payer-mcp-public-url "$PAYER_MCP_PUBLIC_URL" \\
  --payer-mcp-bootstrap-broker-url "$PAYER_MCP_BOOTSTRAP_BROKER_URL" \\
  --payer-mcp-bootstrap-broker-capability-file "$PAYER_MCP_BOOTSTRAP_BROKER_CAPABILITY_FILE" \\
  --payer-mcp-tls-certificate "$PAYER_MCP_TLS_CERTIFICATE" \\
  --payer-mcp-tls-private-key "$PAYER_MCP_TLS_PRIVATE_KEY"`;
const REQUESTOR_REQUEST_PAYMENT_COMMAND = `npm run bilateral:request-payment -- \\
  --discovery-url "$REQUESTOR_DISCOVERY_URL" \\
  --intake-request-id "$REQUESTOR_INTAKE_REQUEST_ID" \\
  --state "$REQUESTOR_SUPERVISOR_STATE"`;
const PAYER_TERMINAL_ROLE_JSON =
  /\{"paymentMoved":false,"role":"payer","state":"ACKNOWLEDGED","status":"PARTY_COMPLETE"\}/;
const REQUESTOR_TERMINAL_ROLE_JSON =
  /\{"paymentMoved":false,"role":"payee","state":"ACCEPTED","status":"PARTY_COMPLETE"\}/;
const NO_POST_FUNDING_HERMES_SENTENCE =
  "No additional Hermes message is required after operator funding.";
const POST_FUNDING_CONTEXT_PATTERN =
  /\bafter operator funding\b/i;
const EXTRA_HERMES_ITEM_PATTERN =
  /\b(?:additional|another|new)\s+Hermes\s+(?:message|prompt|card)\b/i;
const POST_FUNDING_HERMES_REQUEST_PATTERN =
  /\b(?:required|needed|requested|ask(?:\s+for)?|require|request|prompt(?:\s+for)?)\b/i;
const PROHIBITED_POST_FUNDING_HERMES_REQUEST_PATTERN =
  /\b(?:(?:do\s+not|don't|never|must\s+not|mustn't|cannot|can't)\s+(?:ask(?:\s+for)?|require|request|prompt(?:\s+for)?)\b[^.\n,;]*\b(?:additional|another|new)\s+Hermes\s+(?:message|prompt|card)\b[^.\n,;]*\bafter operator funding\b|\bafter operator funding\b[\s,]*\b(?:do\s+not|don't|never|must\s+not|mustn't|cannot|can't)\s+(?:ask(?:\s+for)?|require|request|prompt(?:\s+for)?)\b[^.\n,;]*\b(?:additional|another|new)\s+Hermes\s+(?:message|prompt|card)\b)/gi;

function contradictsNoPostFundingHermes(contents) {
  return contents
    .replaceAll(NO_POST_FUNDING_HERMES_SENTENCE, "")
    .split(/[.!?\r\n]+/)
    .some(
      (sentence) => {
        const residual = sentence.replaceAll(
          PROHIBITED_POST_FUNDING_HERMES_REQUEST_PATTERN,
          " after operator funding ",
        );
        return (
          POST_FUNDING_CONTEXT_PATTERN.test(residual) &&
          EXTRA_HERMES_ITEM_PATTERN.test(residual) &&
          POST_FUNDING_HERMES_REQUEST_PATTERN.test(residual)
        );
      },
    );
}

function bilateralContractFailures(relativePath, contents) {
  const failures = [];
  const fundingCommandPositions = tokenOccurrences(
    contents,
    "npm run bilateral:fund",
  );
  if (fundingCommandPositions.length > 0) {
    if (
      fundingCommandPositions.some(
        (index) =>
          contents.lastIndexOf(
            FUNDING_JOURNAL_PREP_COMMAND,
            index,
          ) === -1,
      )
    ) {
      failures.push(
        `${relativePath}: missing private funding journal directory creation before every funding command.`,
      );
    }
    if (
      !/\bcreates?\b[\s\S]{0,160}\bfunding journal\b[\s\S]{0,160}\bonce\b[\s\S]{0,160}\bbefore\b[\s\S]{0,160}\bbatch\b/i.test(
        contents,
      )
    ) {
      failures.push(
        `${relativePath}: missing private funding journal directory create-once-before-batch instruction.`,
      );
    }
    if (
      !/\bpreserves?\b[\s\S]{0,160}\bfunding journal\b[\s\S]{0,160}\breplay\/recovery\b/i.test(
        contents,
      )
    ) {
      failures.push(
        `${relativePath}: missing private funding journal directory replay/recovery preservation instruction.`,
      );
    }
    if (
      !/\bnever\b[\s\S]{0,160}\bdeletes?\b[\s\S]{0,160}\brecreates?\b[\s\S]{0,160}\bfunding journal\b[\s\S]{0,160}\bafter\b[\s\S]{0,160}\battempt\b/i.test(
        contents,
      )
    ) {
      failures.push(
        `${relativePath}: missing private funding journal directory no-delete-recreate-after-attempt instruction.`,
      );
    }
  }
  if (/https:\/\/mcp\.clockchain\.network\/mcp/i.test(contents)) {
    failures.push(
      `${relativePath}: must not describe hosted Clockchain MCP as the payment-intake entry point; use the Payer-owned TLS MCP /mcp flow.`,
    );
  }
  if (contradictsNoPostFundingHermes(contents)) {
    failures.push(
      `${relativePath}: contradicts the no post-funding Hermes message contract.`,
    );
  }
  if (
    relativePath === "prompts/run-payer-bilateral-demo.md" &&
    /The operator privately sets:[\s\S]*(PAYER_MCP_TLS_ROOT|PAYER_MCP_TLS_CERTIFICATE|PAYER_MCP_TLS_PRIVATE_KEY)/.test(
      contents,
    )
  ) {
    failures.push(
      `${relativePath}: must not claim the operator privately sets Payer-derived MCP TLS paths.`,
    );
  }
  if (
    relativePath === "prompts/run-requestor-bilateral-demo.md" &&
    /The operator privately sets:[\s\S]*(REQUESTOR_INTAKE_REQUEST_ID|PAYER_MCP_URL|PAYER_MCP_TLS_CERTIFICATE|PAYER_MCP_TLS_FINGERPRINT)/.test(
      contents,
    )
  ) {
    failures.push(
      `${relativePath}: must not claim the operator privately sets Requestor-derived or received MCP request inputs.`,
    );
  }
  if (relativePath === "prompts/run-requestor-bilateral-demo.md") {
    for (const [label, pattern] of [
      ["legacy launch-manifest flag", /--launch-manifest\b/],
      ["legacy MCP URL flag", /--mcp-url\b/],
      ["legacy TLS certificate flag", /--tls-certificate\b/],
      ["legacy TLS fingerprint flag", /--tls-fingerprint\b/],
      ["legacy Requestor launch manifest variable", /REQUESTOR_LAUNCH_MANIFEST/],
      ["legacy Payer MCP TLS variable", /PAYER_MCP_TLS_/],
      ["attachment instruction", /\battach(?:ing)?\s+(?:a\s+)?(?:file|manifest|certificate)|\battachment(?:s)?\b/i],
      ["manual second prompt", /\bsecond prompt\b/i],
    ]) {
      if (pattern.test(contents)) failures.push(`${relativePath}: contains ${label}.`);
    }
  }
  for (const { label, pattern } of BILATERAL_COMMON_REQUIREMENTS) {
    if (!pattern.test(contents)) {
      failures.push(
        `${relativePath}: missing bilateral ${label}.`,
      );
    }
  }
  const pathRequirements = {
    "prompts/run-requestor-bilateral-demo.md": [
      [
        "Stakeholder 2 role card",
        /\bYou are Stakeholder 2, Requestor, the payment requestor\./,
      ],
      ["Requestor machine role", /\bRequestor\b[^.]*\brequestor\b/i],
      [
        "automatic signed request",
        /\brequesting payments\b[\s\S]*\bfollowing the payer's required\s+protocol\b[\s\S]*\bHANDSHAKE_REQUIRED\b/i,
      ],
      [
        "automated supervisor session",
        /\bAutomated supervisor session\b/i,
      ],
      [
        "exact request-payment command",
        /npm run bilateral:request-payment -- \\\n  --discovery-url "\$REQUESTOR_DISCOVERY_URL" \\\n  --intake-request-id "\$REQUESTOR_INTAKE_REQUEST_ID" \\\n  --state "\$REQUESTOR_SUPERVISOR_STATE"/,
      ],
      ["no direct supervisor startup", /\bDo not start\s+`npm run bilateral:supervisor`\s+directly\b/i],
      ["HANDSHAKE_REQUIRED gate", /\bHANDSHAKE_REQUIRED\b[\s\S]*\bwrapper\b[\s\S]*\bstarts the Requestor\s+supervisor\b/i],
      ["two-run supervisor lifetime", /\bstays alive\b[^.]*\bboth runs\b/i],
      ["closed command policy", /\bmust not improvise commands\b/i],
      ["non-authorizing role", /\bcannot declare authorization\b/i],
      [
        "ambiguity recovery boundary",
        /\bOn ambiguity,\s+stop immediately\b/i,
      ],
      [
        "Requestor command",
        /\bnode bin\/handshake-accept\.mjs\b/,
      ],
      ["Requestor local state", /\bACCEPTED\b/],
      [
        "Requestor terminal PARTY_COMPLETE",
        REQUESTOR_TERMINAL_ROLE_JSON,
      ],
      [
        "Requestor non-authorizing terminal role finish",
        /\brole-local finish\b[\s\S]*\bnot authorization\b[\s\S]*\bnever emit `AUTHORIZED`|\bnot authorization\b[\s\S]*\brole-local finish\b[\s\S]*\bnever emit `AUTHORIZED`/i,
      ],
      [
        "commercial intent boundary",
        /\bCommercial Intent Boundary\b/i,
      ],
      [
        "clean detached checkout",
        /\bclean detached checkout\b[^.]*\breviewed 40-character SHA\b/i,
      ],
      [
        "time-bounded bootstrap material",
        /\bBootstrap material is time bounded\b/i,
      ],
      [
        "coordination TLS identity pin",
        /\bcoordination\s+relay TLS identity\b[\s\S]{0,160}\bpins that binding\b/i,
      ],
      [
        "neutral private input ownership",
        /\bRequestor receives or derives these private inputs and paths:/,
      ],
      ["secret-byte prohibition", /\bdo not inspect secret bytes\b/i],
      ["role-switch prohibition", /\bdo not switch roles\b/i],
      ["extra-session prohibition", /\bdo not create extra sessions\b/i],
      ["funding prohibition", /\bdo not fund addresses\b/i],
      ["watcher/verifier prohibition", /\bdo not run the watcher or verifier\b/i],
      ["authorization prohibition", /\bdo not declare authorization\b/i],
    ],
    "prompts/run-payer-bilateral-demo.md": [
      [
        "Stakeholder 1 role card",
        /\bYou are Stakeholder 1, Payer, the mandate-owning payer\./,
      ],
      ["Payer machine role", /\bPayer\b[^.]*\bpayer\b/i],
      ["Payer mandate ownership", /\bmandate-owning payer\b/i],
      [
        "automatic signed mandate",
        /\bpublishes and maintains\b[^.]*\bPayer's reusable signed payment mandate\b[^.]*\bincoming payment requests\b/i,
      ],
      [
        "automated supervisor session",
        /\bAutomated supervisor session\b/i,
      ],
      [
        "exact supervisor command",
        /npm run bilateral:supervisor -- \\\n  --launch-manifest "\$PAYER_LAUNCH_MANIFEST" \\\n  --state "\$PAYER_SUPERVISOR_STATE" \\\n  --payer-mcp-host "\$PAYER_MCP_HOST" \\\n  --payer-mcp-port "\$PAYER_MCP_PORT" \\\n  --payer-mcp-public-url "\$PAYER_MCP_PUBLIC_URL" \\\n  --payer-mcp-bootstrap-broker-url "\$PAYER_MCP_BOOTSTRAP_BROKER_URL" \\\n  --payer-mcp-bootstrap-broker-capability-file "\$PAYER_MCP_BOOTSTRAP_BROKER_CAPABILITY_FILE" \\\n  --payer-mcp-tls-certificate "\$PAYER_MCP_TLS_CERTIFICATE" \\\n  --payer-mcp-tls-private-key "\$PAYER_MCP_TLS_PRIVATE_KEY"/,
      ],
      ["PAYER_MCP_READY gate", /\bPAYER_MCP_READY\b/],
      [
        "safe public MCP handoff",
        /\bRequestor receives only\b[\s\S]{0,160}\bsigned discovery URL\b/i,
      ],
      ["two-run supervisor lifetime", /\bstays alive\b[^.]*\bboth runs\b/i],
      ["closed command policy", /\bmust not improvise commands\b/i],
      ["non-authorizing role", /\bcannot declare authorization\b/i],
      [
        "ambiguity recovery boundary",
        /\bOn ambiguity,\s+stop immediately\b/i,
      ],
      [
        "Payer command",
        /\bnode bin\/handshake-propose\.mjs\b/,
      ],
      ["Payer local state", /\bACKNOWLEDGED\b/],
      [
        "Payer terminal PARTY_COMPLETE",
        PAYER_TERMINAL_ROLE_JSON,
      ],
      [
        "Payer non-authorizing terminal role finish",
        /\brole-local finish\b[\s\S]*\bnot authorization\b[\s\S]*\bnever emit `AUTHORIZED`|\bnot authorization\b[\s\S]*\brole-local finish\b[\s\S]*\bnever emit `AUTHORIZED`/i,
      ],
      [
        "commercial intent boundary",
        /\bCommercial Intent Boundary\b/i,
      ],
      [
        "clean detached checkout",
        /\bclean detached checkout\b[^.]*\breviewed 40-character SHA\b/i,
      ],
      [
        "60-minute launch manifests",
        /\blaunch manifest expires after 60 minutes\b/i,
      ],
      [
        "TLS certificate fingerprint pin",
        /\bTLS certificate fingerprint\b[\s\S]{0,160}\bpins that fingerprint\b/i,
      ],
      [
        "neutral private input ownership",
        /\bPayer receives or derives these private inputs and paths:/,
      ],
      ["secret-byte prohibition", /\bdo not inspect secret bytes\b/i],
      ["role-switch prohibition", /\bdo not switch roles\b/i],
      ["extra-session prohibition", /\bdo not create extra sessions\b/i],
      ["funding prohibition", /\bdo not fund addresses\b/i],
      ["watcher/verifier prohibition", /\bdo not run the watcher or verifier\b/i],
      ["authorization prohibition", /\bdo not declare authorization\b/i],
    ],
    "docs/runbooks/bilateral-demo-day.md": [
      [
        "Stakeholder 1 role mapping",
        /\bStakeholder 1\s+[—-]\s+Payer\s+[—-]\s+payer\b/,
      ],
      [
        "Stakeholder 2 role mapping",
        /\bStakeholder 2\s+[—-]\s+Requestor\s+[—-]\s+requestor\b/,
      ],
      [
        "human operator mapping",
        /\bHuman operator\s+[—-]\s+relay,\s+coordinator,\s+read-only console,\s+watcher,\s+funding wallet,\s+fresh aggregate verifier\b/i,
      ],
      [
        "public live-demo helper",
        /\bhttps:\/\/clockchain-research\.vercel\.app\/handshake\/run\b/,
      ],
      [
        "exact startup order",
        /\brelay -> coordinator -> console -> funding readiness -> production bootstrap broker -> Payer raw-TCP tunnel -> Payer MCP\/supervisor -> wait PAYER_MCP_READY -> publish signed discovery -> Requestor request_payment -> HANDSHAKE_REQUIRED -> wait pending bootstrap claim -> approve exact claim fingerprint -> Requestor supervisor continues -> funding batch when record ready -> PROPOSED -> ACCEPTED -> ACKNOWLEDGED -> fresh verification -> AUTHORIZED\b/,
      ],
      [
        "requestor discovery publisher command",
        /\bnpm --silent run bilateral:publish-requestor-discovery --/,
      ],
      [
        "Payer-owned MCP only",
        /\bPayer-owned TLS MCP `\/mcp` endpoint\b/i,
      ],
      ["automated primary flow", /\bAutomated primary flow\b/i],
      [
        "exact relay entrypoint",
        /\bnpm run bilateral:relay -- \\/,
      ],
      [
        "exact coordinator entrypoint",
        /\bnpm run bilateral:coordinator -- \\/,
      ],
      [
        "exact console entrypoint",
        /\bnpm run bilateral:console -- \\/,
      ],
      [
        "read-only advisory console",
        /\boperator console is\s+read-only and advisory\b/i,
      ],
      [
        "automatic mandate and request",
        /\bautomatically create\b[^.]*\bPayer-signed mandate\b[^.]*\bRequestor-signed request\b/i,
      ],
      [
        "two role sessions",
        /\bstart exactly two role sessions\b/i,
      ],
      [
        "four-address funding action",
        /\bfund the four displayed addresses\b/i,
      ],
      [
        "no post-funding Hermes message",
        /\bNo additional Hermes message is required after operator funding\./,
      ],
      [
        "Payer exact terminal role completion",
        PAYER_TERMINAL_ROLE_JSON,
      ],
      [
        "Requestor exact terminal role completion",
        REQUESTOR_TERMINAL_ROLE_JSON,
      ],
      ["one preflight for both runs", /\bone\b[^.]*\bpreflight\b[^.]*\bboth runs\b/i],
      ["one token per role", /\bone token per role\b[^.]*\bboth runs\b/i],
      [
        "physical attestation boundary",
        /\bPhysical separation\b[^.]*\battested\b[^.]*\bnot cryptographically proven\b/i,
      ],
      ["change invalidation", /\bcode or prompt change\b[^.]*\baborts the release\b/i],
      [
        "reachable numeric relay",
        /\bRELAY_ADVERTISED_IP\b[^.\n]*\bnumeric IP\b[^.\n]*\breachable by both role computers\b/i,
      ],
      [
        "reachable numeric relay",
        /\b127\.0\.0\.1\b[^.\n]*\bmust not be the advertised relay address\b/i,
      ],
      [
        "all-interface relay bind",
        /\bRELAY_LISTEN_HOST=0\.0\.0\.0\b[^.\n]*\ball-interface bind\b/i,
      ],
      [
        "advertised relay bind default",
        /--host "\$\{RELAY_LISTEN_HOST:-\$RELAY_ADVERTISED_IP\}"/,
      ],
      [
        "relay certificate IP SAN",
        /\bsubjectAltName=IP:\$RELAY_ADVERTISED_IP\b/,
      ],
      [
        "relay certificate fingerprint",
        /\bRELAY_TLS_FINGERPRINT=.*openssl x509\b/,
      ],
      [
        "coordinator relay URL",
        /\bhttps:\/\/\$RELAY_ADVERTISED_IP:\$RELAY_PORT\b/,
      ],
      [
        "0700 operator and release roots",
        /\bchmod 0700 "\$BILATERAL_OPERATOR_ROOT" "\$BILATERAL_RELEASE_ROOT"/,
      ],
      [
        "0700 relay state",
        /\bchmod 0700 "\$BILATERAL_RELEASE_ROOT\/relay-state"/,
      ],
      [
        "0600 RPC URL file",
        /\btest "\$\(stat -f '%Lp' "\$SEPOLIA_RPC_URL_FILE"\)" = "600"/,
      ],
      [
        "repo-private RPC URL file",
        /\bexport SEPOLIA_RPC_URL_FILE="\$REPOSITORY_ROOT\/\.context\/bilateral-live-2026-07-28\/sepolia-rpc\.url"/,
      ],
      [
        "repo-private RPC URL regular file",
        /\btest -f "\$SEPOLIA_RPC_URL_FILE"/,
      ],
      [
        "repo-private RPC URL nonempty file",
        /\btest -s "\$SEPOLIA_RPC_URL_FILE"/,
      ],
      [
        "repo-private RPC URL mode",
        /\btest "\$\(stat -f '%Lp' "\$SEPOLIA_RPC_URL_FILE"\)" = "600"/,
      ],
      [
        "prepared repo-private RPC URL",
        /\balready prepared repo-private `\$REPOSITORY_ROOT\/\.context\/bilateral-live-2026-07-28\/sepolia-rpc\.url`/,
      ],
      [
        "private launch manifest delivery",
        /\bpayer\.launch\.json\b[^.\n]*\bonly to Payer\b/i,
      ],
      [
        "signed discovery only Requestor",
        /\bRequestor receives only\b[^.\n]*\bsigned discovery\s+URL\b/i,
      ],
      [
        "time-bounded private launch material",
        /\bPrivate launch material expires after 60 minutes\b/i,
      ],
      [
        "funding record capture",
        /\bsave\b[^.\n]*\bfunding-addresses\.json\b[^.\n]*\bmode-`0600` record file\b/i,
      ],
      [
        "funding budget",
        /\b0\.05 Sepolia ETH\b[^.\n]*\bexactly four `0\.01 Sepolia ETH` allocations\b/i,
      ],
      [
        "participant gas boundary",
        /\bdemo transactions spend gas from participant balances\b[^.\n]*\bnever move the represented USD payment\b/i,
      ],
      [
        "recovery reserve",
        /\bsecond `0\.05` drip\b[^.\n]*\brecovery reserve\b/i,
      ],
      [
        "unrecoverable write reset",
        /\bfresh invitations and a newly reviewed release\b/i,
      ],
      [
        "verifier-only authorization",
        /\bonly a fresh aggregate verifier may output\s+`AUTHORIZED`/i,
      ],
      [
        "rehearsal-ready versus live-validated",
        /\brehearsal-ready\b[^.]*\blive-validated\b/i,
      ],
      [
        "stable operator key ID",
        /\bexport OPERATOR_KEY_ID="bilateral-demo-2026-07-28"/,
      ],
      [
        "initial provisioning keygen boundary",
        /\bInitial provisioning only\b/i,
      ],
      [
        "no rerun keygen",
        /\bFor a demo-day rerun, do not run keygen\b/i,
      ],
      [
        "reuse committed operator key pair",
        /\bverify and reuse the existing matching committed operator key pair\b/i,
      ],
      [
        "public operator key commit",
        /\bCommit only `docs\/operator-keys\/\$OPERATOR_KEY_ID\.pub`/,
      ],
      [
        "verify before release freeze",
        /\brun `npm run verify`, then freeze `BILATERAL_REPOSITORY_SHA`/i,
      ],
      [
        "relay terminal",
        /\bTerminal 1 - relay\b/i,
      ],
      [
        "coordinator terminal",
        /\bTerminal 2 - coordinator\b/i,
      ],
      [
        "relay readiness before coordinator",
        /\bStart Terminal 2 only after Terminal 1 prints relay readiness\b/i,
      ],
      [
        "coordinator-owned funding record",
        /\bexport FUNDING_RECORD_FILE="\$BILATERAL_RELEASE_ROOT\/funding-addresses\.json"/,
      ],
      [
        "coordinator-owned funding record",
        /\bcoordinator-owned `\$BILATERAL_RELEASE_ROOT\/funding-addresses\.json`/,
      ],
      [
        "repository root",
        /\bexport REPOSITORY_ROOT="\$\(pwd\)"/,
      ],
      [
        "repo-private treasury keystore",
        /\bexport SEPOLIA_TREASURY_KEYSTORE="\$REPOSITORY_ROOT\/\.context\/sepolia-funding\/funding-wallet\.json"/,
      ],
      [
        "repo-private treasury public metadata",
        /\bexport SEPOLIA_TREASURY_PUBLIC_METADATA="\$REPOSITORY_ROOT\/\.context\/sepolia-funding\/funding-wallet\.public\.json"/,
      ],
      [
        "strict private treasury files",
        /\bstrict private files\b/i,
      ],
      [
        "recovery appendix",
        /\bOperator-authorized recovery appendix\b/i,
      ],
      ["Phase -1", /\bPhase -1\b/i],
      ["four funded addresses", /\bfour funded addresses\b/i],
      ["user/operator-only actions", /\buser\/operator-only\b/i],
      [
        "funding band",
        /\b0\.005\b[^.\n]*\b0\.02\b[^.\n]*Sepolia ETH/i,
      ],
      [
        "registration before descriptor",
        /\bregistration\b[^.]*\bbefore\b[^.]*\bdescriptor\b/i,
      ],
      [
        "token reuse",
        /\bsame\b[^.]*\bClockchain token\b[^.]*\bpreflight\b[^.]*\btimed role\b/i,
      ],
      ["synchronized start", /\bsynchronized start\b/i],
      [
        "watcher command",
        /\bnode scripts\/watch-bilateral-session\.mjs\b/,
      ],
      [
        "verifier command",
        /\bnode scripts\/verify-bilateral-results\.mjs\b/,
      ],
      [
        "verdict completion marker",
        /\.bilateral-verdict\.complete\.json/,
      ],
      ["recovery rules", /\bRecovery rules\b/i],
      ["abort conditions", /\bAbort conditions\b/i],
    ],
    "docs/runbooks/bilateral-demo-quick-start.md": [
      [
        "exact section order",
        /^## Before everyone starts[\s\S]*^## Fixed role assignment[\s\S]*^## Human operator checklist[\s\S]*^## Payer checklist[\s\S]*^## Requestor checklist[\s\S]*^## Funding and execution order[\s\S]*^## What counts as success[\s\S]*^## Immediate stop conditions/m,
      ],
      [
        "operator-provided reviewed release SHA",
        /\boperator-provided exact reviewed\s+40-character immutable repository SHA\s+in `BILATERAL_REPOSITORY_SHA`/i,
      ],
      [
        "release relationship",
        /\bexternal public page later pins the final\s+immutable SHA\b[\s\S]*\bdoes not alter\s+executable runtime bytes\b/i,
      ],
      [
        "Node.js 22 on all computers",
        /\bNode\.js 22\b[^.\n]*\ball three computers\b/i,
      ],
      [
        "clean exact SHA on all computers",
        /\bclean detached checkout\b[^.]*\boperator-provided SHA\b[^.]*\ball\s+three computers\b[\s\S]*\bgit clone --no-checkout\b[\s\S]*\bgit fetch --depth 1\b[\s\S]*\bgit checkout --detach\b[\s\S]*\bnpm ci --ignore-scripts\b/i,
      ],
      [
        "fixed operator role",
        /Human operator[^.\n]*\brelay\b[^.\n]*\bcoordinator\b[^.\n]*\bread-only console\b[^.\n]*\bfunding\b[^.\n]*\bwatcher\b[^.\n]*\bfresh aggregate verifier\b/i,
      ],
      [
        "public live-demo helper",
        /\bhttps:\/\/clockchain-research\.vercel\.app\/handshake\/run\b/,
      ],
      [
        "exact startup order",
        /\brelay -> coordinator -> console -> funding readiness -> production bootstrap broker -> Payer raw-TCP tunnel -> Payer MCP\/supervisor -> wait PAYER_MCP_READY -> publish signed discovery -> Requestor request_payment -> HANDSHAKE_REQUIRED -> wait pending bootstrap claim -> approve exact claim fingerprint -> Requestor supervisor continues -> funding batch when record ready -> PROPOSED -> ACCEPTED -> ACKNOWLEDGED -> fresh verification -> AUTHORIZED\b/,
      ],
      [
        "requestor discovery publisher command",
        /\bnpm --silent run bilateral:publish-requestor-discovery --/,
      ],
      [
        "Payer-owned MCP only",
        /\bPayer-owned TLS MCP `\/mcp` endpoint\b/i,
      ],
      [
        "read-only advisory console",
        /\bread-only advisory\s+operator console\b/i,
      ],
      [
        "automatic mandate and request",
        /\bautomatically create\b[^.]*\bPayer-signed mandate\b[^.]*\bRequestor-signed request\b/i,
      ],
      [
        "four exact allocations",
        /\bexactly four\s+`0\.01 Sepolia ETH` allocations\b/i,
      ],
      [
        "rehearsal-ready versus live-validated",
        /\brehearsal-ready\b[^.]*\blive-validated\b/i,
      ],
      [
        "fixed Payer role",
        /\bStakeholder 1\b[^.\n]*\bPayer\b[^.\n]*\bpayer\b/i,
      ],
      [
        "fixed Requestor role",
        /\bStakeholder 2\b[^.\n]*\bRequestor\b[^.\n]*\brequestor\b/i,
      ],
      [
        "relay before coordinator",
        /\brelay\b[^.\n]*\bbefore\b[^.\n]*\bcoordinator\b/i,
      ],
      [
        "wait for both roles before launch manifest expiry",
        /\bwait\b[^.\n]*\bboth role computers\b[^.\n]*\bready\b[^.\n]*\bmanifests expire after 60 minutes\b/i,
      ],
      [
        "payer manifest only Payer",
        /\bpayer\.launch\.json\b[^.\n]*\bonly Payer\b/i,
      ],
      [
        "signed discovery only Requestor",
        /\bsigned discovery URL\b[^.\n]*\bRequestor\b/i,
      ],
      [
        "coordinator-owned funding record",
        /\bcoordinator-owned\b[^.\n]*\bfunding-addresses\.json\b/i,
      ],
      [
        "funding command",
        /\bnpm run bilateral:fund\b/i,
      ],
      [
        "no post-funding Hermes message",
        /\bNo additional Hermes message is required after operator funding\./,
      ],
      [
        "Payer exact terminal role completion",
        PAYER_TERMINAL_ROLE_JSON,
      ],
      [
        "Requestor exact terminal role completion",
        REQUESTOR_TERMINAL_ROLE_JSON,
      ],
      [
        "verdict sequence",
        /\bPROPOSED\b[\s\S]*\bACCEPTED\b[\s\S]*\bACKNOWLEDGED\b[\s\S]*\boperator verification\b[\s\S]*\bAUTHORIZED\b/i,
      ],
      [
        "exactly three independently verifiable anchors",
        /\bexactly three independently verifiable Clockchain anchors\b/i,
      ],
      [
        "fresh aggregate verifier authorization",
        /\bonly a fresh aggregate verifier\b[^.\n]*\bAUTHORIZED\b/i,
      ],
      ["payment moved false", /\bpaymentMoved:false\b/],
      [
        "evidence stop conditions",
        /\bmissing, duplicate, reordered, expired, malformed, or mismatched evidence\b/i,
      ],
      [
        "secrets and live evidence prohibition",
        /\bno secrets\b[^.\n]*\blive evidence\b[^.\n]*\bmanifest contents\b/i,
      ],
      [
        "no physical rehearsal passed claim",
        /\bdo not claim physical rehearsal passed\b/i,
      ],
    ],
    "docs/runbooks/bilateral-demo-live-handoff.md": [
      [
        "no retired executable release SHA",
        new RegExp(`^(?![\\s\\S]*\\b${RETIRED_LIVE_HANDOFF_RELEASE_SHA}\\b)[\\s\\S]*$`),
      ],
      [
        "operator-provided repository SHA",
        /`BILATERAL_REPOSITORY_SHA` is the operator-provided exact reviewed\s+40-character SHA\b/i,
      ],
      [
        "canonical helper URL",
        new RegExp(LIVE_HANDOFF_HELPER_URL.replaceAll(".", "\\.")),
      ],
      [
        "public treasury address",
        new RegExp(LIVE_HANDOFF_TREASURY_ADDRESS, "i"),
      ],
      [
        "clean detached checkout on all computers",
        /\bclean detached checkout\b[\s\S]*\bNode\.js 22\b[\s\S]*\bnpm ci --ignore-scripts\b[\s\S]*\ball three computers\b/i,
      ],
      [
        "operator private kit path",
        /\.context\/bilateral-live-2026-07-28\//,
      ],
      [
        "treasury private kit path",
        /\.context\/sepolia-funding\//,
      ],
      ["0700/0600 permissions", /\b0700\b[\s\S]*\b0600\b/],
      [
        "secret prohibition",
        /\bNever print, read, paste, or inspect\s+private contents with an agent\b[\s\S]*\bNo token, invitation, capability, private key,\s+TLS key, RPC URL, or live evidence value\b/i,
      ],
      [
        "safe RPC file read",
        /readFile\(process\.env\.SEPOLIA_RPC_URL_FILE/,
      ],
      [
        "safe balance JSON-RPC calls",
        /\beth_chainId\b[\s\S]*\beth_getBalance\b[\s\S]*\beth_getTransactionCount\b/,
      ],
      [
        "no RPC URL printing",
        /\bmust not print the RPC URL\b/i,
      ],
      [
        "sanitized treasury preflight failure",
        /try \{\n  const rpcUrl = \(await readFile\(process\.env\.SEPOLIA_RPC_URL_FILE[\s\S]*\bSAFE_SEPOLIA_TREASURY_CHECK_FAILED\b/,
      ],
      [
        "decimal chain ID and nonce",
        /chainId: BigInt\(chainIdHex\)\.toString\(10\)[\s\S]*nonce: BigInt\(nonceHex\)\.toString\(10\)/,
      ],
      [
        "routable relay placeholder",
        /\b192\.0\.2\.10` is a documentation-only placeholder\b[\s\S]*\breplace it with a numeric LAN IP reachable by both role computers\b[\s\S]*\b127\.0\.0\.1\b[\s\S]*\bdocumentation range\b[\s\S]*\bnon-routable address\b/i,
      ],
      [
        "relay certificate generation",
        /\bopenssl req -x509 -newkey rsa:3072 -nodes\b[\s\S]*\bsubjectAltName=IP:\$RELAY_ADVERTISED_IP\b[\s\S]*\bRELAY_TLS_FINGERPRINT="\$\(openssl x509\b/,
      ],
      [
        "Payer MCP exact IP",
        /\bexport PAYER_MCP_HOST="127\.0\.0\.1"[\s\S]*\bexport PAYER_MCP_PUBLIC_IP="\$\{PAYER_MCP_PUBLIC_IP:\?set operator-provided AWS Elastic IP\}"/i,
      ],
      [
        "Payer MCP certificate generation",
        /\bPAYER_MCP_TLS_ROOT="\$\{PAYER_SUPERVISOR_STATE%\/\}\.payer-mcp-tls"[\s\S]*\bmkdir -p "\$PAYER_MCP_TLS_ROOT"[\s\S]*\bsubjectAltName=IP:\$PAYER_MCP_PUBLIC_IP\b[\s\S]*chmod 0600 "\$PAYER_MCP_TLS_CERTIFICATE"[\s\S]*PAYER_MCP_TLS_FINGERPRINT="\$\(openssl x509 -in "\$PAYER_MCP_TLS_CERTIFICATE" -outform DER \| openssl dgst -sha256 -binary \| xxd -p -c 256\)"[\s\S]*\bgrep -Eq '\^\[0-9a-f\]\{64\}\$'[\s\S]*\bpreserves supervisor restart scanning\b/i,
      ],
      [
        "exact startup order",
        /\brelay -> coordinator -> console -> funding readiness -> production bootstrap broker -> Payer raw-TCP tunnel -> Payer MCP\/supervisor -> wait PAYER_MCP_READY -> publish signed discovery -> Requestor request_payment -> HANDSHAKE_REQUIRED -> wait pending bootstrap claim -> approve exact claim fingerprint -> Requestor supervisor continues -> funding batch when record ready -> PROPOSED -> ACCEPTED -> ACKNOWLEDGED -> fresh verification -> AUTHORIZED\b/,
      ],
      [
        "requestor discovery publisher command",
        /\bnpm --silent run bilateral:publish-requestor-discovery --/,
      ],
      [
        "Payer-owned MCP only",
        /\bPayer-owned TLS MCP `\/mcp` endpoint\b/i,
      ],
      [
        "coordinator-owned funding record",
        /\bexport FUNDING_RECORD_FILE="\$BILATERAL_RELEASE_ROOT\/funding-addresses\.json"/,
      ],
      [
        "four-address allocation",
        /\bfunds exactly four freshly generated addresses with\s+`0\.01 Sepolia ETH` each\b/i,
      ],
      [
        "no post-funding Hermes message",
        /\bNo additional Hermes message is required after operator funding\./,
      ],
      [
        "Payer exact terminal role completion",
        PAYER_TERMINAL_ROLE_JSON,
      ],
      [
        "Requestor exact terminal role completion",
        REQUESTOR_TERMINAL_ROLE_JSON,
      ],
      [
        "safe 0.05 budget",
        /\b0\.05 Sepolia ETH\b[\s\S]*\bsufficient\s+only\s+if\s+preflight\s+still\s+reports\s+balance\/nonce\s+safe\b/i,
      ],
      [
        "no manual address copying",
        /\bno manual address\s+copying\b/i,
      ],
      [
        "commercial intent marker",
        /\bPAYER_MANDATE_READY\b[\s\S]*\bPAYMENT_REQUEST_READY\b[\s\S]*\bPAYMENT_REQUEST_MATCHED\b/,
      ],
      [
        "three protocol anchors",
        /Payer `PROPOSED`[\s\S]*Requestor `ACCEPTED`[\s\S]*Payer `ACKNOWLEDGED`/,
      ],
      [
        "marker-complete role files",
        /\bmarker-complete role files\b[\s\S]*\bverifier files\b/i,
      ],
      [
        "verifier-only AUTHORIZED",
        /`AUTHORIZED` only from fresh\s+aggregate verifier/i,
      ],
      ["paymentMoved:false", /\bpaymentMoved:false\b/],
      [
        "release relationship",
        /\bexternal public page later pins the final immutable SHA\b[\s\S]*\bdoes not alter\s+executable runtime bytes\b/i,
      ],
      [
        "advisory console/relay",
        /\bRelay\/watcher\/console fields are advisory\b/,
      ],
      [
        "evidence recheck",
        /SEPOLIA_RPC_URL="\$\(node --input-type=module[\s\S]*process\.stdout\.write\(\(await readFile\(process\.env\.SEPOLIA_RPC_URL_FILE[\s\S]*node scripts\/verify-bilateral-results\.mjs[\s\S]*--clockchain-token-file "\$OPERATOR_CLOCKCHAIN_TOKEN_FILE"[\s\S]*--rpc-url "\$SEPOLIA_RPC_URL"/,
      ],
      [
        "readiness distinction",
        /\bimplementation-complete and rehearsal-ready\b[\s\S]*only a\s+successful 3-computer run with exact fresh evidence may be called `live-demo validated`/i,
      ],
      [
        "handoff action boundary",
        /\buser eventual actions are only funding four generated addresses and\s+starting two physical role sessions\b[\s\S]*\boperator owns everything else\b/i,
      ],
      [
        "ignored private artifacts",
        /\bPrivate\/live artifacts remain ignored\/outside Git\b/,
      ],
      [
        "stop list",
        /\bmissing, duplicate, reordered, expired, malformed,\s+mismatched\b[\s\S]*\bdirty\/wrong SHA\b[\s\S]*\bwrong Node\b[\s\S]*\bwrong role\/manifest\b[\s\S]*\bsecret exposure\b[\s\S]*\bchanged TLS fingerprint\/relay binding\b[\s\S]*\bfunding mismatch\/nonzero recipient nonce\b[\s\S]*\bnonzero process exit\b[\s\S]*\babsent\s+completion marker\b[\s\S]*\bany authority claim from relay\/watcher\/console\/coordinator\/role\b/i,
      ],
    ],
  };
  for (const [label, pattern] of pathRequirements[relativePath] ?? []) {
    if (!pattern.test(contents)) {
      failures.push(
        `${relativePath}: missing bilateral ${label}.`,
      );
    }
  }
  if (relativePath === "docs/runbooks/bilateral-demo-day.md") {
    const hasExactOrderedAnchors =
      /\bexactly\s+three\s+ordered\s+Clockchain\s+anchors\b/i.test(contents);
    const hasIndependentVerification =
      /\bindependently\s+(?:refetching|verif\w*)\s+all\s+three\s+Clockchain\s+anchors\b/i.test(
        contents,
      );
    const permitsOtherCount =
      /\b(?:at\s+least\s+three|three\s+or\s+more|any\s+number\s+of)\s+(?:ordered\s+)?Clockchain\s+anchors\b/i.test(
        contents,
      );
    if (
      !hasExactOrderedAnchors ||
      !hasIndependentVerification ||
      permitsOtherCount
    ) {
      failures.push(
        `${relativePath}: primary runbook must require exactly three independently verifiable ordered Clockchain anchors and reject any other count.`,
      );
    }
  }
  const requiredRoleCommands = {
    "prompts/run-requestor-bilateral-demo.md": [
      ["exact role CLI", REQUESTOR_ROLE_COMMAND],
    ],
    "prompts/run-payer-bilateral-demo.md": [
      ["exact role CLI", PAYER_ROLE_COMMAND],
    ],
    "docs/runbooks/bilateral-demo-day.md": [
      [
        "exact invitation creation CLI",
        INVITATION_CREATION_COMMAND,
      ],
      ["exact operator keygen CLI", OPERATOR_KEYGEN_COMMAND],
      ["exact token mint CLI", REQUESTOR_TOKEN_COMMAND],
      ["exact token mint CLI", PAYER_TOKEN_COMMAND],
      ["exact token mint CLI", OPERATOR_TOKEN_COMMAND],
      [
        "exact distributed preflight CLI",
        PREFLIGHT_PREPARE_COMMAND,
      ],
      [
        "exact distributed preflight CLI",
        REQUESTOR_PREFLIGHT_COMMAND,
      ],
      [
        "exact distributed preflight CLI",
        PAYER_PREFLIGHT_COMMAND,
      ],
      [
        "exact distributed preflight CLI",
        PREFLIGHT_AGGREGATE_COMMAND,
      ],
      [
        "exact registration CLI",
        REQUESTOR_REGISTRATION_COMMAND,
      ],
      [
        "exact registration CLI",
        PAYER_REGISTRATION_COMMAND,
      ],
      ["exact prompt hash CLI", PROMPT_HASH_COMMAND],
      ["exact descriptor creation CLI", SESSION_CREATE_COMMAND],
      ["exact watcher CLI", WATCHER_COMMAND],
      ["exact role CLI", REQUESTOR_ROLE_COMMAND],
      ["exact role CLI", PAYER_ROLE_COMMAND],
      ["exact verifier CLI", VERIFIER_COMMAND],
      ["reusable bilateral funding command", FUNDING_COMMAND],
    ],
    "docs/runbooks/bilateral-demo-live-handoff.md": [
      ["exact relay CLI", RELAY_COMMAND],
      ["exact coordinator CLI", COORDINATOR_COMMAND],
      ["exact console CLI", CONSOLE_COMMAND],
      ["exact Payer supervisor CLI", PAYER_SUPERVISOR_COMMAND],
      ["exact Requestor request-payment CLI", REQUESTOR_REQUEST_PAYMENT_COMMAND],
      ["reusable bilateral funding command", FUNDING_COMMAND],
      ["exact verifier CLI", VERIFIER_COMMAND],
    ],
  };
  for (
    const [label, command] of
      requiredRoleCommands[relativePath] ?? []
  ) {
    if (!contents.includes(command)) {
      failures.push(
        `${relativePath}: missing ${label}.`,
      );
    }
  }
  if (
    /--private-key-file|--payer-token-file|--payee-token-file/.test(
      contents,
    )
  ) {
    failures.push(
      `${relativePath}: contains obsolete bilateral CLI flag.`,
    );
  }
  if (relativePath === "docs/runbooks/bilateral-demo-day.md") {
    const primary = contents.split(
      /^## Operator-authorized recovery appendix$/m,
      1,
    )[0];
    if (
      /\b(?:--host|--relay-url)\s+(?:"|\$?\{?)?127\.0\.0\.1\b/.test(
        primary,
      )
    ) {
      failures.push(
        `${relativePath}: primary flow must not advertise localhost as the two-machine relay endpoint.`,
      );
    }
    if (
      /\bOPERATOR_KEY_ID="bilateral-demo-\$BILATERAL_REPOSITORY_SHA"/.test(
        primary,
      )
    ) {
      failures.push(
        `${relativePath}: primary flow must use a stable operator key ID before freezing the release SHA.`,
      );
    }
    if (
      /printf '%s\\n' "\$SEPOLIA_RPC_URL" > "\$SEPOLIA_RPC_URL_FILE"/.test(
        primary,
      )
    ) {
      failures.push(
        `${relativePath}: primary flow must have no ambient RPC URL rewrite; use the prepared repo-private RPC URL file instead of rewriting it from ambient SEPOLIA_RPC_URL.`,
      );
    }
    const ordered = [
      [
        "stable operator key ID",
        'export OPERATOR_KEY_ID="bilateral-demo-2026-07-28"',
      ],
      [
        "initial provisioning boundary",
        "Initial provisioning only",
      ],
      [
        "operator keygen",
        "node scripts/create-session.mjs keygen",
      ],
      [
        "public operator key commit",
        "Commit only `docs/operator-keys/$OPERATOR_KEY_ID.pub`",
      ],
      [
        "verify before release freeze",
        "run `npm run verify`, then freeze `BILATERAL_REPOSITORY_SHA`",
      ],
      [
        "release SHA freeze",
        'export BILATERAL_REPOSITORY_SHA="$(git rev-parse HEAD)"',
      ],
    ];
    const positions = ordered.map(([label, marker]) => [
      label,
      primary.indexOf(marker),
    ]);
    if (
      positions.some(([, index]) => index === -1) ||
      positions.some(([, index], offset) =>
        offset > 0 && index <= positions[offset - 1][1],
      )
    ) {
      failures.push(
        `${relativePath}: primary flow must keygen, commit the public key, verify, then freeze the release SHA in that order.`,
      );
    }
  }
  if (relativePath === "docs/runbooks/bilateral-demo-live-handoff.md") {
    const contentsWithoutPermittedReadiness = contents.replace(
      /Only a\s+successful 3-computer run with exact fresh evidence may be called `live-demo validated`/i,
      "",
    );
    if (
      /\b(?:is|as|called|counts as)\s+`?live-demo validated`?\b/i.test(
        contentsWithoutPermittedReadiness,
      )
    ) {
      failures.push(
        `${relativePath}: missing bilateral readiness distinction.`,
      );
    }
    if (/payload\.error\.message|\$\{method\}/.test(contents)) {
      failures.push(
        `${relativePath}: missing bilateral sanitized treasury preflight failure.`,
      );
    }
    if (
      /\bexport\s+SEPOLIA_RPC_URL=https?:\/\//i.test(contents)
    ) {
      failures.push(
        `${relativePath}: missing bilateral safe verifier RPC URL derivation.`,
      );
    }
  }
  return failures;
}

function bilateralNamingAndMovementFailures(
  relativePath,
  contents,
) {
  const failures = [];
  if (
    /\bRequestor(?:,|\s+is|\s+as|\s+[—-])[^.\n]*\bpayer\b(?!')/i.test(
      contents,
    )
  ) {
    failures.push(
      `${relativePath}: contains legacy Requestor payer role mapping.`,
    );
  }
  if (
    /\bPayer(?:,|\s+is|\s+as|\s+[—-])[^.\n]*\bpayee\b/i.test(
      contents,
    )
  ) {
    failures.push(
      `${relativePath}: contains legacy Payer payee role mapping.`,
    );
  }
  const movementPattern =
    /\bauthorization\b[^.]{0,120}\b(?:move|moves|moved|send|sends|sent|settle|settles|settled|transfer|transfers|transferred)\b[^.]{0,120}\bpayment\b/gi;
  if (
    claimSegments(contents).some((segment) =>
      [...segment.matchAll(movementPattern)].some(
        (match) =>
          !EXPLICIT_LIMITATION_PATTERN.test(match[0]),
      ),
    )
  ) {
    failures.push(
      `${relativePath}: claims authorization moved payment.`,
    );
  }
  return failures;
}

function bilateralCompatibilityFailures(
  relativePath,
  contents,
) {
  const failures = bilateralNamingAndMovementFailures(
    relativePath,
    contents,
  );
  if (!/\bcompatibility only\b/i.test(contents)) {
    failures.push(
      `${relativePath}: missing compatibility-only boundary.`,
    );
  }
  if (!/\brun-requestor-bilateral-demo\.md\b/.test(contents)) {
    failures.push(
      `${relativePath}: missing canonical Requestor prompt migration target.`,
    );
  }
  if (/\b(?:npm|node)\s+run\b|\bnode\s+(?:bin|scripts)\//.test(contents)) {
    failures.push(
      `${relativePath}: compatibility path must not contain executable role commands.`,
    );
  }
  return failures;
}

function packageContractFailures(contents) {
  try {
    const value = JSON.parse(contents);
    const expected = Object.freeze({
      "bilateral:coordinator": "node bin/handshake-coordinator.mjs",
      "bilateral:relay": "node bin/handshake-relay.mjs",
      "bilateral:supervisor": "node bin/handshake-supervisor.mjs",
    });
    const failures = [];
    for (const [name, command] of Object.entries(expected)) {
      if (value?.scripts?.[name] !== command) {
        failures.push(
          `package.json: missing exact ${name} production entrypoint.`,
        );
      }
      if (/fake|test/i.test(String(value?.scripts?.[name] ?? ""))) {
        failures.push(
          `package.json: ${name} must not select a fake adapter.`,
        );
      }
    }
    return failures;
  } catch {
    return ["package.json: must be valid JSON."];
  }
}

function readmeRoleplayFailures(contents) {
  const failures = [];
  if (
    /\b(?:roughly|about|approximately)\s+\d+\s*(?:-|–|to)\s*\d+\s+seconds\b/i.test(
      contents,
    )
  ) {
    failures.push(
      "README.md: bilateral readiness documentation must not make live timeline claims.",
    );
  }
  if (!/\breusable Sepolia treasury\b/i.test(contents)) {
    failures.push(
      "README.md: missing reusable Sepolia treasury boundary.",
    );
  }
  if (!/\bStakeholder 1\b[^.]*\bPayer\b[^.]*\bpayer\b/i.test(contents)) {
    failures.push(
      "README.md: missing Stakeholder 1 Payer role mapping.",
    );
  }
  if (!/\bStakeholder 2\b[^.]*\bRequestor\b[^.]*\brequestor\b/i.test(contents)) {
    failures.push(
      "README.md: missing Stakeholder 2 Requestor role mapping.",
    );
  }
  if (
    !contents.includes(
      "relay -> coordinator -> console -> funding readiness -> production bootstrap broker -> Payer raw-TCP tunnel -> Payer MCP/supervisor -> wait PAYER_MCP_READY -> publish signed discovery -> Requestor request_payment -> HANDSHAKE_REQUIRED -> wait pending bootstrap claim -> approve exact claim fingerprint -> Requestor supervisor continues -> funding batch when record ready -> PROPOSED -> ACCEPTED -> ACKNOWLEDGED -> fresh verification -> AUTHORIZED",
    )
  ) {
    failures.push(
      "README.md: missing exact bilateral startup control order.",
    );
  }
  if (!/\bnpm run bilateral:console --/.test(contents)) {
    failures.push(
      "README.md: missing bilateral console entrypoint.",
    );
  }
  if (
    !contents.includes(
      "https://clockchain-research.vercel.app/handshake/run",
    )
  ) {
    failures.push(
      "README.md: missing public live-demo helper URL.",
    );
  }
  if (!/\brehearsal-ready\b[^.]*\blive-validated\b/i.test(contents)) {
    failures.push(
      "README.md: missing rehearsal-ready versus live-validated boundary.",
    );
  }
  if (
    !/\bexactly four\s+`0\.01 Sepolia ETH` allocations\b/i.test(
      contents,
    )
  ) {
    failures.push(
      "README.md: missing exact four-address Sepolia allocation.",
    );
  }
  failures.push(
    ...bilateralNamingAndMovementFailures(
      "README.md",
      contents,
    ),
  );
  return failures;
}

function isPlainRoot(rootDirectory) {
  return (
    typeof rootDirectory === "string" &&
    rootDirectory.length > 0 &&
    !rootDirectory.includes("\0") &&
    isAbsolute(rootDirectory)
  );
}

function containedBy(rootDirectory, target) {
  const fromRoot = relative(rootDirectory, target);
  return !(
    fromRoot === ".." ||
    fromRoot.startsWith("../") ||
    isAbsolute(fromRoot)
  );
}

async function canonicalRoot(rootDirectory) {
  if (!isPlainRoot(rootDirectory)) {
    return null;
  }

  try {
    const canonical = await realpath(rootDirectory);
    return (await lstat(canonical)).isDirectory()
      ? canonical
      : null;
  } catch {
    return null;
  }
}

async function canonicalRegularFile(rootDirectory, path) {
  try {
    const canonical = await realpath(path);
    if (!containedBy(rootDirectory, canonical)) {
      return null;
    }
    return (await lstat(canonical)).isFile()
      ? canonical
      : null;
  } catch {
    return null;
  }
}

function countOccurrences(contents, exact) {
  return tokenOccurrences(contents, exact).length;
}

function canonicalSafetyRemainder(relativePath, contents) {
  const failures = [];
  let remainder = contents;
  for (const { label, text } of
    CANONICAL_SAFETY_SECTIONS[relativePath] ?? []) {
    if (countOccurrences(contents, text) !== 1) {
      failures.push(
        `${relativePath}: canonical ${label} is missing or duplicated.`,
      );
    }
    remainder = remainder.replaceAll(text, "");
  }

  return { failures, remainder };
}

function claimSegments(contents) {
  return contents
    .replace(/\r?\n/g, " ")
    .split(CLAIM_BOUNDARY_PATTERN);
}

function claimedWithoutLimitation(segments, pattern) {
  return segments.some((segment) =>
    [...segment.matchAll(pattern)].some(
      (match) =>
        !EXPLICIT_LIMITATION_PATTERN.test(
          segment.slice(0, match.index),
        ),
    ),
  );
}

// A movement verb can precede the noun ("moves no scenario money"), so the
// limitation can sit inside the matched span rather than before it.
function claimsMoneyMovement(segments) {
  return segments.some((segment) =>
    [...segment.matchAll(MONEY_MOVEMENT_PATTERN)].some(
      (match) =>
        !EXPLICIT_LIMITATION_PATTERN.test(
          segment.slice(0, match.index),
        ) &&
        !EXPLICIT_LIMITATION_PATTERN.test(match[0]),
    ),
  );
}

function capabilityPattern(capability) {
  const escaped = capability.replace(
    /[.*+?^${}()|[\]\\]/g,
    "\\$&",
  );
  return new RegExp(`\\b${escaped}\\b`, "gi");
}

function presentCapabilityFailures(
  relativePath,
  segments,
  capabilities,
) {
  const failures = [];
  for (const capability of capabilities) {
    if (
      claimedWithoutLimitation(
        segments,
        capabilityPattern(capability),
      )
    ) {
      failures.push(
        `${relativePath}: mentions forbidden capability "${capability}" as a present claim.`,
      );
    }
  }
  return failures;
}

function contextualPresentClaimFailures(
  relativePath,
  contents,
) {
  return presentCapabilityFailures(
    relativePath,
    claimSegments(contents),
    CONTEXTUAL_PRESENT_CAPABILITIES,
  );
}

function nonofficialRegistryFailures(
  relativePath,
  contents,
) {
  const failures = [];
  for (const match of contents.matchAll(
    /\b0x[0-9a-fA-F]{40}\b/g,
  )) {
    if (
      match[0].toLowerCase() !==
        OFFICIAL_REGISTRY.toLowerCase() &&
      !(
        relativePath ===
          "docs/runbooks/bilateral-demo-live-handoff.md" &&
        match[0].toLowerCase() ===
          LIVE_HANDOFF_TREASURY_ADDRESS.toLowerCase()
      )
    ) {
      failures.push(
        `${relativePath}: references non-official registry address "${match[0]}".`,
      );
    }
  }
  return failures;
}

function supportingDocumentFailures(
  relativePath,
  contents,
) {
  const segments = claimSegments(contents);
  const failures = presentCapabilityFailures(
    relativePath,
    segments,
    SUPPORTING_PRESENT_CAPABILITIES,
  );

  if (claimsMoneyMovement(segments)) {
    failures.push(
      `${relativePath}: claims scenario money moves.`,
    );
  }

  for (const {
    label,
    pattern,
  } of SUPPORTING_REQUIRED_DISCLOSURES) {
    if (!pattern.test(contents)) {
      failures.push(
        `${relativePath}: missing required disclosure "${label}".`,
      );
    }
  }

  failures.push(
    ...nonofficialRegistryFailures(relativePath, contents),
  );

  return failures;
}

function structuredSafetyFailures(relativePath, contents) {
  const { failures, remainder } =
    canonicalSafetyRemainder(relativePath, contents);

  for (const capability of FORBIDDEN_PRESENT_CAPABILITIES) {
    const pattern = new RegExp(
      `\\b${capability.replace("-", "\\-")}\\b`,
      "i",
    );
    if (pattern.test(remainder)) {
      failures.push(
        `${relativePath}: mentions forbidden capability "${capability}" outside its canonical safety section.`,
      );
    }
  }

  if (/\bAgentDash\b/i.test(remainder)) {
    failures.push(
      `${relativePath}: contains "AgentDash" outside its canonical prohibition.`,
    );
  }
  if (/\bmoney\b/i.test(remainder)) {
    failures.push(
      `${relativePath}: contains "Money moves" outside its canonical no-money boundary.`,
    );
  }

  failures.push(
    ...nonofficialRegistryFailures(relativePath, remainder),
  );

  failures.push(
    ...contextualPresentClaimFailures(
      relativePath,
      remainder,
    ),
  );

  return failures;
}

function tokenBoundaryBefore(contents, index) {
  return (
    index === 0 ||
    TOKEN_BOUNDARY_PATTERN.test(contents[index - 1])
  );
}

function tokenBoundaryAfter(contents, index) {
  if (index === contents.length) {
    return true;
  }
  const next = contents[index];
  if (TOKEN_BOUNDARY_PATTERN.test(next)) {
    return true;
  }
  if (next !== "." && next !== ":") {
    return false;
  }
  const afterPunctuation = contents[index + 1];
  return (
    afterPunctuation === undefined ||
    TOKEN_BOUNDARY_PATTERN.test(afterPunctuation)
  );
}

function tokenOccurrences(contents, token) {
  const occurrences = [];
  let fromIndex = 0;
  while (fromIndex <= contents.length - token.length) {
    const index = contents.indexOf(token, fromIndex);
    if (index === -1) {
      break;
    }
    occurrences.push(index);
    fromIndex = index + token.length;
  }
  return occurrences;
}

function hasCanonicalToken(contents, token) {
  return tokenOccurrences(contents, token).some(
    (index) =>
      tokenBoundaryBefore(contents, index) &&
      tokenBoundaryAfter(contents, index + token.length),
  );
}

function extendedToken(contents, index, token) {
  let start = index;
  while (
    start > 0 &&
    TOKEN_EXTENSION_PATTERN.test(contents[start - 1])
  ) {
    start -= 1;
  }

  let end = index + token.length;
  while (
    end < contents.length &&
    TOKEN_EXTENSION_PATTERN.test(contents[end])
  ) {
    end += 1;
  }
  return contents.slice(start, end);
}

function noncanonicalTokenFailures(
  relativePath,
  contents,
) {
  const failures = [];
  for (const { token } of CANONICAL_DOCUMENT_TOKENS) {
    for (const index of tokenOccurrences(contents, token)) {
      if (
        tokenBoundaryBefore(contents, index) &&
        tokenBoundaryAfter(
          contents,
          index + token.length,
        )
      ) {
        continue;
      }
      const extension = extendedToken(
        contents,
        index,
        token,
      );
      failures.push(
        `${relativePath}: contains noncanonical extension "${extension}" of required token "${token}".`,
      );
    }
  }
  return failures;
}

function noncanonicalCommandFailures(
  relativePath,
  contents,
) {
  const failures = [];
  for (const match of contents.matchAll(
    /(?<!`)`([^`\r\n]+)`(?!`)/g,
  )) {
    const command = match[1];
    if (
      command.startsWith("npm run demo") &&
      command !== "npm run demo"
    ) {
      failures.push(
        `${relativePath}: contains noncanonical command "${command}" derived from "npm run demo".`,
      );
    }
  }

  const unfolded = contents.replace(
    /\\\r?\n[ \t]*/g,
    " ",
  );
  for (const match of unfolded.matchAll(
    /\bnpm run demo((?:[ \t]*(?:&&|\|\||[;|<>])|[ \t]+--?[^\s`])[^`\r\n]*)/g,
  )) {
    const command = `npm run demo${match[1]}`.trimEnd();
    failures.push(
      `${relativePath}: contains noncanonical command "${command}" derived from "npm run demo".`,
    );
  }

  return failures;
}

function failureCodeFailures(relativePath, contents) {
  if (relativePath !== FAILURE_CODE_DOCUMENT) {
    return [];
  }

  const failures = [];
  const documented = new Map();
  for (const match of contents.matchAll(
    FAILURE_CODE_ROW_PATTERN,
  )) {
    const code = match[1];
    if (documented.has(code)) {
      failures.push(
        `${relativePath}: documents failure code "${code}" more than once.`,
      );
      continue;
    }
    documented.set(code, Number(match[2]));
  }

  for (const [code, exitCode] of Object.entries(
    FAILURE_EXIT_CODES,
  )) {
    if (!documented.has(code)) {
      failures.push(
        `${relativePath}: missing failure code "${code}" from the failure code reference.`,
      );
      continue;
    }
    const documentedExit = documented.get(code);
    if (documentedExit !== exitCode) {
      failures.push(
        `${relativePath}: failure code "${code}" documents exit ${documentedExit} instead of ${exitCode}.`,
      );
    }
  }

  for (const code of documented.keys()) {
    if (!Object.hasOwn(FAILURE_EXIT_CODES, code)) {
      failures.push(
        `${relativePath}: documents unknown failure code "${code}".`,
      );
    }
  }

  return failures;
}

function markdownLinks(contents) {
  return [
    ...[...contents.matchAll(MARKDOWN_LINK_PATTERN)].map(
      (match) => match[1] ?? match[2],
    ),
    ...[
      ...contents.matchAll(
        MARKDOWN_REFERENCE_DEFINITION_PATTERN,
      ),
    ].map((match) => match[1] ?? match[2]),
  ];
}

function localLinkTarget(rootDirectory, documentPath, link) {
  if (
    typeof link !== "string" ||
    link.length === 0 ||
    link.startsWith("#") ||
    EXTERNAL_LINK_PATTERN.test(link)
  ) {
    return null;
  }

  const withoutFragment = link.split(/[?#]/, 1)[0];
  let decoded;
  try {
    decoded = decodeURIComponent(withoutFragment);
  } catch {
    return false;
  }
  if (
    decoded.length === 0 ||
    decoded.includes("\0") ||
    isAbsolute(decoded)
  ) {
    return false;
  }

  const target = resolve(
    rootDirectory,
    dirname(documentPath),
    decoded,
  );
  const fromRoot = relative(rootDirectory, target);
  if (
    fromRoot === ".." ||
    fromRoot.startsWith("../") ||
    isAbsolute(fromRoot)
  ) {
    return false;
  }
  return target;
}

async function linkFailures({
  rootDirectory,
  relativePath,
  contents,
}) {
  const failures = [];
  for (const link of markdownLinks(contents)) {
    const target = localLinkTarget(
      rootDirectory,
      relativePath,
      link,
    );
    if (target === null) {
      continue;
    }
    if (
      target === false ||
      !(await canonicalRegularFile(
        rootDirectory,
        target,
      ))
    ) {
      failures.push(
        `${relativePath}: broken relative link "${link}".`,
      );
    }
  }
  return failures;
}

function headingAnchors(contents) {
  const anchors = new Set();
  let fenceCharacter = null;

  for (const { body } of markdownLines(contents)) {
    const { content } = markdownContainerLine(body);
    const fence = content.match(/^ {0,3}(`{3,}|~{3,})/);
    if (fence) {
      if (fenceCharacter === null) {
        fenceCharacter = fence[1][0];
      } else if (fence[1][0] === fenceCharacter) {
        fenceCharacter = null;
      }
      continue;
    }
    if (fenceCharacter !== null) {
      continue;
    }

    const heading = content.match(
      /^ {0,3}#{1,6}[ \t]+([^\r\n]+?)[ \t]*#*[ \t]*$/,
    );
    if (!heading) {
      continue;
    }
    const anchor = heading[1]
      .toLowerCase()
      .replace(/[^\p{L}\p{N} \t-]/gu, "")
      .trim()
      .replace(/[ \t]+/g, "-");
    if (anchor.length > 0) {
      anchors.add(anchor);
    }
  }

  return anchors;
}

async function requiredLinkFragmentFailures({
  rootDirectory,
  relativePath,
  link,
}) {
  const fragment = link.slice(link.indexOf("#") + 1);
  if (!link.includes("#") || fragment.length === 0) {
    return [];
  }

  const target = localLinkTarget(
    rootDirectory,
    relativePath,
    link,
  );
  const path =
    typeof target === "string"
      ? await canonicalRegularFile(rootDirectory, target)
      : null;
  if (path === null) {
    return [];
  }

  let contents;
  try {
    contents = await readFile(path, "utf8");
  } catch {
    return [];
  }

  return headingAnchors(contents).has(fragment.toLowerCase())
    ? []
    : [
        `${relativePath}: required relative link "${link}" targets a missing heading.`,
      ];
}

function markdownLines(contents) {
  const lines = [];
  let start = 0;
  while (start < contents.length) {
    const newline = contents.indexOf("\n", start);
    const end =
      newline === -1 ? contents.length : newline + 1;
    const raw = contents.slice(start, end);
    const body = raw.endsWith("\n")
      ? raw
          .slice(0, -1)
          .replace(/\r$/, "")
      : raw;
    lines.push({ body, end, start });
    start = end;
  }
  return lines;
}

function markdownContainerLine(body) {
  let content = body;
  let blockquoteDepth = 0;

  while (true) {
    const prefix = content.match(/^ {0,3}>[ \t]?/);
    if (!prefix) {
      break;
    }
    content = content.slice(prefix[0].length);
    blockquoteDepth += 1;
  }

  return { blockquoteDepth, content };
}

function fencedBlocks(contents) {
  const lines = markdownLines(contents);
  const blocks = [];

  for (let index = 0; index < lines.length; index += 1) {
    const openingLine = markdownContainerLine(
      lines[index].body,
    );
    const opening = openingLine.content.match(
      /^( {0,3})(`{3,}|~{3,})([^\r\n]*)$/,
    );
    if (!opening) {
      continue;
    }

    const marker = opening[2];
    const markerCharacter = marker[0];
    const info = opening[3].trim();
    if (
      markerCharacter === "`" &&
      info.includes("`")
    ) {
      continue;
    }

    const contentStart = lines[index].end;
    let contentEnd = contents.length;
    let closed = false;
    let closingIndex = lines.length;
    for (
      let candidate = index + 1;
      candidate < lines.length;
      candidate += 1
    ) {
      const candidateLine = markdownContainerLine(
        lines[candidate].body,
      );
      const closing = candidateLine.content.match(
        /^( {0,3})(`+|~+)[ \t]*$/,
      );
      if (
        closing &&
        candidateLine.blockquoteDepth ===
          openingLine.blockquoteDepth &&
        closing[2][0] === markerCharacter &&
        closing[2].length >= marker.length
      ) {
        contentEnd = lines[candidate].start;
        closed = true;
        closingIndex = candidate;
        break;
      }
    }

    blocks.push({
      closed,
      content: contents.slice(contentStart, contentEnd),
      info: info.split(/[ \t]+/, 1)[0],
    });
    index = closed ? closingIndex : lines.length;
  }

  return blocks;
}

export function extractReadmePrompt(readme) {
  if (typeof readme !== "string") {
    return null;
  }
  const prompts = fencedBlocks(readme).filter(
    ({ info }) => info === "text",
  );
  return prompts.length === 1 && prompts[0].closed
    ? prompts[0].content
    : null;
}

function promptContractFailures(prompt) {
  const failures = [];
  if (prompt !== CANONICAL_PROMPT) {
    failures.push(
      "prompts/run-turnkey-demo.md: must match the complete canonical prompt byte-for-byte.",
    );
  }
  if (prompt.includes("HANDSHAKE_REPO_URL")) {
    failures.push(
      "prompts/run-turnkey-demo.md: must not accept a repository URL from the environment.",
    );
  }
  if (!prompt.includes(PROMPT_REPOSITORY_POLICY)) {
    failures.push(
      "prompts/run-turnkey-demo.md: canonical fixed-repository and immutable-ref policy is missing.",
    );
  }
  if (!prompt.includes(PROMPT_INVITATION_POLICY)) {
    failures.push(
      "prompts/run-turnkey-demo.md: canonical metadata-only invitation policy is missing.",
    );
  }

  const policyRemainder = prompt
    .replace(PROMPT_REPOSITORY_POLICY, "")
    .replace(PROMPT_INVITATION_POLICY, "");
  if (
    /\bHANDSHAKE_REPO_REF\b/.test(policyRemainder) ||
    /https:\/\/github\.com\/[^\s`)]+/i.test(
      policyRemainder,
    )
  ) {
    failures.push(
      "prompts/run-turnkey-demo.md: contains repository checkout instructions outside the canonical policy.",
    );
  }
  if (
    /\bHANDSHAKE_INVITE_FILE\b/.test(policyRemainder) ||
    /\binvitation\b/i.test(policyRemainder)
  ) {
    failures.push(
      "prompts/run-turnkey-demo.md: contains invitation handling instructions outside the canonical metadata-only policy.",
    );
  }
  return failures;
}

export async function checkDocumentation({
  rootDirectory = DEFAULT_ROOT_DIRECTORY,
} = {}) {
  const root = await canonicalRoot(rootDirectory);
  if (root === null) {
    return ["documentation root must be an absolute path."];
  }

  const failures = [];
  const documents = new Map();

  for (const relativePath of [
    ...PUBLIC_DOCUMENTS,
    ...BILATERAL_PUBLIC_DOCUMENTS,
    ...BILATERAL_COMPATIBILITY_DOCUMENTS,
    ...BILATERAL_SUPPORTING_DOCUMENTS,
  ]) {
    const path = await canonicalRegularFile(
      root,
      resolve(root, relativePath),
    );
    try {
      if (path === null) {
        throw new Error("not a regular file");
      }
      documents.set(relativePath, await readFile(path, "utf8"));
    } catch {
      failures.push(
        `${relativePath}: required public document is missing or not a regular file.`,
      );
    }
  }

  for (const relativePath of SUPPORTING_DOCUMENTS) {
    const path = await canonicalRegularFile(
      root,
      resolve(root, relativePath),
    );
    try {
      if (path === null) {
        throw new Error("not a regular file");
      }
      failures.push(
        ...supportingDocumentFailures(
          relativePath,
          await readFile(path, "utf8"),
        ),
      );
    } catch {
      failures.push(
        `${relativePath}: required referenced file is missing or not a regular file.`,
      );
    }
  }

  for (const relativePath of REQUIRED_REPOSITORY_FILES) {
    if (
      !(await canonicalRegularFile(
        root,
        resolve(root, relativePath),
      ))
    ) {
      failures.push(
        `${relativePath}: required referenced file is missing or not a regular file.`,
      );
    }
  }

  for (const [relativePath, contents] of documents) {
    if (PUBLIC_DOCUMENTS.includes(relativePath)) {
      for (const requirement of REQUIRED_DOCUMENT_PATTERNS) {
        const present =
          requirement.token === undefined
            ? requirement.pattern.test(contents)
            : hasCanonicalToken(
                contents,
                requirement.token,
              );
        if (!present) {
          failures.push(
            `${relativePath}: missing required phrase "${requirement.label}".`,
          );
        }
      }
    }
    if (BILATERAL_PUBLIC_DOCUMENTS.includes(relativePath)) {
      failures.push(
        ...bilateralContractFailures(relativePath, contents),
        ...bilateralNamingAndMovementFailures(
          relativePath,
          contents,
        ),
      );
    }
    if (
      BILATERAL_COMPATIBILITY_DOCUMENTS.includes(
        relativePath,
      )
    ) {
      failures.push(
        ...bilateralCompatibilityFailures(
          relativePath,
          contents,
        ),
      );
    }
    if (BILATERAL_SUPPORTING_DOCUMENTS.includes(relativePath)) {
      failures.push(
        ...bilateralNamingAndMovementFailures(
          relativePath,
          contents,
        ),
      );
    }
    failures.push(
      ...structuredSafetyFailures(relativePath, contents),
      ...(PUBLIC_DOCUMENTS.includes(relativePath)
        ? noncanonicalTokenFailures(relativePath, contents)
        : []),
      ...(PUBLIC_DOCUMENTS.includes(relativePath)
        ? noncanonicalCommandFailures(relativePath, contents)
        : []),
      ...failureCodeFailures(relativePath, contents),
      ...(await linkFailures({
        rootDirectory: root,
        relativePath,
        contents,
      })),
    );

    for (const requiredLink of REQUIRED_LINKS[relativePath] ?? []) {
      if (!markdownLinks(contents).includes(requiredLink)) {
        failures.push(
          `${relativePath}: missing required relative link "${requiredLink}".`,
        );
        continue;
      }
      failures.push(
        ...(await requiredLinkFragmentFailures({
          rootDirectory: root,
          relativePath,
          link: requiredLink,
        })),
      );
    }
  }

  const readme = documents.get("README.md");
  const prompt = documents.get("prompts/run-turnkey-demo.md");
  const packageDocument = documents.get("package.json");
  if (packageDocument !== undefined) {
    failures.push(...packageContractFailures(packageDocument));
  }
  if (prompt !== undefined) {
    failures.push(...promptContractFailures(prompt));
  }
  if (readme !== undefined) {
    failures.push(...readmeRoleplayFailures(readme));
    const embeddedPrompt = extractReadmePrompt(readme);
    if (embeddedPrompt === null) {
      failures.push(
        "README.md: must contain exactly one fenced text prompt.",
      );
    } else if (
      prompt !== undefined &&
      embeddedPrompt !== prompt
    ) {
      failures.push(
        "README.md: its single text fence must be byte-for-byte identical to prompts/run-turnkey-demo.md.",
      );
    }
  }

  return [...new Set(failures)].sort();
}

export async function main({
  rootDirectory = DEFAULT_ROOT_DIRECTORY,
  stdout = process.stdout,
  stderr = process.stderr,
} = {}) {
  const failures = await checkDocumentation({ rootDirectory });
  if (failures.length > 0) {
    stderr.write(
      `${failures.map((failure) => `docs: ${failure}`).join("\n")}\n`,
    );
    return 1;
  }
  stdout.write(
    `Documentation checks passed (${
      PUBLIC_DOCUMENTS.length +
      BILATERAL_PUBLIC_DOCUMENTS.length +
      BILATERAL_COMPATIBILITY_DOCUMENTS.length +
      BILATERAL_SUPPORTING_DOCUMENTS.length +
      SUPPORTING_DOCUMENTS.length
    } gated documents).\n`,
  );
  return 0;
}

const invokedPath = process.argv[1];
if (
  typeof invokedPath === "string" &&
  import.meta.url === pathToFileURL(invokedPath).href
) {
  process.exitCode = await main();
}
