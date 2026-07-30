# Fresh-Agent Directed Bilateral Demo Design

**Date:** 2026-07-29  
**Status:** Approved conversational design; written specification pending user review  
**Primary repository:** `clockchain-handshake`  
**Publication repository:** `clockchain-research`

## 1. Objective

Build and run a repeatable bilateral authorization demo in which three genuinely
fresh agent contexts participate:

1. a **Demo Director** reads one complete operating prompt and directs the run;
2. **Iris** reads only the payer prompt and acts as Meridian's payer and mandate
   owner; and
3. **Billie** reads only the payee prompt and acts as Trellis's vendor/payee.

The Demo Director must tell Iris and Billie when to begin, observe their
sanitized progress, observe what was anchored on Clockchain, wait for the fresh
aggregate verifier, and automatically publish one historical presentation page
for every invocation.

The first real execution runs in this Codex environment on one Mac against
Sepolia and the Clockchain single-validator testnet. It proves fresh agent
contexts and real network evidence. It does **not** prove three physically
separate computers and must be labeled:

> single-machine fresh-agent rehearsal

## 2. Non-goals

This work does not:

- move the represented payment;
- make the Demo Director, relay, coordinator, console, roles, logs, exporter, or
  web page an authorization source;
- replace the exact three Clockchain anchors with agent narration;
- give any agent unrestricted access to private operator or peer-role material;
- publish raw agent transcripts, launch manifests, capabilities, tokens,
  invitations, private keys, RPC URLs, private paths, session identifiers, or
  raw evidence packages;
- claim physical-machine separation;
- claim mainnet, court-grade, multi-validator, production-ready, trustless, or
  consensus-secure operation; or
- retry a failed or ambiguous protocol or funding action automatically.

## 3. Fixed roles and authority

### 3.1 Demo Director

The Demo Director is an operational agent and presenter. It may request only
closed, repository-defined actions. It may receive only closed, sanitized
observations. It cannot provide commercial terms, sign role evidence, fund an
address directly, run the aggregate verifier directly, alter command
arguments, or issue the authorizing verdict.

### 3.2 Iris

Iris is the payer and mandate owner for Meridian. Iris alone owns:

- `PAYER_MANDATE_READY`;
- the `PROPOSED` Clockchain anchor;
- `PAYMENT_REQUEST_MATCHED`; and
- the `ACKNOWLEDGED` Clockchain anchor.

### 3.3 Billie

Billie is the vendor/payee for Trellis. Billie alone owns:

- `PAYMENT_REQUEST_READY`; and
- the `ACCEPTED` Clockchain anchor.

### 3.4 Operator runtime

The repository-owned runtime owns:

- relay, coordinator, TLS pinning, console, funding adapter, evidence transfer,
  aggregate-verifier launch, export, and publication;
- the mapping from an approved action token to one exact command and private
  path set; and
- rejection of every command, role, path, or argument not defined by this
  release.

### 3.5 Aggregate verifier

Only the existing fresh aggregate-verifier process may create the authorizing
verdict after independently refetching and verifying exactly three ordered
anchors for one subject run:

1. Iris `PROPOSED`
2. Billie `ACCEPTED`
3. Iris `ACKNOWLEDGED`

`AUTHORIZED` is a verifier outcome, not a fourth anchor. The operator console
continues to expose only `PENDING` or `VERIFICATION_PASSED` and never emits the
authorization literal.

Every protocol, director, publication, and page artifact preserves
`paymentMoved:false`.

## 4. Release boundary

The current stable executable SHA
`034cdbe4bff8999819d3834f94da5286470b8a99` predates the fresh-agent director
and publication machinery. The new runtime, prompt, schema, and documentation
must be implemented, independently reviewed, verified, and frozen at a new
40-character reviewed SHA before the live run.

All three agent contexts and every repository-owned runtime process bind to the
same new reviewed SHA. No branch, tag, abbreviated SHA, dirty worktree, or
newer commit may substitute.

The Iris and Billie prompt bytes remain part of the existing payer/payee prompt
bundle. The Demo Director prompt receives its own pinned digest in the directed
run record. The director prompt is not added to the commercial role-authority
bundle because it does not sign or authorize protocol evidence.

## 5. Components

### 5.1 Committed Demo Director prompt

Add `prompts/run-bilateral-demo-director.md`.

It must be understandable without conversation history and include:

- purpose and honest demo claims;
- the fixed Iris/Billie mapping;
- exact startup sequence;
- exact action vocabulary;
- observation vocabulary;
- funding safety and recovery rules;
- authority boundaries;
- exactly three anchors per subject run;
- verifier-only authorization;
- automatic-publication behavior;
- public/private evidence boundary;
- stop conditions;
- how to narrate successful, failed, skipped, and publication-failed runs; and
- the single-machine fresh-agent label.

The director prompt may not contain or request secret values.

### 5.2 Fresh-agent adapter

Create a provider-neutral adapter with a first Codex implementation. Its
interface is:

```text
startContext(role, promptBytes, publicContext) -> contextHandle
send(contextHandle, message) -> exact agent response
stop(contextHandle) -> process result
```

`role` is exactly `director`, `payer`, or `payee`.

Each context must:

- start with no inherited conversation;
- use a distinct context/process identity;
- receive only its own prompt and public run context;
- start in a fresh empty working directory;
- receive a minimal allowlisted environment;
- receive no private path or secret value;
- have raw model output stored only in the private director-run root; and
- return one exact structured response rather than an arbitrary command.

The first implementation may use Codex CLI fresh sessions. Tests use fake
agent executables and must not require a hosted model.

Fresh LLM context is not OS isolation. The product claim is limited to context
isolation. On this single-Mac implementation, filesystem separation is enforced
by not disclosing private paths and by brokering every action through the
launcher, not by claiming separate operating-system principals.

### 5.3 Director broker

The broker is deterministic repository code. It owns agent process lifecycle,
message routing, action validation, private path resolution, runtime process
launch, observation projection, local logging, export, and publication.

The director may request only:

```text
START_OPERATOR_SERVICES
INSTRUCT_IRIS_START
INSTRUCT_BILLIE_START
RUN_FUNDING_BATCH
OBSERVE
EXPORT_AND_PUBLISH
STOP
```

Iris and Billie may respond only:

```text
ACK_ROLE
START_SUPERVISOR
REPORT_LOCAL_STATE
REPORT_FAILURE
STOP
```

An agent never supplies a shell command, executable path, flag, environment
variable, manifest path, state path, output path, URL, evidence value, or
publication field. The broker maps valid tokens to reviewed repository command
builders and private operator configuration.

Every action carries:

```json
{
  "schema": "clockchain.bilateral-directed-agent-action/v1",
  "directorRunId": "opaque local identifier",
  "sequence": "canonical unsigned decimal string",
  "role": "director | payer | payee",
  "action": "one allowlisted token",
  "paymentMoved": false
}
```

Unknown keys, skipped or duplicated sequence values, wrong-role actions,
replays, malformed JSON, extra prose, or `paymentMoved:true` fail closed.

### 5.4 Private director-run ledger

Create an ignored private root:

```text
artifacts/director-runs/<directorRunId>/
```

The root is mode `0700`; files are mode `0600`. It contains:

- `started.json`, created exclusively before any child starts;
- one append-only canonical action/observation journal;
- private agent stdout/stderr and provider metadata;
- references to operator, role, and verifier artifact paths;
- a terminal record written exactly once;
- the validated public bundle staging output; and
- publication receipts.

The private ledger may contain paths and raw evidence references because it is
ignored and access-controlled. It must not enter Git, agent messages, the
public bundle, or the research site.

The terminal director status is exactly one of:

```text
COMPLETED
FAILED_AGENT
FAILED_OPERATOR
FAILED_FUNDING
FAILED_PROTOCOL
FAILED_VERIFICATION
FAILED_PUBLICATION
STOPPED
```

Every invocation reaches one terminal status. An interrupted invocation is
recovered by discovery of the durable ledger. It is never blindly restarted.

### 5.5 Sanitized observation projector

The broker constructs observations from allowlisted verified state. It never
spreads an arbitrary runtime, agent, console, verdict, or error object.

Observations may contain:

- fixed actor and role labels;
- agent-context readiness;
- operator-service readiness;
- subject run: `rehearsal` or `stakeholder`;
- intent marker name and observed/not-observed state;
- anchor slot, actor, state, digest, ledger ID, block height, verified block
  time, and independent recheck status;
- console phase and `PENDING` or `VERIFICATION_PASSED`;
- marker-complete verifier status and historical verifier outcome;
- allowlisted public failure code and stage;
- `paymentMoved:false`; and
- repository SHA and single-machine environment label.

Observations never contain arbitrary agent prose. The presentation timeline is
generated from enumerated events such as:

```text
DIRECTOR_CONTEXT_READY
IRIS_CONTEXT_READY
BILLIE_CONTEXT_READY
OPERATOR_SERVICES_READY
DIRECTOR_INSTRUCTED_IRIS
IRIS_SUPERVISOR_STARTED
DIRECTOR_INSTRUCTED_BILLIE
BILLIE_SUPERVISOR_STARTED
FUNDING_BATCH_REQUESTED
FUNDING_BATCH_CONFIRMED
PAYER_MANDATE_READY
PAYMENT_REQUEST_READY
PAYMENT_REQUEST_MATCHED
PROPOSED_ANCHOR_VERIFIED
ACCEPTED_ANCHOR_VERIFIED
ACKNOWLEDGED_ANCHOR_VERIFIED
AGGREGATE_VERIFICATION_PASSED
PUBLICATION_DEPLOYED
RUN_FAILED
```

Director-run timestamps are operational provenance. They are not presented as
Clockchain-attested time. Only the verified anchor block time and upper-bound
evidence carry Clockchain timing meaning.

### 5.6 Public exporter

Add a Handshake export command that accepts one private director-run root and
produces one canonical secret-free bundle.

For every successful subject run it must:

- validate marker-complete Iris and Billie packages;
- validate the marker-complete aggregate verdict;
- independently recheck exactly three Clockchain anchors;
- confirm intent-marker authority;
- confirm console/verifier binding;
- confirm the reviewed repository SHA;
- confirm `paymentMoved:false`;
- reconstruct public fields individually; and
- run closed-schema, unknown-key, URL-allowlist, path-leak, secret, and canary
  checks.

For failed runs it publishes only observed allowlisted state. The public schema
retains exactly three intent-marker slots and three anchor slots. Unobserved
slots contain `observed:false` and null public evidence. It never fabricates an
anchor or authorization outcome.

### 5.7 Public bundle

The exact schema is
`clockchain.bilateral-directed-run-publication/v1`.

The top level contains:

- `slug`;
- `directorRunId`;
- `environment: "single-machine-fresh-agent"`;
- `startedAt`, `completedAt`, and `exportedAt`;
- `repositorySha`;
- fixed role descriptions;
- three agent-context summaries containing role, provider, model, prompt
  digest, and `freshContext:true`;
- closed presentation timeline;
- `phases`, containing rehearsal and stakeholder phase records;
- terminal director status;
- publication status;
- allowlisted source/runbook links;
- bundle digest; and
- `paymentMoved:false`.

Each phase contains:

- `subjectRun`;
- `status: completed | failed | skipped`;
- exactly three intent-marker slots in canonical authority order;
- exactly three anchor slots in `PROPOSED`, `ACCEPTED`, `ACKNOWLEDGED` order;
- console status;
- verifier publication status;
- historical verifier outcome only when derived from a marker-complete verified
  verdict;
- public failure/recovery state; and
- `paymentMoved:false`.

The page labels the historical verifier outcome as reported evidence. The page
does not present itself as the authorizer.

Public URLs are limited to HTTPS links on an exact host/path allowlist for the
reviewed GitHub tree, canonical runbook, and research site. Version 1 includes
no external anchor-viewer URL; it presents the independently rechecked ledger
ID, block height, digest, and verified time directly.

### 5.8 Research-site importer and pages

The research site receives:

- an exact bundle validator;
- `src/data/handshake-runs/<slug>.json`;
- a newest-first loader;
- an archive added below the stable `/handshake/run` instructions; and
- `/handshake/run/[slug]` detail pages.

The detail page shows:

- explicit environment and honesty labels;
- reviewed repository SHA;
- fresh director, Iris, and Billie context summaries;
- sanitized interaction timeline;
- rehearsal and stakeholder sections;
- exact intent markers and authority;
- exactly three anchor slots per phase;
- digest, ledger ID, block height, Clockchain time, and independent recheck
  result for each observed anchor;
- console status;
- historical aggregate-verifier result;
- failure/recovery state;
- `paymentMoved:false`; and
- source/runbook links.

The site is static. It performs no live polling, receives no upload, and never
reads the Handshake worktree, private ledger, environment, secrets, or live
evidence directories.

### 5.9 Automatic publisher

Every terminal director invocation automatically invokes the operator-owned
publisher. Agents never receive GitHub, Vercel, or repository credentials.

The publisher:

1. validates the bundle in Handshake;
2. imports it through the research-site validator;
3. runs focused research-site tests, typecheck, and production build;
4. commits only the validated bundle and required deterministic index changes;
5. pushes a fresh publication branch;
6. creates and merges a publication pull request under the repository's
   existing policy;
7. waits for Vercel production deployment; and
8. fetches the deployed page and confirms the run slug, status, roles, marker
   count, anchor count, verifier status, and `paymentMoved:false`.

The page is not considered published until the production URL passes that
check.

Publication retries are allowed only for the same byte-identical bundle digest.
They may not rerun funding, protocol, role, or verifier actions. A publication
failure writes `FAILED_PUBLICATION` and preserves the bundle for an idempotent
publisher recovery.

## 6. Execution sequence

### 6.1 Release preparation

1. Implement runtime, prompts, schemas, exporter, importer, pages, and tests.
2. Complete independent specification, security, and code reviews.
3. Run focused tests during iteration.
4. Run one final fresh `npm run verify`.
5. Freeze the new reviewed Handshake SHA.
6. Pin the research helper to that SHA.

### 6.2 Live invocation

1. Preflight Node.js 22, exact clean SHA, private modes, operator key, token,
   Sepolia RPC path, treasury keystore path, reachable relay binding, and
   publication repository state.
2. Create the private director-run ledger.
3. Start a fresh Demo Director context.
4. Start relay, coordinator, and read-only console through the broker.
5. Wait for distinct private payer and payee launch manifests.
6. Start fresh Iris and Billie contexts.
7. The director instructs Iris, then Billie, through the broker.
8. Iris and Billie acknowledge their fixed roles and request their one
   supervisor start.
9. The broker starts each exact long-lived supervisor with its private manifest
   and state path.
10. The coordinator publishes its signed four-address funding record.
11. The director requests one funding batch.
12. The broker runs the exact funding command once using the coordinator-owned
    record.
13. The long-lived supervisors execute rehearsal, then stakeholder, without
    replacement prompts, contexts, tokens, invitations, keys, or manifests.
14. The director receives sanitized timeline events.
15. The coordinator launches a fresh aggregate verifier for each eligible
    subject run.
16. The exporter revalidates the terminal evidence.
17. The publisher deploys the historical page.
18. The director reports the production page URL and honest completion label.

The user's Sepolia treasury is used only if public preflight proves the exact
funding plan is safe and adequately funded. Insufficient balance, changed nonce,
ambiguous journal state, nonzero recipient nonce, or a prior transfer attempt
fails the run without retry.

## 7. Failure handling

### 7.1 Agent failures

The broker rejects:

- malformed response;
- arbitrary prose outside the schema;
- unknown action;
- wrong-role action;
- duplicate, skipped, or replayed sequence;
- any private path or secret-like value;
- agent-authored command or argument;
- request to inspect a manifest or peer state;
- request to declare authorization; or
- context crash or timeout.

The run stops with `FAILED_AGENT`.

### 7.2 Operator failures

Wrong SHA, dirty tree, wrong Node version, missing private paths, unsafe modes,
relay/TLS mismatch, expired manifest, unexpected process, or nonzero operator
process exit stops with `FAILED_OPERATOR`.

### 7.3 Funding failures

Insufficient treasury balance, unsafe recipient admission, changed or ambiguous
journal state, duplicate transfer planning, wrong amount, wrong cardinality, or
broadcast ambiguity stops with `FAILED_FUNDING`.

### 7.4 Protocol and verification failures

Missing, duplicate, reordered, expired, malformed, mismatched, wrong-role,
fourth-write, stale-publication, or marker-incomplete evidence stops with
`FAILED_PROTOCOL` or `FAILED_VERIFICATION`. No subject run receives a historical
authorization outcome unless the fresh verifier's marker-complete package
passes.

### 7.5 Publication failures

Schema failure, path/secret leakage, tampered bundle, site test/build failure,
Git conflict, pull-request failure, deploy failure, or live-page mismatch stops
with `FAILED_PUBLICATION`. The underlying protocol outcome remains recorded
privately; the publisher may retry only the byte-identical bundle.

## 8. Security and privacy invariants

- `paymentMoved:false` everywhere.
- Exactly three Clockchain anchors per completed subject run.
- Only the fresh aggregate verifier creates the authorizing verdict.
- The console never emits the authorization literal.
- The public page reports historical evidence and never creates authority.
- Fresh context is proven separately from physical-machine or OS-user
  separation.
- Raw agent transcripts are private.
- Arbitrary agent prose never becomes a public field.
- Agents never receive secret values or private paths.
- Agents never construct commands.
- Director, role, and publisher actions use closed schemas and exact keys.
- Private files remain mode `0600` under mode-`0700` roots.
- Private artifacts remain ignored and outside Git.
- Public bundles are closed reconstructions, not redacted copies.
- Unknown keys and unexpected URL hosts fail closed.
- Failed and partial runs never fabricate missing markers, anchors, or verdicts.
- Protocol actions are never retried automatically.
- Publication recovery cannot rerun or alter the protocol.

## 9. Testing strategy

### 9.1 Unit tests

Add tests for:

- director and role action schemas;
- exact sequence and role authority;
- fresh-agent adapter input/output contracts;
- private ledger exclusive creation and terminal write;
- observation projection;
- public bundle validation and digest;
- URL allowlist;
- secret, path, canary, and arbitrary-prose rejection;
- exact intent-marker and anchor slot counts;
- `paymentMoved:true` rejection; and
- idempotent byte-identical publication recovery.

### 9.2 Agent-harness tests

Use fake agent executables to prove:

- three distinct fresh contexts;
- no inherited context canary;
- distinct prompt digests and role channels;
- minimal environments and empty workspaces;
- no peer or operator path disclosure;
- director-to-Iris and director-to-Billie messages;
- hostile director and role responses fail closed;
- timeouts and crashes produce terminal records; and
- raw transcript data never reaches the public projection.

### 9.3 Deterministic integration

Extend the isolated multiprocess E2E with the fresh-agent broker and fake
Clockchain service. Prove:

- the director starts the exact operator order;
- Iris and Billie each request one supervisor start;
- funding is requested once;
- commercial-intent authority is exact;
- exactly three anchors per subject run;
- the console remains non-authorizing;
- the fresh verifier alone reports the historical outcome;
- success and all failure classes produce one terminal director record;
- a valid public bundle is emitted for success and failure; and
- publication fixtures render deterministically.

### 9.4 Research-site tests

Add Vitest coverage for:

- schema and filename/slug binding;
- newest-first archive loading;
- static parameters and not-found behavior;
- success, failure, partial, and skipped phase rendering;
- exactly three marker and anchor slots;
- historical-verdict labeling;
- no form, fetch, upload, storage, unsafe HTML, or live endpoint;
- no private identifiers or secret patterns;
- URL allowlist; and
- preservation of the stable `/handshake/run` start surface.

### 9.5 Final verification

Before the live run:

- all focused Handshake tests pass;
- all focused research-site tests pass;
- independent spec, security, and code reviews pass;
- one fresh complete Handshake `npm run verify` passes;
- research typecheck, changed-file lint, and production build pass;
- secret scan and diff check pass; and
- the new reviewed SHA is frozen and used by every context/process.

## 10. Live-run acceptance criteria

The first invocation is complete only when:

1. three distinct fresh agent contexts are recorded;
2. the Demo Director reads the committed instructions and sends bounded
   instructions to Iris and Billie;
3. Iris and Billie acknowledge the correct roles and request only their own
   supervisor start;
4. the broker starts one long-lived supervisor per role;
5. funding admission and the one exact four-address batch succeed, or a
   truthful failure page is published;
6. the intent markers have Iris/Billie/Iris authority;
7. each completed subject run contains exactly three independently rechecked
   Clockchain anchors in order;
8. only marker-complete fresh-verifier evidence supplies the historical
   authorization outcome;
9. the console, director, roles, coordinator, logs, and page do not act as the
   authorizer;
10. `paymentMoved:false` appears throughout;
11. one secret-free page is automatically deployed for the invocation;
12. the production page is fetched and verified; and
13. the final report links the page and states
    `single-machine fresh-agent rehearsal`.

If live credentials, funding, Clockchain, or Sepolia prevent a successful
protocol run, the invocation is complete only after an accurate automatically
published failure page exists. If GitHub or Vercel prevents publication, the
invocation remains incomplete at `FAILED_PUBLICATION`; the byte-identical
publisher recovery continues when the publishing dependency recovers. No
missing external dependency is converted into a successful demo claim.
