# Bilateral coordination relay design

Date: 2026-07-26

Status: User-approved design specification. This document does not authorize
live Clockchain writes, Sepolia transactions, invitation creation, funding, or
deployment.

## 1. Purpose and scope

### 1.1 Problem

The bilateral protocol already defines and deterministically tests the three
authoritative transitions:

```text
PROPOSED -> ACCEPTED -> ACKNOWLEDGED
```

The current operational commands can run those transitions, publish
marker-complete party packages, and independently verify all three Clockchain
anchors. They do not yet coordinate the operator, Billy, and Iris across two
physical role machines. The runbook consequently assigns artifact transfer,
phase signaling, funding checks, descriptor delivery, preflight aggregation,
and verifier invocation to a human operator.

That manual workflow conflicts with the intended human action surface. After
the deterministic build, the user should need to do only two things:

1. fund the four displayed invitation addresses; and
2. start the Billy and Iris sessions on their assigned physical machines.

This design adds an operator-hosted authenticated HTTPS coordination relay and
one long-lived supervisor on each role machine. The relay automates the public
artifact and phase flow without becoming a protocol authority.

### 1.2 Required outcome

One Billy supervisor and one Iris supervisor remain alive across a rehearsal
run and a stakeholder run. Together with the operator coordinator they:

1. authenticate their assigned roles;
2. generate and retain all role secrets locally;
3. expose exactly four public invitation addresses for user funding;
4. detect funding readiness without another user signal;
5. perform one two-write Clockchain preflight against the frozen release;
6. register the rehearsal identities and execute a complete rehearsal;
7. require a fresh independent aggregate-verifier pass;
8. register the stakeholder identities and execute the stakeholder session;
9. require a second fresh independent aggregate-verifier pass; and
10. fail closed on any missing, duplicated, reordered, expired, mismatched,
    malformed, replayed, or marker-incomplete evidence.

Every state and artifact preserves `paymentMoved: false`. Neither role
supervisor, the relay, the watcher, nor the operator coordinator may print the
authorizing literal. Only the dedicated aggregate-verifier process may emit
`AUTHORIZED`.

### 1.3 Relationship to the bilateral protocol

This is a coordination-layer extension to
`clockchain.bilateral-authorization/v1`. It does not change:

- the signed session descriptor;
- canonical proposal, acceptance, or acknowledgment bytes;
- the three deterministic reference IDs;
- transition digest and predecessor binding;
- authoritative Clockchain block and timestamp verification;
- the `600`-second protocol window;
- the party-result or aggregate-verdict trust rules; or
- the rule that advisory fields, cached timestamps, record status, and
  unverified packages are never authoritative.

The coordination layer can transport signed public bytes and decide when an
existing command is allowed to run. It cannot manufacture protocol evidence,
replace a Clockchain read, or authorize a result.

### 1.4 Non-goals

This design does not:

- move money or connect to a payment rail;
- add decline, cancellation, settlement, refund, or partial-acceptance states;
- make the Clockchain single-validator testnet production-grade or trustless;
- provide cryptographic proof that two processes run on physically distinct
  hardware;
- let the relay proxy Clockchain or Sepolia credentials;
- let production CLIs fall back to a deterministic fake;
- support an in-place repository or prompt upgrade after live preflight;
- automate a hosting provider, DNS, or public certificate authority; or
- replace the standalone low-level CLIs as diagnostic and recovery surfaces.

## 2. Design decisions

### 2.1 Chosen approach

Use an operator-hosted Node.js 22 HTTPS relay with:

- no new runtime dependency;
- a pinned TLS identity;
- one-time role-scoped launch capabilities;
- locally generated long-lived machine coordination keys;
- canonical signed envelopes;
- an append-only, hash-chained event log;
- content-addressed, secret-free artifact storage;
- an exact fail-closed lifecycle state machine; and
- a separate operator coordinator that invokes existing commands.

The relay is a mailbox and durable phase ledger. The operator coordinator is
the workflow owner. The aggregate verifier remains the sole authorization
owner.

### 2.2 Rejected alternatives

**Git refs as the coordination bus.** This would reuse repository
authentication, but it introduces polling latency, write credentials on every
machine, mutable-ref races, branch protection dependencies, and awkward
recovery semantics. It also conflates release publication with session state.

**Manual artifact transfer and phase signaling.** This preserves the current
implementation but requires many operator actions and four role-session starts.
It does not meet the approved human action surface.

**Clockchain as both protocol and coordination transport.** Extra control
records would consume live writes, blur the exactly-three-transition story, and
make availability of the protocol ledger a prerequisite for distributing
bytes that must exist before the first transition.

### 2.3 No new dependency

The relay uses Node.js built-ins:

- `node:https` for the live server and client;
- `node:crypto` for Ed25519, SHA-256, random capabilities, constant-time
  comparisons, and TLS fingerprint checks;
- `node:fs/promises` for bounded durable state;
- `node:net` only for test and bind validation; and
- `node:child_process` for isolated command execution.

The implementation must not add an HTTP framework, database, queue, WebSocket
package, or retry library.

## 3. Trust and authority model

### 3.1 Authorities

| Actor | May do | Must never do |
| --- | --- | --- |
| User | Start the two role-specific sessions and fund the four displayed addresses | Transfer private files, hand-edit evidence, or declare authorization |
| Billy supervisor | Own payer-local secrets, run approved payer commands, sign payer coordination envelopes, upload secret-free payer artifacts | Run Iris, the operator verifier, or print `AUTHORIZED` |
| Iris supervisor | Own payee-local secrets, run approved payee commands, sign payee coordination envelopes, upload secret-free payee artifacts | Run Billy, the operator verifier, or print `AUTHORIZED` |
| HTTPS relay | Authenticate, sequence, persist, and distribute signed public coordination data | Read role secrets, write Clockchain transitions, infer authorization, or print `AUTHORIZED` |
| Operator coordinator | Sign phase commands, validate relay state, create public descriptors, run watcher/preflight aggregation, and launch fresh verifier processes | Substitute relay state for protocol verification or suppress verifier failure |
| Aggregate verifier | Refetch identities and all three Clockchain anchors, validate both role packages, publish a marker-complete verdict | Trust relay state, watcher output, cached timestamps, or advisory status |

### 3.2 Key separation

Five key classes remain distinct:

1. the committed operator Ed25519 key signs descriptors and operator
   coordination commands;
2. the HTTPS server key authenticates the transport and signs only
   relay-origin enrollment receipts; it is never reused as an operator signing
   key or treated as protocol authority;
3. each role machine generates one Ed25519 coordination key for the release;
4. each role machine generates one Ed25519 preflight participant key; and
5. each invitation contains its own Ethereum role-signing key.

No private key crosses the relay. The relay persists public keys and signatures
only.

### 3.3 Physical separation

The system can prove separate role credentials and concurrently connected,
role-bound machine keys. Without trusted platform attestation it cannot prove
that those keys reside on distinct physical hardware.

The user's act of starting the Billy launch file on the Billy computer and the
Iris launch file on the Iris computer is the operator attestation of physical
separation. The preflight report continues to say that separate machines were
**attested**, not cryptographically proven. Documentation and verdict artifacts
must not strengthen that claim.

## 4. Components

### 4.1 Operator relay server

The server owns:

- TLS termination;
- one-time bootstrap exchange;
- signed-envelope validation;
- per-sender sequence and replay state;
- the append-only event log;
- content-addressed public artifacts;
- a read-only derived session view; and
- bounded long-poll responses.

It does not launch protocol commands and does not hold the operator signing
private key.

The server accepts an explicit host, port, TLS certificate path, TLS private-key
path, state directory, and frozen repository SHA. It refuses:

- plaintext live operation;
- wildcard or implicit external binds;
- a missing or unreadable TLS identity;
- a reused or non-private state directory;
- a dirty or wrong repository checkout; and
- unknown configuration.

An injected in-memory transport may be used by tests. Production has no
plaintext, fake, or unauthenticated fallback.

### 4.2 Operator coordinator

The coordinator is a separate process that:

- creates the private Billy and Iris launch manifests;
- hashes the one-time capabilities into relay bootstrap state;
- signs phase commands with the operator key;
- observes both role state machines;
- polls funding readiness;
- constructs the public preflight plan from locally generated participant
  public keys;
- verifies participant reports and runs preflight aggregation;
- collects marker-complete identity artifacts;
- creates one descriptor per run;
- starts the advisory watcher;
- orders Iris before Billy;
- collects marker-complete party packages;
- launches a fresh aggregate-verifier process; and
- records the verifier process result without repeating its authorizing text.

The coordinator persists enough public state to resume observation after a
crash. It does not cache private role material or treat a relay event as proof
that a protocol command succeeded. Its dedicated Clockchain token and
independent Sepolia RPC credential remain operator-local and are never uploaded
to the relay.

### 4.3 Billy and Iris supervisors

Each machine runs one supervisor for the full release. A supervisor owns:

- its private launch manifest;
- its coordination key;
- its preflight private key;
- one Clockchain token;
- two invitations, one rehearsal and one stakeholder;
- two registration directories;
- two descriptor files;
- two role-result directories; and
- its local recovery checkpoints.

The supervisor verifies every operator command against the public operator key
at the frozen repository SHA. It invokes only exact, allowlisted repository
commands with path arguments. It never exposes a shell or accepts arbitrary
executable, environment, argument, repository, or output-path overrides from
the relay.

### 4.4 Existing protocol commands

The existing commands remain the implementation units for:

- invitation generation and funding checks;
- token minting;
- preflight participation and aggregation;
- identity registration;
- prompt hashing and descriptor creation;
- watcher observation;
- Billy proposal/acknowledgment execution;
- Iris discovery/acceptance execution; and
- aggregate verification.

The supervisor and coordinator compose these commands. They do not duplicate
their protocol logic.

Preflight preparation changes in one intentional way: participant private keys
are generated on their role machines. The operator-signed plan accepts the two
participant public-key artifacts and never creates or distributes participant
private keys.

### 4.5 Persistent deterministic fake

The process-level test harness exposes the existing deterministic fake
Clockchain through a bounded localhost HTTP service. Billy, Iris, and the
verifier run as separate Node child processes with:

- distinct working directories;
- distinct invitation and coordination keys;
- distinct token files;
- distinct environment allowlists;
- production argument parsers;
- production input builders with explicitly injected test adapters; and
- no shared in-memory role object.

The parent harness may own the fake service. The three protocol actors must not
share process memory.

There is no production CLI flag, environment variable, URL scheme, or automatic
fallback that selects the fake.

## 5. Bootstrap and authentication

### 5.1 Private launch manifests

Before the user starts either role session, the coordinator creates two private
mode-`0600` launch manifests. Each contains:

- schema and protocol identifiers;
- the exact `repositorySha`;
- the operator key ID;
- the assigned role;
- the same fresh unpredictable coordination session ID;
- the HTTPS relay URL;
- the expected TLS certificate SHA-256 fingerprint;
- one 256-bit role-scoped bootstrap capability; and
- the release identifier.

The manifests carry distinct capabilities and distinct assigned roles. A
capability expires 60 minutes after issuance if it has not been consumed. The
raw capability appears only in the matching private launch manifest. The relay
stores its SHA-256 digest, role, session, expiry, and unused/used state.

Providing the matching launch manifest is part of the user's single "start this
agent session" action. The launch path is installed or attached as part of that
start and is not a later artifact-transfer step.

### 5.2 TLS pinning

The supervisor:

1. requires an `https:` relay URL;
2. verifies the normal certificate chain or an explicitly pinned operator CA;
3. compares the connected leaf certificate fingerprint to the launch manifest
   in constant time;
4. rejects redirects, alternate hostnames, proxy-derived endpoints, and
   protocol downgrade; and
5. applies fixed connect, header, body, and total request deadlines.

Tests may inject a transport object. Production may not disable certificate
validation.

### 5.3 Capability exchange

On first contact, the supervisor locally creates:

- its coordination Ed25519 key pair;
- its preflight Ed25519 key pair; and
- its rehearsal and stakeholder invitations.

It sends one bounded bootstrap request containing:

- the raw one-time capability;
- one exact secret-free enrollment object containing the coordination public
  key, preflight public key, and both assigned public invitations;
- proof-of-possession signatures from both invitation keys over their exact
  enrollment challenges; and
- a coordination-key signature over the complete secret-free enrollment.

The bootstrap wrapper has exact keys `capability` and `enrollment`. The
capability is lowercase 64-hex and must hash to the enrollment's
`capabilityDigest`.

The enrollment schema is
`clockchain.bilateral-coordination-enrollment/v1` with exact top-level keys
`capabilityDigest`, `coordinationKey`, `invitations`, `paymentMoved`,
`preflightKey`, `releaseId`, `repositorySha`, `role`, `schema`, `sessionId`,
and `signature`. Coordination and preflight keys have exact keys `algorithm`,
`keyId`, and `publicKey`; both algorithms are `ed25519`, both public keys are
canonical raw 32-byte Base64, and the two keys differ. `invitations` has exact
keys `rehearsal` and `stakeholder`; each value has exact keys `address`,
`algorithm`, and `signature`, uses `eip191`, and the two lowercase addresses
differ.

Each invitation proof signs the ASCII domain
`clockchain.bilateral-invitation-proof/v1\n` followed by the lowercase SHA-256
of canonical exact keys `address`, `capabilityDigest`, `releaseId`,
`repositorySha`, `role`, `run`, and `sessionId`. The enrollment signature uses
the coordination key over the ASCII domain
`clockchain.bilateral-coordination-enrollment-signature/v1\n` followed by the
lowercase SHA-256 of the canonical enrollment without `signature`.

The relay verifies the capability digest, role, session, expiry, exact request
shape, invitation address recovery, and coordination signature. It consumes the
capability atomically while binding it to the enrollment request digest and the
signed enrollment receipt. The receipt signature uses the already pinned HTTPS
server key over a fixed relay-receipt domain and the canonical receipt digest.
The supervisor verifies it against the public key in the pinned leaf
certificate. This proves which pinned relay consumed the capability; it does
not grant the relay operator-command or protocol authority.

The TLS-signed bootstrap receipt is distinct from the later operator-signed
`enrollment receipt` coordination event. The former lets a supervisor recover
ambiguous capability consumption; the latter is the operator coordinator's
phase acknowledgment. Neither is Clockchain protocol evidence.

A consumed capability cannot authorize a different request. Repeating the same
capability with the byte-identical enrollment request returns the already stored
receipt, allowing an ambiguous HTTP response to recover without another user
start. Any different request under that capability is terminal replay. The
supervisor removes the raw capability from its active state only after it has
durably stored and verified the receipt.

Capability consumption stores the exact canonical enrollment bytes and receipt
in the same authoritative journal record. On restart, the relay retrieves the
enrolled coordination/preflight keys and invitation proofs from that durable
record; it never re-enrolls a key from the first event it happens to receive.
Storage invokes the TLS receipt factory only for an unused capability after the
enrollment passes validation. A matching retry returns the already persisted
receipt without invoking or re-signing through the factory, which preserves
byte identity for randomized ECDSA and RSA-PSS signatures.

### 5.4 Funding as approval, not authentication

The launch capability authenticates the expected machine role. Invitation
signatures prove control of the displayed addresses. The user's funding of the
four addresses approves those exact enrolled invitations for the live release.

Funding is not the bootstrap authentication mechanism. An attacker cannot
replace a role enrollment merely by presenting different funded addresses.

## 6. Canonical coordination protocol

### 6.1 Signed envelope

Every post-bootstrap request and operator command uses one canonical envelope
with exact keys:

- `artifactDigest`: SHA-256 or `null`;
- `eventDigest`: SHA-256 of the canonical event body;
- `kind`: one allowlisted event kind;
- `paymentMoved`: exactly `false`;
- `previousEventDigest`: the sender's prior event digest or `null`;
- `releaseId`;
- `repositorySha`;
- `role`: `operator`, `payer`, or `payee`;
- `schema`;
- `sequence`: a canonical non-negative decimal string;
- `sessionId`;
- `signature`: algorithm, public-key identifier, and canonical signature; and
- `subjectRun`: `release`, `rehearsal`, or `stakeholder`.

`eventDigest` is
`SHA-256(canonicalBytes(eventWithoutEventDigestOrSignature))`. The signature
preimage is a fixed coordination domain string followed by that digest. This
avoids a circular signature definition and binds every other envelope field,
including `artifactDigest` and `previousEventDigest`.

The canonical envelope is limited to 64 KiB including the signature. Bootstrap
requests have the same limit. A single stored artifact is limited to 1 MiB and
a marker-complete multi-file package is limited to 3 MiB. A type may impose a
smaller existing protocol limit, which remains authoritative.

Protocol decisions do not use an envelope's local creation time. Relay receipt
time and optional advisory timestamps may be logged for operations but are not
authorization evidence.

Operator authority is resolved from
`docs/operator-keys/<keyId>.pub` at the exact frozen repository SHA. The relay
uses a repository public-key resolver with the same closed path derivation as
descriptor verification; it never trusts the public key embedded in an
operator envelope. Role authority comes only from the durable bootstrap
enrollment for that session and role.

### 6.2 Sequence and replay rules

Each sender has an independent sequence beginning at `0`.

- The next event must be exactly the expected sequence.
- Repeating the same sequence and identical event digest is an idempotent read
  of the existing result.
- Repeating a sequence with a different digest is terminal conflict.
- Skipping a sequence is terminal reordering.
- Reusing an event digest under another sequence, session, role, run, or release
  is terminal replay.
- A broken `previousEventDigest` is terminal chain divergence.

The relay applies these rules transactionally with append-only persistence.
Clients independently revalidate the returned chain.

### 6.3 Event kinds

The event vocabulary is closed and divided by authority.

Role-to-operator events include:

- enrollment confirmed;
- funding inputs ready;
- token ready;
- preflight participant ready;
- identity package ready;
- descriptor accepted;
- role started;
- role package ready;
- recovery required; and
- terminal failure.

Operator-originated coordination events include:

- enrollment receipt;
- wait for funding;
- preflight plan ready;
- register rehearsal;
- rehearsal descriptor ready;
- start rehearsal;
- register stakeholder;
- stakeholder descriptor ready;
- start stakeholder;
- exact recovery authorization;
- verification passed;
- verification failed;
- complete release; and
- terminal abort.

The relay rejects unknown kinds and kinds emitted by the wrong role.

Role authority is checked against the immutable coordination public key accepted
during authenticated enrollment. Signature verification must never use the
public key carried by the same envelope as its own authority expectation. The
envelope key is evidence to compare with the enrolled key, not a source of
trust.

After the stakeholder verifier has exited successfully and published its valid
marker-complete verdict, the operator may emit one release-scoped
`COMPLETE_RELEASE` event. This event records only that the coordinator has
finished the non-authorizing release workflow. It cannot substitute for
`VERIFICATION_PASSED`, carry an authorization verdict, or move a release
directly from `STAKEHOLDER_RUNNING` to `COMPLETE`.

### 6.4 Session state machine

The derived coordinator state advances only through:

```text
BOOTSTRAPPING
-> ADDRESSES_READY
-> FUNDING_READY
-> PREFLIGHT_READY
-> PREFLIGHT_PASSED
-> REHEARSAL_IDENTITIES_READY
-> REHEARSAL_DESCRIPTOR_READY
-> REHEARSAL_RUNNING
-> REHEARSAL_VERIFIED
-> STAKEHOLDER_IDENTITIES_READY
-> STAKEHOLDER_DESCRIPTOR_READY
-> STAKEHOLDER_RUNNING
-> STAKEHOLDER_VERIFIED
-> COMPLETE
```

Any terminal failure moves the release to `ABORTED`. There is no transition out
of `ABORTED`.

`REHEARSAL_VERIFIED` and `STAKEHOLDER_VERIFIED` mean that a fresh verifier
process exited successfully and published a valid marker-complete verdict. They
are coordinator states, not authorizing output.

`COMPLETE` is derived only after the operator's `COMPLETE_RELEASE` event is
accepted from `STAKEHOLDER_VERIFIED`. A premature, duplicated, wrongly scoped,
or wrongly signed completion event aborts or fails closed under the same event
validation rules.

## 7. Artifact transport

### 7.1 Allowed artifacts

The relay accepts only explicitly allowlisted, secret-free public artifacts:

- invitation public bundles;
- coordination enrollment and receipt;
- token-commitment artifacts;
- preflight public-key artifacts;
- signed preflight plan;
- marker-complete participant reports;
- marker-complete aggregate preflight report;
- marker-complete identity packages;
- signed descriptors;
- marker-complete party-result packages; and
- non-authorizing failure summaries.

Aggregate verdict files remain operator-local. The relay may publish only the
non-authorizing coordinator state that the verifier passed or failed.

### 7.2 Content-addressed storage

Every artifact:

1. has a type-specific byte limit;
2. is streamed or read with a maximum-plus-one bound;
3. is hashed before acceptance;
4. is validated against its exact schema and signature;
5. is scanned for active secret canaries and private-key/token patterns;
6. is stored under its SHA-256 digest with exclusive creation;
7. is reread and rehashed before acknowledgement; and
8. is referenced from an event by exact digest.

Artifact validation has two fail-closed layers. The content-addressed storage
layer proves the closed schema, canonical bytes, completion markers, digest,
secret absence, and cryptographic validity of any self-contained signature. It
does not infer that an embedded signing key is an authorized operator or role
key. Before an artifact digest may be referenced by an accepted coordination
event or advance lifecycle state, the relay service repeats the type-specific
validation with the expected repository-pinned operator or enrolled role
authority. An artifact type without an exact repository-owned validator is
rejected; a future producer task must land that validator before the type can
become usable.

Artifact upload carries its closed type in exactly one
`x-clockchain-artifact-type` HTTPS header with an
`application/octet-stream` body. The content-addressed path supplies the
expected digest. Clients cannot supply secret canaries or arbitrary validation
options. The relay derives the expected type for a referenced digest only from
the signed event kind; it never trusts an upload-time type assertion as
lifecycle authority.

The bootstrap consumption receipt stored with capability state is internal
durable relay data, not a public artifact upload. Its exact TLS signature and
certificate binding are validated by the relay bootstrap service before the
storage transaction is acknowledged.

The durable receipt has no free-form or nested fields. Its exact canonical keys
are `capabilityDigest`, `certificateSha256`, `enrollmentDigest`,
`paymentMoved`, `releaseId`, `repositorySha`, `role`, `schema`, `sessionId`,
`signature`, and `signatureAlgorithm`. The schema is
`clockchain.bilateral-coordination-receipt/v1`; all digest fields are lowercase
SHA-256, `paymentMoved` is exactly `false`, the release/role/session/repository
fields repeat the consumed capability scope, the signature is canonical
Base64, and `signatureAlgorithm` is one of `ed25519`, `ecdsa-sha256`, or
`rsa-pss-sha256`. The signature preimage is the ASCII domain
`clockchain.bilateral-coordination-receipt-signature/v1\n` followed by the
lowercase SHA-256 of the canonical receipt without its `signature` field.

Multi-file packages must have a verified completion marker before upload. The
receiver repeats marker and digest verification after download.

### 7.3 Forbidden content

The relay rejects:

- invitation secret bundles;
- Ethereum or Ed25519 private keys;
- Clockchain or RPC tokens;
- launch manifests or raw bootstrap capabilities;
- TLS private keys;
- registration or write-intent checkpoints;
- temporary or marker-incomplete packages;
- arbitrary archives; and
- files not named by an allowlisted artifact schema.

## 8. Release and two-run lifecycle

### 8.1 Frozen release

Before live bootstrap, the operator freezes:

- one immutable repository SHA containing the operator public key;
- one prompt-bundle digest;
- one relay and supervisor contract version;
- one operator key ID;
- two role-scoped launch manifests; and
- one release ID.

Both role machines and the operator verify clean checkouts at the same SHA.

### 8.2 Four invitations and funding

Billy locally creates:

- Billy rehearsal; and
- Billy stakeholder.

Iris locally creates:

- Iris rehearsal; and
- Iris stakeholder.

The coordinator displays exactly those four signed public addresses. The user
funds them with the documented Sepolia amount. The coordinator continuously
applies the repository's invitation-readiness checks until all four have nonce
zero and an allowed balance. No separate "funding complete" message is required.

### 8.3 One preflight for the release

One preflight covers:

- the frozen repository SHA;
- the Billy and Iris supervisor coordination identities;
- the Billy and Iris preflight participant public keys;
- SHA-256 commitments to the exact Billy and Iris Clockchain token bytes;
- the two physical-machine attestation; and
- both runs in the same release.

After token minting, each supervisor reads its bounded private token, computes a
SHA-256 commitment, and signs that commitment with its coordination key. The
operator-signed plan pins both token commitments and both participant public
keys without receiving either token or private key. Each participant report
repeats its signed token commitment. Before preflight and before each role run,
the supervisor rereads the token and requires the same commitment.

The role machines generate participant private keys. The operator creates the
signed plan from public enrollment artifacts. Each role performs exactly one
throwaway write. The operator aggregates both marker-complete participant
reports.

The two-write preflight is never repeated for the same release.

### 8.4 Rehearsal run

After preflight:

1. each supervisor registers its rehearsal invitation;
2. the coordinator receives both marker-complete identity packages;
3. the operator creates and signs a rehearsal descriptor for exactly
   `USD 100`;
4. both supervisors verify byte-identical descriptor content;
5. the coordinator starts Iris polling, then starts Billy;
6. the supervisors upload marker-complete role packages;
7. the coordinator starts a fresh verifier with an independent RPC client; and
8. only exact verifier success advances to `REHEARSAL_VERIFIED`.

### 8.5 Corrections after rehearsal

Operational recovery is allowed only under the existing exact-input,
same-directory rules and only through an operator-signed recovery command.

Changing code, prompts, the repository SHA, the operator key, the preflight
identity, a Clockchain token, or a consumed invitation after live preflight
invalidates the release. The coordinator aborts and does not run the stakeholder
pair.

A corrected repository requires a new release, fresh launch manifests, fresh
invitations, and newly authorized preflight write budget. The system never
silently rebinds old preflight evidence to new code.

Deterministic and two-machine process rehearsals therefore occur before live
preflight. The live rehearsal validates the frozen release and operational
environment; it is not an authorization to patch the release in place.

### 8.6 Stakeholder run

Only a marker-complete rehearsal verifier pass at the unchanged release SHA can
unlock the stakeholder pair.

The coordinator repeats identity registration, descriptor creation, timed role
execution, package collection, and fresh aggregate verification using:

- the stakeholder invitations;
- a fresh descriptor and protocol session ID;
- fresh registration/result/verdict directories; and
- the same supervisor keys, preflight evidence, Clockchain tokens, release ID,
  repository SHA, and prompts.

It does not repeat invitation creation, funding, token minting, session start, or
preflight.

## 9. Recovery and failure handling

### 9.1 Relay disconnects

A supervisor reconnects with its coordination key, reads the signed append-only
chain from its last accepted digest, and resumes only if:

- its local sequence and digest match;
- the release, role, run, and repository SHA match;
- no conflicting event exists; and
- its current local command has not entered an ambiguous state.

Transport retries are safe only for identical signed envelopes. They never
rerun a protocol command.

### 9.2 Artifact upload ambiguity

An upload is idempotent by artifact digest. After an ambiguous response, the
client queries the digest:

- exact stored bytes are adopted;
- absence permits the same upload;
- different bytes or malformed metadata abort the release.

### 9.3 Protocol-write ambiguity

The coordinator never retries an ambiguous Clockchain or Sepolia write on its
own. The role supervisor preserves the exact output directory and reports a
fixed public failure state.

Only an operator-signed exact recovery command may rerun the same repository
command with the same:

- invitation;
- token;
- descriptor;
- repository SHA;
- arguments; and
- output directory.

The role's `RECOVERY_REQUIRED` event and the operator's
`EXACT_RECOVERY_AUTHORIZATION` event must reference the same non-null
`artifactDigest` for that exact secret-free recovery-command manifest. The
coordinator state records recovery requests and authorizations separately for
each role and run. An authorization is valid only when its digest uniquely
matches one outstanding request; missing digests, changed digests, cross-role
substitution, digest collision between roles, or reuse of a prior authorization
fails closed. Downstream execution requires the authorized digest for that exact
role and run, never a run-wide recovery boolean.

The existing discovery-first and checkpoint validation rules decide whether the
write can be adopted. If uniqueness cannot be proven, the run aborts.

### 9.4 Terminal failures

The release aborts on:

- missing or unknown role enrollment;
- capability replay or ambiguous consumption;
- TLS identity mismatch;
- invalid signature;
- sequence gap, duplicate conflict, or hash-chain divergence;
- unknown event kind or wrong event authority;
- funding outside the required range or a nonzero pre-registration nonce;
- missing, duplicate, reordered, expired, malformed, or mismatched protocol
  evidence;
- any advisory field used as authority;
- a secret-bearing or marker-incomplete artifact;
- a dirty or wrong repository checkout;
- a code or prompt change after live preflight;
- a verifier crash, timeout, nonzero exit, or incomplete publication; or
- any `paymentMoved` value other than exactly `false`.

An abort is permanent for that release. The relay and supervisors never convert
an abort into a successful state.

## 10. Authorization boundary

The aggregate-verifier executable remains the sole production source of the
authorizing literal.

The coordinator:

- launches the verifier in a fresh process;
- captures its exact exit, stdout, stderr, and publication paths;
- validates the marker-complete verdict artifacts;
- records only `VERIFICATION_PASSED` or `VERIFICATION_FAILED` in coordination
  state; and
- presents the verifier's original output to the operator without reproducing
  it through the relay or role logs.

Billy, Iris, watcher, relay, coordinator, and all their public failure paths must
remain source- and runtime-tested to exclude the authorizing literal.

## 11. Deterministic process-level end-to-end test

### 11.1 Process topology

The required deterministic test starts:

1. one persistent localhost fake Clockchain service;
2. one HTTPS relay child process with a test-only certificate;
3. one operator-coordinator child process;
4. one Billy child process;
5. one Iris child process; and
6. one fresh aggregate-verifier child process launched by the coordinator.

The role processes execute concurrently through the relay. The verifier starts
only after both marker-complete packages exist. The parent harness observes
processes and artifacts but does not invoke role or verdict functions in its own
memory.

### 11.2 Production-path fidelity

Each child uses:

- the real argument parser;
- the real default input builder;
- the real role or verifier implementation;
- real filesystem artifacts and completion markers; and
- an explicitly injected test adapter to the localhost fake.

The injection occurs in test-only child drivers calling exported builders. It
does not add a production option or environment override.

### 11.3 Required success assertions

The successful deterministic run proves:

- Billy and Iris have different process IDs, directories, invitation keys,
  coordination keys, preflight keys, and token files;
- the fake contains exactly three protocol writes;
- the writes are proposal, acceptance, and acknowledgment in order;
- every message and artifact has `paymentMoved: false`;
- the amount is exactly `USD 100`;
- each transition digest and predecessor triple recomputes;
- block heights and authoritative times increase and remain within deadline;
- Billy ends locally at `ACKNOWLEDGED`;
- Iris ends locally at `ACCEPTED`;
- neither role output contains the authorizing literal;
- the verifier independently queries all three fake anchors; and
- only the verifier child emits the authorizing literal.

### 11.4 Adversarial matrix

The process harness and focused tests cover:

- missing, duplicate, and reordered relay events;
- capability replay and cross-role capability use;
- signature, sequence, previous-digest, session, run, and release mismatch;
- oversized, malformed, secret-bearing, and marker-incomplete artifacts;
- artifact replacement during upload or download;
- relay restart and client reconnect;
- dropped and duplicated HTTP responses;
- wrong TLS fingerprint and plaintext downgrade;
- funding mismatch and nonzero invitation nonce;
- preflight key, token, repository, report, and attestation mismatch;
- missing, duplicate, reordered, expired, and malformed protocol anchors;
- package/Clockchain divergence;
- untrusted advisory status and cached timestamps;
- ambiguous Clockchain and registration writes;
- role, coordinator, relay, watcher, and verifier process crashes; and
- verifier output or publication disagreement.

Every adversarial row has one integrated test or an exact focused-test citation.

## 12. Persistence and local filesystem rules

Every new state directory is:

- created with exact mode `0700`;
- opened with nofollow directory flags;
- pinned by full path/handle identity;
- revalidated around pathname operations; and
- fsynced after durable transitions.

Private files are exact mode `0600`, bounded, nofollow, nonblocking, and checked
before and after reads. Public artifacts use exclusive marker-last publication.

The relay event log is append-only and hash-chained. A derived snapshot is a
cache and may be rebuilt from the log; it is never authoritative when the log
disagrees. Partial tail records, noncanonical bytes, sequence divergence, or
hash mismatch fail startup closed.

Bootstrap capability state stores only capability digests. Raw capabilities
remain in private launch manifests and are destroyed or archived outside the
active path after successful exchange.

## 13. Interface and module boundaries

The implementation plan should keep these responsibilities separate:

- canonical coordination envelopes and signatures;
- lifecycle state reduction;
- durable relay storage;
- HTTPS server routing and bounds;
- HTTPS client transport and TLS pinning;
- role supervisor command policy;
- operator coordinator orchestration;
- preflight local participant-key enrollment; and
- process-level fake service and child drivers.

No one module should combine transport, state reduction, command execution, and
protocol verification.

Expected repository surfaces are:

- new focused modules under `src/bilateral/coordination/`;
- one operator relay/coordinator entrypoint;
- one role-supervisor entrypoint shared by Billy and Iris;
- a preflight preparation extension for role-generated participant keys;
- test-only persistent fake service and child drivers;
- exact focused and process-E2E tests;
- machine prompts for the supervisor lifecycle;
- the demo-day runbook; and
- documentation gates that assert the minimal human action surface.

Low-level role, watcher, preflight, registration, and verifier CLIs remain
independently invocable for tests and operator-authorized diagnosis.

## 14. Documentation contract

The primary runbook must make the automated supervisor flow executable and
unambiguous. It must state:

- the user funds four displayed addresses and starts exactly two role sessions;
- the private launch manifest is supplied as part of each start;
- one Billy/Iris session pair covers both runs;
- one token per role is reused across both runs;
- one preflight covers both runs at one immutable SHA;
- rehearsal and stakeholder invitations, identities, descriptors, and output
  directories remain distinct;
- the coordinator polls funding without user confirmation;
- the coordinator transports only signed secret-free artifacts;
- physical separation is attested, not cryptographically proven;
- live code changes invalidate preflight and abort the stakeholder run;
- watcher and relay states never authorize; and
- only the fresh aggregate verifier can emit the authorizing literal.

The low-level manual commands remain in a recovery appendix, not the primary
happy path.

Documentation tests must reject a regression to manual phase signaling,
participant-private-key transfer, four role-session starts, or human artifact
copying.

## 15. Verification gates

Implementation is not complete until fresh evidence proves:

1. focused envelope, state-machine, persistence, TLS, client, supervisor, and
   coordinator tests pass;
2. the full relay adversarial matrix passes;
3. the separate-process deterministic three-transition session passes;
4. all existing bilateral protocol and operational tests remain green;
5. the documentation gate proves the two-start/funding-only human surface;
6. neither role, relay, coordinator, nor watcher can emit the authorizing
   literal;
7. every state and artifact requires `paymentMoved: false`;
8. no invitation, private key, raw capability, token, or generated live
   evidence is tracked by Git;
9. dependency and secret scans are clean;
10. three consecutive fresh `npm run verify` runs pass on the integrated tree;
    and
11. the integrated diff receives independent security, architecture, code, and
    completion review.

Live invitation generation, funding, preflight writes, Sepolia registration,
rehearsal, and stakeholder execution remain separately gated after the
deterministic build.

## 16. Stop conditions

The deterministic coordination build is complete only when:

- all interfaces in this specification exist and are covered;
- one process-isolated fake session proves the complete three-transition chain;
- the current manual coordination blockers are removed from the happy path;
- the documentation and tests enforce the approved human action surface;
- all verification gates in section 15 pass; and
- no known Critical, High, or material Medium finding remains.

The full goal is complete only after the user funds the four generated
addresses, starts the two machine sessions, and the live rehearsal and
stakeholder runs each produce independently verified three-anchor evidence.
