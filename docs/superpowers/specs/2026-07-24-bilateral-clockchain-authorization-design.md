# Bilateral Clockchain payment authorization design

Date: 2026-07-24

Status: Reviewed design specification. Not an implementation plan, and not an
approval to write to any live service.

## 1. Status and scope

### 1.1 What this document specifies

This specifies `clockchain.bilateral-authorization/v1`: a two-machine protocol in
which Billy (payer, Codex session, machine A) and Iris (payee, Claude Code
session, machine B) prove through Clockchain® that a `100 USD` payment
authorization was proposed, accepted, and acknowledged in that order, inside a
600-second window, with no funds moving.

It is the deliverable named in
[the Opus handoff](../../handoffs/2026-07-24-opus-distributed-bilateral-clockchain-handoff.md),
section "Suggested first Opus deliverable". It covers, in order:

1. the deployed Clockchain capabilities that were empirically verified, and the
   ones that were not;
2. the three candidate rendezvous approaches, the four judge lenses, and why the
   decision is a hybrid;
3. the canonical messages, digests, reference-id scheme, write call shape,
   payload-reveal channel, discovery channels, and verification recipe;
4. the state machine, expiry semantics, recovery rules, and the fail-closed
   matrix;
5. the versioned evidence schemas and the distributed manifest;
6. the role CLIs, role prompts, and operator runbook;
7. the deterministic and live test strategy; and
8. the trust, provenance, and honesty limits.

### 1.2 What this document does not specify

- It does not authorize any Clockchain write, any Ethereum write, any invitation
  creation, or any funding transaction.
- It does not replace, deprecate, or modify the shipped unilateral demo. The
  existing `clockchain.handshake-result/v1` path stays byte-stable; section 6
  states the exact seam a v2 must branch at.
- It does not specify decline, cancellation, settlement, refund, or any payment
  network integration. Iris can accept or let the proposal expire; silence and
  refusal are indistinguishable. This matches the handoff instruction to keep the
  first implementation narrow.
- It does not specify a UI. Both roles are CLI-first.
- It does not claim remote-execution attestation. See section 9.

### 1.3 The Phase -1 gate

No implementation may begin on any live-write-dependent part of this protocol
until the Phase -1 preflight scoping probe (section 4.2) is approved by the
operator and actually run, and its results recorded.

This is not a formality. Nine of the twelve capabilities this protocol depends
on can only be settled by a write, and no write of any kind has ever been
observed against this deployment by any probe. The single load-bearing unknown —
whether one machine can read the other machine's Clockchain record at all — has
three deployed tool descriptions asserting the *opposite* for adjacent surfaces.
If that unknown resolves badly, the rendezvous does not exist and the protocol
must change shape.

Deterministic, offline work may begin before the probe: the canonicalizer
extraction, the bilateral canonical profile, the block-time parser, the
reference-id module, the descriptor schema, the canonical messages and their
digest fixtures, the fake Clockchain, and the aggregate verifier's pure logic all
have zero live dependency. Everything that touches a real transport, a real
write, or a real acceptance run does not.

### 1.4 Provenance convention used throughout

Every capability claim in this document carries one of two markers:

- **VERIFIED** — observed first-hand during the 2026-07-24 read-only probe, with
  the observed response quoted or summarized. A reader can re-run the same
  read-only call.
- **UNVERIFIED** — not observed. The experiment that would settle it is named in
  the same sentence or in the adjacent table row.

A reader must never have to guess which. If a claim in this document has no
marker, it is a design decision, a repository fact with a `file:line` citation,
or a locally reproducible computation, and it is labelled as such.

Three repository-side claims in this document were reproduced on this tree at
HEAD `12cdaa2` while writing it, and are marked **REPRODUCED**.

**Citation convention.** Every `file:line` reference in this document is pinned to
commit `12cdaa2`, which is the tree the read-only probe, the three candidate
designs, the judge panel, and the synthesis were all produced against. All 33
citations were re-validated against `git show 12cdaa2:<path>` before this document
was finalized. Line numbers will drift as implementation lands, so each citation
also names its symbol; when a line number and a symbol name disagree, the symbol
name is authoritative and the line number should be re-derived at `12cdaa2`.

**Repository-state convention.** The same `12cdaa2` pin covers every present-tense
claim in this document about what the repository currently does — what a constant
is set to, which methods a validator checks, which tools a retry set contains,
which characters a module does or does not contain, and every "currently",
"already", "still", or "does not yet" phrasing. Each such claim is a snapshot of
`12cdaa2`, not a live status report, and it must be read as "was true at
`12cdaa2`". Implementation landing after `12cdaa2` will make some of them stale,
and a stale claim reads as outstanding work that has in fact already shipped.
Re-derive any repository-state claim against the integrated tree before acting on
it as an instruction. This applies with most force to the work table in section
5.7, which is written in the present tense throughout.

## 2. Verified deployed Clockchain capabilities

All observations in this section come from the read-only probe of the deployed
hosted Clockchain MCP service on 2026-07-24, roughly 20:06-20:09 UTC, recorded in
`.context/review-2026-07-24/capabilities.json`. No write of any kind was
performed.

This section exists to stop the next session from inventing a capability. If a
capability is not in table 2.1 with VERIFIED, it is not available for design
purposes until table 2.2 settles it.

### 2.1 Verified read surface

| Tool | Verified | Observed behaviour | Usable for | Not usable for |
| --- | --- | --- | --- | --- |
| `search_actions` | VERIFIED | Called 11 times against one known-good id. Exact hit returns a 1-element JSON array of a 13-field record. All 10 deliberate variants — prefix `8677:trust_handshake`, glob `8677*`, trailing space, leading space, case change, `%`, `%8677%`, SQL `_`, regex `.*` — returned `[]` with no error. | The only primitive that maps a party-chosen string to a record, and the only read that misses cleanly. Therefore the only correct polling primitive. | Any enumeration, browsing, prefix, glob, or wildcard. Byte-exact only. |
| `verify_cross_party` | VERIFIED | Called 9 times. With `{ledger_id, block_height}`: `onChain = {verifiedAgainst:"on-chain block", keyless:true, ledgerId, blockHeight (STRING), heightSource:"from the receipt", anchoredHash, assetReferenceId, note:"Read from the immutable on-chain block (/searchAssetFromChain) with NO api key — not the rewritable record cache."}` and `advisoryHashCheck:null`. With `ledger_id` alone, `heightSource` becomes `"discovered via the record cache (advisory)"`. With a WRONG height: `verifiedAgainst:"none"`, no cache fallback. | The authoritative anchoring check. The only call with a structured on-chain/cache discriminator. The only read reported keyless. | Fetching payload content. Bootstrapping a rendezvous — it needs a `ledgerId` or `hash` up front. |
| `verify_cross_party` with `hash` supplied | VERIFIED | `onChain:null`, and `advisoryHashCheck.ledger` returns the FULL 13-field cache record including `clientId` observed as a literal email address. With a wrong `block_height` AND the correct `hash` together: a hard on-chain FAILURE and a populated healthy-looking cache record in one response. | Discovery by digest, as a secondary channel only. | The authoritative check. This is the single most dangerous response shape in the API. |
| `resolve_agent` | VERIFIED | Called 6 times. Agents `8677`, `8679`, `8678`, `8680`, `1` resolved to five records across four owner addresses that are not this session's account. `99999999` returned `{agentId, status:"unknown"}` with no owner. Owner is returned all-lowercase. | A public, NON-client-scoped ERC-8004 chain read. The one discovery channel proven to work across accounts. Yields the peer's owner EOA and `agentURI`. | Reverse lookup. It is a point lookup by `agentId` only. |
| `get_block` | VERIFIED | Called on `latest` twice plus 6 explicit heights. Returns only `{blockHeight (NUMBER), proposerAddress, blockTime}`. `blockTime` is RFC3339 with 9 fractional digits. Re-reading height 1781135 returned a byte-identical `blockTime`. The same single proposer address appeared on every block across 2 days and ~88k heights. Heights `999999999` and `0` both returned the identical `502` message. | The only authoritative, immutable, per-record time source. The call that defeats a forged evidence package, because it re-fetches by height. | Discovery — it returns no record list. Distinguishing "block does not exist" from "service is down": one 502 message covers both. |
| `generate_audit_trail` | VERIFIED | Called on one known reference id. Returned `{assetReferenceId, events:[{ledgerId, assetReferenceId, assetHash, time:"2026-07-23T19:04:41.057495507Z", blockHeight, additionalInfo}], count:1, builtAt}`. `time` is normalized RFC3339 nanosecond, unlike the gateway's other formats. | Ordered multi-event trail keyed on one exact reference id, with `count` for duplicate detection. | Any key the caller cannot already state exactly. |
| `get_log_entry` | VERIFIED | Returns exactly 15 fields and no payload: `ledgerId, clientId, walletId, assetReferenceId, assetHash, hashType, versionNumber, additionalInfo, blockHeight, createdTimestamp, updatedTimestamp, assetName, type, status`. On a well-formed but nonexistent UUID it returned `Clockchain API error (500)`, not a 404 and not an empty result. On live record `370c7672-3a78-4c17-853c-e3037799562c` it returned `status:"anchored"` with `blockHeight:"3375636"`, a height that does not exist on chain. | Fetching metadata for a record whose `ledgerId` is already known. | Polling — it cannot distinguish "peer has not published" from "server is broken". Its `status` field is NOT evidence of anchoring; there is a live counterexample. |
| `get_time` | VERIFIED | Returns exactly `{latestBlockTime, latestBlockHeight}`. Format `DD-MM-YYYY_HH:MM:SS:mmm`, no timezone marker. Height is a STRING and lags `get_block("latest")` by 1. `get_time` returned height 1869480 at 20:08:14.986 while `get_block(1869480).blockTime` is `2026-07-24T20:08:13.788993755Z` — a 1.197 s gap. | A cheap liveness and height poll. | A record's anchor time. It is a query-time "now" clock. Never the expiry clock. |
| `get_timestamp` | VERIFIED | Returns `{consentedOffset:"-999.0", positiveVotesPercentage:"0.0", blockHeight, madMarzulloTime, nodeStatus:"Synced", systemTime, AbsTimeDifference, negativeVotesPercentage:"0.0", "nodeParticipation%":"0.0", totalNodes:"1.0"}`. Every value is a STRING, including the numerics. | Pool-health disclosure in evidence. | Expiry. `madMarzulloTime` is a "now" clock. `consentedOffset` `-999.0` is a sentinel for "no consensus offset available", not a real offset; applying it would shift time by 16.65 minutes. |
| `get_validation` | VERIFIED | Height 1781135: `{"Trust value percentage":"0.0", negativeVotes:"0", "Node participation percentage":"0.0", positiveVotes:"0"}`. Height 1869480: identical shape. Height 1781359, which anchors a real receipt: `Clockchain API error (500)`. Inside `build_evidence_package` it was `null` for the same height. | Per-height health disclosure only. | An authorization gate. It is 0/0/0.0 at the exact block where the prior live receipt successfully anchored, and errors or is absent on other real blocks. A rule keyed on positive vote count would reject every real receipt. |
| `build_evidence_package` | VERIFIED | Deterministic: two calls on one ledger returned byte-identical output with `pkgHash 39e186a8…`. Returns `{packageId, pkgHash, record, block, validation, plainEnglish, honestyNote}`. `block.blockHeight` is a NUMBER here and a STRING elsewhere. `validation` was populated for 1781135 and `null` for 1781359. For the phantom record `370c7672…`, `block:null` and `validation:null` yet `record.status` still `"anchored"` and `plainEnglish` still asserted anchoring at block 3375636. | A human-readable exhibit, and the source of the `honestyNote` disclosure sentence. | A self-contained trust root. Its embedded `block` and `validation` are unauthenticated and must be re-fetched. |
| `verify_package` | VERIFIED (verified broken) | Four calls. Honest package: `{valid:true, pkgHashMatch:true, anchorMatch:true}`. Tampered package with stale `pkgHash`: `valid:false, pkgHashMatch:false`, but `anchorMatch:TRUE` — `anchorMatch` covers only `record.assetHash`. Tampered package resubmitted with the `recomputedPkgHash` the tool itself had just returned: `valid:true, pkgHashMatch:true, anchorMatch:true` for a package asserting `blockTime "1999-01-01…"`, `"Trust value percentage":"100.0"`, `positiveVotes "999"`, and `honestyNote "Mainnet. Court-certified."`. The phantom cache-only record also returned `valid:true`; the sole discriminator was a free-text `note`. | Nothing in the trust path. | Anything. It is a demonstrated forgery oracle: submit tampered content with any `pkgHash`, read `recomputedPkgHash` from the reply, resubmit it, get `valid:true`. No knowledge of the serialization is needed. |
| `verify_asset` | VERIFIED | Correct hash: `{match:true, ledgerId, blockHeight, anchoredHash, currentHash, assetReferenceId}`. Wrong hash: identical shape with `match:false`. There is NO `verifiedAgainst` and NO `keyless` field in either response. | An advisory redundant cross-check at most. | The fail-closed decision. It exposes no on-chain/cache discriminator. `assertReceiptVerification` (`src/mcp.mjs:1461`) would correctly reject this response shape. |
| `tsa_status` | VERIFIED | Called with an invented commitment id. Returned `{commitmentId, assetReferenceId:"tsa:<commitmentId>", count:0, events:[]}` — a clean empty result. | Existence proof that the deployed service already supports a DERIVED namespaced reference id read back as an ordered multi-event trail with a count. This is the pattern `K(slot)` imitates. | Our protocol directly. The exact `commitmentId` derivation function is not published. |
| `get_identity_history` | VERIFIED | `did:agent:8677` returned `{did, events:[]}` — empty, because the demo never called `mint_identity`. Its own tool text states "cross-agent enumeration is backend-gated (searchAsset is exact-match + client-scoped)". | Nothing here. | Peer discovery. Absence is indistinguishable from a scoping miss; `[]` must never be read as "nothing revoked". |
| `verify_identity_at` | VERIFIED | `did:agent:8677` at a past instant returned `{authorized:false, reason:"No attested mint exists at or before T — identity did not exist yet.", note:"…Own-client history (cross-client discovery is backend-gated)."}`. | Confirming that it fails closed on unknown input. | Vouching for a peer's ERC-8004 identity. The ERC-8004 `agentId` namespace and the Clockchain DID namespace are NOT connected. |
| `list_schedules` | VERIFIED | Returned `[]`. Called specifically to make the service echo back this session's `clientId`. It did not. | Nothing. | Settling the scoping question. There is no read-only tool that reflects the caller's own `clientId` back. |

Two cross-cutting VERIFIED facts belong here rather than in any single row.

**Block cadence is 1.0238 s/block, empirically stable.** Direct adjacent-block
measurement 1781135 to 1781136 gave 1.023291 s. Long baselines gave 1.023851,
1.023890, and — over a 25-hour, 87,994-block span — 1.023737 s/block.

**`blockTime` is a lower bound on a record's true write time.** On both prior
live records, `createdTimestamp` is LATER than the record's own anchor block's
`blockTime`: by 0.450 s and by 0.314 s. Billy's `createdTimestamp` 19:00:52.165
falls strictly between block 1781135 at 19:00:51.715 and block 1781136 at
19:00:52.738. So `blockHeight` is the most recently SEALED block at record
creation; the record is not proven to be inside that block. This single fact
drives the upper-bound siding in section 5.3.

**The endpoint rate-limits aggressively, and the wire shape is not settled.**
VERIFIED: four concurrent read calls returned `{"error":"rate_limited",
"retry_after_seconds":26}`; a separate burst of roughly 6-9 reads in 30 s
returned `retry_after_seconds:31`, and a retry 20 s later still returned 10.
UNVERIFIED: whether that arrives as an HTTP 429 with a `Retry-After` header —
which `src/mcp.mjs:1200` handles — or as an HTTP 200 tool-result body, which
`parseToolResult` (`src/mcp.mjs:566`) would pass straight through as a normal
payload. Settled by capturing the exact wire form during the Phase -1 probe.

### 2.2 Unverified capabilities, and what would settle each

Nothing in this table may be assumed. Every row is a write or a second
credential, so none of it could be settled read-only.

| Capability | Status | Why it matters | Experiment that settles it |
| --- | --- | --- | --- |
| Cross-tenant read scoping: can machine A's token read a record written by machine B's token? | UNVERIFIED | The single load-bearing unknown for every candidate design. Every record ever observed carries the same `clientId`, so a client-scoped filter and a global index are observationally identical from one account. Three deployed tool descriptions assert scoping for adjacent surfaces: "searchAsset is exact-match + client-scoped", "cross-client discovery is backend-gated", "Cross-agent verification / enumeration are backend-gated". | Two machines on different IPs, two independently minted tokens. One `log_action` from B at an agreed exact reference id with a known `asset_hash`. From A, call and record SEPARATELY: (a) `search_actions` on that exact string, (b) `verify_cross_party({hash})`, (c) `verify_cross_party({ledger_id, block_height})`. Two shells on one host does not settle it. |
| Does `log_action` store a caller-supplied `asset_reference_id` verbatim? | UNVERIFIED | `search_actions` tolerates zero mutation across 11 verified negative variants. Any lowercasing, prefixing, namespacing, or truncation silently kills the rendezvous. Every reference id anyone has observed was server-generated by `attest_action`. | One `log_action` with a mixed-case, colon- and hyphen-bearing id, read back via `get_log_entry` AND `search_actions` on the byte-identical string. |
| Maximum byte length of `asset_reference_id` | UNVERIFIED | No maximum is documented anywhere. `MAX_IDENTIFIER_LENGTH = 256` at `src/mcp.mjs:17` is a client-side choice, not a server limit. The chosen scheme needs 85 bytes. | A length ladder at 64 / 128 / 192 / 256 / 512 bytes, each read back. |
| Do `log_action` records reach the immutable on-chain projection at all? | UNVERIFIED | Every `onChain` object ever observed came from an `attest_action` write. If `log_action` records only reach the rewritable cache, `verifiedAgainst` never becomes `"on-chain block"` and the entire trust path is gone — no protocol design recovers it. | After one `log_action`, call `verify_cross_party({ledger_id, block_height})` and require `verifiedAgainst === "on-chain block"`, `keyless === true`, and `assetReferenceId` echoed byte-for-byte. |
| Is a caller-supplied `asset_hash` anchored verbatim as `onChain.anchoredHash`? | UNVERIFIED | Every `anchoredHash` ever observed came from `attest_action`'s server-computed event hash. Step 5 of the verification recipe — the only step that binds MEANING to the anchor — depends entirely on this. | Supply a known 64-hex digest to `log_action` and require `onChain.anchoredHash` to equal it exactly. |
| Client-observed submit-to-verifiable latency for `log_action` | UNVERIFIED | The only figures anyone has (591 ms, 729 ms) are `attest_action` server-side `createdTimestamp`-to-`updatedTimestamp` deltas on records written by an earlier session. If a fresh write spends a cache-only window where `status` says `"anchored"` but `verifiedAgainst` is `"none"`, both runners fail closed on their OWN writes and the protocol never leaves the first transition. | Timestamp locally, submit one `log_action`, poll `verify_cross_party({ledger_id, block_height})` every 2 s for 120 s, record time-to-first `"on-chain block"`. |
| Does `log_action` succeed at 0.0% node participation with `allow_degraded:true`, and is `allow_degraded:false` genuinely refused? | UNVERIFIED | No write of any kind has ever been observed. The repo's reliance on `allow_degraded: true` at `src/run.mjs:1135` is code, not observation. The answer forces the product decision in section 5.5. | One `log_action` with `allow_degraded` omitted, then one identical call with `allow_degraded:true`. |
| Can multiple records coexist under one `asset_reference_id`, and does `search_actions` return them all? | UNVERIFIED | The entire duplicate-detection rule — `length` must be exactly 1 — is the defense against a forger racing the honest party at a known key. Every trail anyone read had `count:1`. | Three sequential `log_action` writes at one identical reference id, then one `search_actions` and one `generate_audit_trail`, asserting all three are returned with a count. Separately, two writes sharing one `asset_hash`, then `verify_cross_party({hash})` to see which is returned and whether selection is deterministic. |
| `idempotency_key` semantics on `log_action` | UNVERIFIED | Until proven, the write-intent marker plus `search_actions` precheck must carry all the weight, and an ambiguous write must fail closed rather than retry. | One `log_action`, then an identical retried call with the same `idempotency_key`, then `search_actions` on the key. |
| Rate-limit wire shape, scope, and sustainable rate | UNVERIFIED | Two sub-questions, both blocking. If the limit arrives as an HTTP 200 body it sails through `parseToolResult` and a naive poller reads a throttle as "peer has not published" — a fail-open in the one place the protocol must never fail open. And if the budget is per-account rather than per-IP, Billy's polling starves Iris's inside the 600 s window. | Capture the exact wire form, measure the sustainable serialized rate from one credential, then drive reads from two credentials concurrently. |
| Demo-token TTL and concurrent minting | UNVERIFIED | Nothing in the repo decodes, refreshes, or re-mints the token, and HTTP 401/403 is checked at `src/mcp.mjs:1190-1198` BEFORE every retry branch and throws immediately, so a mid-session expiry is an unrecoverable hard failure across two machines. | Mint a token, hold it, issue a trivial `get_time` at increasing intervals until a 401 appears. Separately, time two mints from two IPs. |
| Is `onChain.assetReferenceId` immune to the cache-rewrite path? | UNVERIFIED | The design deliberately puts the one party-controlled protocol key there BECAUSE it appears in the immutable projection. Its immutability was inferred from the tool's own note, never demonstrated. | Write a record, capture `verify_cross_party`'s `onChain`, attempt a cache update via the documented `PUT /ledger/{id}` path, re-read both the cache record and the on-chain projection, and diff which fields moved. |
| `log_action` response shape and success/failure signalling | UNVERIFIED | The design never reads an evidence field from a write response, but the runner still must distinguish "the write landed" from "the write was rejected" to decide whether to enter `AMBIGUOUS_WRITE`. | Observe one `log_action` response verbatim during the Phase -1 probe. |
| Is `blockHeight` always the last sealed block at creation, never a future block? | UNVERIFIED | Confirmed on 2 records only. If a record can ever be assigned a FUTURE block, `blockTime` stops being a lower bound and every expiry inequality in section 5.3 must be re-sided. | Submit a record deliberately timed a few ms before a block boundary and compare `createdTimestamp` against the assigned block's `blockTime`. |
| `complete_attestation` / `verify_receipt` response conformance | UNVERIFIED | Both tool names ARE present in the deployed tool list, so there is no missing-tool risk. But response-shape conformance is asserted by repo fixtures only, not by any observation. This protocol does not use either, so it is recorded for completeness rather than as a dependency. | One `attest_action(wait:false)`, then `complete_attestation`, then `verify_receipt`, comparing every field. |

### 2.3 One capability that is settled and must not be re-litigated

There is **no address-to-`agentId` reverse lookup available anywhere**. VERIFIED
read-only on the pinned RPC: `eth_getLogs` over a ~120-block range returns
`{"code":-32602,"message":"Archive requests require a personal token"}`;
`tokenOfOwnerByIndex(owner, 0)` reverts; `totalSupply()` reverts, so the registry
is not `ERC721Enumerable` and offers no scan bound. `balanceOf` and `ownerOf`
work keylessly, but only in the `agentId` to owner direction. Clockchain's
`resolve_agent` has the identical direction limit.

One judge lens corrected an overstatement here and the correction is preserved:
a ~10-block `eth_getLogs` window *does* return a clean empty result on this
endpoint; only at ~120 blocks does the archive gate fire. So a narrow recent-window
`Registered`-event filter is technically available as a best-effort lookup. It
does not change the conclusion, because two Sepolia transactions with
2-confirmation waits cannot be safely charged against a 600 s deadline either
way. This settles handoff open decisions #2 and #11 empirically.

## 3. Rendezvous options compared

The handoff required a comparison of exactly three approaches. Three independent
designs were produced against the probe results, then scored by four judge lenses
— honesty, security, feasibility, and demo. The panel split 2-2. This section
records the comparison, the split, and why the synthesis is a hybrid rather than
any one option as written.

### 3.1 The three candidates

**Option 1 — Clockchain-indexed shared session rendezvous** (`indexed_session`).
The operator issues one unpredictable session id `S` out of band. Every reference
id is derived from `S`. The proposal addresses a ROLE SLOT: `payee.agentId` is
explicitly `null`, and the slot is claimed by whoever publishes a valid
acceptance from an agent whose on-chain `agentURI` carries `sha256(S || ":payee")`.
Identity is bound by adding a `sessionCommitment` field to the ERC-8004
registration document. The payload is revealed by local brute-force enumeration
over `agentId` candidates in `[1, 1000000]` until one candidate's digest matches
the anchored hash.

**Option 2 — operator-signed session descriptor** (`operator_descriptor`).
ERC-8004 registration moves to a Phase-0 prerequisite outside the timed window.
Each agent returns `{address, agentId}` to the operator. The operator builds one
canonical descriptor pinning both identities, the terms, the expiry policy, the
repository SHA and the prompt SHA, signs it with an Ed25519 key whose public half
is committed in-repo, and delivers byte-identical bytes to both machines. Every
canonical payload is then a pure function of that descriptor. Clockchain
transports only `{ledgerId, blockHeight}` per transition.

**Option 3 — out-of-band proposal pointer** (`proposal_pointer`). The sealed
invitation is bumped to v2 carrying authenticated `role` and
`counterpartyAddress` fields. Billy writes the proposal, then reads out one
~62-character bearer pointer `ccb1p:<ledgerId>:<blockHeight>:<crc8>` which the
operator relays to Iris. From there every subsequent transition is found by
digest: because the canonical acceptance carries zero payee-chosen entropy, Billy
computes its digest himself and locates Iris's record with
`verify_cross_party({hash})` and nothing else. Iris's `agentId` and her EIP-191
signature ride inside the on-chain `assetReferenceId`, which requires roughly 181
bytes of undocumented reference-id capacity.

### 3.2 Comparison on the axes that decided it

| Axis | Option 1 indexed session | Option 2 operator descriptor | Option 3 proposal pointer |
| --- | --- | --- | --- |
| Runtime out-of-band data | None after the ticket | None | One ~62-char bearer pointer, inside the window |
| Pre-session out-of-band data | Session id `S`, terms, expiry, repo SHA, prompt SHA | Signed descriptor: both identities, terms, expiry, repo SHA, prompt SHA | Invitation v2: role and counterparty address; plus protocol constants |
| Primary discovery primitive | `search_actions(K)` | `search_actions(K)` | `verify_cross_party({hash})` |
| Discovery primitive's failure mode | Clean `[]` | Clean `[]` | Resolves through `advisoryHashCheck`, the rewritable cache path |
| Key-possession proof during the run | None. The payee slot is an open bearer role authenticated only by knowledge of `S` | None live; EIP-191 verified post-hoc by the operator verifier | EIP-191 signature parsed from the counterparty's own reference id |
| Payload reveal mechanism | 1,000,000-candidate local enumeration | None needed — content is 100% derivable | Reconstruction from the pointer plus an ERC-8004 read |
| Expiry siding | Optimistic: `blockTime(h) <= deadline` | Upper bound: `blockTime(h) + 1100 ms <= deadline` | Optimistic, disclosed but not closed |
| Ordering strictness | Strict `<` on heights | Strict `<` on heights | Non-strict `<=`, permitting two transitions in one block |
| Cache-vs-chain trap handling | Ignores `advisoryHashCheck` by discipline | Never passes `hash`, so the field cannot be populated | Makes the cache path its primary discovery primitive |
| Files touched on the secrets or recovery boundary | `src/registration.mjs` `buildRegistrationDocument` — ripples into the byte-for-byte URI comparison used by the recovery machinery | None. `src/registration.mjs` and `src/invitation.mjs` untouched | `src/invitation.mjs` `BUNDLE_KEYS`, `createPublicHeader` (the AES-256-GCM AAD), `PAYLOAD_KEYS`, plus both invitation scripts |
| Self-listed unverified capabilities | 19 | 18 | 19 |
| Behaviour if cross-tenant scoping fails | Dead. No in-design fallback | Degrades to a relayed pointer; canonical messages, digests, recipe, state machine, expiry math and verifier all unchanged | Its own text says the fallback "is a different design" |

### 3.3 The four judge lenses and the 2-2 split

| Lens | Option 1 | Option 2 | Option 3 | Winner |
| --- | --- | --- | --- | --- |
| Honesty | 5.5 | 7 | 8.5 | Option 3 |
| Security | 6.5 | 8.5 | 5 | Option 2 |
| Feasibility | 4.5 | 8 | 6.5 | Option 2 |
| Demo | 7.5 | 7 | 8.5 | Option 3 |

Option 1 took zero votes.

The two Option-2 judges scored on fail-closed strength, smallest diff, and
graceful degradation. The security lens found Option 2 wins six of seven named
adversarial axes: it is the only design where both identities are cryptographically
pinned before the protocol starts, with a triple binding (descriptor address
equals `ownerOf(agentId)` via `eth_call` equals `resolve_agent().owner`) plus
EIP-191 recovery; it is the only one that sides the expiry comparison to an upper
bound; and it is the only one that eliminates the cache-vs-chain trap
*structurally* by never passing `hash`, rather than by remembering to ignore a
field. The feasibility lens found its dependency graph shallowest and — decisively
— that it is the only design whose failure on the load-bearing unknown is a
configuration change rather than a redesign.

The two Option-3 judges scored on demo narrative and commercial premise. The
honesty lens found Option 3's acceptance-to-acknowledgment leg is a genuine
zero-out-of-band Clockchain rendezvous and the strongest TRUE claim any of the
three can make, and that Option 3 is the only design where Billy actually knows
who he is paying. The demo lens applied an explicit test — Clockchain is the
rendezvous rather than decoration if and only if information decisive to the
protocol and unavailable from any other channel flows through Clockchain from one
party to the other — and scored what each design pushes through that pipe:

- Option 1: peer identity, act, time, order. Terms and session id are pre-shared.
- Option 2: act, time, order only. Identity and terms are pre-pinned.
- Option 3: terms-opening, peer identity and signature, act, time, order.

Both sides are right about their axis. Neither judgment is a mistake to be
overridden.

### 3.4 Why the synthesis is a hybrid, not a winner

The disagreement resolves once you notice that **Option 2's register-first move
removes Option 3's most expensive dependencies**. If both `agentId`s are pinned
in a signed descriptor, then:

1. The acceptance reference id becomes derivable by Billy, so Option 3 no longer
   needs `verify_cross_party({hash})` as its SOLE discovery primitive. That was
   Option 3's real weakness: the call resolves through `advisoryHashCheck`, which
   is the rewritable cache path the repository's own verification discipline says
   to ignore, and the path most likely to be client-scoped.
2. The ~181-byte reference id needed to carry a 130-hex signature is no longer
   required, which kills the most aggressive undocumented-capacity assumption in
   the whole candidate set.
3. The invitation-v2 change becomes unnecessary, removing the highest-blast-radius
   edit anyone proposed. `src/invitation.mjs` is the secrets boundary and
   `createPublicHeader` is the AES-256-GCM AAD, so any header change alters
   authentication.

That leaves exactly one honest objection to Option 2, and it is the one both
Option-3 judges pressed and Option 2 itself conceded: **the proposal content is
100% derivable from the operator's descriptor, so Iris can print Billy's "payment
intent" before he runs.** That is a real fidelity gap against handoff step 1
("Billy creates a payment intent"). Option 2's own sentence is that calling the
proposal a payment intent oversells it, because the intent was the operator's.

The synthesis closes that gap with a **bounded** version of Option 1's
derive-and-confirm — not its 1,000,000-candidate sweep, which is unsellable in a
room and whose bound is unverifiable since `totalSupply()` reverts, but an
8-candidate allowlist. Billy genuinely chooses one amount; Iris learns his choice
only from the immutable anchored digest. Three bits of real payer choice, zero
network calls, a collision bound of roughly 8 in 2^256, and a watchable demo beat.

The chosen design therefore takes:

| Graft | From | What it buys |
| --- | --- | --- |
| Register-first, `agentId`s pinned in a signed descriptor | Option 2 | Resolves handoff open decisions #2 and #11; removes Option 3's two most expensive dependencies |
| Ed25519 operator signature with the public key committed in-repo at the pinned `repositorySha` | Option 2 | A third party checks the signature against the repository, not against the key shipped inside the file. This is the answer to handoff open decision #10 |
| Upper-bound expiry siding | Option 2 | Turns a disclosed ~1.02 s hole into a closed one |
| Omit `hash` on the authoritative `verify_cross_party` call | Option 2 | The most dangerous response shape cannot exist in-process, and the operator's email is never pulled into memory |
| Extract the existing canonicalizer instead of writing a second one | Option 2 | Two divergent canonicalizers in one repository is a latent correctness bug |
| Reject integer-like string keys; ASCII-only bounded strings | Option 2 | Closes a silent cross-machine determinism defect (section 4.5) |
| Phase -1 preflight scoping probe | Option 1 | Settles the design-killing unknown before any invitation, gas, or protocol state is spent |
| Mandatory post-write read-back | Option 1 | Converts "does the gateway store a caller-supplied reference id verbatim?" from a silent assumption into a detected fail-closed condition |
| Per-slot write-intent marker plus `search_actions` precheck | Option 1 | Makes every irreversible write crash-safe without trusting unverified `idempotency_key` semantics |
| Bounded candidate enumeration, N <= 8 | Option 1, at a defensible scale | Restores real payer choice and closes Option 2's fidelity gap |
| Trust-path ban list encoded as tests | Option 1 | Stops the ban from decaying into a comment |
| Explicit machine-readable rendezvous disclosure object | Option 1 | The stakeholder claim degrades automatically with the mechanism |
| Digest-hash discovery as a documented secondary channel | Option 3 | A second life if `search_actions` turns out client-scoped |
| No state derived from a write response | Option 3 | Neutralizes the completely unobserved `log_action` response shape |
| Value domain narrowed to strings and booleans, no numbers anywhere | Option 3 | Removes the entire cross-machine numeric ambiguity class |
| Reference-id charset restricted to `[0-9a-z:]` | Option 3 | A lowercasing or punctuation-stripping gateway normalizer cannot silently corrupt the key |
| Derivability guard test over the message key sets | Options 1 and 3 | Converts "never add a free-form field" from a convention into a mechanically enforced invariant |
| Explicit `AMBIGUOUS_WRITE` terminal state | Option 3 | Names the state Option 2 only described |

### 3.5 What was explicitly not adopted

**Option 1's `sessionCommitment` inside the ERC-8004 `agentURI`.** Attractive,
because it binds role to key on-chain through a public, non-client-scoped read.
Rejected for v1 because it changes `buildRegistrationDocument` and therefore the
`agentURI` bytes, and `src/registration.mjs` compares `initialURI` and `finalURI`
byte-for-byte through `verifyRegistrationRecoveryEvidence` and
`verifyMetadataTransactionEvidence`. It ripples straight into the recovery
machinery that protects the currently working demo. Keep it as an optional v1.1
follow-up behind an additive, bilateral-only document builder, gated by a
decision.

**Option 3's invitation schema v2.** Elegant and commercially natural, but the
descriptor already carries both addresses and both `agentId`s, so it buys nothing
here and would touch `BUNDLE_KEYS`, `createPublicHeader` (the AEAD's additional
authenticated data, so any header change alters authentication), `PAYLOAD_KEYS`,
and both invitation scripts.

**Option 1's 1,000,000-candidate enumeration.** Replaced by the 8-candidate
allowlist. The bound was unverifiable, the mechanism is unsellable, and it existed
only to work around the missing address-to-`agentId` lookup that register-first
solves outright.

## 4. The chosen protocol: `clockchain.bilateral-authorization/v1`

Full name of the decision: descriptor-pinned, register-first, dual-channel
Clockchain rendezvous with bounded payer choice.

### 4.1 Phase overview

```text
Phase -1  PREFLIGHT SCOPING PROBE   (both machines, throwaway writes, mandatory gate)
Phase  0  REGISTER-FIRST            (both machines, Ethereum, outside the timed window)
Phase  1  OPERATOR DESCRIPTOR       (operator, offline, signed)
Phase  2  PROPOSED                  (Billy writes M1)      -- the 600 s window opens here
Phase  3  ACCEPTED                  (Iris writes M2)
Phase  4  ACKNOWLEDGED              (Billy writes M3)
Phase  5  AUTHORIZED                (operator aggregate verifier, fresh process)
```

Phases -1, 0 and 1 are outside the timed window. Only phases 2, 3 and 4 are
inside it. Phase 5 is unbounded in time and runs on a third machine.

### 4.2 Phase -1: preflight scoping probe (mandatory gate)

Before any invitation is consumed, any gas is spent, or any protocol state
exists, each machine writes ONE throwaway `log_action` at
`cbv1:probe:<32hex>:payer` or `cbv1:probe:<32hex>:payee` with a random 64-hex
digest. Each machine then polls for the PEER's probe through BOTH
`search_actions(peerKey)` and `verify_cross_party({hash: peerDigest})`, and
finally runs `verify_cross_party({ledger_id, block_height})` against the peer's
record.

Record which of the three channels resolved, separately. If neither discovery
channel resolves the peer's probe within the bounded window, the terminal state
is `RENDEZVOUS_UNAVAILABLE`, it is published, and the run stops.

This settles the single load-bearing unknown at the cost of two throwaway writes
instead of two invitations plus gas plus a stakeholder's afternoon. It doubles as
the live measurement of write-to-on-chain-verifiable latency and of the real
rate-limit budget, which are two more of the unverified rows in table 2.2.

The probe must run from two physical machines on different IPs. Two shells on one
host prove nothing, because a client-scoped filter and a global index are
observationally identical from one account.

### 4.3 Phase 0: register-first

Each agent runs the EXISTING, UNCHANGED `src/registration.mjs` path with its
invitation, outside the timed window, and returns `{address, agentId, registerTx,
metadataTx}` to the operator.

This is forced, not preferred. Section 2.3 records why: there is no
address-to-`agentId` reverse lookup, and two Sepolia transactions with
2-confirmation waits cannot be safely charged against a 600 s deadline.

**State this openly rather than absorbing it: the live bilateral window performs
NO Ethereum writes.** That is a safety win and a narrowing of the existing "a
clean session does everything end to end" story. It needs explicit operator
sign-off (section 10).

### 4.4 Phase 1: the signed session descriptor

Schema `clockchain.bilateral-session-descriptor/v1`, exact key set, delivered
byte-identical to both machines as:

```json
{
  "descriptor": { "...": "see below" },
  "operator": {
    "algorithm": "ed25519",
    "keyId": "<operator key id>",
    "publicKey": "<base64 raw public key>",
    "signature": "<base64 signature over canonicalBytes(descriptor)>"
  }
}
```

The signature is over `canonicalBytes(descriptor)`. The PUBLIC key is committed
in-repo at `docs/operator-keys/<keyId>.pub` at the pinned `repositorySha`, so a
third party checks the signature against the repository rather than against the
key shipped inside the file. A descriptor whose shipped `publicKey` does not
match the repository-committed key at that SHA is rejected before any network
call.

The descriptor itself, with its exact key set:

```json
{
  "amountOptions": [{ "currency": "USD", "value": "100" }],
  "chainId": "11155111",
  "expirySeconds": "600",
  "namespace": "cbv1",
  "payee": {
    "address": "0x<40 lowercase hex>",
    "agentId": "<decimal string>",
    "displayName": "Iris",
    "role": "payee"
  },
  "payer": {
    "address": "0x<40 lowercase hex>",
    "agentId": "<decimal string>",
    "displayName": "Billy",
    "role": "payer"
  },
  "paymentMoved": false,
  "promptSha256": "<64 lowercase hex>",
  "protocol": "clockchain.bilateral-authorization/v1",
  "protocolVersion": "<pinned constant>",
  "registry": "0x8004a818bfb912233c491871b3d84c89a494bd9e",
  "repositorySha": "<40 lowercase hex>",
  "schema": "clockchain.bilateral-session-descriptor/v1",
  "sessionId": "<32 lowercase hex, 128-bit CSPRNG>",
  "settlement": "not-executed"
}
```

`amountOptions` holds at most 8 entries, sorted, unique.

```text
D_session = sha256hex(canonicalBytes(descriptor))
```

`repositorySha` and `promptSha256` live inside the signature, so a machine
running a different repository or prompt version produces a different
`D_session`, different reference ids, and different digests. Every check then
fails closed cryptographically rather than by narration. This is the answer to
handoff open decision #10, and it is the strongest provenance statement available
without claiming remote-execution attestation.

### 4.5 Canonical digest rules

Reuse the repository's already-covered canonicalizer rather than writing a second
one. Extract `canonicalizeReceiptEventValue` (`src/evidence.mjs:146`) into
`src/canonical.mjs`, re-implement `computeReceiptEventHash` (`src/evidence.mjs:241`)
on top of it, and pin the v1 regression fixture FIRST:

```text
computeReceiptEventHash({agentId:"8677", action:"trust_handshake", inputs:{}, outputs:{}})
  === c37387429ff4f787fecb2a5c5a64a277696ee6d768fcb2d5564e7e2268e6dd02
```

REPRODUCED on this tree at HEAD `12cdaa2` under Node v22.23.1 while writing this
document. Pin it as a failing-first regression test before the refactor, so any
drift breaks the existing demo loudly rather than silently.

Then layer a bilateral profile in `src/bilateral/canonical.mjs` with four
additional rules.

**Rule 1 — no numbers anywhere.** The value domain is narrowed to STRING,
BOOLEAN, nested plain objects, and dense arrays. `blockHeight`, `amount`,
`expirySeconds`, `agentId` and `sequence` are all decimal strings. This
eliminates every integer and float precision ambiguity across two machines.
Note the boundary: this rule governs digest *preimages*. It does not govern MCP
wire arguments, where `version_number: 1` remains a number because the deployed
schema expects one.

**Rule 2 — reject integer-like string keys.** This is a real defect in the
current canonicalizer, which accepts rather than rejects them.

REPRODUCED on this tree under Node v22.23.1: an object with keys inserted in the
order `b`, `"10"`, `"2"`, `a` serializes as `{"2":3,"10":2,"b":1,"a":4}`, and
`Reflect.ownKeys` returns `["2","10","b","a"]`. JavaScript's integer-like key
ordering overrides the canonicalizer's sort. Output stays deterministic for one
implementation, but the "keys are sorted" invariant is silently false, so any
independent re-implementation of the canonicalizer computes a different digest.
For a protocol whose entire correctness rests on two machines computing the same
32 bytes, that is not acceptable. The bilateral profile rejects such keys, and
the rejection is a test.

**Rule 3 — printable ASCII only.** Every string field is restricted to
`0x20-0x7E`, bounded length at most 256, no control characters, no leading or
trailing whitespace. This removes the whole Unicode-normalization class from a
two-machine byte-equality argument.

**Rule 4 — address casing.** Addresses are lowercased WITH the `0x` prefix inside
every digest preimage. EIP-55 checksum casing never enters a preimage. Note that
`resolve_agent` returns the owner all-lowercase (VERIFIED) while
`src/run.mjs:1085` passes the checksummed registration address, and the existing
comparison survives only because `verificationValuesMatch` (`src/mcp.mjs:1322-1329`)
special-cases a 40-hex address with a `toLowerCase` compare. That path is
load-bearing, not incidental.

The digest is the lowercase hex SHA-256 of the UTF-8 bytes of `JSON.stringify`
over the rebuilt null-prototype object. That 64-hex string is BOTH the message
digest and the `asset_hash` argument.

### 4.6 Canonical messages

**M1 `PROPOSED`**, written by Billy at `K("proposal")`:

```json
{
  "amount": { "currency": "USD", "moved": false, "value": "<one of descriptor.amountOptions>" },
  "expirySeconds": "600",
  "kind": "proposal",
  "payee": { "address": "0x<40 lowercase hex>", "agentId": "<decimal string>" },
  "payer": {
    "address": "0x<40 lowercase hex>",
    "agentId": "<decimal string>",
    "reference": "eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:<decimal string>"
  },
  "predecessor": null,
  "protocol": "clockchain.bilateral-authorization/v1",
  "schema": "clockchain.bilateral-transition/v1",
  "sequence": "1",
  "sessionDigest": "<D_session>"
}
```

The digest of these canonical bytes is `H1`.

**M2 `ACCEPTED`**, written by Iris at `K("acceptance")`: the same head, with
`"decision":"ACCEPT"`, `"kind":"acceptance"`, `"sequence":"2"`, `amount` copied
from the RECOVERED M1, and:

```json
{
  "predecessor": {
    "anchoredHash": "<H1>",
    "blockHeight": "<h1>",
    "kind": "proposal",
    "ledgerId": "<uuid>"
  }
}
```

The digest is `H2`.

**M3 `ACKNOWLEDGED`**, written by Billy at `K("acknowledgment")`:
`"kind":"acknowledgment"`, `"sequence":"3"`, `"outcome":"ACKNOWLEDGED"`,
`"paymentMoved":false`, `predecessor` set to the acceptance triple, and
`proposal` set to the proposal triple. The digest is `H3`.

**Divergence-proof predecessor rule.** `predecessor.ledgerId` and
`predecessor.blockHeight` are DEFINED as the values returned by
`verify_cross_party({ledger_id, block_height}).onChain` — never from a write
response, never from any cache field. Both sides derive them from the same
authoritative immutable read, so the digests cannot diverge.

**Derivability guard, enforced by test rather than convention.** M2 and M3 have
ZERO free entropy. A guard test enumerates their key sets and asserts they are a
subset of an explicit derivable-field allowlist. The moment anyone adds a memo, a
local timestamp, or a per-run nonce, the counterparty can no longer derive the
digest and the Clockchain-only leg silently stops working. This test is what
stops that.

### 4.7 Reference-id scheme

Charset strictly `/^[0-9a-z:]{1,120}$/` — lowercase only, `:` the sole separator,
asserted before every write and before every search.

Rationale: `log_action`'s sibling field `additional_info` is DOCUMENTED to have
punctuation stripped server-side, which proves a normalizing path exists
somewhere in this gateway. So the scheme uses only the one separator
demonstrably present in stored ids (VERIFIED examples:
`8677:trust_handshake:1784833252067`, `tsa:{commitmentId}`).

```text
K(slot) = "cbv1:" + D_session + ":" + slot,   slot in {proposal, acceptance, acknowledgment}
```

Maximum length is `5 + 64 + 1 + 15 = 85` bytes. All three keys are pure functions
of the signed descriptor — no timestamps, no counters, no server-assigned values
— so both parties AND the offline verifier derive them independently. Probe keys
are `cbv1:probe:<32hex>:payer` and `cbv1:probe:<32hex>:payee`.

**Signatures do not ride in the reference id.** This is a deliberate break from
Option 3. With `agentId`s pinned in the descriptor there is no non-derivable
field left that needs to travel there, so the ~181-byte capacity assumption is
unnecessary — and it was the single most aggressive undocumented assumption in
the candidate set. EIP-191 acceptance and acknowledgment signatures travel in the
party result packages and are verified by the aggregate verifier against three
independent sources: the descriptor-pinned address, `ownerOf(agentId)` via
`eth_call`, and `resolve_agent(agentId).owner` compared case-insensitively.

### 4.8 The exact write call shape

Identical for all three transitions:

```text
log_action({
  asset_reference_id: K(slot),
  asset_hash:         H_i,
  hash_type:          "SHA-256",
  version_number:     1,
  idempotency_key:    sha256hex(D_session + "|" + slot).slice(0, 32),
  wait:               true,
  wait_ms:            20000,
  allow_degraded:     true
})
```

Three parameters are banned, each for a specific reason:

- **NEVER `content`.** The server would SHA-256 a serialization we do not
  control. VERIFIED from the deployed schema: "Pass content (the server
  SHA-256-hashes it — the content is hashed, never stored) OR a pre-computed
  asset_hash."
- **NEVER `did`.** Its schema says only that it "is included in the reference id",
  with no specified prefix or separator. Passing it would silently change the
  searchable key in an undocumented way and break the peer's derivation.
- **NEVER `additional_info`.** It is disqualified twice over: absent from the
  immutable on-chain projection (VERIFIED — the `onChain` object carries only
  `ledgerId`, `blockHeight`, `anchoredHash`, `assetReferenceId`), and documented
  to have punctuation and JSON stripped server-side.

`allow_degraded: true` is not optional. See section 5.5.

### 4.9 The bounded derive-and-confirm payload-reveal channel

Clockchain never carries a byte of the payment intent, and this design does not
pretend otherwise. VERIFIED: `get_log_entry` returns 15 fields and no payload,
and the immutable on-chain projection returned by `verify_cross_party` is only
`{ledgerId, blockHeight, anchoredHash, assetReferenceId}`. Everything else lives
in the cache that the tool's own text names `PUT /ledger/{id}` as able to rewrite.

Every field of every message is therefore one of exactly four kinds:

1. a protocol constant pinned in shared code;
2. a field of the signed descriptor both machines hold byte-identically;
3. a value Clockchain itself returns — `ledgerId` and `blockHeight` — genuinely
   revealed at runtime and not computable by either party in advance; or
4. ONE bounded choice from a descriptor-pinned allowlist: `amount`, chosen by
   Billy from at most 8 options.

Iris reconstructs at most 8 candidate proposals locally, digests each, and
requires EXACTLY ONE to equal `onChain.anchoredHash`. Zero matches or two or more
matches is `AMOUNT_UNRESOLVED`, the distinct terminal code defined in section 5.1,
never confusable with a plain digest mismatch — which is `BINDING_MISMATCH` and
stays `BINDING_MISMATCH`. The enumeration is purely local: zero network calls, so
it costs nothing against the rate limiter, and the aggregate verifier re-runs it
independently rather than trusting either package's stated amount.

This is the mechanism that makes the demo a choice rather than a ceremony. Three
bits of real payer choice, bounded and pinned.

M2 and M3 need no reveal at all — they are pure functions of the descriptor plus
the anchors, which is precisely why Billy can find Iris's acceptance by computing
its digest himself. That is the real Clockchain-only rendezvous leg.

**Hard ceiling, stated permanently.** This works ONLY because the message space
is tiny by construction. Add a free-form memo, an arbitrary amount, or a URL and
the candidate space becomes unbounded and this channel collapses. The derivability
guard test of section 4.6 is what enforces that forever.

### 4.10 Dual discovery channel

**Primary: `search_actions(K(slot))`.** VERIFIED as the only read that misses
cleanly — an empty array, not an error — which makes it the only correct polling
primitive. The result MUST be an Array. A non-array, including an in-body
`{"error":"rate_limited"}` object, is a hard error and NEVER "absent". Length 0
means keep polling. Length greater than 1 is a DUPLICATE and fails the session.

**Secondary: `verify_cross_party({hash: H_i})`.** Used only if the Phase -1 probe
shows `search_actions` is client-scoped. For M2 and M3 the counterparty derives
the digest directly; for M1 the reader tries each of the at most 8 candidates.

**Banned as a poller: `get_log_entry`.** VERIFIED: it returns HTTP 500 on a
well-formed nonexistent UUID, so it cannot distinguish "peer has not published"
from "server is broken".

The evidence records which channel actually resolved. That field is required, and
section 6.4 explains why it drives the stakeholder sentence.

### 4.11 The authoritative per-transition verification recipe

Every step is required. No step may be skipped because an earlier one looked
convincing.

1. `search_actions(K)` returns an Array of length exactly 1. Length 0 and length
   greater than 1 are handled by the fail-closed matrix, not here.
2. `verify_cross_party({ledger_id, block_height})` with `block_height` ALWAYS
   explicit and `hash` DELIBERATELY OMITTED.
   - Omitting `block_height` lets the rewritable cache choose which block is
     checked. VERIFIED: `heightSource` flips from `"from the receipt"` to
     `"discovered via the record cache (advisory)"`.
   - Omitting `hash` keeps `advisoryHashCheck` null, so the single most dangerous
     response shape in the API — `verifiedAgainst:"none"` alongside a populated,
     healthy-looking cache record with `isRecordExist:true` — cannot exist
     in-process at all, and the operator's email is never pulled into memory.
     Not passing the argument is strictly stronger than remembering to ignore it.
     Note `src/run.mjs:1185-1189` currently DOES pass `hash`; the bilateral path
     must not.
3. Require `onChain.verifiedAgainst === "on-chain block"` AND
   `onChain.keyless === true`. Reuse `assertCrossPartyVerification`
   (`src/mcp.mjs:1518-1561`) verbatim — it already gets this exactly right.
4. Require `onChain.ledgerId`, `canonicalDecimalText(onChain.blockHeight)`
   (`src/mcp.mjs:1477-1495`; heights are STRING here and NUMBER in `get_block`),
   `onChain.anchoredHash`, and `onChain.assetReferenceId` to equal the expected
   binding byte-for-byte.
5. Recompute `H_i` locally and require `H_i === onChain.anchoredHash`. **This is
   the ONLY step that binds MEANING to the anchor.**
6. Call `get_block(blockHeight)` independently for `blockTime`. This is the only
   clock.
7. Call `resolve_agent(peerAgentId)`: `status` must be `"active"` and `owner` must
   equal the descriptor address, compared case-insensitively. This is a public,
   non-client-scoped ERC-8004 read.
8. Ignore entirely, and encode the ban as tests rather than comments.

**The trust-path ban list.** These are excluded from the trust path completely:

| Banned | Why, with provenance |
| --- | --- |
| `advisoryHashCheck` and every field under it | VERIFIED: it returns a populated healthy-looking record alongside a hard on-chain FAILURE. It also carries `clientId` and `walletId`, observed as a literal email address. |
| `record.status`, including `"anchored"` | VERIFIED live counterexample: ledger `370c7672-3a78-4c17-853c-e3037799562c` reports `status:"anchored"` at block `3375636`, a height that does not exist on chain. Pin it as a fixture. |
| `verify_package.valid`, `.pkgHashMatch`, `.anchorMatch` | VERIFIED forgery oracle: submit tampered content with any `pkgHash`, read `recomputedPkgHash` from the reply, resubmit it, get `valid:true`. Also returns `valid:true` for a cache-only record. |
| `verify_asset.match` | VERIFIED: the response carries no `verifiedAgainst` and no `keyless` field, so it has no on-chain/cache discriminator. |
| `build_evidence_package`'s embedded `block` and `validation` | VERIFIED: they are unauthenticated attacker-controlled data inside a package. Re-fetch by height with `get_block` and `get_validation` instead. |
| `additionalInfo`, `versionNumber`, `assetName`, `type` | Cache-only, absent from the immutable projection; `additional_info` is additionally documented to have punctuation stripped. |
| `createdTimestamp`, `updatedTimestamp`, and every other cache timestamp | VERIFIED: they live in the rewritable cache, and two endpoints disagree on the same record — `search_actions` reported `updatedTimestamp` null while `build_evidence_package` reported a value for the identical ledger id. |
| `get_validation` as a gate | VERIFIED: 0/0/0.0 at the exact block where the prior live receipt anchored, and a 500 on another real block. Disclosure only. |

### 4.12 Mandatory post-write read-back

Immediately after each write, and before the peer can depend on the key:

1. Assert `search_actions(K)` returns length exactly 1, with `assetReferenceId`
   equal to `K` byte-for-byte and `assetHash` equal to `H_i`.
2. Assert `verify_cross_party({ledger_id, block_height}).onChain.assetReferenceId`
   equals `K`.

This converts the unproven "does the gateway store a caller-supplied reference id
verbatim?" assumption (table 2.2) into a DETECTED fail-closed condition.

### 4.13 Write-intent discipline and recovery rules

One local marker per slot, created with the `fs` flag `"wx"`, mirroring the
existing `createAttestationMarker` pattern at `src/run.mjs:1118`. It records
`{sessionDigest, slot, digest, referenceId}` and is `fsync`'d before the write.

- If the marker exists at startup, the runner MUST NOT write and may only
  re-discover.
- A `search_actions(K)` precheck runs before every write. If a record already
  exists at `K`, adopt it ONLY if its `assetHash` equals the locally computed
  `H_i`; otherwise `FAILED`.
- Never blind-retry an irreversible write. An ambiguous outcome switches the
  runner permanently to discovery-only.

The mitigation is the design. `log_action`'s `idempotency_key` semantics are
UNVERIFIED (table 2.2) and must not carry weight.

A failed run cannot be replayed at the same keys, because a second write would
make `search_actions` return length 2 and fail the session closed. Every retry
needs a fresh `sessionId` and therefore a fresh operator descriptor. That is a
deliberate cost of strict duplicate detection.

## 5. State machine, expiry semantics, and the fail-closed matrix

### 5.1 States

```text
UNSTARTED -> RENDEZVOUS_OK -> PROPOSED -> ACCEPTED -> ACKNOWLEDGED -> AUTHORIZED
```

Terminal failure states, all non-authorizing:

```text
RENDEZVOUS_UNAVAILABLE
EXPIRED
DUPLICATE
AMBIGUOUS_WRITE
BINDING_MISMATCH
ANCHOR_UNVERIFIED
RATE_BLOCKED
AMOUNT_UNRESOLVED
FAILED
```

`AMOUNT_UNRESOLVED` is a design decision made here, not a code the synthesis or
any of the three candidate designs names; the name was proposed by this
document's design review. Matrix row 8 and section 4.9 both require the
bounded-amount enumeration failure to carry "a distinct code never confusable
with a plain digest mismatch", and no upstream design document supplies one; left
unnamed, two independent implementations would invent two different names for the
same terminal state. This document closes that gap by naming it rather than
leaving it open, so an implementer must use this exact spelling and must not
invent a second name. The other eight codes are the synthesis's terminal list
verbatim. Approving this specification approves this one name and nothing further
about amount handling.

Two rules bind the whole product:

- `AUTHORIZED` is emitted ONLY by `scripts/verify-bilateral-results.mjs`. Neither
  agent runner may ever print it, and a test asserts that no runner can reach it
  under any input.
- `paymentMoved` is `false` in every state, including `AUTHORIZED`.

There is no path from `EXPIRED` to `AUTHORIZED`.

### 5.2 The authoritative clock

**Named clock: `get_block(blockHeight).blockTime`, re-fetched by height, and
nothing else.**

It is RFC3339 with nanosecond precision, it is the only immutable, on-chain,
per-record time source, it was VERIFIED byte-identical on re-read, and re-fetching
by height is exactly what defeats the forged-evidence-package attack.

Banned clocks, each for a demonstrated reason:

| Banned clock | Reason, with provenance |
| --- | --- |
| `get_time.latestBlockTime` | VERIFIED query-time "now" clock. It returned height 1869480 at local 20:08:14.986 while `get_block(1869480).blockTime` is 20:08:13.789 — a 1.197 s divergence. Its height also lags `get_block("latest")` by 1. |
| `get_timestamp.madMarzulloTime` | VERIFIED query-time "now" clock, same class. `consentedOffset` is the sentinel `-999.0`, not a real offset. |
| `get_log_entry.createdTimestamp` / `.updatedTimestamp` | VERIFIED cache fields, rewritable via the documented `PUT /ledger/{id}` path, and two endpoints disagree on the same record. |
| Either machine's local wall clock | Used only for poll pacing and an advisory pre-write abort. It never enters an authorization decision. |

Mixing clocks injects up to ~1.2 s of systematic error against a 1.0238 s/block
cadence — enough to invert `PROPOSED`/`ACCEPTED` adjacency.

**Parser.** A dedicated strict regex,
`^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{1,9})Z$`, feeding
`Date.UTC` with the fraction TRUNCATED toward zero to milliseconds.
`Date.parse` must NEVER touch a Clockchain gateway string, and a test asserts
`Date.parse` is unreachable from the module.

Two REPRODUCED hazards drive this, both re-run on this tree under Node v22.23.1:

- `Date.parse("24-07-2026_20:08:42:979")` is `NaN`, and every `NaN` comparison is
  false. A naive `(now - t) > 600000` check would SILENTLY NEVER FIRE and the
  10-minute window would never close.
- `Date.parse("07-08-2026")` silently SUCCEEDS, reading the string as MM-DD-YYYY
  midnight in the HOST's LOCAL zone. The instant it returns therefore depends on
  where the code runs, so no single literal can be pinned: under `TZ=UTC` it is
  `2026-07-08T00:00:00.000Z`, under `TZ=America/Los_Angeles` (PDT)
  `2026-07-08T07:00:00.000Z`, and under `TZ=Asia/Tokyo`
  `2026-07-07T15:00:00.000Z` — three instants and two different calendar days from
  one input. Re-run it with an explicit `TZ` to reproduce a given literal; the
  `TZ=UTC` form is the one quoted here. That host-dependence is itself part of the
  hazard: the same evidence parsed on two machines in two zones can disagree.
  On top of it, because Clockchain emits DD-MM-YYYY, any value with day at most 12
  parses to the WRONG DAY. This is worse than the `NaN` case, because it fails
  silently.

A third REPRODUCED fact shapes the evidence schema:
`new Date("2026-07-24T20:06:03.755004584Z").toISOString()` yields
`"2026-07-24T20:06:03.755Z"`, so the existing `isRfc3339` check
(`src/evidence.mjs:314-320`), which requires an exact `toISOString` round-trip,
REJECTS a raw nanosecond `blockTime`. That is fail-closed by accident. Therefore
the truncated millisecond form is what enters evidence, and the raw nanosecond
string is carried alongside as a separately validated opaque bounded field.

### 5.3 Deadline and upper-bound siding

```text
deadlineMs = truncate(blockTime(h1)) + 600000
```

Because `blockHeight` is the last SEALED block at record creation, and `blockTime`
runs 0.31-0.45 s EARLIER than the record's own `createdTimestamp` (VERIFIED on
both prior live records), `blockTime` is a LOWER bound on the true write time.
Using it for the proposal therefore makes the window start conservatively early.

For the later transitions that same property is a hazard, not a safeguard: a
naive `blockTime(h2) <= deadlineMs` is optimistic by up to one block, roughly
1.024 s at the measured cadence. So compare the UPPER bound instead.

```text
upperBound(h) = blockTime(h) + 1100          on the live path
upperBound(h) = blockTime(h + 1)             in the aggregate verifier, when that block exists
```

The constant is used on the live path because it saves a rate-limited call; the
verifier's call budget is not constrained, so it uses the sharper form.

```text
Require upperBound(h2) <= deadlineMs
Require upperBound(h3) <= deadlineMs
```

**Ordering.** Strict `h1 < h2 < h3` on decimal-string integers via
`canonicalDecimalText` — exact, skew-immune, and the primary gate. `blockTime`
monotonicity is confirmatory only. Strictness means two transitions may not share
a block. The protocol is inherently serialized so a collision is unlikely, and a
false FAIL is safe while a false `AUTHORIZED` is not. This is a real, if
unlikely, flakiness source in a live demo, and it is accepted deliberately.

**Handoff open decision #6 is resolved: all three transitions must anchor at or
before the deadline. There is NO grace period for the acknowledgment.** A grace
period is a second tunable with no verification benefit, and "the acknowledgment
landed late but we authorized anyway" is exactly the narrative the fail-closed
rule exists to forbid. The cost is stated openly: this makes a live run more
likely to fail on a rate-limited network, and that failure is the correct outcome
rather than a softened one. A late acknowledgment yields `EXPIRED`; Iris's
`ACCEPTED` state still stands as truthfully recorded and nothing is retroactively
erased.

**Clock skew between the two machines is ZERO.** There is no cross-machine clock
comparison anywhere in any authorization decision. Both machines read the same
block heights from the same chain. This is the strongest property of the design
and it is worth saying to stakeholders in exactly those terms.

**Poll budget.** At least 20 s spacing with jitter, honoring `Retry-After`, and a
hard wall-clock cap of 8 minutes, leaving 2 minutes of slack inside the 600 s
window. A rate-limited response NEVER decrements the "peer has not published"
logic.

### 5.4 The handoff's enumerated failures, mapped to terminal codes

The handoff enumerates sixteen failures that must fail closed. Each maps to
exactly one terminal code and to the mechanism that detects it.

| Handoff failure | Terminal code | Detecting mechanism |
| --- | --- | --- |
| Expired proposal | `EXPIRED` | `upperBound(h) > deadlineMs`, or the poll deadline passing with `search_actions(K)` still length 0 |
| Wrong session | `BINDING_MISMATCH` | `sessionDigest` is inside every digest preimage and inside `K(slot)`; recomputed `H_i` will not equal `onChain.anchoredHash` |
| Wrong payer or payee | `BINDING_MISMATCH` for the message binding; `FAILED` for the identity binding | Both addresses and both `agentId`s are inside the preimage; plus `ownerOf(agentId)` via `eth_call` and `resolve_agent(agentId).owner` |
| Reused identity where distinct identities are required | `FAILED` | Aggregate verifier requires payer owner and payee owner to be DISTINCT addresses |
| Changed amount, currency, expiry, or commercial terms | `BINDING_MISMATCH` | All are in the preimage; the recomputed digest diverges |
| Acceptance that does not bind the exact proposal | `BINDING_MISMATCH` | `M2.predecessor` triple must equal Billy's own authoritative proposal triple |
| Acknowledgment that does not bind the exact acceptance | `BINDING_MISMATCH` | `M3.predecessor` and `M3.proposal` triples must equal the authoritative triples |
| Unanchored, pending, degraded, cache-only, or unverifiable receipt | `ANCHOR_UNVERIFIED` | `onChain.verifiedAgainst !== "on-chain block"` or `onChain.keyless !== true` |
| Missing consensus time | `ANCHOR_UNVERIFIED` | `get_block(blockHeight)` did not return a parseable `blockTime`; a 502 is non-verification, never proof of absence |
| Non-monotonic or impossible timestamp ordering | `FAILED` | Strict `h1 < h2 < h3` on decimal-string heights |
| Duplicate proposal, acceptance, or acknowledgment | `DUPLICATE` | `search_actions(K)` length greater than 1; `generate_audit_trail(K).count !== 1` in the verifier |
| Replay from another session | `BINDING_MISMATCH` | A different `sessionId` changes `D_session`, which changes `K(slot)` and every digest |
| Ambiguous write outcome | `AMBIGUOUS_WRITE` | Timeout, transport error, or unknown status from `log_action`; the runner switches permanently to discovery-only |
| Peer evidence that cannot be retrieved through the approved rendezvous | `RENDEZVOUS_UNAVAILABLE` at Phase -1; `EXPIRED` inside the window | Preflight probe, then the poll deadline |
| Mismatched repository or prompt version | `FAILED` | `repositorySha` and `promptSha256` are inside the signed descriptor and therefore inside `D_session`; the verifier also requires them equal across both packages |
| Any secret finding in public evidence | `FAILED` | `assertSecretFree` plus the new email pattern; the evidence write aborts before persistence |

### 5.5 The full fail-closed matrix

This is the operational matrix. Every row is a test.

| # | Condition | Terminal code |
| --- | --- | --- |
| 1 | Preflight: neither channel resolves the peer's probe within the bounded window, before any invitation, gas, or protocol state is spent | `RENDEZVOUS_UNAVAILABLE` |
| 2 | `search_actions` returns a non-Array, including an in-body `{"error":"rate_limited"}` object | `RATE_BLOCKED` when the body is the rate-limit shape, otherwise `FAILED`. NEVER conflated with an empty result. This is the one place the protocol must never fail open (codes assigned here, pending confirmation; the synthesis requires a hard error for this row but names no terminal code) |
| 3 | `search_actions(K)` length greater than 1. Also the defense against a forger racing the honest party at a known key | `DUPLICATE` |
| 4 | `search_actions(K)` length 0 past the poll deadline | `EXPIRED`, never a soft pass |
| 5 | `onChain.verifiedAgainst !== "on-chain block"` or `onChain.keyless !== true`, including the wrong-height trap case | `ANCHOR_UNVERIFIED` |
| 6 | `onChain.ledgerId`, `blockHeight`, `anchoredHash`, or `assetReferenceId` not equal to the expected binding | `BINDING_MISMATCH` |
| 7 | Locally recomputed `H_i !== onChain.anchoredHash`. Collapses wrong session, wrong payer, wrong payee, changed amount, changed currency, changed terms, wrong `protocolVersion`, an acceptance not bound to the exact proposal, and an acknowledgment not bound to the exact acceptance into ONE check | `BINDING_MISMATCH` |
| 8 | Bounded amount enumeration yields zero or two or more matches over the at most 8 pinned candidates | `AMOUNT_UNRESOLVED` — never confusable with a plain digest mismatch. The synthesis's row 8 reads "`FAILED` with a distinct code", i.e. it names the terminal code `FAILED` and requires an unnamed distinct sub-code beneath it; this specification promotes that sub-code to a terminal code of its own and names it `AMOUNT_UNRESOLVED` in section 5.1 |
| 9 | Returned `assetReferenceId` not byte-for-byte equal to the derived `K` — case, whitespace, prefix, truncation, gateway normalization | `FAILED` at write read-back, before the peer can depend on it |
| 10 | `resolve_agent(peerAgentId).status !== "active"`, or missing owner, or owner not equal to the descriptor address. Re-checked at acceptance time, not only at init | `FAILED` |
| 11 | `ownerOf(agentId)` via `eth_call` not equal to the descriptor address | `FAILED`, before any network write |
| 12 | Payer owner equals payee owner | `FAILED` |
| 13 | Operator Ed25519 signature invalid, or the shipped public key does not match the one committed at the pinned `repositorySha` | `FAILED`, before any network call |
| 14 | `D_session`, `repositorySha`, or `promptSha256` differs between the two packages | `FAILED` |
| 15 | `M2.predecessor`, `M3.predecessor`, or `M3.proposal` triple not equal to the authoritative triple | `FAILED` |
| 16 | `h1 < h2 < h3` violated, including reorder and same-block | `FAILED` |
| 17 | `upperBound(h2)` or `upperBound(h3)` greater than `deadlineMs` | `EXPIRED` |
| 18 | `get_block` returns 502 — VERIFIED identical message for a future height, for height 0, and plausibly for a genuine outage | Non-verification, NEVER proof of absence. `ANCHOR_UNVERIFIED` (code assigned here, pending confirmation; the synthesis names no terminal code for this row) |
| 19 | Nonexistent `ledgerId`, malformed `ledgerId`, and a genuinely pending record are VERIFIED indistinguishable, all returning `verifiedAgainst:"none"` | All three fail closed as `ANCHOR_UNVERIFIED` (code assigned here, pending confirmation; the synthesis requires all three to fail closed but names no terminal code). Rely on a bounded retry window, never on error-shape discrimination |
| 20 | Ambiguous write: timeout, transport error, or unknown status. Never blind-retry an irreversible write | `AMBIGUOUS_WRITE`; the runner switches permanently to discovery-only and can never reach an authorizing state on that path |
| 21 | A local write-intent marker already exists for this session and slot | Refuse to write; discovery only |
| 22 | `record.status` reports `"anchored"` | Never accepted as evidence of anchoring. Live counterexample pinned as a fixture |
| 23 | `verify_package.valid`, `.pkgHashMatch`, `.anchorMatch`, `verify_asset.match`, `additionalInfo`, `versionNumber`, `createdTimestamp`, `updatedTimestamp` appear anywhere in a decision | Excluded from the trust path entirely, enforced by tests |
| 24 | `log_action` refused, whether for `allow_degraded` or any other reason | `FAILED`, with the exact gap reported. Never converted into a green verdict |
| 25 | Rate-limited, 5xx, or timeout during polling | Consumes the deadline budget. NEVER read as "the peer has not published" |
| 26 | Any secret canary, private key, invitation code, token, or operator email found in a package or Markdown artifact | Evidence write aborts. `assertSecretFree`, plus the new email pattern |
| 27 | Any agent runner attempting to print `AUTHORIZED` | Refused. Only the aggregate verifier may |
| 28 | `get_validation` consulted as an authorization gate | Never. It is VERIFIED 0/0/0.0 at the block where the prior live receipt successfully anchored, and returned a 500 on another real block. Disclosure only |

### 5.6 The degraded-pool product decision

This decision must be made now, not during implementation.

**Scope the handoff's "unanchored, pending, degraded ... fails closed" rule to
ANCHORING VERIFICATION, not to submission.** Every write passes
`allow_degraded: true`.

The reasoning:

- The pool is degraded right now. VERIFIED: `nodeParticipation%` `"0.0"`,
  `totalNodes` `"1.0"`, `consentedOffset` `"-999.0"` sentinel.
- It was equally degraded at block 1781135, where the prior live receipt
  successfully anchored. VERIFIED via `get_validation(1781135)`.
- Every deployed write tool defaults to refusing a degraded pool.
- The shipped demo already relies on the override at `src/run.mjs:1135`.

`degradedAtSubmission` becomes a REQUIRED disclosed evidence field and a required
sentence in `RESULT.md` and `DEMO.md`. Without this decision the bilateral
protocol cannot write at all.

Note the honest asymmetry: whether `allow_degraded: false` is genuinely refused is
UNVERIFIED (table 2.2). The decision is made on the safe side either way — the
protocol opts in explicitly and discloses that it did.

### 5.7 Transport and documentation work this design requires

This is real work, not a docs afterthought, and it must land before any live run.

**Snapshot warning, and one deliberate exception.** The `Seam` column below stays
pinned to `12cdaa2` under the section 1.4 citation convention. The status prose in
this paragraph is the exception: it was re-derived by reading the CURRENT working
tree (`12cdaa2` plus the integrated transport and documentation work), so the line
numbers and the statuses below do not describe the same snapshot. Re-derive again
before using the table as an implementation checklist.

As of the current working tree, two rows have fully landed and are kept below as a
record rather than as remaining work:

- **In-body `rate_limited` detection: landed.** `src/mcp.mjs` now carries a
  `RATE_LIMITED_ERROR_CODE` constant and an `assertNotRateLimited` guard in the
  tool-result path that raises a typed `McpRateLimitedError`
  (`MCP_RATE_LIMITED_BODY`, carrying the `retry_after` hint) instead of returning
  `{"error":"rate_limited","retry_after_seconds":N}` as a normal payload. That
  closes the TRANSPORT half of the matrix row 2 fail-open; mapping the raised
  error onto the terminal code `RATE_BLOCKED` is still protocol work this design
  owns.
- **Email pattern in `src/redact.mjs`: landed.** The module contained no `@`
  character at all at `12cdaa2` and now carries an address pattern.

One row landed **in part, and deliberately not as originally written** — see the
corrected row below. `MAX_RETRY_AFTER_MS` moved 30 s to 62 s, `DEFAULT_MAX_ATTEMPTS`
3 to 4, and `MAX_CONFIGURED_ATTEMPTS` 5 to 6. `DEFAULT_REQUEST_TIMEOUT_MS` did NOT
move: it is still `10_000`, unchanged from `12cdaa2`, and that is intentional.

Every other row is still open in the current tree: no first-class `logAction`,
`searchActions`, `getBlock` or `generateAuditTrail` methods exist; `validateClient`
still checks exactly the same five methods; `READ_RETRY_TOOLS` still contains only
the original five reads; no polling module sits above the transport retry (a
completion-deadline bound, `MAX_COMPLETION_DEADLINE_MS`, did land INSIDE
`src/mcp.mjs`, but that is the transport, not the protocol layer this row asks
for); `captureSubmissionPoolHealth` still requires
`Number.isSafeInteger(totalNodes)`;
and the documentation checker still gates four documents, none of them a bilateral
role prompt.

| Change | Seam | Reason |
| --- | --- | --- |
| Add first-class normalized methods `logAction`, `searchActions`, `getBlock`, `generateAuditTrail` with exact-key argument allowlists | `src/mcp.mjs`, alongside `ATTEST_ACTION_KEYS` at `src/mcp.mjs:35-44` | Do NOT reach the new tools through the permissive default branch at `src/mcp.mjs:981-984`. It gives no argument normalization and no retry |
| Extend `validateClient` | `src/run.mjs:727-744` | It currently checks only five named methods |
| Add the three READS to `READ_RETRY_TOOLS`; never `log_action` | `src/mcp.mjs:24-30` | The set currently contains none of the new tools, so a 429 on any of them throws immediately |
| Raise `MAX_RETRY_AFTER_MS` (30 s) and the attempt cap (`DEFAULT_MAX_ATTEMPTS` 3, `MAX_CONFIGURED_ATTEMPTS` 5) so the observed 31 s `retry_after` can be honoured, and add a total-wait bound (`MAX_TOTAL_RETRY_WAIT_MS`). Do NOT raise `DEFAULT_REQUEST_TIMEOUT_MS`: it stays at 10 s | `src/mcp.mjs:7-14`, `src/mcp.mjs:1021` | The built-in backoff, capped at 1000 ms, cannot survive the live rate limiter, so the throttle must be absorbed by the `retry_after` waits (`MAX_RETRY_AFTER_MS`, `MAX_TOTAL_RETRY_WAIT_MS`), NOT by a longer request budget. The request timeout is the per-attempt BUDGET; `retry_after` is the WAIT, and conflating them is the trap. The observed throttle answers immediately — HTTP 429, or an in-body `rate_limited` object with `retry_after_seconds` — and does not hold the connection open for the window, so a longer request timeout buys nothing while multiplying the worst-case wall clock across every attempt of every call. The transport track raised it to 45 s, measured a ~49-minute worst case, and reverted to 10 s; this row must not re-land that change |
| Add a polling layer above the transport retry | new module | Poll pacing is a protocol concern, not a transport concern |
| Detect the in-body `rate_limited` shape | `parseToolResult`, `src/mcp.mjs:566` | Otherwise a throttle reads as a normal payload — the fail-open in matrix row 2 |
| Add a pool-health normalizer | `captureSubmissionPoolHealth`, `src/run.mjs:788-809` | It requires `Number.isSafeInteger(totalNodes)` while `get_timestamp` returns the strings `"1.0"` and `"0.0"` |
| Add an email pattern to `src/redact.mjs` | `src/redact.mjs` (212 lines, VERIFIED to contain no `@` character at all) | The first code path that serializes a raw Clockchain record would otherwise publish the operator's email |
| Add the two new role prompts to `scripts/check-docs.mjs` as first-class gated documents, in the same commit | `scripts/check-docs.mjs`, `PUBLIC_DOCUMENTS` at line 19, `REQUIRED_DOCUMENT_PATTERNS` at line 141 | The checker byte-pins `prompts/run-turnkey-demo.md` and requires the canonical tokens `npm run demo`, `result.json` and `RESULT.md` in every public document. Adding prompts without updating the checker hard-fails `npm run verify` |

## 6. Evidence schemas and the distributed manifest

### 6.1 How `clockchain.handshake-result/v1` is preserved unbroadened

The handoff is explicit: "Treat the new behavior as a protocol and evidence-schema
version change. Do not silently broaden the meaning of
`clockchain.handshake-result/v1`."

The existing schema is enforced by two seams, and a v2 must branch at both rather
than widening either:

| Seam | `file:line` | What it does |
| --- | --- | --- |
| The schema constant | `src/constants.mjs:8` — `export const RESULT_SCHEMA = "clockchain.handshake-result/v1";` | The single source of the v1 name |
| The exact-key gate | `src/evidence.mjs:21-32` — `RESULT_KEYS` is a frozen 10-entry list | `hasExactKeys` rejects any object with an extra or missing key |
| **The branch point** | `src/evidence.mjs:406` — `result.schema !== RESULT_SCHEMA \|\| ...` inside `validatePassResult` (`src/evidence.mjs:402`) | This is the exact line where a v2 must branch. A bilateral result must NOT reach this comparison |
| The stamping site | `src/run.mjs:1210` — `schema: RESULT_SCHEMA` | The unilateral runner is the only writer of the v1 name |
| The renderer | `renderResultMarkdown`, `src/evidence.mjs:445`, with the hardcoded `"- Payment moved: no"` line at `src/evidence.mjs:465` | v1's Markdown is recomputed byte-for-byte from `result.json`; the bilateral renderer must be a separate function, not a widened one |

The rule for implementation is therefore mechanical: **do not add a key to
`RESULT_KEYS`, do not add a branch to `validatePassResult`, and do not add a
conditional to `renderResultMarkdown`.** The bilateral schemas live in new modules
under `src/bilateral/`, with their own frozen key lists and their own validators
and renderers. The v1 regression fixture of section 4.5 plus the existing
407-test suite is what proves the unilateral path stayed byte-stable.

The one shared change is the canonicalizer extraction, and it is deliberately
structured so that `clockchain.handshake-result/v1` cannot move:
`canonicalizeReceiptEventValue` (`src/evidence.mjs:146`) moves to
`src/canonical.mjs`, `computeReceiptEventHash` (`src/evidence.mjs:241`) is
re-implemented on top of it, and the pinned fixture is written as a failing test
BEFORE the move.

### 6.2 `clockchain.bilateral-transition/v1`

The canonical message envelope of section 4.6. It is not an on-disk artifact in
its own right; it is the object that is canonicalized and digested, and it is
embedded verbatim inside a party result package so a third party can recompute
the digest. Its key set is frozen and the derivability guard test asserts the M2
and M3 key sets are a subset of the derivable-field allowlist.

### 6.3 `clockchain.bilateral-session-descriptor/v1`

Specified in section 4.4. Its exact key set is frozen. Validation requires:

- exact keys, no more and no fewer;
- `amountOptions` non-empty, at most 8 entries, sorted, unique;
- every numeric-looking value a decimal string;
- both addresses lowercase 40-hex with the `0x` prefix;
- `registry` equal to the pinned official registry, lowercased;
- `chainId` equal to `"11155111"`;
- a valid Ed25519 signature over `canonicalBytes(descriptor)`; and
- the shipped `publicKey` equal to the repository-committed key at
  `docs/operator-keys/<keyId>.pub` at the pinned `repositorySha`.

### 6.4 `clockchain.bilateral-party-result/v1`

One per machine. Emitted by the role runner. Never emits `AUTHORIZED`.

Required content:

- `schema`, `role` (`payer` or `payee`), `sessionDigest`, `repositorySha`,
  `promptSha256`, `protocolVersion`;
- `localVerdict`: `LOCAL_OK` or a terminal code from section 5.1;
- for each transition the runner observed: the canonical message object, the
  locally recomputed digest, and the authoritative triple
  `{ledgerId, blockHeight, anchoredHash}` taken from `onChain`;
- `blockTimes`: the truncated-millisecond form plus the raw nanosecond string as
  a separately validated opaque bounded field;
- `deadlineMs` and the computed `upperBound` for each later transition;
- the party's EIP-191 signature over the canonical bytes of its own transitions;
- `poolHealth` including the REQUIRED `degradedAtSubmission` boolean;
- `ackObserved` for the payee, which may be `false` without that being a failure
  of her own transition; and
- the REQUIRED rendezvous disclosure object.

**The rendezvous disclosure object is the single most important anti-overclaim
control in the product.**

```json
{
  "rendezvous": {
    "channel": "derived-reference-id",
    "tenancy": "unknown",
    "degradedAtSubmission": true
  }
}
```

`channel` is one of `derived-reference-id`, `digest-hash`, or
`out-of-band-pointer`. `tenancy` is one of `same-client`, `cross-client`, or
`unknown`. The Markdown renderer DERIVES its claim sentence from those fields.
The stakeholder claim degrades automatically with the mechanism; it cannot be
narrated at full strength by a human who forgot the fallback fired. A test
asserts that a degraded `channel` value produces a weakened sentence.

The Markdown artifact is rendered byte-for-byte from the JSON, exactly as
`renderResultMarkdown` does for v1, and a test asserts the round-trip.

### 6.5 `clockchain.bilateral-authorization-verdict/v1`

Emitted only by `scripts/verify-bilateral-results.mjs`, in a fresh process that
trusts neither agent.

The verifier:

- requires BOTH party packages;
- requires them to AGREE on all three `(ledgerId, blockHeight, digest)` triples —
  not merely that each is internally valid. Disagreement is a `FAILED`, and it is
  the check that catches a party reporting a different record than the one it
  actually verified;
- re-derives `D_session` and all three keys from the descriptor alone;
- re-runs the full verification recipe of section 4.11 for all three transitions
  from scratch;
- INDEPENDENTLY re-runs the bounded amount enumeration rather than trusting
  either package's stated amount;
- never copies a digest out of a package;
- verifies both EIP-191 signatures against three independent sources: the
  descriptor-pinned address, `ownerOf(agentId)` via `eth_call`, and
  `resolve_agent(agentId).owner`;
- requires payer and payee owners to be DISTINCT addresses;
- re-checks `h1 < h2 < h3` and all three upper bounds against `deadlineMs`;
- runs `generate_audit_trail(K).count === 1` per key;
- requires `repositorySha` and `promptSha256` equal across both machines; and
- runs `assertSecretFree` over both packages.

Only then does it emit the verdict with `outcome: "AUTHORIZED"` and
`paymentMoved: false`.

### 6.6 The distributed collection manifest

**OPEN DECISION — requires a schema decision before implementation.** Unlike
sections 6.3, 6.4 and 6.5, this schema has NO frozen exact key set. The source
synthesis underspecifies it, and this document deliberately does not invent one.
What follows is the required content and the required limits, not a key list: an
implementer must not read it as a settled schema, and the exact keys, their
spellings, their types, and their validation rules must be decided and frozen —
under the repository's exact-key, fail-closed idiom — before the manifest is
built. Until then, treat this section as constraints on that decision.

`clockchain.bilateral-collection-manifest/v1` binds the two independently
produced packages to one session and one operator collection event, and replaces
the same-host harness manifest for this product.

It records: the `sessionDigest`; the descriptor bytes and their digest; both
machines' `repositorySha` and `promptSha256`; the client identifier and version
each machine reported (Codex CLI on machine A, Claude Code on machine B); a
per-package content digest; the operator's collection window; and the terminal
state each package reported.

Two limits are structural and must be recorded in the manifest itself rather than
assumed away:

- **The manifest binds packages, not execution.** It proves that a repository SHA
  and a prompt hash were committed to, and that the anchored digests are
  consistent with them. It does not prove which machine ran which code, or that a
  human did not assemble the packages. The wording already used in
  `docs/demo-evidence/latest.md:41-42` — that provenance attributions are
  "provenance records from the original harness, not cryptographic execution
  attestations" — must carry forward verbatim.
- **A package produced outside the operator's collection root is a provenance
  limitation, not a pass.** This is the failure mode the first-generation live
  run actually hit: a valid result pair created outside the harness collection
  root left the aggregate manifest `FAIL`, and it was later recovered and
  independently verified with that limitation attached. The bilateral manifest
  must preserve that distinction rather than smoothing it.

`npm run acceptance:clients` may remain as a same-host regression or smoke tool.
It cannot be the acceptance proof for this product, and the manifest schema must
not accept its output.

## 7. Role CLIs and prompts on two machines

Three commands, three roles, three machines. No shared filesystem at any point.

| Command | Role | Machine | Client |
| --- | --- | --- | --- |
| `bin/handshake-propose.mjs` | Billy, payer | A | Codex coding session |
| `bin/handshake-accept.mjs` | Iris, payee | B | Claude Code session |
| `scripts/verify-bilateral-results.mjs` | Operator verifier | C | Plain Node.js, fresh process |

### 7.1 Billy: `bin/handshake-propose.mjs`

1. Verify the operator Ed25519 signature against the repository-committed key at
   the pinned `repositorySha`. Fail before any network call if it does not match.
2. Recompute `D_session` from the descriptor bytes.
3. Verify BOTH identity bindings: `ownerOf(agentId) == address` by `eth_call`,
   and `resolve_agent(agentId)` reporting `status "active"` with a matching
   owner. Fail before any network write.
4. Choose ONE amount from `descriptor.amountOptions`. This is the payer's real
   choice and the demo's decision beat.
5. Write M1 at `K("proposal")` using the section 4.8 call shape.
6. Post-write read-back (section 4.12).
7. Poll `K("acceptance")` at at least 20 s spacing with jitter.
8. Run the full verification recipe on M2. Assert `M2.predecessor` triple equals
   HIS OWN authoritative proposal triple — this is the step that proves Iris
   bound this exact proposal. Re-check `resolve_agent(payeeAgentId)` at
   acceptance time, not only at init. Assert `h2 > h1` and
   `upperBound(h2) <= deadlineMs`.
9. Write M3 at `K("acknowledgment")`. Post-write read-back. Assert `h3 > h2` and
   `upperBound(h3) <= deadlineMs`.
10. Emit `clockchain.bilateral-party-result/v1` with `localVerdict` `LOCAL_OK` or
    a terminal code. Never print `AUTHORIZED`.

### 7.2 Iris: `bin/handshake-accept.mjs`

1. Same init as Billy: signature, `D_session`, both identity bindings.
2. Poll `K("proposal")`.
3. Run the full verification recipe on M1, including the bounded at-most-8
   candidate reconstruction. Exactly one candidate digest must equal
   `onChain.anchoredHash`.
4. Compute `deadlineMs` from `get_block(h1).blockTime`.
5. Require `deadlineMs` to exceed her conservative "now" upper bound BEFORE
   spending a write. This is an advisory local-clock pre-abort, and it is the
   only place a local wall clock is consulted at all.
6. Write M2 at `K("acceptance")`. Post-write read-back.
7. Assert `h2 > h1` and `upperBound(h2) <= deadlineMs` POST-ANCHOR. If violated,
   the run is `EXPIRED` and she must not claim `ACCEPTED`.
8. Poll `K("acknowledgment")` and run the full recipe on M3, which has zero
   unknowns for her.
9. Emit her package. Absence of the acknowledgment is not a failure of her own
   transition: her package reports `ACCEPTED` with `ackObserved: false`.

### 7.3 The two role prompts

Two new byte-pinned public prompts are required, one per role, and both must be
added to `scripts/check-docs.mjs` as first-class gated documents IN THE SAME
COMMIT that introduces them. `PUBLIC_DOCUMENTS` (`scripts/check-docs.mjs:19`)
grows from three entries to five, the success-count message at
`scripts/check-docs.mjs:805` follows automatically, and the canonical-token and
canonical-command rules must be resolved for the new CLI and artifact names —
`REQUIRED_DOCUMENT_PATTERNS` (`scripts/check-docs.mjs:141`) currently requires
the tokens `npm run demo`, `result.json` and `RESULT.md` in every public
document.

Each role prompt must state, in its own words but without softening:

- the role, the counterparty, and that this machine performs one side only;
- that ERC-8004 registration already happened in Phase 0 and this run performs no
  Ethereum write;
- that the amount is chosen from a pinned allowlist (payer) or reconstructed and
  proven by digest (payee);
- the 600-second window and that there is no grace period;
- that this command can never print `AUTHORIZED`;
- the single-validator testnet, degraded-pool, and `allow_degraded` disclosures;
  and
- that no funds move.

The prompts must be byte-identical across the two machines in everything except
the role-specific sections, and their SHA-256 is pinned into the descriptor as
`promptSha256`, so running the wrong prompt version changes `D_session` and fails
every check closed.

### 7.4 Operator runbook

**Before the session**

1. Run the Phase -1 preflight scoping probe from two physical machines on
   different IPs. Record which of the three channels resolved, separately. If
   neither discovery channel resolves, publish `RENDEZVOUS_UNAVAILABLE` and stop.
   Do not proceed to invitations.
2. Record the measured rate-limit budget and the measured write-to-verifiable
   latency from the same probe. Confirm on paper that the happy path fits inside
   600 s with slack for one 31 s stall.
3. Create four fresh invitations — two for a rehearsal, two for the live run —
   and confirm each disposable wallet is funded inside the inclusive 0.005 to
   0.02 Sepolia ETH band. Never reuse the two previously consumed stakeholder
   invitations; both are at nonce 2.
4. Run one rehearsal of the existing unilateral demo at HEAD with a throwaway
   invitation, to confirm the hardening commits since the last live run did not
   break the only path that has ever run live.

**Phase 0**

5. Deliver one invitation to each machine through a separate private channel.
6. Each machine runs the unchanged registration path and returns
   `{address, agentId, registerTx, metadataTx}`. Nothing else.

**Phase 1**

7. Build the descriptor, pinning both identities, the amount allowlist, 600
   seconds, `repositorySha`, and `promptSha256`.
8. Sign it with the Ed25519 operator key whose public half is committed at that
   `repositorySha`.
9. Deliver byte-identical descriptor bytes to both machines.

**The timed window**

10. Both role commands start. The window opens when M1 anchors, not when the
    operator says go.
11. The operator relays nothing during the window in the normal path. If the
    Phase -1 probe showed `search_actions` is client-scoped, the operator relays
    the fallback pointer, and the `rendezvous.channel` field in both packages
    changes to record it.

**After**

12. Collect both sanitized packages into the collection root.
13. Run `scripts/verify-bilateral-results.mjs` in a fresh process on a third
    machine.
14. Publish the verdict, the rendezvous disclosure, and the honesty limits of
    section 9. Do not narrate a result the verifier did not emit.

**Stop conditions.** Stop and escalate rather than retry if: any write returns an
ambiguous outcome; a write-intent marker exists at startup; `search_actions`
returns length greater than 1 at any key; the demo token returns 401 or 403
mid-run; or the terminal code names attestation, anchoring, or verification. A
blind rerun at the same keys makes `search_actions` return 2 and permanently
fails the session, and every retry requires a fresh `sessionId` and a fresh
signed descriptor.

## 8. Test strategy

Every behavior change follows the repository TDD contract: write the failing
`node:test` first, observe the expected failure, implement the smallest passing
change, refactor while green. Never weaken an existing assertion to make an
implementation pass.

### 8.1 Ordering constraint

The canonicalizer extraction is the single riskiest edit in the whole programme,
so its pinned fixture is written FIRST, before any other bilateral work:

```text
computeReceiptEventHash({agentId:"8677", action:"trust_handshake", inputs:{}, outputs:{}})
  === c37387429ff4f787fecb2a5c5a64a277696ee6d768fcb2d5564e7e2268e6dd02
```

`clockchain.handshake-result/v1`, `runHandshake`, and all existing tests must stay
green and byte-stable across the extraction.

### 8.2 The deterministic suite

**Canonicalization** (`src/bilateral/canonical.mjs`). Reject any number anywhere
in the value domain. Reject integer-like string keys, after first reproducing the
Node 22 defect and asserting the current canonicalizer ACCEPTS it. Reject
non-ASCII and control characters. Enforce bounded string length. Assert the
sorted-key invariant holds for a fixture with adversarial key ordering.

**Block time and expiry** (`src/bilateral/blocktime.mjs`). Strict
RFC3339-nanosecond parse with truncation toward zero. Explicit rejection of all
four Clockchain gateway timestamp formats. A test asserting `Date.parse` is
unreachable from the module. Deadline boundary tests with an INJECTED CLOCK at
`deadline - 1 ms` (passes) and `deadline + 1 ms` (fails). Both `upperBound`
variants: the `+1100 ms` constant and the `blockTime(h+1)` verifier form.

**Reference ids** (`src/bilateral/refid.mjs`). Charset `/^[0-9a-z:]{1,120}$/`.
`K(slot)` as a pure function of `D_session`. Length at most 85. A byte-equality
assertion helper. Rejection of every mutation class: case change, whitespace,
prefix, truncation.

**Descriptor.** Exact-key schema. `D_session` computation. `amountOptions`
bounded to 8 with sorted-unique enforcement. Ed25519 verification against a
fixture keypair committed under `test/fixtures` — no real operator key is needed
for the deterministic suite. Rejection when the shipped `publicKey` does not match
the repository-committed one.

**Canonical messages.** Byte-exact pinned strings and digests for M1, M2 and M3.
The derivability guard test asserting the M2 and M3 key sets are a subset of an
explicit derivable-field allowlist. The bounded amount enumeration with
exactly-one-match, zero-match and two-match cases, each producing the correct
distinct outcome.

**Transport.** First-class normalized `logAction` / `searchActions` / `getBlock` /
`generateAuditTrail` with exact-key argument allowlists, driven by fixtures
recorded from the read-only probes. Extended `validateClient`. An assertion that
`log_action` is never added to `READ_RETRY_TOOLS`. A test that an in-body
`{"error":"rate_limited","retry_after_seconds":N}` response throws a distinct
`RateLimitedError` rather than returning a payload through `parseToolResult`.

**The fake Clockchain and its mutation hooks.** A deterministic fake with
`mutateSearch`, `mutateCrossParty` and `mutateBlock` hooks, mirroring the existing
`mutateCompleted` pattern already used in the acceptance-harness tests. Each hook
exists so an adversarial fixture can forge exactly one field and the suite can
assert the correct terminal code.

**Adversarial fixtures.** Each of these is a test, not a comment:

- the wrong-height-plus-correct-hash `advisoryHashCheck` trap;
- `record.status "anchored"` at a nonexistent block, pinning live ledger
  `370c7672-3a78-4c17-853c-e3037799562c` at block `3375636` as a fixture;
- `get_block` returning 502;
- a non-array `search_actions` result, including the in-body rate-limit shape;
- a `search_actions` result of length greater than 1;
- forged `onChain.anchoredHash`;
- forged `assetReferenceId` carrying another agent's prefix;
- a forged rehydrated event hash; and
- the entire trust-path BAN LIST of section 4.11, encoded as tests.

**Runner state machines.** Driven entirely by the fake: happy path; expiry
violation at each of the three transitions; duplicate; binding mismatch on each
predecessor triple; ambiguous write forcing discovery-only; a write-intent marker
present at startup; `RENDEZVOUS_UNAVAILABLE` from the preflight gate; and an
assertion that NEITHER runner can emit `AUTHORIZED` under any input.

**Evidence schemas.** Exact-key schemas for
`clockchain.bilateral-party-result/v1` and
`clockchain.bilateral-authorization-verdict/v1`. `assertSecretFree` including the
new email pattern. The REQUIRED rendezvous disclosure object. Markdown rendered
byte-for-byte from the JSON, with the claim sentence DERIVED from
`rendezvous.channel` and `rendezvous.tenancy` — including a test asserting that a
degraded channel value produces a weakened sentence.

**Aggregate verifier.** Refuses a single package. Refuses packages that disagree
on any of the three triples. Independently re-derives all three keys and re-runs
the amount enumeration. Refuses to trust any digest copied from a package.
Requires distinct payer and payee owners. Verifies both EIP-191 signatures against
descriptor address, `ownerOf()`, and `resolve_agent().owner`. Enforces
`h1 < h2 < h3` and all three upper bounds.

**Provenance and preservation.** Separate-machine collection manifest validation.
Repository and prompt provenance checks. Secret canaries and redaction. And a
test asserting the unilateral demo is preserved until its disposition is
explicitly approved.

**Documentation.** The two role prompts gated by `scripts/check-docs.mjs` with
their own required phrases and canonical safety sections, the success-document
count bumped, and the canonical-command and filename rules resolved for the new
CLI and artifact names. `npm run verify` must be green before any live probe is
requested.

### 8.3 Live acceptance criteria

The live acceptance is not a test suite; it is a gated exercise. It may run only
after the deterministic suite is green, the security and code reviews pass, the
Phase -1 probe has run and been recorded, and explicit live-test authorization is
given.

It requires all of the following, which restate the handoff's completion criteria
for this feature:

1. the written protocol design is approved;
2. the required Clockchain rendezvous and read capabilities are verified against
   the deployed service, or an approved service change is delivered;
3. deterministic tests pass;
4. security and code reviews pass;
5. two fresh invitations are created and safely funded under explicit authority,
   and neither previously consumed invitation is reused;
6. Billy runs on one physical machine in a clean Codex session;
7. Iris runs on another physical machine in a clean Claude Code session;
8. both use the same immutable repository SHA and the same prompt version;
9. all three transitions anchor and independently verify;
10. the aggregate verifier, in a fresh process on a third machine, independently
    produces `AUTHORIZED`;
11. the evidence states `paymentMoved: false`;
12. no secrets appear in committed or returned public artifacts;
13. the single-validator, degraded-pool, and `allow_degraded` limitations are
    disclosed; and
14. the live evidence and its provenance limitations are recorded truthfully.

There is no same-host substitute for criteria 6 and 7. `npm run acceptance:clients`
cannot stand in for the distributed run.

## 9. Trust, provenance, and honesty limits

These are reproduced from the synthesis without softening. They are in the main
text, not a footnote, because they are the reason this specification can be
trusted.

**1. The payload bytes never travel through Clockchain.** Clockchain stores a
commitment, not content. `get_log_entry` returns 15 fields and no payload, and
the immutable on-chain projection is only
`{ledgerId, blockHeight, anchoredHash, assetReferenceId}`. Iris RECONSTRUCTS the
proposal locally and the anchored digest merely SELECTS which reconstruction is
correct. That is a real cryptographic commitment-opening and it is strictly
stronger than emailing her a JSON file, because a tampered reconstruction cannot
pass. But if anyone drafts the sentence "Iris downloads Billy's proposal from
Clockchain", it is false and should be corrected.

**2. Clockchain records carry NO signature by the writing agent.** The retrievable
fields are `ledgerId`, `clientId`, `walletId`, `assetReferenceId`, `assetHash`,
`hashType`, `versionNumber`, `additionalInfo`, `blockHeight`, timestamps and
`status` — nothing binds a record to an ERC-8004 owner key. LIVE, neither party
can prove the peer wrote the record. Authorship is established only afterwards,
by the aggregate verifier, from EIP-191 signatures in the result packages. "The
two agents cryptographically identified each other through Clockchain during the
run" would be an overclaim.

**3. The parties are INTRODUCED out of band.** The operator authors and signs the
session descriptor and hands the identical bytes to both machines. The identities,
the currency, the amount allowlist, and the 600-second expiry are all pre-agreed.
What Clockchain establishes is that each party ACTED — which one of the allowed
amounts Billy chose, that Iris chose to accept after seeing his anchored
commitment, when, and in what order. That is a genuine and non-trivial
informational product, but it is not a negotiation and it should not be described
as one.

**4. The operator is a trusted third party.** The Ed25519 signature plus the
repository-committed public key make a forged descriptor detectable by anyone, but
they do not make the operator honest. For a stakeholder demo with the operator in
the room this is fine; as a payments protocol claim it is a real limitation.

**5. Both machines will very likely share one hosted Clockchain `clientId`.**
`mintDemoToken` POSTs to `/token` with no credential beyond an optional subject
header, and two prior runs with DISTINCT subjects both produced the same
`clientId`. If that holds, "the parties meet through Clockchain" means they meet
in a shared namespace inside ONE account — same-tenant, not cross-organizational.
If it does NOT hold, the rendezvous may not work at all. Both horns need a
prepared sentence in the stakeholder script; neither should be discovered by a
stakeholder in the room.

**6. Single-validator testnet with a degraded pool.** `get_validation` reports
Trust 0.0%, participation 0.0%, positiveVotes 0 — including at the exact block
where the prior live receipt successfully anchored — and returns null or a 500 for
some blocks entirely. Every write must opt into `allow_degraded: true`. Consensus
strength can only be disclosed, never gated on: a rule keyed on positive vote
count would reject every real receipt. There is also no reorg protection guarantee
on a one-proposer chain, only an absence of observed reorgs.

**7. "Keyless" is the API's own self-report.** The structured field
`onChain.keyless === true` and the note "with NO api key" are what the design
gates on, but the MCP server mediates the HTTP call, so no one has independently
confirmed on the wire that no credential was sent. State it as an API assertion
in stakeholder evidence, not as an independently proven property.

**8. Publishing the transition digests leaks the operator's identity.** Genuine
third-party content verification REQUIRES publishing them, and doing so lets
anyone perform a keyless `verify_cross_party({hash})` and resolve the operator's
`clientId` and `walletId`, observed as a literal email address. Moving to a
non-personal Clockchain account and adding an email redaction pattern mitigates
future leakage but does not retract anything already anchored.

**9. The 600-second window is measured between lower bounds.** Block times are
lower bounds on the true write times, so the effective window can be up to roughly
one block (~1.02 s) longer than 600 seconds. The upper-bound siding closes the
acceptance and acknowledgment side of this, but the proposal's own start instant
remains bounded rather than exact.

**10. The demo still proves nothing about the payment itself.** No funds move in
any version, settlement is the literal string `not-executed`, and `paymentMoved`
is false in every state. The product is an evidence and coordination layer, not a
payment rail.

**11. Nothing here is a remote-execution attestation.** The evidence proves that a
repository SHA and prompt hash were committed to, and that the anchored digests
are consistent with them — it does not prove which machine ran which code, or that
a human did not assemble the packages. The existing
`docs/demo-evidence/latest.md` already discloses that provenance attributions are
"not cryptographic execution attestations", and that disclosure must carry forward
verbatim into the bilateral evidence.

**12. Not court-grade, not trustless, not mainnet, not consensus-secure, not
permissionless.** The service's own `honestyNote` says it plainly: "Testnet.
Designed-for court-grade evidence, not court-tested or certified. Single-validator
testnet: consensus/trust numbers are currently 0." That sentence belongs in the
stakeholder script, not in a footnote.

### 9.1 The sentence that is true, and the sentences that are not

Accurate: "Two agents proved, on an immutable clock neither of them controls, that
they each acted in a fixed order inside a fixed window, on terms an operator
pinned and signed, and that the payer's choice among the allowed amounts was
committed before the payee ever saw it."

Also accurate, and the sharpest single point in the design: Iris demonstrably
could not have constructed her acceptance before Billy's proposal was anchored,
because the acceptance digest commits to the proposal's server-assigned block
height, and that height did not exist yet. That is a causal proof no
pre-agreement can manufacture.

Not accurate, and to be corrected if drafted:

- "Iris downloads Billy's proposal from Clockchain."
- "The two agents cryptographically identified each other through Clockchain
  during the run."
- "Billy and Iris negotiated a payment through Clockchain."
- "Clockchain verified that the payment was authorized" — the aggregate verifier
  did, from Clockchain evidence.

## 10. Open decisions still requiring operator approval

Nothing below may be inferred from this specification's approval. Each item needs
an explicit decision, and the first eleven require an authorized live write.

| # | Approval needed | What it settles |
| --- | --- | --- |
| 1 | **Cross-tenant scoping probe.** Two machines, two independently minted demo tokens, ONE `log_action` from machine B at an agreed exact reference id with a known `asset_hash`. From machine A, record separately: `search_actions` on that exact string; `verify_cross_party({hash})`; `verify_cross_party({ledger_id, block_height})`. Must be two physical machines on different IPs. | The single load-bearing unknown for every candidate design. If `search_actions` fails but the hash lookup or the on-chain path succeeds, the design switches to the digest-hash channel rather than dying. |
| 2 | **Verbatim reference-id storage and maximum length.** One `log_action` with a mixed-case, colon- and hyphen-bearing id, read back via `get_log_entry` AND `search_actions` on the byte-identical string; then a length ladder at 64 / 128 / 192 / 256 / 512 bytes. | Whether the gateway lowercases, prefixes, namespaces, or truncates a caller-supplied id, and whether the 85-byte scheme fits. Every reference id anyone has ever observed was server-generated. |
| 3 | **On-chain projection and caller-supplied hash.** After one `log_action` with a precomputed 64-hex digest, require `onChain.verifiedAgainst === "on-chain block"`, `onChain.keyless === true`, `onChain.assetReferenceId` echoed byte-for-byte, and `onChain.anchoredHash` equal to the supplied digest. | Whether `log_action` records reach the immutable projection at all, and whether the server anchors the caller's digest verbatim rather than re-hashing. If either fails, the digest-binding argument — the only step that binds MEANING to the anchor — is gone and no protocol design recovers it. |
| 4 | **Client-observed anchoring latency.** Timestamp locally, submit one `log_action`, poll `verify_cross_party({ledger_id, block_height})` every 2 s for 120 s. | Whether a fresh write spends a cache-only window where `status` says "anchored" but `verifiedAgainst` is "none". If it does, both runners fail closed on their OWN writes and the protocol never leaves the first transition. Also sizes whether three writes plus polling fit inside 600 s. |
| 5 | **Degraded-pool write behaviour.** One `log_action` with `allow_degraded` omitted, then one identical call with `allow_degraded: true`. | Whether the default is genuinely refused, which makes the section 5.6 disclosure decision mandatory rather than optional, and whether the override actually succeeds. No write of any kind has ever been observed. |
| 6 | **Duplicate and collision semantics.** Three sequential writes at one identical reference id, then `search_actions` and `generate_audit_trail`; then two writes sharing one `asset_hash`, then `verify_cross_party({hash})`. | The entire duplicate-detection rule, which is the defense against a forger racing the honest party at a known key; and whether a shadowing record can hide a real transition on the digest channel. |
| 7 | **`idempotency_key` semantics.** One `log_action`, then an identical retried call with the same key, then `search_actions`. | Whether a retry returns the original result or creates a second record. Until proven, the write-intent marker plus precheck must carry all the weight. |
| 8 | **Rate-limit shape, scope, and sustainable rate.** Capture the exact wire form; measure the sustainable serialized rate from one credential; then drive reads from two credentials concurrently. | Whether an in-body rate limit sails through `parseToolResult` as a normal payload — a fail-open where a throttle reads as "peer has not published"; and whether the budget is per-IP, per-token or per-account, i.e. whether Billy's polling starves Iris's. This is the most likely cause of an honest run failing and it must be measured before the 10-minute product constant is defended to a stakeholder. |
| 9 | **Demo token TTL and concurrent minting.** Mint a token, hold it, issue a trivial `get_time` at increasing intervals until a 401; separately time two mints from two IPs. | Whether a mid-session expiry is possible. Nothing in the repository decodes, refreshes, or re-mints the token, and 401/403 throws immediately before every retry branch, so an expiry mid-run is an unrecoverable hard failure across two machines. |
| 10 | **Cache-rewrite immunity of `assetReferenceId`.** Write a record, capture `onChain`, attempt a cache update via `PUT /ledger/{id}`, re-read both and diff which fields moved. | Whether the one party-controlled field the design relies on is genuinely immutable. Its immutability was inferred from the tool's own note, never demonstrated. |
| 11 | **Four fresh Sepolia registrations** — two for a bilateral rehearsal, two for the live run — each funded inside the 0.005 to 0.02 ETH band. | The Phase-0 register-first path end to end on two physical machines, which has never been done. An overfunded wallet is unrecoverable by design, so the band matters. |
| 12 | **One rehearsal run of the existing unilateral demo at HEAD** with a throwaway invitation, before any stakeholder session. | That the hardening commits since the last live client SHA did not break the only path that has ever run live, and refreshes the published evidence so it matches the shipped code. |

Five further decisions are product decisions rather than probes, and none of them
may be absorbed silently:

| Decision | Why it needs a decision |
| --- | --- |
| **Registration moves out of the timed window**, so the live bilateral run performs NO Ethereum writes. | It is forced by the absence of a reverse lookup and by the 600 s budget, but it narrows the existing "a clean session does everything end to end" story that the shipped demo sells. Handoff open decision #11. |
| **The operator authors the payment intent**, and the proposal content is derivable from the descriptor apart from the bounded amount choice. | A genuine fidelity gap against handoff step 1. The 8-option allowlist narrows it to three bits of real payer choice; it does not eliminate it. |
| **Same-tenant versus cross-tenant disclosure.** | Both horns need a prepared stakeholder sentence written in advance. If the machines share one tenant, the meeting is same-tenant; if they do not, the rendezvous may not work at all. |
| **PII: publish the digests and disclose, or move to a non-personal Clockchain account.** | Must be settled BEFORE the evidence schema is frozen. Either way, an email pattern goes into `src/redact.mjs` before any code path can serialize a raw Clockchain record. |
| **The `clockchain.bilateral-collection-manifest/v1` key schema.** | Section 6.6 declares this an OPEN DECISION and this specification deliberately does not settle it. Unlike sections 6.3, 6.4 and 6.5 the manifest has NO frozen exact key set: the source synthesis underspecifies it, and section 6.6 states required content and required limits only. The exact keys, their spellings, their types, and their validation rules must be decided and frozen under the repository's exact-key, fail-closed idiom before the manifest is built. Approving this specification approves the section 6.6 constraints, NOT a schema, and an implementer must not read section 6.6 as a key list. |

Only after this specification is approved, and after the Phase -1 probe has run
and been recorded, should the implementation plan be written and TDD
implementation begin.
