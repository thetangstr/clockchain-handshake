# Stakeholder-hosted Payer AWS repair design

**Status:** Approved design

**Date:** 2026-08-01

**Repository:** `thetangstr/clockchain-handshake`

## 1. Objective

Repair the existing AWS stakeholder control plane so one Payer stakeholder and
one Requestor stakeholder can each start from a fresh local agent and complete
the real bilateral Handshake with one public prompt apiece.

Yang and Codex remain the behind-the-scenes operator. They approve the two
public claim fingerprints, fund the four generated Sepolia addresses once, and
launch the fresh aggregate verifier. Neither stakeholder receives AWS access,
operator secrets, launch manifests, invitations, capabilities, private paths,
certificates, private keys, or evidence attachments.

This repair reuses the reviewed AWS bootstrap, relay, tunnel, coordinator,
funding, verifier, and publisher architecture. It does not introduce a second
broker, automatic role approval, or a simulated Handshake.

## 2. Current evidence and defect

The accepted protocol release
`a5d3cfd4090f772cb6f97c9bc3d6d2740196253a` already contains the required
one-shot stakeholder wrappers:

- Payer runs `npm run bilateral:payer -- --discovery-url <url> --state <path>`.
- Requestor runs
  `npm run bilateral:request-payment -- --discovery-url <url> --state <path>`.

The Payer wrapper already generates its private X25519, SSH, and MCP TLS
identities locally; submits a public claim; waits for operator approval; opens
the sealed bootstrap response locally; opens an outbound restricted tunnel;
and starts the Payer supervisor. The stakeholder machine requires no inbound
port, router configuration, AWS credential, or operator-owned private file.

The deployed AWS environment is not presently usable for this path:

- the Operator and Publisher ECS services have desired count one but running
  count zero;
- the public Payer discovery is expired and is bound to an older repository
  SHA;
- public Requestor discovery returns HTTP 403 because the run has not advanced
  through Payer readiness;
- the public Payer MCP listener is unavailable because no approved Payer tunnel
  is active; and
- the hosted public monitor reports the failed or expired run.

The repair must diagnose and correct the specific Operator and Publisher task
exit causes. It must not weaken discovery expiry, SHA binding, claim approval,
TLS pinning, event authority, funding replay protection, or verifier freshness
to make the deployment appear healthy.

## 3. Chosen architecture

The repair keeps the existing authority and network boundaries:

1. AWS hosts the coordination relay, bootstrap service, restricted tunnel
   gateway, operator worker, publisher, funding task, and fresh verifier task.
2. Payer owns its local private state, mandate signing key, SSH tunnel key, and
   MCP TLS private key.
3. Payer initiates an outbound SSH connection over TCP 443 and requests only
   the reviewed reverse-forward from the AWS public MCP listener to its local
   `127.0.0.1:9443` MCP service.
4. AWS forwards opaque TCP and never terminates Payer MCP TLS.
5. Requestor validates the signed discovery and Payer MCP certificate binding,
   calls `request_payment`, and must receive exact `HANDSHAKE_REQUIRED` before
   its one-shot wrapper starts the Requestor supervisor.
6. Payer alone signs the mandate, `PROPOSED`, and `ACKNOWLEDGED`. Requestor alone
   signs the payment request and `ACCEPTED`.
7. A new aggregate-verifier task independently refetches the three Clockchain
   anchors and remains the only surface permitted to emit `AUTHORIZED`.

The public monitor, operator console, relay projections, and MCP guidance are
advisory. They cannot substitute for signed role events or fresh verifier
evidence.

## 4. Stakeholder and operator experience

### 4.1 Payer stakeholder

Payer receives only the reviewed SHA and fresh signed Payer discovery URL. A
single public prompt directs its local Codex, Claude Code, or Hermes agent to:

1. confirm the Payer role and reviewed SHA;
2. clone and detach at the accepted release;
3. verify Node.js 22 and install with `npm ci --ignore-scripts`;
4. create a fresh owner-private Payer state root;
5. start the one Payer wrapper command; and
6. remain attached through `PAYER_CLAIM_PENDING`, `PAYER_MCP_READY`,
   `PROPOSED`, `ACKNOWLEDGED`, and local completion.

The Payer agent reports its public claim fingerprint. Yang or Codex compares it
with the authenticated operator view and approves that exact claim once.

### 4.2 Requestor stakeholder

Requestor does not start until the public run page and operator both show exact
`PAYER_MCP_READY`. Requestor receives only the same reviewed SHA and fresh
signed Requestor discovery URL. Its single public prompt directs the agent to
prepare a clean detached checkout, create fresh private state, run the one
request-payment wrapper, and remain attached.

The wrapper obtains the Payer's exact handshake guidance from MCP. It creates
and submits the Requestor bootstrap claim without another human prompt. Yang or
Codex compares and approves the exact Requestor claim fingerprint once.

### 4.3 Behind-the-scenes operator

The operator performs only the existing bounded action sequence:

1. start a fresh run;
2. approve the exact Payer claim;
3. wait for `PAYER_MCP_READY`;
4. approve the exact Requestor claim;
5. fund the signed four-address record once;
6. wait for `PROPOSED -> ACCEPTED -> ACKNOWLEDGED`; and
7. start one fresh aggregate verifier.

The operator never authors role evidence or the authorization verdict.

## 5. Runtime repair scope

The AWS repair is limited to the existing deployment and its exact runtime
configuration:

1. inspect the stopped Operator and Publisher ECS task reasons and redacted
   CloudWatch logs;
2. identify whether the failure is image provenance, task configuration,
   service dependency, secret binding, mounted state, or startup ordering;
3. add or update a focused deterministic test for each corrected defect before
   changing production code or infrastructure;
4. build and deploy immutable images bound to the accepted protocol SHA;
5. update the existing CloudFormation stack without replacing durable funding
   journals or broadening IAM, network, secret, or filesystem access;
6. require Relay, Bootstrap, Tunnel, Operator, and Publisher services to reach
   their intended running counts and remain healthy through one fresh run;
7. start a fresh session and publish unexpired Payer discovery bound to the
   accepted SHA; and
8. publish Requestor discovery only after Payer reaches authenticated
   `PAYER_MCP_READY`.

No change may make Requestor discovery public before the current session is
ready, keep a Payer discovery valid after expiry, or make the public MCP port
appear healthy before the approved Payer tunnel exists.

## 6. Public run-page change

The production `/handshake/run` page changes only after the repaired AWS path
completes a fresh acceptance run.

The primary page order becomes:

1. local-agent prerequisites;
2. Payer stakeholder prompt with one copy icon;
3. prominent operator-approval and `PAYER_MCP_READY` gate;
4. Requestor stakeholder prompt with one copy icon;
5. public Clockchain monitor and historical evidence.

The Payer and Requestor prompts use distinct colors and explicit role labels.
The DOM and visible numbering must place the Payer prompt before the readiness
gate and the Requestor prompt after it. Side-by-side presentation must not imply
that the prompts can start concurrently.

The proven Yang-hosted Payer path remains available as a clearly separated
fallback. The page must not label the stakeholder-Payer path ready until the
live acceptance criteria in this design pass.

## 7. Failure handling

The flow fails closed when any of the following occurs:

- a service repeatedly exits or cannot reach its intended running count;
- discovery is missing, expired, malformed, incorrectly signed, or bound to a
  different repository SHA, release, session, endpoint, or certificate;
- the Payer claim fingerprint differs from the operator view;
- the tunnel requests a different key, port, command, or destination;
- Payer MCP is reachable before approval or unavailable after
  `PAYER_MCP_READY`;
- Requestor discovery is published before Payer readiness;
- MCP returns anything other than the exact reviewed `HANDSHAKE_REQUIRED`
  guidance contract;
- a funding journal is missing, duplicated, recreated, or ambiguous;
- role evidence is missing, duplicated, reordered, expired, malformed, or
  signed by the wrong authority; or
- verifier publication is absent, stale, mismatched, or not independently
  reproducible.

On failure, preserve durable state and funding journals, publish only sanitized
status, and do not retry a consumed bootstrap package, funding batch, anchor,
or verifier publication blindly.

## 8. Acceptance criteria

The repair is complete only when one fresh cross-machine stakeholder run proves
all of the following:

- Relay, Bootstrap, Tunnel, Operator, and Publisher remain healthy for the run;
- Payer discovery is unexpired, correctly signed, and bound to the accepted
  protocol SHA;
- Payer starts from a fresh local agent with only public prompt inputs;
- Payer generates its private identities locally and reaches an operator-
  approved `PAYER_MCP_READY` through the outbound tunnel;
- Requestor discovery becomes publicly readable only after Payer readiness;
- Requestor starts from a separate fresh local agent with only public prompt
  inputs;
- Requestor calls Payer MCP and receives exact `HANDSHAKE_REQUIRED`;
- the operator funds exactly four fresh addresses once with `0.01 Sepolia ETH`
  apiece for gas;
- Clockchain records exactly `PROPOSED -> ACCEPTED -> ACKNOWLEDGED` under the
  exact Payer, Requestor, Payer signer authority;
- exactly three public explorer links and role receipts are available;
- a fresh aggregate verifier alone emits `AUTHORIZED`;
- every protocol, receipt, monitor, console, and verdict artifact preserves
  `paymentMoved:false`;
- the public run page exposes the correct sequential two-prompt procedure; and
- the Yang-hosted fallback remains accurate and usable.

Focused runtime tests, AWS infrastructure tests, site rendering tests, and a
production build must pass before publication. The complete Handshake
verification suite runs only after the repaired happy path succeeds and the
implementation is stable.

## 9. Security invariants

- Never place invitations, raw capabilities, bootstrap packages, private keys,
  TLS private material, tokens, treasury secrets, launch manifests, private
  paths, or live evidence in Git, public discovery, browser state, logs, or the
  public monitor.
- Never transfer stakeholder private keys or private state to AWS or another
  participant.
- Never trust relay fields, console state, monitor fields, health checks, or MCP
  prose as event or authorization authority.
- Never let the operator console, publisher, coordinator, role wrapper, or
  public page emit the authorization literal.
- Never delete or recreate the existing funding journal after a funding
  attempt.
- Never operate two funded live sessions concurrently.

## 10. Non-goals

This repair does not provide production high availability, automatic
stakeholder admission, concurrent sessions, mainnet settlement, multi-
validator security, a general mandate directory, browser-only agent support,
or a new A2A channel. It does not move the Payer agent into AWS. It proves that
two independently controlled stakeholder machines can complete the existing
demo protocol through the reviewed shared AWS infrastructure.

## 11. Rollback and fallback

If the AWS repair exposes more than one unrelated architectural defect or
cannot complete the fresh acceptance run without weakening an invariant, stop
the stakeholder-Payer pilot. Keep the production run page on the proven
Yang-hosted Payer flow and report the exact blocked AWS service and evidence.

CloudFormation rollback must preserve encrypted durable state, immutable image
history, funding journals, public historical evidence, and the last accepted
site release. A failed repair must not overwrite the previously verified run.
