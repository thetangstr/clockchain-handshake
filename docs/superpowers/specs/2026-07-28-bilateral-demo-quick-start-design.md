# Bilateral demo quick-start design

## Objective

Create one concise shared starting brief for the three people and computers in
the bilateral Clockchain demo:

- Operator: relay, coordinator, funding, watcher, and fresh aggregate verifier.
- Stakeholder 1: Iris, the payee.
- Stakeholder 2: Billy, the payer.

The brief must help a first-time participant start the verified release without
replacing or contradicting the complete demo-day runbook or either role prompt.

## Public artifact

Add `docs/runbooks/bilateral-demo-quick-start.md` and link it from `README.md`
and `docs/runbooks/bilateral-demo-day.md`.

The brief will use this order:

1. Before everyone starts.
2. Fixed role assignment.
3. Operator checklist.
4. Iris checklist.
5. Billy checklist.
6. Funding and execution order.
7. What counts as success.
8. Immediate stop conditions.

## Content boundaries

The quick-start will:

- pin release SHA `76f585d1e729326b5d749a61937c3971d4f34050`;
- require Node.js 22 and clean checkouts on all three computers;
- direct Iris and Billy to their existing role-specific prompts;
- require separate private delivery of `payee.launch.json` to Iris and
  `payer.launch.json` to Billy;
- tell the operator to start the relay before the coordinator and to wait until
  both role computers are ready because launch manifests expire after 60
  minutes;
- use the coordinator-owned `funding-addresses.json` and the reusable
  `npm run bilateral:fund` command;
- preserve `paymentMoved: false`;
- describe the required state order:
  `PROPOSED -> ACCEPTED -> ACKNOWLEDGED -> operator verification -> AUTHORIZED`;
- state that exactly three independently verifiable Clockchain anchors are
  required and only a fresh aggregate verifier may output `AUTHORIZED`;
- fail closed on missing, duplicate, reordered, expired, malformed, or
  mismatched evidence; and
- link to the full runbook for preparation, recovery, and diagnostics.

The brief will not contain private keys, invitations, tokens, capabilities,
RPC URLs, live evidence, or launch-manifest contents. It will not claim that a
physical rehearsal has already passed.

## Verification

Extend the existing documentation tests and checker so they require:

- the quick-start file and its links;
- the exact three-role mapping;
- the pinned release SHA;
- the two role prompt links;
- relay-before-coordinator ordering;
- the coordinator-owned funding record and reusable funding command;
- the three-anchor and fresh-verifier authority boundaries;
- `paymentMoved: false`; and
- explicit fail-closed stop conditions.

Run focused documentation tests and `npm run docs:check`. Do not run the full
suite again solely for this documentation addition.
