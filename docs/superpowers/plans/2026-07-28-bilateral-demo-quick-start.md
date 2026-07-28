# Bilateral Demo Quick-Start Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish and gate one concise three-computer quick-start for the Operator, Iris/payee, and Billy/payer.

**Architecture:** The new Markdown file is a navigation and execution-order layer over the existing complete runbook and role prompts. Existing documentation validation remains the authority: the quick-start joins the gated bilateral document set, its required links are resolved, and exact content checks prevent role, funding, and authorization drift.

**Tech Stack:** Markdown, Node.js 22, `node:test`, the repository's `scripts/check-docs.mjs` validator.

---

### Task 1: Lock the quick-start contract with failing documentation tests

**Files:**
- Modify: `test/docs.test.mjs`
- Modify: `scripts/check-docs.mjs`

- [ ] **Step 1: Add the quick-start to the bilateral document fixtures**

Add `docs/runbooks/bilateral-demo-quick-start.md` to both
`BILATERAL_PUBLIC_DOCUMENTS` arrays. Add its required links to
`REQUIRED_LINKS` in `scripts/check-docs.mjs`:

```js
"docs/runbooks/bilateral-demo-quick-start.md": Object.freeze([
  "../../README.md",
  "bilateral-demo-day.md",
  "../../prompts/run-billy-bilateral-demo.md",
  "../../prompts/run-iris-bilateral-demo.md",
]),
```

Also require `README.md` and `docs/runbooks/bilateral-demo-day.md` to link to
`docs/runbooks/bilateral-demo-quick-start.md`.

- [ ] **Step 2: Add exact quick-start assertions**

Add one `node:test` case that reads the quick-start and asserts:

```js
assert.match(quickStart, /76f585d1e729326b5d749a61937c3971d4f34050/);
assert.match(quickStart, /Stakeholder 1\s+[—-]\s+Iris\s+[—-]\s+payee/);
assert.match(quickStart, /Stakeholder 2\s+[—-]\s+Billy\s+[—-]\s+payer/);
assert.match(quickStart, /Operator\s+[—-]\s+relay,\s+coordinator,\s+funding,\s+watcher,\s+fresh aggregate verifier/i);
assert.match(quickStart, /payee\.launch\.json[^.\n]*only to Iris/i);
assert.match(quickStart, /payer\.launch\.json[^.\n]*only to Billy/i);
assert.match(quickStart, /relay[^.\n]*before[^.\n]*coordinator/i);
assert.match(quickStart, /funding-addresses\.json/);
assert.match(quickStart, /npm run bilateral:fund/);
assert.match(quickStart, /exactly three independently verifiable Clockchain anchors/i);
assert.match(quickStart, /only a fresh aggregate verifier may output `AUTHORIZED`/i);
assert.match(quickStart, /paymentMoved: false/);
assert.match(quickStart, /missing, duplicate, reordered, expired, malformed, or mismatched evidence/i);
```

Add matching entries to `pathRequirements` in `scripts/check-docs.mjs` so the
standalone checker enforces the same public contract.

- [ ] **Step 3: Run the focused test and observe the expected failure**

Run:

```sh
node --test test/docs.test.mjs
```

Expected: FAIL because `docs/runbooks/bilateral-demo-quick-start.md` and its
links do not exist yet.

### Task 2: Write the shared three-computer quick-start

**Files:**
- Create: `docs/runbooks/bilateral-demo-quick-start.md`
- Modify: `README.md`
- Modify: `docs/runbooks/bilateral-demo-day.md`

- [ ] **Step 1: Create the quick-start**

Write the approved eight sections in this order:

```markdown
# Bilateral Clockchain demo quick-start

## Before everyone starts
## Fixed role assignment
## Operator checklist
## Iris checklist
## Billy checklist
## Funding and execution order
## What counts as success
## Immediate stop conditions
```

Use release SHA
`76f585d1e729326b5d749a61937c3971d4f34050`, require Node.js 22 and clean
checkouts, link each participant to the full runbook or exact role prompt, and
keep all secrets out of the document.

Include the exact state order:

```text
PROPOSED -> ACCEPTED -> ACKNOWLEDGED -> operator verification -> AUTHORIZED
```

State that exactly three independently verifiable Clockchain anchors are
required, only a fresh aggregate verifier may output `AUTHORIZED`, and
`paymentMoved: false` remains invariant.

- [ ] **Step 2: Link the quick-start from the main entry points**

Add a short “start here” link in `README.md` beside the bilateral demo-day
runbook. Add a reciprocal quick-start link near the top of
`docs/runbooks/bilateral-demo-day.md`.

- [ ] **Step 3: Run focused tests**

Run:

```sh
node --test test/docs.test.mjs
```

Expected: PASS with no failed tests.

- [ ] **Step 4: Run the standalone documentation checker**

Run:

```sh
npm run docs:check
```

Expected: `Documentation checks passed` with the updated gated-document count.

### Task 3: Review and publish the documentation-only release

**Files:**
- Review: `docs/runbooks/bilateral-demo-quick-start.md`
- Review: `README.md`
- Review: `docs/runbooks/bilateral-demo-day.md`
- Review: `scripts/check-docs.mjs`
- Review: `test/docs.test.mjs`

- [ ] **Step 1: Check formatting and forbidden material**

Run:

```sh
git diff --check
rg -n "TBD|TODO|PRIVATE KEY|Bearer |clockchain-token|invitationCode" \
  docs/runbooks/bilateral-demo-quick-start.md
```

Expected: `git diff --check` exits zero and the forbidden-material scan returns
no matches.

- [ ] **Step 2: Confirm the branch is otherwise clean and review the complete diff**

Run:

```sh
git status --short
git diff -- README.md docs/runbooks/bilateral-demo-day.md \
  docs/runbooks/bilateral-demo-quick-start.md scripts/check-docs.mjs \
  test/docs.test.mjs
```

Expected: only the planned documentation and documentation-gate files are
modified or untracked.

- [ ] **Step 3: Commit the implementation**

Stage only the five implementation files and commit with a Lore message:

```text
Make the three-computer bilateral demo easy to start

Constraint: The brief must preserve the reviewed release and keep private launch material role-local.
Rejected: Duplicate the full demo-day runbook | A short shared checklist reduces startup mistakes without creating a second recovery authority.
Confidence: high
Scope-risk: narrow
Directive: Keep role mapping, three-anchor verification, and paymentMoved:false exact.
Tested: node --test test/docs.test.mjs; npm run docs:check; git diff --check
Not-tested: Physical three-computer rehearsal remains a live operator activity.
```

- [ ] **Step 4: Push the branch**

Run:

```sh
git push
```

Expected: the current branch advances on
`origin/kailortang-prog/handshake-demo-review`.
