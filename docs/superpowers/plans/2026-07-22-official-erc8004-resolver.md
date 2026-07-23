# Official ERC-8004 Resolver Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the hosted Clockchain MCP resolve identities from the current official ERC-8004 Ethereum Sepolia registry and prove the change without shipping unrelated developer-tools work.

**Architecture:** Apply a reversible environment-only Cloud Run override for immediate demo readiness, then make the official address the tested source default in a clean checkout of `thetangstr/clockchain-developer-tools`. Merge through the repository's existing build/test/deploy workflow and retain the prior Cloud Run revision as rollback.

**Tech Stack:** TypeScript, Node.js 20/22, Node `test`, GitHub Actions, Google Cloud Run, Ethereum Sepolia JSON-RPC.

---

### Task 1: Capture the live baseline and rollback target

**Files:**
- Create outside Git: `.context/platform/baseline.json`

- [ ] **Step 1: Record non-secret Cloud Run state**

Run:

```bash
mkdir -p .context/platform
gcloud run services describe clockchain-mcp \
  --project clockchain-mcp \
  --region us-central1 \
  --format=json |
  jq '{
    revision:.status.latestReadyRevisionName,
    url:.status.url,
    image:.spec.template.spec.containers[0].image,
    traffic:.status.traffic,
    erc8004Env:[
      .spec.template.spec.containers[0].env[]? |
      select(.name == "EVM_RPC_URL" or .name == "ERC8004_CHAIN" or .name == "ERC8004_REGISTRY_ADDRESS") |
      {name,value}
    ]
  }' > .context/platform/baseline.json
```

Expected at plan authoring time: rollback revision is
`clockchain-mcp-00010-w5b` and no ERC-8004 override is present. Treat the
captured `.revision` value—not this historical expectation—as the rollback
target.

- [ ] **Step 2: Prove the current public behavior**

Mint one demo token and call `resolve_agent` for official-registry agent `0`.
Expected before the override: `unknown` or data from the legacy registry that
does not match the official owner/URI.

### Task 2: Apply the reversible registry override

**Files:**
- External state only: Cloud Run service configuration

- [ ] **Step 1: Update only the registry address**

Run:

```bash
gcloud run services update clockchain-mcp \
  --project clockchain-mcp \
  --region us-central1 \
  --update-env-vars=ERC8004_REGISTRY_ADDRESS=0x8004A818BFB912233c491871b3d84c89A494BD9e \
  --quiet
```

The existing source default already selects Ethereum Sepolia and its public RPC.
Do not redeploy source and do not touch existing secret bindings.

- [ ] **Step 2: Verify service and resolver behavior**

Run:

```bash
curl -fsS https://mcp.clockchain.network/health
```

Then call `resolve_agent("0")` through the hosted MCP.

Expected: health 200; status `active`; owner and URI match direct calls to the
official registry.

- [ ] **Step 3: Record rollback**

If health or resolution fails:

```bash
ROLLBACK_REVISION="$(
  jq -er '.revision | select(test("^clockchain-mcp-[a-z0-9-]+$"))' \
    .context/platform/baseline.json
)"
gcloud run services update-traffic clockchain-mcp \
  --project clockchain-mcp \
  --region us-central1 \
  --to-revisions="${ROLLBACK_REVISION}=100" \
  --quiet
```

### Task 3: Create a clean developer-tools checkout

**Files:**
- Create under gitignored collaboration state: `.context/clockchain-developer-tools/`

- [ ] **Step 1: Clone the verified remote default branch**

Run:

```bash
gh repo clone thetangstr/clockchain-developer-tools \
  .context/clockchain-developer-tools \
  -- --depth 1 --branch main
```

Expected: clean `main` checkout. Do not use
`/Volumes/home/Projects_Hosted/clockchain/specs`; it has unrelated commits and
uncommitted files.

- [ ] **Step 2: Install and run the baseline**

Run:

```bash
cd .context/clockchain-developer-tools
npm ci --ignore-scripts
npm run build
npm test
```

Expected: baseline passes before edits.

- [ ] **Step 3: Create a scoped branch**

Run: `git switch -c kailortang-prog/official-erc8004-registry`

### Task 4: Update the source default with TDD

**Files:**
- Modify: `packages/core/src/config.ts:18`
- Modify: `packages/core/test/erc8004.test.mjs`
- Modify: `product-a-identity-decision.md`
- Modify: `implementation-plan.md`

- [ ] **Step 1: Write the failing default-address test**

Extend the existing `../dist/index.js` import with
`DEFAULT_ERC8004_REGISTRY`, `DEFAULT_ERC8004_CHAIN`, and
`readConfigFromEnv`, then add:

```js
test("defaults to the official ERC-8004 Ethereum Sepolia registry", () => {
  assert.equal(DEFAULT_ERC8004_CHAIN, "ethereum-sepolia");
  assert.equal(
    DEFAULT_ERC8004_REGISTRY,
    "0x8004A818BFB912233c491871b3d84c89A494BD9e",
  );
  assert.equal(
    readConfigFromEnv({}).erc8004RegistryAddress,
    DEFAULT_ERC8004_REGISTRY,
  );
});

test("keeps an explicit registry override", () => {
  assert.equal(
    readConfigFromEnv({ ERC8004_REGISTRY_ADDRESS: "0x1111111111111111111111111111111111111111" })
      .erc8004RegistryAddress,
    "0x1111111111111111111111111111111111111111",
  );
});
```

- [ ] **Step 2: Build and run the focused test to verify it fails**

Run:

```bash
npm run build
node --test packages/core/test/erc8004.test.mjs
```

Expected: FAIL because the checked-in default is `0x7177…`.

- [ ] **Step 3: Change the default and decision record**

Set:

```ts
export const DEFAULT_ERC8004_REGISTRY =
  "0x8004A818BFB912233c491871b3d84c89A494BD9e";
```

Update the comments and decision documents to distinguish:

```text
official current Ethereum Sepolia registry: 0x8004A818...
legacy verified deployment: 0x7177...
Clockchain consumes and resolves identity; it does not issue ERC-8004 identity
```

- [ ] **Step 4: Run focused and full verification**

Run:

```bash
npm run build
node --test packages/core/test/erc8004.test.mjs
npm test
git diff --check
```

Expected: all checks pass.

- [ ] **Step 5: Commit with the Lore protocol**

```bash
git add packages/core/src/config.ts packages/core/test/erc8004.test.mjs product-a-identity-decision.md implementation-plan.md
git commit -m "Resolve agent identities from the official ERC-8004 registry" \
  -m "Constraint: The Handshake demo registers fresh identities on the current official Ethereum Sepolia deployment.
Rejected: Keep the legacy 0x7177 registry | It can return plausible but wrong identities for overlapping numeric IDs.
Confidence: high
Scope-risk: narrow
Directive: Keep explicit env overrides supported for controlled migrations.
Tested: Core build, focused resolver tests, full test suite, and diff check."
```

### Task 5: Review, merge, and verify the gated deployment

**Files:**
- No further source changes unless review identifies a defect

- [ ] **Step 1: Push and open the PR**

```bash
git push -u origin kailortang-prog/official-erc8004-registry
gh pr create --repo thetangstr/clockchain-developer-tools --base main \
  --head kailortang-prog/official-erc8004-registry \
  --title "Resolve identities from the official ERC-8004 registry" \
  --body-file ../platform-pr.md
```

- [ ] **Step 2: Require build/test checks**

Run: `gh pr checks --watch <PR_NUMBER> --repo thetangstr/clockchain-developer-tools`

Expected: all required checks pass.

- [ ] **Step 3: Merge and monitor deployment**

Squash-merge the PR. Watch the `Deploy MCP to Cloud Run` workflow through its
test, deploy, and smoke-test jobs.

- [ ] **Step 4: Verify the final live state**

Confirm:

```text
/health returns 200
latest ready revision serves 100% traffic
ERC8004_REGISTRY_ADDRESS override remains present
known official identity resolves
fresh demo identity resolves with expected owner and URI
existing Clockchain get_timestamp and receipt smoke test still pass
```

- [ ] **Step 5: Save deployment evidence**

Write a sanitized deployment summary to the Handshake repository under
`.context/platform/deployment-result.json`, including PR URL, merge SHA,
workflow URL, revision, official registry, health result, and resolver result.
