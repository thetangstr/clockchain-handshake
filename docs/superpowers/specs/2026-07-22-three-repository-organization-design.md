# Clockchain three-repository organization

Date: 2026-07-22

Status: Approved direction, awaiting written-spec review

## Outcome

Clockchain will have three independently managed product repositories:

1. `thetangstr/clockchain-handshake` for the Agent Trust Handshake product and demo.
2. `thetangstr/clockchain-services` for the Services portal and technical product surfaces.
3. `thetangstr/clockchain-research` for the editorial research publication.

Each repository is a separate Conductor project. They are not nested Git repositories, raw gitlinks, or submodules of an umbrella checkout.

`thetangstr/clockchain-developer-tools` remains a platform dependency that owns the MCP server, schemas, gateway adapters, and shared protocol implementation. The InfoObject D4 repositories remain external network dependencies. Neither is one of the three product surfaces.

The local `knowledge/` repository remains shared operational memory during the migration. It is not a fourth product or a Conductor project. Its backup strategy is separate from this reorganization.

## Approaches considered

### 1. Create a clean Handshake repository and retain the existing Services and Research repositories

This is the selected approach. It matches the actual product boundaries, avoids importing the accidental umbrella history, and lets Conductor create normal worktrees from each remote.

Trade-off: Handshake must be extracted carefully from Research, and shared links and styles must be made explicit.

### 2. Rewrite and repurpose `thetangstr/clockchain` as the Handshake repository

Rejected. Its initial commit contains unrelated workspace artifacts, sensitive-looking files, and nested repository gitlinks without `.gitmodules`. Rewriting that history would add security and recovery risk without preserving useful Handshake history.

### 3. Keep Handshake inside Research and split only Services

Rejected. This preserves the current ownership ambiguity, leaves an interactive product inside an editorial automation repository, and contradicts the approved three-project model.

## Repository boundaries

### Agent Trust Handshake

The Handshake repository owns:

- The public Handshake walkthrough and interactive sequence.
- The honest status/readiness page.
- Handshake-specific scenario data, fixtures, diagrams, media, and copy.
- The canonical Handshake product requirements and demo/runbook documentation.
- Product-level adapters that call versioned platform interfaces.
- Tests that enforce truth labels, interaction behavior, link integrity, accessibility, and responsive layout.

The Handshake repository does not own:

- MCP server or gateway implementation.
- Validator-network or multi-validator implementation.
- AgentDash/Paperclip runtime implementation.
- Payment rails, ERC-8004 contracts, or InfoObject D4 code.
- General Clockchain research articles and stakeholder updates.

The first extraction baseline comes from a clean, verified `clockchain-research/origin/main`, plus the reviewed Handshake status commit if it is still unmerged. The current dirty `feat/handshake-status-onepager` checkout must not be copied wholesale.

Handshake data currently embedded in page-local arrays will be consolidated into typed product fixtures. Walkthrough, one-pager, and status views will render from the same facts so shipped, simulated, blocked, and external states cannot drift independently.

Before any public deployment, the extracted content must resolve these known contradictions:

- `Billie` versus `Billy` naming.
- Server-side ZK proof status versus pages that still call it a placeholder.
- Proof-of-time challenge versus unsupported beacon language.
- Single-validator testnet reality versus court-grade or trustless-adjacent wording.
- Live MCP tool names and availability versus hard-coded catalog claims.

Public positioning remains Clockchain® and time-only until the mainnet and multi-validator gates are genuinely satisfied.

### Services portal

The Services repository owns:

- All `/services/*` user and developer routes.
- `src/components/services/*`.
- Service API proxies and the server-side Clockchain credential boundary.
- The six service libraries: `clockchain`, `clockchain-public`, `intent-detect`, `receipt-format`, `services-history`, and `services-wallet`.
- The service shell, privacy copy, assets, environment contract, and deployment configuration.
- Retained operational product surfaces, including MCP onboarding, status, and playground experiences, after each is explicitly reviewed and moved under a Services-owned route.

The `/services` URL prefix is permanent because already-issued receipts use `/services/verify?ledgerId=...`.

Research continues serving the existing implementation until the standalone deployment passes verification. Cutover uses compatibility redirects or reverse proxying from the old Research host so previously shared receipt URLs remain valid. Code deletion from Research occurs only after routing has changed and old links have been tested.

The standalone Services deployment requires a separate preview environment before production. The deployment target will be selected during implementation planning from the already-directed AWS hosting path; infrastructure changes require the applicable AWS skill and infrastructure-as-code review.

### Research publication

The Research repository owns:

- The public editorial home.
- `/research/*`, `/brief/*`, `/updates/*`, `/strategy/*`, `/manifesto/*`, `/use-cases`, and editorial decks.
- `src/data/briefs`, `src/data/weekly`, editorial loaders, and curated research manifests.
- The Tuesday/Friday research brief workflow.
- The Monday/Thursday stakeholder update workflow.
- Research-specific navigation, metadata, privacy policy, and presentation assets.

Research does not own live writes, product dashboards, product authentication, service APIs, or interactive product demos.

The following existing surfaces require deliberate disposition rather than silent deletion:

- `/handshake` and current Handshake product pages move to Handshake; historical research about the product may remain.
- `/services/*` moves to Services with compatibility routing retained at the old host.
- `/playground` and the MCP `/dashboard` move to Services if they remain active product experiences.
- `/plan/*`, `/review/*`, and current product PRDs move to the relevant private product repository or private documentation tier.
- `/connect`, `/architecture`, `/demo`, and `/atlas-wire` are reviewed individually and either moved to their owning product or archived as historical material.

The public research registry and global navigation must be curated after moves so removed product pages are not still indexed or advertised.

## Interfaces and data flow

The ownership flow is:

```text
Handshake UI  ----\
                    >-- versioned public platform contracts --> clockchain-developer-tools/MCP --> gateway/network
Services portal ----/

Research publication --> static editorial content and scheduled research/update pipelines
```

Handshake and Services consume documented, versioned contracts. They do not copy MCP implementation or maintain independent lists of tool behavior without an automated verification source.

Research may link to the two products using absolute canonical URLs. It does not import their runtime code.

## Migration sequence

### Phase 0: secure and establish clean baselines

1. Inventory sensitive files committed to `thetangstr/clockchain`.
2. Rotate any real credential or private key found in that history.
3. Record the exact source commits for Research, Services, the Handshake feature branch, and developer-tools.
4. Work only from clean clones or worktrees based on verified remote `main` branches.

### Phase 1: establish Handshake

1. Seed the new repository with only the approved Handshake routes, component, assets, and canonical docs.
2. Add a minimal independent Next.js application shell and explicit styling tokens.
3. Consolidate scenario and readiness facts into typed fixtures.
4. Correct contradictory claims before enabling a public deployment.
5. Add unit, interaction, link, accessibility, and build verification.
6. Deploy a non-production preview and verify it independently.
7. Replace Research-owned Handshake product routes with canonical redirects only after the new deployment is accepted.

### Phase 2: cut over Services

1. Prove byte-level parity or intentionally reconcile divergence between Services `main`, Research `origin/main`, and the Handshake-removal change.
2. Add the standalone deployment target and server-side secrets through the approved secret mechanism.
3. Run typecheck, lint, production build, and route/API smoke tests.
4. Verify raw-text versus hash behavior, keyless verification, MCP content, theme behavior, and receipt links.
5. Establish compatibility routing for old Research-hosted `/services/*` URLs.
6. Switch production routing.
7. Replace the Research implementation with redirects, then delete service-only code after a repo-wide import check.

### Phase 3: narrow Research

1. Rebuild navigation and home copy around the editorial contract.
2. Curate the research manifest and privacy boundary.
3. Move or archive operational routes according to the repository boundary above.
4. Remove dependencies and environment variables no longer needed by editorial publishing.
5. Verify both recurring publication workflows and all retained public routes.

### Phase 4: retire the umbrella repository

1. Confirm all required material exists in one of the three product repositories or the shared knowledge store.
2. Confirm all exposed credentials from the umbrella history have been rotated.
3. Remove the umbrella repository from Conductor so no new workspaces are created from it.
4. Delete or archive the GitHub repository according to the credential-remediation result. Archiving alone is insufficient if live secrets remain in history.

## Conductor configuration

Each product is added to Conductor from its own GitHub remote with `origin/main` as the base branch.

Each Next.js repository will receive reviewed shared settings similar to:

```toml
"$schema" = "https://conductor.build/schemas/settings.repo.schema.json"

[scripts]
setup = "npm ci"
run_mode = "concurrent"

[scripts.run.dev]
command = "npm run dev -- --port $CONDUCTOR_PORT"
default = true
icon = "globe"

[scripts.run.verify]
command = "npm run typecheck && npm run build"
icon = "test-tube"
```

Research adds its data validation and test commands. Handshake adds its interaction test command. Services adds API smoke testing when the target environment is configured.

Local credentials use gitignored `.env.local` files copied through Conductor Files to copy. Shared repository settings contain no secrets. Settings become active for the team only after they are merged to each repository's remote default branch.

## Failure handling and rollback

- No source route is removed before its replacement is deployed and verified.
- Existing receipt URLs are treated as durable external contracts.
- Handshake remains non-public if its truth review fails.
- Services routing can roll back to the Research-hosted implementation until Research code deletion is merged.
- Research cleanup is split into reviewable commits so navigation, manifest, route removal, and dependency cleanup can be reverted independently.
- No migration commit sweeps untracked media, `.omc`, `.claude`, generated state, or unrelated local documents.

## Verification and completion criteria

The organization is complete when:

1. All three GitHub repositories have clean `main` branches and can create independent Conductor workspaces.
2. Each repository has an accurate `AGENTS.md`, README, Conductor settings, and explicit environment contract.
3. Handshake builds independently, renders from one canonical status model, and contains no unresolved public claim contradictions.
4. Services builds and deploys independently; all retained routes and APIs pass smoke tests; old receipt links still resolve.
5. Research builds independently; brief and update validation passes; retained public routes have no broken product links.
6. Research no longer contains the Handshake or Services runtime implementations.
7. No product repository contains secrets or unrelated workspace state.
8. The accidental umbrella repository can no longer create broken Conductor workspaces and has been safely archived or deleted after credential remediation.

## Scope boundary

This design covers repository ownership, migration, compatibility routing, Conductor setup, and verification. It does not implement new Handshake capabilities, build the Services auth backend, choose new product claims, change the validator network, or add unrelated features.
