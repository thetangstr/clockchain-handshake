# Public Handshake Monitor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish an exact sanitized operator snapshot to S3 and render it on the public handshake run page.

**Architecture:** Add a pure fail-closed projection and a long-lived publisher to the handshake repository. Add a validating polling client to the research site. Keep publishing independent from protocol execution.

**Tech Stack:** Node.js 22, `node:test`, AWS CLI/S3, React 19, Next.js, Vitest

---

### Task 1: Public projection

**Files:**
- Create: `src/bilateral/coordination/public-monitor.mjs`
- Create: `test/bilateral-public-monitor.test.mjs`

- [ ] Write a failing test for the exact secret-free projection and malformed input rejection.
- [ ] Run `node --test test/bilateral-public-monitor.test.mjs` and observe the expected failure.
- [ ] Implement the minimum exact projection.
- [ ] Rerun the focused test and observe it pass.

### Task 2: Operator publisher

**Files:**
- Create: `scripts/publish-public-monitor.mjs`
- Modify: `package.json`
- Modify: `docs/runbooks/bilateral-demo-live-handoff.md`

- [ ] Add a long-lived publisher that reads the loopback console, probes the local Payer MCP port, and uploads only the public projection to the fixed S3 object.
- [ ] Document `npm run bilateral:public-monitor` as a separate advisory operator process.
- [ ] Run focused tests and syntax checks.

### Task 3: Public run-page monitor

**Files in `clockchain-research`:**
- Create: `src/lib/bilateral-public-monitor.ts`
- Create: `src/components/BilateralPublicMonitor.tsx`
- Create: `src/lib/bilateral-public-monitor.test.ts`
- Modify: `src/components/BilateralHandshakeRunbook.tsx`

- [ ] Write failing validator and run-page contract tests.
- [ ] Implement strict polling, stale-state handling, and the read-only monitor UI.
- [ ] Run focused tests, full tests, typecheck, lint, and production build.

