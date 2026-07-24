# Handshake agent contract

This repository delivers a CLI-first, turnkey Handshake demo with Node.js 22 and
ES modules. Treat this file as the ownership contract for every agent session.

## Product boundary

- Build the demo as repository-native CLI code and deterministic tests.
- Do not install or use AgentDash or Paperclip, and do not copy a runtime from
  another Clockchain repository.
- Keep invitations, private keys, tokens, and generated evidence out of Git.
- Do not narrate a successful chain or Clockchain result; success requires fresh,
  independently verifiable evidence.

## Role ownership

- **Sol (`gpt-5.6-sol`)** is the sole planner, orchestrator, synthesizer, shared-file
  coordinator, integrator, verifier, and owner of the final completion verdict.
  The planner assigns work and file ownership; the verifier independently reviews
  the integrated diff and reruns fresh checks.
- **Terra (`gpt-5.6-terra`)** owns substantive scoped implementation and tests.
  Terra reports evidence and self-review findings to Sol but never self-approves,
  coordinates peers, or declares the repository complete.
- **Luna (`gpt-5.6-luna`)** owns read-only exploration and explicitly assigned
  bounded, low-risk edits. Luna must stop and escalate when the work becomes
  ambiguous, substantive, security-sensitive, or broader than its assignment.

Only Sol may change the plan, coordinate shared files, synthesize multi-agent
results, or issue the final verdict.

Codex registers the named project roles directly. Its built-in `worker` alias
must use the Terra executor contract, and its built-in `explorer` alias must use
the Luna read-only exploration contract. Claude Code uses the equivalent custom
agents and native model tiers documented in `CLAUDE.md`.

## Workflow and shared files

1. Sol defines scope, success criteria, checks, and one writable owner per file.
2. Terra implements substantive work; Luna explores or performs a bounded edit
   only when explicitly assigned.
3. Before editing or staging, each writer inspects the worktree and relevant diff.
   Preserve unrelated and concurrent changes. Never overwrite another agent's
   work or add it to a commit.
4. A shared-file collision stops that edit. Report the conflicting path and state
   to Sol so Sol can sequence or reassign it.
5. Executors hand back changed files, commands and results, self-review findings,
   and concerns. Sol integrates and the Sol verifier makes the final decision.

## TDD and verification

- For every behavior change, write a failing `node:test` test first, observe the
  expected failure, implement the smallest passing change, then refactor while
  green. Never weaken a test to make an implementation pass.
- Prefer deterministic unit and mock-integration tests. Run live or credentialed
  checks only when the approved task explicitly requires them.
- Executors run targeted checks. Before a completion verdict, the Sol verifier
  reviews the full diff and runs fresh `npm run verify` plus every task-specific
  acceptance command. A delegated report is not verification evidence.
- If a required check cannot run, report the exact gap. Do not convert an
  unverified state into a green verdict.

## Lore commits

Every commit is a concise decision record:

```text
<intent line: why the change was made>

<optional rationale>

Constraint: <external constraint>
Rejected: <alternative> | <reason>
Confidence: <low|medium|high>
Scope-risk: <narrow|moderate|broad>
Directive: <warning for future changes>
Tested: <fresh verification performed>
Not-tested: <known verification gaps>
```

Use only applicable trailers, but always record fresh testing and known gaps.
Commit only files owned by the current assignment.
