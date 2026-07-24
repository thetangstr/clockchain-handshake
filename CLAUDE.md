@AGENTS.md

# Claude Code model mapping

Claude Code mirrors the repository roles with native model tiers:
planner/verifier use Opus, substantive executor uses Sonnet, and
explore/lightweight-executor use Haiku. The canonical GPT-5.6 model contract is
enforced by Codex project configuration, not by native Claude model names.

Use the matching custom agent in `.claude/agents/`. The ownership, TDD,
shared-file coordination, verification, and Lore commit rules in `AGENTS.md`
remain authoritative for every model tier.
