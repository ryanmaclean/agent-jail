# AGENTS.md

## Role

BSD jail-based agent isolation control.

## Owns

- jail isolation
- jail lifecycle
- jail-vs-microVM benchmark

## Do not duplicate

- agent orchestration
- image builder
- duplicate worker runtime

## Sibling repos to consult first

- ryanmaclean/smolfire
- ryanmaclean/moth
- ryanmaclean/bop

## Cross-project context

Read `docs/CROSS-PROJECT-LESSONS-2026-09.md` before making architectural changes.

## Agent delegation

- Primary GitHub coding agent: Copilot when assignable/available.
- Fallback: delegate the issue or PR to Codex with `@codex`.
- Do not treat Copilot/Codex state as canonical project state; keep canonical work in repo issues/BOP/filesystem state.
