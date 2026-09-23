# Cross-project lessons — 2026-09

agent-jail should own the **BSD jail-based isolation branch** of the runtime research.

## Relationship to other projects

- **smolFire** = microVM isolation/reference.
- **agent-jail** = jail/OCI isolation/reference.
- **BOP** = run identity + filesystem state.
- **Moth** = candidate tiny worker executed inside the jail.
- **Genoa** = packaging/deployment/receipt layer.

## Comparison contract

Use the same workload and metrics as smolFire:
- startup latency
- RSS
- filesystem bytes
- network setup cost
- escape/isolation boundary
- cleanup/recovery
- BOP run/version binding

Avoid reimplementing orchestration or image construction here.

## Agent assignment

Copilot is primary; Codex fallback is issue/PR delegation with `@codex`.
