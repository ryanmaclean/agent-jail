# agent-jail
Agent harness jails for agentic inference on BSD operating systems

Canonical owner of BSD jail isolation (registry: `ryanmaclean/skills` docs/PROJECTS.md,
"jail isolation -> agent-jail").

## Jail executor

`bin/jail-execute.nu` runs a task's commands in an ephemeral, hardened FreeBSD jail
(nullfs `--base`, `zfs clone --zfs-snapshot`, or ocijail `--image`) and returns
`{verdict, boot_sec, outputs, error?, warnings?}` as JSON. Moved here from
`ryanmaclean/smolfire` (ADR 0001, agent-jail#2). smolfire's coordinator is the caller.

```sh
nu bin/jail-execute.nu contract                                   # JSON contract, no host access
nu bin/jail-execute.nu run task-0042 "uname -a" --base /usr/local/smolfire/base-15.0
nu tests/run-all.nu                                               # host-independent tests (stubbed FreeBSD tools)
```

Full detail: [`docs/JAIL-EXECUTOR.md`](docs/JAIL-EXECUTOR.md). License: Apache-2.0.
