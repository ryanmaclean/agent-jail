#!/usr/bin/env nu
# SPDX-License-Identifier: Apache-2.0
# Native FreeBSD fixture for the agent-jail executor and the smolfire adapter.
#
# Run as root on a disposable FreeBSD 15.x host (never a NAS or a live ZFS pool):
#
#   nu tests/native-freebsd-fixture.nu --smolfire-sha <sha> [--work /var/db/agent-jail-fixture]
#
# It builds a throwaway base from the host userland, installs the executor
# through bin/install-executor.nu, drives the real CLI (`contract`, `run`) and
# then the smolfire adapter against it, and checks that every case leaves no
# jail, mount, rctl rule or directory behind. It prints one line per check and a
# final `agent-jail.native-fixture.v1` JSON summary. Exit 1 if any check failed.
# The work directory is removed at the end (use --keep to inspect it).

const SCHEMA = "agent-jail.native-fixture.v1"

def secs [t0: datetime] { (((date now) - $t0) | into int) / 1_000_000_000 }

def leaks [root: string] {
    let jails = (^jls name | complete | get stdout | lines | where {|l| $l | str starts-with "sf_"})
    let mounts = (^mount -p | complete | get stdout | lines | where {|l| $l | str contains $root})
    let rules = (^rctl -l "jail:" | complete | get stdout | lines | where {|l| $l | str contains "jail:sf_"})
    let dirs = if ($root | path exists) { ls $root | get name } else { [] }
    {jails: $jails, mounts: $mounts, rules: $rules, dirs: $dirs}
}

def clean? [l: record] {
    ($l.jails | is-empty) and ($l.mounts | is-empty) and ($l.rules | is-empty) and ($l.dirs | is-empty)
}

def exec [script: string, args: list<string>] {
    let t0 = (date now)
    let r = (^nu $script ...$args | complete)
    let parsed = try { $r.stdout | from json } catch { null }
    {exit: $r.exit_code, json: $parsed, stdout: $r.stdout, stderr: $r.stderr, secs: (secs $t0)}
}

def out-of [res: record, i: int] {
    try { $res.json.outputs | get $i | get stdout | str trim } catch { "" }
}

def main [
    --smolfire-sha: string = ""
    --smolfire-url: string = "https://github.com/ryanmaclean/smolfire.git"
    --work: string = "/var/db/agent-jail-fixture"
    --keep
] {
    mut checks = []
    let aj = $env.FILE_PWD | path dirname

    if (^uname -s | str trim) != "FreeBSD" or (^id -u | str trim) != "0" {
        print -e "refusing: needs a FreeBSD host and root"
        exit 2
    }
    let host_info = {
        version_k: (^freebsd-version -k | str trim)
        arch: (^uname -m | str trim)
        nu: (^nu --version | str trim)
        racct: (^sysctl -n kern.racct.enable | str trim)
    }

    let base = $"($work)/base"
    let jroot = $"($work)/jails"
    let libexec = $"($work)/libexec"
    let spools = $"($work)/spool"
    rm -rf $work
    mkdir $work $jroot $spools
    chmod 755 $work $jroot

    # --- base: a copy of the host userland, read-only for the jails -----------
    mkdir $base
    ^sh -c $"cd / && timeout 300 tar -cf - bin sbin lib libexec usr/bin usr/sbin usr/lib < /dev/null | tar -xf - -C ($base)"
    mkdir $"($base)/etc" $"($base)/dev" $"($base)/tmp" $"($base)/var"
    for f in [passwd group master.passwd pwd.db spwd.db login.conf login.conf.db nsswitch.conf] {
        if ($"/etc/($f)" | path exists) { cp $"/etc/($f)" $"($base)/etc/($f)" }
    }
    "" | save -f $"($base)/etc/resolv.conf"
    chmod 1777 $"($base)/tmp"

    # --- install the executor and read the pin --------------------------------
    let inst = (^nu $"($aj)/bin/install-executor.nu" --prefix $libexec | complete)
    let inst_line = $inst.stdout | lines | where {|l| $l | str contains "agent-jail.install.v1"} | last
    let inst_json = try { $inst_line | from json } catch { null }
    let script = try { $inst_json.env.AGENT_JAIL_EXECUTOR_PATH } catch { "" }
    let pin = try { $inst_json.env.AGENT_JAIL_EXECUTOR_SHA256 } catch { "" }
    let installed_ok = ($inst.exit_code == 0) and ($script != "") and ($pin != "") and ($script | path exists)
    $checks = ($checks | append {name: "install-executor produces pinned path", ok: $installed_ok, detail: $"exit ($inst.exit_code) ($inst.stderr | str substring 0..120)"})
    if not $installed_ok {
        print ({schema: $SCHEMA, host: $host_info, checks: $checks, failed: 1} | to json -r)
        exit 1
    }
    let st = (^stat -f "%Su %Lp" $script | str trim)
    $checks = ($checks | append {name: "installed script root-owned, not group/other writable", ok: ($st | str starts-with "root ") , detail: $st})

    let c = (exec $script ["contract"])
    $checks = ($checks | append {name: "contract command", ok: ($c.exit == 0 and ($c.json.schema? == "agent-jail.executor.contract.v1")), detail: $"exit ($c.exit)"})

    let common = ["--base" $base "--jail-root" $jroot]
    mut cases = []

    # A. basic pass, jailed, hardening, no network, read-only base, writable tmp
    let a = (exec $script (["run" "case-a"] ++ $common ++ ["--" "uname -s" "sysctl -n security.jail.jailed" "sysctl -n kern.securelevel" "sh -c 'touch /bin/gl23x 2>/dev/null; echo rc=$?'" "sh -c 'echo a > /tmp/w && cat /tmp/w'" "sh -c 'ifconfig -a | grep -c \"inet \" ; true'"]))
    $checks = ($checks | append {name: "A pass verdict, exit 0", ok: ($a.exit == 0 and $a.json.verdict? == "pass"), detail: $"exit ($a.exit) ($a.stderr | str substring 0..160)"})
    $checks = ($checks | append {name: "A FreeBSD + jailed=1 + securelevel=3", ok: ((out-of $a 0) == "FreeBSD" and (out-of $a 1) == "1" and (out-of $a 2) == "3"), detail: $"(out-of $a 0)/(out-of $a 1)/(out-of $a 2)"})
    $checks = ($checks | append {name: "A base read-only (touch refused), tmp writable", ok: ((out-of $a 3) != "rc=0" and (out-of $a 4) == "a"), detail: $"(out-of $a 3) (out-of $a 4)"})
    $checks = ($checks | append {name: "A no network addresses in jail", ok: ((out-of $a 5) == "0"), detail: (out-of $a 5)})
    $checks = ($checks | append {name: "A boot_sec reported", ok: (($a.json.boot_sec? | describe) == "int"), detail: $"boot_sec=($a.json.boot_sec?) wall=($a.secs)s"})
    $checks = ($checks | append {name: "A no leftovers", ok: (clean? (leaks $jroot)), detail: (leaks $jroot | to json -r | str substring 0..200)})

    # B. option-shaped and multiple commands keep order; failing command => fail
    let b = (exec $script (["run" "case-b"] ++ $common ++ ["--" "echo one" "--looks-like-option" "echo three"]))
    let b_cmds = try { $b.json.outputs | get cmd } catch { [] }
    $checks = ($checks | append {name: "B option-shaped command is a command, run is fail", ok: ($b.exit == 1 and $b.json.verdict? == "fail" and ($b_cmds | first) == "echo one" and ("--looks-like-option" in $b_cmds)), detail: $"exit ($b.exit) cmds ($b_cmds | to json -r | str substring 0..120)"})
    $checks = ($checks | append {name: "B no leftovers", ok: (clean? (leaks $jroot)), detail: ""})

    # C. timeout is bounded and torn down
    let t = (exec $script (["run" "case-c" "--timeout" "4"] ++ $common ++ ["--" "sleep 60"]))
    let t_exit = try { $t.json.outputs | last | get exit_code } catch { -1 }
    $checks = ($checks | append {name: "C timeout: fail, bounded wall time, 124/137", ok: ($t.exit == 1 and $t.json.verdict? == "fail" and $t.secs < 20 and ($t_exit in [124 137])), detail: $"exit ($t.exit) cmd_exit ($t_exit) wall ($t.secs)s"})
    $checks = ($checks | append {name: "C no leftovers after timeout", ok: (clean? (leaks $jroot)), detail: (leaks $jroot | to json -r | str substring 0..200)})

    # D. rctl maxproc is enforced (forks fail) and rules are removed
    let d = (exec $script (["run" "case-d" "--maxproc" "8"] ++ $common ++ ["--" "sh -c 'for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do sleep 1 & done; wait' 2>&1"]))
    let d_text = try { $d.json.outputs | first | get stdout } catch { "" }
    $checks = ($checks | append {name: "D maxproc=8 refuses forks", ok: ($d_text =~ '(?i)fork|unavailable|retry'), detail: ($d_text | str substring 0..100)})
    $checks = ($checks | append {name: "D no rctl rule left", ok: (clean? (leaks $jroot)), detail: ""})

    # E. refusals leave nothing behind
    let e = (exec $script (["run" "case-e" "--base" $"($work)/does-not-exist" "--jail-root" $jroot "--" "true"]))
    $checks = ($checks | append {name: "E missing base refused (exit 1 or 2, fail verdict)", ok: ($e.exit in [1 2] and $e.json.verdict? == "fail"), detail: $"exit ($e.exit) ($e.json.error? | default '' | str substring 0..120)"})
    let e2 = (exec $script (["run" "case-e2" "--require-limits"] ++ $common ++ ["--" "true"]))
    $checks = ($checks | append {name: "E2 --require-limits passes with racct on", ok: ($e2.exit == 0), detail: $"exit ($e2.exit)"})
    $checks = ($checks | append {name: "E no leftovers", ok: (clean? (leaks $jroot)), detail: ""})

    # F. abrupt executor death leaks (documented), reconcile by name, verify clean
    let pidfile = $"($work)/crash.pid"
    ^sh -c $"nu ($script) run case-f --base ($base) --jail-root ($jroot) --timeout 120 -- 'sleep 100' > ($work)/crash.out 2>&1 & echo $! > ($pidfile)"
    sleep 5sec
    let before = (leaks $jroot)
    let pid = (open $pidfile | str trim)
    ^kill -9 $pid | complete | ignore
    sleep 2sec
    let after_kill = (leaks $jroot)
    let leaked_names = $after_kill.jails
    $checks = ($checks | append {name: "F SIGKILL of executor leaves a recorded jail (known: no crash reaper)", ok: (($before.jails | length) >= 1), detail: $"before ($before.jails | length) after-kill ($after_kill.jails | length)"})
    for n in $leaked_names {
        ^jail -r $n | complete | ignore
        ^rctl -r $"jail:($n)" | complete | ignore
    }
    for m in ($after_kill.mounts | each {|l| $l | split row "\t" | get 1} | reverse) { ^umount $m | complete | ignore }
    for d in (try { ls $jroot | get name } catch { [] }) { ^rmdir $d | complete | ignore }
    $checks = ($checks | append {name: "F documented manual reconcile restores a clean host", ok: (clean? (leaks $jroot)), detail: (leaks $jroot | to json -r | str substring 0..200)})

    # --- adapter against the real CLI ------------------------------------------
    mut adapter_note = "skipped (no --smolfire-sha)"
    if $smolfire_sha != "" {
        let sf = $"($work)/smolfire"
        let g = (^git clone --quiet $smolfire_url $sf | complete)
        let co = if $g.exit_code == 0 { (^git -C $sf checkout --quiet $smolfire_sha | complete) } else { $g }
        $checks = ($checks | append {name: "smolfire checkout at pinned sha", ok: ($co.exit_code == 0), detail: $co.stderr})
        if $co.exit_code == 0 {
            let adapter = $"($sf)/bin/coord-jail-dispatch.nu"
            let envs = {AGENT_JAIL_EXECUTOR_PATH: $script, AGENT_JAIL_EXECUTOR_SHA256: $pin, SMOLFIRE_JAIL_BASE: $base, SMOLFIRE_JAIL_ROOT: $jroot}
            let mk = {|tid: string, cmds: list<string>|
                let run = ($cmds | each {|c| $c | to json} | str join ", ")
                $"From coordinator@smolfire.local Wed Jan  1 00:00:00 2026\nFrom: coordinator@smolfire.local\nTo: builder@smolfire.local\nMessage-ID: <req.($tid)@fixture>\nContent-Type: text/toml; charset=utf-8\n\ntask_id = \"($tid)\"\ntools_required = [\"Bash\"]\ntimeout_sec = 30\n[commands]\nrun = [($run)]\n\n"
            }
            let disp = {|spool: string, tid: string, did: string, extra: record|
                with-env ($envs | merge $extra) {
                    ^nu $adapter dispatch --task-id $tid --dispatch-id $did --request-id $"<req.($tid)@fixture>" --spool $spool | complete
                }
            }
            let count = {|f: string, pat: string| (open --raw $f | lines | where {|l| $l =~ $pat} | length)}

            # G. one reply per dispatch, bound to the dispatch id
            let sg = $"($spools)/g.mbox"
            (do $mk "tg" ["uname -s" "id -u"]) | save -f $sg
            let rg = (do $disp $sg "tg" "<coord.1.rg@smolfire.local>" {})
            $checks = ($checks | append {name: "G adapter + real CLI: exit 0, exactly one reply bound to dispatch id", ok: ($rg.exit_code == 0 and (do $count $sg '^In-Reply-To: <coord\.1\.rg@smolfire\.local>$') == 1 and (do $count $sg '^X-Verdict: pass$') == 1), detail: $"exit ($rg.exit_code) ($rg.stderr | str substring 0..160)"})

            # H. refusals become exactly one fail reply
            let sh = $"($spools)/h.mbox"
            (do $mk "th" ["true"]) | save -f $sh
            let rh = (do $disp $sh "th" "<coord.1.rh@smolfire.local>" {AGENT_JAIL_EXECUTOR_SHA256: ("0" | fill -c "0" -w 64)})
            $checks = ($checks | append {name: "H wrong pin: one fail reply, no jail run", ok: ((do $count $sh '^X-Verdict: fail') == 1 and (open --raw $sh | str contains "digest mismatch") and (clean? (leaks $jroot))), detail: $"exit ($rh.exit_code)"})
            let unprot = $"($work)/unprotected"
            mkdir $unprot
            chmod 777 $unprot
            cp $script $"($unprot)/jail-execute.nu"
            let si = $"($spools)/i.mbox"
            (do $mk "ti" ["true"]) | save -f $si
            let ri = (do $disp $si "ti" "<coord.1.ri@smolfire.local>" {AGENT_JAIL_EXECUTOR_PATH: $"($unprot)/jail-execute.nu"})
            $checks = ($checks | append {name: "I executor in a world-writable dir refused as unprotected", ok: ((do $count $si '^X-Verdict: fail') == 1 and (open --raw $si | str contains "not protected")), detail: $"exit ($ri.exit_code)"})

            # J. failing command => fail reply, exit 1
            let sj = $"($spools)/j.mbox"
            (do $mk "tj" ["true" "false"]) | save -f $sj
            let rj = (do $disp $sj "tj" "<coord.1.rj@smolfire.local>" {})
            $checks = ($checks | append {name: "J failing command: one fail reply, adapter exit 1", ok: ($rj.exit_code == 1 and (do $count $sj '^X-Verdict: fail') == 1), detail: $"exit ($rj.exit_code)"})

            # K. concurrent appends to one spool: every dispatch gets exactly one intact reply
            let sk = $"($spools)/k.mbox"
            let ids = [1 2 3 4 5 6]
            ($ids | each {|i| do $mk $"tk($i)" [$"echo k($i)"]} | str join "") | save -f $sk
            let t0 = (date now)
            let ks = ($ids | par-each {|i| do $disp $sk $"tk($i)" $"<coord.1.rk($i)@smolfire.local>" {}})
            let k_wall = (secs $t0)
            let k_replies = (do $count $sk '^Message-ID: <jail\.')
            let k_from = (do $count $sk '^From ')
            let k_pass = (do $count $sk '^X-Verdict: pass$')
            let k_bound = ($ids | all {|i| (do $count $sk $"^In-Reply-To: <coord\\.1\\.rk($i)@smolfire\\.local>$") == 1})
            $checks = ($checks | append {name: "K 6 concurrent dispatches, one spool: 6 intact replies, each bound once", ok: ($k_replies == 6 and $k_from == 12 and $k_pass == 6 and $k_bound and ($ks | all {|r| $r.exit_code == 0})), detail: $"replies ($k_replies) from-lines ($k_from) pass ($k_pass) bound ($k_bound) wall ($k_wall)s"})
            $checks = ($checks | append {name: "K no leftovers", ok: (clean? (leaks $jroot)), detail: ""})
            $adapter_note = $"adapter at ($smolfire_sha | str substring 0..8)"
        }
    }

    if not $keep { rm -rf $work }
    let failed = ($checks | where ok == false | length)
    for c in $checks { print $"(if $c.ok { 'ok  ' } else { 'FAIL' }) ($c.name)(if $c.ok { '' } else { ': ' + ($c.detail | into string) })" }
    print ({schema: $SCHEMA, host: $host_info, adapter: $adapter_note, total: ($checks | length), failed: $failed} | to json -r)
    if $failed > 0 { exit 1 }
}
