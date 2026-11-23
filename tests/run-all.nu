#!/usr/bin/env nu
# SPDX-License-Identifier: Apache-2.0
# tests/run-all.nu — run every tests/*-test.nu from the repo root.
# Prints one JSON summary line on stdout; exits non-zero if any suite fails.

def main [] {
    let root = $env.FILE_PWD | path dirname
    cd $root
    let suites = glob ([$root "tests" "*-test.nu"] | path join) | sort
    let results = $suites | each {|s|
        let r = ^nu $s | complete
        let rel = $s | path relative-to $root
        if $r.exit_code != 0 {
            print -e $"FAIL ($rel)\n($r.stdout)\n($r.stderr)"
        }
        {suite: $rel, exit_code: $r.exit_code, passed: ($r.exit_code == 0)}
    }
    let failed = $results | where passed == false | length
    print ({schema: "agent-jail.test-run.v1", suites: $results, failed: $failed} | to json -r)
    if $failed > 0 { exit 1 }
}
