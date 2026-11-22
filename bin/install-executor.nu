#!/usr/bin/env nu
# SPDX-License-Identifier: Apache-2.0
# install-executor.nu: install jail-execute.nu at a content-addressed, protected,
# read-only path and print the pin a coordinator needs. The destination is
# <prefix>/<sha256>/jail-execute.nu, root-owned, mode 0555 in a 0555 directory,
# published by one rename of a fully staged directory, so a launcher that checks
# the pin and then launches `contract` and `run` separately cannot be handed
# different bytes by anyone but root. An existing destination is never
# overwritten: a mismatch is refused.
#
#   nu bin/install-executor.nu [--src FILE] [--prefix DIR] [--immutable] [--allow-nonroot]
#
# Prints one JSON line (schema agent-jail.install.v1) with path, sha256 and the
# AGENT_JAIL_EXECUTOR_PATH / AGENT_JAIL_EXECUTOR_SHA256 values to export.
# --immutable additionally sets the FreeBSD schg flag on the installed tree.
# --allow-nonroot is for tests only: the result is not a protected install.

def digest-of [p: string] { open --raw $p | hash sha256 }

def fail [msg: string] {
    print -e $msg
    exit 1
}

def main [
    --src: string = ""
    --prefix: string = "/usr/local/libexec/agent-jail"
    --immutable
    --allow-nonroot
] {
    let src = if $src == "" { $env.FILE_PWD | path join "jail-execute.nu" } else { $src }
    if not ($src | path exists) { fail $"source not found: ($src)" }
    let uid = ^id -u | str trim
    if $uid != "0" and not $allow_nonroot {
        fail "refusing to install as non-root: the install would not be protected (use --allow-nonroot for tests only)"
    }
    let sha = digest-of $src
    let dest_dir = [$prefix $sha] | path join
    let dest = [$dest_dir "jail-execute.nu"] | path join
    ^install -d -m 0755 $prefix
    mut state = "installed"
    if ($dest_dir | path exists) {
        if not ($dest | path exists) or (digest-of $dest) != $sha {
            fail $"existing ($dest) does not match its content address; refusing to overwrite"
        }
        $state = "already-installed"
    } else {
        let stage = ^mktemp -d ([$prefix ".stage.XXXXXX"] | path join) | str trim
        let staged = [$stage "jail-execute.nu"] | path join
        ^install -m 0555 $src $staged
        ^chmod 0555 $stage
        if (digest-of $staged) != $sha {
            ^chmod 0755 $stage
            rm --recursive --force $stage
            fail "staged copy digest mismatch; nothing installed"
        }
        ^mv $stage $dest_dir
        if $immutable and ((^uname -s | str trim) == "FreeBSD") {
            ^chflags -R schg $dest_dir
        }
    }
    if (digest-of $dest) != $sha { fail "installed file digest mismatch after install" }
    {
        schema: "agent-jail.install.v1"
        state: $state
        path: $dest
        sha256: $sha
        env: {AGENT_JAIL_EXECUTOR_PATH: $dest, AGENT_JAIL_EXECUTOR_SHA256: $sha}
    } | to json -r | print
}
