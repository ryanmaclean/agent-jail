# SPDX-License-Identifier: Apache-2.0
# Offline test for bin/install-executor.nu: temp prefix, no root, no jail.

def assert [condition: bool, what: string] {
    if not $condition { error make {msg: $"assert failed: ($what)"} }
}

let root = $env.FILE_PWD | path dirname
let installer = [$root "bin" "install-executor.nu"] | path join
let src = [$root "bin" "jail-execute.nu"] | path join
let temp = ^mktemp -d | str trim
let prefix = [$temp "libexec"] | path join
let want = open --raw $src | hash sha256

print "install: refuses a non-root install unless explicitly allowed"
if (^id -u | str trim) != "0" {
    let r = ^nu $installer --prefix $prefix | complete
    assert ($r.exit_code != 0) "non-root install refused"
    assert (not ($prefix | path exists)) "nothing written on refusal"
}

print "install: content-addressed, read-only, one JSON pin"
let r = ^nu $installer --prefix $prefix --allow-nonroot | complete
assert ($r.exit_code == 0) $"install ok: ($r.stderr)"
let out = $r.stdout | from json
assert ($out.schema == "agent-jail.install.v1") "schema"
assert ($out.sha256 == $want) "sha256 is the source digest"
assert ($out.path == ([$prefix $want "jail-execute.nu"] | path join)) "content-addressed path"
assert ($out.env.AGENT_JAIL_EXECUTOR_SHA256 == $want) "env pin"
assert ((open --raw $out.path | hash sha256) == $want) "installed bytes match"
assert ((ls -l -D $out.path | first | get mode) == "r-xr-xr-x") "file mode 0555"
assert ((ls -l -D ($out.path | path dirname) | first | get mode) == "r-xr-xr-x") "dir mode 0555"
assert ((ls -a $prefix | where name =~ '\.stage\.' | length) == 0) "no stage dir left behind"

print "install: the installed copy answers the contract"
let c = ^nu $out.path contract | from json
assert ($c.schema == "agent-jail.executor.contract.v1") "contract schema"

print "install: idempotent"
let again = ^nu $installer --prefix $prefix --allow-nonroot | from json
assert ($again.state == "already-installed") "second run is a no-op"
assert ($again.path == $out.path) "same path"

print "install: a tampered destination is refused, never overwritten"
^chmod 755 ($out.path | path dirname)
^chmod 644 $out.path
"tampered\n" | save --force $out.path
let bad = ^nu $installer --prefix $prefix --allow-nonroot | complete
assert ($bad.exit_code != 0) "tampered content address refused"
assert ((open --raw $out.path) == "tampered\n") "tampered file left untouched"

^chmod -R u+w $temp
rm --recursive --force $temp
print "ok"
