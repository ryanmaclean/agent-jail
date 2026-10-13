#!/usr/bin/env nu
# SPDX-License-Identifier: Apache-2.0
# Synthetic native command model. Never executes a native backend.
const TOOL = 'unset'
def knob [name: string] { ($env | get -o $name | default '0') == '1' }
def state [kind: string] { $env.MOCK_DIR | path join ($kind + '.json') }
def --wrapped main [...args] {
    $'($TOOL) ($args | str join " ")' + "\n" | save --append $env.MOCK_LOG
    let file = state $TOOL
    if $TOOL == jail {
        if '-c' in $args {
            let index = ($args | enumerate | where item == '-f' | first | get index)
            let conf = ($args | get ($index + 1))
            let bytes = open --raw $conf
            $bytes | save --force ($env.MOCK_DIR | path join last.conf)
            let dns = ($conf | path dirname | path join resolv.conf)
            if ($dns | path exists) { cp $dns ($env.MOCK_DIR | path join last.resolv.conf) }
            let paths = ($bytes | parse -r 'path = "(?P<path>[^"]+)";')
            {jid:42,name:($args | last),path:$paths.0.path} | to json | save --force $file
            if (knob MOCK_JAIL_CREATE_FAIL) { print -e 'jail: mock create failure'; exit 1 }
            print 42
        } else if '-r' in $args {
            if (knob MOCK_JAIL_REMOVE_FAIL) { print -e 'jail: mock remove failure'; exit 1 }
            if ($file | path exists) { rm $file }
        } else { exit 90 }
    } else if $TOOL == jls {
        if (knob MOCK_IDENTITY_FAIL) { print -e 'inventory failed'; exit 1 }
        let p = state jail
        let rows = if ($p | path exists) {
            let row = open $p
            if (knob MOCK_IDENTITY_CHANGE) { [($row | update jid 43)] } else { [$row] }
        } else { [] }
        let observation = {jail-information:{jail:$rows}}
        $observation | to json | save --force ($env.MOCK_DIR | path join jls-observation.json)
        $observation | to json | print
    } else if $TOOL == mount {
        if (knob MOCK_MOUNT_REMAINS) { print $'tmpfs ($env.MOCK_ROOT)/sf_fault_abcdef/tmp tmpfs rw 0 0' }
    } else if $TOOL == zfs {
        match $args.0 {
            clone => {
                let path = ($args | where {|a| $a | str starts-with 'mountpoint='} | first | str replace 'mountpoint=' '')
                {name:($args | last),id:'101',path:$path} | to json | save --force $file
                if (knob MOCK_CLONE_FAIL) { print -e 'clone failed after attempt'; exit 1 }
            }
            list => {
                if (knob MOCK_ZFS_QUERY_FAIL) { exit 1 }
                if ($file | path exists) {
                    let row = open $file
                    print ($row.name + "\t" + $row.id + "\t" + $row.path)
                }
            }
            destroy => {
                if (knob MOCK_DESTROY_FAIL) { print -e 'destroy failed'; exit 1 }
                if ($file | path exists) { rm $file }
            }
            _ => { exit 90 }
        }
    } else if $TOOL == rctl {
        if $args.0 == '-a' and (knob MOCK_RCTL_ADD_FAIL) { print -e 'rctl add uncertain'; exit 1 }
        if $args.0 == '-r' and (knob MOCK_RCTL_REMOVE_FAIL) { print -e 'rctl remove failed'; exit 1 }
    } else if $TOOL == podman {
        match $args.0 {
            run => {
                let index = ($args | enumerate | where item == '--name' | first | get index)
                let id = ('a' | fill -c a -w 64)
                {name:($args | get ($index + 1)),id:$id} | to json | save --force $file
                if (knob MOCK_PODMAN_FAIL) { print -e 'container acquisition uncertain'; exit 1 }
                print $id
            }
            ps => {
                if (knob MOCK_IDENTITY_FAIL) { exit 1 }
                if ($file | path exists) { let row = open $file; print ($row.id + "\t" + $row.name) }
            }
            rm => {
                if (knob MOCK_PODMAN_REMOVE_FAIL) { exit 1 }
                if ($file | path exists) { rm $file }
            }
            exec => {
                let command = ($args | skip 2)
                let r = (^($command.0) ...($command | skip 1) | complete)
                print -n $r.stdout
                print -e -n $r.stderr
                exit $r.exit_code
            }
            _ => { exit 90 }
        }
    } else { exit 90 }
}
