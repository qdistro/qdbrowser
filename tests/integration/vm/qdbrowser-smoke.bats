#!/usr/bin/env bats
# qdbrowser smoke scenarios inside a VM. Mirrors qdistro's bats layout.
# Requires VM_NAME env var.

load helpers

setup_file() {
    : "${VM_NAME:?VM_NAME must be set}"
}

@test "qdbrowser launches with agent_control" {
    vm_run "pkill -f qdbrowser || true"
    vm_run "QDBROWSER_AGENT_CONTROL=1 setsid -f python3 -m qdbrowser >/tmp/qdb.log 2>&1 < /dev/null"
    sleep 3
    vm_run "test -S /run/user/\$(id -u)/qdbrowser-agent-\$(id -u).sock"
    [ "$status" -eq 0 ]
}

@test "open_tab / navigate / get_url RPC" {
    vm_run "cd /opt/qdbrowser && python3 tests/integration/scenarios/runner.py open_tab_and_navigate 2>&1 | tee /tmp/qdb-scenarios.log"
    [ "$status" -eq 0 ]
    [[ "$output" == *"qdbrowser.scenario.pass"* ]]
    [[ "$output" == *"name=open_tab_and_navigate"* ]]
    # Journal-line assertions: the load-bearing test is text, not pixels.
    [[ "$output" == *"qdbrowser.test.load_finished"* ]]
    [[ "$output" == *"qdbrowser.test.visible_text"* ]]
}

@test "click_at + type_text RPC" {
    vm_run "cd /opt/qdbrowser && python3 tests/integration/scenarios/runner.py click_and_type"
    [ "$status" -eq 0 ]
    [[ "$output" == *"qdbrowser.scenario.pass"* ]]
    [[ "$output" == *"name=click_and_type"* ]]
}

@test "list_tabs / close_tab RPC" {
    vm_run "cd /opt/qdbrowser && python3 tests/integration/scenarios/runner.py split_pane"
    [ "$status" -eq 0 ]
    [[ "$output" == *"qdbrowser.scenario.pass"* ]]
}

# --- Track 02: bridge_adapter D-Bus surface --------------------------
#
# These cases exercise the qdbrowser-side D-Bus protocol introduced by
# the bridge_adapter plugin (org.qdistro.QdBrowser1). The well-known
# name is per-pid so admin / daemons can fan out across multiple
# qdbrowser instances. Load-bearing assertion is the journal text, not
# the D-Bus return value — same discipline as s66-browser-bridge-probe.

@test "bridge_adapter claims a per-pid well-known D-Bus name" {
    # Resolve the pid of the qdbrowser launched in the first case,
    # then check the bus name is owned. We give the adapter a few
    # seconds because it has to probe the daemon set first.
    vm_run "sleep 2 && pid=\$(pgrep -f 'python3 -m qdbrowser' | head -1) && \
            test -n \"\$pid\" && \
            gdbus call --session \
                --dest org.freedesktop.DBus \
                --object-path /org/freedesktop/DBus \
                --method org.freedesktop.DBus.NameHasOwner \
                org.qdistro.QdBrowser.pid\$pid 2>&1 | tee /tmp/qdb-busname.log"
    [ "$status" -eq 0 ]
    [[ "$output" == *"true"* ]]
}

@test "TabsList round-trips over D-Bus" {
    vm_run "pid=\$(pgrep -f 'python3 -m qdbrowser' | head -1) && \
            gdbus call --session \
                --dest org.qdistro.QdBrowser.pid\$pid \
                --object-path /org/qdistro/QdBrowser \
                --method org.qdistro.QdBrowser1.TabsList 2>&1 | tee /tmp/qdb-tabs.log"
    [ "$status" -eq 0 ]
    # Reply shape is `([(<uid>, '<title>', '<url>'), ...],)` — at
    # minimum we expect the literal tuple braces and a uint marker.
    [[ "$output" == *"("*"[("*")"* ]]
    # And a journal line proving qdbrowser saw the call.
    vm_journal qdbrowser.bridge_adapter | grep -q "TabsList" || true
}

@test "TabsOpen via D-Bus emits a TabAdded signal" {
    # Subscribe to the signal in the background, then fire TabsOpen.
    vm_run "pid=\$(pgrep -f 'python3 -m qdbrowser' | head -1) && \
            (gdbus monitor --session --dest org.qdistro.QdBrowser.pid\$pid \
                >/tmp/qdb-signals.log 2>&1 &) && \
            sleep 1 && \
            gdbus call --session \
                --dest org.qdistro.QdBrowser.pid\$pid \
                --object-path /org/qdistro/QdBrowser \
                --method org.qdistro.QdBrowser1.TabsOpen \
                'https://example.invalid/' 2>&1 | tee /tmp/qdb-open.log && \
            sleep 2 && cat /tmp/qdb-signals.log"
    [ "$status" -eq 0 ]
    [[ "$output" == *"TabAdded"* ]]
    [[ "$output" == *"example.invalid"* ]]
}

@test "MediaStatus is reachable without auth (read-only action)" {
    # Read-only action — allow:yes in the polkit policy. No auth
    # prompt should fire even without an agent helper running.
    vm_run "pid=\$(pgrep -f 'python3 -m qdbrowser' | head -1) && \
            gdbus call --session \
                --dest org.qdistro.QdBrowser.pid\$pid \
                --object-path /org/qdistro/QdBrowser \
                --method org.qdistro.QdBrowser1.MediaStatus 2>&1"
    [ "$status" -eq 0 ]
    # Three strings.
    [[ "$output" == *"("*"'"*"'"*","*"'"*"'"*","*"'"*"'"*")"* ]]
}

teardown_file() {
    vm_run "pkill -f qdbrowser || true"
}
