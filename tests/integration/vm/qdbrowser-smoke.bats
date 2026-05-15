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

teardown_file() {
    vm_run "pkill -f qdbrowser || true"
}
