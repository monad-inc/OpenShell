#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Tests the entrypoint's harness version pin check, and that each harness's
# version.sh reads its CLI's real `--version` output.

set -euo pipefail

RUNTIME_UNDER_TEST="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

fail() {
    printf 'not ok - %s\n' "$*" >&2
    exit 1
}

assert_contains() {
    local file="$1"
    local expected="$2"
    if ! grep -Fq "$expected" "$file"; then
        printf 'missing expected text: %s\n' "$expected" >&2
        printf '%s\n' '--- output ---' >&2
        sed -n '1,50p' "$file" >&2
        fail "assert_contains failed"
    fi
}

assert_not_contains() {
    local file="$1"
    local unexpected="$2"
    if grep -Fq "$unexpected" "$file"; then
        printf 'unexpected text: %s\n' "$unexpected" >&2
        sed -n '1,50p' "$file" >&2
        fail "assert_not_contains failed"
    fi
}

# A payload whose `test` harness reports $1 as its installed version, and whose
# supervisor only says it ran.
make_payload() {
    local dir="$1"
    local installed="$2"

    mkdir -p "$dir/runtime/harnesses/test"
    cp "$RUNTIME_UNDER_TEST/entrypoint.sh" "$dir/runtime/entrypoint.sh"
    printf '#!/usr/bin/env bash\necho supervisor-ran\n' > "$dir/runtime/supervisor.sh"
    chmod +x "$dir/runtime/supervisor.sh"
    printf '#!/usr/bin/env bash\necho %s\n' "$installed" > "$dir/runtime/harnesses/test/version.sh"
}

# run_entrypoint <payload> <output> [pinned version]; returns the exit status.
run_entrypoint() {
    local payload="$1"
    local output="$2"
    local pinned="${3-}"
    local status

    set +e
    if [[ $# -ge 3 ]]; then
        OPENSHELL_AGENT_HARNESS=test OPENSHELL_AGENT_HARNESS_VERSION="$pinned" \
            bash "$payload/runtime/entrypoint.sh" > "$output" 2>&1
    else
        env -u OPENSHELL_AGENT_HARNESS_VERSION OPENSHELL_AGENT_HARNESS=test \
            bash "$payload/runtime/entrypoint.sh" > "$output" 2>&1
    fi
    status=$?
    set -e
    return "$status"
}

test_matching_pin_starts_the_supervisor() {
    local tmp
    tmp="$(mktemp -d)"
    make_payload "$tmp/payload" 2.1.251

    run_entrypoint "$tmp/payload" "$tmp/out" 2.1.251 || fail "matching pin exited $?"
    assert_contains "$tmp/out" "harness test 2.1.251 (pinned: 2.1.251)"
    assert_contains "$tmp/out" "supervisor-ran"
    rm -rf "$tmp"
}

test_mismatched_pin_refuses_to_start() {
    local tmp status=0
    tmp="$(mktemp -d)"
    make_payload "$tmp/payload" 2.1.296

    run_entrypoint "$tmp/payload" "$tmp/out" 2.1.251 || status=$?
    [[ "$status" -eq 78 ]] || fail "mismatched pin should exit 78, got $status"
    assert_contains "$tmp/out" "the image carries test 2.1.296, but the deployment pins 2.1.251"
    assert_not_contains "$tmp/out" "supervisor-ran"
    rm -rf "$tmp"
}

test_unreadable_version_refuses_a_pin() {
    local tmp status=0
    tmp="$(mktemp -d)"
    make_payload "$tmp/payload" 2.1.251
    rm "$tmp/payload/runtime/harnesses/test/version.sh"

    run_entrypoint "$tmp/payload" "$tmp/out" 2.1.251 || status=$?
    [[ "$status" -eq 78 ]] || fail "unknown installed version should exit 78, got $status"
    assert_contains "$tmp/out" "the image carries test unknown"
    rm -rf "$tmp"
}

test_latest_is_a_deliberate_opt_out() {
    local tmp
    tmp="$(mktemp -d)"
    make_payload "$tmp/payload" 2.1.296

    run_entrypoint "$tmp/payload" "$tmp/out" latest || fail "latest pin exited $?"
    assert_contains "$tmp/out" "harness test 2.1.296 (pinned: latest)"
    assert_contains "$tmp/out" "supervisor-ran"
    rm -rf "$tmp"
}

test_unpinned_deployment_only_reports() {
    local tmp
    tmp="$(mktemp -d)"
    make_payload "$tmp/payload" 2.1.296

    run_entrypoint "$tmp/payload" "$tmp/out" || fail "unpinned deployment exited $?"
    assert_contains "$tmp/out" "harness test 2.1.296 (pinned: unpinned)"
    assert_contains "$tmp/out" "supervisor-ran"
    rm -rf "$tmp"
}

# version.sh against each CLI's real `--version` output format.
test_version_scripts_parse_real_output() {
    local tmp
    tmp="$(mktemp -d)"
    mkdir -p "$tmp/bin"
    printf '#!/usr/bin/env bash\necho "2.1.251 (Claude Code)"\n' > "$tmp/bin/claude"
    printf '#!/usr/bin/env bash\necho "codex-cli 0.162.1"\n' > "$tmp/bin/codex"
    chmod +x "$tmp/bin/claude" "$tmp/bin/codex"

    local claude codex
    claude="$(PATH="$tmp/bin:$PATH" bash "$RUNTIME_UNDER_TEST/harnesses/claude/version.sh")"
    codex="$(PATH="$tmp/bin:$PATH" bash "$RUNTIME_UNDER_TEST/harnesses/codex/version.sh")"
    [[ "$claude" == "2.1.251" ]] || fail "claude version.sh printed '$claude'"
    [[ "$codex" == "0.162.1" ]] || fail "codex version.sh printed '$codex'"
    rm -rf "$tmp"
}

test_hung_version_check_times_out() {
    local tmp status=0
    tmp="$(mktemp -d)"
    make_payload "$tmp/payload" 2.1.251
    printf '#!/usr/bin/env bash\nsleep 30\n' > "$tmp/payload/runtime/harnesses/test/version.sh"

    OPENSHELL_AGENT_HARNESS_VERSION_TIMEOUT=1 run_entrypoint "$tmp/payload" "$tmp/out" 2.1.251 || status=$?
    [[ "$status" -eq 78 ]] || fail "hung version check should exit 78, got $status"
    assert_contains "$tmp/out" "checking harness test version"
    assert_contains "$tmp/out" "the image carries test unknown"
    rm -rf "$tmp"
}

test_wrapped_command_runs_after_the_check() {
    local tmp status=0
    tmp="$(mktemp -d)"
    make_payload "$tmp/payload" 2.1.251

    set +e
    OPENSHELL_AGENT_HARNESS=test OPENSHELL_AGENT_HARNESS_VERSION=2.1.251 \
        bash "$tmp/payload/runtime/entrypoint.sh" echo listener-ran > "$tmp/out" 2>&1
    status=$?
    set -e
    [[ "$status" -eq 0 ]] || fail "wrapped command exited $status"
    assert_contains "$tmp/out" "listener-ran"
    assert_not_contains "$tmp/out" "supervisor-ran"

    status=0
    set +e
    OPENSHELL_AGENT_HARNESS=test OPENSHELL_AGENT_HARNESS_VERSION=2.1.296 \
        bash "$tmp/payload/runtime/entrypoint.sh" echo listener-ran > "$tmp/out" 2>&1
    status=$?
    set -e
    [[ "$status" -eq 78 ]] || fail "wrapped command with a mismatched pin should exit 78, got $status"
    assert_not_contains "$tmp/out" "listener-ran"
    rm -rf "$tmp"
}

# version.sh checks the binary the adapter runs: a payload-local one (what
# run.sh --codex-bin uploads) wins over the one on PATH, as in exec.sh.
test_version_scripts_check_the_payload_binary() {
    local tmp h
    for h in claude codex; do
        tmp="$(mktemp -d)"
        mkdir -p "$tmp/bin" "$tmp/payload/runtime/harnesses/$h"
        cp "$RUNTIME_UNDER_TEST/harnesses/$h/version.sh" "$tmp/payload/runtime/harnesses/$h/"
        printf '#!/usr/bin/env bash\necho "%s 1.0.0"\n' "$h" > "$tmp/bin/$h"
        printf '#!/usr/bin/env bash\necho "%s 9.9.9"\n' "$h" > "$tmp/payload/runtime/harnesses/$h/$h"
        chmod +x "$tmp/bin/$h" "$tmp/payload/runtime/harnesses/$h/$h"
        local got
        got="$(PATH="$tmp/bin:$PATH" bash "$tmp/payload/runtime/harnesses/$h/version.sh")"
        [[ "$got" == "9.9.9" ]] || fail "$h version.sh checked '$got', not the payload-local binary"
        rm -rf "$tmp"
    done
}

# A warning line or a changed layout must not be read as the version.
test_version_scripts_ignore_noise() {
    local tmp
    tmp="$(mktemp -d)"
    mkdir -p "$tmp/bin"
    printf '#!/usr/bin/env bash\necho "Warning: something odd"\necho\necho "2.1.251 (Claude Code)"\n' > "$tmp/bin/claude"
    printf '#!/usr/bin/env bash\nprintf "codex-cli 0.162.1 (abc123)\\r\\n"\n' > "$tmp/bin/codex"
    chmod +x "$tmp/bin/claude" "$tmp/bin/codex"

    local claude codex
    claude="$(PATH="$tmp/bin:$PATH" bash "$RUNTIME_UNDER_TEST/harnesses/claude/version.sh")"
    codex="$(PATH="$tmp/bin:$PATH" bash "$RUNTIME_UNDER_TEST/harnesses/codex/version.sh")"
    [[ "$claude" == "2.1.251" ]] || fail "claude version.sh printed '$claude' from noisy output"
    [[ "$codex" == "0.162.1" ]] || fail "codex version.sh printed '$codex' from noisy output"
    rm -rf "$tmp"
}

test_matching_pin_starts_the_supervisor
test_mismatched_pin_refuses_to_start
test_unreadable_version_refuses_a_pin
test_latest_is_a_deliberate_opt_out
test_unpinned_deployment_only_reports
test_version_scripts_parse_real_output
test_hung_version_check_times_out
test_wrapped_command_runs_after_the_check
test_version_scripts_check_the_payload_binary
test_version_scripts_ignore_noise

printf 'ok - entrypoint harness version pin\n'
