#!/usr/bin/env bash
set -uo pipefail

SCRIPT_UNDER_TEST="${SCRIPT_UNDER_TEST:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/anonsurf.sh}"
TEST_TMP="$(mktemp -d)"
trap 'rm -rf "$TEST_TMP"' EXIT

passed=0
failed=0

run_test() {
  local name=$1
  shift

  if "$@"; then
    printf 'PASS: %s\n' "$name"
    passed=$((passed + 1))
  else
    printf 'FAIL: %s\n' "$name"
    failed=$((failed + 1))
  fi
}

test_activates_tor_before_bootstrap_polling() {
  local marker="$TEST_TMP/tor-active"

  MARKER="$marker" SCRIPT_UNDER_TEST="$SCRIPT_UNDER_TEST" bash -c '
    source <(sed "/^CMD=/,\$d" "$SCRIPT_UNDER_TEST")

    tor_is_active() { return 0; }
    tor_activate() { : > "$MARKER"; }
    tor_is_bootstrapped() { test -e "$MARKER"; }
    ss() {
      printf "udp UNCONN 0 0 127.0.0.1:9053 0.0.0.0:*\n"
      printf "tcp LISTEN 0 4096 127.0.0.1:9040 0.0.0.0:*\n"
    }
    seq() { printf "1\n"; }
    sleep() { :; }
    spinner() { :; }

    set +e
    wait_for_tor >/dev/null
    test -e "$MARKER"
  '
}

test_bootstrap_timeout_survives_errexit() {
  local output="$TEST_TMP/bootstrap-timeout.out"

  if ! OUTPUT="$output" SCRIPT_UNDER_TEST="$SCRIPT_UNDER_TEST" bash -c '
    source <(sed "/^CMD=/,\$d" "$SCRIPT_UNDER_TEST")

    tor_is_active() { return 0; }
    tor_activate() { return 1; }
    tor_is_bootstrapped() { return 1; }
    ss() {
      printf "udp UNCONN 0 0 127.0.0.1:9053 0.0.0.0:*\n"
      printf "tcp LISTEN 0 4096 127.0.0.1:9040 0.0.0.0:*\n"
    }
    seq() { printf "1\n"; }
    sleep() { :; }
    spinner() { :; }

    wait_for_tor >"$OUTPUT"
    printf "completed\n" >>"$OUTPUT"
  '; then
    return 1
  fi

  grep -q "Bootstrap.*TIMEOUT" "$output" &&
    grep -q "^completed$" "$output"
}

test_interrupt_rolls_back_partial_start() {
  local rollback_log="$TEST_TMP/rollback.log"

  ROLLBACK_LOG="$rollback_log" SCRIPT_UNDER_TEST="$SCRIPT_UNDER_TEST" bash -c '
    source <(sed "/^CMD=/,\$d" "$SCRIPT_UNDER_TEST")

    need_root() { :; }
    print_banner() { :; }
    section() { :; }
    preflight() { :; }
    ensure_state_dir() { :; }
    record_tor_state() { :; }
    ensure_torrc() { TORRC_MODIFIED=1; }
    detect_tor_unit() { TOR_UNIT=tor@default; }
    systemctl() { :; }
    wait_for_tor() {
      kill -INT "$$"
      sleep 0.1
    }
    check_tor_connectivity() { return 0; }
    backup_resolv_conf() { :; }
    apply_iptables() { :; }

    restore_iptables() { printf "firewall\n" >>"$ROLLBACK_LOG"; }
    restore_resolv_conf() { printf "dns\n" >>"$ROLLBACK_LOG"; }
    restore_torrc() { printf "torrc\n" >>"$ROLLBACK_LOG"; }
    tor_stop_if_needed() { printf "tor-service\n" >>"$ROLLBACK_LOG"; }
    clear_state() { printf "state\n" >>"$ROLLBACK_LOG"; }

    start
  ' >/dev/null 2>&1 || true

  for expected in firewall dns torrc tor-service state; do
    grep -qxF "$expected" "$rollback_log" || return 1
  done
}

test_sanitizes_stale_torrc_backup() {
  local state_dir="$TEST_TMP/state"
  local torrc="$TEST_TMP/torrc"
  local backup="$state_dir/torrc.bak"

  mkdir -p "$state_dir"
  for file in "$torrc" "$backup"; do
    {
      printf "SocksPort 9050\n"
      printf "# BEGIN ANONSURF-LITE\n"
      printf "TransPort 9040\n"
      printf "# END ANONSURF-LITE\n"
    } >"$file"
  done

  TEST_STATE_DIR="$state_dir" TEST_TORRC="$torrc" TEST_TORRC_BAK="$backup" \
    SCRIPT_UNDER_TEST="$SCRIPT_UNDER_TEST" bash -c '
      source <(sed "/^CMD=/,\$d" "$SCRIPT_UNDER_TEST")
      STATE_DIR="$TEST_STATE_DIR"
      TORRC="$TEST_TORRC"
      TORRC_BAK="$TEST_TORRC_BAK"
      ensure_torrc

      test "$(grep -c "^# BEGIN ANONSURF-LITE$" "$TORRC")" -eq 1 || exit 1
      if grep -q "^# BEGIN ANONSURF-LITE$" "$TORRC_BAK"; then
        exit 1
      fi
      grep -qxF "SocksPort 9050" "$TORRC_BAK" || exit 1
    '
}

run_test "activates dormant Tor before bootstrap polling" test_activates_tor_before_bootstrap_polling
run_test "handles bootstrap timeout with errexit enabled" test_bootstrap_timeout_survives_errexit
run_test "rolls back a partial start when interrupted" test_interrupt_rolls_back_partial_start
run_test "sanitizes a stale Tor configuration backup" test_sanitizes_stale_torrc_backup

printf '\n%d passed, %d failed\n' "$passed" "$failed"
test "$failed" -eq 0
