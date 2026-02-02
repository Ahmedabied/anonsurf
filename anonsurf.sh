#!/usr/bin/env bash
set -euo pipefail

APP_NAME="anonsurf-lite"
STATE_DIR="/var/lib/${APP_NAME}"
IPTABLES_BAK="${STATE_DIR}/iptables.rules"
IP6TABLES_BAK="${STATE_DIR}/ip6tables.rules"
RESOLV_BAK="${STATE_DIR}/resolv.conf"
RESOLV_LINK_BAK="${STATE_DIR}/resolv.conf.link"
TORRC="/etc/tor/torrc"
TORRC_BAK="${STATE_DIR}/torrc.bak"
TOR_WAS_ACTIVE="${STATE_DIR}/tor.was.active"

TOR_TRANS_PORT=9040
TOR_DNS_PORT=9053
TOR_CTRL_PORT=9051
TOR_VADDR="10.192.0.0/10"
TORRC_MODIFIED=0
TOR_UNIT=""
TOR_EXCLUDE="192.168.0.0/16 172.16.0.0/12 10.0.0.0/8"
FORCE_STOP=0
VERIFY_START=1
TOR_STREAMING=0
TOR_EXIT_NODES=""
TOR_STRICT_NODES=0
TOR_NEW_CIRCUIT_PERIOD=""
TOR_MAX_DIRTINESS=""
AUTO_EXIT=0
FORCE_OS=0
FORCE_NFT=0

COLOR=${COLOR:-1}
if [ "$COLOR" -eq 1 ]; then
  C_RED='\033[1;31m'
  C_GREEN='\033[1;32m'
  C_YELLOW='\033[1;33m'
  C_BLUE='\033[1;34m'
  C_CYAN='\033[1;36m'
  C_RESET='\033[0m'
else
  C_RED=''
  C_GREEN=''
  C_YELLOW=''
  C_BLUE=''
  C_CYAN=''
  C_RESET=''
fi

log() { printf "%s\n" "$*"; }
say() { printf "%b%s%b\n" "$1" "$2" "$C_RESET"; }
section() { printf "%b==> %s%b\n" "$C_CYAN" "$1" "$C_RESET"; }
ok() { say "$C_GREEN" "[OK] $1"; }
warn() { say "$C_YELLOW" "[!!] $1"; }
err() { say "$C_RED" "[ERR] $1"; }
die() { printf "error: %s\n" "$*" >&2; exit 1; }

has_tor_nat_rules() {
  iptables -t nat -S 2>/dev/null | grep -Eq 'REDIRECT.*(9040|9053)'
}

has_tor_filter_rules() {
  local tuser tuid
  tuser="$(tor_user)"
  tuid="$(id -u "$tuser" 2>/dev/null || true)"
  if [ -n "$tuid" ]; then
    iptables -S 2>/dev/null | grep -Eq "uid-owner ${tuid}"
  else
    iptables -S 2>/dev/null | grep -Eq 'uid-owner .*tor|uid-owner .*debian-tor'
  fi
}

verify_tor_connectivity() {
  if ! command -v torsocks >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
    warn "torsocks/curl missing; cannot verify Tor connectivity"
    return 1
  fi
  if torsocks curl -s --max-time 6 https://api.ipify.org >/dev/null 2>&1; then
    ok "Tor connectivity check: OK"
    return 0
  fi
  warn "Tor connectivity check: FAILED"
  return 1
}

need_root() {
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    die "run as root (try: sudo $0 <start|stop|reset|status>)"
  fi
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing dependency: $1"
}

is_supported_os() {
  if [ -r /etc/os-release ]; then
    . /etc/os-release
    case "${ID:-}" in
      ubuntu|pop|popos) return 0 ;;
    esac
    case "${ID_LIKE:-}" in
      *ubuntu*|*debian*) return 0 ;;
    esac
  fi
  return 1
}

check_iptables_backend() {
  if iptables -V 2>/dev/null | grep -q 'nf_tables'; then
    if [ "$FORCE_NFT" -eq 1 ]; then
      warn "iptables-nft detected; continuing by request"
      return 0
    fi
    die "iptables-nft detected; use --force-nft to continue (may be unstable)"
  fi
}

preflight() {
  need_cmd iptables
  need_cmd iptables-save
  need_cmd iptables-restore
  need_cmd systemctl
  if ! is_supported_os; then
    if [ "$FORCE_OS" -eq 1 ]; then
      warn "unsupported OS detected; continuing by request"
    else
      die "unsupported OS (intended for Pop!/Ubuntu). Use --force-os to continue."
    fi
  fi
  check_iptables_backend
  tor_user >/dev/null 2>&1 || die "tor user not found (install tor first)"
}

tor_user() {
  if id -u debian-tor >/dev/null 2>&1; then
    printf "debian-tor"
  elif id -u tor >/dev/null 2>&1; then
    printf "tor"
  else
    die "tor user not found (install tor first)"
  fi
}

detect_tor_unit() {
  if systemctl list-unit-files --type=service | grep -q '^tor@default.service'; then
    TOR_UNIT="tor@default"
  elif systemctl list-unit-files --type=service | grep -q '^tor.service'; then
    TOR_UNIT="tor"
  else
    TOR_UNIT="tor"
  fi
}

ensure_state_dir() {
  mkdir -p "$STATE_DIR"
  chmod 700 "$STATE_DIR"
}

backup_resolv_conf() {
  if [ ! -e "$RESOLV_BAK" ]; then
    cp -a /etc/resolv.conf "$RESOLV_BAK"
    if [ -L /etc/resolv.conf ]; then
      readlink -f /etc/resolv.conf > "$RESOLV_LINK_BAK" || true
    fi
  fi
  if systemctl is-active --quiet systemd-resolved; then
    # Keep systemd-resolved's stub; DNS will be redirected to Tor by iptables.
    return 0
  fi
  printf "nameserver 127.0.0.1\n" > /etc/resolv.conf
  chmod 644 /etc/resolv.conf
}

restore_resolv_conf() {
  if systemctl is-active --quiet systemd-resolved; then
    ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
    return
  fi
  if [ -s "$RESOLV_LINK_BAK" ]; then
    local target
    target="$(cat "$RESOLV_LINK_BAK" 2>/dev/null || true)"
    if [ -n "$target" ]; then
      ln -sf "$target" /etc/resolv.conf
      return
    fi
  fi
  if [ -e "$RESOLV_BAK" ]; then
    cp -a "$RESOLV_BAK" /etc/resolv.conf
  fi
}

ensure_torrc() {
  if [ ! -e "$TORRC" ]; then
    touch "$TORRC"
  fi
  if [ ! -e "$TORRC_BAK" ]; then
    cp -a "$TORRC" "$TORRC_BAK"
  fi
  sed -i "/# BEGIN ${APP_NAME^^}/,/# END ${APP_NAME^^}/d" "$TORRC"
  {
    printf "# BEGIN %s\n" "${APP_NAME^^}"
    printf "VirtualAddrNetworkIPv4 %s\n" "$TOR_VADDR"
    printf "AutomapHostsOnResolve 1\n"
    printf "TransPort %s\n" "$TOR_TRANS_PORT"
    printf "DNSPort %s\n" "$TOR_DNS_PORT"
    printf "ControlPort %s\n" "$TOR_CTRL_PORT"
    printf "CookieAuthentication 1\n"
    if [ -n "$TOR_EXIT_NODES" ]; then
      printf "ExitNodes %s\n" "$TOR_EXIT_NODES"
      if [ "$TOR_STRICT_NODES" -eq 1 ]; then
        printf "StrictNodes 1\n"
      fi
    fi
    if [ -n "$TOR_NEW_CIRCUIT_PERIOD" ]; then
      printf "NewCircuitPeriod %s\n" "$TOR_NEW_CIRCUIT_PERIOD"
    fi
    if [ -n "$TOR_MAX_DIRTINESS" ]; then
      printf "MaxCircuitDirtiness %s\n" "$TOR_MAX_DIRTINESS"
    fi
    printf "# END %s\n" "${APP_NAME^^}"
  } >> "$TORRC"
  TORRC_MODIFIED=1
}

restore_torrc() {
  if [ -e "$TORRC_BAK" ]; then
    cp -a "$TORRC_BAK" "$TORRC"
  fi
}

strip_torrc_block() {
  if [ -e "$TORRC" ]; then
    sed -i "/# BEGIN ${APP_NAME^^}/,/# END ${APP_NAME^^}/d" "$TORRC"
  fi
}

clear_state() {
  rm -f "$IPTABLES_BAK" "$IP6TABLES_BAK" "$RESOLV_BAK" "$RESOLV_LINK_BAK" "$TORRC_BAK" "$TOR_WAS_ACTIVE"
}

save_iptables() {
  iptables-save > "$IPTABLES_BAK"
  if command -v ip6tables-save >/dev/null 2>&1; then
    ip6tables-save > "$IP6TABLES_BAK" || true
  fi
}

apply_iptables() {
  local tor_uid
  tor_uid="$(tor_user)"

  iptables -F
  iptables -t nat -F
  iptables -t nat -X
  iptables -X

  iptables -P INPUT ACCEPT
  iptables -P FORWARD ACCEPT
  iptables -P OUTPUT ACCEPT

  iptables -A INPUT -i lo -j ACCEPT
  iptables -A OUTPUT -o lo -j ACCEPT

  iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

  # Allow DHCP (needed for lease renewals)
  iptables -A OUTPUT -p udp --sport 68 --dport 67 -j ACCEPT
  iptables -A INPUT -p udp --sport 67 --dport 68 -j ACCEPT

  iptables -A OUTPUT -m owner --uid-owner "$tor_uid" -j ACCEPT

  iptables -t nat -A OUTPUT -m owner --uid-owner "$tor_uid" -j RETURN
  iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports "$TOR_DNS_PORT"
  iptables -t nat -A OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports "$TOR_DNS_PORT"
  iptables -t nat -A OUTPUT -p tcp -d "$TOR_VADDR" -j REDIRECT --to-ports "$TOR_TRANS_PORT"
  iptables -t nat -A OUTPUT -p udp -d "$TOR_VADDR" -j REDIRECT --to-ports "$TOR_TRANS_PORT"

  for NET in $TOR_EXCLUDE 127.0.0.0/8 127.128.0.0/10; do
    iptables -t nat -A OUTPUT -d "$NET" -j RETURN
  done

  iptables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports "$TOR_TRANS_PORT"

  for NET in $TOR_EXCLUDE 127.0.0.0/8; do
    iptables -A OUTPUT -d "$NET" -j ACCEPT
  done

  iptables -A OUTPUT -j REJECT --reject-with icmp-port-unreachable

  if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -F || true
    ip6tables -X || true
    ip6tables -P INPUT ACCEPT || true
    ip6tables -P FORWARD ACCEPT || true
    ip6tables -P OUTPUT ACCEPT || true
    ip6tables -A INPUT -i lo -j ACCEPT || true
    ip6tables -A OUTPUT -o lo -j ACCEPT || true
    ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || true
    ip6tables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || true
    ip6tables -A OUTPUT -j REJECT --reject-with icmp6-adm-prohibited || true
  fi
}

restore_iptables() {
  if [ -e "$IPTABLES_BAK" ]; then
    iptables-restore < "$IPTABLES_BAK"
  fi
  if [ -e "$IP6TABLES_BAK" ] && command -v ip6tables-restore >/dev/null 2>&1; then
    ip6tables-restore < "$IP6TABLES_BAK" || true
  fi
}

tor_start() {
  detect_tor_unit
  systemctl start "$TOR_UNIT"
}

tor_is_active() {
  detect_tor_unit
  systemctl is-active --quiet "$TOR_UNIT"
}

tor_stop() {
  detect_tor_unit
  systemctl stop "$TOR_UNIT"
}

tor_stop_if_needed() {
  if [ -e "$TOR_WAS_ACTIVE" ]; then
    if ! grep -q "active" "$TOR_WAS_ACTIVE"; then
      tor_stop || true
    fi
  fi
}

record_tor_state() {
  if tor_is_active; then
    printf "active\n" > "$TOR_WAS_ACTIVE"
  else
    printf "inactive\n" > "$TOR_WAS_ACTIVE"
  fi
}

tor_newnym() {
  local cookie_file auth_hex
  cookie_file=""
  for path in /run/tor/control.authcookie /var/run/tor/control.authcookie; do
    if [ -e "$path" ]; then
      cookie_file="$path"
      break
    fi
  done

  if [ -n "$cookie_file" ] && command -v xxd >/dev/null 2>&1 && command -v nc >/dev/null 2>&1; then
    auth_hex="$(xxd -p "$cookie_file" | tr -d '\n')"
    {
      printf 'AUTHENTICATE "%s"\r\n' "$auth_hex"
      printf 'SIGNAL NEWNYM\r\n'
      printf 'QUIT\r\n'
    } | nc 127.0.0.1 "$TOR_CTRL_PORT" >/dev/null 2>&1 && return 0
  fi

  return 1
}

wait_for_tor() {
  local i
  local check_cmd=""
  if command -v ss >/dev/null 2>&1; then
    check_cmd="ss"
  elif command -v netstat >/dev/null 2>&1; then
    check_cmd="netstat"
  else
    die "missing ss/netstat; install iproute2 or net-tools before start"
  fi
  for i in $(seq 1 10); do
    if tor_is_active; then
      if [ "$check_cmd" = "ss" ]; then
        if ss -ltnu | grep -q ":${TOR_DNS_PORT} " && ss -ltn | grep -q ":${TOR_TRANS_PORT} "; then
          return 0
        fi
      else
        if netstat -ltnu | grep -q ":${TOR_DNS_PORT} " && netstat -ltn | grep -q ":${TOR_TRANS_PORT} "; then
          return 0
        fi
      fi
    fi
    sleep 1
  done
  die "tor did not become ready (service: ${TOR_UNIT})"
}

status() {
  section "Status"
  detect_tor_unit
  if tor_is_active; then
    ok "tor: active (${TOR_UNIT})"
  else
    warn "tor: inactive (${TOR_UNIT})"
  fi
  if [ -e "$IPTABLES_BAK" ]; then
    ok "iptables backup: present"
  else
    warn "iptables backup: missing"
  fi

  if has_tor_nat_rules; then
    ok "tor NAT rules: present"
  else
    warn "tor NAT rules: missing"
  fi

  if has_tor_filter_rules; then
    ok "tor filter rules: present"
  else
    warn "tor filter rules: missing"
  fi

  if command -v ss >/dev/null 2>&1; then
    if ss -ltnu | grep -q ":${TOR_DNS_PORT} "; then
      ok "tor DNS port listening (${TOR_DNS_PORT})"
    else
      warn "tor DNS port not listening (${TOR_DNS_PORT})"
    fi
    if ss -ltn | grep -q ":${TOR_TRANS_PORT} "; then
      ok "tor TransPort listening (${TOR_TRANS_PORT})"
    else
      warn "tor TransPort not listening (${TOR_TRANS_PORT})"
    fi
  fi

  if command -v curl >/dev/null 2>&1 && command -v torsocks >/dev/null 2>&1; then
    local direct_ip tor_ip
    direct_ip="$(curl -s --max-time 3 https://api.ipify.org || true)"
    tor_ip="$(torsocks curl -s --max-time 6 https://api.ipify.org || true)"
    if [ -n "$direct_ip" ]; then
      ok "direct IP: ${direct_ip}"
    else
      warn "direct IP: unavailable"
    fi
    if [ -n "$tor_ip" ]; then
      ok "tor IP: ${tor_ip}"
    else
      warn "tor IP: unavailable"
    fi
    if [ -n "$direct_ip" ] && [ -n "$tor_ip" ]; then
      if [ "$direct_ip" = "$tor_ip" ]; then
        warn "Tor not enforced (direct == Tor IP)"
      else
        if has_tor_nat_rules && has_tor_filter_rules; then
          ok "system appears torified (iptables enforced)"
        else
          warn "Tor reachable via torsocks only (system not torified)"
        fi
      fi
    fi
  fi
}

doctor() {
  section "Doctor"
  status
  if [ -L /etc/resolv.conf ]; then
    ok "resolv.conf is symlink: $(readlink -f /etc/resolv.conf)"
  else
    warn "resolv.conf is not a symlink"
  fi
  if systemctl is-active --quiet systemd-resolved; then
    ok "systemd-resolved: active"
  else
    warn "systemd-resolved: inactive"
  fi
  if systemctl is-active --quiet NetworkManager; then
    ok "NetworkManager: active"
  else
    warn "NetworkManager: inactive"
  fi
}

start() {
  need_root
  section "Starting ${APP_NAME}"
  # If this fails, it’s not personal. Tor just ghosted your packets.
  preflight
  ensure_state_dir
  record_tor_state
  ensure_torrc
  local rollback=1
  trap 'if [ "$rollback" -eq 1 ]; then restore_iptables; restore_resolv_conf; if [ "$TORRC_MODIFIED" -eq 1 ]; then restore_torrc; fi; tor_stop_if_needed; fi' ERR

  if [ "$TORRC_MODIFIED" -eq 1 ]; then
    detect_tor_unit
    systemctl restart "$TOR_UNIT"
  else
    tor_start
  fi
  wait_for_tor
  if [ "$VERIFY_START" -eq 1 ]; then
    if ! verify_tor_connectivity; then
      warn "start aborted to avoid lockout (use --no-verify to force)"
      tor_stop_if_needed
      return 1
    fi
  fi
  backup_resolv_conf
  save_iptables
  apply_iptables

  rollback=0
  trap - ERR
  ok "tor routing enabled"
  status
}

stop() {
  need_root
  section "Stopping ${APP_NAME}"
  # Returning your network to normal, begrudgingly.
  restore_iptables
  restore_resolv_conf
  restore_torrc
  if [ "$FORCE_STOP" -eq 1 ]; then
    tor_stop || true
    strip_torrc_block
    clear_state
  else
    tor_stop_if_needed
  fi
  systemctl restart NetworkManager >/dev/null 2>&1 || true
  systemctl restart systemd-resolved >/dev/null 2>&1 || true
  if has_tor_nat_rules || has_tor_filter_rules; then
    warn "Tor rules still present after restore; applying panic fallback"
    panic
  else
    ok "tor routing disabled"
  fi
  status
}

reset() {
  need_root
  section "Resetting Tor identity"
  # Because nothing says “fresh start” like asking Tor nicely.
  if tor_newnym; then
    ok "tor identity refreshed"
  else
    warn "unable to signal NEWNYM (control port/cookie not available)"
    warn "no restart performed to avoid network disruption"
  fi
  status
}

panic() {
  need_root
  section "Panic: Unblock network"
  iptables -F || true
  iptables -t nat -F || true
  iptables -t mangle -F || true
  iptables -X || true
  iptables -P INPUT ACCEPT || true
  iptables -P FORWARD ACCEPT || true
  iptables -P OUTPUT ACCEPT || true
  if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -F || true
    ip6tables -X || true
    ip6tables -P INPUT ACCEPT || true
    ip6tables -P FORWARD ACCEPT || true
    ip6tables -P OUTPUT ACCEPT || true
  fi
  restore_resolv_conf
  systemctl restart NetworkManager >/dev/null 2>&1 || true
  systemctl restart systemd-resolved >/dev/null 2>&1 || true
  ok "network unblocked (panic)"
}

usage() {
  cat <<EOF
Usage: $0 start|stop|reset|status|panic
  start  - route all TCP/DNS through Tor (blocks other traffic)
  stop   - restore network settings
  reset  - request a new Tor identity
  status - show Tor + backup state
  panic  - unblock network without relying on backups
  doctor - run a detailed status check

Options:
  --force  (with stop) always stop Tor service
  --no-verify (with start) skip Tor connectivity check
  --streaming (with start) tune Tor for longer-lived circuits
  --best-exit (with start) let Tor pick the fastest/healthiest exit
  --exit=CC,CC (with start) prefer exit countries, e.g. --exit=US,DE
  --strict (with start) require exit nodes to match --exit
  --force-os (with start) run on non-Ubuntu/Pop distros
  --force-nft (with start) allow iptables-nft backend
  COLOR=0 disable colored output
EOF
}

parse_start_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --no-verify) VERIFY_START=0 ;;
      --streaming)
        TOR_STREAMING=1
        TOR_NEW_CIRCUIT_PERIOD=30
        TOR_MAX_DIRTINESS=3600
        ;;
      --best-exit|--auto-exit)
        AUTO_EXIT=1
        TOR_EXIT_NODES=""
        TOR_STRICT_NODES=0
        ;;
      --exit=*)
        TOR_EXIT_NODES="${1#--exit=}"
        TOR_EXIT_NODES="$(printf "%s" "$TOR_EXIT_NODES" | sed 's/,/},{/g')"
        TOR_EXIT_NODES="{${TOR_EXIT_NODES}}"
        ;;
      --exit)
        shift
        TOR_EXIT_NODES="${1:-}"
        TOR_EXIT_NODES="$(printf "%s" "$TOR_EXIT_NODES" | sed 's/,/},{/g')"
        TOR_EXIT_NODES="{${TOR_EXIT_NODES}}"
        ;;
      --strict) TOR_STRICT_NODES=1 ;;
      --force-os) FORCE_OS=1 ;;
      --force-nft) FORCE_NFT=1 ;;
      *) ;;
    esac
    shift
  done
}

parse_stop_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --force) FORCE_STOP=1 ;;
      *) ;;
    esac
    shift
  done
}

CMD="${1:-}"
shift || true
case "$CMD" in
  start) parse_start_args "$@"; start ;;
  stop) parse_stop_args "$@"; stop ;;
  reset) reset ;;
  status) status ;;
  panic) panic ;;
  doctor) doctor ;;
  *) usage; exit 1 ;;
esac
