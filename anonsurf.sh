#!/usr/bin/env bash
set -euo pipefail

APP_NAME="anonsurf-lite"
STATE_DIR="/var/lib/${APP_NAME}"
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

COLOR=${COLOR:-1}
if [ "$COLOR" -eq 1 ]; then
  C_RED='\033[1;31m'
  C_GREEN='\033[1;32m'
  C_YELLOW='\033[1;33m'
  C_BLUE='\033[1;34m'
  C_CYAN='\033[1;36m'
  C_MAGENTA='\033[1;35m'
  C_WHITE='\033[1;37m'
  C_BOLD='\033[1m'
  C_RESET='\033[0m'
else
  C_RED=''
  C_GREEN=''
  C_YELLOW=''
  C_BLUE=''
  C_CYAN=''
  C_MAGENTA=''
  C_WHITE=''
  C_BOLD=''
  C_RESET=''
fi

log() { printf "%s\n" "$*"; }
say() { printf "%b%s%b\n" "$1" "$2" "$C_RESET"; }
section() { printf "\n%b▶ %s%b\n" "$C_CYAN$C_BOLD" "$1" "$C_RESET"; }
ok() { say "$C_GREEN" " ✔  $1"; }
warn() { say "$C_YELLOW" " ⚠  $1"; }
err() { say "$C_RED" " ✖  $1"; }
die() { printf "error: %s\n" "$*" >&2; exit 1; }

print_banner() {
  printf "\n%b" "$C_CYAN$C_BOLD"
  cat <<"EOF"
    ___                         _____urf 
   /   |  ____  ____  ____     / ___/__  ___________ 
  / /| | / __ \/ __ \/ __ \    \__ \/ / / / ___/ __ \
 / ___ |/ / / / /_/ / / / /   ___/ / /_/ / /  / /_/ /
/_/  |_/_/ /_/\____/_/ /_/   /____/\__,_/_/  / .___/ 
      Lite Edition ⚡                           /_/     
EOF
  printf "%b\n" "$C_RESET"
}

spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    while kill -0 "$pid" 2>/dev/null; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

has_tor_nat_rules() {
  nft list table inet anonsurf >/dev/null 2>&1
}

has_tor_filter_rules() {
  has_tor_nat_rules
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

preflight() {
  need_cmd nft
  need_cmd resolvectl
  need_cmd systemctl
  if ! is_supported_os; then
    if [ "$FORCE_OS" -eq 1 ]; then
      warn "unsupported OS detected; continuing by request"
    else
      die "unsupported OS (intended for Pop!/Ubuntu). Use --force-os to continue."
    fi
  fi
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

get_default_interface() {
  ip route show default | awk '/default/ {print $5}' | head -n 1
}

backup_resolv_conf() {
  # We use resolvectl now, no need to backup resolv.conf
  local iface
  iface="$(get_default_interface)"
  if [ -z "$iface" ]; then
    warn "could not detect default interface for DNS routing"
    return 0
  fi
  # Redirect DNS for the primary interface to Tor's DNS port
  resolvectl dns "$iface" 127.0.0.1
  resolvectl domain "$iface" "~."
}

restore_resolv_conf() {
  local iface
  iface="$(get_default_interface)"
  if [ -z "$iface" ]; then
    return 0
  fi
  # Revert to automatic DNS (usually provided by DHCP via NetworkManager)
  resolvectl revert "$iface" >/dev/null 2>&1 || true
  # Flush DNS cache by restarting systemd-resolved
  systemctl restart systemd-resolved >/dev/null 2>&1 || true
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
    
    # Speed Optimizations
    printf "UseEntryGuards 1\n"
    printf "NumEntryGuards 2\n"
    printf "CircuitBuildTimeout 10\n"
    printf "LearnCircuitBuildTimeout 1\n"
    printf "MaxCircuitDirtiness 600\n"

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
  rm -f "$TORRC_BAK" "$TOR_WAS_ACTIVE"
}

apply_iptables() {
  local tuid
  tuid="$(id -u "$(tor_user)")"
  
  # Clean old rules if they exist
  nft delete table inet anonsurf >/dev/null 2>&1 || true

  nft -f - << EOF2
table inet anonsurf {
    chain output_nat {
        type nat hook output priority filter; policy accept;

        # Redirect DNS
        udp dport 53 redirect to :$TOR_DNS_PORT
        tcp dport 53 redirect to :$TOR_DNS_PORT

        # Redirect Virtual Addresses (onion routed)
        ip daddr $TOR_VADDR tcp dport != 53 redirect to :$TOR_TRANS_PORT
        ip daddr $TOR_VADDR udp dport != 53 redirect to :$TOR_TRANS_PORT

        # Accept traffic from tor itself
        meta skuid $tuid accept

        # Exclude local networks
        ip daddr { 127.0.0.0/8, 127.128.0.0/10, 192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8 } accept

        # Redirect all other TCP to TransPort
        meta l4proto tcp redirect to :$TOR_TRANS_PORT
    }

    chain output_filter {
        type filter hook output priority filter; policy accept;

        # Allow loopback
        oifname "lo" accept

        # Allow established
        ct state established,related accept

        # Allow DHCP
        udp sport 68 udp dport 67 accept

        # Allow tor user
        meta skuid $tuid accept

        # Allow local networks
        ip daddr { 127.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8 } accept

        # Block all other (non-TCP, non-DNS) traffic e.g UDP leaks
        meta l4proto udp udp dport != 53 reject with icmp type port-unreachable
    }
}
EOF2
}

restore_iptables() {
  nft delete table inet anonsurf >/dev/null 2>&1 || true
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
  
  printf "%b ⟳  Building Tor circuits... %b" "$C_YELLOW" "$C_RESET"
  
  (
    for i in $(seq 1 150); do
      if tor_is_active; then
        if [ "$check_cmd" = "ss" ]; then
          if ss -ltnu | grep -q ":${TOR_DNS_PORT} " && ss -ltn | grep -q ":${TOR_TRANS_PORT} "; then
            exit 0
          fi
        else
          if netstat -ltnu | grep -q ":${TOR_DNS_PORT} " && netstat -ltn | grep -q ":${TOR_TRANS_PORT} "; then
            exit 0
          fi
        fi
      fi
      sleep 0.1
    done
    exit 1
  ) &
  
  local pid=$!
  spinner $pid
  wait $pid
  local exit_code=$?
  
  if [ $exit_code -ne 0 ]; then
    printf "\n"
    die "tor did not become ready (service: ${TOR_UNIT})"
  fi
  printf "\r%b ✔  Tor circuits established!       %b\n" "$C_GREEN" "$C_RESET"
}

status() {
  print_banner
  section "System Service Status"
  detect_tor_unit
  if tor_is_active; then
    ok "Tor Engine: Active (${TOR_UNIT})"
  else
    warn "Tor Engine: Inactive (${TOR_UNIT})"
  fi

  if has_tor_nat_rules; then
    ok "Transparent Proxy: Active (nftables)"
  else
    warn "Transparent Proxy: Inactive (nftables missing)"
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
    section "Network Identity"
    local direct_ip tor_ip geo_json geo_city geo_country geo_org
    
    printf "%b ⟳  Analyzing network streams... %b" "$C_CYAN" "$C_RESET"
    
    # Hide standard error to prevent UI breaking
    direct_ip="$(curl -s --max-time 3 -4 https://api.ipify.org 2>/dev/null || true)"
    tor_ip="$(torsocks curl -s --max-time 6 -4 https://api.ipify.org 2>/dev/null || true)"
    geo_json="$(torsocks curl -s --max-time 6 -4 https://ipinfo.io/json 2>/dev/null || true)"
    
    printf "\r                                  \r"
    
    # Parse JSON poorly via grep/sed (avoids jq dependency)
    geo_city="$(printf "%s" "$geo_json" | grep '"city"' | cut -d '"' -f 4 || true)"
    geo_country="$(printf "%s" "$geo_json" | grep '"country"' | cut -d '"' -f 4 || true)"
    geo_org="$(printf "%s" "$geo_json" | grep '"org"' | cut -d '"' -f 4 || true)"
    
    if [ -z "$geo_city" ] || [ -z "$geo_country" ]; then
      geo_city="Unknown"
      geo_country="Location"
    fi
    if [ -z "$geo_org" ]; then
      geo_org="Unknown ISP"
    fi

    printf " ╭───────────────────────────────────────────────────╮\n"
    printf " │ %b%-18s%b │ %-30s │\n" "$C_BOLD" "Real Interface" "$C_RESET" "${direct_ip:-Unavailable}"
    printf " ├────────────────────┼────────────────────────────────┤\n"
    printf " │ %b%-18s%b │ %b%-30s%b │\n" "$C_MAGENTA$C_BOLD" "Anonsurf Node" "$C_RESET" "$C_GREEN" "${tor_ip:-Unavailable}" "$C_RESET"
    printf " │ %b%-18s%b │ %-30s │\n" "$C_BOLD" "Exit Location" "$C_RESET" "${geo_city}, ${geo_country}"
    printf " │ %b%-18s%b │ %-30s │\n" "$C_BOLD" "Exit ISP" "$C_RESET" "$(printf "%.30s" "$geo_org")"
    printf " ╰───────────────────────────────────────────────────╯\n"

    if [ -n "$direct_ip" ] && [ -n "$tor_ip" ]; then
      if [ "$direct_ip" = "$tor_ip" ]; then
        err "SYSTEM COMPROMISED: Tor is not enforcing routing! (Direct IP = Tor IP)"
      else
        if has_tor_nat_rules; then
          printf "\n%b [✔] SYSTEM IS SECURED AND TORIFIED %b\n\n" "$C_GREEN$C_BOLD" "$C_RESET"
        else
          warn "Tor is reachable but global system is NOT torified."
        fi
      fi
    else
      warn "Unable to fetch complete network identity."
    fi
  fi
}

doctor() {
  section "Doctor"
  status
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
  print_banner
  section "Engaging Anonsurf..."
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
  apply_iptables

  rollback=0
  trap - ERR
  ok "tor routing enabled via nftables"
  status
}

stop() {
  need_root
  print_banner
  section "Disengaging Anonsurf..."
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
  if has_tor_nat_rules; then
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
  nft delete table inet anonsurf >/dev/null 2>&1 || true
  restore_resolv_conf
  # No longer restarting NM during panic!
  ok "network unblocked (panic) - nftables cleared"
}

usage() {
  cat <<EOF2
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
  COLOR=0 disable colored output
EOF2
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
