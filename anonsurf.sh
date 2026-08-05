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
START_ROLLBACK_ACTIVE=0

# ── Color Palette ──────────────────────────────────────────────
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
  C_DIM='\033[2m'
  C_RESET='\033[0m'
  C_GRAY='\033[0;90m'
  C_DIM_CYAN='\033[0;36m'
  C_DIM_GREEN='\033[0;32m'
  C_DIM_RED='\033[0;31m'
  C_DIM_YELLOW='\033[0;33m'
  C_BG_RED='\033[1;97;41m'
  C_BG_GREEN='\033[1;97;42m'
  C_BG_CYAN='\033[1;97;46m'
else
  C_RED='' C_GREEN='' C_YELLOW='' C_BLUE='' C_CYAN='' C_MAGENTA=''
  C_WHITE='' C_BOLD='' C_DIM='' C_RESET='' C_GRAY=''
  C_DIM_CYAN='' C_DIM_GREEN='' C_DIM_RED='' C_DIM_YELLOW=''
  C_BG_RED='' C_BG_GREEN='' C_BG_CYAN=''
fi

# ── Output Helpers ─────────────────────────────────────────────
HR_W=58

hr_heavy() { printf " %b" "$C_CYAN"; printf '━%.0s' $(seq 1 $HR_W); printf "%b\n" "$C_RESET"; }
hr_light() { printf " %b" "$C_GRAY"; printf '─%.0s' $(seq 1 $HR_W); printf "%b\n" "$C_RESET"; }

ok()   { printf "  %b✔%b  %s\n" "$C_GREEN" "$C_RESET" "$1"; }
warn() { printf "  %b⚠%b  %b%s%b\n" "$C_YELLOW" "$C_RESET" "$C_DIM_YELLOW" "$1" "$C_RESET"; }
err()  { printf "  %b✖  %s%b\n" "$C_RED" "$1" "$C_RESET"; }
info() { printf "  %b●%b  %s\n" "$C_CYAN" "$C_RESET" "$1"; }
die()  { printf "\n %b FATAL %b %s\n\n" "$C_BG_RED" "$C_RESET" "$*" >&2; exit 1; }

section() {
  printf "\n  %b%s%b\n" "$C_BOLD" "$1" "$C_RESET"
  hr_light
}

# Badge renderer: badge "LABEL" "$COLOR"
badge() { printf "%b%-10s%b" "$2" "$1" "$C_RESET"; }

# Row renderer: status_row "Label" "badge" "badge_color" "detail"
status_row() {
  printf "  %-22s" "$1"
  badge "$2" "$3"
  printf "%b%s%b\n" "$C_GRAY" "$4" "$C_RESET"
}

# ── Banner ─────────────────────────────────────────────────────
print_banner() {
  printf "\n"
  hr_heavy
  printf "%b" "$C_CYAN"
  cat <<'EOF'
      _   _  _  ___  _  _  ___ _   _ ___ ___
     /_\ | \| |/ _ \| \| |/ __| | | | _ \ __|
    / _ \| .` | (_) | .` |\__ \ |_| |   / _|
   /_/ \_\_|\_|\___/|_|\_||___/\___/|_|_\_|
EOF
  printf "%b" "$C_RESET"
  printf "  %b LITE %b  %bTransparent Tor Proxy%b\n" "$C_BG_CYAN" "$C_RESET" "$C_DIM_CYAN" "$C_RESET"
  hr_heavy
}

# ── Spinner ────────────────────────────────────────────────────
spinner() {
  local pid=$1
  local delay=0.08
  local frames='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
  while kill -0 "$pid" 2>/dev/null; do
    local f=${frames#?}
    printf "%b%c%b " "$C_CYAN" "$frames" "$C_RESET"
    frames=$f${frames%"$f"}
    sleep $delay
    printf "\b\b"
  done
  printf "  \b\b"
}

# ── Core Checks ───────────────────────────────────────────────
has_tor_nat_rules() {
  nft list table inet anonsurf >/dev/null 2>&1
}

has_tor_filter_rules() {
  has_tor_nat_rules
}

check_tor_connectivity() {
  if ! command -v torsocks >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
    return 1
  fi
  torsocks curl -s --max-time 15 https://api.ipify.org >/dev/null 2>&1
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
      warn "Unsupported OS — continuing by request"
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
  local iface
  iface="$(get_default_interface)"
  if [ -z "$iface" ]; then
    warn "Could not detect default interface for DNS routing"
    return 0
  fi
  resolvectl dns "$iface" 127.0.0.1
  resolvectl domain "$iface" "~."
}

restore_resolv_conf() {
  local iface
  iface="$(get_default_interface)"
  if [ -z "$iface" ]; then
    return 0
  fi
  resolvectl revert "$iface" >/dev/null 2>&1 || true
  systemctl restart systemd-resolved >/dev/null 2>&1 || true
}

ensure_torrc() {
  if [ ! -e "$TORRC" ]; then
    touch "$TORRC"
  fi
  if [ ! -e "$TORRC_BAK" ]; then
    cp -a "$TORRC" "$TORRC_BAK"
  fi
  sed -i "/# BEGIN ${APP_NAME^^}/,/# END ${APP_NAME^^}/d" "$TORRC_BAK"
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
    printf "NumEntryGuards 3\n"
    printf "CircuitBuildTimeout 30\n"
    printf "LearnCircuitBuildTimeout 1\n"
    printf "MaxCircuitDirtiness 600\n"
    printf "KeepalivePeriod 60\n"
    printf "AvoidDiskWrites 1\n"
    printf "ClientUseIPv6 1\n"
    printf "ConnectionPadding 0\n"

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
    if grep -qx "active" "$TOR_WAS_ACTIVE"; then
      # Tor was running before anonsurf — reload config so it drops anonsurf settings
      detect_tor_unit
      systemctl reload-or-restart "$TOR_UNIT" >/dev/null 2>&1 || true
    else
      # Tor was NOT running before anonsurf — stop it entirely
      tor_stop || true
    fi
  else
    # No state file — stop Tor to be safe
    tor_stop || true
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
    # Hex auth must NOT be quoted — Tor control protocol requires bare hex
    local response
    response="$(printf 'AUTHENTICATE %s\r\nSIGNAL NEWNYM\r\nQUIT\r\n' "$auth_hex" \
      | nc -w 3 127.0.0.1 "$TOR_CTRL_PORT" 2>/dev/null)" || true
    if printf "%s" "$response" | grep -q "250"; then
      return 0
    fi
  fi

  return 1
}

tor_activate() {
  local cookie_file="" auth_hex response
  for path in /run/tor/control.authcookie /var/run/tor/control.authcookie; do
    if [ -r "$path" ]; then cookie_file="$path"; break; fi
  done
  if [ -n "$cookie_file" ] && command -v xxd >/dev/null 2>&1 && command -v nc >/dev/null 2>&1; then
    auth_hex="$(xxd -p "$cookie_file" 2>/dev/null | tr -d '\n')" || return 1
    [ -n "$auth_hex" ] || return 1
    response="$(printf 'AUTHENTICATE %s\r\nSIGNAL ACTIVE\r\nQUIT\r\n' "$auth_hex" \
      | nc -w 3 127.0.0.1 "$TOR_CTRL_PORT" 2>/dev/null)" || true
    if printf "%s" "$response" | grep -q '^250 OK' &&
      ! printf "%s" "$response" | grep -q '^5[0-9][0-9]'; then
      return 0
    fi
  fi
  return 1
}

tor_is_bootstrapped() {
  local cookie_file="" auth_hex response
  for path in /run/tor/control.authcookie /var/run/tor/control.authcookie; do
    if [ -r "$path" ]; then cookie_file="$path"; break; fi
  done
  if [ -n "$cookie_file" ] && command -v xxd >/dev/null 2>&1 && command -v nc >/dev/null 2>&1; then
    auth_hex="$(xxd -p "$cookie_file" 2>/dev/null | tr -d '\n')" || return 1
    [ -n "$auth_hex" ] || return 1
    response="$(printf 'AUTHENTICATE %s\r\nGETINFO status/bootstrap-phase\r\nQUIT\r\n' "$auth_hex" \
      | nc -w 2 127.0.0.1 "$TOR_CTRL_PORT" 2>/dev/null)" || true
    if printf "%s" "$response" | grep -q 'PROGRESS=100'; then
      return 0
    fi
  fi
  return 1
}

# ── Wait for Tor ───────────────────────────────────────────────
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

  # Phase 1: ports
  printf "  %b⟳%b  Waiting for Tor ports  " "$C_CYAN" "$C_RESET"

  (
    for i in $(seq 1 200); do
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
  local exit_code
  if wait $pid; then
    exit_code=0
  else
    exit_code=$?
  fi

  if [ $exit_code -ne 0 ]; then
    printf "\r  %b✖%b  Tor ports              %bTIMEOUT%b\n" "$C_RED" "$C_RESET" "$C_RED" "$C_RESET"
    die "tor did not become ready (service: ${TOR_UNIT})"
  fi
  printf "\r  %b✔%b  Tor ports                 %bLISTENING%b\n" "$C_GREEN" "$C_RESET" "$C_DIM_GREEN" "$C_RESET"

  # A dormant Tor client does not bootstrap until it sees client activity.
  tor_activate || true

  # Phase 2: bootstrap
  printf "  %b⟳%b  Bootstrapping circuits  " "$C_CYAN" "$C_RESET"

  (
    for i in $(seq 1 90); do
      if tor_is_bootstrapped; then
        exit 0
      fi
      sleep 0.5
    done
    exit 1
  ) &

  pid=$!
  spinner $pid
  if wait $pid; then
    exit_code=0
  else
    exit_code=$?
  fi

  if [ $exit_code -ne 0 ]; then
    printf "\r  %b⚠%b  Bootstrap                 %bTIMEOUT%b  %b(continuing)%b\n" "$C_YELLOW" "$C_RESET" "$C_DIM_YELLOW" "$C_RESET" "$C_GRAY" "$C_RESET"
  else
    printf "\r  %b✔%b  Bootstrap                 %bREADY%b\n" "$C_GREEN" "$C_RESET" "$C_DIM_GREEN" "$C_RESET"
  fi
}

# ══════════════════════════════════════════════════════════════
#  STATUS
# ══════════════════════════════════════════════════════════════
status() {
  print_banner

  # ── Service Status ─────────────────────────────────
  section "SERVICE STATUS"

  detect_tor_unit

  # Tor Engine
  if tor_is_active; then
    status_row "Tor Engine" "ACTIVE" "$C_GREEN" "$TOR_UNIT"
  else
    status_row "Tor Engine" "DOWN" "$C_DIM_RED" "$TOR_UNIT"
  fi

  # Transparent Proxy
  if has_tor_nat_rules; then
    status_row "Transparent Proxy" "ACTIVE" "$C_GREEN" "nftables"
  else
    status_row "Transparent Proxy" "INACTIVE" "$C_DIM_RED" "no rules loaded"
  fi

  # Ports
  if command -v ss >/dev/null 2>&1; then
    if ss -ltnu | grep -q ":${TOR_DNS_PORT} "; then
      status_row "DNS Port" "LISTEN" "$C_GREEN" ":${TOR_DNS_PORT}"
    else
      status_row "DNS Port" "CLOSED" "$C_DIM_RED" ":${TOR_DNS_PORT}"
    fi
    if ss -ltn | grep -q ":${TOR_TRANS_PORT} "; then
      status_row "TransPort" "LISTEN" "$C_GREEN" ":${TOR_TRANS_PORT}"
    else
      status_row "TransPort" "CLOSED" "$C_DIM_RED" ":${TOR_TRANS_PORT}"
    fi
  fi

  # Bootstrap
  if tor_is_active; then
    if tor_is_bootstrapped; then
      status_row "Bootstrap" "READY" "$C_GREEN" "100%"
    else
      status_row "Bootstrap" "BUILDING" "$C_DIM_YELLOW" "circuits in progress"
    fi
  else
    status_row "Bootstrap" "—" "$C_GRAY" ""
  fi

  # ── Network Identity ───────────────────────────────
  if command -v curl >/dev/null 2>&1 && command -v torsocks >/dev/null 2>&1; then
    section "NETWORK IDENTITY"

    printf "  %b⟳  Probing...%b" "$C_GRAY" "$C_RESET"

    local direct_ip tor_ip geo_json geo_city geo_country geo_org
    direct_ip="$(curl -s --max-time 3 -4 https://api.ipify.org 2>/dev/null || true)"
    tor_ip="$(torsocks curl -s --max-time 6 -4 https://api.ipify.org 2>/dev/null || true)"
    geo_json="$(torsocks curl -s --max-time 6 -4 https://ipinfo.io/json 2>/dev/null || true)"

    printf "\r              \r"

    geo_city="$(printf "%s" "$geo_json" | grep '"city"' | cut -d '"' -f 4 || true)"
    geo_country="$(printf "%s" "$geo_json" | grep '"country"' | cut -d '"' -f 4 || true)"
    geo_org="$(printf "%s" "$geo_json" | grep '"org"' | cut -d '"' -f 4 || true)"

    [ -z "$geo_city" ] || [ -z "$geo_country" ] && { geo_city="Unknown"; geo_country="??"; }
    [ -z "$geo_org" ] && geo_org="Unknown"

    # Real IP
    printf "  %-22s" "Real IP"
    if [ -n "$direct_ip" ]; then
      printf "%b%s%b\n" "$C_DIM_RED" "$direct_ip" "$C_RESET"
    else
      printf "%bunavailable%b\n" "$C_GRAY" "$C_RESET"
    fi

    # Tor Exit
    printf "  %-22s" "Tor Exit IP"
    if [ -n "$tor_ip" ]; then
      printf "%b%s%b\n" "$C_GREEN" "$tor_ip" "$C_RESET"
    else
      printf "%bunavailable%b\n" "$C_GRAY" "$C_RESET"
    fi

    # Location + Provider
    printf "  %-22s%b%s, %s%b\n" "Exit Location" "$C_MAGENTA" "$geo_city" "$geo_country" "$C_RESET"
    printf "  %-22s%b%.40s%b\n" "Exit Provider" "$C_GRAY" "$geo_org" "$C_RESET"

    # ── Verdict ──────────────────────────────────────
    printf "\n"
    hr_light
    if [ -n "$direct_ip" ] && [ -n "$tor_ip" ]; then
      if [ "$direct_ip" = "$tor_ip" ]; then
        printf "\n %b  ✖  COMPROMISED — Real IP exposed through Tor  %b\n\n" "$C_BG_RED" "$C_RESET"
      else
        if has_tor_nat_rules; then
          printf "\n %b  ✔  SYSTEM TORIFIED  %b  %bAll traffic routed through Tor%b\n\n" "$C_BG_GREEN" "$C_RESET" "$C_DIM_GREEN" "$C_RESET"
        else
          printf "\n"
          warn "Tor reachable but system is NOT globally torified"
          printf "\n"
        fi
      fi
    else
      printf "\n"
      warn "Could not determine full network identity"
      printf "\n"
    fi
  fi
}

# ══════════════════════════════════════════════════════════════
#  DOCTOR
# ══════════════════════════════════════════════════════════════
doctor() {
  status

  section "SYSTEM DIAGNOSTICS"

  # systemd-resolved
  printf "  %-22s" "systemd-resolved"
  if systemctl is-active --quiet systemd-resolved; then
    badge "ACTIVE" "$C_GREEN"
  else
    badge "DOWN" "$C_DIM_RED"
  fi
  printf "\n"

  # NetworkManager
  printf "  %-22s" "NetworkManager"
  if systemctl is-active --quiet NetworkManager; then
    badge "ACTIVE" "$C_GREEN"
  else
    badge "DOWN" "$C_DIM_RED"
  fi
  printf "\n"

  # Default interface
  local iface
  iface="$(get_default_interface)"
  printf "  %-22s" "Default Interface"
  if [ -n "$iface" ]; then
    badge "$iface" "$C_CYAN"
  else
    badge "NONE" "$C_DIM_RED"
  fi
  printf "\n"

  # State files
  printf "  %-22s" "State Directory"
  if [ -d "$STATE_DIR" ]; then
    badge "EXISTS" "$C_GREEN"
    printf "%b%s%b" "$C_GRAY" "$STATE_DIR" "$C_RESET"
  else
    badge "MISSING" "$C_DIM_YELLOW"
  fi
  printf "\n"

  printf "\n"
}

rollback_start() {
  if [ "$START_ROLLBACK_ACTIVE" -ne 1 ]; then
    return 0
  fi

  START_ROLLBACK_ACTIVE=0
  set +e
  restore_iptables
  restore_resolv_conf
  if [ "$TORRC_MODIFIED" -eq 1 ]; then
    restore_torrc
  fi
  tor_stop_if_needed
  clear_state
}

abort_start() {
  local exit_code="${1:-1}"
  trap - ERR INT TERM HUP
  rollback_start
  exit "$exit_code"
}

# ══════════════════════════════════════════════════════════════
#  START
# ══════════════════════════════════════════════════════════════
start() {
  need_root
  print_banner

  section "ENGAGING ANONSURF"

  printf "  %b[1/6]%b  %-34s" "$C_DIM_CYAN" "$C_RESET" "Preflight checks"
  preflight
  printf "%b✔%b\n" "$C_GREEN" "$C_RESET"

  printf "  %b[2/6]%b  %-34s" "$C_DIM_CYAN" "$C_RESET" "Preparing state"
  ensure_state_dir
  record_tor_state
  printf "%b✔%b\n" "$C_GREEN" "$C_RESET"

  START_ROLLBACK_ACTIVE=1
  trap 'abort_start $?' ERR
  trap 'abort_start 130' INT
  trap 'abort_start 143' TERM
  trap 'abort_start 129' HUP

  printf "  %b[3/6]%b  %-34s" "$C_DIM_CYAN" "$C_RESET" "Configuring Tor"
  ensure_torrc
  printf "%b✔%b\n" "$C_GREEN" "$C_RESET"

  printf "  %b[4/6]%b  %-34s" "$C_DIM_CYAN" "$C_RESET" "Starting Tor service"
  if [ "$TORRC_MODIFIED" -eq 1 ]; then
    detect_tor_unit
    systemctl restart "$TOR_UNIT"
  else
    tor_start
  fi
  printf "%b✔%b\n\n" "$C_GREEN" "$C_RESET"

  wait_for_tor

  if [ "$VERIFY_START" -eq 1 ]; then
    printf "\n  %b[5/6]%b  %-34s" "$C_DIM_CYAN" "$C_RESET" "Verifying connectivity"
    if ! check_tor_connectivity; then
      printf "%b✖%b\n" "$C_RED" "$C_RESET"
      warn "Start aborted to prevent lockout (use --no-verify to force)"
      abort_start 1
    fi
    printf "%b✔%b\n" "$C_GREEN" "$C_RESET"
  fi

  printf "  %b[6/6]%b  %-34s" "$C_DIM_CYAN" "$C_RESET" "Applying firewall rules"
  backup_resolv_conf
  apply_iptables
  printf "%b✔%b\n" "$C_GREEN" "$C_RESET"

  START_ROLLBACK_ACTIVE=0
  trap - ERR INT TERM HUP

  printf "\n"
  hr_light
  printf "\n %b  ✔  ANONSURF ENGAGED  %b  %bAll traffic now routed through Tor%b\n\n" "$C_BG_GREEN" "$C_RESET" "$C_DIM_GREEN" "$C_RESET"
}

# ══════════════════════════════════════════════════════════════
#  STOP
# ══════════════════════════════════════════════════════════════
stop() {
  need_root
  print_banner

  section "DISENGAGING ANONSURF"

  printf "  %b[1/4]%b  %-34s" "$C_DIM_CYAN" "$C_RESET" "Removing firewall rules"
  restore_iptables
  printf "%b✔%b\n" "$C_GREEN" "$C_RESET"

  printf "  %b[2/4]%b  %-34s" "$C_DIM_CYAN" "$C_RESET" "Restoring DNS"
  restore_resolv_conf
  printf "%b✔%b\n" "$C_GREEN" "$C_RESET"

  printf "  %b[3/4]%b  %-34s" "$C_DIM_CYAN" "$C_RESET" "Restoring Tor config"
  restore_torrc
  printf "%b✔%b\n" "$C_GREEN" "$C_RESET"

  printf "  %b[4/4]%b  %-34s" "$C_DIM_CYAN" "$C_RESET" "Stopping Tor"
  if [ "$FORCE_STOP" -eq 1 ]; then
    tor_stop || true
    strip_torrc_block
    clear_state
  else
    tor_stop_if_needed
  fi
  printf "%b✔%b\n" "$C_GREEN" "$C_RESET"

  # Panic fallback if rules stuck
  if has_tor_nat_rules; then
    printf "\n"
    warn "Firewall rules stuck — applying panic fallback"
    panic_quiet
  fi

  # Post-stop verification
  sleep 0.5
  if command -v ss >/dev/null 2>&1; then
    if ss -ltn | grep -q ":${TOR_TRANS_PORT} " || ss -ltnu | grep -q ":${TOR_DNS_PORT} "; then
      printf "\n"
      warn "Tor still listening on anonsurf ports — forcing stop"
      detect_tor_unit
      systemctl stop "$TOR_UNIT" >/dev/null 2>&1 || true
      sleep 0.5
      if ss -ltn | grep -q ":${TOR_TRANS_PORT} "; then
        err "Port ${TOR_TRANS_PORT} still open — check manually"
      else
        ok "Tor fully stopped"
      fi
    fi
  fi
  clear_state

  printf "\n"
  hr_light
  printf "\n %b  ✔  ANONSURF DISENGAGED  %b  %bNormal network restored%b\n\n" "$C_BG_CYAN" "$C_RESET" "$C_DIM_CYAN" "$C_RESET"
}

# ══════════════════════════════════════════════════════════════
#  RESET
# ══════════════════════════════════════════════════════════════
reset() {
  need_root
  print_banner

  section "RESETTING IDENTITY"

  printf "  %b⟳%b  Requesting new circuit  " "$C_CYAN" "$C_RESET"

  if tor_newnym; then
    printf "\r  %b✔%b  New circuit              %bNEWNYM%b\n" "$C_GREEN" "$C_RESET" "$C_DIM_GREEN" "$C_RESET"
  else
    printf "\r  %b⚠%b  NEWNYM failed            %brestarting Tor%b\n" "$C_YELLOW" "$C_RESET" "$C_DIM_YELLOW" "$C_RESET"
    detect_tor_unit
    systemctl restart "$TOR_UNIT"
    wait_for_tor
    ok "Identity refreshed via restart"
  fi

  printf "\n"
  hr_light
  printf "\n %b  ✔  IDENTITY RESET  %b  %bNew Tor exit node active%b\n\n" "$C_BG_GREEN" "$C_RESET" "$C_DIM_GREEN" "$C_RESET"

  # Show new identity
  if command -v curl >/dev/null 2>&1 && command -v torsocks >/dev/null 2>&1; then
    printf "  %b⟳  Fetching new identity...%b" "$C_GRAY" "$C_RESET"
    local tor_ip geo_json geo_city geo_country
    tor_ip="$(torsocks curl -s --max-time 8 -4 https://api.ipify.org 2>/dev/null || true)"
    geo_json="$(torsocks curl -s --max-time 8 -4 https://ipinfo.io/json 2>/dev/null || true)"
    printf "\r                                \r"

    geo_city="$(printf "%s" "$geo_json" | grep '"city"' | cut -d '"' -f 4 || true)"
    geo_country="$(printf "%s" "$geo_json" | grep '"country"' | cut -d '"' -f 4 || true)"
    [ -z "$geo_city" ] && geo_city="Unknown"
    [ -z "$geo_country" ] && geo_country="??"

    printf "  %-22s%b%s%b\n" "New Exit IP" "$C_GREEN" "${tor_ip:-unavailable}" "$C_RESET"
    printf "  %-22s%b%s, %s%b\n\n" "New Location" "$C_MAGENTA" "$geo_city" "$geo_country" "$C_RESET"
  fi
}

# ══════════════════════════════════════════════════════════════
#  PANIC
# ══════════════════════════════════════════════════════════════
panic_quiet() {
  nft delete table inet anonsurf >/dev/null 2>&1 || true
  restore_resolv_conf
}

panic() {
  need_root
  printf "\n"
  printf " %b  ⚠  PANIC MODE  %b\n" "$C_BG_RED" "$C_RESET"
  hr_light

  printf "  %-34s" "Clearing nftables rules"
  nft delete table inet anonsurf >/dev/null 2>&1 || true
  printf "%b✔%b\n" "$C_GREEN" "$C_RESET"

  printf "  %-34s" "Restoring DNS"
  restore_resolv_conf
  printf "%b✔%b\n" "$C_GREEN" "$C_RESET"

  printf "\n"
  hr_light
  printf "\n %b  ✔  NETWORK UNBLOCKED  %b  %bPanic recovery complete%b\n\n" "$C_BG_CYAN" "$C_RESET" "$C_DIM_CYAN" "$C_RESET"
}

# ══════════════════════════════════════════════════════════════
#  USAGE
# ══════════════════════════════════════════════════════════════
usage() {
  print_banner
  printf "\n  %bUSAGE%b\n" "$C_BOLD" "$C_RESET"
  hr_light
  printf "  %banonsurf%b %b<command>%b %b[options]%b\n" "$C_CYAN" "$C_RESET" "$C_WHITE" "$C_RESET" "$C_GRAY" "$C_RESET"

  printf "\n  %bCOMMANDS%b\n" "$C_BOLD" "$C_RESET"
  printf "    %b%-14s%b%s\n" "$C_GREEN"   "start"   "$C_RESET" "Route all TCP/DNS through Tor"
  printf "    %b%-14s%b%s\n" "$C_RED"     "stop"    "$C_RESET" "Restore normal network settings"
  printf "    %b%-14s%b%s\n" "$C_YELLOW"  "reset"   "$C_RESET" "Request a new Tor identity"
  printf "    %b%-14s%b%s\n" "$C_CYAN"    "status"  "$C_RESET" "Show current Tor and network state"
  printf "    %b%-14s%b%s\n" "$C_MAGENTA" "panic"   "$C_RESET" "Emergency network unblock"
  printf "    %b%-14s%b%s\n" "$C_BLUE"    "doctor"  "$C_RESET" "Detailed system diagnostics"

  printf "\n  %bSTART OPTIONS%b\n" "$C_BOLD" "$C_RESET"
  printf "    %b--no-verify%b         Skip Tor connectivity check\n" "$C_WHITE" "$C_RESET"
  printf "    %b--streaming%b         Tune for longer-lived circuits\n" "$C_WHITE" "$C_RESET"
  printf "    %b--best-exit%b         Auto-pick fastest exit node\n" "$C_WHITE" "$C_RESET"
  printf "    %b--exit=%bCC,CC%b        Prefer exit countries %b(e.g. US,DE)%b\n" "$C_WHITE" "$C_GREEN" "$C_RESET" "$C_GRAY" "$C_RESET"
  printf "    %b--strict%b            Require exit nodes to match --exit\n" "$C_WHITE" "$C_RESET"
  printf "    %b--force-os%b          Run on non-Ubuntu/Pop distros\n" "$C_WHITE" "$C_RESET"

  printf "\n  %bSTOP OPTIONS%b\n" "$C_BOLD" "$C_RESET"
  printf "    %b--force%b             Always kill Tor service\n" "$C_WHITE" "$C_RESET"

  printf "\n  %bGLOBAL%b\n" "$C_BOLD" "$C_RESET"
  printf "    %bCOLOR=0%b            Disable colored output\n" "$C_WHITE" "$C_RESET"
  printf "\n"
}

# ── Arg Parsing ────────────────────────────────────────────────
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

# ── Main ───────────────────────────────────────────────────────
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
