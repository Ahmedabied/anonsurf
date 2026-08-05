# AnonSurf

**Transparent Tor proxy for Ubuntu and Pop!_OS.** One command puts every TCP connection
and every DNS lookup on the machine through Tor. One command puts it all back.

```bash
sudo anonsurf start
```

Think of it as putting a blanket on when you think there's a monster under the bed.
im watching u CIA!!

```
 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
      _   _  _  ___  _  _  ___ _   _ ___ ___
     /_\ | \| |/ _ \| \| |/ __| | | | _ \ __|
    / _ \| .` | (_) | .` |\__ \ |_| |   / _|
   /_/ \_\_|\_|\___/|_|\_||___/\___/|_|_\_|
   LITE   Transparent Tor Proxy
 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

This is **not** the original AnonSurf. It is my own build, inspired by Parrot OS's AnonSurf,
because I love that tool and can't live without it. If you want the official experience, go
to Parrot. This one is mine, it runs on Pop!, and I use it almost every day.

---

## Why you can point this at your own firewall

Writing iptables rules that hijack all your traffic is the easy part. Doing it without
bricking your box at 2am is the actual work. So:

- **Atomic start.** Hit Ctrl-C halfway through, or fail the Tor check, and it rolls back
  everything it touched: iptables, `resolv.conf`, `torrc`, and the Tor service goes back to
  exactly the state it was in before you ran it. No half-applied firewall. Ever.
- **It asks Tor if it is actually ready.** Authenticates to the control port with the auth
  cookie and reads `status/bootstrap-phase` until `PROGRESS=100`, instead of sleeping five
  seconds and hoping for the best. If Tor is installed but dormant, it wakes it up first.
- **Your LAN stays yours.** `192.168.0.0/16`, `172.16.0.0/12` and `10.0.0.0/8` are excluded,
  so your router, your SSH sessions and your printer keep working while everything else goes
  dark.
- **torrc is fenced and backed up.** Everything it adds lives between `# BEGIN ANONSURF-LITE`
  and `# END ANONSURF-LITE`, your original is saved under `/var/lib/anonsurf-lite`, and a
  stale backup left behind by an earlier crash gets sanitized first, so a restore can never
  paste my own block back on top of you.
- **`panic`** tears out every rule and hands your internet back, no questions asked.
- **`doctor`** tells you what is actually broken instead of making you guess.
- **It has tests.** Four of them, and they cover the parts that scare me: rollback on
  interrupt, bootstrap timeout surviving `set -e`, waking a dormant Tor, and the stale-backup
  trap.

```bash
bash tests/anonsurf_test.sh
```

---

## Install

```bash
git clone https://github.com/Ahmedabied/anonsurf.git
cd anonsurf
sudo install -m 755 ./anonsurf.sh /usr/local/bin/anonsurf
```

## Usage

```bash
sudo anonsurf start      # route all TCP and DNS through Tor
sudo anonsurf stop       # put the network back
sudo anonsurf reset      # new identity, new circuit
sudo anonsurf status     # what is on right now
sudo anonsurf doctor     # full diagnostics
sudo anonsurf panic      # emergency unblock
```

### Options

| Flag | Command | What it does |
|---|---|---|
| `--no-verify` | start | Skip the Tor connectivity check |
| `--streaming` | start | Longer-lived circuits, fewer rebuilds mid-stream |
| `--best-exit` | start | Let Tor pick the fastest healthy exit |
| `--exit=US,DE` | start | Prefer these exit countries |
| `--strict` | start | Refuse any exit outside `--exit` |
| `--force-os` | start | Run it on a distro I have not tested |
| `--force-nft` | start | Allow the iptables-nft backend |
| `--force` | stop | Always stop the Tor service on the way out |
| `COLOR=0` | any | Kill the colors |

---

## Under the hood

| Piece | Value |
|---|---|
| Tor TransPort | `9040` |
| Tor DNSPort | `9053` |
| Control port | `9051` |
| Virtual address range | `10.192.0.0/10` |
| State directory | `/var/lib/anonsurf-lite` |
| Excluded networks | `192.168.0.0/16`, `172.16.0.0/12`, `10.0.0.0/8` |

`start` does this in order, and unwinds all of it if any step fails: detect the Tor unit
(`tor` or `tor@default`), record whether Tor was already running, back up and fence `torrc`,
back up `resolv.conf`, apply the iptables NAT and filter rules, bring Tor up, wait for a real
bootstrap, then verify the circuit actually carries traffic.

982 lines of Bash, `set -euo pipefail`, nothing a normal Ubuntu box does not already have.

## Requirements

- Tor, installed and enabled (`tor` or `tor@default`)
- `iptables`, `iptables-save`, `iptables-restore`
- `systemctl`
- `curl` and `torsocks` for the connectivity checks
- `xxd` and `nc` for the control-port bootstrap check (optional, it degrades gracefully)

## Recovery

If you lose connectivity:

```bash
sudo anonsurf panic
```

If that does not help, take a breath, open and close your wifi, itll come back to normal.

## The honest notes

- Tor is **TCP only**. UDP is blocked, except DNS and DHCP, so nothing leaks around the side.
- It refuses to pretend Tor is fast. It is not. If you want 4K, you want a CDN, not Tor.
- `--strict` can leave you with no usable exit when exits are scarce. That is the trade.
- If you break your internet, that is why there is a `panic` command. You're welcome.
- Built and tested on Pop!_OS and Ubuntu. `--force-os` runs it anywhere else, but you are the
  QA team at that point.

It is not one script to rule them all. It is one glock to keep the hood safe. <3
