# anonsurf-lite (Pop!/Ubuntu)

This script routes system TCP/DNS traffic through Tor using iptables on Pop!/Ubuntu.
It is intended for **Ubuntu/Pop!_OS** only, and includes safety checks to avoid lockouts.
Think of it as a putting a blanket on when you think theres a monster under the bed 
im watching u CIA!!

This is **not** the original AnonSurf. It’s a copycat inspired by Parrot OS’s AnonSurf because I love it and can’t live without it.
Yes, I said copycat. If you want the “official” experience, go to Parrot.

## Features
- Start/stop/reset/status/doctor + panic recovery
- Safe start with Tor connectivity verification
- Optional streaming mode with longer-lived circuits
- Optional exit country selection
- Colored status output
 - Refuses to pretend Tor is fast. It’s not.

## Requirements
- Tor installed and enabled (service `tor` or `tor@default`)
- `iptables`, `iptables-save`, `iptables-restore`
- `systemctl`
- `curl`, `torsocks` (for connectivity checks)

## Install
```
sudo install -m 755 ./anonsurf.sh /usr/local/bin/anonsurf
```

## Usage
```
sudo anonsurf start
sudo anonsurf stop
sudo anonsurf reset
sudo anonsurf status
sudo anonsurf doctor
sudo anonsurf panic
```

## Options
- `--no-verify` (start): skip Tor connectivity check
- `--streaming` (start): tune for longer-lived circuits
- `--best-exit` (start): let Tor select the fastest/healthiest exit
- `--exit=US,DE` (start): prefer exit countries
- `--strict` (start): require exit nodes to match `--exit`
- `--force-os` (start): run on non-Ubuntu/Pop
- `--force-nft` (start): allow iptables-nft backend
- `--force` (stop): always stop Tor service
- `COLOR=0`: disable colored output

## Notes
- Tor is **TCP-only**. UDP is blocked (except DNS/DHCP) to avoid leaks.
- Streaming through Tor can be slow by design. If you want 4K, you want a CDN, not Tor.
- `--strict` can reduce reliability if exits are scarce. Strict is a way to show ppl that your white..
 - If you break your internet, that’s why there’s a `panic` command. You’re welcome.

## Recovery
If you lose connectivity:
```
sudo anonsurf panic
```
If that doesn’t help, take a breath, open and close your wifi itll come back to normal 

## Sharing
This script is suitable **Pop!/Ubuntu**. i think... 
add nftables support and distro-specific checks bcs im lazy.
In other words: it’s not “one script to rule them all,” it’s “one glock to keep the hood safe <3
