# Threat Model / Scope

SOC Navigator has two modes with genuinely different threat models. They are never blended in the
UI (a persistent badge says which one you're looking at), and this doc covers them separately.

## Attack Lab (synthetic) — educational simulation

An educational, portfolio-scale simulation of a SOC investigation workflow: how raw telemetry
becomes a prioritized, explainable incident. Meant to demonstrate understanding of SOC operations,
detection engineering concepts, and how AI fits responsibly into that workflow — not to be a
production detection product.

**What this is not:**
- **Not a live security tool.** It does not connect to any real EDR, identity provider, SIEM, or
  cloud environment. It does not collect, store, or process real telemetry.
- **Not an offensive tool.** There is no exploit code, credential attack, or payload generation
  anywhere in this repo. All "attacks" in Attack Lab are pre-written synthetic JSON event data, not
  live actions against any system.
- **Not a source of real detection coverage.** The 10 Sigma-style rules in `detections/sigma/` are
  illustrative and written against synthetic field names — they are not validated against real
  Windows/EDR log schemas and should not be deployed to a production SIEM as-is.

**Data:** all telemetry in `app/data/telemetry/*.json` is fabricated: fictional usernames
(`@acme.com`), fictional hostnames, fictional IP addresses. No real organization, customer, or
individual is represented. There is no ingestion path for real data into this part of the app —
telemetry is loaded from static JSON files bundled in the repo.

**If extended toward real validation:** the roadmap in the main README mentions
[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) as a future direction: running
Atomic's structured, ATT&CK-mapped tests against an isolated, disposable lab VM to confirm the
Sigma rules actually fire against real telemetry. That would remain strictly a *defensive
validation* exercise run only in an authorized, isolated test environment — never against
production systems or third-party infrastructure.

## My Network (live) — a real, narrowly-scoped scanner

This is the one part of the app that performs a genuine action against a real network: device
discovery (ICMP ping sweep) and a TCP connect scan of a small, curated port list, against whatever
subnet the machine running the app is on. See `app/live/scanner.py`.

**Authorization boundary:** this tool is intended for scanning a network you own or are otherwise
authorized to test — a home network, a personal lab. It is not intended for, and should not be
used for, scanning networks you don't control.

**Technical safety boundary, enforced in code, not just policy:**
- `validate_subnet()` in `app/live/scanner.py` rejects anything that isn't a private (RFC1918) or
  link-local address range, and rejects anything larger than a /24 — checked on every call,
  independent of what a client requests. The scan target can never be a public IP range.
- Device discovery is a plain ICMP ping via the system `ping` binary — no raw sockets, no crafted
  packets, no elevated privileges.
- Port scanning is a TCP connect scan (`connect()`, not a SYN scan) against ~30 named ports, not a
  full port sweep. No authentication is attempted against any discovered service — only whether a
  connection succeeds, plus an optional passive read of whatever banner the service offers
  unprompted.
- No exploitation, credential brute-forcing, or payload delivery of any kind.

**What it can tell you:** real, accurate device and port inventory for your own local network —
useful for "what's actually on my Wi-Fi" and "did I leave something reachable that I didn't mean
to." Findings are genuinely actionable (e.g. "Telnet is open on 192.168.1.10") because they're
real.

**What it can't tell you:** anything at the process/endpoint level — command lines, credential
theft, malware execution. That requires OS-level instrumentation (Sysmon, an EDR agent, auditd)
running *on* each device, which this project does not and cannot provide from a network vantage
point alone. This is why live findings are never mapped to a MITRE ATT&CK technique — an open port
is an exposure fact, not an observed attack technique, and the UI says so explicitly rather than
forcing a mapping that wouldn't be honest.

**Data:** scan results (devices, open ports, derived incidents) live only in server memory for the
running process — nothing is written to disk, and everything is discarded on restart. The app has
no authentication of its own, so if it's bound to a LAN interface (see the README's "Testing it
from other devices on your network" section), anyone with the URL on that network can trigger a
scan and view results.
