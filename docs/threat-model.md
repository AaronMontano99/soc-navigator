# Threat Model / Scope

## What this is

SOC Navigator is an educational, portfolio-scale simulation of a SOC investigation workflow: how
raw telemetry becomes a prioritized, explainable incident. It's meant to demonstrate understanding
of SOC operations, detection engineering concepts, and how AI fits responsibly into that workflow —
not to be a production detection product.

## What this is not

- **Not a live security tool.** It does not connect to any real EDR, identity provider, SIEM, or
  cloud environment. It does not collect, store, or process real telemetry of any kind.
- **Not an offensive tool.** There is no exploit code, scanning, credential attack, or payload
  generation anywhere in this repo. All "attacks" in Attack Story Mode are pre-written synthetic
  JSON event data, not live actions against any system.
- **Not a source of real detection coverage.** The 10 Sigma-style rules are illustrative and
  written against synthetic field names chosen for this project — they are not validated against
  real Windows/EDR log schemas and should not be deployed to a production SIEM as-is.

## Data

All telemetry in `app/data/telemetry/*.json` is fabricated for this project: fictional usernames
(`@acme.com`), fictional hostnames, and fictional IP addresses chosen to illustrate detection
logic. No real organization, customer, or individual is represented. There is no ingestion path
for real data in this codebase — telemetry is loaded from static JSON files bundled in the repo.

## If extended toward real validation

The roadmap in the main README mentions [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
as a future direction: running Atomic's structured, ATT&CK-mapped tests against an isolated,
disposable lab VM to confirm the Sigma rules in `detections/sigma/` actually fire against real
telemetry, not just synthetic JSON. That would remain strictly a *defensive validation* exercise
(confirming detections work) run only in an authorized, isolated test environment — never against
production systems or third-party infrastructure.
