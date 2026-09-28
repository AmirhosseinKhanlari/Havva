# iOS SSL Pinning and Client-Integrity Measurement Pipeline

Measures, at scale on non-jailbroken devices, how much of the iOS app ecosystem's
certificate pinning and client-side integrity defense actually holds against a
client-side attacker. Follow-up to the "Subscribe for Free" subscription paper.

Design spec: [docs/superpowers/specs/2026-09-27-ios-pinning-bypass-measurement-design.md](docs/superpowers/specs/2026-09-27-ios-pinning-bypass-measurement-design.md)

## The funnel

```
crawl -> acquire+decrypt (JB iPhone 8) -> static classify -> instrument+re-sign
-> dynamic test (non-JB iPhone XR, Proxyman MITM) -> escalate -> success oracle
-> attestation-enforcement test -> aggregate
```

Static analysis covers the whole corpus (prevalence). The dynamic bypass test
runs on the funnel subset. The attestation-enforcement test (the headline: how
many apps adopt App Attest vs actually enforce it) runs on an authenticated
sample.

## Layout

```
pipeline/
  config.py     # all machine-specific config via env / .env (nothing hardcoded)
  models.py     # enums + dataclasses: outcomes, crash classes, ladder, profile
  db.py         # SQLite backbone: schema, resumable tri-state work queues
  oracle.py     # success oracle (flow diff -> outcome label)   [tested]
  escalate.py   # crash triage + escalation planner              [tested]
  cli.py        # status / doctor entry points
tests/          # oracle, escalate, db
```

Modules landing next: `crawl.py`, `acquire.py`, `static_classify.py`,
`instrument.py`, `device.py`, `capture.py`, `attestation.py`, `aggregate.py`.

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env      # fill in device UDID/IP, SSH host, signing paths
python -m pipeline.cli doctor    # check tools and assets
python -m pipeline.cli status    # DB counts and readiness
```

## Testing

```bash
pytest -q          # or: python3 -c "..." standalone runner (see commit history)
```

## Ethics

Authorized measurement. Turnkey mass-exploitation tooling and per-app rules for
real apps are withheld; apps are not named; responsible disclosure applies.
Evasion is capped at measurement hygiene (avoid trivial detection, report the
residue), never an attempt to defeat enforced attestation. Test accounts are
researcher-owned. Decrypted binaries and captured traffic are gitignored and
never committed.
