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
  config.py         # all machine-specific config via env / .env (nothing hardcoded)
  models.py         # enums + dataclasses: outcomes, crash classes, ladder, profile
  db.py             # SQLite backbone: schema, resumable tri-state work queues [tested]
  util.py           # subprocess runner + logging
  oracle.py         # success oracle (flow diff -> outcome label)               [tested]
  escalate.py       # crash triage + escalation planner                         [tested]
  crawl.py          # A: AppFigures ranks + iTunes RSS fallback + metadata enrich
  acquire.py        # B: download + FairPlay decrypt (ipadecrypt / ipatool)
  static_classify.py# C: defense profile (pin layer/lib, TLS stack, attest, tamper) [tested]
  instrument.py     # D: re-sign + LIEF dylib injection (all bypass configs)
  device.py         # E: install/launch/drive (Appium + cold-launch) + crash pull
  capture.py        # 6: Proxyman control + header-aware HAR parsing            [tested]
  dynamic.py        # E/F/G: run the ladder, triage, decide outcome
  attestation.py    # H: attestation-enforcement differential test (headline)
  aggregate.py      # I: metrics + summary
  cli.py            # status / doctor / crawl / acquire / static / dynamic / attest / aggregate
tests/              # oracle, escalate, db, static, capture (40 tests)
scripts/            # attest_neutralize.js (Frida)
tweaks/EvasionKit/  # bounded detection-neutralization dylib (build with Theos)
tools/              # prebuilt ipadecrypt (gitignored)
```

## Running the pipeline

```bash
python3 -m pipeline.cli crawl                 # A: build the corpus
./tools/ipadecrypt bootstrap                 # one-time device setup
python3 -m pipeline.cli acquire               # B: download + decrypt
python3 -m pipeline.cli static                # C: classify defenses (prevalence)
python3 -m pipeline.cli dynamic               # E/F/G: run the bypass ladder
python3 -m pipeline.cli attest                # H: attestation-enforcement test
python3 -m pipeline.cli aggregate             # I: metrics -> results/summary.md
```

Every stage is resumable (tri-state work queue) and safe to re-run.

## EvasionKit (bounded detection-neutralization)

The `evasion` bypass rung uses `EvasionKit.dylib`, built from `tweaks/EvasionKit/`
with Theos + fishhook. Until built, that rung degrades gracefully (skipped). It
neutralizes only standard detectors (injected-image enumeration, ptrace/sysctl
anti-debug, csops signature flags), never enforced App Attest.

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env      # fill in device UDID/IP, SSH host, signing paths
python3 -m pipeline.cli doctor    # check tools and assets
python3 -m pipeline.cli status    # DB counts and readiness
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

## vphone MCP (iOS VM control)

`.mcp.json` registers the [vphone-mcp](https://github.com/pluginslab/vphone-mcp)
server (cloned in `tools/vphone-mcp`, gitignored), which lets an agent drive the
vphone iOS VM (tap, type, screenshot, read screen) over the VM's control socket.
Activate: restart Claude Code and approve the project MCP; it only works while a
vphone VM is running. Re-clone with `git clone https://github.com/pluginslab/vphone-mcp tools/vphone-mcp && (cd tools/vphone-mcp && uv sync)`.

## Havva (web UI)

A mobile-friendly web UI over the whole pipeline: run any stage or the full
funnel, watch live progress, browse results. The CLI keeps working exactly as
before; the console just calls the same pipeline functions.

```bash
# set a token first (in .env): WEB_AUTH_TOKEN=<long random string>
python3 -m pipeline.cli web          # or: python3 -m pipeline.web
# open http://<mac-ip>:8770 from your phone on the same network, then sign in
```

Config (in .env): WEB_AUTH_TOKEN, WEB_HOST (default 0.0.0.0), WEB_PORT
(default 8770), WEB_MAX_WORKERS (default 3).
