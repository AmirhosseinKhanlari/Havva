# iOS Security Suite Web UI — Design Spec

Date: 2026-09-29
Working name: **Satella Console**
Status: Approved (pending spec review)

## Goal

A mobile-friendly web UI over the existing iOS pinning/attestation measurement
pipeline. It must let the researcher run any stage separately or the full funnel,
watch live progress, browse and search the corpus and all results, and perform
MobSF-style deep static analysis per app — a fuller iOS mobile-security suite than
MobSF, built on the pipeline that already exists.

## Hard constraints

1. **Do not break anything.** The existing `pipeline/` package and its CLI
   (`python3 -m pipeline.cli …`) must keep working exactly as they do today.
2. **CLI parity.** Every capability in the web UI must also be runnable from the
   command line. The web layer is a *thin skin* that calls the same pipeline
   functions the CLI calls; it never reimplements pipeline logic. The one new
   capability (deep analysis) is added to BOTH the web UI and the CLI (a new
   `analyze` subcommand).
3. **Single source of truth.** Web and CLI call identical underlying functions
   (`acquire.acquire_one`, `static_classify.run`, `dynamic.run`,
   `attestation.run`, `appstore_dl.*`, the new `analysis.analyze_one`, etc.), so
   the two front-ends can never drift.

## Decisions (from brainstorming)

- **Scope (v1):** control panel + report viewer + new MobSF-style deep analysis.
- **Access:** LAN-bound (`0.0.0.0`) with a single shared-token login. Mobile-first
  because the researcher will use it from a phone.
- **Stack:** FastAPI + Jinja2 + HTMX + Tailwind. Server-rendered partials, SSE for
  live progress. No JS build step.
- **Jobs:** in-process background worker pool + SQLite `jobs` table, limited
  concurrency, device-bound stages serialized. No Redis/Celery.

## Architecture

```
Browser (phone/desktop) — HTMX + Tailwind, server-rendered
        │  HTTP + SSE (live progress)
        ▼
FastAPI app  (pipeline/web/)
  ├── __main__.py   launches uvicorn (python3 -m pipeline.web)
  ├── app.py        FastAPI instance, middleware, static, templates
  ├── auth.py       single-token login -> signed httpOnly cookie
  ├── jobs.py       worker pool + jobs table + per-job log stream (SSE)
  ├── analysis.py   NEW deep-analysis engine (also used by the CLI)
  ├── routers/
  │     dashboard.py corpus.py app_detail.py acquire.py analyze.py
  │     dynamic.py attest.py jobs.py settings.py
  └── templates/    Jinja2 base + HTMX partials
        │
        ▼
existing pipeline/  (acquire, static_classify, dynamic, attestation,
                     appstore_dl, iap, aggregate, crawl, db, device, …)  ← unchanged
        │
        ▼
SQLite (pinning.db) + ipas/ + work/ + results/
```

Properties:
- Web actions map 1:1 to existing pipeline functions or the new `analyze_one`.
- Background jobs: a `ThreadPoolExecutor` (default width 3) for non-device jobs,
  plus a **single device lock** shared by decrypt / dynamic / attest so the
  physical iPhone 8 and XR are never double-driven.
- Live progress: each job tees stdout/stderr and `run_cmd_streamed` output into a
  per-job log buffer (in-memory ring + DB); the browser subscribes to
  `/jobs/{id}/stream` (SSE) and sees the same output as the terminal (tqdm
  download %, ipadecrypt steps).

## Screens

Bottom tab bar on mobile, left sidebar on desktop. Destructive/outward actions
confirm first.

1. **Dashboard** — funnel counts (corpus → acquired → static → pinned →
   attest-adopted → tested), counts by category, running jobs, `doctor` health
   (devices reachable, iTunes server up, signing assets, dylibs). One-tap "run
   full pipeline" + per-stage buttons.
2. **Corpus** — searchable/filterable app table (name, bundle, category, pinned?,
   attest?, acquired?). Row → App detail. Bulk-select → acquire/analyze selected.
   Crawl controls (category, count, source) live here.
3. **App detail** — tabs:
   - *Overview*: metadata, icon, version, IAP, status.
   - *Acquire*: download+decrypt; list versions + pick an old build; download the
     decrypted IPA.
   - *Static / Deep analysis*: pinning verdict (layer/library), TLS stack,
     App Attest/DeviceCheck flags, anti-tamper/debug/jailbreak; entitlements,
     Info.plist, ATS config, frameworks & dylibs inventory + SDK fingerprints,
     secrets/URLs/strings scan, in-IPA file browser.
   - *Dynamic*: bypass-ladder runs, per-config outcome, crash triage, captured
     hosts (device required).
   - *Attestation*: enforcement probe verdicts (device + accounts required).
4. **Jobs** — queue + history, live per-job log, cancel, re-run.
5. **Settings** — view/edit `.env`-backed config (acquire mode, iTunes server,
   device UDID/IP, paths), run `doctor`, device-pair helper. Secrets masked.

Every stage is runnable standalone (per-app buttons + a stage batch page) and
chained (Dashboard "full pipeline"). All rendered as HTMX partials.

## Deep-analysis engine (`pipeline/analysis.py`)

Runs over a **decrypted** IPA, offline on the Mac, producing a rich per-app
report persisted to a new `analysis` table (+ cached JSON). Extends, does not
replace, `static_classify` (the pinning/attest classifier stays authoritative for
the funnel).

Extractors (each an isolated, independently testable function returning a typed
dataclass; one failing extractor never sinks the report):
- **Bundle metadata** — Info.plist pretty-render, `CFBundle*`, min iOS, URL
  schemes, background modes, permission usage strings.
- **Entitlements** — from main binary + appex targets (`codesign -d
  --entitlements` / LIEF); interesting ones flagged (App Attest env, keychain
  groups, associated domains, HealthKit).
- **ATS** — `NSAppTransportSecurity` parsed to a readable table (arbitrary loads,
  per-domain exceptions, `NSPinnedDomains`).
- **Frameworks & dylibs inventory** — embedded `.framework`/`.dylib`, linked libs
  (`otool -L`), and SDK fingerprinting (Firebase, Alamofire, TrustKit, Branch,
  Facebook…), doubling as third-party-SDK prevalence data.
- **Secrets / URLs / strings scan** — regex sweep over binary + resources for API
  keys, tokens, endpoints, base URLs, S3 buckets, hardcoded IPs; grouped and
  severity-tagged. Findings only, no exploitation.
- **File tree** — browsable IPA contents with sizes; view text/plist inline.
- **Crypto/API usage hints** — presence of `SecItem*`, `CommonCrypto`,
  `CryptoKit`, `SecTrust*`, `DCAppAttest*` symbol references.

Runs as a `deep_analyze` job; App-detail Static tab renders the cached result.
Also exposed on the CLI: `python3 -m pipeline.cli analyze [--app-id … | --limit …]`.

YAGNI cuts for v1: no decompiler/disassembler view; secrets scan is regex-based
(not entropy/ML).

## Data model (additive migrations, existing pattern)

- `jobs` — `id, kind (crawl|acquire|deep_analyze|static|dynamic|attest|iap|
  aggregate|full), target (app_id or 'batch'), params (JSON), state
  (queued|running|done|failed|cancelled), progress_pct, log (text), created_at,
  started_at, finished_at, error`.
- `analysis` — `app_id, info_plist, entitlements, ats, frameworks, sdks, secrets,
  file_tree, crypto_hints (all JSON), analyzed_at` (one row per app).

Migrations are additive `ALTER`/`CREATE IF NOT EXISTS`, run at startup, matching
the pipeline's current DB approach. No existing table is modified destructively.

## Job manager (`pipeline/web/jobs.py`)

- `ThreadPoolExecutor` (default 3) for non-device jobs + a single-slot device lock
  shared by decrypt/dynamic/attest.
- Each job invokes the matching pipeline function; stdout/stderr and
  `run_cmd_streamed` output are teed into the job log (DB + in-memory) for SSE.
- Cancel = cooperative flag + subprocess kill for subprocess-based stages.
- Job records survive restart (DB); in-flight jobs on restart are marked
  `failed (interrupted)`.

## Auth (`pipeline/web/auth.py`)

- One shared token in `.env` (`WEB_AUTH_TOKEN`). Login form → signed httpOnly
  cookie. All routes except `/login`, `/healthz`, static assets require it.
- Bound to `0.0.0.0`; login is the boundary between the LAN and sensitive actions.
- Secrets (Apple-ID password, tokens) masked in Settings, never sent to client.

## Error handling

- Every job wraps its pipeline call; on failure records `failed` + error text
  (via existing `_short_reason`). A failed download never crashes the server.
- Missing prerequisites (no device, iTunes server down, not bootstrapped) surface
  as a pre-flight check with a clear message, not a stack trace. Reuses
  `CONFIG.missing_for_dynamic()` and `doctor`-style checks.

## CLI parity additions

- Existing subcommands unchanged.
- New: `python3 -m pipeline.cli analyze` (deep analysis) — same `analysis.py`
  the web uses.
- New: `python3 -m pipeline.web` launches the server (does not affect the CLI).
- Optional convenience: `python3 -m pipeline.cli web` as an alias to launch the
  server.

## Testing

- pytest: job manager (state transitions, device-lock serialization, cancel),
  deep-analysis extractors (fixture decrypted IPA → expected dataclasses), auth
  (protected routes redirect without cookie), DB migrations (idempotent).
- Route smoke tests via FastAPI `TestClient`.
- Manual: mobile-layout pass; live-progress SSE.

## Dependencies (added to requirements.txt)

`fastapi`, `uvicorn[standard]`, `jinja2`, `python-multipart`, `itsdangerous`
(cookie signing). HTMX + Tailwind via CDN (no build step) or vendored static
assets. `tqdm`, `requests`, `LIEF` already present.

## Phasing (build order)

1. App skeleton + auth + job manager + Dashboard/doctor + Jobs page.
2. Corpus browser + App detail Overview + Acquire tab (download/decrypt/versions).
3. Deep-analysis engine (`analysis.py`) + Static tab + CLI `analyze`.
4. Dynamic + Attestation tabs (device-dependent).
5. Settings + polish + mobile pass.

## Out of scope (v1)

Apple-ID pool management, scheduling/cron, multi-user accounts, decompilation,
ML/entropy secrets scanning. Candidate follow-up specs.
