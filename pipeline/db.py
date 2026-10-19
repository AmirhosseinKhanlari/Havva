"""SQLite backbone. Every pipeline stage reads and writes here.

Design goals, learned from paper 1:
- One schema owner (this module), not each script declaring its own table.
- Resumable: a stage reads which apps still need it and skips the rest.
- Tri-state work queue so transient failures retry and only definitive results
  or permanent skips leave the queue.
- Additive migrations via `ALTER TABLE ADD COLUMN` so new fields never require a
  rebuild.
- Full metadata retained: normalized columns for the fields we query on, plus a
  verbatim `raw_json` blob so nothing the store returned is ever lost.
"""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .models import (
    BackendBehavior,
    BypassStage,
    CrashClass,
    DefenseProfile,
    Outcome,
    PinLayer,
    Stage,
    TlsStack,
    WorkState,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS apps (
    app_id TEXT PRIMARY KEY,              -- App Store numeric track id (as text)
    bundle_id TEXT,
    country TEXT,
    rank INTEGER,
    rank_category TEXT,                   -- chart/genre it was scraped from
    name TEXT,
    subtitle TEXT,
    seller_name TEXT,
    developer_id TEXT,
    sku TEXT,
    primary_category TEXT,
    all_categories TEXT,                  -- JSON list
    content_rating TEXT,
    current_version TEXT,
    release_date TEXT,
    current_version_release_date TEXT,
    minimum_os TEXT,
    supported_devices TEXT,              -- JSON list
    languages TEXT,                      -- JSON list
    price REAL,
    currency TEXT,
    formatted_price TEXT,
    has_iap INTEGER DEFAULT 0,
    iap_products TEXT,                    -- JSON
    avg_rating REAL,
    rating_count INTEGER,
    description TEXT,
    release_notes TEXT,
    screenshot_urls TEXT,                -- JSON list
    artwork_url TEXT,
    seller_url TEXT,
    support_url TEXT,
    marketing_url TEXT,
    privacy_policy_url TEXT,
    file_size_bytes INTEGER,
    crawl_timestamp TEXT,
    source_endpoint TEXT,
    raw_json TEXT,                        -- verbatim store response
    stage TEXT DEFAULT 'crawled',
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS acquisition (
    app_id TEXT PRIMARY KEY REFERENCES apps(app_id),
    decrypt_status INTEGER DEFAULT 0,    -- WorkState
    ipa_path TEXT,
    arch TEXT,
    error TEXT,
    acquired_at TEXT
);

CREATE TABLE IF NOT EXISTS acquisition_versions (
    app_id TEXT REFERENCES apps(app_id),
    version_id TEXT NOT NULL,            -- externalVersionId / short version requested
    status INTEGER DEFAULT 0,            -- WorkState
    ipa_path TEXT,
    error TEXT,
    acquired_at TEXT,
    PRIMARY KEY (app_id, version_id)
);

CREATE TABLE IF NOT EXISTS static_profile (
    app_id TEXT PRIMARY KEY REFERENCES apps(app_id),
    pins_flag INTEGER DEFAULT 0,
    pin_layer TEXT,
    pin_library TEXT,
    tls_stack TEXT,
    anti_tamper_hints INTEGER DEFAULT 0,
    anti_debug_hints INTEGER DEFAULT 0,
    jailbreak_detection_hints INTEGER DEFAULT 0,
    appattest_flag INTEGER DEFAULT 0,
    appattest_level TEXT DEFAULT 'none', -- none|referenced|adopted|production
    devicecheck_flag INTEGER DEFAULT 0,
    networkextension_flag INTEGER DEFAULT 0,
    matched_patterns TEXT,               -- JSON
    static_state INTEGER DEFAULT 0,      -- WorkState
    analyzed_at TEXT
);

CREATE TABLE IF NOT EXISTS dynamic_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id TEXT REFERENCES apps(app_id),
    config TEXT,                          -- BypassStage or 'stage0'/'control'
    install_status TEXT,
    crash_class TEXT,
    flows_captured INTEGER DEFAULT 0,
    login_status TEXT,
    har_path TEXT,
    error TEXT,
    log TEXT DEFAULT '',
    run_at TEXT
);

CREATE TABLE IF NOT EXISTS outcome (
    app_id TEXT PRIMARY KEY REFERENCES apps(app_id),
    label TEXT,                          -- Outcome
    bypass_cost TEXT,                    -- BypassStage
    pinned INTEGER DEFAULT 0,
    work_state INTEGER DEFAULT 0,        -- WorkState
    decided_at TEXT
);

CREATE TABLE IF NOT EXISTS iap_bypass (
    app_id TEXT PRIMARY KEY REFERENCES apps(app_id),
    verdict TEXT,                        -- bypassable | not_bypassable | inconclusive
    tamperable INTEGER,
    fields TEXT, urls TEXT, method TEXT, -- JSON / text from the LLM verdict
    analysis TEXT, error TEXT,
    n_iap_flows INTEGER,
    probed_at TEXT
);

CREATE TABLE IF NOT EXISTS storage_probe (
    app_id TEXT PRIMARY KEY REFERENCES apps(app_id),
    verdict TEXT,                        -- exposed | review | clean | inconclusive
    note TEXT,
    findings TEXT,                       -- JSON list of {store,file,type,severity,detail}
    stores TEXT,                         -- JSON dict store -> file count
    probed_at TEXT
);

CREATE TABLE IF NOT EXISTS sideload_probe (
    app_id TEXT PRIMARY KEY REFERENCES apps(app_id),
    verdict TEXT,                        -- detected | no_detection | inconclusive
    note TEXT,
    control_alive INTEGER, fix_alive INTEGER,
    control_crashed INTEGER, fix_crashed INTEGER,
    probed_at TEXT
);

CREATE TABLE IF NOT EXISTS pinning_probe (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id TEXT REFERENCES apps(app_id),
    host TEXT,
    verdict TEXT,                        -- 'pinned' | 'not_pinned' | 'uncertain'
    seen_bypass INTEGER DEFAULT 0,       -- decrypted in the SSL-Kill-Switch run
    seen_clean INTEGER DEFAULT 0,        -- decrypted in the no-bypass run
    probed_at TEXT
);

CREATE TABLE IF NOT EXISTS attestation (
    app_id TEXT PRIMARY KEY REFERENCES apps(app_id),
    tested_flag INTEGER DEFAULT 0,
    neutralized_flag INTEGER DEFAULT 0,
    backend_behavior TEXT,               -- BackendBehavior
    work_state INTEGER DEFAULT 0,
    error TEXT,
    tested_at TEXT
);

CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,                  -- crawl|acquire|deep_analyze|static|dynamic|attest|iap|aggregate|full
    target TEXT,                         -- app_id or 'batch'
    params TEXT,                         -- JSON
    state TEXT NOT NULL DEFAULT 'queued',-- queued|running|done|failed|cancelled
    progress_pct INTEGER DEFAULT 0,
    log TEXT DEFAULT '',
    error TEXT,
    created_at TEXT,
    started_at TEXT,
    finished_at TEXT
);

CREATE TABLE IF NOT EXISTS analysis (
    app_id TEXT PRIMARY KEY REFERENCES apps(app_id),
    info_plist TEXT,                     -- JSON
    entitlements TEXT,                   -- JSON
    ats TEXT,                            -- JSON
    frameworks TEXT,                     -- JSON
    sdks TEXT,                           -- JSON
    secrets TEXT,                        -- JSON
    file_tree TEXT,                      -- JSON
    crypto_hints TEXT,                   -- JSON
    binary_protections TEXT,             -- JSON (checksec: pie/nx/canary/arc/rpath/signature/encrypted)
    insecure_apis TEXT,                  -- JSON (banned APIs, weak crypto/hash, random, webview)
    binary_type TEXT,                    -- Swift | Objective-C | unknown
    security_score TEXT,                 -- JSON {score, grade, deductions}
    trackers TEXT,                       -- JSON
    dependencies TEXT,                   -- JSON [{name,version,cves:[...]}]
    privacy_manifest TEXT,               -- JSON
    bundled_certs TEXT,                  -- JSON list of cert/key files in bundle
    app_extensions TEXT,                 -- JSON list of .appex extensions
    ats_gap TEXT,                        -- JSON ATS declared-vs-needed result
    analyzed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_apps_stage ON apps(stage);
CREATE INDEX IF NOT EXISTS idx_static_pins ON static_profile(pins_flag);
CREATE INDEX IF NOT EXISTS idx_dynamic_app ON dynamic_runs(app_id);
CREATE INDEX IF NOT EXISTS idx_pinning_app ON pinning_probe(app_id);
CREATE INDEX IF NOT EXISTS idx_jobs_state ON jobs(state);
"""


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


class Database:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.migrate()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def migrate(self) -> None:
        with self.connect() as conn:
            conn.executescript(SCHEMA)
        # additive columns for existing DBs (analysis deep-scan fields)
        for col, decl in (("binary_protections", "TEXT"), ("insecure_apis", "TEXT"),
                          ("binary_type", "TEXT"), ("security_score", "TEXT"),
                          ("trackers", "TEXT"), ("dependencies", "TEXT"),
                          ("privacy_manifest", "TEXT"), ("bundled_certs", "TEXT"),
                          ("app_extensions", "TEXT"), ("ats_gap", "TEXT"),
                          ("iap", "TEXT")):
            self.add_column_if_missing("analysis", col, decl)
        self.add_column_if_missing("static_profile", "appattest_level", "TEXT DEFAULT 'none'")
        self.add_column_if_missing("dynamic_runs", "log", "TEXT DEFAULT ''")
        # acquisition work-queue bookkeeping: retry budget + last transient error
        self.add_column_if_missing("acquisition", "attempts", "INTEGER DEFAULT 0")
        self.add_column_if_missing("acquisition", "last_error", "TEXT")

    def add_column_if_missing(self, table: str, column: str, decl: str) -> None:
        """The paper-1 `ensure_rc_columns` idiom: additive migration."""
        with self.connect() as conn:
            cols = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
            if column not in cols:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")

    # ---- Stage A: crawl -------------------------------------------------

    def upsert_app(self, app_id: str, country: str, **fields: Any) -> None:
        """Insert or update an app row. Unknown keys are ignored so callers can
        pass whatever metadata they scraped."""
        fields = dict(fields)
        fields["country"] = country
        fields["updated_at"] = _now()
        # JSON-encode any list/dict values.
        for k, v in list(fields.items()):
            if isinstance(v, (list, dict)):
                fields[k] = json.dumps(v, ensure_ascii=False)
        with self.connect() as conn:
            valid = {r["name"] for r in conn.execute("PRAGMA table_info(apps)")}
            fields = {k: v for k, v in fields.items() if k in valid}
            exists = conn.execute("SELECT 1 FROM apps WHERE app_id=?", (app_id,)).fetchone()
            if exists:
                # Never overwrite an existing value with NULL (e.g. a numeric
                # acquire passes bundle_id=None; that must not clobber a resolved id).
                upd = {k: v for k, v in fields.items() if v is not None}
                if upd:
                    sets = ", ".join(f"{k}=?" for k in upd)
                    conn.execute(f"UPDATE apps SET {sets} WHERE app_id=?",
                                 (*upd.values(), app_id))
            else:
                cols = ["app_id", *fields.keys()]
                conn.execute(
                    f"INSERT INTO apps ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
                    (app_id, *fields.values()),
                )

    # ---- Jobs (web UI) --------------------------------------------------

    _JOB_TERMINAL = ("done", "failed", "cancelled")

    def create_job(self, kind: str, target: str, params: dict | None = None) -> int:
        with self.connect() as conn:
            cur = conn.execute(
                "INSERT INTO jobs (kind, target, params, state, created_at) "
                "VALUES (?, ?, ?, 'queued', ?)",
                (kind, target, json.dumps(params or {}), _now()),
            )
            return int(cur.lastrowid)

    def get_job(self, job_id: int):
        with self.connect() as conn:
            return conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()

    def list_jobs(self, limit: int = 50):
        with self.connect() as conn:
            return conn.execute(
                "SELECT * FROM jobs ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()

    def clear_jobs(self) -> int:
        """Delete all finished jobs (done/failed/cancelled); keep running/queued.
        Returns how many were removed."""
        with self.connect() as conn:
            cur = conn.execute(
                "DELETE FROM jobs WHERE state IN ('done','failed','cancelled')")
            return cur.rowcount

    def active_job(self, target: str, kinds: tuple[str, ...]):
        """Most recent queued/running job for this target whose kind is in
        `kinds` -- so a tab can re-attach to an in-progress job on reload."""
        if not kinds:
            return None
        with self.connect() as conn:
            ph = ",".join("?" * len(kinds))
            return conn.execute(
                f"SELECT * FROM jobs WHERE target=? AND kind IN ({ph}) "
                f"AND state IN ('queued','running') ORDER BY id DESC LIMIT 1",
                (target, *kinds)).fetchone()

    def set_job_state(self, job_id: int, state: str, error: str | None = None) -> None:
        with self.connect() as conn:
            sets = ["state=?"]
            vals: list = [state]
            if state == "running":
                sets.append("started_at=?"); vals.append(_now())
            if state in self._JOB_TERMINAL:
                sets.append("finished_at=?"); vals.append(_now())
            if error is not None:
                sets.append("error=?"); vals.append(error)
            vals.append(job_id)
            conn.execute(f"UPDATE jobs SET {', '.join(sets)} WHERE id=?", vals)

    def append_job_log(self, job_id: int, text: str) -> None:
        with self.connect() as conn:
            conn.execute("UPDATE jobs SET log = COALESCE(log,'') || ? WHERE id=?",
                         (text, job_id))

    def set_job_progress(self, job_id: int, pct: int) -> None:
        with self.connect() as conn:
            conn.execute("UPDATE jobs SET progress_pct=? WHERE id=?", (int(pct), job_id))

    def mark_interrupted_jobs(self) -> int:
        with self.connect() as conn:
            cur = conn.execute(
                "UPDATE jobs SET state='failed', error='interrupted', finished_at=? "
                "WHERE state IN ('queued','running')", (_now(),))
            return cur.rowcount

    # ---- Stage transitions ----------------------------------------------

    def set_stage(self, app_id: str, stage: Stage) -> None:
        with self.connect() as conn:
            conn.execute("UPDATE apps SET stage=?, updated_at=? WHERE app_id=?",
                         (stage.value, _now(), app_id))

    # ---- Stage B: acquisition ------------------------------------------

    def save_acquisition(self, app_id: str, state: WorkState, ipa_path: str = "",
                         arch: str = "", error: str = "") -> None:
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO acquisition (app_id, decrypt_status, ipa_path, arch, error, acquired_at)
                   VALUES (?,?,?,?,?,?)
                   ON CONFLICT(app_id) DO UPDATE SET
                     decrypt_status=excluded.decrypt_status, ipa_path=excluded.ipa_path,
                     arch=excluded.arch, error=excluded.error, acquired_at=excluded.acquired_at""",
                (app_id, int(state), ipa_path, arch, error, _now()),
            )

    def record_acquisition_attempt(self, app_id: str, error: str = "") -> int:
        """Count one failed (UNTESTED, i.e. retryable) acquire attempt for the
        work queue. Creates the acquisition row if needed (status stays
        UNTESTED). Returns the new attempt count."""
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO acquisition (app_id, decrypt_status, attempts, last_error, acquired_at)
                   VALUES (?, 0, 1, ?, ?)
                   ON CONFLICT(app_id) DO UPDATE SET
                     attempts=COALESCE(acquisition.attempts,0)+1, last_error=excluded.last_error""",
                (app_id, error, _now()))
            row = conn.execute("SELECT attempts FROM acquisition WHERE app_id=?",
                               (app_id,)).fetchone()
            return int(row["attempts"] or 0) if row else 0

    def save_acquisition_version(self, app_id: str, version_id: str, state: WorkState,
                                 ipa_path: str = "", error: str = "") -> None:
        """Record the result of acquiring one SPECIFIC older build. Kept apart
        from the canonical `acquisition` row so a version-specific failure (or
        success) never clobbers the app's current-build acquisition state."""
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO acquisition_versions
                   (app_id, version_id, status, ipa_path, error, acquired_at)
                   VALUES (?,?,?,?,?,?)
                   ON CONFLICT(app_id, version_id) DO UPDATE SET
                     status=excluded.status, ipa_path=excluded.ipa_path,
                     error=excluded.error, acquired_at=excluded.acquired_at""",
                (app_id, str(version_id), int(state), ipa_path, error, _now()))

    def get_acquisition_versions(self, app_id: str) -> list[sqlite3.Row]:
        with self.connect() as conn:
            return conn.execute(
                "SELECT * FROM acquisition_versions WHERE app_id=? ORDER BY acquired_at DESC, version_id",
                (app_id,)).fetchall()

    def app_id_for_bundle(self, bundle_id: str) -> str | None:
        """Existing corpus key for a bundle id (so a bundle-id acquire reuses the
        crawled row instead of inserting a duplicate keyed by bundle id)."""
        if not bundle_id:
            return None
        with self.connect() as conn:
            row = conn.execute(
                "SELECT app_id FROM apps WHERE bundle_id=? ORDER BY (app_id=?) DESC, app_id LIMIT 1",
                (bundle_id, bundle_id)).fetchone()
            return row["app_id"] if row else None

    def delete_acquisition(self, app_id: str) -> None:
        with self.connect() as conn:
            conn.execute("DELETE FROM acquisition WHERE app_id=?", (app_id,))
            conn.execute("UPDATE apps SET stage='crawled' WHERE app_id=? AND stage='acquired'",
                         (app_id,))

    # ---- Stage C: static profile ---------------------------------------

    def save_static_profile(self, app_id: str, p: DefenseProfile) -> None:
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO static_profile
                   (app_id, pins_flag, pin_layer, pin_library, tls_stack,
                    anti_tamper_hints, anti_debug_hints, jailbreak_detection_hints,
                    appattest_flag, appattest_level, devicecheck_flag, networkextension_flag,
                    matched_patterns, static_state, analyzed_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(app_id) DO UPDATE SET
                     pins_flag=excluded.pins_flag, pin_layer=excluded.pin_layer,
                     pin_library=excluded.pin_library, tls_stack=excluded.tls_stack,
                     anti_tamper_hints=excluded.anti_tamper_hints,
                     anti_debug_hints=excluded.anti_debug_hints,
                     jailbreak_detection_hints=excluded.jailbreak_detection_hints,
                     appattest_flag=excluded.appattest_flag,
                     appattest_level=excluded.appattest_level,
                     devicecheck_flag=excluded.devicecheck_flag,
                     networkextension_flag=excluded.networkextension_flag,
                     matched_patterns=excluded.matched_patterns,
                     static_state=excluded.static_state, analyzed_at=excluded.analyzed_at""",
                (app_id, int(p.pins_flag), p.pin_layer.value, p.pin_library, p.tls_stack.value,
                 int(p.anti_tamper_hints), int(p.anti_debug_hints), int(p.jailbreak_detection_hints),
                 int(p.appattest_flag), p.appattest_level, int(p.devicecheck_flag), int(p.networkextension_flag),
                 json.dumps(p.matched_patterns), int(WorkState.POSITIVE), _now()),
            )

    # ---- Stage E/F: dynamic runs ---------------------------------------

    def clear_dynamic_runs(self, app_id: str) -> None:
        """Remove prior dynamic runs for an app so a new run's results replace
        them (each run of the ladder re-adds stage0 etc., which otherwise piles up)."""
        with self.connect() as conn:
            conn.execute("DELETE FROM dynamic_runs WHERE app_id=?", (app_id,))

    def add_dynamic_run(self, app_id: str, config: str, install_status: str,
                        crash_class: CrashClass, flows_captured: int,
                        login_status: str, har_path: str = "", error: str = "",
                        log: str = "") -> None:
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO dynamic_runs
                   (app_id, config, install_status, crash_class, flows_captured,
                    login_status, har_path, error, log, run_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (app_id, config, install_status, crash_class.value, flows_captured,
                 login_status, har_path, error, log, _now()),
            )

    # ---- IAP / subscription bypass probe -------------------------------

    def save_iap_bypass(self, app_id: str, verdict: str, res: dict, n_iap_flows: int) -> None:
        import json
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO iap_bypass
                   (app_id, verdict, tamperable, fields, urls, method, analysis, error,
                    n_iap_flows, probed_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(app_id) DO UPDATE SET
                     verdict=excluded.verdict, tamperable=excluded.tamperable,
                     fields=excluded.fields, urls=excluded.urls, method=excluded.method,
                     analysis=excluded.analysis, error=excluded.error,
                     n_iap_flows=excluded.n_iap_flows, probed_at=excluded.probed_at""",
                (app_id, verdict,
                 None if res.get("tamperable") is None else int(bool(res.get("tamperable"))),
                 json.dumps(res.get("fields") or []), json.dumps(res.get("urls") or []),
                 res.get("method") or "", res.get("analysis") or "", res.get("error") or "",
                 n_iap_flows, _now()),
            )

    def get_iap_bypass(self, app_id: str):
        with self.connect() as conn:
            return conn.execute(
                "SELECT * FROM iap_bypass WHERE app_id=?", (app_id,)).fetchone()

    # ---- Data-storage inspection probe ---------------------------------

    def save_storage_probe(self, app_id: str, verdict: str, note: str,
                           findings: list, stores: dict) -> None:
        import json
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO storage_probe (app_id, verdict, note, findings, stores, probed_at)
                   VALUES (?,?,?,?,?,?)
                   ON CONFLICT(app_id) DO UPDATE SET
                     verdict=excluded.verdict, note=excluded.note,
                     findings=excluded.findings, stores=excluded.stores,
                     probed_at=excluded.probed_at""",
                (app_id, verdict, note, json.dumps(findings), json.dumps(stores), _now()),
            )

    def get_storage_probe(self, app_id: str):
        with self.connect() as conn:
            return conn.execute(
                "SELECT * FROM storage_probe WHERE app_id=?", (app_id,)).fetchone()

    # ---- Sideload / anti-resign probe ----------------------------------

    def save_sideload_probe(self, app_id: str, verdict: str, note: str,
                            control_alive: bool, fix_alive: bool,
                            control_crashed: bool, fix_crashed: bool) -> None:
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO sideload_probe
                   (app_id, verdict, note, control_alive, fix_alive,
                    control_crashed, fix_crashed, probed_at)
                   VALUES (?,?,?,?,?,?,?,?)
                   ON CONFLICT(app_id) DO UPDATE SET
                     verdict=excluded.verdict, note=excluded.note,
                     control_alive=excluded.control_alive, fix_alive=excluded.fix_alive,
                     control_crashed=excluded.control_crashed, fix_crashed=excluded.fix_crashed,
                     probed_at=excluded.probed_at""",
                (app_id, verdict, note, int(control_alive), int(fix_alive),
                 int(control_crashed), int(fix_crashed), _now()),
            )

    def get_sideload_probe(self, app_id: str):
        with self.connect() as conn:
            return conn.execute(
                "SELECT * FROM sideload_probe WHERE app_id=?", (app_id,)).fetchone()

    # ---- Pinning probe (differential SSL-pinning detection) ------------

    def clear_pinning_probe(self, app_id: str) -> None:
        with self.connect() as conn:
            conn.execute("DELETE FROM pinning_probe WHERE app_id=?", (app_id,))

    def add_pinning_probe(self, app_id: str, host: str, verdict: str,
                          seen_bypass: bool, seen_clean: bool) -> None:
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO pinning_probe
                   (app_id, host, verdict, seen_bypass, seen_clean, probed_at)
                   VALUES (?,?,?,?,?,?)""",
                (app_id, host, verdict, int(seen_bypass), int(seen_clean), _now()),
            )

    def get_pinning_probe(self, app_id: str):
        with self.connect() as conn:
            return conn.execute(
                "SELECT * FROM pinning_probe WHERE app_id=? "
                "ORDER BY (verdict='pinned') DESC, host", (app_id,)).fetchall()

    # ---- Stage G: outcome ----------------------------------------------

    def save_outcome(self, app_id: str, label: Outcome, bypass_cost: BypassStage,
                     pinned: bool, work_state: WorkState) -> None:
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO outcome (app_id, label, bypass_cost, pinned, work_state, decided_at)
                   VALUES (?,?,?,?,?,?)
                   ON CONFLICT(app_id) DO UPDATE SET
                     label=excluded.label, bypass_cost=excluded.bypass_cost,
                     pinned=excluded.pinned, work_state=excluded.work_state,
                     decided_at=excluded.decided_at""",
                (app_id, label.value, bypass_cost.value, int(pinned), int(work_state), _now()),
            )

    # ---- Stage H: attestation ------------------------------------------

    def save_attestation(self, app_id: str, tested: bool, neutralized: bool,
                         behavior: BackendBehavior, state: WorkState, error: str = "") -> None:
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO attestation
                   (app_id, tested_flag, neutralized_flag, backend_behavior, work_state, error, tested_at)
                   VALUES (?,?,?,?,?,?,?)
                   ON CONFLICT(app_id) DO UPDATE SET
                     tested_flag=excluded.tested_flag, neutralized_flag=excluded.neutralized_flag,
                     backend_behavior=excluded.backend_behavior, work_state=excluded.work_state,
                     error=excluded.error, tested_at=excluded.tested_at""",
                (app_id, int(tested), int(neutralized), behavior.value, int(state), error, _now()),
            )

    # ---- Resumable work queues -----------------------------------------

    @staticmethod
    def acquire_max_attempts() -> int:
        """Retry budget for transient acquire failures (env ACQUIRE_MAX_ATTEMPTS)."""
        import os
        try:
            return max(1, int(os.environ.get("ACQUIRE_MAX_ATTEMPTS", "5")))
        except ValueError:
            return 5

    def apps_needing(self, stage: Stage, max_attempts: int | None = None) -> list[sqlite3.Row]:
        """Return apps that still need `stage` run, honoring the tri-state queue.
        For ACQUIRED, rows whose transient-failure `attempts` reached
        `max_attempts` (default env ACQUIRE_MAX_ATTEMPTS=5) are left out so a
        permanently flaky app stops consuming the device."""
        params: tuple = ()
        if stage == Stage.ACQUIRED:
            params = (max_attempts if max_attempts is not None else self.acquire_max_attempts(),)
        q = {
            Stage.ACQUIRED: """SELECT a.* FROM apps a
                LEFT JOIN acquisition ac ON ac.app_id=a.app_id
                WHERE (ac.app_id IS NULL OR ac.decrypt_status=0)
                  AND COALESCE(ac.attempts,0) < ?""",
            Stage.STATIC_DONE: """SELECT a.* FROM apps a
                JOIN acquisition ac ON ac.app_id=a.app_id AND ac.decrypt_status=1
                LEFT JOIN static_profile s ON s.app_id=a.app_id
                WHERE s.app_id IS NULL OR s.static_state=0""",
            Stage.DYNAMIC_DONE: """SELECT a.* FROM apps a
                JOIN static_profile s ON s.app_id=a.app_id AND s.pins_flag=1
                LEFT JOIN outcome o ON o.app_id=a.app_id
                WHERE o.app_id IS NULL OR o.work_state=0""",
            Stage.ATTESTATION_DONE: """SELECT a.* FROM apps a
                JOIN static_profile s ON s.app_id=a.app_id AND s.appattest_flag=1
                LEFT JOIN attestation at ON at.app_id=a.app_id
                WHERE at.app_id IS NULL OR at.work_state=0""",
        }[stage]
        with self.connect() as conn:
            return conn.execute(q, params).fetchall()

    # ---- Web reads ------------------------------------------------------

    def get_app(self, app_id: str):
        with self.connect() as conn:
            return conn.execute("SELECT * FROM apps WHERE app_id=?", (app_id,)).fetchone()

    def set_bundle_id(self, app_id: str, bundle_id: str) -> None:
        """Backfill a bundle id the crawl never captured (recovered from the IPA)."""
        with self.connect() as conn:
            conn.execute("UPDATE apps SET bundle_id=? WHERE app_id=?", (bundle_id, app_id))

    def backfill_bundle_ids(self) -> tuple[int, int]:
        """Populate missing bundle ids from the best available source: crawl
        raw_json (bundleId), stored analysis Info.plist, or the decrypted IPA.
        Returns (fixed, still_missing)."""
        from pathlib import Path
        from . import instrument
        with self.connect() as conn:
            ids = [r["app_id"] for r in conn.execute(
                "SELECT app_id FROM apps WHERE bundle_id IS NULL OR bundle_id=''")]
        fixed = 0
        for aid in ids:
            bid = None
            r = self.get_app(aid)
            if r and r["raw_json"]:
                try:
                    bid = json.loads(r["raw_json"]).get("bundleId")
                except (ValueError, TypeError):
                    bid = None
            if not bid:
                an = self.get_analysis(aid)
                if an and an["info_plist"]:
                    try:
                        bid = (json.loads(an["info_plist"]).get("summary", {}) or {}).get("CFBundleIdentifier")
                    except (ValueError, TypeError):
                        bid = None
            if not bid:
                ac = self.get_acquisition(aid)
                p = Path(ac["ipa_path"]) if ac and ac["ipa_path"] else None
                if p and p.exists():
                    bid = instrument.bundle_id_from_ipa(p)
            if bid:
                self.set_bundle_id(aid, bid)
                fixed += 1
        with self.connect() as conn:
            missing = conn.execute(
                "SELECT COUNT(*) FROM apps WHERE bundle_id IS NULL OR bundle_id=''").fetchone()[0]
        return fixed, missing

    def _distinct(self, table: str, column: str, nonempty: bool = True) -> list[str]:
        with self.connect() as conn:
            sql = f"SELECT DISTINCT {column} FROM {table} WHERE {column} IS NOT NULL"
            if nonempty:
                sql += f" AND {column} != ''"
            sql += f" ORDER BY {column}"
            return [r[0] for r in conn.execute(sql).fetchall()]

    def categories(self) -> list[str]:
        return self._distinct("apps", "primary_category")

    def countries(self) -> list[str]:
        return self._distinct("apps", "country")

    def content_ratings(self) -> list[str]:
        return self._distinct("apps", "content_rating")

    def tls_stacks(self) -> list[str]:
        return self._distinct("static_profile", "tls_stack")

    def pin_libraries(self) -> list[str]:
        return self._distinct("static_profile", "pin_library")

    def filter_options(self) -> dict:
        """All dropdown option lists for the corpus filter UI."""
        return {
            "categories": self.categories(),
            "countries": self.countries(),
            "content_ratings": self.content_ratings(),
            "tls_stacks": self.tls_stacks(),
            "pin_libraries": self.pin_libraries(),
        }

    def search_apps(self, q: str = "", category: str = "", pinned: str = "",
                    acquired: str = "", attest: str = "", country: str = "",
                    devicecheck: str = "", anti_tamper: str = "", tls_stack: str = "",
                    pin_library: str = "", has_iap: str = "", price: str = "",
                    content_rating: str = "", min_ios: str = "", min_rating: str = "",
                    static_done: str = "", seller: str = "",
                    limit: int = 50, offset: int = 0):
        """Filtered corpus query. Returns (rows, total_count). Every filter is
        optional; '' means 'any'. Boolean-ish filters take '1'/'0'."""
        joins = ("LEFT JOIN acquisition ac ON ac.app_id=a.app_id "
                 "LEFT JOIN static_profile s ON s.app_id=a.app_id")
        where = []
        params: list = []
        if q:
            where.append("(a.name LIKE ? OR a.bundle_id LIKE ? OR a.app_id LIKE ?)")
            params += [f"%{q}%", f"%{q}%", f"%{q}%"]
        if category:
            where.append("a.primary_category=?"); params.append(category)
        if country:
            where.append("a.country=?"); params.append(country)
        if seller:
            where.append("a.seller_name LIKE ?"); params.append(f"%{seller}%")
        if content_rating:
            where.append("a.content_rating=?"); params.append(content_rating)
        if tls_stack:
            where.append("s.tls_stack=?"); params.append(tls_stack)
        if pin_library:
            where.append("s.pin_library=?"); params.append(pin_library)
        if pinned in ("0", "1"):
            where.append("COALESCE(s.pins_flag,0)=?"); params.append(int(pinned))
        if attest in ("0", "1"):
            where.append("COALESCE(s.appattest_flag,0)=?"); params.append(int(attest))
        if devicecheck in ("0", "1"):
            where.append("COALESCE(s.devicecheck_flag,0)=?"); params.append(int(devicecheck))
        if anti_tamper == "1":
            where.append("COALESCE(s.anti_tamper_hints,0) > 0")
        elif anti_tamper == "0":
            where.append("COALESCE(s.anti_tamper_hints,0) = 0")
        if has_iap in ("0", "1"):
            where.append("COALESCE(a.has_iap,0)=?"); params.append(int(has_iap))
        if price == "free":
            where.append("COALESCE(a.price,0)=0")
        elif price == "paid":
            where.append("COALESCE(a.price,0) > 0")
        if min_ios:
            try:
                where.append("CAST(a.minimum_os AS REAL) >= ?"); params.append(float(min_ios))
            except ValueError:
                pass
        if min_rating:
            try:
                where.append("COALESCE(a.avg_rating,0) >= ?"); params.append(float(min_rating))
            except ValueError:
                pass
        if static_done == "1":
            where.append("COALESCE(s.static_state,0)=1")
        elif static_done == "0":
            where.append("COALESCE(s.static_state,0)=0")
        if acquired == "1":
            where.append("COALESCE(ac.decrypt_status,0)=1")
        elif acquired == "0":
            where.append("COALESCE(ac.decrypt_status,0)=0")
        wsql = ("WHERE " + " AND ".join(where)) if where else ""
        with self.connect() as conn:
            total = conn.execute(
                f"SELECT COUNT(*) FROM apps a {joins} {wsql}", params).fetchone()[0]
            rows = conn.execute(
                f"SELECT a.app_id, a.name, a.bundle_id, a.primary_category, a.artwork_url, "
                f"a.file_size_bytes, a.minimum_os, a.country, "
                f"COALESCE(ac.decrypt_status,0) AS acquired, "
                f"COALESCE(s.pins_flag,0) AS pinned, "
                f"COALESCE(s.appattest_flag,0) AS attest "
                f"FROM apps a {joins} {wsql} "
                f"ORDER BY a.rank IS NULL, a.rank LIMIT ? OFFSET ?",
                (*params, limit, offset)).fetchall()
            return rows, total

    def get_acquisition(self, app_id: str):
        with self.connect() as conn:
            return conn.execute("SELECT * FROM acquisition WHERE app_id=?", (app_id,)).fetchone()

    def get_static_profile(self, app_id: str):
        with self.connect() as conn:
            return conn.execute("SELECT * FROM static_profile WHERE app_id=?", (app_id,)).fetchone()

    def get_outcome(self, app_id: str):
        with self.connect() as conn:
            return conn.execute("SELECT * FROM outcome WHERE app_id=?", (app_id,)).fetchone()

    def get_dynamic_runs(self, app_id: str):
        with self.connect() as conn:
            return conn.execute(
                "SELECT * FROM dynamic_runs WHERE app_id=? ORDER BY id", (app_id,)).fetchall()

    def get_attestation(self, app_id: str):
        with self.connect() as conn:
            return conn.execute("SELECT * FROM attestation WHERE app_id=?", (app_id,)).fetchone()

    def save_analysis(self, app_id: str, data: dict) -> None:
        cols = ("info_plist", "entitlements", "ats", "frameworks", "sdks",
                "secrets", "file_tree", "crypto_hints", "binary_protections",
                "insecure_apis", "binary_type", "security_score", "trackers",
                "dependencies", "privacy_manifest", "bundled_certs", "app_extensions",
                "iap")
        # SQL NULL for absent values, never the JSON literal string 'null'.
        vals = [None if data.get(c) is None else json.dumps(data.get(c)) for c in cols]
        with self.connect() as conn:
            conn.execute(
                f"INSERT INTO analysis (app_id, {', '.join(cols)}, analyzed_at) "
                f"VALUES (?, {', '.join('?' * len(cols))}, ?) "
                f"ON CONFLICT(app_id) DO UPDATE SET "
                + ", ".join(f"{c}=excluded.{c}" for c in cols)
                + ", analyzed_at=excluded.analyzed_at",
                (app_id, *vals, _now()))

    def get_analysis(self, app_id: str):
        with self.connect() as conn:
            return conn.execute("SELECT * FROM analysis WHERE app_id=?", (app_id,)).fetchone()

    def set_analysis_field(self, app_id: str, field: str, value: str) -> None:
        """Update one JSON column on an existing analysis row (e.g. ats_gap set
        after the deep analysis, since it needs a network/nscurl step)."""
        allowed = {"ats_gap", "app_extensions", "dependencies", "privacy_manifest"}
        if field not in allowed:
            raise ValueError(f"field not allowed: {field}")
        with self.connect() as conn:
            conn.execute(f"UPDATE analysis SET {field}=? WHERE app_id=?", (value, app_id))

    def counts(self) -> dict[str, int]:
        with self.connect() as conn:
            def one(sql: str) -> int:
                return conn.execute(sql).fetchone()[0]
            return {
                "apps": one("SELECT COUNT(*) FROM apps"),
                "acquired": one("SELECT COUNT(*) FROM acquisition WHERE decrypt_status=1"),
                "static_done": one("SELECT COUNT(*) FROM static_profile WHERE static_state=1"),
                "pinned": one("SELECT COUNT(*) FROM static_profile WHERE pins_flag=1"),
                "appattest": one("SELECT COUNT(*) FROM static_profile WHERE appattest_flag=1"),
                "outcomes": one("SELECT COUNT(*) FROM outcome WHERE work_state!=0"),
                "attested_tested": one("SELECT COUNT(*) FROM attestation WHERE work_state!=0"),
            }
