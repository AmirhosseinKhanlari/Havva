"""Scan a pulled iOS app data container for insecure local storage.

Complements the static NSUserDefaults/SQLite/etc. API flags: this inspects what
the app *actually wrote* to its unencrypted stores at runtime (pulled from the
device via house_arrest/AFC), following the Trelis iOS static/dynamic guide:
  Library/Preferences/*.plist  -> NSUserDefaults (unencrypted)
  *.sqlite / *.db / Cache.db   -> SQLite / Core Data (unencrypted)
  *.realm                      -> Realm (unencrypted unless encryptionKey set)
  Library/Cookies/*.binarycookies -> persisted cookies
  Library/Keyboard/*.dat       -> keyboard autocorrect cache
  Library/Caches, HTTPStorages -> cached responses
"""

from __future__ import annotations

import plistlib
import re
from pathlib import Path

from .analysis import scan_secrets

_MAX_FILE = 8 * 1024 * 1024  # don't scan huge media/db blobs whole

_SENSITIVE_KEY = re.compile(
    r"(?i)(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|refresh[_-]?token|"
    r"auth[_-]?token|id[_-]?token|session[_-]?id|credential|private[_-]?key|"
    r"card[_-]?number|creditcard|cvv|ssn|pin\b)")
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


def _store_of(rel: str) -> str:
    low = ("/" + rel).lower().replace("\\", "/")
    if rel.endswith(".binarycookies") or "/cookies/" in low:
        return "Cookies"
    if "/keyboard/" in low and rel.endswith(".dat"):
        return "Keyboard cache"
    if rel.endswith((".sqlite", ".sqlite3", ".db")) or low.endswith("cache.db"):
        return "SQLite / Core Data"
    if rel.endswith(".realm"):
        return "Realm"
    if "/preferences/" in low and rel.endswith(".plist"):
        return "NSUserDefaults"
    if rel.endswith(".plist"):
        return "Property list"
    if "/caches/" in low or "/httpstorages/" in low:
        return "Caches"
    return "Other"


def _plist_pairs(raw: bytes) -> list[tuple[str, str]]:
    """Flatten a plist to (dotted-key, value) string pairs for keyword scanning."""
    try:
        obj = plistlib.loads(raw)
    except Exception:
        return []
    pairs: list[tuple[str, str]] = []

    def walk(o, prefix=""):
        if isinstance(o, dict):
            for k, v in o.items():
                walk(v, f"{prefix}{k}." if prefix else f"{k}")
        elif isinstance(o, (list, tuple)):
            for v in o:
                walk(v, prefix)
        else:
            pairs.append((prefix.rstrip("."), str(o)))
    walk(obj)
    return pairs


def scan_container(root: str | Path) -> tuple[list[dict], dict]:
    """Walk a pulled container. Returns (findings, store_summary).
    Each finding: {store, file, type, severity, detail}."""
    root = Path(root)
    findings: list[dict] = []
    stores: dict[str, int] = {}
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        rel = str(p.relative_to(root))
        store = _store_of(rel)
        stores[store] = stores.get(store, 0) + 1
        try:
            if p.stat().st_size > _MAX_FILE:
                raw = p.read_bytes()[:_MAX_FILE]
            else:
                raw = p.read_bytes()
        except OSError:
            continue

        # 1) Known secret patterns (tokens, keys, JWTs, private keys, ...).
        for s in scan_secrets(raw).get("findings", []):
            findings.append({"store": store, "file": rel, "type": s["type"],
                             "severity": s["severity"],
                             "detail": (s.get("value") or "")[:80]})

        # 2) Sensitive keys/values in plists (NSUserDefaults et al.).
        if rel.endswith(".plist"):
            pairs = _plist_pairs(raw)
            for key, val in pairs:
                if val and _SENSITIVE_KEY.search(key):
                    findings.append({"store": store, "file": rel,
                                     "type": f"sensitive key: {key}", "severity": "medium",
                                     "detail": val[:60]})
                elif val and _EMAIL.search(val):
                    findings.append({"store": store, "file": rel,
                                     "type": "email in stored value", "severity": "medium",
                                     "detail": val[:60]})
            # NSUserDefaults is unencrypted; surface that it holds data to review.
            if pairs and store in ("NSUserDefaults", "Property list"):
                findings.append({"store": store, "file": rel,
                                 "type": f"{len(pairs)} value(s) stored (unencrypted)",
                                 "severity": "info", "detail": ", ".join(
                                     sorted({k.split('.')[0] for k, _ in pairs})[:6])})

        # 3) SQLite / Core Data: open the DB and read tables + rows (like
        #    Objection's `sqlite connect` / `execute query`).
        if store == "SQLite / Core Data" and len(raw) > 64:
            findings += _scan_sqlite(p, store, rel)
        # Other unencrypted stores: just note presence.
        elif store in ("Realm", "Cookies", "Keyboard cache") and len(raw) > 64:
            findings.append({"store": store, "file": rel,
                             "type": f"{store} present (unencrypted)", "severity": "info",
                             "detail": f"{len(raw)} bytes"})
    return findings, stores


def _scan_sqlite(path, store: str, rel: str) -> list[dict]:
    """Open a pulled SQLite DB read-only, enumerate tables, and scan rows for
    secrets / sensitive columns. If it won't open it may be encrypted (good)."""
    import sqlite3
    out: list[dict] = []
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True, timeout=3)
    except Exception:  # noqa: BLE001
        return [{"store": store, "file": rel, "severity": "info",
                 "type": "SQLite present but could not open (possibly encrypted)", "detail": ""}]
    try:
        cur = con.cursor()
        tables = [r[0] for r in cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%'").fetchall()]
        for t in tables:
            try:
                n = cur.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
                cur.execute(f'SELECT * FROM "{t}" LIMIT 25')
                cols = [d[0] for d in (cur.description or [])]
                rows = cur.fetchall()
            except Exception:  # noqa: BLE001
                continue
            sens_cols = [c for c in cols if c and _SENSITIVE_KEY.search(c)]
            if sens_cols:
                out.append({"store": store, "file": rel, "severity": "medium",
                            "type": f"SQLite table '{t}' has sensitive column(s): {', '.join(sens_cols[:4])}",
                            "detail": f"{n} rows · cols: {', '.join(cols[:8])}"})
            hits = 0
            for row in rows:
                text = " ".join("" if v is None else str(v) for v in row)
                for s in scan_secrets(text.encode("utf-8", "replace")).get("findings", []):
                    out.append({"store": store, "file": rel, "severity": s["severity"],
                                "type": f"SQLite '{t}': {s['type']}",
                                "detail": (s.get("value") or "")[:60]})
                    hits += 1
                m = _EMAIL.search(text)
                if m:
                    out.append({"store": store, "file": rel, "severity": "medium",
                                "type": f"SQLite '{t}': email in row", "detail": m.group()[:60]})
                    hits += 1
                if hits >= 6:
                    break
            if not sens_cols and not hits:
                out.append({"store": store, "file": rel, "severity": "info",
                            "type": f"SQLite table '{t}' ({n} rows)",
                            "detail": f"cols: {', '.join(cols[:8])}"})
    finally:
        con.close()
    return out


def verdict_of(findings: list[dict]) -> tuple[str, str]:
    sev = {f["severity"] for f in findings}
    if "high" in sev:
        return "exposed", "Secrets/credentials found in an unencrypted store."
    if "medium" in sev:
        return "exposed", "Sensitive values found in an unencrypted store (NSUserDefaults / tokens)."
    if "info" in sev:
        return "review", "Unencrypted stores hold data but no obvious secret was matched. Review manually."
    return "clean", "No data found in the inspected unencrypted stores."
