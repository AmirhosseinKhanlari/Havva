"""Scan a pulled iOS app data container for insecure local storage.

Complements the static NSUserDefaults/SQLite/etc. API flags: this inspects what
the app *actually wrote* to its stores at runtime (pulled from the device via
house_arrest/AFC), following the MASTG storage tests:
  Library/Preferences/*.plist  -> NSUserDefaults
  *.sqlite / *.db / Cache.db   -> SQLite / Core Data (WAL applied, see _scan_sqlite)
  *.realm                      -> Realm (unencrypted unless encryptionKey set)
  Library/Cookies/*.binarycookies -> persisted cookies (parsed)
  Library/Keyboard/*.dat       -> keyboard autocorrect cache
  Library/Caches, HTTPStorages -> cached responses
  Documents/FakeGroupContainers -> app-group containers (redirected by SideloadFix)

FRAMING: every container file is encrypted at rest by Data Protection (class
CompleteUntilFirstUserAuthentication by default), so "unencrypted" is the wrong
word. What matters is (a) whether a secret sits in a FILE instead of the
Keychain, (b) the file's protection class, and (c) for Keychain items, the
kSecAttrAccessible class. (b) and (c) come from StorageObserver.dylib's syslog
trail (parse_observer / apply_observer); without it the verdict says so.
"""

from __future__ import annotations

import plistlib
import re
import shutil
import sqlite3
import struct
import tempfile
from pathlib import Path

from .analysis import _looks_like_email, scan_secrets

_MAX_FILE = 8 * 1024 * 1024  # cap for the raw secret scan (plists / DBs are read whole)


# ---- sensitive key names ----------------------------------------------------
# Each keyword must start at a word boundary or a camelCase transition (so
# "clientSecret" / "user_password" match) and end at a word boundary or a
# camelCase transition (so "pin" does not match "pinned", "ssn" not "ssnumber",
# "secret" not "secretary"). A trailing plural "s" is allowed. Bare "pin" is
# stricter (no camelCase continuation) so "pinCount" / "pinImage" in map apps
# do not fire; "pinCode" / "PIN_CODE" are listed explicitly.
_B_START = r"(?:(?<![A-Za-z0-9])|(?<=[a-z])(?=[A-Z]))"
_B_END = r"(?i:s)?(?![a-z0-9])"

# Credentials: a value under one of these keys is a secret by definition.
_CRED_WORDS = (r"password|passwd|pwd|passcode|private[_-]?key|mnemonic|seed[_-]?phrase|"
               r"card[_-]?number|creditcard|cvv2?|ssn|pin[_-]?code|pincode")
# Tokens / identifiers: sensitive, but short-lived or scoped.
_TOKEN_WORDS = (r"secret(?!ary)|api[_-]?key|api[_-]?token|access[_-]?key|access[_-]?token|"
                r"refresh[_-]?token|auth[_-]?token|id[_-]?token|session[_-]?token|"
                r"session[_-]?id|bearer|jwt|oauth|credential")   # cookies: parsed from the store itself
_CREDENTIAL_KEY = re.compile(_B_START + r"(?i:" + _CRED_WORDS + r")" + _B_END
                             + r"|(?<![A-Za-z0-9])(?i:pin)(?![A-Za-z0-9])")
_TOKEN_KEY = re.compile(_B_START + r"(?i:" + _TOKEN_WORDS + r")" + _B_END)
_SENSITIVE_KEY = re.compile(_CREDENTIAL_KEY.pattern + "|" + _TOKEN_KEY.pattern)

_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

_SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}
_SEV_NAMES = ["info", "low", "medium", "high"]


def _key_severity(key: str) -> str | None:
    """'high' for a credential key, 'medium' for a token key, None otherwise."""
    if _CREDENTIAL_KEY.search(key or ""):
        return "high"
    if _TOKEN_KEY.search(key or ""):
        return "medium"
    return None


def _find_email(text: str) -> str | None:
    """First address in `text` that survives the shared noise filter (drops
    resource names such as logo@2x.png / icon@3x and format-string artifacts)."""
    for m in _EMAIL.finditer(text or ""):
        e = m.group()
        if "@2x" in e or "@3x" in e or "@4x" in e:
            continue
        if _looks_like_email(e):
            return e
    return None


def _store_of(rel: str) -> str:
    low = ("/" + rel).lower().replace("\\", "/")
    if "/fakegroupcontainers/" in low:
        return "App group (via SideloadFix)"
    if rel.endswith(".binarycookies") or "/cookies/" in low:
        return "Cookies"
    if "/keyboard/" in low and rel.endswith(".dat"):
        return "Keyboard cache"
    if rel.endswith((".sqlite", ".sqlite3", ".db", "-wal", "-shm", "-journal")) or low.endswith("cache.db"):
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


# ---- binarycookies ------------------------------------------------------------

def parse_binarycookies(raw: bytes) -> list[dict]:
    """Best-effort parser for Library/Cookies/*.binarycookies. Returns
    [{name, domain, path, value, secure, httponly}]; never raises."""
    out: list[dict] = []
    try:
        if raw[:4] != b"cook":
            return out
        n_pages = struct.unpack(">I", raw[4:8])[0]
        sizes = [struct.unpack(">I", raw[8 + 4 * i:12 + 4 * i])[0] for i in range(n_pages)]
        off = 8 + 4 * n_pages
        for size in sizes:
            page = raw[off:off + size]
            off += size
            if page[:4] != b"\x00\x00\x01\x00":
                continue
            n = struct.unpack("<I", page[4:8])[0]
            offsets = [struct.unpack("<I", page[8 + 4 * i:12 + 4 * i])[0] for i in range(n)]
            for co in offsets:
                c = page[co:]
                if len(c) < 56:
                    continue
                flags = struct.unpack("<I", c[8:12])[0]
                u_off, n_off, p_off, v_off = struct.unpack("<IIII", c[16:32])

                def s(o):
                    end = c.find(b"\x00", o)
                    return c[o:end if end >= 0 else len(c)].decode("utf-8", "replace")
                out.append({"domain": s(u_off), "name": s(n_off), "path": s(p_off),
                            "value": s(v_off), "secure": bool(flags & 1),
                            "httponly": bool(flags & 4)})
    except Exception:  # noqa: BLE001 - malformed file, keep what we have
        pass
    return out


# ---- container walk -------------------------------------------------------------

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
        if rel.endswith(("-wal", "-shm", "-journal")):
            continue   # folded into the database they belong to (see _scan_sqlite)
        try:
            raw = p.read_bytes()
        except OSError:
            continue
        head = raw[:_MAX_FILE]

        # 1) Known secret patterns (tokens, keys, JWTs, private keys, ...).
        for s in scan_secrets(head).get("findings", []):
            findings.append({"store": store, "file": rel, "type": s["type"],
                             "severity": s["severity"],
                             "detail": (s.get("value") or "")[:80]})

        # 2) Sensitive keys/values in plists (NSUserDefaults et al.). Whole
        #    file: a truncated plist does not parse at all.
        if rel.endswith(".plist"):
            pairs = _plist_pairs(raw)
            for key, val in pairs:
                sev = _key_severity(key) if val else None
                if sev:
                    findings.append({"store": store, "file": rel,
                                     "type": f"sensitive key: {key}", "severity": sev,
                                     "detail": val[:60]})
                elif val and _find_email(val):
                    findings.append({"store": store, "file": rel,
                                     "type": "email in stored value", "severity": "medium",
                                     "detail": val[:60]})
            if pairs and store in ("NSUserDefaults", "Property list", "App group (via SideloadFix)"):
                findings.append({"store": store, "file": rel,
                                 "type": f"{len(pairs)} value(s) stored in a file",
                                 "severity": "info", "detail": ", ".join(
                                     sorted({k.split('.')[0] for k, _ in pairs})[:6])})

        # 3) SQLite / Core Data: open a WAL-complete copy, enumerate tables + rows.
        if store == "SQLite / Core Data" and len(raw) > 64:
            try:
                findings += _scan_sqlite(p, store, rel)
            except (sqlite3.DatabaseError, OSError) as e:   # never abort the walk
                findings.append({"store": store, "file": rel, "severity": "info",
                                 "type": "sqlite file not readable (encrypted?)",
                                 "detail": str(e)[:80]})
        # 4) Cookies: parse, flag sensitive names / secret-shaped values.
        elif store == "Cookies" and rel.endswith(".binarycookies"):
            findings += _scan_cookies(raw, store, rel)
        # Other stores: just note presence.
        elif store in ("Realm", "Keyboard cache") and len(raw) > 64:
            findings.append({"store": store, "file": rel,
                             "type": f"{store} present", "severity": "info",
                             "detail": f"{len(raw)} bytes"})
    return findings, stores


def _scan_cookies(raw: bytes, store: str, rel: str) -> list[dict]:
    out: list[dict] = []
    cookies = parse_binarycookies(raw)
    if not cookies:
        return [{"store": store, "file": rel, "severity": "info",
                 "type": "Cookies present (not parseable)", "detail": f"{len(raw)} bytes"}]
    hits = 0
    for c in cookies:
        sev = _key_severity(c["name"])
        secretish = scan_secrets(c["value"].encode("utf-8", "replace")).get("findings", [])
        if sev or secretish:
            flags = ("secure" if c["secure"] else "NOT secure") + ", " + \
                    ("httponly" if c["httponly"] else "NOT httponly")
            out.append({"store": store, "file": rel, "severity": sev or secretish[0]["severity"],
                        "type": f"cookie '{c['name']}' for {c['domain']} ({flags})",
                        "detail": (secretish[0]["type"] if secretish else "sensitive name")})
            hits += 1
            if hits >= 8:
                break
    out.append({"store": store, "file": rel, "severity": "info",
                "type": f"{len(cookies)} cookie(s) persisted",
                "detail": ", ".join(sorted({c['domain'] for c in cookies})[:5])})
    return out


def _scan_sqlite(path, store: str, rel: str) -> list[dict]:
    """Open a pulled SQLite DB and scan rows for secrets / sensitive columns.

    The database is copied TOGETHER WITH its -wal / -shm sidecars into a temp
    directory and opened read-only there. Core Data stores run in WAL mode, so
    everything the app wrote during the run sits in the -wal file; the old
    `immutable=1` open disabled the WAL and saw the pre-run contents (or
    failed to open). A file that still will not open (SQLCipher, truncated,
    not SQLite) yields one info finding and the walk CONTINUES."""
    out: list[dict] = []
    unreadable = {"store": store, "file": rel, "severity": "info",
                  "type": "sqlite file not readable (encrypted?)", "detail": ""}
    path = Path(path)
    tmp = Path(tempfile.mkdtemp(prefix="havva_db_"))
    try:
        for side in ("", "-wal", "-shm", "-journal"):
            src = Path(str(path) + side)
            if src.is_file():
                shutil.copy2(src, tmp / (path.name + side))
        copy = tmp / path.name
        try:
            con = sqlite3.connect(f"file:{copy}?mode=ro", uri=True, timeout=3)
        except (sqlite3.DatabaseError, OSError) as e:
            return [{**unreadable, "detail": str(e)[:80]}]
        try:
            cur = con.cursor()
            try:
                tables = [r[0] for r in cur.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "AND name NOT LIKE 'sqlite_%'").fetchall()]
            except (sqlite3.DatabaseError, OSError) as e:
                # "file is not a database" surfaces on the first query, not on connect.
                return [{**unreadable, "detail": str(e)[:80]}]
            for t in tables:
                try:
                    n = cur.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
                    cur.execute(f'SELECT * FROM "{t}" LIMIT 25')
                    cols = [d[0] for d in (cur.description or [])]
                    rows = cur.fetchall()
                except (sqlite3.DatabaseError, OSError):
                    continue
                sens = [(c, _key_severity(c)) for c in cols if c and _key_severity(c)]
                if sens:
                    top = max((s for _, s in sens), key=lambda s: _SEV_ORDER[s])
                    out.append({"store": store, "file": rel, "severity": top,
                                "type": f"SQLite table '{t}' has sensitive column(s): "
                                        f"{', '.join(c for c, _ in sens[:4])}",
                                "detail": f"{n} rows · cols: {', '.join(cols[:8])}"})
                hits = 0
                for row in rows:
                    text = " ".join("" if v is None else str(v) for v in row)
                    for s in scan_secrets(text.encode("utf-8", "replace")).get("findings", []):
                        out.append({"store": store, "file": rel, "severity": s["severity"],
                                    "type": f"SQLite '{t}': {s['type']}",
                                    "detail": (s.get("value") or "")[:60]})
                        hits += 1
                    em = _find_email(text)
                    if em:
                        out.append({"store": store, "file": rel, "severity": "medium",
                                    "type": f"SQLite '{t}': email in row", "detail": em[:60]})
                        hits += 1
                    if hits >= 6:
                        break
                if not sens and not hits:
                    out.append({"store": store, "file": rel, "severity": "info",
                                "type": f"SQLite table '{t}' ({n} rows)",
                                "detail": f"cols: {', '.join(cols[:8])}"})
        finally:
            con.close()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return out


# ---- StorageObserver trail ----------------------------------------------------

_OBS_FILE_RE = re.compile(r"STORAGEOBS FILE (\S+) (\d+) (.+?)\s*$")
_OBS_KC_RE = re.compile(r"STORAGEOBS KEYCHAIN (.+?)\s*$")
_OBS_BEGIN_RE = re.compile(r"STORAGEOBS BEGIN (\d+)")
_OBS_END_RE = re.compile(r"STORAGEOBS END (\d+)")

# kSecAttrAccessible codes -> name; the two 'Always' classes are the weak ones.
KEYCHAIN_ACCESSIBLE = {
    "ak": "WhenUnlocked", "ck": "AfterFirstUnlock", "dk": "Always",
    "akpu": "WhenPasscodeSetThisDeviceOnly", "aku": "WhenUnlockedThisDeviceOnly",
    "cku": "AfterFirstUnlockThisDeviceOnly", "dku": "AlwaysThisDeviceOnly",
}
_WEAK_KEYCHAIN = {"dk", "dku"}
_WEAK_FILE = "NSFileProtectionNone"


def parse_observer(syslog_text: str) -> dict:
    """StorageObserver trail -> {'files': {rel: protection}, 'keychain': [attrs],
    'dumps': n, 'loaded': bool}. The LAST complete dump wins (it reflects what
    the run wrote); an incomplete trailing dump is merged on top of it."""
    res = {"files": {}, "keychain": [], "dumps": 0, "loaded": False}
    blocks: list[dict] = []
    cur: dict | None = None
    for line in (syslog_text or "").splitlines():
        if "STORAGEOBS" not in line:
            continue
        if "STORAGEOBS LOADED" in line:
            res["loaded"] = True
            continue
        if _OBS_BEGIN_RE.search(line):
            cur = {"files": {}, "keychain": [], "complete": False}
            blocks.append(cur)
            continue
        if cur is None:
            continue
        m = _OBS_FILE_RE.search(line)
        if m:
            cur["files"][m.group(3)] = m.group(1)
            continue
        m = _OBS_KC_RE.search(line)
        if m:
            attrs = {}
            for tok in m.group(1).split():
                if "=" in tok:
                    k, v = tok.split("=", 1)
                    attrs[k] = v
            cur["keychain"].append(attrs)
            continue
        if _OBS_END_RE.search(line):
            cur["complete"] = True
    complete = [b for b in blocks if b["complete"]]
    base = complete[-1] if complete else (blocks[-1] if blocks else None)
    if base:
        res["files"] = dict(base["files"])
        res["keychain"] = list(base["keychain"])
        if blocks and blocks[-1] is not base:
            res["files"].update(blocks[-1]["files"])
    res["dumps"] = len(complete)
    return res


def _protection_for(files: dict, rel: str) -> str | None:
    """Match a pulled path to an observer path (the pull may or may not keep
    the top-level directory name)."""
    if rel in files:
        return files[rel]
    for obs, cls in files.items():
        if obs.endswith("/" + rel) or rel.endswith("/" + obs):
            return cls
    return None


def _bump(sev: str) -> str:
    return _SEV_NAMES[min(_SEV_ORDER.get(sev, 0) + 1, 3)]


def apply_observer(findings: list[dict], stores: dict, obs: dict) -> tuple[list[dict], dict]:
    """Attach Data Protection classes to file findings (bumping severity for
    NSFileProtectionNone) and add Keychain findings from the observer trail."""
    if not obs or not (obs.get("files") or obs.get("keychain")):
        return findings, stores
    out: list[dict] = []
    for f in findings:
        g = dict(f)
        cls = _protection_for(obs.get("files", {}), f.get("file", ""))
        if cls:
            g["protection"] = cls
            if cls == _WEAK_FILE and f["severity"] != "info":
                g["severity"] = _bump(f["severity"])
                g["type"] = f["type"] + " [NSFileProtectionNone]"
        out.append(g)
    kc = obs.get("keychain", [])
    for it in kc:
        acc = it.get("acc", "-")
        name = KEYCHAIN_ACCESSIBLE.get(acc, acc)
        label = it.get("svce") if it.get("svce", "-") != "-" else it.get("labl", "-")
        if acc in _WEAK_KEYCHAIN:
            out.append({"store": "Keychain", "file": f"{it.get('class', '?')}:{label}",
                        "severity": "high",
                        "type": f"Keychain item accessible {name} (readable without unlock)",
                        "detail": f"group {it.get('agrp', '-')}, account length {it.get('acct_len', '?')}"})
        else:
            out.append({"store": "Keychain", "file": f"{it.get('class', '?')}:{label}",
                        "severity": "info", "type": f"Keychain item accessible {name}",
                        "detail": f"group {it.get('agrp', '-')}"})
    stores = dict(stores)
    if kc:
        stores["Keychain"] = len(kc)
    return out, stores


# ---- verdict -------------------------------------------------------------------

_TOKEN_TYPES = ("JWT", "Bearer token", "sensitive key", "sensitive column", "cookie",
                "Google API key", "Stripe pub key")


def verdict_of(findings: list[dict], observed: bool | None = None) -> tuple[str, str]:
    """Tiered verdict:
      credentials_exposed  a high: password / private key / live secret key in a
                           file, or a Keychain item readable without unlock
      tokens_in_files      a medium token / session / API key in a file or cookie
      pii_in_files         only e-mail addresses in files
      data_only            files hold data, nothing sensitive matched
      clean                nothing in the inspected stores
    `observed` says whether StorageObserver supplied protection classes; when
    it did not, the note says the file class is unknown."""
    sev = {f.get("severity") for f in findings}
    tail = "" if observed else (
        " Data Protection classes unknown (StorageObserver trail missing); files are class C by default."
        if observed is False else "")
    weak_files = sum(1 for f in findings if f.get("protection") == _WEAK_FILE)
    wf = f" {weak_files} finding(s) are in NSFileProtectionNone files." if weak_files else ""
    if "high" in sev:
        return "credentials_exposed", ("Credentials, keys or always-readable Keychain items found "
                                       "outside protected storage." + wf + tail)
    if "medium" in sev:
        med = [f for f in findings if f.get("severity") == "medium"]
        if all("email" in f.get("type", "") for f in med):
            return "pii_in_files", "E-mail addresses stored in files; no credential or token matched." + wf + tail
        return "tokens_in_files", ("Tokens, session identifiers or API keys stored in files "
                                   "instead of the Keychain." + wf + tail)
    if sev & {"low", "info"}:
        return "data_only", "Files hold data but no credential, token or PII was matched. Review manually." + tail
    return "clean", "No data found in the inspected stores." + tail
