"""Typed-decision fallback for the login navigator (Jev / TypeSafe AI).

When the heuristic navigator cannot decide which on-screen control advances toward
login, it enumerates the visible accessibility labels and asks Jev, a non-generative
"System One" model that returns a typed choice with a calibrated confidence, to pick
one (or decline). A separate yes/no (noul) check asks whether the login / phone
screen has been reached.

Text-only by design: we send element LABELS and short screen context, never
credentials, OTPs, or screenshots. Best-effort: any failure (no key, network,
low confidence) returns None/False so the navigator falls back to swiping, and the
whole module is optional (the heuristics work without it).

Config (env / .env): JEV_API_KEY (required to enable), JEV_URL, JEV_MODEL.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request

from .config import CONFIG
from .util import get_logger

log = get_logger("llm_driver", CONFIG.paths.log_dir)

_URL = os.environ.get("JEV_URL", "https://api.typesafe.ai/v1/systemone")
_MODEL = os.environ.get("JEV_MODEL", "jev-latest")
_UA = "Mozilla/5.0"  # TypeSafe's edge blocks empty user agents


def available() -> bool:
    """True if a Jev API key is configured (the fallback is opt-in)."""
    return bool(os.environ.get("JEV_API_KEY"))


def _post(body: dict, timeout: int = 20) -> dict | None:
    key = os.environ.get("JEV_API_KEY")
    if not key:
        return None
    req = urllib.request.Request(
        _URL, data=json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json",
                 "User-Agent": _UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        log.warning("jev HTTP %s: %s", e.code, e.read().decode(errors="replace")[:160])
    except Exception as e:  # noqa: BLE001 - never let the fallback break a run
        log.warning("jev request failed: %s", e)
    return None


def choose_next_control(candidates: list[str], screen_summary: str = "",
                        min_conf: float = 0.6) -> str | None:
    """Ask Jev which visible control best advances toward a login / phone-entry
    screen. `candidates` are on-screen tappable labels. Returns the chosen label
    (verbatim from `candidates`) when confidence >= min_conf, else None. 'none' is
    always offered so Jev can decline rather than force a tap."""
    cands = list(dict.fromkeys(c.strip() for c in candidates if c and c.strip()))[:20]
    if not cands:
        return None
    # Key options by index so arbitrary label text never breaks the criteria map.
    crit = {f"opt{i}": c for i, c in enumerate(cands)}
    crit["none"] = "no control makes forward progress (e.g. only page dots on an image carousel)"
    state = (screen_summary or "A mobile app screen shown during startup/onboarding.") + \
        "\nVisible tappable controls: " + ", ".join(f"'{c}'" for c in cands)
    resp = _post({"model": _MODEL, "state": state, "questions": {"pick": {
        "type": "choice",
        "instructions": (
            "Goal: advance this app toward its sign-in / log-in screen. Pick the "
            "SINGLE control that makes forward progress: the primary call-to-action "
            "that continues past a welcome, intro, carousel, consent, or permission "
            "screen (e.g. 'Start Messaging', 'Get Started', 'Continue', 'Next', "
            "'Agree and continue', 'Allow'), OR an explicit sign-in control ('Log "
            "in', 'Sign in', 'Continue with phone/Google/Apple'). Do NOT pick "
            "controls that open unrelated content, settings, help, language pickers, "
            "or that dismiss/cancel. Choose 'none' only if nothing makes forward "
            "progress."),
        "criteria": crit}}})
    try:
        ans = _answer(resp, "pick")
        choice = ans.get("choice")
        conf = _as_float(ans.get("confidence"))
        if not isinstance(choice, str) or not choice or choice == "none" or conf < min_conf:
            log.info("jev: no confident advance (choice=%s conf=%.2f)", choice, conf)
            return None
        idx = _opt_index(choice, len(cands))
        if idx is None:
            log.info("jev: unusable choice %r", choice)
            return None
        label = cands[idx]
        log.info("jev chose %r (conf %.2f)", label, conf)
        return label
    except Exception as e:  # noqa: BLE001 - the fallback must never break a run
        log.warning("jev: malformed response (%s)", e)
        return None


def _answer(resp, key: str) -> dict:
    """The `answers[key]` object from a Jev response, or {} when the response is
    not shaped like one (None, non-dict, missing keys, wrong types)."""
    if not isinstance(resp, dict):
        return {}
    answers = resp.get("answers")
    if not isinstance(answers, dict):
        return {}
    ans = answers.get(key)
    return ans if isinstance(ans, dict) else {}


def _as_float(v, default: float = 0.0) -> float:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return default
    return f if f == f else default  # NaN -> default


_OPT_RE = re.compile(r"^opt(\d+)$")


def _opt_index(choice: str, n: int) -> int | None:
    """Index for an 'opt<N>' choice if 0 <= N < n; None otherwise (rejects
    'opt-1', 'opt', 'optx', and out-of-range indices)."""
    m = _OPT_RE.match(choice.strip())
    if not m:
        return None
    idx = int(m.group(1))
    return idx if 0 <= idx < n else None


def login_goal_reached(screen_summary: str, min_yes: float = 0.6) -> bool:
    """Ask Jev (yes/no) whether the current screen is the login / phone-entry goal."""
    resp = _post({"model": _MODEL, "state": screen_summary, "questions": {"goal": {
        "type": "noul",
        "instructions": "Is this the app's sign-in / log-in screen, i.e. are login "
                        "inputs ready (fields for email, phone, username, or "
                        "password) or explicit sign-in options (e.g. 'Continue with "
                        "Google/Apple', 'Log in with phone number')?"}}})
    try:
        return _as_float(_answer(resp, "goal").get("noul")) >= min_yes
    except Exception as e:  # noqa: BLE001
        log.warning("jev: malformed goal response (%s)", e)
        return False
