"""Google Voice OTP retrieval via the Gmail API.

Google Voice is configured to forward incoming SMS to a throwaway Gmail account;
during a phone-number login we poll that inbox for the verification code. The
SMS lands in the cloud (the GV number), not on the device, so there is no iOS
SMS autofill to read, we must read it from Gmail.

Pure parsing (`_extract_code`, `_select_message`) is split from the Gmail I/O so
it is unit-tested without network or credentials. Codes are never logged.
"""
from __future__ import annotations

import base64
import os
import re
import time
from pathlib import Path

from .config import CONFIG
from .util import get_logger

log = get_logger("otp", CONFIG.paths.log_dir)

GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"

_G_CODE = re.compile(r"\bG-(\d{4,8})\b")
_CODE_NEAR = re.compile(
    r"(?:code|verification|verify|otp|passcode|pin|one[\s-]?time)[^0-9]{0,24}(\d{4,8})", re.I)
_STANDALONE = re.compile(r"(?<!\d)(\d{4,8})(?!\d)")

# Clock skew tolerated between Gmail's internalDate and our local `after`
# timestamp: a message stamped slightly before we started waiting still counts.
CLOCK_SKEW_MS = 30_000


def _looks_like_year(c: str) -> bool:
    return len(c) == 4 and c.startswith(("19", "20"))

# Google Voice wraps the SMS text in boilerplate (links, the sender's number, a
# footer). Those contain digit runs that are NOT the code, so for the standalone
# fallback we first isolate the actual message text and strip that noise.
_GV_FOOTER = re.compile(
    r"(to respond to this text message|your account\b|get the google voice app|"
    r"this message was sent|unsubscribe)", re.I)
_URL = re.compile(r"https?://\S+")
_PHONE = re.compile(r"\+?\d{0,3}[\s.()\-]*\(?\d{3}\)?[\s.()\-]*\d{3}[\s.()\-]*\d{4}")


def _clean_sms_body(body: str) -> str:
    """Strip Google Voice email boilerplate so the standalone-number fallback only
    sees the actual SMS text: cut at the first footer marker, drop URLs and
    phone-number-shaped runs (both carry spurious digit runs)."""
    m = _GV_FOOTER.search(body)
    if m:
        body = body[:m.start()]
    body = _URL.sub(" ", body)
    body = _PHONE.sub(" ", body)
    return body


def _extract_code(body: str | None) -> str | None:
    """Pull a 4-8 digit verification code out of an SMS/email body. Prefers the
    Google 'G-123456' form, then a digit run next to a code-ish keyword, then (only
    after stripping Google Voice boilerplate) the first standalone run, skipping
    4-digit years. Returns None when the message carries no code (e.g. 'Test')."""
    if not body:
        return None
    m = _G_CODE.search(body)
    if m:
        return m.group(1)
    # Keyword path: the first keyword-adjacent run that is not a 4-digit year
    # ("Use 1234 to verify. Sent at 2024" -> 1234, never 2024).
    for m in _CODE_NEAR.finditer(body):
        if not _looks_like_year(m.group(1)):
            return m.group(1)
    cands = [c for c in _STANDALONE.findall(_clean_sms_body(body))
             if not _looks_like_year(c)]
    if not cands:
        return None
    six = [c for c in cands if len(c) == 6]
    return six[0] if six else cands[0]


def _candidate_messages(messages: list[dict], after_ms: int,
                        sender_filter: str | None = None,
                        skew_ms: int = CLOCK_SKEW_MS) -> list[dict]:
    """All messages with internalDate >= after_ms - skew_ms (and matching
    sender_filter if given), newest first. messages: [{internalDate, from, body}]."""
    out = []
    for m in messages:
        try:
            ts = int(m.get("internalDate", 0))
        except (TypeError, ValueError):
            ts = 0
        if ts < after_ms - skew_ms:
            continue
        if sender_filter and sender_filter.lower() not in str(m.get("from", "")).lower():
            continue
        out.append((ts, m))
    out.sort(key=lambda t: t[0], reverse=True)
    return [m for _, m in out]


def _select_message(messages: list[dict], after_ms: int,
                    sender_filter: str | None = None) -> dict | None:
    """Newest candidate message (see `_candidate_messages`), or None."""
    cands = _candidate_messages(messages, after_ms, sender_filter)
    return cands[0] if cands else None


def _first_code(messages: list[dict], after_ms: int,
                sender_filter: str | None = None) -> str | None:
    """Walk candidate messages newest-first and return the first code found, so an
    unrelated newer message (a promo, 'Test') does not block an older OTP."""
    for m in _candidate_messages(messages, after_ms, sender_filter):
        code = _extract_code(m.get("body"))
        if code:
            return code
    return None


# ---- Gmail I/O --------------------------------------------------------------

def _env(key: str, default: str) -> str:
    return os.environ.get(key, default)


def _service():
    """Build a read-only Gmail service from the stored OAuth token, or None if the
    libraries or credentials are missing (caller treats None as 'no code')."""
    try:
        from google.auth.transport.requests import Request
        from google.oauth2.credentials import Credentials
        from googleapiclient.discovery import build
    except ImportError:
        log.error("google api libs missing; pip install google-api-python-client "
                  "google-auth google-auth-oauthlib")
        return None
    token = Path(_env("GMAIL_TOKEN", str(CONFIG.paths.results_dir / "gmail_token.json")))
    if not token.exists():
        log.error("gmail token missing: %s (run the one-time OAuth consent)", token)
        return None
    try:
        creds = Credentials.from_authorized_user_file(str(token), [GMAIL_SCOPE])
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
            token.write_text(creds.to_json())
        return build("gmail", "v1", credentials=creds, cache_discovery=False)
    except Exception as e:  # noqa: BLE001
        log.error("gmail auth failed: %s", e)
        return None


def _decode_body(payload: dict) -> str:
    """Walk a Gmail message payload for text/plain (preferred) or text/html."""
    def _data(p):
        b = (p.get("body") or {}).get("data")
        if not b:
            return ""
        return base64.urlsafe_b64decode(b + "===").decode("utf-8", "replace")

    stack, text, html = [payload], "", ""
    while stack:
        p = stack.pop()
        mt = p.get("mimeType", "")
        if mt == "text/plain":
            text += _data(p)
        elif mt == "text/html":
            html += _data(p)
        stack.extend(p.get("parts") or [])
    if text.strip():
        return text
    return re.sub(r"<[^>]+>", " ", html)


def fetch(after: float | None = None, timeout: int = 90, poll: int = 5,
          sender: str | None = None) -> str | None:
    """Poll Gmail for a Google-Voice-forwarded OTP newer than `after` (epoch secs).
    Returns the code string, or None on timeout / missing setup. Never raises."""
    svc = _service()
    if svc is None:
        return None
    after_ms = int((after if after is not None else time.time()) * 1000)
    sender = sender if sender is not None else _env("GV_SENDER", "voice.google.com")
    q = "newer_than:1h" + (f" from:{sender}" if sender else "")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = svc.users().messages().list(userId="me", q=q, maxResults=10).execute()
            msgs = []
            for ref in (resp.get("messages") or []):
                raw = svc.users().messages().get(
                    userId="me", id=ref["id"], format="full").execute()
                hdrs = {h["name"].lower(): h["value"]
                        for h in (raw.get("payload", {}).get("headers") or [])}
                msgs.append({"id": ref["id"], "internalDate": raw.get("internalDate", 0),
                             "from": hdrs.get("from", ""),
                             "body": _decode_body(raw.get("payload") or {})})
            code = _first_code(msgs, after_ms)  # sender already filtered in the query
            if code:
                log.info("otp: code received (%d digits)", len(code))
                return code
        except Exception as e:  # noqa: BLE001
            log.warning("otp poll error: %s", e)
        time.sleep(poll)
    log.warning("otp: no code within %ss", timeout)
    return None
