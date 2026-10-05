# Login Automation Design

**Date:** 2026-10-05
**Status:** Draft for review
**Context:** The App Attest enforcement probe and the usage detector both need the app in an
authenticated, gated state to measure anything. Automating login is the gating blocker. This
spec covers the two flows we can realistically automate on a non-jailbroken iPhone XR driven by
Appium/WebDriverAgent.

## Goal
Get a target app from launch to a logged-in state where attestation-gated requests fire, with
as little human involvement as possible, for the sample tier (hundreds of apps), not 7,000.

## Scope decisions
- **Phone number + Google Voice OTP** — fully automatable. PRIMARY flow.
- **"Continue with Google"** — best-effort automatable, with a manual-assisted fallback.
- **"Sign in with Apple"** — OUT OF SCOPE. The confirmation is Face ID / side-button on the
  XR and cannot be scripted. Dropped per decision 2026-10-05.
- Email/password heuristic login already exists in `device.py` and is unchanged here.

## Platform constraints (the hard facts)
- `ASWebAuthenticationSession` (what Google Sign-In and most OAuth use) runs in a separate
  system process (SafariViewService). Appium/WDA **cannot see or tap inside it.** So we can
  never type a Google password or tap an in-sheet account picker.
- What IS accessible: the app's own "Continue with Google" button, and the iOS **native
  consent alert** ("<App> Wants to Use google.com to Sign In") via Appium's alert API.
- Therefore Google only completes automatically when the Google web session is **warm** (the
  account is already signed in in Safari's shared cookie jar) AND the app+account pairing was
  authorized before, so the sheet auto-dismisses after the native alert. First-time consent
  with an in-sheet picker falls back to manual.
- The OTP for a phone login goes to the **Google Voice cloud number, not the device**, so we
  read the code from Google's side, not from iOS Messages (no on-device SMS autofill applies).

## Architecture
Three pieces:

1. **`pipeline/otp.py` (new)** — Gmail-API OTP retriever. Pure parsing split from I/O so it is
   unit-testable. Reads the throwaway Google account's inbox (Google Voice is configured to
   forward texts to that Gmail), finds the newest message matching a recency window + optional
   sender/keyword filter, and extracts the numeric code.

2. **Login strategies in `device.py`** — `_attempt_login` dispatches on `credentials["method"]`:
   - `"phone"` → phone + OTP flow (new).
   - `"google"` → Google-button flow (new, best-effort).
   - `"native"` / `"google"(existing)` / `"auto"` → unchanged existing heuristics.

3. **`accounts.json` schema** — per-app credential records carry the method and its parameters.

## Data: accounts.json schema
Keyed by app_id or bundle_id (unchanged lookup). New method shapes:
```json
{
  "547702041": { "method": "phone", "phone": "+1XXXXXXXXXX", "otp_from": "voice" },
  "328415391": { "method": "google" }
}
```
- `phone`: the Google Voice number to type.
- `otp_from`: reserved; "voice" = expect a Google-Voice-forwarded SMS in Gmail. Default "voice".
- `google` method needs no secret in the file; it relies on the warm Safari session.

## Flow 1: Phone + Google Voice OTP (primary)
Steps in `_login_phone(drv, creds)`:
1. Find the phone-number field (TextField with `keyboardType` phone, or the only visible
   TextField on a "enter your number" screen). Type `creds["phone"]`.
2. Tap a continue control (`_tap_label` with `Continue, Next, Send code, Get code, Submit`).
3. Record `t0 = now()`. Call `otp.fetch(after=t0, timeout=90)`.
4. Find the code field(s) (a single field, or N single-digit boxes). Type the code (per-box if
   multiple fields are present).
5. Tap continue/verify. Return `success` if a post-login view appears, else `attempted`.

`otp.fetch(after, timeout, poll=5)`:
- Poll the Gmail API every `poll` seconds until `timeout`.
- Query: `newer_than:1h` plus the configured sender filter (Google Voice forwards from a
  `...@txt.voice.google.com` / `@voice.google.com` style address; make the filter configurable).
- Of messages with `internalDate >= after`, take the newest, pull the text/plain body.
- Extract the code with `_extract_code(body)` (pure): first match of `\b(\d{4,8})\b` near words
  like "code", "verification", "OTP"; fall back to the first standalone 4-8 digit run.
- Return the code string, or `None` on timeout.

### Gmail API auth
- Use `google-api-python-client` + `google-auth` (new deps).
- One-time OAuth: a `credentials.json` (OAuth client) → consent → store `token.json`.
- Both files live under `results/` (gitignored) or a path from `.env`:
  `GMAIL_CREDENTIALS` (default `results/gmail_credentials.json`),
  `GMAIL_TOKEN` (default `results/gmail_token.json`),
  `GV_SENDER` (default `voice.google.com`, the forwarding sender filter).
- Scope: `https://www.googleapis.com/auth/gmail.readonly`.
- If the token/credentials are missing, `otp.fetch` logs a clear error and returns `None`
  (the login reports `attempted`, the probe stays INCONCLUSIVE, never crashes).

## Flow 2: Google button (best-effort)
Steps in `_login_google_button(drv)`:
1. `_tap_label(Continue with Google, Sign in with Google, Sign in with Google, Google)`.
2. `_accept_native_alert` (existing) to accept the "Wants to Use google.com" consent alert.
3. Wait briefly for the sheet to auto-dismiss (warm session). Poll the app view for a
   logged-in signal (absence of the login button / presence of a known post-login element).
4. If still on the sheet after a timeout, return `attempted` and log
   "google sheet needs manual consent" — the manual-assisted path (existing manual mode)
   takes over.
- No typing is attempted inside the sheet (impossible). This flow is a tap-and-hope that
  succeeds on warm, pre-authorized sessions and degrades to manual otherwise.

## One-time operator setup (documented, not automated)
1. Throwaway Google account with a Google Voice number.
2. Google Voice → Settings → Messages → **Forward messages to email** ON.
3. Create a Gmail OAuth client, run the one-time consent, drop `gmail_credentials.json` /
   `gmail_token.json` in `results/`.
4. Sign that Google account into **Safari on the XR** once (warm session for the Google button).
5. Put per-app records in `results/accounts.json`.

## Error handling + security
- All Gmail/credential reads are best-effort: missing or invalid creds → clear log + `None`,
  never an exception that sinks the job.
- OTP codes and phone numbers are **never logged** (log "code received (N digits)" only).
- `results/` is gitignored; no secrets enter the repo.
- OTP freshness: only accept messages with `internalDate >= t0` to avoid reusing an old code;
  enforce a max age (1h) as a backstop.

## Files
- Create: `pipeline/otp.py` (Gmail client + pure `_extract_code`, `_select_message`).
- Modify: `pipeline/device.py` (`_attempt_login` dispatch, `_login_phone`, `_login_google_button`).
- Modify: `requirements.txt` (`google-api-python-client`, `google-auth`, `google-auth-oauthlib`).
- Modify: `.env.example` (GMAIL_CREDENTIALS, GMAIL_TOKEN, GV_SENDER).
- Docs: a short "login setup" note (operator steps above).

## Testing
- `_extract_code` — unit tests over real Google-Voice-forwarded SMS bodies (code present,
  code absent, multiple numbers, "code: 123456", "G-123456").
- `_select_message` — pure function picking the newest message after `t0` from a list of
  {internalDate, from, body}; tests for recency and sender filtering.
- `_login_phone` / `_login_google_button` — not unit-tested (device I/O); validated manually
  on one phone-login app (e.g. Tinder with the GV number) and one Google-button app.

## Out of scope / deferred
- Sign in with Apple (biometric, un-scriptable).
- Vision/LLM-driven driver (separate future option).
- Authenticated-state snapshot/restore.
- Account provisioning automation (operator creates accounts by hand).

## Open questions
1. Exact Google Voice forwarding sender address to filter on (confirm from a real forwarded
   message; `GV_SENDER` is configurable to cover it).
2. Whether to also support reading OTP straight from voice.google.com as a fallback if the
   Gmail forward is flaky (deferred unless needed).
