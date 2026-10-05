"""In-app-purchase / subscription bypass detection (from paper 1's phase_2).

Feeds the app's decrypted IAP-related MITM traffic to Meta's Llama API and asks
whether any request/response field is client-tamperable to bypass a purchase or
subscription (i.e. the app trusts a client-visible value instead of verifying
server-side). Verdict: tamperable (bypassable) or not.

The URL include/exclude keyword lists, the prompt (system + few-shot), the input
format (<=10 flows, 2000/12000 char caps), and the JSON verdict schema are ported
verbatim from the previous project so results stay comparable.
"""

from __future__ import annotations

import json
import re

from .config import CONFIG
from .models import Flow
from .util import get_logger

log = get_logger("iap", CONFIG.paths.log_dir)

# URL substrings that mark an IAP / subscription / entitlement request.
IAP_URL_PATTERNS = [
    "validate", "verify", "check", "confirm",
    "receipt", "receipts", "verify_receipt", "validate_receipt",
    "check_receipt", "verifyreceipt",
    "subscription", "subscriptions", "validate_subscription",
    "verify_subscription", "check_subscription", "subscription_status",
    "purchase", "purchases", "validate_purchase", "verify_purchase",
    "check_purchase", "purchase_status",
    "iap", "in_app", "inapp", "in-app",
    "premium", "unlock", "unlocked", "upgrade", "full_version",
    "transaction", "transactions", "validate_transaction",
    "payment", "payments", "validate_payment", "verify_payment",
    "license", "licenses", "validate_license", "verify_license",
    "entitlement", "entitlements", "validate_entitlement",
    "feature", "features", "validate_feature",
    "validate_product", "verify_product",
    "active", "expired", "trial", "billing",
    "appstore", "sandbox", "production",
    "api.storekit", "/inApps/v1/", "/inApps/v2/",
    "auth", "authorize", "token", "tokens",
]

# Third-party / infra domains excluded even if they match an include keyword.
EXCLUDE_PATTERNS = [
    "facebook", "google", "amazon", "amzn", "unity3d", "applovin",
    "moloco", "appsflyer", "itunes.apple.com/lookup",
    "launchdarkly", "sentry.io", "firebaselogging", "slack.com",
    "branch.io", "onesignal.com", "mzstatic.com", "appmetrica",
    "itunes", "mixpanel",
    "moengage.com", "app-ads-services.com", "adjust.com",
    "amplitude.com", "clevertap.com", "airbridge.io",
    "icloud", "sandbox.apple.com",
]


def is_iap_request(url: str) -> bool:
    """Exclude wins first, then any include keyword marks it IAP-relevant."""
    low = (url or "").lower()
    if any(x in low for x in EXCLUDE_PATTERNS):
        return False
    return any(p in low for p in IAP_URL_PATTERNS)


def iap_flows(flows: list[Flow]) -> list[Flow]:
    return [f for f in flows if f.url and is_iap_request(f.url)]


def _bodies_text(flows: list[Flow]) -> str:
    text = ""
    for i, f in enumerate(flows[:10]):          # <= 10 flows
        text += f"\n--- Flow {i+1}: {f.method} {f.url} (Status: {f.status}) ---\n"
        if f.request_body:
            text += f"REQUEST BODY:\n{f.request_body[:2000]}\n"
        if f.response_body:
            text += f"RESPONSE BODY:\n{f.response_body[:2000]}\n"
    return text[:12000]                          # total cap


_SYSTEM_PROMPT = (
    "You are a security researcher analyzing network traffic from an iOS app. "
    "Your job is to identify fields in API request/response bodies that could be "
    "tampered with using a MITM proxy to bypass in-app purchase or subscription verification.\n\n"
    "IMPORTANT: Look very carefully for these patterns:\n"
    "- isValid: false → change to true\n"
    "- isEligible: false → change to true\n"
    "- isPremium: false → change to true\n"
    "- subscriptions: null → inject a fake subscription object\n"
    "- subscriptionStatus: expired/inactive → change to active\n"
    "- trialTaken: false → keep trial active\n"
    "- is_add_free: false → change to true to remove ads\n"
    "- expire_date / expiry_date in the past → change to a future date\n"
    "- status: 0 or status: 'expired' → change to 1 or 'active'\n"
    "- receipt validation responses with status codes\n"
    "- entitlements or feature flags that gate premium content\n"
    "- fromApple: 0 → change to 1\n"
    "- Any boolean or status field that controls access to paid features\n\n"
    "Respond ONLY with valid JSON in this exact format:\n"
    '{"tamperable": true, "fields": ["isValid", "isEligible"], "urls": ["https://api.example.com/subscription/status"], "method": "Change isValid from false to true to bypass subscription check"}\n\n'
    "If genuinely no tamperable fields exist, respond with:\n"
    '{"tamperable": false, "fields": [], "urls": [], "method": "none"}'
)
_FEWSHOT_EXAMPLE = (
    '--- Flow 1: POST https://api.example.com/subscription/status (Status: 200) ---\n'
    'RESPONSE BODY:\n'
    '{"isValid":false,"isPremium":false,"subscriptions":null,"trialTaken":false,"is_add_free":false}'
)
_FEWSHOT_ANSWER = ('{"tamperable": true, "fields": ["isValid", "isPremium", "subscriptions", '
                   '"trialTaken", "is_add_free"], "urls": ["https://api.example.com/subscription/status"], '
                   '"method": "Change isValid and isPremium to true, inject subscription object, set is_add_free to true"}')


def _messages(app_name: str, bodies: str) -> list[dict]:
    return [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": f"Analyze this traffic:\n\n{_FEWSHOT_EXAMPLE}"},
        {"role": "assistant", "content": _FEWSHOT_ANSWER},
        {"role": "user", "content": (
            f"Analyze the following network traffic from the app '{app_name}'. "
            f"Identify any fields that can be tampered to bypass in-app purchases or subscriptions:\n\n"
            f"{bodies}")},
    ]


def _parse_verdict(answer: str) -> dict:
    log.info("[iap] verdict: %s", answer[:300])
    m = re.search(r"\{.*\}", answer, re.DOTALL)
    if m:
        try:
            p = json.loads(m.group())
            return {"tamperable": bool(p.get("tamperable", False)),
                    "fields": p.get("fields", []), "urls": p.get("urls", []),
                    "method": p.get("method", ""), "analysis": answer, "error": ""}
        except json.JSONDecodeError:
            pass
    return {"tamperable": ("true" in answer.lower() and "tamperable" in answer.lower()),
            "fields": [], "urls": [], "method": "", "analysis": answer, "error": ""}


def _call_llama_api(messages: list[dict]) -> tuple[str, str]:
    """Meta hosted Llama API. Returns (answer, error)."""
    import requests
    llama = CONFIG.llama
    if not llama.api_key:
        return "", "LLAMA_API_KEY not set"
    payload = {"model": llama.model, "messages": messages, "max_tokens": 500, "temperature": 0}
    headers = {"Authorization": f"Bearer {llama.api_key}", "Content-Type": "application/json"}
    last = ""
    for _ in range(3):
        try:
            r = requests.post(llama.api_url, json=payload, headers=headers, timeout=120, verify=False)
            if r.status_code != 200:
                try:
                    j = r.json()
                    last = (j.get("detail") or j.get("error", {}).get("message") or f"HTTP {r.status_code}")
                except ValueError:
                    last = f"HTTP {r.status_code}"
                continue
            result = r.json()
            if "completion_message" in result:
                c = result["completion_message"].get("content", {})
                return (c.get("text", "") if isinstance(c, dict) else str(c)).strip(), ""
            if "choices" in result:
                return result["choices"][0].get("message", {}).get("content", "").strip(), ""
            last = "unrecognized response"
        except Exception as e:  # noqa: BLE001
            last = str(e)
    return "", last or "llama api call failed"


def _call_ollama(messages: list[dict]) -> tuple[str, str]:
    """Local Ollama (/api/chat). Returns (answer, error)."""
    import requests
    llama = CONFIG.llama
    try:
        r = requests.post(f"{llama.ollama_url.rstrip('/')}/api/chat", timeout=180,
                          json={"model": llama.ollama_model, "messages": messages,
                                "stream": False, "options": {"temperature": 0}})
        if r.status_code != 200:
            return "", f"ollama HTTP {r.status_code}: {r.text[:120]}"
        return (r.json().get("message", {}) or {}).get("content", "").strip(), ""
    except Exception as e:  # noqa: BLE001
        return "", f"ollama unreachable ({e}); run `ollama serve` and pull the model"


def analyze_with_llama(app_name: str, flows: list[Flow]) -> dict:
    """Ask the configured LLM whether the IAP traffic is tamperable. Returns
    {tamperable, fields, urls, method, analysis, error}."""
    empty = {"tamperable": False, "fields": [], "urls": [], "method": "", "analysis": ""}
    if not flows:
        return {**empty, "error": "no IAP flows"}
    bodies = _bodies_text(flows)
    if not bodies.strip():
        return {**empty, "error": "empty bodies"}
    messages = _messages(app_name, bodies)
    if CONFIG.llama.provider == "ollama":
        answer, err = _call_ollama(messages)
    else:
        answer, err = _call_llama_api(messages)
    if err:
        return {**empty, "error": err}
    if not answer:
        return {**empty, "error": "empty LLM response"}
    return _parse_verdict(answer)
