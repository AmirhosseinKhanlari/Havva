"""Static in-app-purchase security analysis.

Reads the decrypted binary's strings + symbol table (nm) + embedded framework
binaries to answer, without running the app:

  1. Does the app actually DO in-app purchases, and with which StoreKit generation?
       StoreKit 1  - ObjC SKPaymentQueue / SKPaymentTransaction + the legacy
                     base64 app-receipt. The bypassable generation: the receipt is
                     a static blob a MITM can forge the validation reply for.
       StoreKit 2  - Swift Transaction / AppTransaction carried as a JWS verified
                     on-device (currentEntitlements, jwsRepresentation). Forgery
                     needs Apple's key, so the client side is sound.

  2. Where purchase state is validated, and whether it is the known-weak path
     (deprecated verifyReceipt endpoint, or local on-device receipt parsing).

PRECISION NOTES (why symbol presence != IAP):
  * StoreKit is also linked for NON-IAP reasons: SKStoreReviewController ("rate
    us"), SKStoreProductViewController / SKOverlay (app promotion), SKAdNetwork
    (ad attribution). Those are tracked separately and never counted as IAP.
  * Only strong, IAP-unique tokens count. Generic names (VerificationResult) and a
    bare "verifyReceipt" substring are ignored - they over-match (e.g. Lyft, which
    offers no IAP, carries StoreKit for reviews/ads).
  * The App Store "offers IAP" flag (apps.has_iap) is passed in and reconciled: a
    no-IAP app with latent payment symbols is reported as latent, not vulnerable.
"""
from __future__ import annotations

# StoreKit 1 IAP (purchase/receipt) classes - genuinely IAP.
_SK1_IAP = [b"SKPaymentQueue", b"SKPaymentTransaction", b"SKMutablePayment",
            b"SKProductsRequest", b"SKProductsResponse", b"SKPaymentTransactionObserver",
            b"SKReceiptRefreshRequest", b"SKProductDiscount", b"SKPaymentDiscount",
            b"SKDownload"]

# StoreKit used for NON-IAP purposes (do NOT count as IAP).
_SK_NONIAP = {
    "review":    [b"SKStoreReviewController"],
    "promotion": [b"SKStoreProductViewController", b"SKOverlay"],
    "ads":       [b"SKAdNetwork", b"SKAdImpression"],
}

# StoreKit 2 IAP tokens. Two tiers (precision): `SubscriptionInfo`, `RenewalInfo`
# and `AppTransaction` alone are generic enough to appear in non-IAP code (SDK
# model types, dead code), so SK2 evidence is STRONG only when a unique token is
# present or at least two distinct generic tokens co-occur.
_SK2_STRONG = [b"jwsRepresentation", b"currentEntitlements", b"Product.PurchaseResult",
               b"unsafePayloadValue"]
_SK2_GENERIC = [b"AppTransaction", b"SubscriptionInfo", b"RenewalInfo", b"Transaction.updates"]
_SK2_IAP = _SK2_STRONG + _SK2_GENERIC

# Deprecated, MITM-bypassable verification endpoint - full host only (the bare
# "verifyReceipt" substring over-matches, so it is not used).
_VERIFYRECEIPT = [b"buy.itunes.apple.com/verifyReceipt",
                  b"sandbox.itunes.apple.com/verifyReceipt"]
# Modern server-to-Apple App Store Server API (the right way).
_SERVER_API = [b"api.storekit.itunes.apple.com", b"api.storekit-sandbox.itunes.apple.com",
               b"/inApps/v1/", b"/inApps/v2/"]
# On-device receipt handling: local app-receipt + PKCS#7 verification. Specific
# functions only - the generic "PKCS7_" prefix matches any bundled OpenSSL and
# over-fires (e.g. Lyft), so it is excluded.
_PKCS7 = [b"d2i_PKCS7", b"PKCS7_verify", b"PKCS7_dataDecode"]
_JWS = [b"jwsRepresentation"]  # SK2 on-device verification marker (strong)

_IAP_SDKS = {
    "RevenueCat": [b"RevenueCat", b"RCPurchases", b"api.revenuecat.com"],
    "Adapty":     [b"Adapty", b"api.adapty.io"],
    "Qonversion": [b"Qonversion", b"api.qonversion.io"],
    "Superwall":  [b"Superwall", b"api.superwall.com", b"superwall.me"],
    "Purchasely": [b"Purchasely", b"purchasely.com"],
    "Glassfy":    [b"Glassfy", b"api.glassfy.io"],
    "Nami":       [b"NamiML", b"nami.ml"],
}


def _hits(blob: bytes, tokens: list[bytes]) -> list[str]:
    return [t.decode() for t in tokens if t in blob]


def analyze(strings_blob: bytes = b"", nm_blob: bytes = b"",
            frameworks: dict | None = None, bundle_files: list[str] | None = None,
            app_store_has_iap: bool | None = None) -> dict:
    """Static IAP security profile. `app_store_has_iap` is the App Store "offers
    IAP" flag (apps.has_iap); pass None if unknown. `bundle_files` must be the
    FULL bundle namelist (the caller builds it from zf.namelist(), not from a
    capped file tree) so a shipped .storekit config is never missed.
    Best-effort, never raises."""
    blob = (strings_blob or b"") + b"\n" + (nm_blob or b"")
    bundle_files = bundle_files or []

    sk1_iap = _hits(blob, _SK1_IAP)
    sk2_all = _hits(blob, _SK2_IAP)
    sk2_strong = bool(_hits(blob, _SK2_STRONG)) or len(set(_hits(blob, _SK2_GENERIC))) >= 2
    # Only strong SK2 evidence drives the generation / validation logic; weak
    # single generic tokens are reported but do not count as IAP code.
    sk2_iap = sk2_all if sk2_strong else []
    noniap = {k: _hits(blob, toks) for k, toks in _SK_NONIAP.items()}
    noniap = {k: v for k, v in noniap.items() if v}
    iap_sdks = sorted(n for n, toks in _IAP_SDKS.items() if any(t in blob for t in toks))

    verifyreceipt = _hits(blob, _VERIFYRECEIPT)
    server_api = _hits(blob, _SERVER_API)
    jws = bool(_hits(blob, _JWS)) and bool(sk2_iap)
    on_device = (b"appStoreReceiptURL" in blob and any(t in blob for t in _PKCS7)
                 and bool(sk1_iap))
    storekit_cfg = sorted(f for f in bundle_files if f.lower().endswith(".storekit"))

    # Evidence strength. STRONG = unambiguous active-IAP signals; SK1 class
    # references alone are WEAK (present in apps that ship StoreKit for reviews/ads
    # or carry latent/SDK payment code, e.g. Lyft), so they are treated as latent
    # unless something else confirms an active flow. The App Store has_iap flag
    # CORROBORATES (True promotes), but is never used to suppress strong evidence,
    # because the flag is often a false negative in the corpus.
    strong_iap = bool(sk2_iap or iap_sdks or verifyreceipt or server_api or on_device)
    weak_iap = bool(sk1_iap) and not strong_iap
    active_iap = strong_iap or (app_store_has_iap is True)
    binary_iap_code = bool(sk1_iap or sk2_iap or iap_sdks)
    treat_as_iap = active_iap

    # StoreKit generation (IAP-relevant only; non-IAP StoreKit does not set this).
    if sk1_iap and sk2_iap:
        version = "both"
    elif sk2_iap:
        version = "2"
    elif sk1_iap:
        version = "1"
    elif iap_sdks:
        version = "sdk-only"
    else:
        version = "none"

    # Offering status (what to tell the user up top).
    if app_store_has_iap is True:
        offering = "store-listed"
    elif strong_iap:
        offering = "code-detected"      # binary clearly does IAP (flag may be wrong)
    elif weak_iap:
        offering = "latent"             # SK1 symbols only, no active flow confirmed
    else:
        offering = "none"

    # Validation path (only meaningful for apps that actually do IAP).
    if not treat_as_iap:
        location = "n/a"
    elif server_api:
        location = "server-apple-api"
    elif jws:
        location = "storekit2-jws"
    elif iap_sdks:
        location = "sdk"
    elif verifyreceipt:
        location = "client-verifyreceipt"
    elif on_device:
        location = "on-device-receipt"
    else:
        location = "unknown"

    findings: list[dict] = []

    def add(category, severity, matches):
        findings.append({"category": category, "severity": severity, "matches": matches[:8]})

    if treat_as_iap and verifyreceipt:
        add("Legacy verifyReceipt validation (deprecated, MITM-bypassable)", "high", verifyreceipt)
    if treat_as_iap and on_device and not server_api and not iap_sdks:
        add("On-device receipt validation (appStoreReceiptURL + PKCS#7)", "high",
            _hits(blob, _PKCS7) + ["appStoreReceiptURL"])
    if treat_as_iap and version == "1" and location in ("unknown", "on-device-receipt", "client-verifyreceipt"):
        add("StoreKit 1 receipt model; no App Store Server API / JWS verification visible "
            "in the binary (server-side validation to the app's own backend cannot be excluded)",
            "medium", sk1_iap)
    if storekit_cfg:
        add("StoreKit test configuration (.storekit) shipped in the bundle", "medium", storekit_cfg)
    if treat_as_iap and server_api:
        add("App Store Server API (server-side validation)", "info", server_api)
    if treat_as_iap and location == "storekit2-jws":
        add("StoreKit 2 with on-device JWS verification", "info", _hits(blob, _JWS))
    for name in iap_sdks:
        add(f"Managed IAP SDK: {name}", "info", [name])
    if weak_iap and not active_iap:
        add("StoreKit 1 payment symbols present but no active IAP flow confirmed "
            "(latent / SDK / dead code, or non-IAP StoreKit use)", "info", sk1_iap[:6])

    # Risk: only an active IAP flow can be vulnerable; latent symbols are info.
    if not active_iap:
        if weak_iap:
            risk, why = "info", "StoreKit 1 payment symbols present but no active IAP flow confirmed (latent / SDK)"
        else:
            risk, why = "info", "no active in-app purchase usage detected in the binary"
    elif location in ("client-verifyreceipt", "on-device-receipt"):
        risk, why = "high", "purchase state validated on a MITM-forgeable / on-device path"
    elif version == "1" and location == "unknown":
        risk, why = "medium", ("StoreKit 1 receipt model; no App Store Server API / JWS verification "
                               "visible in the binary (own-backend validation cannot be excluded)")
    elif location in ("server-apple-api", "storekit2-jws", "sdk"):
        risk, why = "low", "validation uses a signed / server-side path"
    else:
        risk, why = "medium", "IAP present but the validation path could not be determined"

    return {
        "offering": offering,                 # store-listed | none | code-detected | none-detected
        "app_store_has_iap": app_store_has_iap,
        "binary_iap_code": binary_iap_code,
        "has_storekit": bool(sk1_iap or sk2_iap or noniap),
        "storekit_version": version,
        "storekit_noniap_uses": sorted(noniap.keys()),   # review / promotion / ads
        "sk1_symbols": sk1_iap,
        "sk2_symbols": sk2_all,
        "sk2_strong": sk2_strong,
        "validation": {
            "location": location,
            "verifyreceipt_endpoints": verifyreceipt,
            "appstore_server_api": bool(server_api),
            "on_device_receipt": on_device,
            "jws_verification": jws,
        },
        "iap_sdks": iap_sdks,
        "storekit_config_files": storekit_cfg,
        "risk": {"level": risk, "reason": why},
        "findings": findings,
    }
