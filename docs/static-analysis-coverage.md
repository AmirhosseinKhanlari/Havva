# iOS Static Analysis — Coverage & Gap Analysis

_Written for: the research team, as a reference for the pinning/client-integrity paper._
_Last updated: 2026-09-30._

This documents how our static analyzer (`pipeline/analysis.py` + `pipeline/static_classify.py`)
compares to the authoritative iOS static-analysis catalogs — the
[OWASP MASTG iOS test list](https://mas.owasp.org/MASTG/tests/) and
[MobSF's iOS rule set](https://deepwiki.com/MobSF/Mobile-Security-Framework-MobSF/2.2-ios-static-analysis).

**Verdict:** we fully cover (and in pinning / attestation / trackers *exceed*) the common
MobSF-level checks, but we do **not** implement every MASTG static technique. The 12 items
below are the partial (🟡) and missing (❌) techniques. Most are generic app-sec checks that
are not central to the paper's thesis; two (dependency CVEs, `get-task-allow`) are worth
closing and are being implemented.

Status legend: ✅ full · 🟡 partial (detected/surfaced but not assessed) · ❌ missing.

---

## The 12 gap features

### 1. Dependency CVEs / SBOM — ✅ IMPLEMENTED (2026-09-30)
**MASTG-TEST-0273 / 0275.** We now extract each embedded framework's
`CFBundleShortVersionString` and check it against OSV.dev (SwiftPM packages, keyed by GitHub
repo) plus a curated advisory list for classic CocoaPods CVEs OSV lacks. Results are cached
on disk, dock the security score, and show in a "Dependencies & known CVEs" card.
See `pipeline/cve.py`. (`CVE_LOOKUP=0` to stay offline.)

### 2. Debuggable entitlement (`get-task-allow`) — ✅ IMPLEMENTED (2026-09-30)
**MASTG-TEST-0261.** `analyze_ipa` flags `get-task-allow == true` as a high-severity finding
("Debuggable in production") and docks the score. See `analysis.debuggable_findings`.

### 3. WebView security configuration — ❌
**MASTG-TEST-0331 / 0332 / 0333 / 0335 / 0376 / 0378.** We flag only the deprecated
`UIWebView`. We do not analyze `WKWebView` configuration: `allowFileAccessFromFileURLs`,
`allowUniversalAccessFromFileURLs`, `loadFileURL:allowingReadAccessToURL:`, JS bridges
(`WKScriptMessageHandler`, `addScriptMessageHandler`, `evaluateJavaScript`), or password
fields in WebView-loaded HTML.

### 4. Insecure deserialization — ❌
**MASTG-TEST-0386.** No detection of `NSKeyedUnarchiver` used without secure coding
(`requiresSecureCoding` / `unarchivedObjectOfClass:`), i.e. deserialization of untrusted data.

### 5. Backup exclusion of sensitive data — ❌
**MASTG-TEST-0215.** We do not check whether sensitive files set
`URLResourceKey.isExcludedFromBackupKey` / `NSURLIsExcludedFromBackupKey`, so sensitive data
may sync to iCloud/iTunes backups.

### 6. Granular ATS per-domain exceptions — ✅ IMPLEMENTED (2026-09-30)
**MASTG-TEST-0342.** `ats()` now returns per-domain `exception_details` with
`NSExceptionMinimumTLSVersion`, `NSExceptionAllowsInsecureHTTPLoads`,
`NSExceptionRequiresForwardSecrecy`, `NSIncludesSubdomains`,
`NSRequiresCertificateTransparency`, plus `NSAllowsLocalNetworking`. Insecure-HTTP / weak-TLS
exceptions and global `NSAllowsArbitraryLoads` are raised as findings and shown in an "ATS
exceptions" card.

### 7. Cleartext `http://` URLs — ✅ IMPLEMENTED (2026-09-30)
**MASTG-TEST-0321.** `config_findings` flags any referenced `http://` endpoint (medium) and
`UIFileSharingEnabled` (exposed Documents).

### 8. Biometric authentication policy — 🟡
**MASTG-TEST-0266 / 0268 / 0270.** We record `LAContext` presence as a crypto hint, but do
not analyze the policy: fallback to device passcode
(`deviceOwnerAuthentication` vs `deviceOwnerAuthenticationWithBiometrics`) or
enrollment-change detection (`evaluatedPolicyDomainState`).

### 9. Insufficient key sizes / hardcoded symmetric keys — 🟡
**MASTG-TEST-0209 / 0213 / 0214.** `scan_secrets` catches vendor tokens (AWS/GCP/Stripe/…)
and private-key PEM blocks, but not generic small RSA key sizes or hardcoded symmetric keys
/ high-entropy hex blobs used as keys.

### 10. Privacy: manifest, purpose-string accuracy & unjustified entitlements — 🟡 (partly implemented)
**MASTG-TEST-0360 / 0362.** IMPLEMENTED (2026-09-30): `privacy_manifest()` parses
`PrivacyInfo.xcprivacy` (app + bundled SDKs) for tracking flag, tracking domains, collected
data types, and required-reason APIs; a **missing app manifest** is flagged. Still partial:
we don't assess whether purpose strings are *accurate* for reachable APIs, or whether declared
entitlements are *justified* (those need reachability analysis).

### 11. Misc platform / storage hardening — ❌
**MASTG-TEST-0248 / 0313 / 0389 / 0395.** Not checked: secure-screen-lock detection
(`LAPolicy` passcode set), missing `isSecureTextEntry` on sensitive text fields, app-wide
custom-keyboard restriction (`shouldAllowExtensionPointIdentifier`), and universal-link
handler input validation (`continueUserActivity`). (We do flag the keyboard **autocorrect**
cache via `autocorrectionType`.)

### 12. Code-signature format version — 🟡
**MASTG-TEST-0220.** We detect the presence of `LC_CODE_SIGNATURE` but not whether the
signature uses an outdated format/version.

---

## What we already cover (for context)

**Full / ahead of MobSF & MASTG:**
- Mach-O protections: PIE, NX, stack canary, ARC, RPATH, code-signature, encrypted (cryptid), symbols-stripped.
- Binary API rules: insecure C funcs, weak crypto (DES/3DES/RC4/RC2/ECB), weak hash (MD5/MD4/SHA1), insecure random, malloc, NSLog, ptrace, UIWebView.
- SSL pinning: **4-layer taxonomy** (ATS `NSPinnedDomains` / delegate / library / SecTrust+BoringSSL) with library fingerprinting — beyond MASTG/MobSF.
- **App Attest** graded adoption (referenced/adopted/production), DeviceCheck, anti-tamper, anti-debug, jailbreak detection, NetworkExtension — beyond.
- SDK fingerprint (~55 SDKs, static-link aware) + tracker-by-domain (~70).
- Hardcoded secrets (AWS/GCP/Stripe/Slack/JWT/bearer/private-key/S3/IP).
- Insecure storage **API flags** (NSUserDefaults/SQLite/Core Data/Realm/keychain/pasteboard/cookies/keyboard) **plus a dynamic container pull-and-scan probe** — beyond.
- ATS global flags, Info.plist summary + permissions, entitlements, URL/domain/email extraction, security scoring, file tree.

**Note on relevance to the paper:** the paper's contribution is pinning + client-integrity +
App Attest **at scale**, where our coverage is strongest and exceeds the standard tools. The
gaps above are mostly generic app-sec completeness items.

---

## Addendum: My-iOS-Pentesting-Cheatsheet coverage (2026-09-30)

Compared against the [My-iOS-Pentesting-Cheatsheet](https://github.com/Abhinandan-Khurana/My-iOS-Pentesting-Cheatsheet)
(26-section playbook). We cover the static phases and our research-focused dynamic phases
(and exceed the cheatsheet on pinning-library ID, App Attest, anti-tamper, SDK/tracker
fingerprinting, dependency CVEs). Tool differences that are the same method count as covered:
Proxyman≈Burp/mitmproxy, SSL Kill Switch≈`objection sslpinning disable`, zsign≈`objection
patchipa`, pymobiledevice3/ideviceinstaller≈frida-server/ios-deploy/simctl.

**Intentionally out of scope** (interactive, per-app, manual — not for an at-scale tool):
Objection interactive hooking & memory search, auth/session/authorization + BOLA/IDOR,
WebView JS-bridge payload probing, URL-scheme/deeplink fuzzing, document-handling & push
testing, biometric bypass.

**SQLite content enumeration — ✅ IMPLEMENTED (2026-09-30).** The dynamic storage probe now
opens each pulled `.sqlite`/`.db` read-only, enumerates tables, and scans rows + column names
for secrets / sensitive data (like Objection's `sqlite connect` / `execute query`). A DB that
won't open is flagged as possibly-encrypted. See `storage_scan._scan_sqlite`.

**Automatable gaps still open** (candidates for future work):
- **Keychain dump** (dynamic) — the one remaining item from the Objection guides. Needs an
  injected dylib (or Frida-gadget script) that calls `SecItemCopyMatching` for the app's own
  keychain items, writes the dump into the container, which we then pull. We already have the
  container-pull path; this requires building a new injectable dylib.
- **Class-dump** (ObjC metadata) — `otool -ov` / rabin2-style class listing for richer surface.
- **AASA / universal links** — fetch `/.well-known/apple-app-site-association` for
  `associated-domains` and validate.
- **Snapshot & pasteboard** runtime capture during the storage probe.
- **File-protection class & backup-exclusion** — NOTE: these are filesystem xattrs not
  preserved by AFC pull, so they need on-device/JB inspection; not reliably automatable on the
  non-JB path.
- **Swift symbol demangling** for readability.

---

## Addendum: MASTG-TECH-0064 (Bypassing Certificate Pinning) — 2026-09-30

Reviewed the technique. We cover the core methods (non-JB re-sign + SSKS for standard-API
pinning, and the differential probe detects what SSKS can't as hard-pinned). Implemented the
one detail we were missing:

**Bundled-certificate detection + swap — ✅ IMPLEMENTED.**
- Static: `analysis.bundled_certs` flags cert/key files shipped in the app bundle
  (`.cer/.der/.crt/.pem/.p12/.pfx/.cert/.pub/.key`) as a pinning-by-cert signal (info finding +
  "Bundled certificates" card).
- Dynamic: an **on/off** "Swap bundled certificates with the MITM CA" option on the pinning
  probe and manual run (`instrument._swap_bundled_certs`, CLI `--swap-certs`). When on, the
  bypass build overwrites bundled `.cer/.der` (DER) and `.pem/.crt/.cert` (PEM) with the
  Proxyman CA (`CONFIG.proxyman.ca_cert`, env `PROXY_CA_CERT`), defeating pinning that compares
  against a bundled cert — without Frida.

Still not done (documented, lower priority): binary patching of hardcoded pin hashes / OpenSSL
pinning, and custom Frida bypass scripts (the deferred Frida-gadget work).

---

## Addendum: New paper measurement dimensions (2026-09-30)

Three MASTG techniques implemented as at-scale measurement dimensions for the next paper.

### ATS declared-vs-needed gap (MASTG-TECH-0149) — ✅
`pipeline/ats_runtime.py` runs `nscurl --ats-diagnostics` per endpoint and parses the
"Default ATS Secure Connection" result, then cross-references the app's declared ATS config.
Flags **unnecessary weakening**: apps that set `NSAllowsArbitraryLoads` or per-domain
exceptions for endpoints that already pass default ATS (the transport-layer analogue of the
adopt-vs-enforce gap). Per-domain results cached on disk; `ATS_LOOKUP=0` for offline.
Stored in `analysis.ats_gap`. CLI: `ats-gap --app <id>` or batch `ats-gap [--limit N]`.
Web: "Check ATS gap" button + result card in the Static tab.

### Dependency-vulnerability prevalence + SBOM (MASTG-TECH-0132/0133) — ✅
`cve.build_sbom` emits a CycloneDX 1.5 SBOM per app (components + vulnerabilities from the
dependency/CVE data). `cve.prevalence(db)` gives corpus-wide stats (percentage of apps shipping
a known-vulnerable dependency, top vulnerable libs/CVEs). CLI: `sbom --app <id> [--out]`,
`dep-stats`. Web: "Download SBOM (CycloneDX)" link in the Dependencies card.

### App-extension attack surface (MASTG-TECH-0170/0171) — ✅
`analysis.app_extensions` enumerates `PlugIns/*.appex` with extension type (share, widget,
keyboard, network-extension, etc.) and bundle id. Extensions frequently skip the parent app's
pinning/attest defenses, so this is an under-measured surface. Stored in
`analysis.app_extensions`; "App extensions" card in the Static tab.
(Verified on APTV: a Network Extension packet tunnel + a Share extension.)
