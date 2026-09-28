# iOS SSL Pinning Bypass and Client-Integrity Defense Measurement: Design Spec

Date: 2026-09-27
Author: Amirhossein Khanlari (Stony Brook University), advisor Amir Rahmati
Status: Design approved in brainstorming; pending written-spec review

## 1. Summary

This is the design for the measurement pipeline behind the follow-up paper to
"Subscribe for Free" (the iOS in-app subscription security paper). The prior
paper's reviewers noted it never measured certificate pinning. This project
measures, at scale and on non-jailbroken devices, how much of the iOS app
ecosystem's client-side transport and integrity defense actually holds against a
client-side attacker.

The headline is not a new bypass technique. Pinning is bypassable by definition
against an attacker who can modify the app binary, and claiming a novel bypass
would contradict that thesis. The contribution is a first at-scale
characterization of the full iOS client-integrity defense stack, culminating in
the attestation-enforcement gap: how many apps adopt App Attest / DeviceCheck,
and how few actually enforce it server-side.

## 2. Research framing and contributions

Two-attacker story that composes with the subscription paper:
- Paper 1 threat model: network-only attacker A, defeated by pinning.
- This paper: client-side re-sign-and-inject attacker B, defeats pinning.

Claimed contributions:
1. First at-scale characterization of the full iOS client-integrity defense
   stack: pinning (layer and library), anti-tamper, anti-debug, jailbreak/Frida
   detection, and App Attest / DeviceCheck, on a fresh 2026 corpus.
2. The attestation-enforcement gap: adoption vs actual server-side enforcement,
   measured by differential testing. This is the headline finding and mirrors
   the "informational vs enforced" trap found with RevenueCat Trusted
   Entitlements in paper 1.
3. A fully automated non-jailbroken pipeline: download, decrypt, classify,
   bypass with automated escalation, drive, and verify, with an automated
   success oracle. Prior work (Pradeep et al., IMC 2022) was jailbroken and
   semi-manual.
4. A bypass-cost model: per app, the cheapest technique in the escalation ladder
   that yields proxy-visible traffic.

Completeness argument (defends against "did you miss a technique"): a client-side
check can only be (i) made to pass, (ii) removed, (iii) never triggered, or
(iv) read around after decryption. The escalation ladder instantiates these
classes; an app resisting all of them is either using an instantiation not
reached (a measurement gap) or protected by enforced attestation (a real
defense). The classifier plus crash triage disambiguate the two.

## 3. Locked decisions (from brainstorming)

1. Scope: full defense-stack characterization with the attestation-enforcement
   gap as the headline (not bypass-only).
2. Devices: decrypt on the jailbroken iPhone 8 (ipadecrypt); test on the
   non-jailbroken iPhone XR via re-sign plus injection. Faithful to the
   stock-device threat model.
3. Corpus: fresh 2026 category-stratified top-free crawl across 5 storefronts,
   same crawl methodology as paper 1.
4. App driving: AI-driven auto-login on the real XR, best-effort, with
   automatic fallback to unauthenticated capture where login is not possible.
   (Not the vphone virtual iPhone: a VM has no genuine Secure Enclave and would
   confound the attestation measurement.)
5. Bypass: automated escalation ladder across the whole dynamic corpus
   (dylib, renamed/stripped dylib, Frida gadget with targeted hooks, evasion
   hooks), driven by crash triage plus a control re-sign. Binary patching is the
   manual sample tail.
6. Scale (funnel): static/prevalence pass on 5,000+ apps; dynamic bypass test on
   ~2,000 to 3,000; authenticated attestation test on a few hundred.

Bounded evasion policy: evasion is measurement hygiene, not offense. Rename and
strip the injected dylib, and neutralize standard, documented detectors
(loaded-image enumeration, codesign/csops checks, ptrace/sysctl anti-debug,
jailbreak/Frida canaries). Capped at "avoid trivial detection, then report the
residue." No attempt to defeat enforced App Attest, because nothing client-side
can, and that residue is the headline finding.

## 4. Architecture: nine-stage funnel

Each app is one row in a SQLite database that advances stage by stage. A failure
or skip at any stage is labeled and the app stops there; nothing hard-stops the
run, and the run is resumable.

```
[A] Crawl               -> 5,000+ apps (category, storefront, rank)
[B] Acquire + Decrypt   -> decrypted IPA        (JB iPhone 8, ipadecrypt over SSH)
[C] Static classifier   -> defense profile       (PREVALENCE, large N)
[D] Instrument builder  -> re-signed IPA configs  (zsign + certs + dylibs)
[E] Dynamic test        -> captured flows         (non-JB XR; Stage-0 baseline then bypass)
[F] Escalation control  -> bypass cost per app    (crash triage -> ladder)
[G] Success oracle      -> outcome label          (flow diff)
[H] Attestation tester  -> enforcement result     (authenticated sample; HEADLINE)
[I] Aggregation         -> metrics, tables, figures
```

Devices: JB iPhone 8 (A11/arm64) for decryption only; non-JB iPhone XR (A12) for
all testing. Minimum one of each; more stock devices only add throughput.

## 5. Components

| # | Component | Built from | Job |
|---|---|---|---|
| C1 | Crawler | new Python, ideas from paper-1 crawler | Fresh 2026 category-stratified top-free list, 5 storefronts; capture ALL available metadata per app (see section 12) into DB |
| C2 | Acquire+Decrypt | ipadecrypt on iPhone 8 over SSH | Download and FairPlay-decrypt to IPA |
| C3 | Static classifier | new Python, ideas from ipa_vulnerability_analyzer.py | Per-app defense profile |
| C4 | Instrument builder | zsign + certs + dylibs + evasion module | Inject, re-sign, output installable IPA configs |
| C5 | Device runner | ideviceinstaller/ios-deploy + Appium/WDA + AI agent | Install on XR, drive UI, auto-login best-effort |
| C6 | Capture | Proxyman + own CA | Record flows per config |
| C7 | Escalation controller | new Python state machine | Crash triage, control re-sign, ladder, bypass cost |
| C8 | Success oracle | new Python | Diff Stage-0 vs post-bypass flows, assign label |
| C9 | Attestation tester | new Python + C5/C6 | Authenticated sample: neutralize App Attest, test backend |
| C10 | Aggregator | new Python + SQLite | Metrics, tables, figures |

Build all pipeline code fresh and clean. Paper 1 is a source of ideas and
lessons only (crawl approach, instrument-and-capture flow, zsign re-sign flow,
Proxyman capture pattern, the RevenueCat trusted-entitlement test as the analog
for C9, SQLite staging), not code to copy or extend. External binaries still used
directly: zsign, FridaGadget.dylib, ipadecrypt, Proxyman, Theos. Prebuilt dylibs on hand: SSLKillSwitch2.dylib (SSKS, arm64 +
arm64e), sideloadFixerLol.dylib (SideloadFix). SB-1/SB-2 are unrelated app cheats
(PicsArt, KineMaster) and are not used.

## 6. Static classifier (C3) output: the defense profile

Per app, from the decrypted binary, Info.plist, and linked libraries:
- pins_flag, pin_layer (L1 ATS / L2 NSURLSession delegate / L3 library / L4
  SecTrust), pin_library (TrustKit, AFNetworking, Alamofire, Cordova, custom)
- tls_stack (native, Flutter, React Native, Xamarin, embedded BoringSSL)
- anti_tamper_hints (integrity/codesign checks, image-count scans)
- appattest_flag, devicecheck_flag (entitlement appattest-environment,
  DCAppAttestService/DCDevice symbols)
- networkextension_flag (VPN entitlement that can tunnel around the proxy)

Static is a noisy over-approximation (Pradeep: ~33 percent static vs ~11 percent
runtime), so it is a feature and pre-filter, not ground truth. Dynamic Stage 0 is
the ground-truth pinning detector.

## 7. Instrument builder (C4) and the injection configs

zsign re-signs each decrypted IPA with Certificates.p12 and a wildcard dev
provisioning profile that has the XR UDID registered, rewriting the bundle ID to
match. Injection configs, produced on demand by the escalation controller:
- stage0: no bypass dylib (baseline, plus SideloadFix so the app runs)
- control: re-sign only, no bypass dylib (crash-cause disambiguation)
- dylib: SSKS3 (as-is) + SideloadFix
- renamed: SSKS3 renamed and stripped + SideloadFix
- frida: FridaGadget + targeted hook script + SideloadFix
- evasion: renamed SSKS3 + SideloadFix + evasion module (detector neutralization)

SideloadFix (sideloadFixerLol.dylib) is always included so re-sign side effects
(keychain access group, app-group container, bundle identity) do not crash the
app. Evasion module is a new Theos-built fishhook dylib that neutralizes standard
detectors, per the bounded policy in section 3.

## 8. Dynamic test (C5, C6) and app driving

For each app: install the config on the XR, route through Proxyman with the
trusted own-CA, launch, drive. Driving = AI-agent UI automation over
Appium/WebDriverAgent, best-effort auto-login using provisioned test accounts,
exercising screens that generate network traffic. If login cannot complete
(no account, 2FA, captcha, hard paywall), fall back to unauthenticated capture
and label login_status accordingly. Capture window and HAR handling reuse the
paper-1 pattern. Apple hosts excluded from interception as in paper 1.

Order per app: Stage 0 first (own CA, no bypass). If Stage-0 traffic is visible,
the app does not pin (NOT_PINNED) and no bypass is attempted. If Stage 0 shows no
app traffic, the app pins, and the escalation ladder runs.

## 9. Escalation controller (C7) and bypass cost

On the pinned set, escalate and record the cheapest working stage as bypass_cost:
1. dylib (SSKS3 as-is)
2. On crash: run the control re-sign (no bypass dylib).
   - Control also crashes -> tamper detection on re-signing itself -> try evasion
     config -> still crashes -> queue for binary patch (manual sample).
   - Control runs clean -> crash was SSKS3-specific -> try renamed dylib, then
     frida with targeted hooks.
3. Whatever first yields proxy-visible traffic sets bypass_cost.

Crash triage inputs: crash report (kernel-kill via CODESIGNING vs app self-abort
SIGABRT with app backtrace), timing (pre-network launch check vs post-first-TLS
canary), and console/os_log. Binary patching is never fully automated; it runs
on a stratified sample only.

## 10. Success oracle (C8) and outcome taxonomy

Success = the diff between Stage-0 captured flows and post-bypass flows: endpoints
invisible at Stage 0 that become visible after bypass. Labels:
- NOT_PINNED: traffic visible at Stage 0
- BYPASSED: was invisible at Stage 0, visible after a bypass config
- PARTIAL: some endpoints visible, some not (multiple pinning layers)
- PINNED_UNBYPASSED: app runs, still no traffic after the full ladder
- TAMPER_DETECTED: app crashes/exits/refuses to connect after injection
- INCONCLUSIVE: login-walled, region-locked, networkextension tunnel, or no
  network triggered

Headline bypass rates are computed over evaluable apps; excluded and inconclusive
sets are reported with explicit codes so denominators stay honest.

## 11. Attestation-enforcement tester (C9): the headline

On a stratified authenticated sample of apps whose static profile flags App
Attest / DeviceCheck: log in, reach the gated action, then neutralize attestation
(hook DCAppAttestService so the assertion is absent or invalid) and observe the
backend. Result per app:
- fail_closed: backend refuses to serve gated data without valid attestation
  (real, effective defense)
- fail_open: backend still serves gated data (attestation is adopted but not
  enforced; theater)
- inconclusive: could not reach or observe the gated action

Enforcement is a property of the backend, not the device, so this is valid on the
faithful non-JB device. The adoption-vs-enforcement split is the paper's headline.

## 12. Data model (one SQLite DB, one row per app)

- apps: capture every available field per app, not a minimal subset. Core keys:
  bundle_id, track_id (App Store numeric id), storefront/country, rank,
  rank_category (the chart it was scraped from). Full metadata (all fields the
  App Store / iTunes lookup API expose):
  - Identity: name, subtitle, seller/developer name, developer_id, SKU
  - Taxonomy: primary_category, all_categories/genres, content_advisory_rating
  - Versioning: current_version, release_date, current_version_release_date,
    version_history (per-version date and notes where available), minimum_os,
    supported_devices, supported_languages
  - Monetization: price, currency, formatted_price, has_iap flag, iap_products
    (names, tiers, prices where available), business model
  - Engagement: average_user_rating, user_rating_count (current and all
    versions)
  - Presentation: description, release_notes, screenshot_urls, artwork_url,
    seller_url, support_url, marketing_url, privacy_policy_url
  - Package: file_size_bytes, App Store privacy "nutrition label" data where
    scrapable
  - Provenance: crawl_timestamp, source_endpoint, raw_json blob (store the full
    raw API response verbatim so nothing is lost even if not normalized into a
    column)
- acquisition: decrypt_status, ipa_path, arch
- static_profile: pins_flag, pin_layer, pin_library, tls_stack,
  anti_tamper_hints, appattest_flag, devicecheck_flag, networkextension_flag
- dynamic_runs: config, install_status, crash_class, flows_captured, login_status
- outcome: label, bypass_cost
- attestation: tested_flag, neutralized_flag, backend_behavior

## 13. Error handling and resumability

Every stage writes a status and moves on. Failures are labeled, not lost.
Re-running resumes apps not yet at their next stage. Structural exclusions
(networkextension, region lock, login impossible, decrypt failure) get explicit
codes to preserve honest denominators.

## 14. Testing the pipeline itself

Three control apps built in-house with known behavior validate the instrument
before real apps:
1. Pinned (TrustKit) -> oracle must return BYPASSED after dylib.
2. Non-pinned -> oracle must return NOT_PINNED at Stage 0.
3. Pinned + anti-tamper that exits on injected dylib -> triage must return
   TAMPER_DETECTED, confirmed by the control re-sign.
Correct labels on these three establish oracle and escalation trustworthiness.

## 15. Assets and prerequisites

On hand: SSLKillSwitch2.dylib, sideloadFixerLol.dylib, FridaGadget.dylib, zsign,
Certificates.p12 + amir.mobileprovision (renew, register XR UDID), Theos, JB
iPhone 8 (OpenSSH + AppSync Unified + appinst for ipadecrypt), non-JB iPhone XR,
Proxyman (CA trusted on XR, capture scripting), external drives for IPA storage,
paid Apple Developer account, test/burner Apple IDs.

To build/configure: Appium + WebDriverAgent (WDA re-signed), the evasion module
(Theos fishhook dylib), the three control apps, and components C3/C7/C8/C9/C10.

Not used: SB-1/SB-2 (app-specific cheats, unrelated).

## 16. Ethics

Same posture as paper 1: authorized measurement, withhold turnkey
mass-exploitation tooling and per-app rules for real apps, do not name apps,
responsible disclosure. Evasion is capped at measurement hygiene. Test accounts
are researcher-owned; no real users' subscriptions or data are touched.

## 17. Limitations and risks

- Static over-approximates pinning; dynamic Stage 0 is ground truth but only for
  endpoints actually exercised (UI/login coverage bounds it).
- Flutter/React Native with embedded (statically linked) BoringSSL is the hard
  bucket the injected dylib cannot reach via symbol rebinding; measure it as a
  result, escalate to Frida/patch on the sample.
- Auto-login cannot pass account creation, 2FA, captcha, or hard paywalls at
  scale; those apps fall to unauthenticated or inconclusive.
- Single test device (XR) makes the dynamic stage throughput-bound.
- Binary patching does not fully automate; sample only.
- Attestation enforcement is testable only where the gated action is reachable;
  report the tested subset size.
- Paid developer account and provisioning are hard prerequisites gating all
  on-device stages.
