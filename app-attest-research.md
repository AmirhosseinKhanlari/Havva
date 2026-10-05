# App Attest: Bypass Tools and Research Landscape

Notes for the pinning/attestation paper. Captured 2026-09-27.

## Can App Attest actually be bypassed?

Not by breaking the crypto. The Secure Enclave private key cannot be extracted
even on a jailbroken device, and assertions are hardware-signed. There is
**no SSKS-style turnkey "App Attest bypass."** The real attack surface is three
indirect routes:

1. **Exploit weak server enforcement (the dominant one).** If the backend does
   not verify the assertion, soft-fails, or leaves endpoints unattested, you do
   not bypass App Attest at all, you go around it. This is exactly the
   enforcement-gap thesis of this project.
2. **Capture-and-replay / relay on a genuine device.** Crucial nuance: App Attest
   verifies the app, not the device, and does not detect jailbreak, so a
   jailbroken device using a "jailbreak-hide" tweak can still produce a *valid*
   attestation. An attacker then hooks `DCAppAttestService` with Frida to capture
   the valid signed token and replay/relay it from a bot or tampered context.
   Needs a genuine (or JB-passing) device and works only where counters/binding
   are weak.
3. **Downgrade to a fallback path** the developer left for older devices that do
   not support App Attest.

**Tools:** Frida, Objection, Cydia Substrate, plus jailbreak-hide tweaks (Shadow,
etc.). There is **no dedicated App Attest bypass tool**; it is manual, per-app,
and requires exploiting a weak integration. When enforced correctly, it holds.

- Approov, How to Defeat DeviceCheck and App Attest:
  https://approov.io/knowledge/how-to-defeat-apple-devicecheck-and-appattest
- Approov, Exposing the Shortcomings of Apple DeviceCheck and App Attest:
  https://approov.io/blog/limitations-of-apple-devicecheck-and-apple-app-attest
- Guardsquare, Is app attestation on Android and iOS secure?:
  https://www.guardsquare.com/blog/android-and-ios-app-attestation
- Guardsquare, Remove the Constraints of iOS App Attest and DeviceCheck:
  https://www.guardsquare.com/blog/remove-constraints-of-ios-app-attest
- Zimperium, App Attestation glossary: https://zimperium.com/glossary/app-attestation

## Research papers

**iOS App Attest is essentially unstudied academically.** Everything on iOS is
vendor blogs (Approov, Guardsquare, Zimperium); no measurement paper on adoption
or enforcement. That is the gap for this project.

The **Android** side is well studied, and provides both the methodology template
and the related work to cite/differentiate:

- **SafetyNOT: On the usage of the SafetyNet attestation API in Android.** Usage
  across 35,245 apps; found all 104 apps using it were attackable via **downgrade
  to software checks**. Direct analog to this project (at-scale measurement of
  attestation usage and misintegration, on Android). Model the methodology on it
  and position this work as the iOS counterpart nobody has done.
  https://www.researchgate.net/publication/352713395_SafetyNOT_on_the_usage_of_the_SafetyNet_attestation_API_in_Android
- **Assessing the Security Coverage of the Google Play Integrity API on Android.**
  https://sol.sbc.org.br/index.php/errc/article/download/39189/38961/
- **Symbolic modelling of remote attestation protocols for device and app
  integrity on Android** (Tamarin; relay attack on Samsung Knox v2, replay flaw
  in Android Key Attestation). https://dl.acm.org/doi/fullHtml/10.1145/3579856.3582812
- **On the (In)Security of Manufacturer-Provided Remote Attestation Frameworks in
  Android.** https://link.springer.com/chapter/10.1007/978-3-031-51482-1_13
- **ARAP: Demystifying Anti Runtime Analysis Code in Android Apps.**
  https://arxiv.org/pdf/2408.11080
- **Leveraging remote attestation APIs for secure image sharing in messaging
  apps.** https://eprint.iacr.org/2024/2057.pdf
- **Play Integrity Attestation Bypass** (practitioner reference: cert-chain
  replacement, profile spoofing).
  https://hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/play-integrity-attestation-bypass.html

## What this means for the paper

1. **The gap is real and clean.** Android attestation has SafetyNOT and
   follow-ups; iOS App Attest has zero academic measurement. "First measurement
   of App Attest adoption and server-side enforcement on iOS" is a defensible
   novelty claim.
2. **The literature validates the attack model.** SafetyNOT's core finding, that
   attestation fails in practice through weak integration and downgrade, not
   broken crypto, is exactly what the enforcement differential test measures.
   This is the iOS version of that result.
3. **Related-work paragraph:** cite SafetyNOT / Play Integrity work as the Android
   precedent, note the crypto is sound, and frame the contribution as measuring
   whether iOS developers actually enforce the one control that resists a
   client-side re-signing attacker.
