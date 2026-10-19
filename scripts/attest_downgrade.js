// Probe: DOWNGRADE. Report App Attest as unsupported so the app takes its
// "device doesn't support attestation" fallback path. If gated data still flows,
// the backend allows an unattested downgrade (DOWNGRADEABLE). Hygiene.
'use strict';
let __hooked = 0;
if (ObjC.available) {
  try {
    const S = ObjC.classes.DCAppAttestService;
    // isSupported is a property on the shared instance; force NO.
    for (const sel of ['- isSupported', '- supported']) {
      const m = S && S[sel];
      if (m) {
        __hooked++; Interceptor.attach(m.implementation, { onLeave(ret) { console.log('ATTESTPROBE HIT downgrade'); ret.replace(0); } });
        console.log('[downgrade] forced ' + sel + ' = NO');
      }
    }
    if (__hooked) console.log('ATTESTPROBE ARMED downgrade'); else console.log('ATTESTPROBE NOHOOK downgrade');
  } catch (e) { console.log('[downgrade] ' + e); }
}
