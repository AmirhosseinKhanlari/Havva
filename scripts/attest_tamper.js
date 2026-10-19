// Probe: TAMPER the assertion. generateAssertion returns a garbage (random) Data
// blob instead of the real Secure-Enclave signature. If the backend accepts it,
// the server is not verifying the signature (SIGNATURE_NOT_VERIFIED). Hygiene.
'use strict';
let __hooked = 0;
if (ObjC.available) {
  try {
    const S = ObjC.classes.DCAppAttestService;
    // 64 random bytes as a fake assertion.
    const NSMutableData = ObjC.classes.NSMutableData;
    function garbage() {
      const d = NSMutableData.dataWithLength_(64);
      return d;
    }
    for (const sel of ['generateAssertion:clientDataHash:completionHandler:',
                       'generateAssertionWithKeyId:clientDataHash:completionHandler:']) {
      const m = S && S['- ' + sel];
      if (m) {
        __hooked++; Interceptor.attach(m.implementation, {
          onEnter(a) { console.log('ATTESTPROBE HIT tamper');
            const i = sel.split(':').length;
            const b = new ObjC.Block(a[i]); const orig = b.implementation;
            b.implementation = function () { return orig(garbage(), NULL); };
          }
        });
        console.log('[tamper] hooked ' + sel);
      }
    }
    if (__hooked) console.log('ATTESTPROBE ARMED tamper'); else console.log('ATTESTPROBE NOHOOK tamper');
  } catch (e) { console.log('[tamper] ' + e); }
}
