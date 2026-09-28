// Probe: TAMPER the assertion. generateAssertion returns a garbage (random) Data
// blob instead of the real Secure-Enclave signature. If the backend accepts it,
// the server is not verifying the signature (SIGNATURE_NOT_VERIFIED). Hygiene.
'use strict';
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
        Interceptor.attach(m.implementation, {
          onEnter(a) {
            const i = sel.split(':').length;
            const b = new ObjC.Block(a[i]); const orig = b.implementation;
            b.implementation = function () { return orig(garbage(), NULL); };
          }
        });
        console.log('[tamper] hooked ' + sel);
      }
    }
  } catch (e) { console.log('[tamper] ' + e); }
}
