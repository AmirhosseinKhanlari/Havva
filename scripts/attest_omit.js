// Probe: OMIT the assertion. generateAssertion fails, so the app attaches no
// valid assertion to its requests. If the backend still serves gated data, the
// assertion is not required (NOT_REQUIRED weakness). Measurement hygiene.
'use strict';
let __hooked = 0;
if (ObjC.available) {
  try {
    const S = ObjC.classes.DCAppAttestService;
    const err = ObjC.classes.NSError.errorWithDomain_code_userInfo_('DCErrorDomain', 2, NULL);
    for (const sel of ['generateAssertion:clientDataHash:completionHandler:',
                       'generateAssertionWithKeyId:clientDataHash:completionHandler:']) {
      const m = S && S['- ' + sel];
      if (m) {
        __hooked++; Interceptor.attach(m.implementation, {
          onEnter(a) { console.log('ATTESTPROBE HIT omit');
            const i = sel.split(':').length; // last arg = completion block
            const b = new ObjC.Block(a[i]); const orig = b.implementation;
            b.implementation = function () { return orig(NULL, err); };
          }
        });
        console.log('[omit] hooked ' + sel);
      }
    }
    if (__hooked) console.log('ATTESTPROBE ARMED omit'); else console.log('ATTESTPROBE NOHOOK omit');
  } catch (e) { console.log('[omit] ' + e); }
}
