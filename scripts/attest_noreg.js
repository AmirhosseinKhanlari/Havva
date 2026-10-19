// Probe: NO REGISTRATION. generateKey and attestKey fail, so the app never
// registers an attested key with the backend. If gated data still flows, the
// backend never required registration (NOT_REGISTERED_OK). Hygiene.
'use strict';
let __hooked = 0;
if (ObjC.available) {
  try {
    const S = ObjC.classes.DCAppAttestService;
    const err = ObjC.classes.NSError.errorWithDomain_code_userInfo_('DCErrorDomain', 2, NULL);
    const gk = S && S['- generateKeyWithCompletionHandler:'];
    if (gk) {
      __hooked++; Interceptor.attach(gk.implementation, {
        onEnter(a) { console.log('ATTESTPROBE HIT noreg'); const b = new ObjC.Block(a[2]); const o = b.implementation;
          b.implementation = function () { return o(NULL, err); }; }
      });
      console.log('[noreg] hooked generateKey');
    }
    for (const sel of ['attestKey:clientDataHash:completionHandler:',
                       'attestKeyWithClientDataHash:completionHandler:']) {
      const m = S && S['- ' + sel];
      if (m) {
        __hooked++; Interceptor.attach(m.implementation, {
          onEnter(a) { console.log('ATTESTPROBE HIT noreg'); const i = sel.split(':').length;
            const b = new ObjC.Block(a[i]); const o = b.implementation;
            b.implementation = function () { return o(NULL, err); }; }
        });
        console.log('[noreg] hooked ' + sel);
      }
    }
    if (__hooked) console.log('ATTESTPROBE ARMED noreg'); else console.log('ATTESTPROBE NOHOOK noreg');
  } catch (e) { console.log('[noreg] ' + e); }
}
