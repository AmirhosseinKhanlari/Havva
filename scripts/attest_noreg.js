// Probe: NO REGISTRATION. generateKey and attestKey fail, so the app never
// registers an attested key with the backend. If gated data still flows, the
// backend never required registration (NOT_REGISTERED_OK). Hygiene.
'use strict';
if (ObjC.available) {
  try {
    const S = ObjC.classes.DCAppAttestService;
    const err = ObjC.classes.NSError.errorWithDomain_code_userInfo_('DCErrorDomain', 2, NULL);
    const gk = S && S['- generateKeyWithCompletionHandler:'];
    if (gk) {
      Interceptor.attach(gk.implementation, {
        onEnter(a) { const b = new ObjC.Block(a[2]); const o = b.implementation;
          b.implementation = function () { return o(NULL, err); }; }
      });
      console.log('[noreg] hooked generateKey');
    }
    for (const sel of ['attestKey:clientDataHash:completionHandler:',
                       'attestKeyWithClientDataHash:completionHandler:']) {
      const m = S && S['- ' + sel];
      if (m) {
        Interceptor.attach(m.implementation, {
          onEnter(a) { const i = sel.split(':').length;
            const b = new ObjC.Block(a[i]); const o = b.implementation;
            b.implementation = function () { return o(NULL, err); }; }
        });
        console.log('[noreg] hooked ' + sel);
      }
    }
  } catch (e) { console.log('[noreg] ' + e); }
}
