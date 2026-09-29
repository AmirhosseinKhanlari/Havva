// Observe (do not modify) App Attest / DeviceCheck usage at runtime. Logs a
// marker whenever the app actually invokes an attestation API, which is the
// highest-confidence signal that the app uses App Attest (stronger than a static
// symbol, which could be dead code). The pipeline parses these markers from the
// Frida output. Read-only: it changes nothing.
'use strict';

function mark(m) { console.log('ATTEST_OBSERVE ' + m); }

if (ObjC.available) {
  const hooks = {
    'DCAppAttestService': [
      'generateKeyWithCompletionHandler:',
      'attestKey:clientDataHash:completionHandler:',
      'attestKeyWithClientDataHash:completionHandler:',
      'generateAssertion:clientDataHash:completionHandler:',
      'generateAssertionWithKeyId:clientDataHash:completionHandler:',
      'isSupported',
    ],
    'DCDevice': [
      'generateTokenWithCompletionHandler:',
    ],
  };
  for (const cls in hooks) {
    const C = ObjC.classes[cls];
    if (!C) continue;
    mark('CLASS_PRESENT ' + cls);
    for (const sel of hooks[cls]) {
      const m = C['- ' + sel];
      if (!m) continue;
      try {
        Interceptor.attach(m.implementation, {
          onEnter() { mark('CALL ' + cls + ' ' + sel); }
        });
      } catch (e) { mark('HOOK_ERR ' + sel + ' ' + e); }
    }
  }
  mark('READY');
}
