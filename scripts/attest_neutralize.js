// Frida script: neutralize App Attest / DeviceCheck so the app sends no valid
// hardware assertion. Used by the attestation-enforcement differential test:
// if the backend still serves gated data with attestation neutralized, it is
// adopted-but-not-enforced (fail-open). Measurement hygiene, not an attack tool.

'use strict';

function log(m) { console.log('[attest-neutralize] ' + m); }

if (ObjC.available) {
  // DCAppAttestService: make key generation / attestation / assertion fail so
  // the app cannot attach a valid assertion to its requests.
  try {
    const DCAppAttestService = ObjC.classes.DCAppAttestService;
    if (DCAppAttestService) {
      const err = ObjC.classes.NSError.errorWithDomain_code_userInfo_(
        'DCErrorDomain', 2, NULL); // DCErrorFeatureUnsupported

      const sel_gen = 'generateKeyWithCompletionHandler:';
      if (DCAppAttestService['- ' + sel_gen]) {
        Interceptor.attach(DCAppAttestService['- ' + sel_gen].implementation, {
          onEnter(args) {
            const block = new ObjC.Block(args[2]);
            const orig = block.implementation;
            block.implementation = function () { return orig(NULL, err); };
          }
        });
        log('hooked ' + sel_gen);
      }

      for (const sel of ['attestKeyWithClientDataHash:completionHandler:',
                         'generateAssertionWithKeyId:clientDataHash:completionHandler:',
                         'attestKey:clientDataHash:completionHandler:']) {
        const m = DCAppAttestService['- ' + sel];
        if (m) {
          Interceptor.attach(m.implementation, {
            onEnter(args) {
              // completion handler is the last block arg
              const idx = sel.split(':').length; // args[2..], last block
              const block = new ObjC.Block(args[idx]);
              const orig = block.implementation;
              block.implementation = function () { return orig(NULL, err); };
            }
          });
          log('hooked ' + sel);
        }
      }
    }
  } catch (e) { log('DCAppAttestService error: ' + e); }

  // DeviceCheck token generation -> fail.
  try {
    const DCDevice = ObjC.classes.DCDevice;
    if (DCDevice && DCDevice['- generateTokenWithCompletionHandler:']) {
      const err = ObjC.classes.NSError.errorWithDomain_code_userInfo_('DCErrorDomain', 1, NULL);
      Interceptor.attach(DCDevice['- generateTokenWithCompletionHandler:'].implementation, {
        onEnter(args) {
          const block = new ObjC.Block(args[2]);
          const orig = block.implementation;
          block.implementation = function () { return orig(NULL, err); };
        }
      });
      log('hooked DCDevice generateToken');
    }
  } catch (e) { log('DCDevice error: ' + e); }
}
