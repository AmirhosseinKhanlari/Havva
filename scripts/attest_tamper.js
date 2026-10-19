// Probe: TAMPER the assertion SIGNATURE ONLY. The real assertion is a CBOR map
// {signature: <DER ECDSA>, authenticatorData: <bytes>}. We let the Secure
// Enclave produce it, then flip bytes INSIDE the signature value and leave the
// structure and authenticatorData intact. A server that parses the CBOR and
// checks the counter but never verifies the signature accepts it (F1,
// SIGNATURE_NOT_VERIFIED); a server that merely fails to parse garbage would
// have looked "enforcing" under the old zero-byte probe. Hygiene.
'use strict';
let __hooked = 0;
if (ObjC.available) {
  try {
    const S = ObjC.classes.DCAppAttestService;
    const NSMutableData = ObjC.classes.NSMutableData;
    const SIG = [0x69, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65]; // text(9) "signature"
    function corrupt(data) {
      if (!data || data.isNull()) return data;
      const n = data.length();
      const md = NSMutableData.dataWithData_(data);
      const p = md.mutableBytes();
      const buf = p.readByteArray(n);
      const b = new Uint8Array(buf);
      let at = -1;
      for (let i = 0; i + SIG.length < n; i++) {
        let ok = true;
        for (let j = 0; j < SIG.length; j++) if (b[i + j] !== SIG[j]) { ok = false; break; }
        if (ok) { at = i + SIG.length; break; }
      }
      // After the key comes the byte-string header (0x58 <len> for <256 bytes);
      // corrupt a run of bytes inside the DER value, skipping the first few so
      // the DER SEQUENCE header stays well-formed.
      let start = at >= 0 ? at + 2 + 4 : Math.floor(n / 2);
      if (start + 8 > n) start = Math.max(0, n - 8);
      for (let k = 0; k < 8 && start + k < n; k++) p.add(start + k).writeU8(b[start + k] ^ 0xff);
      console.log('[tamper] signature corrupted at ' + start + ' of ' + n + (at >= 0 ? ' (cbor key found)' : ' (key not found; mid-blob)'));
      return md;
    }
    for (const sel of ['generateAssertion:clientDataHash:completionHandler:',
                       'generateAssertionWithKeyId:clientDataHash:completionHandler:']) {
      const m = S && S['- ' + sel];
      if (m) {
        __hooked++; Interceptor.attach(m.implementation, {
          onEnter(a) { console.log('ATTESTPROBE HIT tamper');
            const i = sel.split(':').length;
            const b = new ObjC.Block(a[i]); const orig = b.implementation;
            b.implementation = function (assertion, err) {
              try { if (assertion && !assertion.isNull()) assertion = corrupt(new ObjC.Object(assertion)); }
              catch (e) { console.log('[tamper] corrupt failed: ' + e); }
              return orig(assertion, err);
            };
          }
        });
        console.log('[tamper] hooked ' + sel);
      }
    }
    if (__hooked) console.log('ATTESTPROBE ARMED tamper'); else console.log('ATTESTPROBE NOHOOK tamper');
  } catch (e) { console.log('[tamper] ' + e); }
}
