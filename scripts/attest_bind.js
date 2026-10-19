// Probe: REQUEST BINDING (F3). The assertion is left intact; the request it
// travels with is altered AFTER the app built it, at the NSURLSession task
// boundary, for the gated endpoints only (__GATED__ is substituted at arm
// time with the baseline's "host/path" list). A server that recomputes
// clientDataHash from the request it received refuses; a server that only
// checks the challenge (or nothing) serves -> UNBOUND_REQUEST. JSON bodies get
// an extra top-level key; form bodies an extra pair; GETs an extra query
// parameter. Hygiene.
'use strict';
let __hooked = 0;
const GATED = __GATED__;
if (ObjC.available) {
  try {
    const NSMutableURLRequest = ObjC.classes.NSMutableURLRequest;
    const NSString = ObjC.classes.NSString;
    function key(req) {
      const u = req.URL(); if (!u) return '';
      const host = (u.host() ? u.host().toString() : '').toLowerCase();
      const path = u.path() ? u.path().toString() : '';
      return host + path;
    }
    function mutate(req) {
      const k = key(req);
      if (GATED.indexOf(k) < 0) return req;
      const m = req.mutableCopy();
      const body = m.HTTPBody();
      if (body && !body.isNull() && body.length() > 0) {
        const s = NSString.alloc().initWithData_encoding_(body, 4); // UTF-8
        if (s && !s.isNull()) {
          let t = s.toString();
          if (t.trim().startsWith('{')) t = t.trim().replace(/^\{/, '{"havva_bind":1,');
          else if (t.indexOf('=') >= 0) t = t + '&havva_bind=1';
          else t = t + ' ';
          m.setHTTPBody_(NSString.stringWithString_(t).dataUsingEncoding_(4));
          console.log('ATTESTPROBE HIT bind (body) ' + k);
          return m;
        }
      }
      const u = m.URL().absoluteString().toString();
      const nu = u + (u.indexOf('?') >= 0 ? '&' : '?') + 'havva_bind=1';
      m.setURL_(ObjC.classes.NSURL.URLWithString_(nu));
      console.log('ATTESTPROBE HIT bind (query) ' + k);
      return m;
    }
    const Session = ObjC.classes.NSURLSession;
    for (const sel of ['- dataTaskWithRequest:', '- dataTaskWithRequest:completionHandler:',
                       '- uploadTaskWithRequest:fromData:', '- uploadTaskWithRequest:fromData:completionHandler:']) {
      const m = Session[sel];
      if (!m) continue;
      __hooked++; Interceptor.attach(m.implementation, {
        onEnter(a) {
          try {
            const req = new ObjC.Object(a[2]);
            const r2 = mutate(req);
            if (!r2.equals(req)) a[2] = r2;
          } catch (e) { console.log('[bind] ' + e); }
        }
      });
      console.log('[bind] hooked ' + sel);
    }
    if (__hooked) console.log('ATTESTPROBE ARMED bind'); else console.log('ATTESTPROBE NOHOOK bind');
  } catch (e) { console.log('[bind] ' + e); }
}
