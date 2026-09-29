//
// AttestObserver - observe-only App Attest / DeviceCheck usage detector.
//
// Injected into a re-signed app (no jailbreak, no Frida). At load it swizzles the
// DCAppAttestService / DCDevice methods and logs a staged marker trail via NSLog
// (visible in `idevicesyslog` over USB). The trail lets the pipeline tell apart:
//   - tooling broken (no OBSERVER_LOADED)
//   - app does not use App Attest (CLASS_ABSENT)
//   - hook armed but not triggered (HOOK_VERIFIED, no CALL) = coverage-bounded
//   - confirmed usage (CALL)
//
// Read-only: every swizzled method logs and then calls the original unchanged.
// NSLog is used deliberately (os_log info/debug is filtered out of idevicesyslog).
//

#import <Foundation/Foundation.h>
#import <objc/runtime.h>

#define MARK(fmt, ...) NSLog(@"OBSERVER " fmt, ##__VA_ARGS__)

// ---- Swizzled implementations (call through to the original) -----------------
// After method_exchangeImplementations, the obs_ selector points at the ORIGINAL
// implementation, so calling [self obs_x:...] inside obs_x:... runs the original.

@interface NSObject (AttestObserve)
@end

@implementation NSObject (AttestObserve)

- (void)obs_generateKeyWithCompletionHandler:(id)ch {
    MARK(@"CALL DCAppAttestService generateKey");
    [self obs_generateKeyWithCompletionHandler:ch];
}

- (void)obs_attestKey:(id)keyId clientDataHash:(id)h completionHandler:(id)ch {
    MARK(@"CALL DCAppAttestService attestKey");
    [self obs_attestKey:keyId clientDataHash:h completionHandler:ch];
}

- (void)obs_generateAssertion:(id)keyId clientDataHash:(id)h completionHandler:(id)ch {
    MARK(@"CALL DCAppAttestService generateAssertion");
    [self obs_generateAssertion:keyId clientDataHash:h completionHandler:ch];
}

- (void)obs_generateTokenWithCompletionHandler:(id)ch {
    MARK(@"CALL DCDevice generateToken");
    [self obs_generateTokenWithCompletionHandler:ch];
}

@end

// ---- Swizzle helper ---------------------------------------------------------

static void swizzleAndVerify(Class cls, SEL orig, SEL repl) {
    if (!cls) return;
    Method mo = class_getInstanceMethod(cls, orig);
    Method mr = class_getInstanceMethod(cls, repl);
    if (!mo) { MARK(@"HOOK_ABSENT %@", NSStringFromSelector(orig)); return; }
    if (!mr) { MARK(@"HOOK_REPL_MISSING %@", NSStringFromSelector(repl)); return; }
    IMP before = method_getImplementation(mo);
    method_exchangeImplementations(mo, mr);
    IMP after = method_getImplementation(mo);
    if (after != before) MARK(@"HOOK_VERIFIED %@", NSStringFromSelector(orig));
    else                 MARK(@"HOOK_FAILED %@", NSStringFromSelector(orig));
}

static BOOL installHooks(void) {
    Class attest = NSClassFromString(@"DCAppAttestService");
    Class dcdev  = NSClassFromString(@"DCDevice");
    if (!attest && !dcdev) {
        MARK(@"CLASS_ABSENT DCAppAttestService");
        return NO;
    }
    if (attest) {
        MARK(@"CLASS_PRESENT DCAppAttestService");
        swizzleAndVerify(attest, @selector(generateKeyWithCompletionHandler:),
                         @selector(obs_generateKeyWithCompletionHandler:));
        swizzleAndVerify(attest, @selector(attestKey:clientDataHash:completionHandler:),
                         @selector(obs_attestKey:clientDataHash:completionHandler:));
        swizzleAndVerify(attest, @selector(generateAssertion:clientDataHash:completionHandler:),
                         @selector(obs_generateAssertion:clientDataHash:completionHandler:));
    }
    if (dcdev) {
        MARK(@"CLASS_PRESENT DCDevice");
        swizzleAndVerify(dcdev, @selector(generateTokenWithCompletionHandler:),
                         @selector(obs_generateTokenWithCompletionHandler:));
    }
    return YES;
}

__attribute__((constructor))
static void attestobserver_init(void) {
    MARK(@"OBSERVER_LOADED");
    if (installHooks()) return;
    // DeviceCheck may load lazily; retry a few times before giving up.
    for (int i = 1; i <= 3; i++) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(i * 2 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            if (NSClassFromString(@"DCAppAttestService") || NSClassFromString(@"DCDevice")) {
                installHooks();
            } else if (i == 3) {
                MARK(@"CLASS_ABSENT_FINAL");
            }
        });
    }
}
