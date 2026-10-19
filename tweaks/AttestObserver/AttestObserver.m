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

// Install-once guards. method_exchangeImplementations is an INVOLUTION: running
// it a second time on the same pair swaps the hooks back OFF. The retry timers
// below each call installHooks(), so without these flags a class that appears
// at 2s would be hooked at 2s and silently un-hooked at 4s, turning a real
// "present and called" into a false "present, not called". Each class is
// exchanged at most once per process; HOOK_VERIFIED is therefore emitted once.
static BOOL g_attestInstalled = NO;
static BOOL g_dcdevInstalled  = NO;

static BOOL installHooks(void) {
    Class attest = g_attestInstalled ? Nil : NSClassFromString(@"DCAppAttestService");
    Class dcdev  = g_dcdevInstalled  ? Nil : NSClassFromString(@"DCDevice");
    if (g_attestInstalled && g_dcdevInstalled) return YES;   // nothing left to do
    if (!attest && !dcdev) {
        if (!g_attestInstalled && !g_dcdevInstalled) MARK(@"CLASS_ABSENT DCAppAttestService");
        return g_attestInstalled || g_dcdevInstalled;
    }
    if (attest) {
        g_attestInstalled = YES;   // set BEFORE exchanging: never exchange twice
        MARK(@"CLASS_PRESENT DCAppAttestService");
        swizzleAndVerify(attest, @selector(generateKeyWithCompletionHandler:),
                         @selector(obs_generateKeyWithCompletionHandler:));
        swizzleAndVerify(attest, @selector(attestKey:clientDataHash:completionHandler:),
                         @selector(obs_attestKey:clientDataHash:completionHandler:));
        swizzleAndVerify(attest, @selector(generateAssertion:clientDataHash:completionHandler:),
                         @selector(obs_generateAssertion:clientDataHash:completionHandler:));
    }
    if (dcdev) {
        g_dcdevInstalled = YES;
        MARK(@"CLASS_PRESENT DCDevice");
        swizzleAndVerify(dcdev, @selector(generateTokenWithCompletionHandler:),
                         @selector(obs_generateTokenWithCompletionHandler:));
    }
    return YES;
}

__attribute__((constructor))
static void attestobserver_init(void) {
    MARK(@"OBSERVER_LOADED");
    // DeviceCheck.framework may load lazily; retry a few times before giving up.
    // Both classes live in the same framework, so once either is hooked the
    // framework is up; the per-class flags make every later call a no-op for
    // classes already exchanged (see the involution note above).
    BOOL first = installHooks();
    if (first && g_attestInstalled && g_dcdevInstalled) return;
    for (int i = 1; i <= 3; i++) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(i * 2 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            if (g_attestInstalled && g_dcdevInstalled) return;   // installed: never re-exchange
            if (NSClassFromString(@"DCAppAttestService") || NSClassFromString(@"DCDevice")) {
                installHooks();
            } else if (i == 3 && !g_attestInstalled && !g_dcdevInstalled) {
                MARK(@"CLASS_ABSENT_FINAL");
            }
        });
    }
}
