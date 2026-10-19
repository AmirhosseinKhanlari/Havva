//
// EntitlementShim - generic neutralizer for re-sign entitlement-loss crashes.
//
// When a store app is re-signed with our (free/dev) profile, Apple's RESTRICTED
// entitlements (TV-provider SSO, etc.) cannot be carried. At launch the matching
// Apple framework method then raises an uncaught NSException and the app abort()s
// -- a crash that LOOKS like anti-tamper but is just lost entitlements. For our
// measurement that is a CONFOUND: it must not be counted as tamper detection.
//
// This dylib does NOT grant any entitlement (impossible for restricted ones). It
// only stops the resulting exception from killing the process, so the real
// pinning / App Attest probe can run. Three layers:
//
//   1. Targeted wrap: a table of (class, selector) whose calls are wrapped in
//      @try/@catch (swallow). Applied at constructor time and re-applied from
//      the (main-thread) UIApplication setDelegate: hook, so frameworks that
//      load after our constructor are still covered. Seeded with the known
//      VideoSubscriberAccount case; extend via env ENTSHIM_TARGETS.
//
//   2. Generic delegate net: wraps the app delegate's
//      application:will/didFinishLaunchingWithOptions: and swallows ONLY
//      exceptions whose name/reason looks entitlement-related (re-raises anything
//      else, so genuine app bugs still crash). Env ENTSHIM_MATCH_ALL=1 makes it
//      swallow every launch exception (aggressive mode for stubborn apps).
//
//   3. Generic scene net: scene-based apps (UIApplicationSceneManifest) run their
//      SSO / entitlement setup in scene:willConnectToSession:options: rather than
//      in the app delegate; the scene delegate's connect callback is wrapped with
//      the same entitlement-reason filter (SWALLOWED_SCENE / RERAISE_SCENE).
//
// There is deliberately NO dyld add-image callback: doing ObjC runtime work
// (class lookup, method swizzling, NSString) while dyld holds its loader lock
// deadlocks launch. Everything here runs from our constructor or from a UIKit
// setter on the main thread.
//
// Observe-safe, constructor-time install, NSLog markers (idevicesyslog).
//

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <os/lock.h>

#define MARK(fmt, ...) NSLog(@"ENTSHIM " fmt, ##__VA_ARGS__)

// ---------------------------------------------------------------------------
// Registry of wrapped methods: maps (class, selector) -> original IMP so the
// shared trampolines can forward. Small linear table; writes under a lock.
// ---------------------------------------------------------------------------
typedef struct { Class cls; SEL sel; IMP orig; } Entry;
static Entry g_entries[256];
static int g_nentries = 0;
static os_unfair_lock g_lock = OS_UNFAIR_LOCK_INIT;

// Find the original IMP for (class-of-self, _cmd). Matched by CLASS ONLY:
// walk self's class and its superclasses and take the first entry whose class
// is exactly that class. The old selector-only fallback is gone: with two
// unrelated classes wrapped for the same selector it could forward one class's
// call into the other's implementation.
static IMP lookupOrig(id self, SEL _cmd) {
    IMP found = NULL;
    os_unfair_lock_lock(&g_lock);
    for (Class c = object_getClass(self); c && !found; c = class_getSuperclass(c)) {
        for (int i = 0; i < g_nentries; i++) {
            if (g_entries[i].sel == _cmd && g_entries[i].cls == c) {
                found = g_entries[i].orig; break;
            }
        }
    }
    os_unfair_lock_unlock(&g_lock);
    return found;
}

// Returns NO when the table is full. Callers MUST NOT install a trampoline in
// that case: a trampoline without a registry entry would find no original and
// silently turn the method into a no-op.
static BOOL recordEntry(Class cls, SEL sel, IMP orig) {
    BOOL ok = NO;
    os_unfair_lock_lock(&g_lock);
    if (g_nentries < (int)(sizeof(g_entries) / sizeof(g_entries[0]))) {
        g_entries[g_nentries++] = (Entry){cls, sel, orig};
        ok = YES;
    }
    os_unfair_lock_unlock(&g_lock);
    return ok;
}

static void logSwallow(SEL _cmd, NSException *e) {
    MARK(@"SWALLOWED %@ -- %@ : %@", NSStringFromSelector(_cmd), e.name, e.reason);
}

// ---------------------------------------------------------------------------
// Generic swallow trampolines, one per integer-arg arity. Args/returns use
// pointer-width slots: on arm64 this preserves the bits of scalar (BOOL/NSInteger)
// args and x0 returns. Float/struct-by-value signatures are not supported and are
// skipped at wrap time (logged).
// ---------------------------------------------------------------------------
static id ent_u0(id self, SEL _cmd) {
    IMP o = lookupOrig(self, _cmd); if (!o) return nil;
    @try { return ((id (*)(id, SEL))o)(self, _cmd); }
    @catch (NSException *e) { logSwallow(_cmd, e); return nil; }
}
static id ent_u1(id self, SEL _cmd, void *a) {
    IMP o = lookupOrig(self, _cmd); if (!o) return nil;
    @try { return ((id (*)(id, SEL, void *))o)(self, _cmd, a); }
    @catch (NSException *e) { logSwallow(_cmd, e); return nil; }
}
static id ent_u2(id self, SEL _cmd, void *a, void *b) {
    IMP o = lookupOrig(self, _cmd); if (!o) return nil;
    @try { return ((id (*)(id, SEL, void *, void *))o)(self, _cmd, a, b); }
    @catch (NSException *e) { logSwallow(_cmd, e); return nil; }
}
static id ent_u3(id self, SEL _cmd, void *a, void *b, void *c) {
    IMP o = lookupOrig(self, _cmd); if (!o) return nil;
    @try { return ((id (*)(id, SEL, void *, void *, void *))o)(self, _cmd, a, b, c); }
    @catch (NSException *e) { logSwallow(_cmd, e); return nil; }
}
static id ent_u4(id self, SEL _cmd, void *a, void *b, void *c, void *d) {
    IMP o = lookupOrig(self, _cmd); if (!o) return nil;
    @try { return ((id (*)(id, SEL, void *, void *, void *, void *))o)(self, _cmd, a, b, c, d); }
    @catch (NSException *e) { logSwallow(_cmd, e); return nil; }
}

static IMP pickTramp(int objArgs) {
    switch (objArgs) {
        case 0: return (IMP)ent_u0;
        case 1: return (IMP)ent_u1;
        case 2: return (IMP)ent_u2;
        case 3: return (IMP)ent_u3;
        case 4: return (IMP)ent_u4;
        default: return NULL;
    }
}

// Forward decls of the delegate/scene trampolines so isOurTramp can see them.
static signed char ent_launch(id self, SEL _cmd, id app, id opts);
static void ent_scene_connect(id self, SEL _cmd, id scene, id session, id opts);

static BOOL isOurTramp(IMP p) {
    return p == (IMP)ent_u0 || p == (IMP)ent_u1 || p == (IMP)ent_u2 ||
           p == (IMP)ent_u3 || p == (IMP)ent_u4 ||
           p == (IMP)ent_launch || p == (IMP)ent_scene_connect;
}

// Supported = all args + return fit in integer registers (no 'f'/'d' float,
// no '{' struct). Entitlement-gated setters/getters are object/scalar; this holds.
static BOOL sigSupported(Method m) {
    char ret[64] = {0};
    method_getReturnType(m, ret, sizeof(ret));
    if (ret[0] == 'f' || ret[0] == 'd' || ret[0] == '{' || ret[0] == '(') return NO;
    unsigned n = method_getNumberOfArguments(m);
    for (unsigned i = 2; i < n; i++) {
        char *t = method_copyArgumentType(m, i);
        if (!t) return NO;
        char c = t[0]; free(t);
        if (c == 'f' || c == 'd' || c == '{' || c == '(') return NO;
    }
    return YES;
}

// ---------------------------------------------------------------------------
// Install helper shared by every wrap site.
//
// class_getInstanceMethod(cls, sel) returns the Method found by walking UP the
// hierarchy, so for an inherited method it is the SUPERCLASS's Method object.
// method_setImplementation on that would clobber the superclass for every
// subclass (and every unrelated subclass) at once. When the method is
// inherited we instead class_addMethod an override on the exact class and
// record the superclass IMP as the original; when it is the class's own
// method we swap its IMP in place.
// Registry first, trampoline second: never install without an entry.
// ---------------------------------------------------------------------------
static BOOL installTramp(Class cls, SEL sel, Method m, IMP tramp, const char *tag) {
    IMP cur = method_getImplementation(m);
    Class sup = class_getSuperclass(cls);
    BOOL inherited = (sup != Nil) && (class_getInstanceMethod(sup, sel) == m);
    if (!recordEntry(cls, sel, cur)) {
        MARK(@"REGISTRY_FULL %s %s (not wrapped)", class_getName(cls), sel_getName(sel));
        return NO;
    }
    if (inherited) {
        if (!class_addMethod(cls, sel, tramp, method_getTypeEncoding(m))) {
            // Cannot happen (we just saw the class has no own copy), but be loud.
            MARK(@"ADD_METHOD_FAILED %s %s", class_getName(cls), sel_getName(sel));
            return NO;
        }
        MARK(@"%s %s %s (override of inherited %s)", tag, class_getName(cls),
             sel_getName(sel), class_getName(sup));
    } else {
        method_setImplementation(m, tramp);
        MARK(@"%s %s %s", tag, class_getName(cls), sel_getName(sel));
    }
    return YES;
}

// ---------------------------------------------------------------------------
// Targeted wrapping.
// ---------------------------------------------------------------------------
typedef struct { const char *cls; const char *sel; } Target;
static Target g_targets[256];
static int g_ntargets = 0;

static void addTarget(const char *cls, const char *sel) {
    if (g_ntargets < (int)(sizeof(g_targets) / sizeof(g_targets[0])))
        g_targets[g_ntargets++] = (Target){cls, sel};
}

static void wrapOne(const char *clsName, const char *selName) {
    Class cls = objc_getClass(clsName);
    if (!cls) return;  // framework not loaded yet; re-scanned from the setDelegate: hook
    SEL sel = sel_registerName(selName);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    IMP cur = method_getImplementation(m);
    if (isOurTramp(cur)) return;  // already wrapped (on this class or an ancestor)
    if (!sigSupported(m)) { MARK(@"UNSUPPORTED_SIG %s %s", clsName, selName); return; }
    int objArgs = (int)method_getNumberOfArguments(m) - 2;
    IMP tr = pickTramp(objArgs);
    if (!tr) { MARK(@"UNSUPPORTED_ARITY %s %s (%d)", clsName, selName, objArgs); return; }
    installTramp(cls, sel, m, tr, "WRAPPED");
}

static void wrapAllTargets(void) {
    for (int i = 0; i < g_ntargets; i++) wrapOne(g_targets[i].cls, g_targets[i].sel);
}

// ---------------------------------------------------------------------------
// Generic delegate-level net: catch entitlement exceptions thrown anywhere in
// the launch delegate callbacks (covers entitlements we did not enumerate).
// ---------------------------------------------------------------------------
static BOOL g_matchAll = NO;

static BOOL looksLikeEntitlement(NSException *e) {
    if (g_matchAll) return YES;
    NSString *s = [[NSString stringWithFormat:@"%@ %@", e.name ?: @"", e.reason ?: @""]
                   lowercaseString];
    const char *needles[] = {
        "entitlement", "not authorized", "not entitled", "not permitted",
        "requires the", "requires an", "privacy-sensitive data without a usage",
        "is missing", "provisioning profile", "restricted",
    };
    for (size_t i = 0; i < sizeof(needles) / sizeof(needles[0]); i++)
        if ([s containsString:@(needles[i])]) return YES;
    return NO;
}

// Trampoline for -application:will/didFinishLaunchingWithOptions: (returns BOOL).
static signed char ent_launch(id self, SEL _cmd, id app, id opts) {
    IMP o = lookupOrig(self, _cmd);
    @try {
        if (o) return ((signed char (*)(id, SEL, id, id))o)(self, _cmd, app, opts);
        return 1;
    } @catch (NSException *e) {
        if (looksLikeEntitlement(e)) {
            MARK(@"SWALLOWED_DELEGATE %@ -- %@ : %@", NSStringFromSelector(_cmd), e.name, e.reason);
            return 1;
        }
        MARK(@"RERAISE_DELEGATE %@ -- %@ : %@", NSStringFromSelector(_cmd), e.name, e.reason);
        @throw;  // genuine app exception: let it crash as it would have
    }
}

// Trampoline for -scene:willConnectToSession:options: (void). Same filter.
static void ent_scene_connect(id self, SEL _cmd, id scene, id session, id opts) {
    IMP o = lookupOrig(self, _cmd);
    if (!o) return;
    @try {
        ((void (*)(id, SEL, id, id, id))o)(self, _cmd, scene, session, opts);
    } @catch (NSException *e) {
        if (looksLikeEntitlement(e)) {
            MARK(@"SWALLOWED_SCENE %@ -- %@ : %@", NSStringFromSelector(_cmd), e.name, e.reason);
            return;
        }
        MARK(@"RERAISE_SCENE %@ -- %@ : %@", NSStringFromSelector(_cmd), e.name, e.reason);
        @throw;
    }
}

// Wrap one delegate callback on the exact delegate class with a fixed-signature
// trampoline (no arity/signature inference: the selector fixes the shape).
static void wrapDelegateCallback(Class cls, const char *selName, IMP tramp, const char *tag) {
    if (!cls) return;
    SEL sel = sel_registerName(selName);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;  // delegate doesn't implement this one
    if (isOurTramp(method_getImplementation(m))) return;  // already (here or an ancestor)
    installTramp(cls, sel, m, tramp, tag);
}

static void wrapDelegateLaunch(Class cls, const char *selName) {
    wrapDelegateCallback(cls, selName, (IMP)ent_launch, "WRAPPED_DELEGATE");
}

static void wrapSceneDelegate(Class cls) {
    wrapDelegateCallback(cls, "scene:willConnectToSession:options:",
                         (IMP)ent_scene_connect, "WRAPPED_SCENE");
}

// Scene delegates named statically in Info.plist (UIApplicationSceneManifest ->
// UISceneConfigurations -> <role> -> [{UISceneDelegateClassName}]). Wrapping them
// here, from the app-delegate hook, covers apps whose scene delegate is set
// through a path that bypasses the public setDelegate: setter.
static void wrapManifestSceneDelegates(void) {
    NSDictionary *manifest = [[NSBundle mainBundle] infoDictionary][@"UIApplicationSceneManifest"];
    if (![manifest isKindOfClass:[NSDictionary class]]) return;
    NSDictionary *confs = manifest[@"UISceneConfigurations"];
    if (![confs isKindOfClass:[NSDictionary class]]) return;
    for (id role in confs) {
        NSArray *list = confs[role];
        if (![list isKindOfClass:[NSArray class]]) continue;
        for (NSDictionary *conf in list) {
            if (![conf isKindOfClass:[NSDictionary class]]) continue;
            NSString *name = conf[@"UISceneDelegateClassName"];
            if (![name isKindOfClass:[NSString class]] || !name.length) continue;
            Class dc = NSClassFromString(name);
            if (dc) wrapSceneDelegate(dc);
            else MARK(@"SCENE_DELEGATE_CLASS_MISSING %@", name);
        }
    }
}

// Swizzle -[UIApplication setDelegate:] so we learn the delegate class and wrap
// its launch callbacks before they run.
static IMP g_orig_setDelegate = NULL;
static void ent_setDelegate(id self, SEL _cmd, id delegate) {
    if (delegate) {
        Class dc = object_getClass(delegate);
        wrapDelegateLaunch(dc, "application:didFinishLaunchingWithOptions:");
        wrapDelegateLaunch(dc, "application:willFinishLaunchingWithOptions:");
        // By now most frameworks are loaded; re-run the targeted pass to catch any
        // whose class was not yet available at constructor time. Safe: main thread,
        // no dyld loader lock held.
        wrapAllTargets();
        wrapManifestSceneDelegates();
    }
    if (g_orig_setDelegate)
        ((void (*)(id, SEL, id))g_orig_setDelegate)(self, _cmd, delegate);
}

// Swizzle -[UIWindowScene setDelegate:] (falling back to UIScene) so the scene
// delegate's connect callback is wrapped before UIKit delivers it.
static IMP g_orig_setSceneDelegate = NULL;
static void ent_setSceneDelegate(id self, SEL _cmd, id delegate) {
    if (delegate) wrapSceneDelegate(object_getClass(delegate));
    if (g_orig_setSceneDelegate)
        ((void (*)(id, SEL, id))g_orig_setSceneDelegate)(self, _cmd, delegate);
}

static void installDelegateNet(void) {
    Class ua = objc_getClass("UIApplication");
    if (!ua) {
        // UIKit is a direct dependency of every app binary, so it is mapped and
        // its classes registered before our constructor runs; if it is still
        // missing the delegate net cannot be armed (there is no retry on purpose:
        // see the add-image note at the top).
        MARK(@"DELEGATE_NET_MISSING (UIApplication class not available)");
        return;
    }
    SEL sel = sel_registerName("setDelegate:");
    Method m = class_getInstanceMethod(ua, sel);
    if (!m) { MARK(@"DELEGATE_NET_MISSING (-[UIApplication setDelegate:] not found)"); return; }
    if (method_getImplementation(m) == (IMP)ent_setDelegate) return;  // already
    g_orig_setDelegate = method_setImplementation(m, (IMP)ent_setDelegate);
    MARK(@"DELEGATE_NET_ARMED");
}

static void installSceneNet(void) {
    const char *which = "UIWindowScene";
    Class sc = objc_getClass(which);
    if (!sc) { which = "UIScene"; sc = objc_getClass(which); }
    if (!sc) {
        // iOS 12 or no UIKit scenes at all: delegate net alone applies.
        MARK(@"SCENE_NET_MISSING (no UIWindowScene/UIScene class)");
        return;
    }
    SEL sel = sel_registerName("setDelegate:");
    Method m = class_getInstanceMethod(sc, sel);
    if (!m) { MARK(@"SCENE_NET_MISSING (-[%s setDelegate:] not found)", which); return; }
    if (method_getImplementation(m) == (IMP)ent_setSceneDelegate) return;  // already
    // The setter is defined on UIScene and inherited by UIWindowScene; swapping
    // the IMP on the Method object we found (whichever class owns it) covers
    // every scene subclass with one original, which is what we want here.
    g_orig_setSceneDelegate = method_setImplementation(m, (IMP)ent_setSceneDelegate);
    MARK(@"SCENE_NET_ARMED (%s)", which);
}

// ---------------------------------------------------------------------------
// Target seeding + env extension.
// ---------------------------------------------------------------------------
static void seedTargets(void) {
    // Known restricted-entitlement thrower (Paramount+, many TV-provider apps).
    addTarget("VSSubscriptionRegistrationCenter", "setCurrentSubscription:");

    // ENTSHIM_TARGETS="Class sel:,Other selWith:arg:" (space between class & sel).
    const char *env = getenv("ENTSHIM_TARGETS");
    if (env && env[0]) {
        NSString *all = [NSString stringWithUTF8String:env];
        for (NSString *pair in [all componentsSeparatedByString:@","]) {
            NSString *p = [pair stringByTrimmingCharactersInSet:
                           [NSCharacterSet whitespaceCharacterSet]];
            NSRange sp = [p rangeOfString:@" "];
            if (sp.location == NSNotFound) continue;
            NSString *c = [p substringToIndex:sp.location];
            NSString *s = [[p substringFromIndex:sp.location + 1]
                           stringByTrimmingCharactersInSet:
                           [NSCharacterSet whitespaceCharacterSet]];
            if (c.length && s.length) {
                addTarget(strdup(c.UTF8String), strdup(s.UTF8String));
                MARK(@"TARGET_ADDED %@ %@", c, s);
            }
        }
    }
    const char *ma = getenv("ENTSHIM_MATCH_ALL");
    if (ma && (ma[0] == '1' || ma[0] == 'y' || ma[0] == 'Y')) {
        g_matchAll = YES;
        MARK(@"MATCH_ALL enabled");
    }
}

__attribute__((constructor))
static void entshim_init(void) {
    @autoreleasepool {
        MARK(@"LOADED");
        seedTargets();
        // Nudge the known default framework so its class exists for the first pass.
        dlopen("/System/Library/Frameworks/VideoSubscriberAccount.framework/VideoSubscriberAccount",
               RTLD_NOW | RTLD_GLOBAL);
        installDelegateNet();
        installSceneNet();
        // First targeted pass for frameworks already loaded. Frameworks that load
        // later are re-scanned in ent_setDelegate (safe, main thread). There is no
        // dyld add-image callback on purpose: ObjC work under the loader lock
        // deadlocks launch.
        wrapAllTargets();
        MARK(@"READY (%d targets)", g_ntargets);
    }
}
