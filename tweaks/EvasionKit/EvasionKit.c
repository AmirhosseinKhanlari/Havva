/*
 * EvasionKit - bounded detection-neutralization for measurement hygiene.
 *
 * Scope (agreed): avoid TRIVIAL detection of our own instrumentation so a
 * bypassable app is not mislabeled as protected. It neutralizes the standard,
 * documented detectors only. It does NOT and cannot defeat server-enforced
 * App Attest; that residue is a reported finding, not something to beat.
 *
 * Non-jailbroken target, so the relevant vectors are:
 *   1. injected-image enumeration (_dyld_image_count / _dyld_get_image_name /
 *      _dyld_get_image_header / _dyld_get_image_vmaddr_slide, all remapped
 *      through ONE visible-index mapping so index i is the same image in
 *      every API)
 *   2. anti-debug (ptrace PT_DENY_ATTACH, sysctl P_TRACED)
 *   3. code-signature self-inspection (csops flags)
 *
 * Built as a fishhook dylib (non-JB), injected + re-signed like the others.
 * Requires fishhook (github.com/facebook/fishhook); see Makefile.
 */

#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/sysctl.h>
#include <mach-o/dyld.h>
#include <dlfcn.h>
#include "fishhook.h"

/* Names of our own injected libraries to hide from image enumeration.
 * Both the build names and the instrument.py aliases (the names the dylibs
 * actually carry inside the re-signed bundle) are listed. */
static const char *kHiddenNames[] = {
    "libAudioBridge.dylib",    /* SSKS alias */
    "ChromaBridge.dylib",      /* Frida gadget alias */
    "libSystemBridge.dylib",   /* this module's alias / install name */
    "libMobileBridge.dylib",   /* SideloadFix alias */
    "libServiceBridge.dylib",  /* AttestObserver alias */
    "libAccountBridge.dylib",  /* EntitlementShim alias */
    "EvasionKit.dylib",
    "AttestObserver.dylib",
    "EntitlementShim.dylib",
    "sideloadFixerLol.dylib",
    "SSLKillSwitch2.dylib",
    "FridaGadget.dylib",
    "frida", "cynject", "substrate",
};
static const int kHiddenCount = sizeof(kHiddenNames) / sizeof(kHiddenNames[0]);

static int is_hidden(const char *name) {
    if (!name) return 0;
    for (int i = 0; i < kHiddenCount; i++) {
        if (strstr(name, kHiddenNames[i])) return 1;
    }
    return 0;
}

/* ---- _dyld image enumeration: present a filtered view ---- */

static uint32_t (*orig_dyld_image_count)(void);
static const char *(*orig_dyld_get_image_name)(uint32_t);
static const struct mach_header *(*orig_dyld_get_image_header)(uint32_t);
static intptr_t (*orig_dyld_get_image_vmaddr_slide)(uint32_t);

/* Count of visible (non-hidden) images, computed lazily each call. */
static uint32_t visible_count(void) {
    uint32_t real = orig_dyld_image_count();
    uint32_t n = 0;
    for (uint32_t i = 0; i < real; i++) {
        const char *nm = orig_dyld_get_image_name(i);
        if (!is_hidden(nm)) n++;
    }
    return n;
}

/* The single visible-index -> real-index mapping shared by every remapped
 * dyld API. Returns 1 and fills *real_out when `vindex` names a visible
 * image, 0 when it is out of range (callers then return NULL/0 exactly like
 * libdyld does for an invalid index -- never a hidden image's data). */
static int visible_to_real(uint32_t vindex, uint32_t *real_out) {
    uint32_t real = orig_dyld_image_count();
    uint32_t n = 0;
    for (uint32_t i = 0; i < real; i++) {
        const char *nm = orig_dyld_get_image_name(i);
        if (is_hidden(nm)) continue;
        if (n == vindex) { *real_out = i; return 1; }
        n++;
    }
    return 0;
}

static const char *visible_name(uint32_t vindex) {
    uint32_t r;
    if (!visible_to_real(vindex, &r)) return NULL;   /* out of range: no fallback */
    return orig_dyld_get_image_name(r);
}

static const struct mach_header *visible_header(uint32_t vindex) {
    uint32_t r;
    if (!visible_to_real(vindex, &r)) return NULL;
    return orig_dyld_get_image_header(r);
}

static intptr_t visible_slide(uint32_t vindex) {
    uint32_t r;
    if (!visible_to_real(vindex, &r)) return 0;
    return orig_dyld_get_image_vmaddr_slide(r);
}

static uint32_t my_dyld_image_count(void) { return visible_count(); }
static const char *my_dyld_get_image_name(uint32_t i) { return visible_name(i); }
static const struct mach_header *my_dyld_get_image_header(uint32_t i) { return visible_header(i); }
static intptr_t my_dyld_get_image_vmaddr_slide(uint32_t i) { return visible_slide(i); }

/* ---- anti-debug: ptrace + sysctl ---- */

static int (*orig_ptrace)(int, int, void *, int);
static int my_ptrace(int request, int pid, void *addr, int data) {
    /* PT_DENY_ATTACH (31): swallow it so the process is not killed/hardened. */
    if (request == 31) return 0;
    return orig_ptrace(request, pid, addr, data);
}

static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static int my_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp,
                     void *newp, size_t newlen) {
    int r = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    /* Clear the P_TRACED flag if the app probes kinfo_proc. Only touch the
     * buffer when the caller actually supplied one large enough to hold a
     * whole kinfo_proc (a size-query call passes oldp == NULL, and a short
     * buffer must not be written past its end). */
    if (r == 0 && namelen == 4 && name != NULL && name[0] == CTL_KERN &&
        name[1] == KERN_PROC && name[2] == KERN_PROC_PID &&
        oldp != NULL && oldlenp != NULL && *oldlenp >= sizeof(struct kinfo_proc)) {
        struct kinfo_proc *kp = (struct kinfo_proc *)oldp;
        kp->kp_proc.p_flag &= ~P_TRACED;
    }
    return r;
}

/* ---- code-signature self-inspection: mask via csops ---- */

extern int csops(pid_t, unsigned int, void *, size_t);
static int (*orig_csops)(pid_t, unsigned int, void *, size_t);
#define CS_OPS_STATUS 0
#define CS_VALID 0x0000001
#define CS_DEBUGGED 0x10000000
static int my_csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
    int r = orig_csops(pid, ops, useraddr, usersize);
    if (ops == CS_OPS_STATUS && useraddr && usersize >= sizeof(uint32_t)) {
        uint32_t *flags = (uint32_t *)useraddr;
        *flags |= CS_VALID;
        *flags &= ~CS_DEBUGGED;
    }
    return r;
}

__attribute__((constructor))
static void evasionkit_init(void) {
    /* Pre-seed the originals with the real libdyld entry points (resolved at
     * load, before any rebinding) so the shared index mapping never calls a
     * NULL pointer even if fishhook rebinds only a subset of the four. */
    orig_dyld_image_count = _dyld_image_count;
    orig_dyld_get_image_name = _dyld_get_image_name;
    orig_dyld_get_image_header = _dyld_get_image_header;
    orig_dyld_get_image_vmaddr_slide = _dyld_get_image_vmaddr_slide;
    rebind_symbols((struct rebinding[]){
        {"_dyld_image_count", (void *)my_dyld_image_count, (void **)&orig_dyld_image_count},
        {"_dyld_get_image_name", (void *)my_dyld_get_image_name, (void **)&orig_dyld_get_image_name},
        {"_dyld_get_image_header", (void *)my_dyld_get_image_header, (void **)&orig_dyld_get_image_header},
        {"_dyld_get_image_vmaddr_slide", (void *)my_dyld_get_image_vmaddr_slide, (void **)&orig_dyld_get_image_vmaddr_slide},
        {"ptrace", (void *)my_ptrace, (void **)&orig_ptrace},
        {"sysctl", (void *)my_sysctl, (void **)&orig_sysctl},
        {"csops", (void *)my_csops, (void **)&orig_csops},
    }, 7);
}
