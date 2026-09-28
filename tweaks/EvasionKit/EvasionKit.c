/*
 * EvasionKit - bounded detection-neutralization for measurement hygiene.
 *
 * Scope (agreed): avoid TRIVIAL detection of our own instrumentation so a
 * bypassable app is not mislabeled as protected. It neutralizes the standard,
 * documented detectors only. It does NOT and cannot defeat server-enforced
 * App Attest; that residue is a reported finding, not something to beat.
 *
 * Non-jailbroken target, so the relevant vectors are:
 *   1. injected-image enumeration (_dyld_image_count / _dyld_get_image_name)
 *   2. anti-debug (ptrace PT_DENY_ATTACH, sysctl P_TRACED)
 *   3. code-signature self-inspection (csops flags)
 *
 * Built as a fishhook dylib (non-JB), injected + re-signed like the others.
 * Requires fishhook (github.com/facebook/fishhook); see Makefile.
 */

#include <string.h>
#include <stdint.h>
#include <sys/sysctl.h>
#include <mach-o/dyld.h>
#include <dlfcn.h>
#include "fishhook.h"

/* Names of our own injected libraries to hide from image enumeration. */
static const char *kHiddenNames[] = {
    "libAudioBridge.dylib",   /* SSKS alias */
    "ChromaBridge.dylib",     /* Frida gadget alias */
    "libSystemBridge.dylib",  /* this module's install name */
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

/* Build an index map that skips hidden images, computed lazily each call. */
static uint32_t visible_count(void) {
    uint32_t real = orig_dyld_image_count();
    uint32_t n = 0;
    for (uint32_t i = 0; i < real; i++) {
        const char *nm = orig_dyld_get_image_name(i);
        if (!is_hidden(nm)) n++;
    }
    return n;
}

static const char *visible_name(uint32_t vindex) {
    uint32_t real = orig_dyld_image_count();
    uint32_t n = 0;
    for (uint32_t i = 0; i < real; i++) {
        const char *nm = orig_dyld_get_image_name(i);
        if (is_hidden(nm)) continue;
        if (n == vindex) return nm;
        n++;
    }
    return orig_dyld_get_image_name(vindex); /* fallback */
}

static uint32_t my_dyld_image_count(void) { return visible_count(); }
static const char *my_dyld_get_image_name(uint32_t i) { return visible_name(i); }

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
    /* Clear the P_TRACED flag if the app probes kinfo_proc. */
    if (r == 0 && namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC &&
        name[2] == KERN_PROC_PID && oldp) {
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
    rebind_symbols((struct rebinding[]){
        {"_dyld_image_count", (void *)my_dyld_image_count, (void **)&orig_dyld_image_count},
        {"_dyld_get_image_name", (void *)my_dyld_get_image_name, (void **)&orig_dyld_get_image_name},
        {"ptrace", (void *)my_ptrace, (void **)&orig_ptrace},
        {"sysctl", (void *)my_sysctl, (void **)&orig_sysctl},
        {"csops", (void *)my_csops, (void **)&orig_csops},
    }, 5);
}
