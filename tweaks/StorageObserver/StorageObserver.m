// StorageObserver.dylib
//
// Injected into the re-signed app for the data-storage probe. From INSIDE the
// process it can see two things the AFC container pull cannot:
//   1. the Data Protection class of every file in the data container
//      (NSFileProtectionKey), which decides whether "sensitive value in a file"
//      is a finding or just a class-C file like everything else;
//   2. the app's own Keychain items with their kSecAttrAccessible value
//      (kSecAttrAccessibleAlways / AlwaysThisDeviceOnly are the weak classes).
// It logs a marker trail via NSLog (os_log info/debug is filtered out of
// idevicesyslog), mirroring AttestObserver. Values are NEVER logged: only
// paths, classes, service/label names and the account's length.
//
//   STORAGEOBS BEGIN <n>
//   STORAGEOBS FILE <protection-class> <size> <relative/path>
//   STORAGEOBS KEYCHAIN class=<genp|inet|cert|keys|idnt> acc=<ak|ck|dk|...> agrp=<group> svce=<service> labl=<label> acct_len=<n>
//   STORAGEOBS END <n> files=<f> keychain=<k>
//
// A dump runs 6s after load, every 10s while active, and on
// DidEnterBackground / WillTerminate, so the trail reflects what the run wrote.

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <UIKit/UIKit.h>

#define MARK(fmt, ...) NSLog(@"STORAGEOBS " fmt, ##__VA_ARGS__)

static NSUInteger g_dump = 0;
static const NSUInteger kMaxFiles = 3000;

static NSString *protClass(NSString *path) {
    NSError *err = nil;
    NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:&err];
    if (!attrs) return @"unreadable";
    NSString *p = attrs[NSFileProtectionKey];
    return p ?: @"none-reported";
}

static NSUInteger dumpFiles(void) {
    NSString *home = NSHomeDirectory();
    NSFileManager *fm = [NSFileManager defaultManager];
    NSDirectoryEnumerator *en = [fm enumeratorAtPath:home];
    NSUInteger n = 0;
    NSString *rel;
    while ((rel = [en nextObject])) {
        if (n >= kMaxFiles) { MARK(@"FILE-CAP %lu", (unsigned long)kMaxFiles); break; }
        NSDictionary *a = [en fileAttributes];
        if (![a[NSFileType] isEqualToString:NSFileTypeRegular]) continue;
        NSString *full = [home stringByAppendingPathComponent:rel];
        unsigned long long size = [a[NSFileSize] unsignedLongLongValue];
        MARK(@"FILE %@ %llu %@", protClass(full), size, rel);
        n++;
    }
    return n;
}

static NSString *str(id v) {
    if (!v) return @"-";
    if ([v isKindOfClass:[NSString class]]) return [v stringByReplacingOccurrencesOfString:@" " withString:@"_"];
    if ([v isKindOfClass:[NSData class]]) return [NSString stringWithFormat:@"<data:%lu>", (unsigned long)[(NSData *)v length]];
    return [[v description] stringByReplacingOccurrencesOfString:@" " withString:@"_"];
}

static NSUInteger dumpKeychain(void) {
    NSArray *classes = @[(__bridge id)kSecClassGenericPassword, (__bridge id)kSecClassInternetPassword,
                         (__bridge id)kSecClassCertificate, (__bridge id)kSecClassKey,
                         (__bridge id)kSecClassIdentity];
    NSArray *names = @[@"genp", @"inet", @"cert", @"keys", @"idnt"];
    NSUInteger n = 0;
    for (NSUInteger i = 0; i < classes.count; i++) {
        NSDictionary *q = @{(__bridge id)kSecClass: classes[i],
                            (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,
                            (__bridge id)kSecReturnAttributes: @YES};
        CFTypeRef result = NULL;
        OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &result);
        if (st != errSecSuccess || !result) { if (result) CFRelease(result); continue; }
        NSArray *items = (__bridge_transfer NSArray *)result;
        for (NSDictionary *it in items) {
            id acct = it[(__bridge id)kSecAttrAccount];
            NSUInteger alen = [acct isKindOfClass:[NSString class]] ? [(NSString *)acct length] :
                              ([acct isKindOfClass:[NSData class]] ? [(NSData *)acct length] : 0);
            MARK(@"KEYCHAIN class=%@ acc=%@ agrp=%@ svce=%@ labl=%@ acct_len=%lu",
                 names[i], str(it[(__bridge id)kSecAttrAccessible]), str(it[(__bridge id)kSecAttrAccessGroup]),
                 str(it[(__bridge id)kSecAttrService]), str(it[(__bridge id)kSecAttrLabel]), (unsigned long)alen);
            n++;
        }
    }
    return n;
}

static void dump(void) {
    @autoreleasepool {
        NSUInteger id_ = ++g_dump;
        MARK(@"BEGIN %lu", (unsigned long)id_);
        NSUInteger f = dumpFiles();
        NSUInteger k = dumpKeychain();
        MARK(@"END %lu files=%lu keychain=%lu", (unsigned long)id_, (unsigned long)f, (unsigned long)k);
    }
}

static void dumpAsync(void) {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{ dump(); });
}

__attribute__((constructor))
static void storageobs_init(void) {
    @autoreleasepool {
        MARK(@"LOADED %@", [[NSBundle mainBundle] bundleIdentifier] ?: @"?");
        NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
        [nc addObserverForName:UIApplicationDidEnterBackgroundNotification object:nil queue:nil
                    usingBlock:^(NSNotification *n) { dump(); }];
        [nc addObserverForName:UIApplicationWillTerminateNotification object:nil queue:nil
                    usingBlock:^(NSNotification *n) { dump(); }];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(6 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            dumpAsync();
            // Repeat while the app lives; the probe window is 30-60s.
            dispatch_source_t t = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
                                                         dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));
            dispatch_source_set_timer(t, dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC),
                                      10 * NSEC_PER_SEC, 1 * NSEC_PER_SEC);
            dispatch_source_set_event_handler(t, ^{ dump(); });
            dispatch_resume(t);
            static dispatch_source_t keep; keep = t;
        });
    }
}
