// Included only in the diagnostic build. Never log userInfo, localized text,
// request/response bodies, Keychain queries, account identifiers, or secrets.
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <stdatomic.h>
#include <string.h>
#include <os/log.h>

static _Thread_local BOOL LMDLogging;
static atomic_uint LMDErrorCount, LMDLocalizationCount, LMDContainerCount;

// Callers pass only sanitized fields. Explicit public visibility is necessary:
// NSLog's interpolated strings were redacted on the user's iOS 27 device.
static void LMDEmit(NSString *message) {
    os_log_with_type(OS_LOG_DEFAULT, OS_LOG_TYPE_DEFAULT, "%{public}@", message);
#ifdef LINE_DIAGNOSTICS_TESTING
    // Test-only capture of exactly the string sent to unified logging.
    fprintf(stderr, "%s\n", message.UTF8String);
#endif
}

static BOOL LMDInterestingKey(NSString *key) {
    return [@[@"common.error.applicationError", @"common.error.systemError",
              @"common.error.unknownError", @"authorize.dt.loginerror.general",
              @"authorize.e2ee.error"] containsObject:key ?: @""];
}

static NSString *LMDSafeDomain(NSString *domain) {
    // Only fixed, known domains are emitted. Unknown domains may contain data.
    NSArray *allowed = @[@"NSOSStatusErrorDomain", @"NSCocoaErrorDomain",
        @"NSPOSIXErrorDomain", @"NSURLErrorDomain", @"SAMKeychainErrorDomain",
        @"SecondAuthFactorPinCodeErrorDomain", @"LoginQRCodeErrorDomain",
        @"SecondaryPwlessLoginErrorDomain", @"RegistrationErrorDomain",
        @"CommonCryptoErrorDomain", @"LEGYHTTPErrorDomain",
        @"AccessTokenRefreshErrorDomain", @"AuthAccountReloginErrorDomain",
        // Additional fixed names found in this exact executable's strings.
        @"TalkThriftErrorDomain", @"LEGYErrorDomain", @"SSServerErrorDomain",
        @"VGuardErrorDomain", @"NLChannelGatewayErrorDomain", @"LIFFErrorDomain",
        @"ChannelPaakAuthnErrorDomain", @"PwlessCredentialErrorDomain",
        @"AccountRestoreErrorDomain", @"PrimaryQrCodeMigrationErrorDomain",
        @"LineEAPIntegrateErrorDomain", @"AccountAuthFactorEapConnectErrorDomain",
        @"LineAuthSeamlessLoginLineAuthSeamlessLoginErrorDomain",
        @"LineAuthPrimaryAccountInitFeatureQueryLineAuthPrimaryAccountInitFeatureQueryErrorDomain"];
    return [allowed containsObject:domain ?: @""] ? domain : @"other-redacted";
}

static NSString *LMDLINEFrames(void) {
    void *frames[32];
    int count = backtrace(frames, 32);
    NSMutableArray *offsets = [NSMutableArray array];
    for (int i = 0; i < count && offsets.count < 12; i++) {
        Dl_info info = {0};
        if (!dladdr(frames[i], &info) || !info.dli_fname || !info.dli_fbase) continue;
        const char *name = strrchr(info.dli_fname, '/');
        name = name ? name + 1 : info.dli_fname;
        if (strcmp(name, "LINE") != 0) continue;
        uintptr_t offset = (uintptr_t)frames[i] - (uintptr_t)info.dli_fbase;
        [offsets addObject:[NSString stringWithFormat:@"LINE+0x%lx", (unsigned long)offset]];
    }
    return [offsets componentsJoinedByString:@","];
}

static BOOL LMDShouldEmitError(NSString *domain, NSInteger code, NSString *frames) {
    static NSLock *lock;
    static NSMutableDictionary<NSString *, NSNumber *> *counts;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ lock = [NSLock new]; counts = [NSMutableDictionary new]; });
    // Full domain is used only in memory for deduplication, never emitted.
    NSString *key = [NSString stringWithFormat:@"%@|%ld|%@", domain ?: @"", (long)code, frames];
    [lock lock];
    NSNumber *previous = counts[key];
    BOOL emit = previous ? previous.unsignedIntValue < 3 : counts.count < 512;
    if (emit) counts[key] = @(previous.unsignedIntValue + 1);
    [lock unlock];
    return emit;
}

static void LMDLogError(NSString *domain, NSInteger code, const char *origin) {
    if (LMDLogging) return;
    LMDLogging = YES;
    NSString *frames = LMDLINEFrames();
    if (LMDShouldEmitError(domain, code, frames)) {
        atomic_fetch_add(&LMDErrorCount, 1);
        LMDEmit([NSString stringWithFormat:@"[LINELoginDiag] error origin=%s domain=%@ code=%ld frames=%@",
              origin, LMDSafeDomain(domain), (long)code, frames]);
    }
    LMDLogging = NO;
}

static void LMDLogContainer(NSString *identifier, BOOL original, BOOL fallback) {
    if (LMDLogging) return;
    LMDLogging = YES;
    if (atomic_fetch_add(&LMDContainerCount, 1) < 80) {
        NSString *group = ([identifier isEqualToString:@"group.com.linecorp.line"] ||
                          [identifier isEqualToString:@"group.share.com.linecorp.line"])
                          ? identifier : @"other-redacted";
        LMDEmit([NSString stringWithFormat:@"[LINELoginDiag] container group=%@ original=%d fallback=%d frames=%@",
              group, original, fallback, LMDLINEFrames()]);
    }
    LMDLogging = NO;
}

typedef NSString *(*LMDLocalizedIMP)(id, SEL, NSString *, NSString *, NSString *);
static LMDLocalizedIMP LMDOriginalLocalized;
static NSString *LMDLocalized(id receiver, SEL selector, NSString *key,
                              NSString *value, NSString *table) {
    NSString *result = LMDOriginalLocalized(receiver, selector, key, value, table);
    if (!LMDLogging && LMDInterestingKey(key)) {
        LMDLogging = YES;
        if (atomic_fetch_add(&LMDLocalizationCount, 1) < 80)
            LMDEmit([NSString stringWithFormat:@"[LINELoginDiag] error-text key=%@ frames=%@", key, LMDLINEFrames()]);
        LMDLogging = NO;
    }
    return result;
}

// Match init-family ARC ownership: receiver is consumed, result is retained.
typedef id (*LMDErrorInitIMP)(id __attribute__((ns_consumed)), SEL,
                             NSString *, NSInteger, NSDictionary *)
                             __attribute__((ns_returns_retained));
static LMDErrorInitIMP LMDOriginalErrorInit;
static id LMDErrorInit(id receiver __attribute__((ns_consumed)), SEL selector,
                      NSString *domain, NSInteger code, NSDictionary *userInfo)
                      __attribute__((ns_returns_retained));
static id LMDErrorInit(id receiver __attribute__((ns_consumed)), SEL selector,
                      NSString *domain, NSInteger code, NSDictionary *userInfo) {
    id result = LMDOriginalErrorInit(receiver, selector, domain, code, userInfo);
    LMDLogError(domain, code, "init");
    return result;
}

typedef id (*LMDErrorFactoryIMP)(id, SEL, NSString *, NSInteger, NSDictionary *);
static LMDErrorFactoryIMP LMDOriginalErrorFactory;
static id LMDErrorFactory(id receiver, SEL selector, NSString *domain,
                         NSInteger code, NSDictionary *userInfo) {
    id result = LMDOriginalErrorFactory(receiver, selector, domain, code, userInfo);
    LMDLogError(domain, code, "factory");
    return result;
}

static void LMInstallLoginDiagnostics(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        Method localized = class_getInstanceMethod(NSBundle.class,
                             @selector(localizedStringForKey:value:table:));
        Method errorInit = class_getInstanceMethod(NSError.class,
                             @selector(initWithDomain:code:userInfo:));
        Method errorFactory = class_getClassMethod(NSError.class,
                             @selector(errorWithDomain:code:userInfo:));
        if (!localized || !errorInit || !errorFactory) {
            LMDEmit(@"[LINELoginDiag] required methods unavailable; diagnostics skipped");
            return;
        }
        LMDOriginalLocalized = (LMDLocalizedIMP)method_getImplementation(localized);
        LMDOriginalErrorInit = (LMDErrorInitIMP)method_getImplementation(errorInit);
        LMDOriginalErrorFactory = (LMDErrorFactoryIMP)method_getImplementation(errorFactory);
        method_setImplementation(localized, (IMP)LMDLocalized);
        method_setImplementation(errorInit, (IMP)LMDErrorInit);
        method_setImplementation(errorFactory, (IMP)LMDErrorFactory);
        LMDEmit(@"[LINELoginDiag] v3 diagnostics loaded; public sanitized fields; duplicate errors limited");
    });
}
