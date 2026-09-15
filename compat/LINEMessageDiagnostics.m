// Read-only observations of the post-login path. Never inspect message bodies,
// credentials, request headers, error descriptions, or error userInfo.
#import <objc/message.h>

static BOOL LMMTake(NSString *key) {
    static NSLock *lock;
    static NSMutableDictionary<NSString *, NSNumber *> *counts;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ lock = [NSLock new]; counts = [NSMutableDictionary new]; });
    [lock lock];
    unsigned count = [counts[key] unsignedIntValue];
    BOOL take = count < 8 && (counts[key] != nil || counts.count < 512);
    if (take) counts[key] = @(count + 1);
    [lock unlock];
    return take;
}

static void LMMEvent(NSString *event, NSString *fields) {
    if (LMDLogging) return;
    LMDLogging = YES;
    if (LMMTake([event stringByAppendingString:fields]))
        LMDEmit([NSString stringWithFormat:@"[LINELoginDiag] message event=%@ %@ frames=%@",
                 event, fields, LMDLINEFrames()]);
    LMDLogging = NO;
}

static void LMMError(id error, NSString *event) {
    if (![error isKindOfClass:NSError.class]) return;
    NSError *e = error;
    LMMEvent(event, [NSString stringWithFormat:@"domain=%@ code=%ld",
                    LMDSafeDomain(e.domain), (long)e.code]);
}

// Validate Objective-C ABI before wrapping. Each hook keeps the original call
// and result, including nil credentials and real error classification.
static Method LMMMethod(NSString *className, BOOL meta, NSString *name,
                        const char *result, const char *argument) {
    Class cls = NSClassFromString(className);
    if (meta) cls = object_getClass(cls);
    Method method = cls ? class_getInstanceMethod(cls, NSSelectorFromString(name)) : NULL;
    if (!method || method_getNumberOfArguments(method) != (argument ? 3u : 2u)) return NULL;
    char type[64] = {0};
    method_getReturnType(method, type, sizeof(type));
    if (strcmp(type, result)) return NULL;
    if (argument) {
        method_getArgumentType(method, 2, type, sizeof(type));
        if (strcmp(type, argument)) return NULL;
    }
    return method;
}

static BOOL LMMVoidHook(NSString *cls, BOOL meta, NSString *name, NSString *event) {
    Method m = LMMMethod(cls, meta, name, "v", NULL);
    if (!m) return NO;
    SEL selector = NSSelectorFromString(name);
    void (*original)(id, SEL) = (void *)method_getImplementation(m);
    IMP hook = imp_implementationWithBlock(^(id receiver) {
        LMMEvent(event, @"called=1");
        original(receiver, selector);
    });
    method_setImplementation(m, hook);
    return YES;
}

static BOOL LMMObjectHook(NSString *cls, NSString *name, NSString *event) {
    Method m = LMMMethod(cls, NO, name, "@", NULL);
    if (!m) return NO;
    SEL selector = NSSelectorFromString(name);
    id (*original)(id, SEL) = (void *)method_getImplementation(m);
    IMP hook = imp_implementationWithBlock(^id(id receiver) {
        id result = original(receiver, selector);
        LMMEvent(event, [NSString stringWithFormat:@"present=%d", result != nil]);
        return result;
    });
    method_setImplementation(m, hook);
    return YES;
}

static BOOL LMMIntegerHook(NSString *cls, BOOL meta, NSString *name, NSString *event) {
    Method m = LMMMethod(cls, meta, name, "q", NULL);
    if (!m) m = LMMMethod(cls, meta, name, "Q", NULL);
    if (!m) return NO;
    SEL selector = NSSelectorFromString(name);
    NSInteger (*original)(id, SEL) = (void *)method_getImplementation(m);
    IMP hook = imp_implementationWithBlock(^NSInteger(id receiver) {
        NSInteger result = original(receiver, selector);
        LMMEvent(event, [NSString stringWithFormat:@"value=%ld", (long)result]);
        return result;
    });
    method_setImplementation(m, hook);
    return YES;
}

static BOOL LMMErrorHook(NSString *name) {
    Method m = LMMMethod(@"TalkErrorManager", YES, name, @encode(BOOL), "@");
    if (!m) return NO;
    SEL selector = NSSelectorFromString(name);
    BOOL (*original)(id, SEL, id) = (void *)method_getImplementation(m);
    IMP hook = imp_implementationWithBlock(^BOOL(id receiver, id error) {
        LMMError(error, [@"check-" stringByAppendingString:name]);
        return original(receiver, selector, error);
    });
    method_setImplementation(m, hook);
    return YES;
}

static void LMInstallMessageDiagnostics(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        unsigned installed = 0;
        installed += LMMVoidHook(@"_TtC4LINE21FetchOperationService", NO, @"start", @"sync-start");
        installed += LMMVoidHook(@"_TtC4LINE21FetchOperationService", NO, @"shutdown", @"sync-stop");
        NSString *push = @"_TtC7LEGY_H214ServerPushCall";
        installed += LMMVoidHook(push, NO, @"resume", @"connection-resume");
        installed += LMMVoidHook(push, NO, @"pause", @"connection-pause");
        installed += LMMVoidHook(push, NO, @"startNewSessionIfNeeded", @"connection-start");
        installed += LMMObjectHook(@"NLAuthenticationManager", @"accessToken", @"access-token");
        installed += LMMObjectHook(@"NLAuthenticationManager", @"authTokenV3", @"access-token-v3");
        installed += LMMObjectHook(@"NLAuthenticationManager", @"getAuthenticationToken", @"authentication-token");
        installed += LMMIntegerHook(@"NLAuthenticationManager", NO, @"authenticationTokenStatus", @"authentication-status");
        installed += LMMIntegerHook(@"ApplicationType", YES, @"applicationTypeIndex", @"application-type");
        for (NSString *name in @[@"isNetworkError:", @"isTalkError:", @"isFatalError:",
              @"isNotAllowedSecondaryDeviceError:", @"isNotAvailableSession:"])
            installed += LMMErrorHook(name);
        LMDEmit([NSString stringWithFormat:@"[LINELoginDiag] v6 message diagnostics loaded; hooks=%u/15; read-only", installed]);
    });
}
