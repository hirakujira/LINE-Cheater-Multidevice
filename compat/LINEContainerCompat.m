// Restore a usable database location when a re-signed LINE lacks its App Group.
// This is app-private storage. It is NOT shared with app extensions.
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#ifdef LINE_MULTI_DIAGNOSTICS
#include "LINELoginDiagnostics.m"
#endif
#ifdef LINE_MULTI_KEYCHAIN_COMPAT
#include "LINEKeychainCompat.m"
#endif
#ifdef LINE_MULTI_MESSAGE_DIAGNOSTICS
#include "LINEMessageDiagnostics.m"
#endif

typedef NSURL *(*LMContainerIMP)(id, SEL, NSString *);
static LMContainerIMP LMOriginalContainer;

static BOOL LMIsLINEGroup(NSString *identifier) {
    return [identifier isEqualToString:@"group.com.linecorp.line"] ||
           [identifier isEqualToString:@"group.share.com.linecorp.line"];
}

static NSURL *LMLocalContainer(NSFileManager *manager, NSString *identifier) {
    // Exact allowlist above makes the last component safe as a directory name.
#ifdef LINE_MULTI_TESTING
    NSString *testRoot = NSProcessInfo.processInfo.environment[@"LINE_MULTI_TEST_ROOT"];
    if (!testRoot.length) return nil;
    NSURL *library = [NSURL fileURLWithPath:testRoot isDirectory:YES];
#else
    NSURL *library = [manager URLsForDirectory:NSLibraryDirectory
                                     inDomains:NSUserDomainMask].firstObject;
#endif
    if (!library) return nil;
    NSURL *root = [library URLByAppendingPathComponent:@"Application Support/LINEContainerCompat" isDirectory:YES];
    NSURL *directory = [root URLByAppendingPathComponent:identifier isDirectory:YES];
    NSError *error = nil;
    if (![manager createDirectoryAtURL:directory withIntermediateDirectories:YES
                            attributes:nil error:&error]) {
        NSLog(@"[LINEContainerCompat] Cannot create local container (domain=%@ code=%ld)",
              error.domain, (long)error.code);
        return nil;
    }
    return directory;
}

static NSURL *LMContainerURL(id receiver, SEL selector, NSString *identifier) {
    NSURL *original = LMOriginalContainer(receiver, selector, identifier);
    NSURL *fallback = (!original && LMIsLINEGroup(identifier))
                      ? LMLocalContainer(receiver, identifier) : nil;
#ifdef LINE_MULTI_DIAGNOSTICS
    LMDLogContainer(identifier, original != nil, fallback != nil);
#endif
    return original ?: fallback;
}

static void LMInstallContainerFallback(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        Method method = class_getInstanceMethod(NSFileManager.class,
                        @selector(containerURLForSecurityApplicationGroupIdentifier:));
        if (!method) {
            NSLog(@"[LINEContainerCompat] Container method missing; fallback unavailable");
            return;
        }
        // Installed during image initialization, before the app's main() runs.
        LMOriginalContainer = (LMContainerIMP)method_getImplementation(method);
        method_setImplementation(method, (IMP)LMContainerURL);
        NSLog(@"[LINEContainerCompat] v1 loaded; local fallback enabled for LINE groups");
    });
}

#ifndef LINE_MULTI_TESTING
__attribute__((constructor)) static void LMContainerCompatLoad(void) {
    @autoreleasepool {
        // The dylib is loaded only by the main LINE executable, even if its
        // bundle identifier changes during signing. Do not activate in appex.
        NSString *executable = NSBundle.mainBundle.infoDictionary[@"CFBundleExecutable"];
        if ([executable isEqualToString:@"LINE"]) {
            LMInstallContainerFallback();
#ifdef LINE_MULTI_DIAGNOSTICS
            LMInstallLoginDiagnostics();
#endif
#ifdef LINE_MULTI_KEYCHAIN_COMPAT
            LMInstallKeychainCompat();
#endif
#ifdef LINE_MULTI_MESSAGE_DIAGNOSTICS
            LMInstallMessageDiagnostics();
#endif
        }
    }
}
#endif
