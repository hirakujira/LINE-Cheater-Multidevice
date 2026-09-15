// Version-locked E2EE and authentication Keychain fallback. No values logged.
#import <Security/Security.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <string.h>

static uintptr_t LMKBase;
static BOOL LMKInstalled;
static BOOL LMKWaitingLogged;
static OSStatus (*LMKAdd)(CFDictionaryRef, CFTypeRef *) = SecItemAdd;
static OSStatus (*LMKCopy)(CFDictionaryRef, CFTypeRef *) = SecItemCopyMatching;
static OSStatus (*LMKDelete)(CFDictionaryRef) = SecItemDelete;
static OSStatus (*LMKUpdate)(CFDictionaryRef, CFDictionaryRef) = SecItemUpdate;

#ifdef LINE_MULTI_LEGACY_KEYCHAIN_COMPAT
#define LMK_IMAGE_NAME "LINE"
#define LMK_GOT_ADDRESS 0x109d4f3d0ULL
#define LMK_GOT_OFFSET 0x9d4f3d0ULL
#define LMK_VERSION @"v10 legacy authentication-store group retry"
#else
#define LMK_IMAGE_NAME "LINE"
#define LMK_GOT_ADDRESS 0x10b377cd8ULL
#define LMK_GOT_OFFSET 0xb377cd8ULL
#define LMK_VERSION @"v7 keychain hooks installed; E2EE and exact authentication-store group retry"
#endif

static OSStatus LMKCall(unsigned op, CFDictionaryRef query, CFDictionaryRef attributes, CFTypeRef *result) {
    switch (op) {
        case 0: return LMKAdd(query, result);
        case 1: return LMKCopy(query, result);
        case 2: return LMKDelete(query);
        default: return LMKUpdate(query, attributes);
    }
}

static BOOL LMKAuthQuery(unsigned op, uintptr_t caller, CFDictionaryRef query) {
#ifdef LINE_MULTI_LEGACY_KEYCHAIN_COMPAT
    // 15.7.2 main executable authentication-store return addresses.
    BOOL site = (op == 0 && caller == 0x5db0534) ||
                (op == 1 && caller == 0x5daff40) ||
                (op == 2 && caller == 0x5db0784) ||
                (op == 3 && caller == 0x5db04bc);
#else
    // NLAuthenticationManager's six audited Security API return addresses.
    BOOL site = (op == 0 && (caller == 0x37c6ee0 || caller == 0x37c6f14)) ||
                (op == 1 && caller == 0x37c7074) ||
                (op == 2 && (caller == 0x37c712c || caller == 0x37c7144)) ||
                (op == 3 && caller == 0x37c6f8c);
#endif
    if (!site || !query) return NO;
    NSDictionary *q = (__bridge NSDictionary *)query;
    id account = q[(__bridge id)kSecAttrAccount];
    return [q[(__bridge id)kSecClass] isEqual:(__bridge id)kSecClassGenericPassword] &&
           [q[(__bridge id)kSecAttrService] isEqual:@"jp.naver.line"] &&
           [q[(__bridge id)kSecAttrAccessGroup] isEqual:@"ZW4U99SQQ3.jp.naver.line"] &&
           ([account isEqual:@"auth-token"] || [account isEqual:@"auth-token-v3"]);
}

static OSStatus LMKPerform(unsigned op, CFDictionaryRef query, CFDictionaryRef attributes,
                           CFTypeRef *result, uintptr_t caller) {
    OSStatus initial = LMKCall(op, query, attributes, result);
    BOOL authQuery = LMKAuthQuery(op, caller, query);
#ifdef LINE_MULTI_LEGACY_KEYCHAIN_COMPAT
    // The legacy build modifies only its audited authentication store. Other
    // missing-entitlement failures are observed without changing requests.
    if (!authQuery) {
        if (initial == errSecMissingEntitlement && !LMDLogging) {
            LMDLogging = YES;
            LMDEmit([NSString stringWithFormat:
                @"[LINELoginDiag] keychain-observe op=%u status=%d explicit-group=%d attribute-group=%d caller=LINE+0x%lx",
                op, (int)initial, query && CFDictionaryContainsKey(query, kSecAttrAccessGroup),
                attributes && CFDictionaryContainsKey(attributes, kSecAttrAccessGroup),
                (unsigned long)caller]);
            LMDLogging = NO;
        }
        return initial;
    }
#else
    // Preserve the v5 E2EE scope; add only the observed authentication store.
    if (!authQuery && (caller < 0x3d63000 || caller >= 0x3d64200)) {
#ifdef LINE_MULTI_MESSAGE_DIAGNOSTICS
        // Observe other failures without changing their query or result.
        if ((initial != errSecSuccess || (caller >= 0x37c6e7c && caller < 0x37c7200)) && !LMDLogging) {
            LMDLogging = YES;
            NSString *key = [NSString stringWithFormat:@"keychain-%u-%d-%lx", op, (int)initial, (unsigned long)caller];
            if (LMDShouldEmitError(key, initial, @"")) {
                static const char *names[] = {"add", "copy", "delete", "update"};
                LMDEmit([NSString stringWithFormat:@"[LINELoginDiag] keychain-observe op=%s status=%d explicit-group=%d attribute-group=%d caller=LINE+0x%lx",
                    names[op], (int)initial,
                    query && CFDictionaryContainsKey(query, kSecAttrAccessGroup),
                    attributes && CFDictionaryContainsKey(attributes, kSecAttrAccessGroup), (unsigned long)caller]);
            }
            LMDLogging = NO;
        }
#endif
        return initial;
    }
#endif
    BOOL hasGroup = query && CFDictionaryContainsKey(query, kSecAttrAccessGroup);
    BOOL retried = NO;
    OSStatus finalStatus = initial;
    BOOL attributeGroup = attributes && CFDictionaryContainsKey(attributes, kSecAttrAccessGroup);
    // This exact E2EE write call puts its group in the update attributes,
    // while its search query contains class/service/account only.
    BOOL auditedUpdate =
#ifdef LINE_MULTI_LEGACY_KEYCHAIN_COMPAT
        NO;
#else
        op == 3 && caller == 0x3d63df4;
#endif
    BOOL compatibleGroups = !hasGroup || !attributeGroup ||
        CFEqual(CFDictionaryGetValue(query, kSecAttrAccessGroup),
                CFDictionaryGetValue(attributes, kSecAttrAccessGroup));
    BOOL canRetry = compatibleGroups &&
        ((hasGroup && !attributeGroup) || (auditedUpdate && attributeGroup));
    if (initial == errSecMissingEntitlement && canRetry) {
        NSMutableDictionary *local = [(__bridge NSDictionary *)query mutableCopy];
        [local removeObjectForKey:(__bridge id)kSecAttrAccessGroup];
        NSMutableDictionary *localAttributes = nil;
        if (attributeGroup) {
            localAttributes = [(__bridge NSDictionary *)attributes mutableCopy];
            [localAttributes removeObjectForKey:(__bridge id)kSecAttrAccessGroup];
        }
        retried = YES;
        finalStatus = LMKCall(op, (__bridge CFDictionaryRef)local,
                             localAttributes ? (__bridge CFDictionaryRef)localAttributes : attributes, result);
    }
    static const char *names[] = {"add", "copy", "delete", "update"};
    LMDEmit([NSString stringWithFormat:
        @"[LINELoginDiag] keychain op=%s initial=%d explicit-group=%d attribute-group=%d retry-default=%d final=%d caller=LINE+0x%lx scope=%s",
        names[op], (int)initial, hasGroup, attributeGroup, retried, (int)finalStatus, (unsigned long)caller,
        authQuery ? "auth" : "e2ee"]);
    return finalStatus;
}

__attribute__((noinline)) static OSStatus LMKAddHook(CFDictionaryRef q, CFTypeRef *r) {
    return LMKPerform(0, q, NULL, r, (uintptr_t)__builtin_return_address(0) - LMKBase);
}
__attribute__((noinline)) static OSStatus LMKCopyHook(CFDictionaryRef q, CFTypeRef *r) {
    return LMKPerform(1, q, NULL, r, (uintptr_t)__builtin_return_address(0) - LMKBase);
}
__attribute__((noinline)) static OSStatus LMKDeleteHook(CFDictionaryRef q) {
    return LMKPerform(2, q, NULL, NULL, (uintptr_t)__builtin_return_address(0) - LMKBase);
}
__attribute__((noinline)) static OSStatus LMKUpdateHook(CFDictionaryRef q, CFDictionaryRef a) {
    return LMKPerform(3, q, a, NULL, (uintptr_t)__builtin_return_address(0) - LMKBase);
}

static BOOL LMKReplaceSlots(uintptr_t *slots, const uintptr_t *expected, const uintptr_t *replacement) {
    for (unsigned i = 0; i < 4; i++) if (slots[i] != expected[i]) return NO;
    vm_address_t page = (vm_address_t)slots & ~((vm_address_t)vm_page_size - 1);
    if (((vm_address_t)(slots + 4) - 1) / vm_page_size != page / vm_page_size) return NO;
    vm_address_t region = page;
    vm_size_t regionSize = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    kern_return_t kr = vm_region_64(mach_task_self(), &region, &regionSize,
                                    VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &object);
    if (object != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), object);
    if (kr != KERN_SUCCESS || region > page || region + regionSize < page + vm_page_size) return NO;
    if (info.protection & VM_PROT_EXECUTE) return NO;
    kr = vm_protect(mach_task_self(), page, vm_page_size, FALSE,
                    VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) return NO;
    for (unsigned i = 0; i < 4; i++) __atomic_store_n(slots + i, replacement[i], __ATOMIC_RELEASE);
    kr = vm_protect(mach_task_self(), page, vm_page_size, FALSE, info.protection);
    if (kr != KERN_SUCCESS)
        LMDEmit([NSString stringWithFormat:@"[LINELoginDiag] keychain GOT protection restore failed status=%d", kr]);
    return YES;
}

static void LMKTryInstallKeychainCompat(void) {
    if (LMKInstalled) return;
    const struct mach_header_64 *h = NULL;
    for (uint32_t index = 0; index < _dyld_image_count(); index++) {
        const char *path = _dyld_get_image_name(index);
        const char *name = path ? strrchr(path, '/') : NULL;
        if (name && strcmp(name + 1, LMK_IMAGE_NAME) == 0) {
            h = (const struct mach_header_64 *)_dyld_get_image_header(index);
            break;
        }
    }
#ifdef LINE_MULTI_LEGACY_KEYCHAIN_COMPAT
    static const unsigned char uuid[16] = {0x59,0xae,0xfc,0xc3,0xde,0x1f,0x36,0x4f,
                                          0xae,0xed,0xcc,0x1e,0x68,0x55,0x0a,0x99};
#else
    static const unsigned char uuid[16] = {0x0b,0xab,0x48,0x3c,0xca,0x85,0x38,0xce,
                                          0x89,0x84,0x0c,0x20,0xc9,0x25,0x11,0xe4};
#endif
    if (!h || h->magic != MH_MAGIC_64 || h->sizeofcmds > 0x8000) {
        if (!LMKWaitingLogged) {
            LMKWaitingLogged = YES;
            LMDEmit([NSString stringWithFormat:
                @"[LINELoginDiag] keychain hooks waiting for %s", LMK_IMAGE_NAME]);
        }
        return;
    }
    BOOL uuidOK = NO, sectionOK = NO;
    const char *p = (const char *)(h + 1), *end = p + h->sizeofcmds;
    for (unsigned i = 0; i < h->ncmds; i++) {
        if (p + sizeof(struct load_command) > end) return;
        const struct load_command *lc = (const void *)p;
        if (lc->cmdsize < sizeof(*lc) || p + lc->cmdsize > end) return;
        if (lc->cmd == LC_UUID && lc->cmdsize >= sizeof(struct uuid_command))
            uuidOK = memcmp(((const struct uuid_command *)lc)->uuid, uuid, 16) == 0;
        if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *seg = (const void *)lc;
            if (seg->nsects > (lc->cmdsize - sizeof(*seg)) / sizeof(struct section_64)) return;
            const struct section_64 *s = (const void *)(seg + 1);
            for (unsigned j = 0; j < seg->nsects; j++, s++) {
                if (strncmp(s->sectname, "__got", 16) == 0 &&
                    s->addr <= LMK_GOT_ADDRESS &&
                    s->addr + s->size >= LMK_GOT_ADDRESS + 4 * sizeof(uintptr_t))
                    sectionOK = YES;
            }
        }
        p += lc->cmdsize;
    }
    if (!uuidOK || !sectionOK) {
        LMDEmit([NSString stringWithFormat:
            @"[LINELoginDiag] keychain hooks skipped: executable layout mismatch uuid=%d got=%d",
            uuidOK, sectionOK]);
        return;
    }
    LMKBase = (uintptr_t)h;
    uintptr_t expected[] = {(uintptr_t)SecItemAdd, (uintptr_t)SecItemCopyMatching,
                            (uintptr_t)SecItemDelete, (uintptr_t)SecItemUpdate};
    uintptr_t replacement[] = {(uintptr_t)LMKAddHook, (uintptr_t)LMKCopyHook,
                               (uintptr_t)LMKDeleteHook, (uintptr_t)LMKUpdateHook};
    BOOL installed = LMKReplaceSlots((uintptr_t *)(LMKBase + LMK_GOT_OFFSET), expected, replacement);
    if (installed) LMKInstalled = YES;
    LMDEmit([NSString stringWithFormat:@"[LINELoginDiag] %@ installed=%d", LMK_VERSION, installed]);
}

static void LMKImageAdded(const struct mach_header *header, intptr_t slide) {
    (void)header;
    (void)slide;
    LMKTryInstallKeychainCompat();
}

static void LMInstallKeychainCompat(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        _dyld_register_func_for_add_image(LMKImageAdded);
    });
    LMKTryInstallKeychainCompat();
}
