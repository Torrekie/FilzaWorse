// SPDX-License-Identifier: GPL-3.0-or-later
#import "WQIdentity.h"
#import <objc/message.h>
#import <objc/runtime.h>
#include <dlfcn.h>

static NSString *const groupBase = @"group.com.tigisoftware.FilzaWorse";
static NSString *const legacyGroup = @"com.tigisoftware.sharedfiles";

NSArray<NSString *> *FWQApplicationGroups(void) {
    static NSArray<NSString *> *groups;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        void *security = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY | RTLD_LOCAL);
        if (!security) return;
        CFTypeRef (*create)(CFAllocatorRef) = dlsym(security, "SecTaskCreateFromSelf");
        CFTypeRef (*copyValue)(CFTypeRef, CFStringRef, CFErrorRef *) = dlsym(security, "SecTaskCopyValueForEntitlement");
        if (create && copyValue) {
            CFTypeRef task = create(kCFAllocatorDefault);
            CFTypeRef value = task ? copyValue(task, CFSTR("com.apple.security.application-groups"), NULL) : NULL;
            if (value && CFGetTypeID(value) == CFArrayGetTypeID())
                groups = [(__bridge NSArray *)value copy];
            if (value) CFRelease(value);
            if (task) CFRelease(task);
        }
        dlclose(security);
    });
    return groups;
}

NSString *FWQStandaloneGroupIdentifier(void) {
    // AltStore/SideStore append the signing team's suffix to the declared group.
    NSArray<NSString *> *groups = FWQApplicationGroups();
    if ([groups containsObject:groupBase]) return groupBase;
    NSString *prefix = [groupBase stringByAppendingString:@"."];
    for (NSString *group in groups)
        if ([group hasPrefix:prefix]) return group;
    return nil;
}

static NSURL *(*originalGroupURL)(id, SEL, NSString *);
static NSString *(*originalLibName)(id, SEL);
static NSString *(*originalTranslatedPath)(id, SEL, NSString *);

static NSURL *hookedGroupURL(id self, SEL cmd, NSString *identifier) {
    if ([identifier isEqualToString:legacyGroup] || [identifier isEqualToString:groupBase]) {
        // LiveContainer maps the guest's shared-data requests to its host group.
        Class lc = NSClassFromString(@"LCSharedUtils");
        SEL idSelector = NSSelectorFromString(@"appGroupID");
        SEL pathSelector = NSSelectorFromString(@"appGroupPath");
        if (lc && [lc respondsToSelector:idSelector] && [lc respondsToSelector:pathSelector]) {
            NSString *hostID = ((id (*)(id, SEL))objc_msgSend)(lc, idSelector);
            NSURL *hostPath = ((id (*)(id, SEL))objc_msgSend)(lc, pathSelector);
            if (hostID.length && hostPath.isFileURL) return hostPath;
        }
        // AltStore/SideStore append the signing-team suffix to the declared group.
        NSString *signedIdentifier = FWQStandaloneGroupIdentifier();
        if (signedIdentifier) identifier = signedIdentifier;
    }
    return originalGroupURL(self, cmd, identifier);
}

static NSString *hookedLibName(id self, SEL cmd) {
    NSString *name = originalLibName(self, cmd);
    // Filza 5.0.1 uses either Filza or Filza-<hidden instance serial>.
    return [@"FilzaWorse" stringByAppendingString:[name substringFromIndex:5]];
}

static NSString *hookedDataRoot(id self, SEL cmd) {
    (void)cmd;
    NSString *library = [NSHomeDirectory() stringByAppendingPathComponent:@"Library"];
    return [library stringByAppendingPathComponent:hookedLibName(self, sel_registerName("libName"))];
}

static NSString *hookedTranslatedPath(id self, SEL cmd, NSString *path) {
    NSString *root = @"/var/mobile/Library/Filza";
    if ([path isEqualToString:root] || [path hasPrefix:[root stringByAppendingString:@"/"]])
        return [hookedDataRoot(self, sel_registerName("dataRootDir"))
                stringByAppendingString:[path substringFromIndex:root.length]];
    return originalTranslatedPath(self, cmd, path);
}

__attribute__((constructor)) static void installIdentity(void) {
    @autoreleasepool {
        Method group = class_getInstanceMethod(NSFileManager.class,
                            @selector(containerURLForSecurityApplicationGroupIdentifier:));
        if (!group) return;
        originalGroupURL = (NSURL *(*)(id, SEL, NSString *))
            method_setImplementation(group, (IMP)hookedGroupURL);

        Class defaults = NSClassFromString(@"TGUserDefaults");
        if (!defaults) return; // The sharing extension only needs the group mapping.
        Method name = class_getInstanceMethod(defaults, sel_registerName("libName"));
        Method root = class_getInstanceMethod(defaults, sel_registerName("dataRootDir"));
        Method translate = class_getInstanceMethod(defaults, sel_registerName("translatedSystemPath:"));
        if (!name || !root || !translate) {
            NSLog(@"[FilzaWorse] Expected Filza 5.0.1 application-data methods missing.");
            return;
        }
        originalLibName = (NSString *(*)(id, SEL))method_setImplementation(name, (IMP)hookedLibName);
        method_setImplementation(root, (IMP)hookedDataRoot);
        originalTranslatedPath = (NSString *(*)(id, SEL, NSString *))
            method_setImplementation(translate, (IMP)hookedTranslatedPath);
    }
}
