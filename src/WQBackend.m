/*
 * Based on worse_query, Copyright (C) 2026 Taj C (forcequit).
 * Upstream: forcequitOS/worse_query, d1540e20cd82b974d891e0551ced6d6aeb570ac2.
 * Filza/LiveContainer integration and cache-preserving transaction, 2026.
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Distributed WITHOUT ANY WARRANTY. See LICENSE.
 */
#import <Foundation/Foundation.h>
#import <objc/message.h>
#import <objc/runtime.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <xpc/xpc.h>
#include "WQBackend.h"
#import "WQIdentity.h"

static void *(*queryCreate)(void);
static void (*querySetClass)(void *, uint64_t);
static void (*querySetGroups)(void *, xpc_object_t);
static void (*querySetFlags)(void *, uint64_t);
static void (*querySetPart)(void *, uint64_t);
static void *(*queryResult)(void *);
static void (*queryFree)(void *);
static char *(*copyToken)(void *);
static int64_t (*consumeToken)(const char *);
static NSString *groupID;
static NSURL *groupURL;
static NSMutableDictionary<NSString *, NSNumber *> *grants;
static pthread_mutex_t queryLock = PTHREAD_MUTEX_INITIALIZER;
static bool backendReady;
static bool cacheRecoveryFailed;
static const char *stageName = ".FilzaWorseQuery.saved-caches";

static NSInteger querySystemMajorVersion(void) {
    return NSProcessInfo.processInfo.operatingSystemVersion.majorVersion;
}

static bool queryVersionSupported(void) {
    NSInteger major = querySystemMajorVersion();
    return major == 26 || major == 27;
}

static uint64_t queryFlagsForSystem(void) {
    // worse_query uses the alternate operation flags on iOS 26.x and the
    // default flags on the listed 27.x releases.
    if (querySystemMajorVersion() == 26) return 0x0000000800000000ULL;
    return 0x0000008000000000ULL;
}

bool FWQPermissionError(int error) {
    return error == EACCES || error == EPERM;
}

static void initializeBackend(void) {
    // Use the real process's entitlement in both hosted and direct installations.
    NSArray<NSString *> *groups = FWQApplicationGroups();
    Class lc = NSClassFromString(@"LCSharedUtils");
    SEL identifierSelector = NSSelectorFromString(@"appGroupID");
    SEL pathSelector = NSSelectorFromString(@"appGroupPath");
    NSString *identifier = nil;
    NSURL *url = nil;
    if (lc) {
        if ([lc respondsToSelector:identifierSelector] && [lc respondsToSelector:pathSelector]) {
            identifier = ((id (*)(id, SEL))objc_msgSend)(lc, identifierSelector);
            if (identifier && [groups containsObject:identifier])
                url = ((id (*)(id, SEL))objc_msgSend)(lc, pathSelector);
        }
    } else {
        identifier = FWQStandaloneGroupIdentifier();
        if (identifier)
            url = [NSFileManager.defaultManager containerURLForSecurityApplicationGroupIdentifier:identifier];
    }
    if (![url isKindOfClass:NSURL.class] || !url.isFileURL) {
        NSLog(@"[FilzaWorse] No accessible App Group in the running process's signature.");
        return;
    }
    if (!queryVersionSupported()) {
        NSLog(@"[FilzaWorseQuery] The upstream query is only supported on iOS 26.x and 27.x.");
        return;
    }
    groupID = [identifier copy];
    groupURL = [url copy];
    // Signatures and query constants follow the pinned upstream implementation.
    void *manager = dlopen("/usr/lib/system/libsystem_containermanager.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!manager) return;
    queryCreate = dlsym(manager, "container_query_create");
    querySetClass = dlsym(manager, "container_query_set_class");
    querySetGroups = dlsym(manager, "container_query_set_group_identifiers");
    querySetFlags = dlsym(manager, "container_query_operation_set_flags");
    querySetPart = dlsym(manager, "container_query_operation_set_part");
    queryResult = dlsym(manager, "container_query_get_single_result");
    queryFree = dlsym(manager, "container_query_free");
    copyToken = dlsym(manager, "container_copy_sandbox_token");
    consumeToken = dlsym(RTLD_DEFAULT, "sandbox_extension_consume");
    backendReady = queryCreate && querySetClass && querySetGroups && querySetFlags &&
                   querySetPart && queryResult && queryFree && copyToken && consumeToken;
    // Keep this image open for the lifetime of its function pointers and tokens.
    if (!backendReady) {
        dlclose(manager);
        NSLog(@"[FilzaWorseQuery] Required container-manager symbols unavailable.");
        return;
    }
    grants = [NSMutableDictionary dictionary];
}

static bool recoverCaches(int library) {
    struct stat saved, caches;
    if (fstatat(library, stageName, &saved, AT_SYMLINK_NOFOLLOW) != 0)
        return errno == ENOENT;
    if (fstatat(library, "Caches", &caches, AT_SYMLINK_NOFOLLOW) != 0)
        return false;
    // A directory at stageName is the original Caches inode after an interrupted swap.
    if (S_ISDIR(saved.st_mode) && S_ISLNK(caches.st_mode)) {
        if (renameatx_np(library, "Caches", library, stageName, RENAME_SWAP) != 0)
            return false;
    } else if (!(S_ISLNK(saved.st_mode) && S_ISDIR(caches.st_mode))) {
        // Never remove a directory or guess which of two directories contains user data.
        return false;
    }
    return unlinkat(library, stageName, 0) == 0;
}

static int64_t requestExtension(NSString *target) {
    if (cacheRecoveryFailed) return -1;
    int64_t handle = -1;
    int root = -1, library = -1, lock = -1;
    void *query = NULL;
    char *token = NULL;
    struct stat caches, linkInfo, current;
    bool staged = false, swapped = false;

    root = open(groupURL.fileSystemRepresentation, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root < 0) goto done;
    if (mkdirat(root, "Library", 0755) != 0 && errno != EEXIST) goto done;
    library = openat(root, "Library", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (library < 0) goto done;
    lock = openat(library, ".FilzaWorseQuery.lock", O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lock < 0 || flock(lock, LOCK_EX) != 0) goto done;
    if (!recoverCaches(library)) {
        cacheRecoveryFailed = true;
        NSLog(@"[FilzaWorseQuery] Cache recovery requires attention; preserved Library/%s.", stageName);
        goto done;
    }
    if (mkdirat(library, "Caches", 0755) != 0 && errno != EEXIST) goto done;
    if (fstatat(library, "Caches", &caches, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISDIR(caches.st_mode))
        goto done;

    query = queryCreate();
    if (!query) goto done;
    querySetClass(query, 7);
    {
        xpc_object_t identifier = xpc_string_create(groupID.UTF8String);
        querySetGroups(query, identifier);
        querySetPart(query, 3);
        querySetFlags(query, queryFlagsForSystem());
        if (symlinkat(target.fileSystemRepresentation, library, stageName) != 0) goto done;
        staged = true;
        if (fstatat(library, stageName, &linkInfo, AT_SYMLINK_NOFOLLOW) != 0) goto done;
        if (renameatx_np(library, "Caches", library, stageName, RENAME_SWAP) != 0) goto done;
        swapped = true;
        void *result = queryResult(query);
        if (result) token = copyToken(result);
    }

done:
    if (swapped) {
        // Restore only while Caches is still the exact symlink installed by this request.
        bool ours = fstatat(library, "Caches", &current, AT_SYMLINK_NOFOLLOW) == 0 &&
                    S_ISLNK(current.st_mode) && current.st_ino == linkInfo.st_ino &&
                    current.st_dev == linkInfo.st_dev;
        if (!ours || renameatx_np(library, "Caches", library, stageName, RENAME_SWAP) != 0) {
            cacheRecoveryFailed = true;
            NSLog(@"[FilzaWorseQuery] Caches could not be restored; original data preserved at Library/%s.", stageName);
        } else {
            swapped = false;
        }
    }
    if (staged && !swapped && unlinkat(library, stageName, 0) != 0) {
        cacheRecoveryFailed = true;
        NSLog(@"[FilzaWorseQuery] Temporary cache link cleanup failed.");
    }
    if (token && !cacheRecoveryFailed) handle = consumeToken(token);
    if (query) queryFree(query);
    free(token);
    if (lock >= 0) close(lock);
    if (library >= 0) close(library);
    if (root >= 0) close(root);
    return handle;
}

static NSString *absolutePath(const char *path) {
    if (!path || !*path) return nil;
    NSString *value = [NSFileManager.defaultManager stringWithFileSystemRepresentation:path length:strlen(path)];
    if ([value isAbsolutePath]) return value;
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd))) return nil;
    NSString *base = [NSFileManager.defaultManager stringWithFileSystemRepresentation:cwd length:strlen(cwd)];
    return [base stringByAppendingFormat:@"/%@", value];
}

bool FWQGrantPath(const char *path, bool parent) {
    int savedError = errno;
    bool acquired = false;
    @autoreleasepool {
        NSString *candidate = absolutePath(path);
        if (parent) candidate = [candidate stringByDeletingLastPathComponent];
        // Never create a target as a side effect of obtaining a token. Find an existing
        // directory first; the final file operation still receives its original path.
        while (candidate.length) {
            struct stat st;
            if (stat(candidate.fileSystemRepresentation, &st) == 0 && S_ISDIR(st.st_mode))
                break;
            if ([candidate isEqualToString:@"/"]) { candidate = nil; break; }
            candidate = [candidate stringByDeletingLastPathComponent];
        }
        if (candidate) {
            static dispatch_once_t once;
            dispatch_once(&once, ^{ initializeBackend(); });
            if (backendReady) {
                pthread_mutex_lock(&queryLock);
                if (!grants[candidate]) {
                    int64_t handle = requestExtension(candidate);
                    if (handle >= 0) {
                        // Retain tokens for later Foundation/SQLite/viewer accesses.
                        // The OS releases them when the LiveContainer guest process exits.
                        grants[candidate] = @(handle);
                        acquired = true;
                    }
                }
                pthread_mutex_unlock(&queryLock);
            }
        }
    }
    errno = savedError;
    return acquired;
}

static NSString *requestPath(xpc_object_t request, const char *key, bool url) {
    const char *raw = xpc_dictionary_get_string(request, key);
    if (!raw) return nil;
    NSString *value = [NSString stringWithUTF8String:raw];
    if (!url) return value;
    NSURL *parsed = [NSURL URLWithString:value];
    return parsed.isFileURL ? parsed.path : nil;
}

static void preparePath(NSString *path, bool parent, int mode) {
    if (!path.length) return;
    NSString *checked = parent ? [path stringByDeletingLastPathComponent] : path;
    if (access(checked.fileSystemRepresentation, mode) == 0) return;
    if (FWQPermissionError(errno) || (parent && errno == ENOENT))
        FWQGrantPath(path.fileSystemRepresentation, parent);
}

static void prepareRequest(xpc_object_t request) {
    int savedError = errno;
    @autoreleasepool {
        if (request && xpc_get_type(request) == XPC_TYPE_DICTIONARY) {
            const char *name = xpc_dictionary_get_string(request, "name");
            NSString *operation = name ? [NSString stringWithUTF8String:name] : nil;
            NSString *path = requestPath(request, "path", false) ?: requestPath(request, "url", true);
            NSString *src = requestPath(request, "srcPath", false) ?: requestPath(request, "srcURL", true);
            NSString *dst = requestPath(request, "dstPath", false) ?: requestPath(request, "dstURL", true);
            // Copies/moves are prepared before execution, never replayed after partial work.
            if (src || dst) {
                preparePath(src, false, R_OK);
                if ([operation hasPrefix:@"move"] || [operation isEqualToString:@"rename-excl"])
                    preparePath(src, true, W_OK | X_OK);
                preparePath(dst, true, W_OK | X_OK);
            }
            if (path) {
                bool create = [operation hasPrefix:@"create-"] || [operation isEqualToString:@"mkdir"];
                bool remove = [operation hasPrefix:@"delete"] || [operation isEqualToString:@"unlink"] ||
                              [operation isEqualToString:@"rmdir"];
                bool write = [operation hasPrefix:@"set-"] || [operation isEqualToString:@"setxattr"];
                int mode = write ? W_OK : R_OK;
                if ([operation isEqualToString:@"access"])
                    mode = (int)xpc_dictionary_get_int64(request, "mode");
                if ([operation isEqualToString:@"get-file-desc"]) {
                    int flags = (int)xpc_dictionary_get_int64(request, "flags");
                    mode = (flags & O_ACCMODE) == O_RDONLY ? R_OK :
                           (flags & O_ACCMODE) == O_WRONLY ? W_OK : R_OK | W_OK;
                    create = (flags & O_CREAT) != 0;
                }
                if (create || remove) preparePath(path, true, W_OK | X_OK);
                if (!create) preparePath(path, false, mode);
                if ([operation isEqualToString:@"create-hardlink"])
                    preparePath(requestPath(request, "dest", false), false, R_OK);
            }
        }
    }
    errno = savedError;
}

static id (*originalSync)(id, SEL, xpc_object_t);
static id (*originalFD)(id, SEL, xpc_object_t, int *);
static id (*originalTTY)(id, SEL, xpc_object_t, int *, bool);
static void (*originalAsync)(id, SEL, xpc_object_t, dispatch_queue_t, id);
static void (*originalNoReply)(id, SEL, xpc_object_t);

static id hookedSync(id self, SEL cmd, xpc_object_t request) {
    prepareRequest(request);
    return originalSync(self, cmd, request);
}
static id hookedFD(id self, SEL cmd, xpc_object_t request, int *fd) {
    prepareRequest(request);
    return originalFD(self, cmd, request, fd);
}
static id hookedTTY(id self, SEL cmd, xpc_object_t request, int *fd, bool login) {
    prepareRequest(request);
    return originalTTY(self, cmd, request, fd, login);
}
static void hookedAsync(id self, SEL cmd, xpc_object_t request, dispatch_queue_t queue, id completion) {
    prepareRequest(request);
    originalAsync(self, cmd, request, queue, completion);
}
static void hookedNoReply(id self, SEL cmd, xpc_object_t request) {
    prepareRequest(request);
    originalNoReply(self, cmd, request);
}

__attribute__((constructor)) static void installFilzaBackend(void) {
    @autoreleasepool {
        Class manager = NSClassFromString(@"TGRootFileManager");
        if (!manager) return;
        const char *selectors[] = {
            "sendObjectWithReplySync:", "sendObjectWithReplySync:fileDescriptor:",
            "sendObjectWithReplySync:fileDescriptor:logintty:",
            "sendObjectWithReplyAsync:queue:completion:", "sendObjectNoReply:"
        };
        IMP replacements[] = { (IMP)hookedSync, (IMP)hookedFD, (IMP)hookedTTY,
                               (IMP)hookedAsync, (IMP)hookedNoReply };
        IMP *originals[] = { (IMP *)&originalSync, (IMP *)&originalFD, (IMP *)&originalTTY,
                            (IMP *)&originalAsync, (IMP *)&originalNoReply };
        Method methods[5];
        for (int i = 0; i < 5; ++i) {
            methods[i] = class_getInstanceMethod(manager, sel_registerName(selectors[i]));
            if (!methods[i]) {
                NSLog(@"[FilzaWorseQuery] Expected Filza 5.0.1 backend method missing: %s", selectors[i]);
                return;
            }
        }
        for (int i = 0; i < 5; ++i)
            *originals[i] = method_setImplementation(methods[i], replacements[i]);
        NSLog(@"[FilzaWorseQuery] File backend installed; directory UI unchanged.");
    }
}
