/*
 * Directory discovery based on worse_query/pathleak.m, Copyright (C) 2026
 * Taj C (forcequit), with the bounded-scan approach inspected in FileQuest.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/fsgetpath.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#import "WQBackend.h"

// These are the inspected Filza 5.0.1 selectors and result dictionary keys.
@interface NSObject (FWQBrowser)
- (NSString *)currentPath;
- (id)browserView;
- (void)setCurrentItemsCount:(NSString *)text;
@end

@interface FWQDirectoryScan : NSObject
@property(nonatomic, copy) NSString *path;
@property(nonatomic) uint64_t nextInode;
@property(nonatomic, copy) NSArray<NSString *> *discoveredPaths;
@property(nonatomic, copy) NSArray<NSDictionary *> *items;
@property(nonatomic, strong) NSProgress *progress;
@property(nonatomic, strong) NSError *scanError;
@property(nonatomic) BOOL running;
@property(nonatomic) BOOL reloading;
@property(nonatomic) BOOL complete;
@property(nonatomic) int sortMode;
@end
@implementation FWQDirectoryScan
@end

static char scanKey;
static _Thread_local __unsafe_unretained UIViewController *listingPage;
static _Thread_local int listingSortMode;
static NSArray *(*originalContents)(id, SEL, NSString *, NSError **);
static void (*originalLoad)(id, SEL, int, BOOL);
static void (*originalSetPath)(id, SEL, NSString *);
static void (*originalDisappear)(id, SEL, BOOL);

static NSString *canonicalPath(NSString *path) {
    NSString *value = path.stringByStandardizingPath;
    if ([value hasPrefix:@"/private/var/"]) value = [value substringFromIndex:8];
    return value;
}

static BOOL isContainerBase(NSString *path) {
    return [@[@"/var/containers/Data/System", @"/var/containers/Shared/SystemGroup",
              @"/var/mobile/Containers/Data/Application", @"/var/mobile/Containers/Data/InternalDaemon",
              @"/var/mobile/Containers/Data/PluginKitPlugin", @"/var/mobile/Containers/Shared/AppGroup"]
            containsObject:path];
}

static BOOL permissionError(NSError *error) {
    return error && (FWQPermissionError((int)error.code) ||
        ([error.domain isEqualToString:NSCocoaErrorDomain] && error.code == NSFileReadNoPermissionError));
}

static NSString *text(NSString *key) {
    return [NSBundle.mainBundle localizedStringForKey:key value:nil table:@"FilzaWorse"];
}

static void updateScanStatus(UIViewController *page) {
    FWQDirectoryScan *scan = objc_getAssociatedObject(page, &scanKey);
    if (!scan) return;
    NSString *status;
    if (scan.running) {
        status = text(@"scan.loading");
    } else if (scan.scanError) {
        status = [NSString stringWithFormat:text(@"scan.error"), scan.scanError.localizedDescription];
    } else if (scan.items.count) {
        status = [NSString stringWithFormat:text(@"scan.partial"), (unsigned long)scan.items.count];
    } else {
        status = text(@"scan.none");
    }
    [[page browserView] setCurrentItemsCount:status];
}

static double monotonicTime(void) {
    struct timespec value;
    clock_gettime(CLOCK_MONOTONIC, &value);
    return value.tv_sec + value.tv_nsec / 1e9;
}

static NSError *posixError(int code) {
    return [NSError errorWithDomain:NSPOSIXErrorDomain code:code userInfo:nil];
}

static NSArray<NSString *> *scanPaths(NSString *base, NSArray<NSString *> *known,
                                    uint64_t *cursor, NSProgress *progress, NSError **error) {
    // A newly allocated inode gives a practical search ceiling, not a completeness proof.
    char temporary[PATH_MAX];
    NSString *template = [NSTemporaryDirectory() stringByAppendingPathComponent:@".FilzaWorse-scan.XXXXXX"];
    if (![template getFileSystemRepresentation:temporary maxLength:sizeof(temporary)]) {
        *error = posixError(ENAMETOOLONG);
        return nil;
    }
    int fd = mkstemp(temporary);
    if (fd < 0) { *error = posixError(errno); return nil; }
    struct stat anchor;
    struct statfs filesystem;
    int failure = 0;
    if (fstat(fd, &anchor) != 0) failure = errno;
    if (!failure && statfs(base.fileSystemRepresentation, &filesystem) != 0 &&
        fstatfs(fd, &filesystem) != 0) failure = errno;
    if (unlink(temporary) != 0 && !failure) failure = errno;
    close(fd);
    if (failure) { *error = posixError(failure); return nil; }

    // All supported bases are on the data volume, as is this app's temporary file.
    fsid_t fsid = filesystem.f_fsid;
    uint64_t limit = anchor.st_ino;
    uint64_t inode = *cursor;
    if (inode > limit) inode = 1;
    NSString *prefix = [base stringByAppendingString:@"/"];
    const char *prefixBytes = prefix.fileSystemRepresentation;
    size_t prefixLength = strlen(prefixBytes);
    NSMutableOrderedSet<NSString *> *paths = [NSMutableOrderedSet orderedSetWithArray:known];
    char buffer[PATH_MAX];
    double deadline = monotonicTime() + 3.0;
    for (; inode <= limit; ++inode) {
        if ((inode & 0xFF) == 0 && (progress.cancelled || monotonicTime() >= deadline)) break;
        if (fsgetpath(buffer, sizeof(buffer), &fsid, inode) <= 0) continue;
        const char *candidate = buffer;
        if (strncmp(candidate, "/private/var/", 13) == 0) candidate += 8;
        if (strncmp(candidate, prefixBytes, prefixLength) != 0) continue;
        const char *name = candidate + prefixLength;
        if (!*name || strchr(name, '/')) continue;
        @autoreleasepool {
            NSString *path = [NSFileManager.defaultManager stringWithFileSystemRepresentation:candidate
                                                                                       length:strlen(candidate)];
            if (path) [paths addObject:path];
        }
    }
    *cursor = inode > limit ? 0 : inode;
    return paths.array;
}

static NSArray<NSDictionary *> *itemsForPaths(NSArray<NSString *> *paths, NSProgress *progress) {
    NSMutableArray *items = [NSMutableArray array];
    NSFileManager *files = NSFileManager.defaultManager;
    for (NSString *path in paths) {
        if (progress.cancelled) break;
        @autoreleasepool {
            FWQGrantPath(path.fileSystemRepresentation, false);
            NSMutableDictionary *attributes = [[files attributesOfItemAtPath:path error:nil] mutableCopy];
            // Do not invent metadata or turn unreadable discoveries into usable directories.
            if (!attributes) continue;
            int32_t tag = -1;
            getxattr(path.fileSystemRepresentation, "com.tigisoftware.tag", &tag, sizeof(tag), 0, 0);
            attributes[@"TGFileTag"] = @(tag);
            if ([attributes[NSFileType] isEqualToString:NSFileTypeSymbolicLink]) {
                NSString *realPath = path.stringByResolvingSymlinksInPath;
                FWQGrantPath(realPath.fileSystemRepresentation, false);
                NSDictionary *realAttributes = [files attributesOfItemAtPath:realPath error:nil];
                if (realAttributes) {
                    attributes[@"TGSymlinkRealPath"] = realPath;
                    attributes[@"TGRealFileAttr"] = realAttributes;
                    attributes[@"TGSymlinkFileIsDirectory"] = @([realAttributes[NSFileType] isEqualToString:NSFileTypeDirectory]);
                }
            }
            [items addObject:@{@"n": path.lastPathComponent, @"a": attributes}];
        }
    }
    return items;
}

static void hookedLoad(id self, SEL cmd, int mode, BOOL preserve);

static void startScan(UIViewController *page, FWQDirectoryScan *scan) {
    scan.running = YES;
    scan.scanError = nil;
    scan.progress = [NSProgress progressWithTotalUnitCount:-1];
    NSProgress *progress = scan.progress;
    NSString *path = scan.path;
    NSArray *known = scan.discoveredPaths;
    uint64_t start = scan.nextInode;
    __weak UIViewController *weakPage = page;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        @autoreleasepool {
            uint64_t next = start;
            NSError *failure = nil;
            NSArray *paths = scanPaths(path, known, &next, progress, &failure);
            NSArray *items = paths ? itemsForPaths(paths, progress) : nil;
            dispatch_async(dispatch_get_main_queue(), ^{
                UIViewController *owner = weakPage;
                if (!owner || objc_getAssociatedObject(owner, &scanKey) != scan) return;
                scan.running = NO;
                scan.nextInode = next;
                scan.complete = (next == 0);
                scan.scanError = failure;
                if (paths) scan.discoveredPaths = paths;
                if (items && !progress.cancelled) scan.items = items;
                if (!progress.cancelled && owner.isViewLoaded && owner.view.window &&
                    [canonicalPath([owner currentPath]) isEqualToString:path]) {
                    scan.reloading = YES;
                    hookedLoad(owner, sel_registerName("loadFilesWithSortMode:preserveSeletedItems:"), scan.sortMode, YES);
                    scan.reloading = NO;
                }
            });
        }
    });
}

static NSArray *hookedContents(id self, SEL cmd, NSString *path, NSError **error) {
    NSError *failure = nil;
    NSArray *result = originalContents(self, cmd, path, &failure);
    UIViewController *page = listingPage;
    NSString *base = canonicalPath(path);
    if (result || !page || !isContainerBase(base) || !permissionError(failure)) {
        if (page) {
            FWQDirectoryScan *old = objc_getAssociatedObject(page, &scanKey);
            [old.progress cancel];
            objc_setAssociatedObject(page, &scanKey, nil, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        }
        if (error) *error = failure;
        return result;
    }

    FWQDirectoryScan *scan = objc_getAssociatedObject(page, &scanKey);
    if (!scan) {
        scan = [FWQDirectoryScan new];
        scan.path = base;
        scan.nextInode = 1;
        scan.discoveredPaths = @[];
        scan.items = @[];
        objc_setAssociatedObject(page, &scanKey, scan, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }
    scan.sortMode = listingSortMode;
    if (!scan.running && !scan.reloading && !scan.complete) startScan(page, scan);
    if (scan.running || scan.items.count) {
        if (error) *error = nil;
        return scan.items;
    }
    // No results after the scan is still a failed listing, not an empty directory.
    if (error) *error = failure;
    return nil;
}

static void hookedLoad(id self, SEL cmd, int mode, BOOL preserve) {
    UIViewController *previousPage = listingPage;
    int previousMode = listingSortMode;
    listingPage = self;
    listingSortMode = mode;
    originalLoad(self, cmd, mode, preserve);
    listingPage = previousPage;
    listingSortMode = previousMode;
    updateScanStatus(self);
}

static void hookedSetPath(id self, SEL cmd, NSString *path) {
    FWQDirectoryScan *scan = objc_getAssociatedObject(self, &scanKey);
    if (scan && ![scan.path isEqualToString:canonicalPath(path)]) {
        [scan.progress cancel];
        objc_setAssociatedObject(self, &scanKey, nil, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }
    originalSetPath(self, cmd, path);
}

static void hookedDisappear(id self, SEL cmd, BOOL animated) {
    FWQDirectoryScan *scan = objc_getAssociatedObject(self, &scanKey);
    [scan.progress cancel];
    originalDisappear(self, cmd, animated);
}

__attribute__((constructor)) static void installDirectoryDiscovery(void) {
    @autoreleasepool {
        Class page = NSClassFromString(@"TGPageViewController");
        if (!page) return;
        Method contents = class_getInstanceMethod(NSClassFromString(@"TGRootFileManager"),
                            sel_registerName("contentsOfDirectoryWithSubItemAttributesAtPath:error:"));
        Method load = class_getInstanceMethod(page, sel_registerName("loadFilesWithSortMode:preserveSeletedItems:"));
        Method setPath = class_getInstanceMethod(page, sel_registerName("setCurrentPath:"));
        Method disappear = class_getInstanceMethod(page, @selector(viewWillDisappear:));
        if (!contents || !load || !setPath || !disappear) {
            NSLog(@"[FilzaWorse] Expected Filza 5.0.1 browser methods missing.");
            return;
        }
        originalContents = (NSArray *(*)(id, SEL, NSString *, NSError **))
            method_setImplementation(contents, (IMP)hookedContents);
        originalLoad = (void (*)(id, SEL, int, BOOL))method_setImplementation(load, (IMP)hookedLoad);
        originalSetPath = (void (*)(id, SEL, NSString *))method_setImplementation(setPath, (IMP)hookedSetPath);
        originalDisappear = (void (*)(id, SEL, BOOL))method_setImplementation(disappear, (IMP)hookedDisappear);
    }
}
