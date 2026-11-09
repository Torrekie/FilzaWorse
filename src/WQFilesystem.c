// SPDX-License-Identifier: GPL-3.0-or-later
#include "WQBackend.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/xattr.h>
#include <unistd.h>

// Only Filza's import table is redirected. These calls keep their libSystem binding;
// no instruction patching, global interposing, JIT or writable executable pages.
#define RETRY_PATH(type, name, params, args, failed, path, parent) \
    type FWQ_##name params { \
        type result = name args; \
        if ((failed) && FWQPermissionError(errno) && FWQGrantPath(path, parent)) \
            result = name args; \
        return result; \
    }

RETRY_PATH(DIR *, opendir, (const char *path), (path), !result, path, false)
RETRY_PATH(int, stat, (const char *path, struct stat *st), (path, st), result < 0, path, false)
RETRY_PATH(int, lstat, (const char *path, struct stat *st), (path, st), result < 0, path, false)
RETRY_PATH(int, access, (const char *path, int mode), (path, mode), result < 0, path, false)
RETRY_PATH(int, chmod, (const char *path, mode_t mode), (path, mode), result < 0, path, false)
RETRY_PATH(int, chown, (const char *path, uid_t uid, gid_t gid), (path, uid, gid), result < 0, path, false)
RETRY_PATH(int, lchown, (const char *path, uid_t uid, gid_t gid), (path, uid, gid), result < 0, path, true)
RETRY_PATH(int, mkdir, (const char *path, mode_t mode), (path, mode), result < 0, path, true)
RETRY_PATH(int, rmdir, (const char *path), (path), result < 0, path, true)
RETRY_PATH(int, unlink, (const char *path), (path), result < 0, path, true)
RETRY_PATH(int, remove, (const char *path), (path), result < 0, path, true)
RETRY_PATH(int, symlink, (const char *target, const char *path), (target, path), result < 0, path, true)
RETRY_PATH(ssize_t, readlink, (const char *path, char *buffer, size_t size), (path, buffer, size), result < 0, path, true)
RETRY_PATH(char *, realpath, (const char *path, char *buffer), (path, buffer), !result, path, false)
RETRY_PATH(FILE *, fopen, (const char *path, const char *mode), (path, mode), !result, path, false)
RETRY_PATH(int, statfs, (const char *path, struct statfs *st), (path, st), result < 0, path, false)
RETRY_PATH(int, statvfs, (const char *path, struct statvfs *st), (path, st), result < 0, path, false)
RETRY_PATH(ssize_t, getxattr, (const char *path, const char *name, void *value, size_t size, uint32_t position, int options),
           (path, name, value, size, position, options), result < 0, path, false)
RETRY_PATH(ssize_t, listxattr, (const char *path, char *names, size_t size, int options),
           (path, names, size, options), result < 0, path, false)
RETRY_PATH(int, setxattr, (const char *path, const char *name, const void *value, size_t size, uint32_t position, int options),
           (path, name, value, size, position, options), result < 0, path, false)

int FWQ_open(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }
    int result = open(path, flags, mode);
    if (result < 0 && FWQPermissionError(errno) && FWQGrantPath(path, false))
        result = open(path, flags, mode);
    return result;
}

int FWQ_openat(int fd, const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }
    int result = openat(fd, path, flags, mode);
    if (result >= 0 || !FWQPermissionError(errno)) return result;
    int savedError = errno;
    bool acquired = false;
    if (path[0] == '/' || fd == AT_FDCWD) {
        acquired = FWQGrantPath(path, false);
    } else {
        char base[PATH_MAX], absolute[PATH_MAX];
        if (fcntl(fd, F_GETPATH, base) == 0) {
            int length = snprintf(absolute, sizeof(absolute), "%s/%s", base, path);
            if (length > 0 && (size_t)length < sizeof(absolute))
                acquired = FWQGrantPath(absolute, false);
        }
    }
    errno = savedError;
    return acquired ? openat(fd, path, flags, mode) : result;
}

static bool grantPair(const char *src, bool sourceParent, const char *dst) {
    bool source = FWQGrantPath(src, sourceParent);
    bool destination = FWQGrantPath(dst, true);
    return source || destination;
}

int FWQ_rename(const char *src, const char *dst) {
    int result = rename(src, dst);
    if (result < 0 && FWQPermissionError(errno) && grantPair(src, true, dst))
        result = rename(src, dst);
    return result;
}

int FWQ_renamex_np(const char *src, const char *dst, unsigned int flags) {
    int result = renamex_np(src, dst, flags);
    if (result < 0 && FWQPermissionError(errno) && grantPair(src, true, dst))
        result = renamex_np(src, dst, flags);
    return result;
}

int FWQ_link(const char *src, const char *dst) {
    int result = link(src, dst);
    if (result < 0 && FWQPermissionError(errno) && grantPair(src, false, dst))
        result = link(src, dst);
    return result;
}
