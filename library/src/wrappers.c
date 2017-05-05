#define _GNU_SOURCE /* Must include to use RTLD_NEXT pseudo-handle with dlsym(3) */

#include "wrappers.h"

/**
 * Basic wrapper for access(2). It logs the access request, then invokes
 * glibc access(2) with the given argument.
 *
 * Note that the function prototype for access(2) is defined in <fcntl.h> and <unistd.h>.
 */

wrapper(int, access, const char *pathname, int mode) {

	logmsg("Intercepted access call with path: %s, mode: %d\n", pathname, mode);

	_access = dlsym(RTLD_NEXT, "access");
	return _access(pathname, mode);
}

/**
 * Basic wrapper for chmod(2). It logs the chmod request, then invokes
 * glibc chmod(2) with the given argument.
 *
 * Note that the function prototype for chmod(2) is defined in < >.
 */

wrapper(int, chmod, const char *pathname, mode_t mode) {

	logmsg("Intercepted chmod call with path: %s, mode: %d\n");

	_chmod = dlsym(RTLD_NEXT, "chmod");
	return _chmod(pathname, mode);
}

/**
 * Basic wrapper for faccessat(2). It logs the faccessat request, then invokes
 * glibc faccessat(2) with the given argument.
 *
 * Note that the function prototype for faccessat(2) is defined in <fcntl.h> and <unistd.h>.
 */

wrapper(int, faccessat, int dirfd, const char *pathname, int mode, int flags) {

	logmsg("Intercepted faccessat call with dirfd: %d, path: %s, mode: %d, flags: %d\n", dirfd, pathname, mode, flags);

	_faccessat = dlsym(RTLD_NEXT, "faccessat");
	return _faccessat(dirfd, pathname, mode, flags);
}

/**
 * Basic wrapper for fchmod(2). It logs the fchmod request, then invokes
 * glibc fchmod(2) with the given argument.
 *
 * Note that the function prototype for fchmod(2) is defined in <sys/stat.h>.
 */

wrapper(int, fchmod, int fd, mode_t mode) {

	logmsg("Intercepted fchmod call with fd: %d, mode: %d\n", fd, mode);

	_fchmod = dlsym(RTLD_NEXT, "fchmod");
	return _fchmod(pathname, mode);
}

/**
 * Basic wrapper for fchmodat(2). It logs the fchmodat request, then invokes
 * glibc fchmodat(2) with the given argument.
 *
 * Note that the function prototype for fchmodat(2) is defined in <sys/stat.h>.
 */
wrapper(int, fchmodat, int dirfd, const char *pathname, mode_t mode, int flags) {

	logmsg("Intercepted fchmodat call with dirfd: %d, path: %s, mode: %d, flags: %d\n", dirfd, pathname, mode, flags);

	_fchmodat = dlsym(RTLD_NEXT, "fchmodat");
	return _fchmodat(dirfd, pathname, mode, flags);
}

/**
 * Basic wrapper for fchownat(2). It logs the fchownat request, then invokes
 * glibc fchownat(2) with the given argument.
 *
 * Note that the function prototype for fchownat(2) is defined in <unistd.h> <fcntl.h>.
 */

wrapper(int fchownat, int dirfd, const char *pathname, uid_t owner, gid_t group, int flags) {

	logmsg("Intercepted fchownat call with dirfd: %d, path: %s, uid: %lu, gid: %lu, flags: %d\n", dirfd, pathname, owner, group, flags);

	_fchownat = dlsym(RTLD_NEXT, "fchownat");
	return _fchownat(dirfd, pathname, owner, group, flags);
}

/**
 * Basic wrapper for mkdir(2). It logs the mkdir request, then invokes
 * glibc mkdir(2) with the given argument.
 *
 * Note that the function prototype for mkdir(2) is defined in <sys/types.h>.
 */

wrapper(int, mkdir, const char *pathname, mode_t mode) {

	logmsg("Intercepted mkdir call with path: %s, mode: %d\n", pathname, mode);

	_mkdir = dlsym(RTLD_NEXT, "mkdir");
	return _mkdir(pathname, mode);
}

/**
 * Basic wrapper for mkdirat(2). It logs the mkdirat request, then invokes
 * glibc mkdir(2) with the given arguments.
 *
 * Note that the function prototype for mkdirat(2) is defined in <sys/types.h>
 * and <sys/stat.h>.
 */

wrapper(int, mkdirat, int dirfd, const char *pathname, mode_t mode) {

	logmsg("Intercepted mkdirat call with dirfd: %d, path: %s, mode: %d\n", dirfd, pathname, mode);

	_mkdirat = dlsym(RTLD_NEXT, "mkdirat");
	return _mkdir(pathname, mode);
}

/**
 * Basic wrapper for open(2). It logs the open request, then invokes
 * glibc open(2) with the given arguments.
 *
 * Note that the function prototype for open(2) is defined in <fcntl.h>.
 */

wrapper(int, open, const char *__file, int __oflag, ...) {
	va_list args;

	mode_t mode = 0;

	/* Initialize variable argument list */
	va_start(args, __oflag);

	/* Mode only considered when flags includes O_CREAT or O_TMPFILE */
	if (__oflag & O_CREAT || __oflag & O_TMPFILE)
		mode = va_arg(args, mode_t);

	logmsg("intercepted open call with file=%s, flags=%d, mode=%d\n", __file, __oflag, mode);

	/* Destory va list */
	va_end(args);

	_open = dlsym(RTLD_NEXT, "open");
	return _open(__file, __oflag, mode);
}

/**
 * Basic wrapper for puts(3). It logs the puts request, then invokes
 * glibc puts(3) with the given argument.
 *
 * Note that the function prototype for puts(3) is defined in <stdio.h>.
 */

wrapper(int, puts, const char* str) {

    logmsg("Intercepted puts call with string: %s\n", str);

    _puts = dlsym(RTLD_NEXT, "puts");
    return _puts(str);
}

/**
 * Basic wrapper for write(2). It logs the write request, then invokes
 * glibc write(2) with the given arguments.
 *
 * Note that the function prototype for write(2) is defined in <unistd.h>.
 */

wrapper(ssize_t, write, int fd, const void *buf, size_t count) {

	logmsg("Intercepted write call with fd: %d, count: %lu\n", fd, count);

    _write = dlsym(RTLD_NEXT, "write");
    return _write(fd, buf, count);
}

