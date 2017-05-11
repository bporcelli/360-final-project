#define _GNU_SOURCE // required to expose certain symbols -- don't remove

#include <utime.h>      // struct utimbuf
#include <sys/statfs.h> // struct statfs
#include <sys/stat.h>   // struct stat
#include <fcntl.h>      // S_* constants, AT_* constants
#include <stdarg.h>
#include <sys/stat.h>
#include "wrappers.h"
#include "dlhelper.h"
#include "logger.h"

/**
 * Basic wrapper for access(2). It logs the access request, then invokes
 * glibc access(2) with the given argument.
 *
 * Note that the function prototype for access(2) is defined in <fcntl.h> and <unistd.h>.
 */

sip_wrapper(int, access, const char *pathname, int mode) {

	sip_info("Intercepted access call with path: %s, mode: %d\n", pathname, mode);

	_access = sip_find_sym("access");
	return _access(pathname, mode);
}

/**
 * Basic wrapper for chmod(2). It logs the chmod request, then invokes
 * glibc chmod(2) with the given argument.
 *
 * Note that the function prototype for chmod(2) is defined in < >.
 */

sip_wrapper(int, chmod, const char *pathname, mode_t mode) {

	sip_info("Intercepted chmod call with path: %s, mode: %d\n", pathname, mode);

	_chmod = sip_find_sym("chmod");
	return _chmod(pathname, mode);
}

/**
 * Basic wrapper for execve(2). It logs the execve request, then invokes
 * glibc execve(2) with the given argument.
 *
 * Note that the function prototype for execve(2) is defined in <unistd.h>.
 */

sip_wrapper(int, execve, const char *filename, char *const argv[], char *const envp[]) {

	sip_info("Intercepted execve call with file: %s\n", filename);

	_execve = sip_find_sym("execve");
	return _execve(filename, argv, envp);
}

/**
 * Basic wrapper for faccessat(2). It logs the faccessat request, then invokes
 * glibc faccessat(2) with the given argument.
 *
 * Note that the function prototype for faccessat(2) is defined in <fcntl.h> and <unistd.h>.
 */

sip_wrapper(int, faccessat, int dirfd, const char *pathname, int mode, int flags) {

	sip_info("Intercepted faccessat call with dirfd: %d, path: %s, mode: %d, flags: %d\n", dirfd, pathname, mode, flags);

	_faccessat = sip_find_sym("faccessat");
	return _faccessat(dirfd, pathname, mode, flags);
}

/**
 * Basic wrapper for fchmod(2). It logs the fchmod request, then invokes
 * glibc fchmod(2) with the given argument.
 *
 * Note that the function prototype for fchmod(2) is defined in <sys/stat.h>.
 */

sip_wrapper(int, fchmod, int fd, mode_t mode) {

	sip_info("Intercepted fchmod call with fd: %d, mode: %d\n", fd, mode);

	_fchmod = sip_find_sym("fchmod");
	return _fchmod(fd, mode);
}

/**
 * Basic wrapper for fchmodat(2). It logs the fchmodat request, then invokes
 * glibc fchmodat(2) with the given argument.
 *
 * Note that the function prototype for fchmodat(2) is defined in <sys/stat.h>.
 */
sip_wrapper(int, fchmodat, int dirfd, const char *pathname, mode_t mode, int flags) {

	sip_info("Intercepted fchmodat call with dirfd: %d, path: %s, mode: %d, flags: %d\n", dirfd, pathname, mode, flags);

	_fchmodat = sip_find_sym("fchmodat");
	return _fchmodat(dirfd, pathname, mode, flags);
}

/**
 * Basic wrapper for fchownat(2). It logs the fchownat request, then invokes
 * glibc fchownat(2) with the given argument.
 *
 * Note that the function prototype for fchownat(2) is defined in <unistd.h> <fcntl.h>.
 */

sip_wrapper(int, fchownat, int dirfd, const char *pathname, uid_t owner, gid_t group, int flags) {

	sip_info("Intercepted fchownat call with dirfd: %d, path: %s, uid: %lu, gid: %lu, flags: %d\n", dirfd, pathname, owner, group, flags);

	_fchownat = sip_find_sym("fchownat");
	return _fchownat(dirfd, pathname, owner, group, flags);
}

/**
 * Basic wrapper for fstat(2). It logs the fstat request, then invokes
 * glibc fstat(2) with the given argument.
 *
 * Note that the function prototype for fstat(2) is defined in <unistd.h> <sys/types.h> <sys/stat.h>.
 */

sip_wrapper(int, fstat, int fd, struct stat *statbuf) {

	sip_info("Intercepted fstat call with fd: %d\n", fd);

	_fstat = sip_find_sym("fstat");
	return _fstat(fd, statbuf);
}

/**
 * Basic wrapper for fstatat(2). It logs the fstatat request, then invokes
 * glibc fstatat(2) with the given argument.
 *
 * Note that the function prototype for fstatat(2) is defined in <fnctl.h> <sys/stat.h>.
 */

sip_wrapper(int, fstatat, int dirfd, const char *pathname, struct stat *statbuf, int flags) {

	sip_info("Intercepted fstatat call with dirfd: %d, path: %s, flags: %d\n", dirfd, pathname, flags);

	_fstatat = sip_find_sym("fstatat");
	return _fstatat(dirfd, pathname, statbuf, flags);
}


/**
 * Basic wrapper for fstatfs(2). It logs the fstatfs request, then invokes 
 * glibc fstatfs(2) with the given argument.
 *
 * Note that the function prototype for fstatfs(2) is defined in <sys/vfs.h>
 */
sip_wrapper(int, fstatfs, int fd, struct statfs *buf) {

	sip_info("Intercepted fstatfs call with fd: %d\n", fd);

	_fstatfs = sip_find_sym("fstatfs");
	return _fstatfs(fd, buf);
}

/**
 * Basic wrapper for futimens(2). It logs the futimens request, then invokes
 * glibc futimens(2) with the given arguments.
 *
 * Note that the function prototype for futimens(2) is defined in <sys/stat.h> <fcntl.h>.
 */

sip_wrapper(int, futimesat, int dirfd, const char *pathname, const struct timeval times[2]) {

	sip_info("Intercepted futimesat call with dirfd: %d, pathname: %s\n", dirfd, pathname);

    _futimesat = sip_find_sym("futimesat");
    return _futimesat(dirfd, pathname, times);
}

/**
 * Basic wrapper for getgid(2). It logs the getgid request, then invokes
 * glibc getgid(2) with the given argument.
 *
 * Note that the function prototype for getgid(2) is defined in <unistd.h> <sys/types.h>.
 */

sip_wrapper(uid_t, getgid, void) {

	sip_info("Intercepted getgid call:\n");

	_getgid = sip_find_sym("getgid");
	return _getgid();
}

/**
 * Basic wrapper for getgroups(2). It logs the getgroups request, then invokes
 * glibc getgroups(2) with the given argument.
 *
 * Note that the function prototype for getgroups(2) is defined in <unistd.h> <sys/types.h>.
 */

sip_wrapper(int, getgroups, int size, gid_t list[]) {

	sip_info("Intercepted getgroups call with size: %d\n", size);

	_getgroups = sip_find_sym("getgroups");
	return _getgroups(size, list);
}


/**
 * Basic wrapper for getuid2). It logs the getuid request, then invokes
 * glibc getuid(2) with the given argument.
 *
 * Note that the function prototype for getuid(2) is defined in <unistd.h> <sys/types.h>.
 */

sip_wrapper(uid_t, getuid, void) {

	sip_info("Intercepted getuid call:\n");

	_getuid = sip_find_sym("getuid");
	return _getuid();
}

/**
 * Basic wrapper for getresuid2). It logs the getresuid request, then invokes
 * glibc getresuid(2) with the given argument.
 *
 * Note that the function prototype for getresuid(2) is defined in <unistd.h>.
 */

sip_wrapper(int, getresuid, uid_t *ruid, uid_t *euid, uid_t *suid) {

	sip_info("Intercepted getresuid call with ruid: %lu, euid: %lu, suid: %lu\n", ruid, euid, suid);

	_getresuid = sip_find_sym("getresuid");
	return _getresuid(ruid, euid, suid);
}

/**
 * Basic wrapper for getreguid2). It logs the getreguid request, then invokes
 * glibc getreguid(2) with the given argument.
 *
 * Note that the function prototype for getreguid(2) is defined in <unistd.h>.
 */

sip_wrapper(int, getreguid, gid_t *rgid, gid_t *egid, gid_t *sgid) {

	sip_info("Intercepted getreguid call with rgid: %lu, egid: %lu, sgid: %lu\n", rgid, egid, sgid);

	_getreguid = sip_find_sym("getresgid");
	return _getreguid(rgid, egid, sgid);
}



/**
 * Basic wrapper for lchown(2). It logs the lchown request, then invokes
 * glibc lchown(2) with the given argument.
 *
 * Note that the function prototype for lchown(2) is defined in <unistd.h>.
 */

sip_wrapper(int, lchown, const char *pathname, uid_t owner, gid_t group) {

	sip_info("Intercepted lchown call with path: %s, uid: %lu, gid: %lu\n", pathname, owner, group);

	_lchown = sip_find_sym("lchown");
	return _lchown(pathname, owner, group);
}



/**
 * Basic wrapper for link(2). It logs the link request, then invokes 
 * glibc link(2) with the given argument.
 *
 * Note that the function prototype for link(2) is defined in <unistd.h>
 */

sip_wrapper(int, link, const char *oldpath, const char *newpath) {

	sip_info("Intercepted link call with oldpath: %s, newpath: %s\n", oldpath, newpath);

	_link = sip_find_sym("link");
	return _link(oldpath, newpath);
}

/**
 * Basic wrapper for linkat(2). It logs the linkat request, then invokes 
 * glibc linkat(2) with the given argument.
 *
 * Note that the function prototype for linkat(2) is defined in <fnctl.h> <unistd.h>
 */
sip_wrapper(int, linkat, int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags) {

	sip_info("Intercepted linkat call with olddir: %d, oldpath: %s, newdir: %d, newpath: %s\n", olddirfd, oldpath, newdirfd, newpath);

	_linkat = sip_find_sym("linkat");
	return _linkat(olddirfd, oldpath, newdirfd, newpath, flags);
}

/**
 * Basic wrapper for lstat(2). It logs the lstat request, then invokes 
 * glibc lstat(2) with the given argument.
 *
 * Note that the function prototype for lstat(2) is defined in <sys/types.h> <sys/stat.h> <unistd.h>
 */
sip_wrapper(int, lstat, const char *pathname, struct stat *statbuf) {

	sip_info("Intercepted lstat call with path: %s\n", pathname);

	_lstat = sip_find_sym("lstat");
	return _lstat(pathname, statbuf);
}



/**
 * Basic wrapper for mkdir(2). It logs the mkdir request, then invokes
 * glibc mkdir(2) with the given argument.
 *
 * Note that the function prototype for mkdir(2) is defined in <sys/types.h>.
 */

sip_wrapper(int, mkdir, const char *pathname, mode_t mode) {

	sip_info("Intercepted mkdir call with path: %s, mode: %d\n", pathname, mode);

	_mkdir = sip_find_sym("mkdir");
	return _mkdir(pathname, mode);
}

/**
 * Basic wrapper for mkdirat(2). It logs the mkdirat request, then invokes
 * glibc mkdir(2) with the given arguments.
 *
 * Note that the function prototype for mkdirat(2) is defined in <sys/types.h>
 * and <sys/stat.h>.
 */

sip_wrapper(int, mkdirat, int dirfd, const char *pathname, mode_t mode) {

	sip_info("Intercepted mkdirat call with dirfd: %d, path: %s, mode: %d\n", dirfd, pathname, mode);

	_mkdirat = sip_find_sym("mkdirat");
	return _mkdir(pathname, mode);
}

/**
 * Basic wrapper for mknod(2). It logs the mknod request, then invokes
 * glibc mknod(2) with the given arguments.
 *
 * Note that the function prototype for mknod(2) is defined in <sys/types.h> <sys/stat.h> <fcntl.h> <unistd.h>
 */

sip_wrapper(int, mknod, const char *pathname, mode_t mode, dev_t dev) {

	sip_info("Intercepted mknod call with path: %s, mode: %lu, dev: %lu\n", pathname, mode, dev);

	_mknod = sip_find_sym("mknod");
	return _mknod(pathname, mode, dev);
}

/**
 * Basic wrapper for mknodat(2). It logs the mknodat request, then invokes
 * glibc mknodat(2) with the given arguments.
 *
 * Note that the function prototype for mknodat(2) is defined in <sys/stat.h> <fcntl.h>
 */

sip_wrapper(int, mknodat, int dirfd, const char *pathname, mode_t mode, dev_t dev) {

	sip_info("Intercepted mknodat call with dirfd: %d, path: %s, mode: %lu, dev: %lu\n", dirfd, pathname, mode, dev);

	_mknodat = sip_find_sym("mknodat");
	return _mknodat(dirfd, pathname, mode, dev);
}



/**
 * Basic wrapper for open(2). It logs the open request, then invokes
 * glibc open(2) with the given arguments.
 *
 * Note that the function prototype for open(2) is defined in <fcntl.h>.
 */

sip_wrapper(int, open, const char *__file, int __oflag, ...) {
	va_list args;

	mode_t mode = 0;

	/* Initialize variable argument list */
	va_start(args, __oflag);

	/* Mode only considered when flags includes O_CREAT or O_TMPFILE */
	if (__oflag & O_CREAT || __oflag & O_TMPFILE)
		mode = va_arg(args, mode_t);

	sip_info("intercepted open call with file=%s, flags=%d, mode=%d\n", __file, __oflag, mode);

	/* Destory va list */
	va_end(args);

	_open = sip_find_sym("open");
	return _open(__file, __oflag, mode);
}

/**
 * Basic wrapper for readlink(2). It logs the readlink request, then invokes
 * glibc readlink with the given argument.
 *
 * Note that the function prototype for readlinkat is defined in <unistd.h>.
 */

sip_wrapper(ssize_t, readlink, const char *pathname, char *buf, size_t bufsiz) {

    sip_info("Intercepted readlink call with pathname: %s, bufsiz: %lu\n", pathname, bufsiz);

    _readlink = sip_find_sym("readlink");
    return _readlink(pathname, buf, bufsiz);
}

/**
 * Basic wrapper for readlinkat(2). It logs the readlinkat request, then invokes
 * glibc readlinkat with the given argument.
 *
 * Note that the function prototype for readlinkat is defined in <unistd.h>.
 */

sip_wrapper(ssize_t, readlinkat, int dirfd, const char *pathname, char *buf, size_t bufsiz) {

    sip_info("Intercepted readlinkat call with dirfd: %d, pathname: %s, bufsiz: %lu\n", dirfd, pathname, bufsiz);

    _readlinkat = sip_find_sym("readlinkat");
    return _readlinkat(dirfd, pathname, buf, bufsiz);
}

/**
 * Basic wrapper for rename(2). It logs the rename(2) request, then invokes
 * glibc rename with the given argument.
 *
 * Note that the function prototype for rename is defined in <stdio.h>.
 */

sip_wrapper(int, rename, const char *oldpath, const char *newpath) {

    sip_info("Intercepted rename call with oldpath: %s, newpath: %s\n", oldpath, newpath);

    _rename = sip_find_sym("rename");
    return _rename(oldpath, newpath);
}

/**
 * Basic wrapper for renameat(2). It logs the renameat(2) request, then invokes
 * glibc renameat with the given argument.
 *
 * Note that the function prototype for renameat is defined in <fcntl.h> <stdio.h>.
 */

sip_wrapper(int, renameat, int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {

    sip_info("Intercepted renameat call with olddirfd: %s, oldpath: %s, newdirfd: %d\n", olddirfd, oldpath, newpath);

    _renameat = sip_find_sym("renameat");
    return _renameat(olddirfd, oldpath, newdirfd, newpath);
}

/**
 * Basic wrapper for renameat2(2). It logs the renameat2(2) request, then invokes
 * glibc renameat2 with the given argument.
 *
 * Note that the function prototype for renameat2 is defined in <fcntl.h> <stdio.h>.
 */

sip_wrapper(int, renameat2, int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags) {

    sip_info("Intercepted renameatat2 call with olddirfd: %s, oldpath: %s, newdirfd: %d, newpath: %s, flags: %d\n", 
    	olddirfd, oldpath, newdirfd, newpath, flags);

    _renameat2 = sip_find_sym("renameat2");
    return _renameat2(olddirfd, oldpath, newdirfd, newpath, flags);
}



/**
 * Basic wrapper for rmdir. It logs the rmdir request, then invokes
 * glibc rmdirt with the given argument.
 *
 * Note that the function prototype for rmdir is defined in <unistd.h>.
 */
sip_wrapper(int, rmdir, const char *pathname) {

	sip_info("Intercepted rmdir call with path: %s\n", pathname);

	_rmdir = sip_find_sym("rmdir");
	return _rmdir(pathname);
}

/**
 * Basic wrapper for stat(2). It logs the stat request, then invokes 
 * glibc stat(2) with the given argument.
 *
 * Note that the function prototype for stat(2) is defined in <sys/types.h> <sys/stat.h> <unistd.h>
 */
sip_wrapper(int, stat, const char *pathname, struct stat *statbuf) {

	sip_info("Intercepted stat call with path: %s\n", pathname);

	_stat = sip_find_sym("stat");
	return _stat(pathname, statbuf);
}

/**
 * Basic wrapper for statfs(2). It logs the statfs request, then invokes 
 * glibc statfs(2) with the given argument.
 *
 * Note that the function prototype for statfs(2) is defined in <sys/vfs.h>
 */
sip_wrapper(int, statfs, const char *path, struct statfs *buf) {

	sip_info("Intercepted statfs call with path: %s\n", path);

	_statfs = sip_find_sym("statfs");
	return _statfs(path, buf);
}

/**
 * Basic wrapper for symlink(2). It logs the symlink request, then invokes
 * glibc symlink(2) with the given argument.
 *
 * Note that the function prototype for symlink(2) is defined in <unistd.h>.
 */

sip_wrapper(int, symlink, const char *target, const char *linkpath) {

	sip_info("Intercepted symlink call with target: %s, linkpath: %s\n", target, linkpath);

    _symlink = sip_find_sym("symlink");
    return _symlink(target, linkpath);
}

/**
 * Basic wrapper for symlinkat(2). It logs the symlinkat request, then invokes
 * glibc symlinkat(2) with the given argument.
 *
 * Note that the function prototype for symlinkat(2) is defined in <fnctl.h> <unistd.h>.
 */

sip_wrapper(int, symlinkat, const char *target, int newdirfd, const char *linkpath) {

	sip_info("Intercepted symlinkat call with target: %s, newdirfd: %d, linkpath: %s\n", target, newdirfd, linkpath);

    _symlinkat = sip_find_sym("symlinkat");
    return _symlinkat(target, newdirfd, linkpath);
}

/**
 * Basic wrapper for unlink(2). It logs the unlink request, then invokes
 * glibc unlink(2) with the given argument.
 *
 * Note that the function prototype for unlink(2) is defined in <unistd.h>.
 */

sip_wrapper(int, unlink, const char *pathname) {

	sip_info("Intercepted unlink call with path: %s\n", pathname);

    _unlink = sip_find_sym("unlink");
    return _unlink(pathname);
}

/**
 * Basic wrapper for unlinkT(2). It logs the unlinkT request, then invokes
 * glibc unlinkat(2) with the given argument.
 *
 * Note that the function prototype for unlinkat(2) is defined in <fnctl.h> <unistd.h>.
 */

sip_wrapper(int, unlinkat, int dirfd, const char *pathname, int flags) {

	sip_info("Intercepted unlinkat call with dirfd: %d, path: %s, flags: %d\n", dirfd, pathname, flags);

    _unlinkat = sip_find_sym("unlinkat");
    return _unlinkat(dirfd, pathname, flags);
}

/**
 * Basic wrapper for write(2). It logs the write request, then invokes
 * glibc write(2) with the given arguments.
 *
 * Note that the function prototype for write(2) is defined in <unistd.h>.
 */

sip_wrapper(ssize_t, write, int fd, const void *buf, size_t count) {

	// Don't print log message for now -- wreaks havoc if you try to read log file
	// e.g. with a program like cat
	// sip_info("Intercepted write call with fd: %d, count: %lu\n", fd, count);

    _write = sip_find_sym("write");
    return _write(fd, buf, count);
}

/**
 * Basic wrapper for utime(2). It logs the utime request, then invokes
 * glibc utime(2) with the given arguments.
 *
 * Note that the function prototype for utime(2) is defined in <utime.h>.
 */

sip_wrapper(int, utime, const char *path, const struct utimbuf *times) {

	sip_info("Intercepted utime call with path: %s\n", path);

    _utime = sip_find_sym("utime");
    return _utime(path, times);
}

/**
 * Basic wrapper for utimensat(2). It logs the utimensat request, then invokes
 * glibc utimensat(2) with the given arguments.
 *
 * Note that the function prototype for utimensat(2) is defined in <utime.h>.
 */

sip_wrapper(int, utimensat, int dirfd, const char *pathname, const struct timespec times[2], int flags) {

	sip_info("Intercepted utimensat call with dirfd: %d, pathname: %s, flags: %d\n", dirfd, pathname, flags);

    _utimensat = sip_find_sym("utimensat");
    return _utimensat(dirfd, pathname, times, flags);
}

/**
 * Basic wrapper for utimes(2). It logs the utimes request, then invokes
 * glibc utimes(2) with the given arguments.
 *
 * Note that the function prototype for utimes(2) is defined in <sys/time.h>.
 */

sip_wrapper(int, utimes, const char *filename, const struct timeval times[2]) {

	sip_info("Intercepted utimes call with filename: %s\n", filename);

    _utimes = sip_find_sym("utimes");
    return _utimes(filename, times);
}

