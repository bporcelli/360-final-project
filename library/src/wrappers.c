
#include <utime.h>
#include <sys/statfs.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdlib.h>

#include "wrappers.h"
#include "dlhelper.h"
#include "common.h"
#include "logger.h"
#include "level.h"
#include "util.h"

/**
 * Wrapper for faccessat(2). Enforces the following policy:
 *
 * PROCESS LEVEL | ACTION
 * ---------------------------------------------------------------------------
 * HIGH          | Deny read/write access for low integrity files.
 * ---------------------------------------------------------------------------
 * LOW           | If request fails with errno EACCES, forward to delegator.
 * ---------------------------------------------------------------------------
 */
sip_wrapper(int, faccessat, int dirfd, const char *pathname, int mode, int flags) {

	sip_info("Intercepted faccessat call with dirfd: %d, path: %s, mode: %d, flags: %d\n", dirfd, pathname, mode, flags);

	if (SIP_IS_HIGHI) {
		int read_or_exec = (mode & R_OK) || (mode & X_OK);

		if (SIP_LV_LOW == sip_path_to_level(pathname) && read_or_exec) {
			sip_info("Denied read/exec permissions on low integrity file %s\n", pathname);
			errno = EACCES;
			return -1;
		}
	}

	_faccessat = sip_find_sym("faccessat");

	int rv = _faccessat(dirfd, pathname, mode, flags);

	if (rv == -1 && errno == EACCES && SIP_IS_LOWI) {
		// TODO: SEND REQUEST TO DELEGATOR. UPDATE ERRNO/RV ON RESPONSE.
		// HOW TO DO THIS WITHOUT COPYING THE PIP SOLUTION ONE-FOR-ONE...?
		sip_info("Would delegate faccessat on %s\n", pathname);
	}
	return rv;
}

/**
 * Wrapper for access(2). Redirects to faccessat(2).
 */
sip_wrapper(int, access, const char *pathname, int mode) {
	return faccessat(AT_FDCWD, pathname, mode, 0);
}

/**
 * Wrapper for fchmodat(2). Enforces the following policies:
 *
 * PROCESS LEVEL | ACTION
 * ---------------------------------------------------------------------------
 * HIGH          | None.
 * ---------------------------------------------------------------------------
 * LOW           | If request fails with errno EACCES or EPERM, forward to delegator.
 * ---------------------------------------------------------------------------
 */
sip_wrapper(int, fchmodat, int dirfd, const char *pathname, mode_t mode, int flags) {

	sip_info("Intercepted fchmodat call with dirfd: %d, path: %s, mode: %d, flags: %d\n", dirfd, pathname, mode, flags);

	_fchmodat = sip_find_sym("fchmodat");
	
	int rv = _fchmodat(dirfd, pathname, mode, flags);

	if (rv == -1 && (errno == EACCES || errno == EPERM) && SIP_IS_LOWI) {
		// TODO: SEND REQUEST TO DELEGATOR. UPDATE ERRNO/RV ON RESPONSE.
		sip_info("Would delegate faccessat on %s\n", pathname);
	}
	return rv;
}

/**
 * Wrapper for chmod(2). Redirects to fchmodat(2).
 */
sip_wrapper(int, chmod, const char *pathname, mode_t mode) {
	return fchmodat(AT_FDCWD, pathname, mode, 0);
}

/**
 * Basic wrapper for fchmod(2). Redirects to fchmodat(2).
 */
sip_wrapper(int, fchmod, int fd, mode_t mode) {
	char* path = sip_fd_to_path(fd);

	if (path == NULL)
		return -1;

	int res = fchmodat(AT_FDCWD, path, mode, 0);

	free(path);
	return res;
}

/**
 * Basic wrapper for fchownat(2). Enforces the following policies:
 *
 * PROCESS LEVEL | ACTION
 * ---------------------------------------------------------------------------
 * ALL           | Prevent changes from low -> high integrity.
 * ---------------------------------------------------------------------------
 * HIGH          | Allow changes from high -> low integrity.
 * ---------------------------------------------------------------------------
 * LOW           | Delegate to helper if request fails with EACCES or EPERM.
 * ---------------------------------------------------------------------------
 */
sip_wrapper(int, fchownat, int dirfd, const char *pathname, uid_t owner, gid_t group, int flags) {

	sip_info("Intercepted fchownat call with dirfd: %d, path: %s, uid: %lu, gid: %lu, flags: %d\n", dirfd, pathname, owner, group, flags);

	int flevel = sip_path_to_level(pathname);
	int ulevel = sip_uid_to_level(owner);
	int glevel = sip_gid_to_level(group);

	if (sip_level_min(glevel, ulevel) > flevel) {
		sip_info("Blocked attempt to upgrade file %s\n", pathname);
		errno = EACCES;
		return -1;
	} else if (sip_level_min(glevel, ulevel) < flevel && SIP_IS_LOWI) {
		sip_info("Blocked attempt to downgrade file %s\n", pathname);
		errno = EACCES;
		return -1;
	}

	_fchownat = sip_find_sym("fchownat");

	int rv = _fchownat(dirfd, pathname, owner, group, flags);

	if (rv == -1 && (errno == EACCES || errno == EPERM) && SIP_IS_LOWI) {
		// TODO: SEND REQUEST TO DELEGATOR. UPDATE ERRNO/RV ON RESPONSE.
		sip_info("Would delegate fchownat on %s\n", pathname);
	}
	return rv;
}

/**
 * Wrapper for fchown(2). Redirects to fchownat(2).
 */
sip_wrapper(int, fchown, int fd, uid_t owner, gid_t group) {
	char* path = sip_fd_to_path(fd);

	if (path == NULL)
		return -1;

	sip_info("in fchown. resolved fd %d to path %s\n", fd, path);

	int res = fchownat(AT_FDCWD, path, owner, group, 0);

	free(path);
	return res;
}

/**
 * Wrapper for lchown(2). Redirects to fchownat(2).
 */
sip_wrapper(int, lchown, const char *pathname, uid_t owner, gid_t group) {
	return fchownat(AT_FDCWD, pathname, owner, group, AT_SYMLINK_NOFOLLOW);
}

/**
 * Wrapper for chown(2). Redirects to fchownat(2).
 */
sip_wrapper(int, chown, const char *file, uid_t owner, gid_t group) {
	return fchownat(AT_FDCWD, file, owner, group, 0);
}

/**
 * Wrapper for getgid(2). Enforces the following policy:
 *
 * PROCESS LEVEL | ACTION
 * ---------------------------------------------------------------------------
 * HIGH          | None.
 * ---------------------------------------------------------------------------
 * LOW           | If real GID is untrusted GID, return trusted GID.
 * ---------------------------------------------------------------------------
 */
sip_wrapper(uid_t, getgid, void) {
	_getgid = sip_find_sym("getgid");

	gid_t group = _getgid();

	if (group == SIP_UNTRUSTED_USERID) {
		return SIP_TRUSTED_GROUP_GID;
	}	
	return group;
}

/**
 * Wrapper for getreguid2). Enforces the following policy:
 *
 * PROCESS LEVEL | ACTION
 * ---------------------------------------------------------------------------
 * HIGH          | None.
 * ---------------------------------------------------------------------------
 * LOW           | If real, saved, or effective GID is untrusted, return trusted GID.
 * ---------------------------------------------------------------------------
 */
sip_wrapper(int, getresgid, gid_t *rgid, gid_t *egid, gid_t *sgid) {
	_getresgid = sip_find_sym("getresgid");

	int rv = _getresgid(rgid, egid, sgid);

	if (rv == 0) {
		if (*rgid == SIP_UNTRUSTED_USERID) 
			*rgid = SIP_TRUSTED_GROUP_GID;

		if (*egid == SIP_UNTRUSTED_USERID)
			*egid = SIP_TRUSTED_GROUP_GID;
		
		if (*sgid == SIP_UNTRUSTED_USERID)
			*sgid = SIP_TRUSTED_GROUP_GID;
	}
	return rv;
}

/**
 * Wrapper for getuid2). Enforces the following policy:
 *
 * PROCESS LEVEL | ACTION
 * ---------------------------------------------------------------------------
 * HIGH          | None.
 * ---------------------------------------------------------------------------
 * LOW           | If real UID is untrusted UID, return trusted UID.
 * ---------------------------------------------------------------------------
 */
sip_wrapper(uid_t, getuid, void) {
	_getuid = sip_find_sym("getuid");

	uid_t user = _getuid();

	if (user == SIP_UNTRUSTED_USERID) {
		return SIP_REAL_USERID;
	}
	return user;
}

/**
 * Wrapper for getuid2). Enforces the following policy:
 *
 * PROCESS LEVEL | ACTION
 * ---------------------------------------------------------------------------
 * HIGH          | None.
 * ---------------------------------------------------------------------------
 * LOW           | If real, effective, or saved UID is untrusted UID, return trusted UID.
 * ---------------------------------------------------------------------------
 */
sip_wrapper(int, getresuid, uid_t *ruid, uid_t *euid, uid_t *suid) {
	_getresuid = sip_find_sym("getresuid");

	int rv = _getresuid(ruid, euid, suid);

	if (rv == 0) {
		if (*ruid == SIP_UNTRUSTED_USERID) 
			*ruid = SIP_REAL_USERID;

		if (*euid == SIP_UNTRUSTED_USERID)
			*euid = SIP_REAL_USERID;
		
		if (*suid == SIP_UNTRUSTED_USERID)
			*suid = SIP_REAL_USERID;
	} 	
	return rv;
}

/**
 * Wrapper for getgroups(2). Enforces the following process:
 *
 * PROCESS LEVEL | ACTION
 * ---------------------------------------------------------------------------
 * HIGH          | None.
 * ---------------------------------------------------------------------------
 * LOW           | Substitute untrusted GID with trusted GID in result.
 * ---------------------------------------------------------------------------
 */
sip_wrapper(int, getgroups, int size, gid_t list[]) {
	_getgroups = sip_find_sym("getgroups");

	int rv = _getgroups(size, list), i;

	if (rv > 0 && size > 0) {
		/* If any of the GIDs in list match the untrusted GID, substitute with
		 * the trusted GID. */
		for (i = 0; i < rv; i++) {
			if (list[i] == SIP_UNTRUSTED_USERID) {
				list[i] = SIP_TRUSTED_GROUP_GID;
			}
		}
	}

	return rv;
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
 * Basic wrapper for stat(2). It logs the stat request, then invokes 
 * glibc stat(2) with the given argument.
 *
 * NOTE: __xstat is the name libc uses internally for stat.
 */
sip_wrapper(int, __xstat, int ver, const char *pathname, struct stat *statbuf) {

	sip_info("Intercepted stat call with path: %s\n", pathname);

	___xstat = sip_find_sym("__xstat");
	return ___xstat(ver, pathname, statbuf);
}

/**
 * Basic wrapper for fstat(2). It logs the fstat request, then invokes
 * glibc fstat(2) with the given argument.
 *
 * NOTE: __fxstat is the name libc uses internally for fstat.
 */
sip_wrapper(int, __fxstat, int ver, int fd, struct stat *statbuf) {

	sip_info("Intercepted fstat call with fd: %d\n", fd);

	___fxstat = sip_find_sym("__fxstat");
	return ___fxstat(ver, fd, statbuf);
}

/**
 * Basic wrapper for fstatat(2). It logs the fstatat request, then invokes
 * glibc fstatat(2) with the given argument.
 *
 * NOTE: __fxstatat is the name libc uses internally for fstatat.
 */
sip_wrapper(int, __fxstatat, int ver, int dirfd, const char *pathname, struct stat *statbuf, int flags) {

	sip_info("Intercepted fstatat call with dirfd: %d, path: %s, flags: %d\n", dirfd, pathname, flags);

	___fxstatat = sip_find_sym("__fxstatat");
	return ___fxstatat(ver, dirfd, pathname, statbuf, flags);
}

/**
 * Basic wrapper for lstat(2). It logs the lstat request, then invokes 
 * glibc lstat(2) with the given argument.
 *
 * NOTE: __lxstat is the name libc uses internally for lstat.
 */
sip_wrapper(int, __lxstat, int ver, const char *pathname, struct stat *statbuf) {

	sip_info("Intercepted lstat call with path: %s\n", pathname);

	___lxstat = sip_find_sym("__lxstat");
	return ___lxstat(ver, pathname, statbuf);
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
 * Wrapper for link(2). Enforces the following policy:
 *
 * PROCESS LEVEL | ACTION
 * ---------------------------------------------------------------------------
 * Send to linkat()
 * ---------------------------------------------------------------------------
 */

sip_wrapper(int, link, const char *oldpath, const char *newpath) {

	sip_info("Intercepted link call with oldpath: %s, newpath: %s\n", oldpath, newpath);

	_link = linkat(AT_FDCWD, oldpath, AT_FDCWD, newpath, AT_SYMLINK_FOLLOW);

	return _link;
}

/**
 * Wrapper for linkat(2). Enforces the following policy:
 *
 * PROCESS LEVEL | ACTION
 * ---------------------------------------------------------------------------
 * Create link. No need to check trusted or untrusted open() will do that.
 * ---------------------------------------------------------------------------
 */
sip_wrapper(int, linkat, int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags) {

	sip_info("Intercepted linkat call with olddir: %d, oldpath: %s, newdir: %d, newpath: %s\n", olddirfd, oldpath, newdirfd, newpath);

	_linkat = sip_find_sym("linkat");

	if(_linkat == -1 && errno == EACCES && SIP_IS_LOWI) {
		// TODO: SEND REQUEST TO DELEGATOR. UPDATE ERRNO/RV ON RESPONSE.
		// HOW TO DO THIS WITHOUT COPYING THE PIP SOLUTION ONE-FOR-ONE...?
		sip_info("Would delegate linkat on %s\n", olddirfd);
	}

	return _linkat;
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
 * NOTE: __xmknod is the name libc uses internally for mknod.
 */

sip_wrapper(int, __xmknod, int ver, const char *pathname, mode_t mode, dev_t *dev) {

	sip_info("Intercepted mknod call with path: %s, mode: %lu, dev: %lu\n", pathname, mode, dev);

	___xmknod = sip_find_sym("__xmknod");
	return ___xmknod(ver, pathname, mode, dev);
}

/**
 * Basic wrapper for mknodat(2). It logs the mknodat request, then invokes
 * glibc mknodat(2) with the given arguments.
 *
 * NOTE: __xmknodat is the name libc uses internally for mknod.
 */
sip_wrapper(int, __xmknodat, int ver, int dirfd, const char *pathname, mode_t mode, dev_t *dev) {

	sip_info("Intercepted mknodat call with dirfd: %d, path: %s, mode: %lu, dev: %lu\n", dirfd, pathname, mode, dev);

	___xmknodat = sip_find_sym("__xmknodat");
	return ___xmknodat(ver, dirfd, pathname, mode, dev);
}

/**
 * Wrapper for open(2). Enforces the following policy:
 *
 * PROCESS
 * ---------------------------------------------------------------------------
 * Call openat() to handle this syscall.
 * ---------------------------------------------------------------------------
 */

sip_wrapper(int, open, const char *__file, int __oflag, ...) {
	va_list args;

	mode_t mode = 0;

	/* Initialize variable argument list */
	va_start(args, __oflag);

	/* Mode only considered when flags includes O_CREAT or O_TMPFILE */
	if (__oflag & O_CREAT || __oflag & O_TMPFILE)
		mode = va_arg(args, mode_t);

	int res = openat(AT_FDCWD, __file, __oflag, mode);

	/* Destory va list */
	va_end(args);

	return res;
}

/**
 * Wrapper for open(2). Enforces the following policy:
 *
 * PROCESS LEVEL | ACTION
 * ---------------------------------------------------------------------------
 * HIGH          | Deny read/write access for low integrity files.
 * ---------------------------------------------------------------------------
 * LOW           | If request fails with errno == EACCES || EISDIR || ENOENT, 
 *				 | forward to delegator.
 * ---------------------------------------------------------------------------
 */

sip_wrapper(int, openat, int dirfd, const char * __file, int __oflag, ...) {
	va_list args;

	mode_t mode = 0;

	/* Initialize variable argument list */
	va_start(args, __oflag);

	/* Mode only considered when flags includes O_CREAT or O_TMPFILE */
	if (__oflag & O_CREAT || __oflag & O_TMPFILE)
		mode = va_arg(args, mode_t);

	sip_info("intercepted open call with file=%s, flags=%d, mode=%d\n", __file, __oflag, mode);

	/* NOTE: Check if the calling process is trusted or untrusted. If untrusted . */
	if(SIP_IS_HIGHI) {


		if(SIP_LV_LOW == sip_path_to_level(__file)) {
			sip_info("Denied read/write/exec permissions on low integrity file %s\n", __file);
			errno = EACCES;
			return -1;
		} 
	}
	/* Destory va list */
	va_end(args);

	_open = sip_find_sym("open");

	/* NOTE: If the calling process is trusted check to see if file exists if so then proceed 
			 with call. */
	if(_open == -1 && (errno == EACCES || errno == EISDIR || errno == ENOENT) && SIP_IS_LOWI) {
		// TODO: SEND REQUEST TO DELEGATOR. UPDATE ERRNO/RV ON RESPONSE.
		// HOW TO DO THIS WITHOUT COPYING THE PIP SOLUTION ONE-FOR-ONE...?
		sip_info("Would delegate openat on %s\n", __file);
	}
	return _open;
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

