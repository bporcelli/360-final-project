#define _GNU_SOURCE // Needed to expose struct ucred; don't remove

#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/statfs.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <utime.h>
#include <fcntl.h>
#include <stdarg.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>

#include "wrappers.h"
#include "dlhelper.h"
#include "common.h"
#include "logger.h"
#include "level.h"
#include "util.h"
#include "redirect.h"
#include "bridge.h"
#include "packets.h"

// TODO: POSSIBLY ENABLE REDIRECTION IF WE HAVE TIME TO TEST

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

 	char *redirected_path = strdup(pathname), *temp_path;

 	if (redirected_path == NULL) {
 		sip_error("faccessat aborted: out of memory.\n");
 	   	return -1;
 	}

 	/* Redirect pathname before call if appropriate */
 	// if(SIP_LV_LOW) {
	// 		redirected_path = sip_convert_to_redirected_path(redirected_path);
	// }

	if (SIP_IS_HIGHI) {
		int read_or_exec = (mode & R_OK) || (mode & X_OK);

		if (SIP_LV_LOW == sip_path_to_level(redirected_path) && read_or_exec) {

			sip_info("Denied read/exec permissions on low integrity file %s\n", redirected_path);
			errno = EACCES;
			return -1;
		}
	}

	_faccessat = sip_find_sym("faccessat");

	int rv = _faccessat(dirfd, redirected_path, mode, flags);

	if (rv == -1 && errno == EACCES && SIP_IS_LOWI) {

		sip_info("Delegating faccessat on %s\n", redirected_path);

		temp_path = redirected_path;
		redirected_path = sip_abs_path(dirfd, redirected_path); /* to avoid passing dirfd to helper */
		free(temp_path);

		SIP_PREPARE_REQ(faccessat, request);
		
		strncpy(request.pathname, redirected_path, PATH_MAX);
		request.mode = mode;
		request.flags = flags;

		SIP_PREPARE_RES(response);		
		
		if (sip_delegate_call(&request, &response) == 0) {
			rv = response.rv;
			errno = response.err;
		}

		free(redirected_path);
	}

	return rv;
}

/**
 * Wrapper for access(2). Enforces the following policies:
 *
 * PROCESS LEVEL | ACTION
 * ---------------------------------------------------------------------------
 * Redirects to faccessat().
 * ---------------------------------------------------------------------------
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

 	char *redirected_path = strdup(pathname), *temp_path;

 	if (redirected_path == NULL) {
 		sip_error("fchmodat aborted: out of memory.\n");
 	   	return -1;
 	}

 	/* Redirect pathname before call if appropriate */
	// if (SIP_LV_LOW) {
 	// 		redirected_path = sip_convert_to_redirected_path(redirected_path);
	// }

	_fchmodat = sip_find_sym("fchmodat");
	
	int rv = _fchmodat(dirfd, redirected_path, mode, flags);

	if (rv == -1 && (errno == EACCES || errno == EPERM) && SIP_IS_LOWI) {

		sip_info("Delegating fchmodat on %s\n", redirected_path);

		temp_path = redirected_path;
		redirected_path = sip_abs_path(dirfd, redirected_path); /* to avoid passing dirfd to helper */
		free(temp_path);

		SIP_PREPARE_REQ(fchmodat, request);
		SIP_PREPARE_RES(response);
		strncpy(request.pathname, redirected_path, PATH_MAX);
		request.mode = mode;
		request.flags = flags;
		
		if (sip_delegate_call(&request, &response) == 0) {
			rv = response.rv;
			errno = response.err;
		}

		free(redirected_path);
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
	} 
	else if (sip_level_min(glevel, ulevel) < flevel && SIP_IS_LOWI) {
		sip_info("Blocked attempt to downgrade file %s\n", pathname);
		errno = EACCES;
		return -1;
	}

 	char *redirected_path = strdup(pathname), *temp_path;

 	if (redirected_path == NULL) {
 		sip_error("fchownat aborted: out of memory.\n");
 	   	return -1;
 	}

 	/* Redirect pathname before call if appropriate */
    //  if(SIP_LV_LOW) {
	// 		redirected_path = sip_convert_to_redirected_path(redirected_path);
	// 	}

	_fchownat = sip_find_sym("fchownat");

	int rv = _fchownat(dirfd, redirected_path, owner, group, flags);

	if (rv == -1 && (errno == EACCES || errno == EPERM) && SIP_IS_LOWI) {
		
		sip_info("Delegating fchownat on %s\n", redirected_path);

		temp_path = redirected_path;
		redirected_path = sip_abs_path(dirfd, redirected_path); /* to avoid passing dirfd to helper */
		free(temp_path);

		SIP_PREPARE_REQ(fchownat, request);
		SIP_PREPARE_RES(response);
		strncpy(request.pathname, redirected_path, PATH_MAX);
		request.owner = owner;
		request.group = group;
		request.flags = flags;
		
		if (sip_delegate_call(&request, &response) == 0) {
			rv = response.rv;
			errno = response.err;
		}

		free(redirected_path);
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
 * Wrapper for execve(2). Enforces the following policy:
 *
 * PROCESS LEVEL | ACTION
 * ---------------------------------------------------------------------------
 * HIGH          | Deny if file to be executed is untrusted.
 * ---------------------------------------------------------------------------
 */

sip_wrapper(int, execve, const char *filename, char *const argv[], char *const envp[]) {

	if (SIP_IS_HIGHI && SIP_LV_LOW == sip_path_to_level(filename)) {
		sip_info("Blocking attempt to execute low integrity file %s\n", filename);
		errno = EACCES;
		return -1;
	}

	_execve = sip_find_sym("execve");

	return _execve(filename, argv, envp);
}

/**
 * Wrapper for fstatat(2). Enforces the following policies:
 *
 * PROCESS LEVEL | ACTION
 * ---------------------------------------------------------------------------
 * LOW           | Convert path to redirected path if appropriate.
 * ---------------------------------------------------------------------------
 * LOW           | If request fails with errno EACCES, forward to delegator.
 * ---------------------------------------------------------------------------
 *
 * NOTE: __fxstatat is the name libc uses internally for fstatat.
 */
sip_wrapper(int, __fxstatat, int ver, int dirfd, const char *pathname, struct stat *statbuf, int flags) {

	sip_info("Intercepted fstatat call with dirfd: %d, path: %s, flags: %d\n", dirfd, pathname, flags);

 	char *redirected_path = strdup(pathname), *temp_path;

	if (redirected_path == NULL) {
		sip_error("__fxstatat aborted: out of memory.\n");
		return -1;
	}

 	/* Redirect pathname before call if appropriate */
    //  if(SIP_LV_LOW) {	
	// 		redirected_path = sip_convert_to_redirected_path(redirected_path);
	// 	}

	___fxstatat = sip_find_sym("__fxstatat");

	int rv = ___fxstatat(ver, dirfd, redirected_path, statbuf, flags);

	if (rv == -1 && errno == EACCES && SIP_IS_LOWI) {

		sip_info("Delegating __fxstatat on %s\n", redirected_path);

		temp_path = redirected_path;
		redirected_path = sip_abs_path(dirfd, redirected_path); /* to avoid passing dirfd to helper */
		free(temp_path);

		SIP_PREPARE_REQ(fstatat, request);
		SIP_PREPARE_RES(response);
		strncpy(request.pathname, redirected_path, PATH_MAX);
		request.flags = flags;
		
		if (sip_delegate_call(&request, &response) == 0) {
			rv = response.rv;
			errno = response.err;

			if (rv >= 0) { /* stat buf will be in response.buf */
				memcpy(statbuf, response.buf, sizeof(struct stat));
			}
		}

		free(redirected_path);
	}

	return rv;
}

/**
 * Wrapper for stat(2). Redirects to fstatat(2).
 *
 * NOTE: __xstat is the name libc uses internally for stat.
 */
sip_wrapper(int, __xstat, int ver, const char *pathname, struct stat *statbuf) {
	return __fxstatat(ver, AT_FDCWD, pathname, statbuf, 0);
}

/**
 * Wrapper for fstat(2). Redirects to fstatat(2).
 *
 * NOTE: __fxstat is the name libc uses internally for fstat.
 */

sip_wrapper(int, __fxstat, int ver, int fd, struct stat *statbuf) {
	char* path = sip_fd_to_path(fd);

	if (path == NULL)
		return -1;

	return __fxstatat(ver, AT_FDCWD, path, statbuf, 0);
}

/**
 * Wrapper for lstat(2). Redirects to fstatat(2).
 *
 * NOTE: __lxstat is the name libc uses internally for lstat.
 */

sip_wrapper(int, __lxstat, int ver, const char *pathname, struct stat *statbuf) {
	return __fxstatat(ver, AT_FDCWD, pathname, statbuf, AT_SYMLINK_NOFOLLOW);
}

/**
 * Wrapper for statvfs(3). Enforces the following process:
 *
 * PROCESS LEVEL | ACTION
 * ---------------------------------------------------------------------------
 * LOW           | Delegate if call fails due to lack of permissions.
 * ---------------------------------------------------------------------------
 */
sip_wrapper(int, statvfs, const char *path, struct statvfs *buf) {

	sip_info("Intercepted statvfs call with path: %s\n", path);
	
	/* Create copy of path we can modify */
	char* redirected_path = strdup(path), *temp_path;

	// if (SIP_IS_LOWI) {
	//		redirected_path = sip_convert_to_redirected_path(redirected_path); 
	// }

	_statvfs = sip_find_sym("statvfs");

    int res = _statvfs(redirected_path, buf);

	if (res == -1 && errno == EACCES && SIP_IS_LOWI) {
		
		sip_info("Delegating statvfs on %s\n", redirected_path);

		temp_path = redirected_path;
		redirected_path = sip_abs_path(AT_FDCWD, redirected_path); /* handle relative paths */
		free(temp_path);

		SIP_PREPARE_REQ(statvfs, request);
		SIP_PREPARE_RES(response);
		strncpy(request.path, redirected_path, PATH_MAX);
		
		if (sip_delegate_call(&request, &response) == 0) {
			res = response.rv;
			errno = response.err;

			if (res >= 0) { /* statvfs buf will be in response.buf */
				memcpy(buf, response.buf, sizeof(struct statvfs));
			}
		}

		free(redirected_path);
	}

	return res;
}

/**
 * Wrapper for fstatvfs(3). Enforces the following process:
 *
 * PROCESS LEVEL | ACTION
 * ---------------------------------------------------------------------------
 * ALL           | Forward to statvfs.
 * ---------------------------------------------------------------------------
 */
sip_wrapper(int, fstatvfs, int fd, struct statvfs *buf) {
	char* path = sip_fd_to_path(fd);

	if (path == NULL) {
		return -1;
	}

	int res = statvfs(path, buf);
	free(path);
	return res;
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

	int res = _linkat(olddirfd, oldpath, newdirfd, newpath, flags);

	if(res == -1 && errno == EACCES && SIP_IS_LOWI) {
		
		sip_info("Delegating linkat with oldpath %s, newpath %s\n", oldpath, newpath);

		/* convert paths to abs. paths to avoid passing dirfds */
		oldpath = sip_abs_path(olddirfd, oldpath);
		newpath = sip_abs_path(newdirfd, newpath);

		SIP_PREPARE_REQ(linkat, request);
		SIP_PREPARE_RES(response);
		strncpy(request.oldpath, oldpath, PATH_MAX);
		strncpy(request.newpath, newpath, PATH_MAX);
		request.flags = flags;
		
		if (sip_delegate_call(&request, &response) == 0) {
			res = response.rv;
			errno = response.err;	
		}
	}

	return res;
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
	return linkat(AT_FDCWD, oldpath, AT_FDCWD, newpath, AT_SYMLINK_FOLLOW);
}

/**
 * Wrapper for mkdirat(2). Enforces the following policy:
 *
 * PROCESS LEVEL | ACTION
 * ---------------------------------------------------------------------------
 * LOW           | Convert path to redirected path if appropriate.
 * ---------------------------------------------------------------------------
 * LOW           | If request fails with errno EACCES, forward to delegator.
 * ---------------------------------------------------------------------------
 */
sip_wrapper(int, mkdirat, int dirfd, const char *pathname, mode_t mode) {

	/* Create copy of pathname we can modify */
	char* redirected_path = strdup(pathname), *temp_path;

	// if (SIP_IS_LOWI) {
	// 		redirected_path = sip_convert_to_redirected_path(redirected_path);
	// }

	_mkdirat = sip_find_sym("mkdirat");
	
	int rv = _mkdirat(dirfd, redirected_path, mode);

	if (rv == -1 && errno == EACCES && SIP_IS_LOWI) {
		
		sip_info("Delegating mkdirat with path %s\n", redirected_path);

		temp_path = redirected_path;
		redirected_path = sip_abs_path(dirfd, redirected_path); /* handle relative paths */
		free(temp_path);

		SIP_PREPARE_REQ(mkdirat, request);
		SIP_PREPARE_RES(response);
		strncpy(request.pathname, redirected_path, PATH_MAX);
		request.mode = mode;
		
		if (sip_delegate_call(&request, &response) == 0) {
			rv = response.rv;
			errno = response.err;	
		}

		free(redirected_path);
	}

	return rv;
}

/**
 * Wrapper for mkdir(2). Enforces the following policies:
 *
 * PROCESS LEVEL | ACTION
 * ---------------------------------------------------------------------------
 * Redirects to mkdirat().
 * ---------------------------------------------------------------------------
 */
sip_wrapper(int, mkdir, const char *pathname, mode_t mode) {
	return mkdirat(AT_FDCWD, pathname, mode);
}

/**
 * Wrapper for mknodat(2). Enforces the following policy:
 *
 * PROCESS LEVEL | ACTION
 * ---------------------------------------------------------------------------
 * LOW           | Convert pathname to redirected path if appropriate.
 * ---------------------------------------------------------------------------
 * LOW           | Delegate to helper if call fails due to lack of permissions.
 * ---------------------------------------------------------------------------
 */
sip_wrapper(int, __xmknodat, int ver, int dirfd, const char *pathname, mode_t mode, dev_t *dev) {

	char* redirected_path = strdup(pathname), *temp_path;

	// if (SIP_IS_LOWI) {
	// 	redirected_path = sip_get_redirected_path(redirected_path);
	// }

	___xmknodat = sip_find_sym("__xmknodat");

	int rv = ___xmknodat(ver, dirfd, redirected_path, mode, dev);

	if (rv == -1 && (errno == EACCES || errno == EPERM) && SIP_IS_LOWI) {
		
		sip_info("Delegating __xmknodat with path %s\n", redirected_path);

		temp_path = redirected_path;
		redirected_path = sip_abs_path(dirfd, redirected_path); /* handle relative paths */
		free(temp_path);

		SIP_PREPARE_REQ(mknodat, request);
		SIP_PREPARE_RES(response);
		strncpy(request.pathname, redirected_path, PATH_MAX);
		request.mode = mode;

		/* dev parameter only used when type is S_IFCHR or S_IFBLK */
		if ((mode & S_IFCHR) || (mode & S_IFBLK)) {
			memcpy(&request.dev, dev, sizeof(dev_t));
		}
		
		if (sip_delegate_call(&request, &response) == 0) {
			rv = response.rv;
			errno = response.err;	
		}

		free(redirected_path);
	}

	return rv;
}

/**
 * Wrapper for mknod(2). Redirects to mknodat(2).
 *
 * NOTE: __xmknod is the name libc uses internally for mknod.
 */

sip_wrapper(int, __xmknod, int ver, const char *pathname, mode_t mode, dev_t *dev) {
	return __xmknodat(ver, AT_FDCWD, pathname, mode, dev);
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

	sip_info("intercepted openat call with file=%s, flags=%d, mode=%d\n", __file, __oflag, mode);

	/* If a high integrity process tries to open a low integrity file, deny */
	if(SIP_IS_HIGHI) {

		if(SIP_LV_LOW == sip_path_to_level(__file)) {
			sip_info("Denied read/write/exec permissions on low integrity file %s\n", __file);
			errno = EACCES;
			return -1;
		}
	}

	/* Destory va list */
	va_end(args);

	_openat = sip_find_sym("openat");

	int res = _openat(dirfd, __file, __oflag, mode);

	/* If process is low integrity and request fails due to lack of permissions,
	   delegate to helper. */
	if(res == -1 && (errno == EACCES || errno == EPERM) && SIP_IS_LOWI) {
		
		sip_info("Delegating openat on %s\n", __file);

		char* abspath = sip_abs_path(dirfd, __file); /* to avoid passing dirfd to helper */

		SIP_PREPARE_REQ(openat, request);
		
		strncpy(request.file, abspath, PATH_MAX);
		request.mode = mode;
		request.flags = __oflag;

		SIP_PREPARE_RES(response);

		if (sip_delegate_call_fd(&request, &response) == 0) {
			res = response.rv;
			errno = response.err;
		}

		free(abspath); /* dynamically allocated by sip_abs_path */
	}

	return res;
}

/**
 * Wrapper for readlinkat(2). Enforces the following policy:
 *
 * PROCESS LEVEL | ACTION
 * ---------------------------------------------------------------------------
 * LOW           | Redirect pathname before call if necessary.
 * ---------------------------------------------------------------------------
 * ALL           | Convert redirected pathname to original pathname.
 * ---------------------------------------------------------------------------
 */
sip_wrapper(ssize_t, readlinkat, int dirfd, const char *pathname, char *buf, size_t bufsiz) {

    sip_info("Intercepted readlinkat call with dirfd: %d, pathname: %s, bufsiz: %lu\n", dirfd, pathname, bufsiz);

    /* To avoid compiler warnings, created a copy of pathname we can modify */
    char *redirected_path = strdup(pathname);

    if (redirected_path == NULL) {
    	sip_error("readlinkat aborted: out of memory.\n");
    	return -1;
    }

    /* Redirect pathname before call if appropriate */
 	// if(SIP_LV_LOW) {
	// 	redirected_path = sip_convert_to_redirected_path(redirected_path);
	// }

    _readlinkat = sip_find_sym("readlinkat");

    int res = _readlinkat(dirfd, redirected_path, buf, bufsiz);
    
    free(redirected_path); 	/* clean up after strdup */

    if(res > 0 && sip_is_redirected(buf)) {
    	char* orig_path = sip_revert_path(buf);
    	strncpy(buf, orig_path, bufsiz);
    	return strlen(orig_path) - 1; 	/* exclude null terminator */
    }

    return res;
}

/**
 * Wrapper for readlink(2). Redirects to readlinkat.
 */
sip_wrapper(ssize_t, readlink, const char *pathname, char *buf, size_t bufsiz) {
    return readlinkat(AT_FDCWD, pathname, buf, bufsiz);
}

/**
 * Wrapper for renameat2(2). Enforces the following policy:
 *
 * PROCESS LEVEL | ACTION
 * ---------------------------------------------------------------------------
 * LOW           | Delegate to helper if request fails due to permissions.
 * ---------------------------------------------------------------------------
 */
// sip_wrapper(int, renameat2, int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags) {

//     sip_info("Intercepted renameat2 call with olddirfd: %s, oldpath: %s, newdirfd: %d, newpath: %s, flags: %d\n", 
//     	olddirfd, oldpath, newdirfd, newpath, flags);

// 	_renameat2 = sip_find_sym("renameat2");

// 	int res = _renameat2(olddirfd, oldpath, newdirfd, newpath, flags);

// 	if(res == -1 && errno == EACCES && SIP_IS_LOWI) {
		
// 		sip_info("Delegating renameat2 with oldpath %s, newpath %s\n", oldpath, newpath);

// 		/* convert paths to abs. paths to avoid passing dir fds */
// 		char* oldpathfull = sip_abs_path(olddirfd, oldpath);
// 		char* newpathfull = sip_abs_path(newdirfd, newpath);

// 		SIP_PREPARE_REQ(renameat2, request);
// 		SIP_PREPARE_RES(response);
// 		strncpy(request.oldpath, oldpathfull, PATH_MAX);
// 		strncpy(request.newpath, newpathfull, PATH_MAX);
// 		request.flags = flags;
		
// 		if (sip_delegate_call(&request, &response) == 0) {
// 			res = response.rv;
// 			errno = response.err;	
// 		}

// 		free(oldpathfull);
// 		free(newpathfull);
// 	}

// 	return res;
// }

/**
 * Wrapper for renameat(2). Enforces the following policy:
 *
 * PROCESS LEVEL | ACTION
 * ---------------------------------------------------------------------------
 * Redirects to renameat2()
 * ---------------------------------------------------------------------------
 */
// sip_wrapper(int, renameat, int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
//     return renameat2(olddirfd, oldpath, newdirfd, newpath, 0);
// }

/**
 * Basic wrapper for rename(2). It logs the rename(2) request, then invokes
 * glibc rename with the given argument.
 *
 * PROCESS LEVEL | ACTION
 * ---------------------------------------------------------------------------
 * Redirects to renameat2()
 * ---------------------------------------------------------------------------
 */
// sip_wrapper(int, rename, const char *oldpath, const char *newpath) {
//     return renameat2(AT_FDCWD, oldpath, AT_FDCWD, newpath, 0);
// }

/**
 * Wrapper for rmdir(2). Enforces the following policy:
 *
 * PROCESS LEVEL | ACTION
 * ---------------------------------------------------------------------------
 * High 		 | Allow rmdir to execute with original path
 * ---------------------------------------------------------------------------
 * Low 		 	 | Change the pathname to point to the correct dir in the 
 * 			 	 | /tmp folder that we created.
 * ---------------------------------------------------------------------------
 */
sip_wrapper(int, rmdir, const char *pathname) {

	sip_info("Intercepted rmdir call with path: %s\n", pathname);

    // if (SIP_LV_LOW) {
	//	pathname = sip_convert_to_redirected_path(pathname); 
	// }

    _rmdir = sip_find_sym("rmdir");

    return _rmdir(pathname);
}

/**
 * Wrapper for symlinkat(2). Enforces the following policy:
 *
 * PROCESS LEVEL | ACTION
 * ---------------------------------------------------------------------------
 * Create the link if low integrity delegate.
 * ---------------------------------------------------------------------------
 */
sip_wrapper(int, symlinkat, const char *target, int newdirfd, const char *linkpath) {

	sip_info("Intercepted symlinkat call with target: %s, newdirfd: %d, linkpath: %s\n", target, newdirfd, linkpath);

    _symlinkat = sip_find_sym("symlinkat");

    int res = _symlinkat(target, newdirfd, linkpath);

    if (res == -1 && errno == EACCES && SIP_IS_LOWI) {
		
		sip_info("Delegating symlinkat with target %s, linkpath %s\n", target, linkpath);

		char* linkpathfull = sip_abs_path(newdirfd, linkpath); /* handle rel. paths */

		SIP_PREPARE_REQ(symlinkat, request);
		SIP_PREPARE_RES(response);
		strncpy(request.target, target, PATH_MAX);
		strncpy(request.linkpath, linkpathfull, PATH_MAX);
		
		if (sip_delegate_call(&request, &response) == 0) {
			res = response.rv;
			errno = response.err;	
		}

		free(linkpathfull);
	}

    return res;
}

/**
 * Wrapper for symlink(2). Enforces the following policy:
 *
 * PROCESS LEVEL | ACTION
 * ---------------------------------------------------------------------------
 * Redirect call to symlinkat
 * ---------------------------------------------------------------------------
 */
sip_wrapper(int, symlink, const char *target, const char *linkpath) {
    return symlinkat(target, AT_FDCWD, linkpath);
}

/**
 * Wrapper for unlinkat(2). Enforces the following policy:
 *
 * PROCESS LEVEL | ACTION
 * ---------------------------------------------------------------------------
 * High 		 | Send original pathname
 * ---------------------------------------------------------------------------
 * Low 			 | Alter the pathname so it points to the correct file in the 
 * 				 | /tmp/ folder. If request fails due to lack of permissions,
 *               | delegate.
 * ---------------------------------------------------------------------------
 */
sip_wrapper(int, unlinkat, int dirfd, const char *pathname, int flags) {

	sip_info("Intercepted unlinkat call with dirfd: %d, path: %s, flags: %d\n", dirfd, pathname, flags);

 	// if (SIP_LV_LOW) {
	// 	pathname = sip_convert_to_redirected_path(pathname); 
	// }

    _unlinkat = sip_find_sym("unlinkat");

    int res = _unlinkat(dirfd, pathname, flags);

    if (res == -1 && (errno == EACCES || errno == EPERM) && SIP_IS_LOWI) {

		sip_info("Delegating unlinkat with pathname %s\n", pathname);

		char* abspathname = sip_abs_path(dirfd, pathname); /* handle rel. paths */

		SIP_PREPARE_REQ(unlinkat, request);
		SIP_PREPARE_RES(response);
		strncpy(request.pathname, abspathname, PATH_MAX);
		request.flags = flags;
		
		if (sip_delegate_call(&request, &response) == 0) {
			res = response.rv;
			errno = response.err;	
		}

		free(abspathname);
    }

    return res;
}

/**
 * Wrapper for unlink(2). Enforces the following policy:
 *
 * PROCESS LEVEL | ACTION
 * ---------------------------------------------------------------------------
 * Call unlinkat() to process.
 * ---------------------------------------------------------------------------
 */
sip_wrapper(int, unlink, const char *pathname) {
    return unlinkat(AT_FDCWD, pathname, 0);
}

/**
 * Wrapper for utime(2). Enforces the following policy:
 *
 * PROCESS LEVEL | ACTION
 * ---------------------------------------------------------------------------
 * LOW           | Convert path to redirected path if appropriate.
 * ---------------------------------------------------------------------------
 * LOW           | If request fails with errno EACCES or EPERM, forward to delegator.
 * ---------------------------------------------------------------------------
 */
sip_wrapper(int, utime, const char *path, const struct utimbuf *times) {

	// if (SIP_IS_LOWI) {
	//	path = sip_get_redirected_path(path);
	// }

    _utime = sip_find_sym("utime");

    int rv = _utime(path, times);

    if (rv == -1 && (errno == EACCES || errno == EPERM) && SIP_IS_LOWI) {
    	
    	sip_info("Delegating utime with path %s\n", path);

		char* pathfull = sip_abs_path(AT_FDCWD, path); /* handle rel. paths */

		SIP_PREPARE_REQ(utime, request);
		SIP_PREPARE_RES(response);
		strncpy(request.path, pathfull, PATH_MAX);
		memcpy(&request.times, times, sizeof(struct utimbuf));
		
		if (sip_delegate_call(&request, &response) == 0) {
			rv = response.rv;
			errno = response.err;	
		}

		free(pathfull);
    }

    return rv;
}

/**
 * Wrapper for utimes(2). Enforces the following policy:
 *
 * PROCESS LEVEL | ACTION
 * ---------------------------------------------------------------------------
 * LOW           | Convert path to redirected path if appropriate.
 * ---------------------------------------------------------------------------
 * LOW           | If request fails with errno EACCES or EPERM, forward to delegator.
 * ---------------------------------------------------------------------------
 */
sip_wrapper(int, utimes, const char *filename, const struct timeval times[2]) {
	
	// if (SIP_IS_LOWI) {
	// 	filename = sip_convert_to_redirected_path(filename);
	// }

    _utimes = sip_find_sym("utimes");

    int rv = _utimes(filename, times);

    if (rv == -1 && (errno == EACCES || errno == EPERM) && SIP_IS_LOWI) {
    	
    	sip_info("Delegating utimes with filename %s\n", filename);

		char* filenamefull = sip_abs_path(AT_FDCWD, filename); /* handle rel. paths */

		SIP_PREPARE_REQ(utimes, request);
		SIP_PREPARE_RES(response);
		strncpy(request.filename, filenamefull, PATH_MAX);
		memcpy(&request.times, times, 2 * sizeof(struct timeval));
		
		if (sip_delegate_call(&request, &response) == 0) {
			rv = response.rv;
			errno = response.err;	
		}

		free(filenamefull);
    }

    return rv;
}

/**
 * Wrapper for utimensat(2). Enforces the following policy:
 *
 * PROCESS LEVEL | ACTION
 * ---------------------------------------------------------------------------
 * LOW           | Convert path to redirected path if appropriate.
 * ---------------------------------------------------------------------------
 * LOW           | If request fails with errno EACCES or EPERM, forward to delegator.
 * ---------------------------------------------------------------------------
 */
sip_wrapper(int, utimensat, int dirfd, const char *pathname, const struct timespec times[2], int flags) {

	// if (SIP_IS_LOWI) {
	// 	pathname = sip_get_redirected_path(pathname);
	// }

    _utimensat = sip_find_sym("utimensat");

    int rv = _utimensat(dirfd, pathname, times, flags);

    if (rv == -1 && (errno == EACCES || errno == EPERM) && SIP_IS_LOWI) {
    	
    	sip_info("Delegating utimensat with pathname %s\n", pathname);

		char* pathnamefull = sip_abs_path(dirfd, pathname); /* handle rel. paths */

		SIP_PREPARE_REQ(utimensat, request);
		SIP_PREPARE_RES(response);
		strncpy(request.pathname, pathnamefull, PATH_MAX);
		memcpy(&request.times, times, 2 * sizeof(struct timespec));
		request.flags = flags;
		
		if (sip_delegate_call(&request, &response) == 0) {
			rv = response.rv;
			errno = response.err;	
		}

		free(pathnamefull);
    }

    return rv;
}

/**
 * Wrapper for futimens(2). Enforces the following policy:
 *
 * PROCESS LEVEL | ACTION
 * ---------------------------------------------------------------------------
 * LOW           | Convert path to redirected path if appropriate.
 * ---------------------------------------------------------------------------
 * LOW           | If request fails with errno EACCES or EPERM, forward to delegator.
 * ---------------------------------------------------------------------------
 */
sip_wrapper(int, futimens, int fd, const struct timespec times[2]) {

    _futimens = sip_find_sym("futimens");

    int rv = _futimens(fd, times);

    if (rv == -1 && (errno == EACCES || errno == EPERM) && SIP_IS_LOWI) {
    	
    	sip_info("Delegating futimens with descriptor %d\n", fd);

    	/* NOTE: glibc uses utimensat internally to implement this call.
    	   We convert to an equivalent utimensat call here so as to avoid
    	   passing the fd to the helper. */
    	char* pathname = sip_fd_to_path(fd);

  		// if (SIP_IS_LOWI) {
  		//  char* temp_path = pathname;
		// 	pathname = sip_convert_to_redirected_path(pathname);
		// 	free(temp_path);
		// }

    	if (pathname != NULL) {
    		
    		SIP_PREPARE_REQ(utimensat, request);
			SIP_PREPARE_RES(response);
			strncpy(request.pathname, pathname, PATH_MAX);
			memcpy(&request.times, times, 2 * sizeof(struct timespec));
			request.flags = 0;
			
			if (sip_delegate_call(&request, &response) == 0) {
				rv = response.rv;
				errno = response.err;	
			}

    		free(pathname);
    	}
    }

    return rv;
}

/**
 * Wrapper for bind(2). Enforces the following policy: 
 *
 * PROCESS LEVEL | ACTION
 * ---------------------------------------------------------------------------
 * LOW           | For UNIX domain sockets, delegate if bind request fails with
 *               | errno EACCES.
 * ---------------------------------------------------------------------------
 */
sip_wrapper(int, bind, int sockfd, const struct sockaddr *addr, socklen_t addrlen) {

    _bind = sip_find_sym("bind");

    int rv = _bind(sockfd, addr, addrlen);

    if (rv == -1 && errno == EACCES && SIP_IS_LOWI) {
    	
    	if (addr->sa_family == AF_LOCAL) { /* AF_LOCAL = AF_UNIX = PF_LOCAL... */
			
			sip_info("Delegating bind with sockfd %s\n", sockfd);

			/* NOTE: the sockfd is not passed to the helper. It is expected that
			   the helper creates a new socket, binds it to the given address,
			   and returns the descriptor for the new socket. */
			SIP_PREPARE_REQ(bind, request);
			SIP_PREPARE_RES(response);
			memcpy(&request.addr, addr, sizeof(struct sockaddr));
			request.addrlen = addrlen;

			/* Need to set socktype so server can create socket of appropriate
			   type. Query using getsockopt. */
			int socktype, optlen = sizeof(int);		

			if (getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &socktype, &optlen) < 0) {
				sip_error("Couldn't get socket type for %d -- aborting.\n", sockfd);
				errno = EACCES;
				return -1;
			}

			request.socktype = socktype;
			
			if (sip_delegate_call_fd(&request, &response) == 0) {
				rv = response.rv;
				errno = response.err;

				if (rv >= 0) { /* copy newsockfd to sockfd, close newsockfd */
					dup2(rv, sockfd);
					close(rv);
					rv = 0;
				}
			}
	    }
    }
 
    return rv;
}

/**
 * Wrapper for connect(2). Enforces the following policy: 
 *
 * PROCESS LEVEL | ACTION
 * ---------------------------------------------------------------------------
 * LOW           | For UNIX domain sockets identified by a pathname, delegate 
 *               | if request fails with errno EACCES.
 * ---------------------------------------------------------------------------
 */
sip_wrapper(int, connect, int sockfd, const struct sockaddr *addr, socklen_t addrlen) {

    _connect = sip_find_sym("connect");

    int rv = _connect(sockfd, addr, addrlen);

    if (rv == -1 && errno == EACCES && SIP_IS_LOWI) {
    	
    	if (addr->sa_family == AF_LOCAL && sip_is_named_sock(addr, addrlen)) {
    		
    		sip_info("Delegating connect with sockfd %s\n", sockfd);

			/* NOTE: the sockfd is not passed to the helper. It is expected that
			   the helper creates a new socket, connects it to the given address,
			   and returns the descriptor for the new socket. */
			SIP_PREPARE_REQ(connect, request);
			SIP_PREPARE_RES(response);
			memcpy(&request.addr, addr, sizeof(struct sockaddr));
			request.addrlen = addrlen;
			
			/* Need to set socktype so server can create socket of appropriate
			   type. Query using getsockopt. */
			int socktype, optlen = sizeof(int);

			if (getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &socktype, &optlen) < 0) {
				sip_error("Couldn't get socket type for %d -- aborting.\n", sockfd);
				errno = EACCES;
				return -1;
			}

			request.socktype = socktype;

			if (sip_delegate_call_fd(&request, &response) == 0) {
				rv = response.rv;
				errno = response.err;

				if (rv >= 0) { /* copy newsockfd to sockfd, close newsockfd */
					dup2(rv, sockfd);
					close(rv);
					rv = 0;
				}
			}
    	}
    }

    return rv;
}

/**
 * Wrapper for accept4(2). Enforces the following policy:
 *
 * PROCESS LEVEL | ACTION
 * ---------------------------------------------------------------------------
 * ALL           | Restrict call if current process is not the daemon and the
 *               | peer integrity levels don't match.
 * ---------------------------------------------------------------------------
 */
sip_wrapper(int, accept4, int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags) {

    _accept4 = sip_find_sym("accept4");

    int newfd = _accept4(sockfd, addr, addrlen, flags);

    /* SO_PEERCRED only available for UNIX domain sockets -- don't check
     * peer creds for sockets with other domains. */
    if (newfd >= 0 && addr->sa_family == AF_LOCAL) {
    	
    	struct ucred peercreds;
    	socklen_t optlen = sizeof(struct ucred);

    	int getres = getsockopt(newfd, SOL_SOCKET, SO_PEERCRED, 
    							&peercreds, &optlen);

    	/* If we can't get the peer credentials, deny (safe default). */
    	if (getres == -1) {
    		goto deny;
    	}

    	/* If current process is daemon, allow regardless of the level of the
    	 * peer. Otherwise, deny if levels don't match. */
    	int peerlevel = sip_level_min(sip_uid_to_level(peercreds.uid),
    								  sip_gid_to_level(peercreds.gid));

    	if (sip_is_daemon() || peerlevel == sip_level()) {
    		sip_info("Allowing accept4 on socket %d: peer levels match.\n", newfd);
    		goto allow;
    	}

deny:
		sip_info("Denying accept4 on socket %d: peer levels do not match.", newfd);

		close(newfd);
		errno = ECONNABORTED;
		return -1;
    }

allow:
    return newfd;
}

/**
 * Wrapper for accept(2). Redirects to accept4(2).
 */
sip_wrapper(int, accept, int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
	return accept4(sockfd, addr, addrlen, 0);
}

/**
 * Wrapper for msgget(2). Enforces the following policy:
 *
 * PROCESS LEVEL | ACTION
 * ---------------------------------------------------------------------------
 * ALL           | Restrict if integrity level of current process and message
 *               | queue creator differ.
 * ---------------------------------------------------------------------------
 */
sip_wrapper(int, msgget, key_t key, int msgflg) {
	_msgget = sip_find_sym("msgget");

	int msgid = _msgget(key, msgflg);

	if (msgid >= 0) {
		struct msqid_ds msq;

		int statres = msgctl(msgid, IPC_STAT, &msq);

		if (statres == -1) {
			sip_info("Denying msgget request: failed to get peer credentials.\n");
			errno = EACCES;
			return -1;
		}

		int ulevel = sip_uid_to_level(msq.msg_perm.cuid);
		int glevel = sip_gid_to_level(msq.msg_perm.cgid);

		if (sip_level() != sip_level_min(ulevel, glevel)) {
			sip_info("Denying msgget request: peer integrity levels don't match.\n");
			errno = EACCES;
			return -1;
		}
	}

	return msgid;
}

/**
 * Wrapper for shmget(2). Enforces the following policy:
 *
 * PROCESS LEVEL | ACTION
 * ---------------------------------------------------------------------------
 * ALL           | Restrict if integrity level of current process and message
 *               | queue creator differ.
 * ---------------------------------------------------------------------------
 */
sip_wrapper(int, shmget, key_t key, size_t size, int shmflg) {
	_shmget = sip_find_sym("shmget");

	int shmid = _shmget(key, size, shmflg);

	if (shmid >= 0) {
		struct shmid_ds shm;

		int statres = shmctl(shmid, IPC_STAT, &shm);

		if (statres == -1) {
			sip_info("Denying shmget request: failed to get peer credentials.\n");
			errno = EACCES;
			return -1;
		}

		int ulevel = sip_uid_to_level(shm.shm_perm.cuid);
		int glevel = sip_gid_to_level(shm.shm_perm.cgid);

		if (sip_level() != sip_level_min(ulevel, glevel)) {
			sip_info("Denying shmget request: peer integrity levels don't match.\n");
			errno = EACCES;
			return -1;
		}
	}

	return shmid;
}
