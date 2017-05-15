#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <utime.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include "handlers.h"
#include "logger.h"
#include "level.h"
#include "common.h"

/**
 * Handler for SYS_delegatortest. Simply sets the return value to 0
 * and sets errno to the given value.
 */
void handle_delegatortest(struct sip_request_test *request, struct sip_response *response) {
	response->rv = 0;
	response->err = request->err;
}

/**
 * Handler for faccessat.
 *
 * Policy: Deny write access on high integrity files.
 */
void handle_faccessat(struct sip_request_faccessat *request, struct sip_response *response) {
	if (SIP_LV_HIGH == sip_path_to_level(request->pathname) && (request->mode & W_OK)) {
		response->rv = -1;
		response->err = EACCES;
		return;
	}
	
	response->rv = faccessat(AT_FDCWD, request->pathname, request->mode, request->flags);
	response->err = errno;
}

/**
 * Handler for fchmodat.
 *
 * Policy: If the target file is high integrity and can be downgraded, allow the operation
 * to proceed. Otherwise, block it.
 */
void handle_fchmodat(struct sip_request_fchmodat *request, struct sip_response *response) {

	struct stat sbuf;

	if (stat(request->pathname, &sbuf) < 0) {
		sip_error("Failed to stat %s.\n", request->pathname);
		
		response->rv = -1;
		response->err = EACCES;
		return;
	}

	/* If file is high integrity but can't be downgraded, don't proceed. */
	int high_level = SIP_LV_HIGH == sip_path_to_level(request->pathname);
	
	if (high_level && !sip_can_downgrade_buf(&sbuf)) {
		sip_error("Can't downgrade %s: blocking fchmodat.\n");

		response->rv = -1;
		response->err = EACCES;
		return;
	}

	/* If file is high integrity, downgrade before change. */
	gid_t orig_group = sbuf.st_gid;

	if (high_level) {
		if (lchown(request->pathname, -1, SIP_UNTRUSTED_USERID) < 0) {
			sip_error("Couldn't lchown %s: aborting.\n", request->pathname);

			response->rv = -1;
			response->err = EACCES;
			return;
		}
	}

	/* Perform operation. */
	response->rv = fchmodat(AT_FDCWD, request->pathname, request->mode, request->flags);
	response->err = errno;

	/* If failure and file was high integrity, restore original integrity label. */
	if (response->rv == -1 && high_level) {
		lchown(request->pathname, -1, orig_group);
	}
}

/**
 * Handler for fchownat.
 *
 * Policy: Deny calls where the target is a high integrity file. Prevent changes in integrity
 * label.
 */
void handle_fchownat(struct sip_request_fchownat *request, struct sip_response *response) {
	
	int orig_level = sip_path_to_level(request->pathname);

	/* If target file is benign, deny outright. */
	if (SIP_LV_HIGH == orig_level) {
		response->rv = -1;
		response->err = EACCES;
		return;
	}

	/* If the new integrity label doesn't match the original integrity label,
	   deny. */
	int olevel = sip_uid_to_level(request->owner);
	int glevel = sip_gid_to_level(request->group);

	if (sip_level_min(olevel, glevel) != orig_level) { /* Integrity label would change! */
		response->rv = -1;
		response->err = EACCES;
		return;
	}

	response->rv = fchownat(AT_FDCWD, request->pathname, request->owner, request->group, request->flags);
	response->err = errno;
}

/**
 * Handler for fstatat.
 *
 * Policy: Simply perform the operation with the trusted user's credentials and return
 * the result.
 */
void handle_fstatat(struct sip_request_fstatat *request, struct sip_response *response) {

	struct stat sbuf;

	response->rv = fstatat(AT_FDCWD, request->pathname, &sbuf, request->flags);
	response->err = errno;

	/* If successful, we need to copy the stat buf into response->buf */
	if (response->rv == 0) {
		memcpy(&response->buf, &sbuf, sizeof(struct stat));
	}
}

/**
 * Handler for statvfs.
 *
 * Policy: Simply perform the operation with the trusted user's credentials and
 * return the result.
 */
void handle_statvfs(struct sip_request_statvfs *request, struct sip_response *response) {
	
	struct statvfs sbuf;

	response->rv = statvfs(request->path, &sbuf);
	response->err = errno;

	/* If successful, copy buf to response->buf */
	if (response->rv == 0) {
		memcpy(&response->buf, &sbuf, sizeof(struct statvfs));
	}
}

/**
 * Handler for linkat.
 *
 * Policy: Deny if oldpath is high integrity.
 */
void handle_linkat(struct sip_request_linkat *request, struct sip_response *response) {
	
	if (SIP_LV_HIGH == sip_path_to_level(request->oldpath)){
		response->rv = -1;
		response->err = EACCES;
		return;
	}
	
	response->rv = linkat(AT_FDCWD, request->oldpath, AT_FDCWD, request->newpath, request->flags);
	response->err = errno;
}

/**
 * Handler for mkdirat.
 *
 * Policy: Carry out operation with trusted credentials and return result.
 */
void handle_mkdirat(struct sip_request_mkdirat *request, struct sip_response *response) {
	response->rv = mkdirat(AT_FDCWD, request->pathname, request->mode);
	response->err = errno;
}

/**
 * Handler for mknodat.
 *
 * Policy: Carry out policy with trusted credentials and return result.
 */
void handle_mknodat(struct sip_request_mknodat *request, struct sip_response *response) {
	response->rv = mknodat(AT_FDCWD, request->pathname, request->mode, request->dev);
	response->err = errno;
}

/**
 * Handler for openat.
 *
 * Policy: Deny requests to write high integrity files. Allow all other
 * requests.
 */
void handle_openat(struct sip_request_openat *request, struct sip_response *response) {
	int writing = (request->flags & O_RDWR) || (request->flags & O_WRONLY);

	if (SIP_LV_HIGH == sip_path_to_level(request->file) && writing) {
		response->rv = -1;
		response->err = EACCES;
		return;
	}

	response->rv = open(request->file, request->flags, request->mode);
	response->err = errno;
}

/**
 * Handler for renameat2.
 *
 * Policy: Allow rename operation if the file is untrusted.
 */
void handle_renameat2(struct sip_request_renameat2 *request, struct sip_response *response) {
	if (SIP_LV_HIGH == sip_path_to_level(request->oldpath)) {
		response->rv = -1;
		response->err = EACCES;
		return;
	}

	response->rv = syscall(SYS_renameat2, AT_FDCWD, request->oldpath, AT_FDCWD, request->newpath, request->flags);
	response->err = errno;
}

/**
 * Handler for symlinkat.
 */
void handle_symlinkat(struct sip_request_symlinkat *request, struct sip_response *response) {
	// If target is high integrity, deny (prevents creating very long chains for TOCTTOU attacks)
	if (sip_path_to_level(request->target) == SIP_LV_HIGH) {
		response->rv = -1;
		response->err = EACCES; // Write access is denied error
		return;
	}
	// Else, allow
	response->rv = symlinkat(request->target, AT_FDCWD, request->linkpath);
	response->err = errno;
}

/**
 * Handler for unlinkat.
 */
void handle_unlinkat(struct sip_request_unlinkat *request, struct sip_response *response) {
	// If target is high integrity, deny
	if (sip_path_to_level(request->pathname) == SIP_LV_HIGH) {
		response->rv = -1;
		response->err = EBADF; // Error for invalid FD
		return;
	}
	// Otherwise, allow
	response->rv = unlinkat(AT_FDCWD, request->pathname, request->flags);
	response->err = errno;
}

/**
 * Handler for utime.
 */
void handle_utime(struct sip_request_utime *request, struct sip_response *response) {
	// No private copies of files are made and this syscall will always write, so allow it
	response->rv = utime(request->path, &request->times);
	response->err = errno;
}

/**
 * Handler for utimes.
 */
void handle_utimes(struct sip_request_utimes *request, struct sip_response *response) {
	// No private copies of files are made and this syscall will always write, so allow it
	response->rv = utimes(request->filename, request->times);
	response->err = errno;
}

/**
 * Handler for utimensat.
 */
void handle_utimensat(struct sip_request_utimensat *request, struct sip_response *response) {
	// No private copies of files are made and this syscall will always write, so allow it
	response->rv = utimensat(AT_FDCWD, request->pathname, request->times, request->flags);
	response->err = errno;
}

/**
 * Handler for bind. Note that the client side expects this handler to create a NEW
 * socket, bind it to the given address, and return the new socket's descriptor.
 *
 * NOTE: Bind requests are only delegated when the socket family is AF_UNIX. Therefore,
 * we assume AF_UNIX when creating the socket.
 */
void handle_bind(struct sip_request_bind *request, struct sip_response *response) {
	int newfd = socket(AF_UNIX, request->socktype, 0);

	if (newfd == -1) {
		response->rv = -1;
		response->err = EACCES;
		return;
	}

	/* Bind to given address */
	response->rv = bind(newfd, &request->addr, request->addrlen);
	response->err = errno;

	if (response->rv == 0) {
		response->rv = newfd; /* new fd expected on success */
		response->err = 0;
	}

	/* Set permissions so that others can't write to the socket */
	if (fchmod(newfd, S_IRWXU|S_IRWXG|S_IROTH|S_IXOTH) < 0) {
		sip_warning("Failed to chmod socket with descriptor %d\n", newfd);
	}
}

/**
 * Handler for connect. Note that the client side expects this handler to create a NEW
 * socket, connect it to the given address, and return the new socket's descriptor.
 */
void handle_connect(struct sip_request_connect *request, struct sip_response *response) {
	int newfd = socket(AF_UNIX, request->socktype, 0);

	if (newfd == -1) {
		response->rv = -1;
		response->err = EACCES;
		return;
	}

	/* Connect to given address */
	response->rv = connect(newfd, &request->addr, request->addrlen);
	response->err = errno;

	if (response->rv == 0) {
		response->rv = newfd; /* new fd expected on success */
		response->err = 0;
	}
}
