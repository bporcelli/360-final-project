#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <errno.h>
#include "handlers.h"
#include "logger.h"
#include "level.h"

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
 */
void handle_faccessat(struct sip_request_faccessat *request, struct sip_response *response) {
	// TODO
}

/**
 * Handler for fchmodat.
 */
void handle_fchmodat(struct sip_request_fchmodat *request, struct sip_response *response) {
	// TODO
}

/**
 * Handler for fchownat.
 */
void handle_fchownat(struct sip_request_fchownat *request, struct sip_response *response) {
	// TODO
}

/**
 * Handler for fstatat.
 */
void handle_fstatat(struct sip_request_fstatat *request, struct sip_response *response) {
	// TODO
}

/**
 * Handler for statvfs.
 */
void handle_statvfs(struct sip_request_statvfs *request, struct sip_response *response) {
	// TODO
}

/**
 * Handler for linkat.
 */
void handle_linkat(struct sip_request_linkat *request, struct sip_response *response) {
	// TODO
}

/**
 * Handler for mkdirat.
 */
void handle_mkdirat(struct sip_request_mkdirat *request, struct sip_response *response) {
	// TODO
}

/**
 * Handler for mknodat.
 */
void handle_mknodat(struct sip_request_mknodat *request, struct sip_response *response) {
	// TODO
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
 */
void handle_renameat2(struct sip_request_renameat2 *request, struct sip_response *response) {
	// TODO
}

/**
 * Handler for symlinkat.
 */
void handle_symlinkat(struct sip_request_symlinkat *request, struct sip_response *response) {
	// TODO
}

/**
 * Handler for unlinkat.
 */
void handle_unlinkat(struct sip_request_unlinkat *request, struct sip_response *response) {
	// TODO
}

/**
 * Handler for utime.
 */
void handle_utime(struct sip_request_utime *request, struct sip_response *response) {
	// TODO
}

/**
 * Handler for utimes.
 */
void handle_utimes(struct sip_request_utimes *request, struct sip_response *response) {
	// TODO
}

/**
 * Handler for utimensat.
 */
void handle_utimensat(struct sip_request_utimensat *request, struct sip_response *response) {
	// TODO
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
