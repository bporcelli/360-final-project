#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "util.h"
#include "logger.h"
#include "level.h"
#include "common.h"

/**
 * Resolve the given link to a pathname and return it in an appropriately
 * sized dynamically allocated buffer.
 *
 * @param char* linkname
 * @return Pointer to resolved path name, or NULL on error.
 */
static char* sip_readlink(char* linkname) {
	char resolved_path[PATH_MAX];
	int rd;

	rd = readlink(linkname, resolved_path, PATH_MAX);

	if (rd == -1) {
		sip_error("Failed to read link %s: %s\n", linkname, strerror(errno));
		return NULL;
	}
	if (rd == PATH_MAX) {
		sip_error("Failed to read link %s: link size too large.\n", linkname);
		return NULL;
	}

	resolved_path[rd] = '\0';

	return strdup(resolved_path);
}

/**
 * Convert the given file descriptor to a file path. Our strategy is to
 * use the /proc pseudo-filesystem to obtain a symbolic link to the open
 * file, then resolve this link using readlink(2).
 *
 * NOTE: The buffer returned by this function is dynamically allocated
 * and should be freed by the caller.
 *
 * @param int fd File descriptor.
 * @return char* Resolved path name on success, NULL on error.
 */
char* sip_fd_to_path(int fd) {
	char linkname[PATH_MAX], *resolved;
	int len = 0;

	/* Construct link name */
	len = snprintf(linkname, PATH_MAX, "/proc/self/fd/%d", fd);
	
	if (len >= PATH_MAX) {
		sip_error("Failed to convert %d to path: maximum link length exceeded.\n", fd);
		return NULL;
	}

	/* Resolve link name to path */
	resolved = sip_readlink(linkname);

	if (resolved == NULL) {
		sip_error("Failed to convert %d to path: readlink error.\n", fd);
		return NULL;
	}

	return resolved;
}

/**
 * Is the socket with the given addr and addrlen a named socket?
 *
 * @param struct sockaddr* addr
 * @param socklen_t addrlen
 */
int sip_is_named_sock(const struct sockaddr* addr, socklen_t addrlen) {
	if (addr->sa_family != AF_LOCAL) {
		return 0;
	}

	struct sockaddr_un* unaddr = (struct sockaddr_un*) addr;

	if (addrlen == sizeof(sa_family_t)) {		/* unnamed */
		return 0;
	} else if (unaddr->sun_path[0] == '\0') {	/* abstract */
		return 0;
	}

	return 1;
}

/**
 * Is the current process the daemon?
 *
 * @return 1 if current process is daemon, otherwise 0.
 */
int sip_is_daemon() {
	char linkpath[100], *resolved;

	/* /proc/<PID>/exe returns link to current process's executable */
	snprintf(linkpath, 100, "/proc/%d/exe", getpid());

	/* resolve link to executable path */
	resolved = sip_readlink(linkpath);

	if (resolved != NULL && strcmp(linkpath, SIP_DAEMON_PATH) == 0) {
		return 1;
	}
	return 0;
}

/**
 * If the given pathname is relative, interpret it relative to the directory
 * referred to by dirfd and return the absolute path. If dirfd has the special
 * value AT_FDCWD and the path is relative, interpret it relative to the current
 * working directory. If the pathname is absolute, return it unmodified.
 *
 * NOTE: The buffer returned by this function is dynamically allocated and must
 * be freed.
 */
char *sip_abs_path(int dirfd, const char *pathname) {
	if (pathname[0] == '/') { 	/* absolute path */
		return strdup(pathname);
	}

	char temppath[PATH_MAX] = {0};

	if (dirfd != AT_FDCWD) {	/* interpret path relative to dirfd */
		char *cwd = sip_fd_to_path(dirfd);
		
		if (cwd != NULL) {
			strncpy(temppath, cwd, PATH_MAX);
			free(cwd);
		}
	}

	strncat(temppath, pathname, PATH_MAX);

	return realpath(temppath, NULL);
}

/**
 * Send descriptor fd over the socket referred to by descriptor sockfd.
 *
 * @return 0 on success, -1 on error
 */
int sip_send_fd(int sockfd, int fd) {
	
	/* prepare struct msghdr */
	struct msghdr msg = {0};
	struct cmsghdr *cmsg;
	int *fdptr;

	union {
	   /* ancillary data buffer, wrapped in a union in order to ensure
	      it is suitably aligned */
	   char buf[CMSG_SPACE(sizeof(int))];
	   struct cmsghdr align;
	} u;

	msg.msg_control = u.buf;
	msg.msg_controllen = sizeof u.buf;

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	fdptr = (int *) CMSG_DATA(cmsg);
	*fdptr = fd;

	/* send */
	if (sendmsg(sockfd, &msg, 0) <= 0) {
		sip_error("Failed to send file descriptor: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}
