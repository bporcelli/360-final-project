#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

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
	struct stat sb;
	char* resolved_path;
	int rd;

	/* Allocate buffer large enough to hold resolved link name + \0 */
	if (lstat(linkname, &sb) == -1) {
		sip_error("Failed to read link: lstat error.\n");
		return NULL;
	}
	if ((resolved_path = malloc(sb.st_size + 1)) == NULL) {
		sip_error("Failed to read link: out of memory.\n");
		return NULL;
	}

	/* Read link -- make sure number of bytes returned is number expected. */
	rd = readlink(linkname, resolved_path, sb.st_size + 1);

	if (rd == -1) {
		sip_error("Failed to read link %s: %s\n", linkname, strerror(errno));
		return NULL;
	}
	if (rd > sb.st_size) {
		sip_error("Failed to read link %s: link size changed between calls.\n", linkname);
		return NULL;
	}

	resolved_path[rd] = '\0';

	return resolved_path;
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
	char linkname[100], *resolved;
	int len = 0;

	/* Construct link name */
	len = snprintf(linkname, 100, "/proc/self/fd/%d", fd);
	
	if (len >= 100) {
		sip_error("Failed to convert %d to path: maximum link length exceeded.\n", fd);
		return NULL;
	}

	/* Resolve link name to path */
	resolved = sip_readlink(linkname);

	if (resolved == NULL) {
		sip_error("Failed to convert %d to path: readlink error.\n", fd);
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
