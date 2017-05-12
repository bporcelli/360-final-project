#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "util.h"
#include "logger.h"
#include "common.h"
#include "level.h"

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
	struct stat sb;
	char pathname[22], *linkname = NULL;
	int r = 0;

	/* Get path name */
	r = snprintf(pathname, 22, "/proc/self/fd/%d", fd);
	if (r >= 22) {
		sip_error("Large file descriptor (%d) provided to sip_fd_to_path.\n", fd);
		return NULL;
	}

	/* Allocate buffer large enough to hold resolved link name + \0 */
	if (lstat(pathname, &sb) == -1) {
		sip_error("Path resolution failed: lstat error.\n");
		return NULL;
	}
	if ((linkname = malloc(sb.st_size + 1)) == NULL) {
		sip_error("Path resolution failed: out of memory.\n");
		return NULL;
	}

	/* Read link -- make sure number of bytes returned is number expected. */
	r = readlink(pathname, linkname, sb.st_size + 1);

	if (r == -1) {
		sip_error("Failed to read link %s: %s\n", pathname, strerror(errno));
		return NULL;
	}
	if (r > sb.st_size) {
		sip_error("Failed to read link %s: link size changed between calls.\n", pathname);
		return NULL;
	}

	linkname[r] = '\0';

	return linkname;
}

/**
 * Get the integrity level of the given user.
 *
 * @param uid_t uid User ID.
 * @return SIP_LV_HIGH or SIP_LV_LOW
 */
int sip_uid_to_level(uid_t uid) {
	if (uid == SIP_UNTRUSTED_USERID) {
		return SIP_LV_LOW;
	}
	return SIP_LV_HIGH;
}

/**
 * Get the integrity level of the given group.
 *
 * @param gid_t gid User ID.
 * @return SIP_LV_HIGH or SIP_LV_LOW
 */
int sip_gid_to_level(gid_t gid) {
	if (gid == SIP_UNTRUSTED_USERID) {
		return SIP_LV_LOW;
	}
	return SIP_LV_HIGH;
}
