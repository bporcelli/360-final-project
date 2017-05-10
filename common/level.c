#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "common.h"
#include "level.h"
#include "logger.h"

/**
 * Determine the integrity level of a file given a file descriptor.
 *
 * @param int fd File descriptor.
 * @return int -1 on error, otherwise SIP_LV_HIGH or SIP_LV_LOW
 */
int sip_fd_to_level(int fd) {
	struct stat sbuf;

	if ((fstat(fd, &sbuf)) == -1) {
		return -1;
	}

	/* Files that are world-writable are low integrity */
	if (sbuf.st_mode & S_IWOTH) {
		return SIP_LV_LOW;
	}

	/* Files that are owned or group-owned by untrusted user are low integrity */
	if (sbuf.st_uid == SIP_UNTRUSTED_USERID || sbuf.st_gid == SIP_UNTRUSTED_USERID) {
		return SIP_LV_LOW;
	} else {
		return SIP_LV_HIGH;
	}
}

/**
 * Attempt to downgrade the integrity level of the file with the given
 * descriptor.
 *
 * @param int fd File descriptor.
 * @return 0 on success, -1 on error
 */
int sip_downgrade_fd(int fd) {
	struct stat sbuf;

	if ((fstat(fd, &sbuf)) == -1) {
		return -1;
	}

	if (sbuf.st_uid == SIP_UNTRUSTED_USERID || sbuf.st_gid == SIP_UNTRUSTED_USERID) {
		sip_warning("Tried to downgrade a low integrity file.\n");
		return 0; 	/* Already downgraded */
	} else if (sbuf.st_uid != SIP_REAL_USERID && sbuf.st_gid != SIP_REAL_USERID) {
		sip_error("Tried to downgrade non-user-owned file.\n");
		return -1; 	/* Not user-owned */
	}

	/* Can't downgrade if group permissions are being used. Note: must shift
	 * group bits left by 3 to align with user bits. */
	if (sbuf.st_uid != sbuf.st_gid) {
		if ((sbuf.st_mode & S_IRWXU) != (sbuf.st_mode & S_IRWXG) << 3) {
			sip_error("Tried to downgrade file with group permissions used.\n");
			return -1;
		}
	}

	/* Change group owner to untrusted group */
	if (fchown(fd, -1, SIP_UNTRUSTED_USERID) < 0) {
		sip_error("Can't downgrade file: chown failed.\n");
		return -1;
	}

	/* Set permissions for group. Keep original permissions for owner/others. */
	if (fchmod(fd, (sbuf.st_mode & ~S_IRWXG) | S_IRGRP | S_IWGRP) < 0) {
		sip_error("Can't downgrade file: chmod failed.\n");
		return -1;
	}

	return 0;
}
