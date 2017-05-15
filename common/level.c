#define _GNU_SOURCE /* required to expose syscall(2) */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "common.h"
#include "level.h"
#include "logger.h"

/**
 * Given a stat struct, determine the integrity level of a file.
 *
 * @param struct stat* sb
 * @return SIP_LV_HIGH or SIP_LV_LOW
 */
static int sip_stat_buf_to_level(struct stat* sb) {
	/* World-writable FIFOs and special files should be considered lowi. */
	if ((S_ISREG(sb->st_mode) || S_ISFIFO(sb->st_mode)) && (sb->st_mode & S_IWOTH)) {
		return SIP_LV_LOW;
	}

	/* Any file owned or group owned by the untrusted user should be lowi. */
	if (sb->st_uid == SIP_UNTRUSTED_USERID || sb->st_gid == SIP_UNTRUSTED_USERID) {
		return SIP_LV_LOW;
	} else {
		return SIP_LV_HIGH;
	}
}

/**
 * Determine the integrity level of a file given a file descriptor.
 *
 * @param int fd File descriptor.
 * @return int -1 on error, otherwise SIP_LV_HIGH or SIP_LV_LOW
 */
int sip_fd_to_level(int fd) {
	struct stat sbuf;
	
	if ((fstat(fd, &sbuf)) == -1)
		return -1;
	
	return sip_stat_buf_to_level(&sbuf);
}

/**
 * Determine the integrity level of a file given a file path.
 *
 * @param const char* path File path.
 * @return -1 on error, otherwise SIP_LV_HIGH or SIP_LV_LOW
 */
int sip_path_to_level(const char* path) {
	struct stat sbuf;
	
	if ((stat(path, &sbuf)) == -1)
		return -1;
	
	return sip_stat_buf_to_level(&sbuf);
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

/**
 * Given a stat buffer, determine whether the corresponding file can
 * be downgraded.
 *
 * @param struct stat *sbuf
 * @return 1 if file can be downgraded, otherwise 0.
 */
int sip_can_downgrade_buf(struct stat *sbuf) {
	/* Can't downgrade if file is not owned by the user. */
	if (sbuf->st_uid != SIP_REAL_USERID && sbuf->st_gid != SIP_REAL_USERID) {
		sip_error("Tried to downgrade non-user-owned file.\n");
		return 0;
	}

	/* Can't downgrade if group permissions are being used. */
	if (sbuf->st_uid != sbuf->st_gid) {
		if ((sbuf->st_mode & S_IRWXU) != (sbuf->st_mode & S_IRWXG) << 3) {
			sip_error("Tried to downgrade file with group permissions used.\n");
			return 0;
		}
	}

	return 1;
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

	/* Can't downgrade? Bail. */
	if (!sip_can_downgrade_buf(&sbuf)) {
		return -1;
	}

	/* Change group owner to untrusted group */
	if (fchown(fd, -1, SIP_UNTRUSTED_USERID) < 0) {
		sip_error("Can't downgrade file: chown failed.\n");
		return -1;
	}

	/* Give RW permissions to group. Keep original permissions for owner/others. */
	if (fchmod(fd, (sbuf.st_mode & ~S_IRWXG) | S_IRGRP | S_IWGRP) < 0) {
		sip_error("Can't downgrade file: chmod failed.\n");
		return -1;
	}

	return 0;
}

/**
 * Get the integrity level of the calling process by checking the real user ID.
 *
 * @return SIP_LV_HIGH or SIP_LV_LOW
 */
int sip_level() {
	long uid = syscall(SYS_getuid32); /* use syscall(2) to avoid interception */
	
	if (uid == SIP_UNTRUSTED_USERID)
		return SIP_LV_LOW;
	
	return SIP_LV_HIGH;
}
