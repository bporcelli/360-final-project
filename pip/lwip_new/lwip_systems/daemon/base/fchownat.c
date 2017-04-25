/* * Portable Integrity Protection (PIP) System -
 * Copyright (C) 2012 Secure Systems Laboratory, Stony Brook University
 *
 * This file is part of Portable Integrity Protection (PIP) System.
 *
 * Portable Integrity Protection (PIP) System is free software: you can redistribute it
 * and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Portable Integrity Protection (PIP) System is distributed in the hope that it will
 * be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Portable Integrity Protection (PIP) System.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include "base.h"


define_helperFunction(safe_fchown, int fd, uid_t owner, gid_t group) {
	struct stat buf;
	if (lwip_util_fstat(fd, &buf)) {
		LWIP_UNEXPECTED("[FCHOWN] Failed to stat opened file fd: %s, errno: %d", lwip_util_nonSafefd2FullPath(fd), errno);
		LWIP_SET_RESPONSE_ERROR(errno);
		goto out;
	}

	Level oldLevel = lwip_level_statLv(buf);

	if (!lwip_level_isLow(oldLevel)) {
		LWIP_LOWI_VIOLATION("Attempt to chown on non-low integrity file %s", lwip_util_nonSafefd2FullPath(fd));
		LWIP_SET_RESPONSE_ERROR(EPERM);
		goto out;
	}

	if (group == LWIP_CF_REAL_USERID)
		group = LWIP_CF_UNTRUSTED_USERID;

	Level newLevel = lwip_level_statNewOwnerLv(buf, owner, group);

	if (!lwip_level_isLow(newLevel)) {
		LWIP_LOWI_VIOLATION("Attempt to change the file to highI %s", lwip_util_nonSafefd2FullPath(fd));
		LWIP_SET_RESPONSE_ERROR(EPERM);
		goto out;
	}

	lwip_del_performOperationAndSetResponse(fchown(fd, owner, group));

out:
	return;

}


//chown
lwip_del_call(fchownat) {
	getVariables4(char *, path, uid_t, owner, gid_t, group, int, flag);

	WARN_IF_NOT_ABS(path);
	LWIP_ASSERT(((owner != -1) && (group != -1)), "owner and group should not be -1!! uid %d, gid %d", owner, group);
	LWIP_ASSERT(flag == 0 || flag == AT_SYMLINK_NOFOLLOW, "flag is %d", flag);

	int fd = openat(-1, path, O_NOFOLLOW|O_NOATIME|O_RDONLY);
	if (fd == -1) {
		if ((flag & AT_SYMLINK_NOFOLLOW) && errno == ELOOP && LWIP_ISREDIRECTEDPATH(path))
			lwip_del_performOperationAndSetResponse(fchownat(-1, path, owner, LWIP_CF_UNTRUSTED_USERID, flag));
		else
			LWIP_SET_RESPONSE_ERROR(errno);
		return 0;
	}

	invoke_helperFunction(safe_fchown, fd, owner, group);
	close(fd);
	return 0;
}

