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

define_helperFunction(safe_fchmod, int fd, mode_t mode) {
	struct stat buf;

	if (fstat(fd, &buf)) {
		LWIP_UNEXPECTED("[FCHMODAT] Failed to stat opened file fd: %s, errno: %d", lwip_util_nonSafefd2FullPath(fd), errno);
		LWIP_SET_RESPONSE_ERROR(errno);
		goto out;
	}

        if ((buf.st_mode&(S_IRWXU|S_IRWXG|S_IRWXO)) == (mode & (S_IRWXU|S_IRWXG|S_IRWXO))) {
                LWIP_UNSET_RESPONSE_ERROR(0);
                LWIP_INFO("Will not change the permission %s", lwip_util_nonSafefd2FullPath(fd));
                goto out;
        }

	if (!lwip_isUntrustedBuf(buf)) {
		LWIP_LOWI_VIOLATION("[FCHMODAT] Attempt to chmod a file which is not lowI %s", lwip_util_nonSafefd2FullPath(fd));
		LWIP_SET_RESPONSE_ERROR(EPERM);
		goto out;
	}

	mode |= S_IWGRP|S_IRGRP|S_IWUSR|S_IRUSR;

	if (S_ISDIR(buf.st_mode))
		mode |= S_IXGRP;

	lwip_del_performOperationAndSetResponse(fchmod(fd, mode));

out:
	return;
}


//chmod
lwip_del_call(fchmodat) {
	getVariables3(char *, path, mode_t, mode, int, flag);

	WARN_IF_NOT_ABS(path);
	LWIP_ASSERT(flag == 0 || flag == AT_SYMLINK_NOFOLLOW, "flag is %d", flag);

	LWIP_INFO("[FCHMODAT] Received request to perform fchmod on path %s", path);
	/*
		If the path is a symlink
			If the operation is on symlink, and the symlink is located in redirected directory
			then it is safe to perform fchmodat.
			Else, it is not safe.
		Else
			open the file, perform the operation if it is untrusted, close the file.
	*/

	int fd = openat(-1, path, O_NOFOLLOW|O_NOATIME|O_RDONLY);
	if (fd == -1) {
		if ((flag & AT_SYMLINK_NOFOLLOW) && errno == ELOOP && LWIP_ISREDIRECTEDPATH(path))
			lwip_del_performOperationAndSetResponse(fchmodat(-1, path, mode, flag));
		else {
 			if (errno == ENXIO) {
				if (!fchmodat(-1, path, mode, flag)) {
					LWIP_UNSET_RESPONSE_ERROR(0);
					return 0;
				}
			}
			LWIP_SET_RESPONSE_ERROR(errno);
		}
		return 0;
	}

	invoke_helperFunction(safe_fchmod, fd, mode);
	close(fd);

	return 0;
}


lwip_del_call(fchmod) {
	getVariables2(int, fd, mode_t, mode);

	LWIP_INFO("[FCHMOD] Received request to perform fchmod on file %s", lwip_util_nonSafefd2FullPath(fd));

	invoke_helperFunction(safe_fchmod, fd, mode);

	return 0;
}

