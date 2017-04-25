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

#include "lwip_chmod.h"
#include "lwip_syscall_handler.h"

#include "lwip_debug.h"
#include "lwip_utils.h"
#include "lwip_level.h"
#include "lwip_in_utils.h"

#include "lwip_delegator_connection.h"
#include <string.h>
#include <sys/stat.h>

#include "lwip_bufferManager.h"

lwip_callback(deny_xchmod_h_post) {
	LWIP_SET_SYSCALL_ERROR(EACCES);
	prepare_variables1(char *, path);
	LWIP_CRITICAL("CHMOD is denied %s", path);
}

lwip_callback(deny_fchmodat_post) {
	LWIP_SET_SYSCALL_ERROR(EACCES);
	LWIP_CRITICAL("FCHMODAT is denied %s", (char *)*p2_ptr);
}

lwip_callback(deny_fchmod_post) {
	LWIP_SET_SYSCALL_ERROR(EACCES);
	LWIP_CRITICAL("FCHMOD is denied");
}

/*
int lwip_base_fchmodat_h_isSafeOperation(int dirfd, const char *pathname, mode_t mode, int flag) {
	struct stat buf;

	if (lwip_util_fstatat(dirfd, pathname, &buf, flag))
		return 1;

	if (flag & AT_SYMLINK_NOFOLLOW)
		LWIP_UNEXPECTED("Not clear how to handle symlink in chmod yet! %s", pathname);

	Level oldLevel = lwip_level_statLv(buf);
	Level newLevel = lwip_level_statNewModeLv(buf, mode);


	if (oldLevel != newLevel) {
		if (oldLevel == LV_HIGH && lwip_isTrusted2DowngradeFileAt(dirfd, pathname))
			return 1;

		if (oldLevel == LV_HIGH)
			LWIP_HIGHI_VIOLATION("Attempt to downgrade file %s via chmod", pathname);
		else
			LWIP_HIGHI_VIOLATION("Attempt to upgrade file %s via chmod", pathname);

		return 0;
	}
	return 1;
}
*/

lwip_syscall(chmod_h, pre) {
	lwip_change_syscall4(SYS_fchmodat, AT_FDCWD, *p1_ptr, *p2_ptr, 0);
	lwip_call(fchmodat_h, pre);
}

lwip_syscall(fchmodat_h, pre) {
	LWIP_SAVE_PARAMETERS_N(4);
	*p4_ptr = 0; /*Kernel does not implement flag != 0. It must be 0, or it will result in error.*/
	prepare_variables4(int, dirfd, char *, path, mode_t, mode, int, flag);


	struct stat buf;

	if (lwip_util_fstatat(dirfd, path, &buf, flag))
		return;

	if (flag & AT_SYMLINK_NOFOLLOW)
		LWIP_UNEXPECTED("Not clear how to handle symlink in chmod yet! %s", path);

	Level oldLevel = lwip_level_statLv(buf);
	Level newLevel = lwip_level_statNewModeLv(buf, mode);

	if (oldLevel != newLevel) {
		if (oldLevel == LV_HIGH && lwip_isTrusted2DowngradeFileAt(dirfd, path))
			return;

		if (oldLevel == LV_HIGH) {
			if ((mode & S_IRWXO) && (mode & S_IRWXG) && (mode & S_IRWXO)) {
				if (fchownat(dirfd, path, -1, LWIP_CF_TRUSTED_GROUP_GID, 0) == 0) {
					LWIP_HIGHI_VIOLATION("Making file %s as group writable instead of worldwritable", path);
					*p3_ptr &= ~(S_IWOTH);
					return;
				}
				LWIP_HIGHI_VIOLATION("Failed to change world-writable file into group-writable file %s", path);
			}

			LWIP_HIGHI_VIOLATION("Attempt to downgrade file %s via chmod is prevented", path);
			if (lwip_isIN_mode)
				LWIP_IN_TRACE_MSG("Info: Installation involves downgrading file %s, which is not allowed!", path);

		} else
			LWIP_HIGHI_VIOLATION("Attempt to upgrade file %s via chmod is prevented", path);

		lwip_cancelSyscall(&deny_fchmodat_post);
	}

}

lwip_syscall(fchmod_h, pre) {
	LWIP_SAVE_PARAMETERS_N(2);
	prepare_variables2(int, fd, mode_t, mode);

	struct stat buf;
	if (lwip_util_fstat(fd, &buf))
		return;

	Level oldLevel = lwip_level_statLv(buf);
	Level newLevel = lwip_level_statNewModeLv(buf, mode);

	if (oldLevel != newLevel) {
		if (oldLevel == LV_HIGH) {
			if ((mode & S_IRWXO) && (mode & S_IRWXG) && (mode & S_IRWXO)) {
				if (fchown(fd, -1, LWIP_CF_TRUSTED_GROUP_GID) == 0) {
					LWIP_HIGHI_VIOLATION("Making file %s as group writable instead of worldwritable", lwip_util_nonSafefd2FullPath(fd));
					*p3_ptr &= ~(S_IWOTH);
					return;
				}
				LWIP_HIGHI_VIOLATION("Failed to change world-writable file into group-writable file %s", lwip_util_nonSafefd2FullPath(fd));
			}

			LWIP_HIGHI_VIOLATION("Attempt to downgrade file %s via fchmod is prevented", lwip_util_nonSafefd2FullPath(fd));
			if (lwip_isIN_mode)
				LWIP_IN_TRACE_MSG("Info: Installation involves downgrading file %s, which is not allowed!", lwip_util_nonSafefd2FullPath(fd));

		} else
			LWIP_HIGHI_VIOLATION("Attempt to upgrade file %s via fchmod is prevented", lwip_util_nonSafefd2FullPath(fd));

		lwip_cancelSyscall(&deny_fchmod_post);
	}
}


