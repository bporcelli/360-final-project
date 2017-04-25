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

#include "lwip_debug.h"
#include "lwip_level.h"
#include "lwip_delegator_connection.h"
#include "lwip_redirect.h"
#include <unistd.h>
#include "lwip_chown.h"

#include "lwip_in_utils.h"

#include "lwip_bufferManager.h"

lwip_callback(deny_fchownat_post) {
	LWIP_SET_SYSCALL_ERROR(EACCES);
	LWIP_HIGHI_VIOLATION("CHOWN is denied %s", (char *)*p2_ptr);
}

lwip_callback(deny_fchown_post) {
	LWIP_SET_SYSCALL_ERROR(EACCES);
	char *tempPath = (char *)lwip_bm_malloc(PATH_MAX);
	lwip_util_fd2fullPath((int)*p1_ptr, tempPath); 
	LWIP_HIGHI_VIOLATION("FCHOWN is denied %s", tempPath);
	lwip_bm_free(tempPath);
}


lwip_syscall(chown_h, pre) {
	lwip_change_syscall5(SYS_fchownat, AT_FDCWD, *p1_ptr, *p2_ptr, *p3_ptr, 0);
	lwip_call(fchownat_h, pre);
}

lwip_syscall(lchown_h, pre) {
	lwip_change_syscall5(SYS_fchownat, AT_FDCWD, *p1_ptr, *p2_ptr, *p3_ptr, AT_SYMLINK_NOFOLLOW);
	lwip_call(fchownat_h, pre);
}

int lwip_chown_isSafe(struct stat buf, uid_t uid, gid_t gid) {
	Level oldLevel = lwip_level_statLv(buf);
	Level newLevel = lwip_level_statNewOwnerLv(buf, uid, gid);

	if (oldLevel != newLevel) {
		if (oldLevel == LV_HIGH)
			LWIP_HIGHI_VIOLATION("Attempt to downgrade file via chown");
		else
			LWIP_HIGHI_VIOLATION("Attempt to upgrade file via chown");
		return 0;
	}
	return 1;
}

lwip_syscall(fchownat_h, pre) {
      
	prepare_variables5(int, dirfd, char *, path, uid_t, uid, gid_t, gid, int, flag);

	struct stat buf;
        if (lwip_util_fstatat(dirfd, path, &buf, flag))
        	return;

	if (!lwip_chown_isSafe(buf, uid, gid))
		lwip_cancelSyscall(&deny_fchownat_post);
}

lwip_syscall(fchown_h, pre) {

	prepare_variables3(int, fd, uid_t, uid, gid_t, gid);

	struct stat buf;
	if (lwip_util_fstat(fd, &buf)) {
		LWIP_UNEXPECTED("fstat failed for file for fchown: errno: %d", errno);
		return;
	}

	if (!lwip_chown_isSafe(buf, uid, gid))
		lwip_cancelSyscall(&deny_fchownat_post);
}

