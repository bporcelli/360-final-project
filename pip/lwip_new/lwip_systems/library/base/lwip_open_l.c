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

#include "lwip_open.h"
#include "lwip_notifier.h"

#include "lwip_debug.h"
#include "lwip_utils.h"
#include "lwip_level.h"
#include "lwip_trusted.h"

#include "lwip_syscall_handler.h"
#include "lwip_del_conf.h"
#include "lwip_delegator_connection.h"

#include "lwip_in_utils.h"

#include <string.h>
#include <fcntl.h>
#include <libgen.h>

#include "lwip_trackOpen.h"

#include <sys/types.h>
#include <dirent.h>

lwip_callback(ask_delegator_open_l_post) {

	prepare_variables4(int VARIABLE_IS_NOT_USED, dirfd, char *, op_pathname, int, flags, mode_t, mode);

	LWIP_ASSERT(op_pathname[0] == '/', "Path must be absolute");

	del_pkt_prepare_packets(open, pkt, response);
	strncpy(pkt.pathname, op_pathname, PATH_MAX);
	pkt.mode = mode;
	pkt.flags = flags;
	int newfd;

	if (LWIP_likely(sh_SEND2DELEGATOR(&pkt) == 0)) {
		if (LWIP_likely(sh_RECVFDFROMDELEGATOR(&response, &newfd) != -1)) {
			if (response.l_isError) {
				int isWrite = ((flags & 2) != O_RDONLY);
				if (response.l_rv == EACCES && isWrite && lwip_isRedirectableFile(op_pathname)) {
					LWIP_INFO("Try to redirect the file %s", op_pathname);
					if (lwip_redirect_createRedirectedCopy(op_pathname) == 0) {
						char *redirectedPath = lwip_bm_malloc(PATH_MAX);
						newfd = open(getFullandRedirectedPath(AT_FDCWD, op_pathname, redirectedPath), flags, mode);
						lwip_bm_free(redirectedPath);
						if (newfd > 0) {
							LWIP_INFO("File is successfully redirected, and opened %s", op_pathname);
							LWIP_UNSET_SYSCALL_ERROR(newfd);
							goto out;
						}
						LWIP_CRITICAL("Failed to open the redirected file %s", op_pathname);
					}
					LWIP_CRITICAL("Failed to redirect file %s", op_pathname);
				}

				LWIP_INFO("Delegator also failed to open the file %s: errno: %d", op_pathname, response.l_rv);
				LWIP_SET_SYSCALL_ERROR(response.l_rv);
			} else {
				LWIP_INFO("Delegator returned %d on open, new fd is %d", response.l_rv, newfd);
				LWIP_UNSET_SYSCALL_ERROR(newfd);
			} 
		}
	}
out:
	return;
}

lwip_callback(error_fileExist_open_l_post) {
	LWIP_SET_SYSCALL_ERROR(EEXIST);
}

lwip_syscall(open_l, pre) {
	LWIP_SAVE_PARAMETERS_N(4);
	lwip_change_syscall4(SYS_openat, AT_FDCWD, *p1_ptr, *p2_ptr, *p3_ptr);
	lwip_call(openat_l, pre);
}

lwip_syscall(openat_l, pre) {

	/* If create file or has no permission to access file, ask delegator */

	LWIP_SAVE_PARAMETERS_N(4);
	lwip_syscall_covert2FullAndRedirectedPathat_re(p1_ptr, p2_ptr);

	prepare_variables3(int VARIABLE_IS_NOT_USED, dirfd, char *, op_pathname, int, flags);

	int accessMode = 0;
	if (LWIP_FLAGISSET(flags, O_RDONLY) || LWIP_FLAGISSET(flags, O_RDWR))
		accessMode |= R_OK;
	if (LWIP_FLAGISSET(flags, O_WRONLY) || LWIP_FLAGISSET(flags, O_RDWR))
                accessMode |= W_OK;

	if (lwip_util_faccessat(-1, op_pathname, accessMode, 0)) {
		if ((errno == ENOENT && LWIP_FLAGISSET(flags, O_CREAT)) ||
			errno == EPERM || errno == EACCES) {
			LWIP_INFO("Will ask delegator to create file or grant access to file %s", op_pathname);
			lwip_cancelSyscall(&ask_delegator_open_l_post);
			goto out;
		}
	}

	/* fstatat returned without problem... File exists */
	if (LWIP_FLAGISSET(flags, O_EXCL)) {
		lwip_cancelSyscall(&error_fileExist_open_l_post);
	}

out:
	return;
}


lwip_syscall(openat_l, post) {
	if (LWIP_ISERRORNO(EACCES) || LWIP_ISERRORNO(EPERM)) {
		LWIP_INFO("Opening of file failed, will invoke delegator...");
		lwip_invokeCallback(ask_delegator_open_l_post);
	}
}


