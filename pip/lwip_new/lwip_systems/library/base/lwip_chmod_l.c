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

lwip_syscall(fchmod_l, post) {
	if (LWIP_ISERRORNO(EACCES) || LWIP_ISERRORNO(EPERM)) {
		prepare_variables2(int, fd, mode_t, mode);

		del_pkt_prepare_packets(fchmod, pkt, response);
		pkt.mode = mode;

		if ((sh_SENDFDTODELEGATOR(&pkt, fd) == pkt.l_size) && (sh_RECVFROMDELEGATOR(&response) == 0)) {
				sh_COPYRESPONSE(response);
				LWIP_INFO("Response from delegator fchmod: isError %d, rv: %d", response.l_isError, response.l_rv);
		} else
			LWIP_UNEXPECTED_PATH_REACHED;
	}
}

lwip_syscall(chmod_l, pre) {
	LWIP_SAVE_PARAMETERS_N(4);
	lwip_change_syscall4(SYS_fchmodat, AT_FDCWD, *p1_ptr, *p2_ptr, 0);
	lwip_call(fchmodat_l, pre);
}

#ifdef LWIP_OS_BSD
lwip_syscall(lchmod_l, pre) {
	LWIP_SAVE_PARAMETERS_N(4);
	lwip_change_syscall4(SYS_fchmodat, AT_FDCWD, *p1_ptr, *p2_ptr, AT_SYMLINK_NOFOLLOW);
	lwip_call(fchmodat_l, pre);
}
#endif

lwip_syscall(fchmodat_l, pre) {
	LWIP_SAVE_PARAMETERS_N(4);
#ifdef LWIP_OS_LINUX
	*p4_ptr = 0; /*Kernel does not implement flag != 0. It must be 0, or it will result in error.*/
#endif
	lwip_syscall_covert2FullAndRedirectedPathat_re(p1_ptr, p2_ptr);
}

lwip_syscall(fchmodat_l, post) {
	if (LWIP_ISERRORNO(EACCES) || LWIP_ISERRORNO(EPERM)) {
		prepare_variables4(int VARIABLE_IS_NOT_USED, dirfd, char *, path, mode_t, mode, int, flag);

		del_pkt_prepare_packets(fchmodat, pkt, response);
		strncpy(pkt.path, path, PATH_MAX);
		pkt.mode = mode;
		pkt.flag = flag;

		if (LWIP_likely(sh_SENDRECVDELEGATOR_CORRECTLY(pkt, response))) {
			sh_COPYRESPONSE(response);
			LWIP_INFO("Response from delegator: isError %d, rv: %d", response.l_isError, response.l_rv);

			if (response.l_isError && (response.l_rv == EPERM) && lwip_isRedirectableFile(path)) {
				LWIP_INFO("Delegator failed to perform chmod, but path %s is redirectable. Try redirection", path);
				if (lwip_redirect_createRedirectedCopy(path)) {
					LWIP_INFO("Failed to copy to redirected path for %s", path);
					return;
				}

				char *redirectedPath = lwip_bm_malloc(PATH_MAX);
				sprintf(redirectedPath, LWIP_REDIRECTION_PATH "%s", path);
				if (chmod(redirectedPath, mode)) {
					LWIP_SET_SYSCALL_ERROR(errno);
					LWIP_UNEXPECTED("Failed to chmod a redirected file %s", redirectedPath);
				} else {
					LWIP_UNSET_SYSCALL_ERROR(0);
					LWIP_INFO("Chmod eventually performed");
				}
				lwip_bm_free(redirectedPath);
			}
		} else
			LWIP_UNEXPECTED_PATH_REACHED;

	}
}

