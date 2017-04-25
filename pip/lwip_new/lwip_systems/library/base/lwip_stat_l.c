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

#include "lwip_stat.h"
#include "lwip_syscall_handler.h"



#include "lwip_debug.h"
#include "lwip_utils.h"
#include "lwip_level.h"

#include "lwip_delegator_connection.h"
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>



lwip_syscall(stat_l, pre) {
	LWIP_SAVE_PARAMETERS_N(4);
	lwip_change_syscall4(SYS_lwip_fstatat, AT_FDCWD, *p1_ptr, *p2_ptr, 0);
	lwip_call(fstatat_l, pre);
}

lwip_syscall(lstat_l, pre) {
	LWIP_SAVE_PARAMETERS_N(4);
	lwip_change_syscall4(SYS_lwip_fstatat, AT_FDCWD, *p1_ptr, *p2_ptr, AT_SYMLINK_NOFOLLOW);
	lwip_call(fstatat_l, pre);
}

lwip_syscall(fstatat_l, pre) {
	LWIP_SAVE_PARAMETERS_N(2);
	lwip_syscall_covert2FullAndRedirectedPathat_re(p1_ptr, p2_ptr);
}


lwip_syscall(fstatat_l, post) {
	prepare_variables4(int VARIABLE_IS_NOT_USED, dirfd, char *, pathname, lwip_fstatat_struct_stat *, buf, int, flags);

	if (LWIP_ISERRORNO(EACCES)) {
		del_pkt_prepare_packets(lwip_fstatat, pkt, response);
		strncpy(pkt.pathname, pathname, PATH_MAX);
		pkt.flags = flags;

		if (LWIP_likely(sh_SENDRECVDELEGATOR_CORRECTLY(pkt, response))) {
			sh_COPYRESPONSE(response);
			if (!response.l_isError)
				memcpy(buf, &response.buf, sizeof(response.buf));
			LWIP_INFO("Response from delegator: isError %d, rv: %d", response.l_isError, response.l_rv);
		} else
			LWIP_UNEXPECTED_PATH_REACHED;
	}

	if (!LWIP_ISERROR) {
		if (buf->st_uid == LWIP_CF_UNTRUSTED_USERID)
			buf->st_uid = LWIP_CF_REAL_USERID;
		if (buf->st_gid == LWIP_CF_UNTRUSTED_USERID)
			buf->st_gid = LWIP_CF_REAL_USERID;
	}
}



