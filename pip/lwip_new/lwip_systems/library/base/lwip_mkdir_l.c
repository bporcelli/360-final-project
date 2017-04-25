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

#include "lwip_mkdir.h"
#include "lwip_syscall_handler.h"

#include "lwip_debug.h"
#include "lwip_delegator_connection.h"
#include <string.h>

lwip_callback(ask_delegator_mkdirat_l_post) {
	prepare_variables3(int VARIABLE_IS_NOT_USED, dirfd, char *, path, mode_t, mode);
	LWIP_INFO("Requesting delegator to mkdir on path %s", path);

	del_pkt_prepare_packets(mkdir, pkt, response);
	strncpy(pkt.path, path, PATH_MAX);
	pkt.mode = mode;

	if (LWIP_likely(sh_SENDRECVDELEGATOR_CORRECTLY(pkt, response))) {
		sh_COPYRESPONSE(response);
		LWIP_INFO("Response from delegator: isError %d, rv: %d", response.l_isError, response.l_rv);
	} else
		LWIP_UNEXPECTED_PATH_REACHED;
}

lwip_syscall(mkdir_l, pre) {
	LWIP_SAVE_PARAMETERS_N(3);
	lwip_change_syscall3(SYS_mkdirat, AT_FDCWD, *p1_ptr, *p2_ptr);
	lwip_call(mkdirat_l, pre);
}

lwip_syscall(mkdirat_l, pre) {
	LWIP_SAVE_PARAMETERS_N(3);
	lwip_syscall_covert2FullAndRedirectedPathat_re(p1_ptr, p2_ptr);
	lwip_cancelSyscall(&ask_delegator_mkdirat_l_post);
}

