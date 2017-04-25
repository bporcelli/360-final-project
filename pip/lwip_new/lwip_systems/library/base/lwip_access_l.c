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

#include "lwip_access.h"
#include "lwip_syscall_handler.h"

#include "lwip_debug.h"
#include "lwip_utils.h"
#include "lwip_level.h"

#include "lwip_delegator_connection.h"
#include <string.h>
#include <unistd.h>

#include "lwip_redirect.h"


lwip_syscall(access_l, pre) {
	LWIP_SAVE_PARAMETERS_N(4);
        lwip_change_syscall4(SYS_faccessat, AT_FDCWD, *p1_ptr, *p2_ptr, 0);
	lwip_call(faccessat_l, pre);
}

#ifdef LWIP_OS_BSD
lwip_syscall(eaccess_l, pre) {
	LWIP_SAVE_PARAMETERS_N(4);
        lwip_change_syscall4(SYS_faccessat, AT_FDCWD, *p1_ptr, *p2_ptr, AT_EACCESS);
	lwip_call(faccessat_l, pre);
}
#endif

lwip_syscall(faccessat_l, pre) {
	LWIP_SAVE_PARAMETERS_N(4);
	lwip_syscall_covert2FullAndRedirectedPathat_re(p1_ptr, p2_ptr);
}

lwip_syscall(faccessat_l, post) {

	if (LWIP_ISERRORNO(EACCES)) {
		prepare_variables4(int VARIABLE_IS_NOT_USED, fd, char *, path, int, mode, int, flag);
		LWIP_INFO("Untrusted process failed to do access on path %s, mode %d", path, mode);

		del_pkt_prepare_packets(faccessat, pkt, response);
		strncpy(pkt.pathname, path, PATH_MAX);
		pkt.mode = mode;
		pkt.flag = flag;

		if (LWIP_likely(sh_SENDRECVDELEGATOR_CORRECTLY(pkt, response))) {
			sh_COPYRESPONSE(response);
			LWIP_INFO("Response from delegator: isError %d, rv: %d", response.l_isError, response.l_rv);
		} else
			LWIP_UNEXPECTED_PATH_REACHED;
	}

}

