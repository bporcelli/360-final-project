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

#include "lwip_statfs.h"
#include "lwip_debug.h"
#include "lwip_level.h"
#include "lwip_common.h"
#include "lwip_delegator_connection.h"
#include <string.h>
#include <sys/stat.h>

lwip_syscall(statfs_l, pre) {
	lwip_syscall_covert2FullAndRedirectedPath_re(p1_ptr);
}

lwip_syscall(statfs_l, post) {
	prepare_variables2(char *, path, struct statfs *, buf);

	if (LWIP_ISERRORNO(EACCES)) {
		del_pkt_prepare_packets(statfs, pkt, response);
		strncpy(pkt.path, path, PATH_MAX); //TODO: Possible to optimize by resolving it in the pre call!

		if (LWIP_likely(sh_SENDRECVDELEGATOR_CORRECTLY(pkt, response))) {
			LWIP_INFO("Response from delegator: isError %d, rv: %d", response.l_isError, response.l_rv);
			sh_COPYRESPONSE(response);
			if (!response.l_isError)
				memcpy(buf, &(response.buf), sizeof(response.buf));
		} else
			LWIP_UNEXPECTED_PATH_REACHED;
	}
}

#ifdef LWIP_OS_LINUX

lwip_syscall(statfs64_l, pre) {
	lwip_syscall_covert2FullAndRedirectedPath_re(p1_ptr);
}

lwip_syscall(statfs64_l, post) {
	prepare_variables3(char *, path, int, size, struct statfs64 *, buf);

	if (LWIP_ISERRORNO(EACCES)) {
		del_pkt_prepare_packets(statfs64, pkt, response);
		strncpy(pkt.path, path, PATH_MAX);
		pkt.size = size;

		if (LWIP_likely(sh_SENDRECVDELEGATOR_CORRECTLY(pkt, response))) {
			LWIP_INFO("Response from delegator: isError %d, rv: %d", response.l_isError, response.l_rv);
			sh_COPYRESPONSE(response);
			if (!response.l_isError)
				memcpy(buf, &response.buf, sizeof(response.buf));
		} else
			LWIP_UNEXPECTED_PATH_REACHED;
	}
}

#endif

