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

#include "lwip_utimes.h"

#include "lwip_debug.h"
#include "lwip_utils.h"
#include "lwip_level.h"

#include "lwip_delegator_connection.h"
#include <string.h>


lwip_syscall(utimes_l, pre) {
	LWIP_SAVE_PARAMETERS_N(1);
	lwip_syscall_covert2FullAndRedirectedPath_re(p1_ptr);
}

lwip_syscall(utimes_l, post) {
	prepare_variables2(char *, path, struct timeval *,times);

	if (LWIP_ISERRORNO(EACCES) || LWIP_ISERRORNO(EPERM)) {

		LWIP_INFO("Untrusted process failed to do utimes on path %s", path);
		del_pkt_prepare_packets(utimes, pkt, response);
		strncpy(pkt.path, path, PATH_MAX);

		if (times != NULL) {
			memcpy(&pkt.times, (char *)times, sizeof(pkt.times));
			pkt.timeisnull = 0;
		} else
			pkt.timeisnull = 1;

		if (LWIP_likely(sh_SENDRECVDELEGATOR_CORRECTLY(pkt, response))) {
			sh_COPYRESPONSE(response);
			LWIP_INFO("Response from delegator: isError %d, rv: %d", response.l_isError, response.l_rv);
		} else
			LWIP_UNEXPECTED_PATH_REACHED;
	}
}



lwip_syscall(futimesat_l, pre) {
	LWIP_SAVE_PARAMETERS_N(3);
        lwip_syscall_covert2FullAndRedirectedPathat_re(p1_ptr, p2_ptr);
	lwip_change_syscall2(SYS_utimes, *p2_ptr, *p3_ptr);
	LWIP_UNEXPECTED("Call is obsolete");
}



#ifdef LWIP_OS_LINUX

lwip_syscall(utime_l, pre) {
	LWIP_SAVE_PARAMETERS_N(2);
	lwip_syscall_covert2FullAndRedirectedPath_re(p1_ptr);
}

lwip_syscall(utime_l, post) {
	prepare_variables2(char *, filename, struct utimbuf *, times);

	if (LWIP_ISERRORNO(EACCES) || LWIP_ISERRORNO(EPERM)) {

		del_pkt_prepare_packets(utime, pkt, response);
		strncpy(pkt.filename, filename, PATH_MAX);
		if (times != NULL) {
			memcpy(&pkt.times, (char *)times, sizeof(pkt.times));
			pkt.timeisnull = 0;
		} else
			pkt.timeisnull = 1;

		if (LWIP_likely(sh_SENDRECVDELEGATOR_CORRECTLY(pkt, response))) {
			sh_COPYRESPONSE(response);
			LWIP_INFO("Response from delegator: isError %d, rv: %d", response.l_isError, response.l_rv);
		} else
			LWIP_UNEXPECTED_PATH_REACHED;
	}
}


lwip_syscall(utimensat_l, pre) {
	LWIP_SAVE_PARAMETERS_N(2);
	lwip_syscall_covert2FullAndRedirectedPathat_re(p1_ptr, p2_ptr);
}

lwip_syscall(utimensat_l, post) {
	prepare_variables4(int VARIABLE_IS_NOT_USED, dirfd, char *, pathname, struct timespec *, times, int, flags);

	if (LWIP_ISERRORNO(EACCES) || LWIP_ISERRORNO(EPERM)) {

		del_pkt_prepare_packets(utimensat, pkt, response);
		pkt.flags = flags;
		if (pathname == NULL)
			lwip_util_fd2fullPath(dirfd, pkt.pathname);
		else
			strncpy(pkt.pathname, pathname, PATH_MAX);

		if (times != NULL) {
			memcpy(&pkt.times, (char *)times, sizeof(struct timespec)*2);
			pkt.timeisnull = 0;
		} else
			pkt.timeisnull = 1;

		if (LWIP_likely(sh_SENDRECVDELEGATOR_CORRECTLY(pkt, response))) {
			sh_COPYRESPONSE(response);
			LWIP_INFO("Response from delegator: isError %d, rv: %d", response.l_isError, response.l_rv);
		} else
			LWIP_UNEXPECTED_PATH_REACHED;
	}
}

#elif defined LWIP_OS_BSD

lwip_syscall(lutimes_l, pre) {
	LWIP_SAVE_PARAMETERS_N(2);
	lwip_syscall_covert2FullAndRedirectedPath_re(p1_ptr);
}


lwip_syscall(lutimes_l, post) {
	prepare_variables2(char *, path, struct timeval *,times);

	if (LWIP_ISERRORNO(EACCES) || LWIP_ISERRORNO(EPERM)) {
		LWIP_INFO("Untrusted process failed to do utimes on path %s", path);
		del_pkt_prepare_packets(lutimes, pkt, response);
		strncpy(pkt.path, path, PATH_MAX);
		if (times != NULL) {
			memcpy(&pkt.times, (char *)times, sizeof(pkt.times));
			pkt.timeisnull = 0;
		} else
			pkt.timeisnull = 1;

		if (LWIP_likely(sh_SENDRECVDELEGATOR_CORRECTLY(pkt, response))) {
			sh_COPYRESPONSE(response);
			LWIP_INFO("Response from delegator: isError %d, rv: %d", response.l_isError, response.l_rv);
		} else
			LWIP_UNEXPECTED_PATH_REACHED;
	}
}

#endif


