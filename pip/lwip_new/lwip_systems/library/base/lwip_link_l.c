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

#include "lwip_link.h"
#include "lwip_debug.h"
#include "lwip_level.h"
#include "lwip_common.h"
#include "lwip_delegator_connection.h"
#include <unistd.h>
#include <fcntl.h> 
#include <string.h>
#include "lwip_redirect.h"

#include "lwip_in_utils.h"

static __thread char *link_buffer1 = NULL, *link_buffer2 = NULL;

lwip_syscall(link_l, pre) {
	LWIP_SAVE_PARAMETERS_N(5);
	lwip_change_syscall5(SYS_linkat, AT_FDCWD, *p1_ptr, AT_FDCWD, *p2_ptr, 0);
	lwip_call(linkat_l, pre);
}

lwip_syscall(linkat_l, pre) {
	LWIP_SAVE_PARAMETERS_N(5);
        lwip_syscall_covert2FullAndRedirectedPathat_re(p1_ptr, p2_ptr);
        link_buffer1 = (char *)lwip_bm_malloc(PATH_MAX);
        link_buffer2 = (char *)lwip_bm_malloc(PATH_MAX);
        convert2FullAndRedirectPathat_re(p3_ptr, p4_ptr, link_buffer1, link_buffer2);
 
}

lwip_syscall(linkat_l, post) {

	prepare_variables5(int VARIABLE_IS_NOT_USED, olddirfd, char *, oldpath, int VARIABLE_IS_NOT_USED, newdirfd, char *, newpath, int, flags);

	if (LWIP_ISERRORNO(EACCES) || LWIP_ISERRORNO(EPERM)) {
		LWIP_INFO("Untrusted process failed to do link on path %s to %s", oldpath, newpath);

		del_pkt_prepare_packets(linkat, pkt, response);
		strncpy(pkt.oldpath, oldpath, PATH_MAX);
		strncpy(pkt.newpath, newpath, PATH_MAX);
		pkt.flags = flags;

		if (LWIP_likely(sh_SENDRECVDELEGATOR_CORRECTLY(pkt, response))) {
			sh_COPYRESPONSE(response);
			LWIP_INFO("Response from delegator: isError %d, rv: %d", response.l_isError, response.l_rv);
		}
	}
	else if (LWIP_ISERROR)
		LWIP_INFO("link of file %s to %s failed: errno: %d", oldpath, newpath, lwip_syscall_errno);

	if (lwip_isIN_mode) {
		LWIP_IN_TRACE("LowWrite, %s", newpath);
	}

	if (link_buffer1 != NULL) {
		lwip_bm_free(link_buffer1);
		lwip_bm_free(link_buffer2);
		link_buffer1 = NULL;
		link_buffer2 = NULL;
	}


}


lwip_syscall(symlink_l, pre) {
	LWIP_SAVE_PARAMETERS_N(3);
	lwip_change_syscall3(SYS_symlinkat, *p1_ptr, AT_FDCWD, *p2_ptr);
	lwip_call(symlinkat_l, pre);
}

lwip_syscall(symlinkat_l, pre) {
	LWIP_SAVE_PARAMETERS_N(3);
        lwip_syscall_covert2FullAndRedirectedPathat_re(p2_ptr, p3_ptr);
}

lwip_syscall(symlinkat_l, post) {
	prepare_variables3(char *, oldpath, int VARIABLE_IS_NOT_USED, newdirfd, char *, newpath);

	if (LWIP_ISERRORNO(EACCES) || LWIP_ISERRORNO(EPERM)) {

		del_pkt_prepare_packets(symlink, pkt, response);

		strncpy(pkt.oldpath, oldpath, PATH_MAX);
		strncpy(pkt.newpath, newpath, PATH_MAX);

		if (LWIP_likely(sh_SENDRECVDELEGATOR_CORRECTLY(pkt, response))) {
			sh_COPYRESPONSE(response);
			LWIP_INFO("Response from delegator: isError %d, rv: %d", response.l_isError, response.l_rv);
		} else
			LWIP_UNEXPECTED_PATH_REACHED;
	}     

	if (lwip_isIN_mode && !LWIP_ISERROR)
		LWIP_IN_TRACE("LowWrite, %s", newpath);
}

lwip_syscall(readlink_l, pre) {
	LWIP_SAVE_PARAMETERS_N(4);
	lwip_change_syscall4(SYS_readlinkat, AT_FDCWD, *p1_ptr, *p2_ptr, *p3_ptr);
	lwip_call(readlinkat_l, pre);
}

lwip_syscall(readlinkat_l, pre) {
	LWIP_SAVE_PARAMETERS_N(4);
	lwip_syscall_covert2FullAndRedirectedPathat_re(p1_ptr, p2_ptr);
}

lwip_syscall(readlinkat_l, post) {

	prepare_variables4(int VARIABLE_IS_NOT_USED, dirfd, char *, path, char *, buf, size_t, bufsiz);

	if (LWIP_ISERRORNO(EACCES) || LWIP_ISERRORNO(EPERM)) {

		del_pkt_prepare_packets(readlink, pkt, response);
		strncpy(pkt.path, path, PATH_MAX);
		pkt.bufsiz = bufsiz;

		if (LWIP_likely(sh_SENDRECVDELEGATOR_CORRECTLY(pkt, response))) {
			sh_COPYRESPONSE(response);
			if (!response.l_isError)
				strncpy(buf, response.buf, response.l_rv);
			LWIP_INFO("Response from delegator: isError %d, rv: %d", response.l_isError, response.l_rv);
		} else
			LWIP_UNEXPECTED_PATH_REACHED;
	}     
}


