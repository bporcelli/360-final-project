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

#include "lwip_rename.h"
#include "lwip_syscall_handler.h"

#include "lwip_debug.h"
#include "lwip_utils.h"
#include "lwip_level.h"

#include "lwip_delegator_connection.h"
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "lwip_in_utils.h"

#include "lwip_redirectHelper.h"

//static __thread char rename_buffer1[PATH_MAX], rename_buffer2[PATH_MAX];

static __thread char *rename_buffer1 = NULL, *rename_buffer2 = NULL;

lwip_syscall(rename_l, pre) {
        LWIP_SAVE_PARAMETERS_N(4);
        lwip_change_syscall4(SYS_renameat, AT_FDCWD, *p1_ptr, AT_FDCWD, *p2_ptr);
        lwip_call(renameat_l, pre);
}

lwip_syscall(renameat_l, pre) {
	LWIP_SAVE_PARAMETERS_N(4);
	LWIP_INFO("RENAME Before 1: %s, 2: %s", (char *)*p2_ptr, (char *)*p4_ptr);
	lwip_syscall_covert2FullAndRedirectedPathat_re(p1_ptr, p2_ptr);
        rename_buffer1 = (char *)lwip_bm_malloc(PATH_MAX);
        rename_buffer2 = (char *)lwip_bm_malloc(PATH_MAX);
        convert2FullAndRedirectPathat_re_F(p3_ptr, p4_ptr, rename_buffer1, rename_buffer2);
	LWIP_INFO("RENAME After 1: %s, 2: %s", (char *)*p2_ptr, (char *)*p4_ptr);
        *p1_ptr = -1;
        *p3_ptr = -1;
}

lwip_syscall(renameat_l, post) {
	prepare_variables4(int VARIABLE_IS_NOT_USED, olddirfd, char *, from, int VARIABLE_IS_NOT_USED, newdirfd, char *, to);

	if (LWIP_ISERRORNO(EACCES) || LWIP_ISERRORNO(EPERM)) {
		LWIP_INFO("Untrusted process failed to do rename on path %s to %s", from, to);

		del_pkt_prepare_packets(rename, pkt, response);
		strncpy(pkt.from, from, PATH_MAX);
		strncpy(pkt.to, to, PATH_MAX);

		if (strncmp(to, LWIP_REDIRECTION_PATH, strlen(LWIP_REDIRECTION_PATH)) == 0) {
			LWIP_INFO("target is in redirected directory, will create... ");
			lwip_createDirsIgnLast_with_permissions(pkt.to, LWIP_CF_UNTRUSTED_USERID, S_IRWXU|S_IRWXG|S_IROTH|S_IXOTH);
		} else
			LWIP_INFO("target is not in redirected directory, will not create... ");

		if (LWIP_likely(sh_SENDRECVDELEGATOR_CORRECTLY(pkt, response))) {
			sh_COPYRESPONSE(response);
			LWIP_INFO("Response from delegator: isError %d, rv: %d", response.l_isError, response.l_rv);
		} else
			LWIP_UNEXPECTED_PATH_REACHED;
	}
	
//	if (lwip_isIN_mode && LWIP_PROCESS_LV_HIGH && !LWIP_ISERROR)
//		lwip_in_authorizedRemove(from);

	if (rename_buffer1 != NULL) {
		lwip_bm_free(rename_buffer1);
		lwip_bm_free(rename_buffer2);
		rename_buffer1 = NULL;
		rename_buffer2 = NULL;
	}
}
