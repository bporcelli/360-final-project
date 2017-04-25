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

lwip_syscall(fchown_l, post) {

	prepare_variables1(int ,fd);
	if (LWIP_ISERRORNO(EACCES) || LWIP_ISERRORNO(EPERM)) {
		char *fullPath = lwip_bm_malloc(PATH_MAX);
		unsigned int *new_p2_ptr = (unsigned int *)fullPath;
		if (lwip_util_fd2fullPath(fd, fullPath) == -1) {
			LWIP_UNEXPECTED("Failed to convert fd to full path");
			goto out;
		}
		lwip_call_syscall_post_handler5(fchownat_l, -1, new_p2_ptr, *p2_ptr, *p3_ptr, 0);
out:
		lwip_bm_free(fullPath);
	}
}


lwip_syscall(chown_l, pre) {
	LWIP_SAVE_PARAMETERS_N(5);
	lwip_change_syscall5(SYS_fchownat, AT_FDCWD, *p1_ptr, *p2_ptr, *p3_ptr, 0);
	lwip_call(fchownat_l, pre);
}

lwip_syscall(lchown_l, pre) {
	LWIP_SAVE_PARAMETERS_N(5);
	lwip_change_syscall5(SYS_fchownat, AT_FDCWD, *p1_ptr, *p2_ptr, *p3_ptr, AT_SYMLINK_NOFOLLOW); 	
	lwip_call(fchownat_l, pre);
}

lwip_syscall(fchownat_l, pre) {
	LWIP_SAVE_PARAMETERS_N(5);
	lwip_syscall_covert2FullAndRedirectedPathat_re(p1_ptr, p2_ptr); 

	prepare_variables4(int VARIABLE_IS_NOT_USED, dirfd, char * VARIABLE_IS_NOT_USED, path, uid_t, owner, gid_t, group);

	if (owner == LWIP_CF_UNTRUSTED_USERID)
		*p3_ptr = LWIP_CF_UNTRUSTED_USERID;
	if (group == LWIP_CF_UNTRUSTED_USERID)
		*p4_ptr = LWIP_CF_UNTRUSTED_USERID;

}


lwip_syscall(fchownat_l, post) {

	//XXX: is there a scenario to help untrusted process to do chown??????
	if (LWIP_ISERRORNO(EACCES) || LWIP_ISERRORNO(EPERM)) {

		prepare_variables5(int VARIABLE_IS_NOT_USED, dirfd, char *, path, uid_t, owner, gid_t, group, int, flag);

		LWIP_INFO("Attempt to modify file ownership %s, uid %d, gid %d", path, owner, group);

		/* Checking for why it failed should be done by delegator. should not be done here!!! */
		del_pkt_prepare_packets(fchownat, pkt, response);
		if (owner == -1) owner = getuid();
		if (group == -1) group = getgid();

		strncpy(pkt.path, path, PATH_MAX);
		pkt.owner = owner;
		pkt.group = group;
		pkt.flag = flag;

		if (lwip_isIN_mode && (owner != 0) && (group != 0))
			LWIP_IN_REPORT("Attempt to modify file ownership %s, uid %d, gid %d", path, owner, group);

		if (LWIP_likely(sh_SENDRECVDELEGATOR_CORRECTLY(pkt, response))) {
			sh_COPYRESPONSE(response);
			LWIP_INFO("Response from delegator: isError %d, rv: %d", response.l_isError, response.l_rv);
		} else
			LWIP_UNEXPECTED_PATH_REACHED;
	}

}

