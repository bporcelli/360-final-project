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

#include "lwip_fork.h"
#include <sched.h>
#include "lwip_in_utils.h"
#include "lwip_ae_utils.h"
#include "lwip_utils.h"
#include <stdlib.h>

lwip_syscall(vfork, pre) {
	lwip_change_syscall(SYS_fork);
/*	if (*return_value_ptr != 0) {
		LWIP_IN_TRACE("vFork, %d", *return_value_ptr);
	}
*/
}


lwip_syscall(vfork, post) {
	if (*return_value_ptr != 0) {
		LWIP_IN_TRACE("vFork, %d", *return_value_ptr);
		if (lwip_isAE_mode)
			LWIP_AE_TRACE("vFork, %d", *return_value_ptr);
	}
}


#ifdef LWIP_OS_LINUX

lwip_syscall(clone, pre) {

//	prepare_variables3(int, VARIABLE_IS_NOT_USED t1, void *, VARIABLE_IS_NOT_USED child_stack, int, flags);
//	if (lwip_isAE_mode) {
//		LWIP_AE_TRACE_MSG("pid: %d parent in clone pre", getpid());
//	}

/*
	LWIP_INFO("Pre clone");
	if ((CLONE_NEWPID & flags) || (CLONE_THREAD & flags))
		LWIP_INFO("newpid or clone thread is set");
	else
		LWIP_INFO("Clone is called without the flags set");
*/
}

lwip_syscall(clone, post) {

	prepare_variables3(int, VARIABLE_IS_NOT_USED t1, void *, VARIABLE_IS_NOT_USED child_stack, int, flags);

	if (*return_value_ptr != 0) {
		LWIP_INFO("Clone_edge, %d %s %d %s", getpid(), lwip_util_getProcessImagePath(), *return_value_ptr, lwip_util_getProcessImagePath());
		if (lwip_isIN_mode)
			LWIP_IN_TRACE("Clone_edge, %d %s %d %s", getpid(), lwip_util_getProcessImagePath(), *return_value_ptr, lwip_util_getProcessImagePath());
		
		if (lwip_isAE_mode)
			LWIP_AE_TRACE("Clone_edge, %d %s %d %s", getpid(), lwip_util_getProcessImagePath(), *return_value_ptr, lwip_util_getProcessImagePath());

		if (lwip_isAE_mode) {
			LWIP_AE_TRACE("Clone, %d", *return_value_ptr);
//			LWIP_AE_TRACE_MSG("pid: %d parent in clone gets %d", getpid(), *return_value_ptr);
		}


	}
	else {

//		if (lwip_isAE_mode) {
//			LWIP_AE_TRACE_MSG("pid: %d child in clone gets %d", getpid(), *return_value_ptr);
//		}



		if (!((CLONE_THREAD) & flags) || (CLONE_NEWPID & flags)) {
			LWIP_INFO("Clone %d %s", getpid(), lwip_util_getProcessImagePath());
			if (lwip_isIN_mode)
				LWIP_IN_TRACE("Clone %d %s", getpid(), lwip_util_getProcessImagePath());

				//LWIP_AE_TRACE("Clone %d %s", getpid(), lwip_util_getProcessImagePath());

			if (lwip_isAE_mode) {
				char *newprogress = malloc(PATH_MAX*3);
				snprintf(newprogress, PATH_MAX*3, "%s:C %s", getenv("LWIP_AE_EXECUTION_PROGRESS"), lwip_util_getProcessImagePath());
				setenv("LWIP_AE_EXECUTION_PROGRESS", newprogress, 1);
//				LWIP_AE_TRACE_MSG("pid: %d, In clone now: %s", getpid(), getenv("LWIP_AE_EXECUTION_PROGRESS"));
				free(newprogress);
			}



		}

	}


}

#endif

