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

#include "lwip_common.h"
#include "lwip_os_mapping.h"

#ifdef LWIP_OS_LINUX
#include <syscall.h>
#elif defined LWIP_OS_BSD
#include <sys/syscall.h>
#endif

#include "lwip_syscall_mapping.h"
#include "lwip_base_syscall.h"

#include "lwip_syscall_ftb.h"

#define lc(syscall) [SYS_ ##syscall] = syscall ##_pre
#define lo(syscall) [SYS_ ##syscall] = lwip_obsoleted
#define lu(syscall) [SYS_ ##syscall] = lwip_unhandled
#define li(syscall) [SYS_ ##syscall] = NULL

#ifdef LWIP_OS_BSD
#define ll(syscall)
#define lb(syscall) lc(syscall)
#elif defined LWIP_OS_LINUX
#define ll(syscall) lc(syscall)
#define lb(syscall)
#endif


#ifdef LWIP_OS_LINUX
#define LWIP_SYSCALL_FTB_SIZE 338
#elif defined LWIP_OS_BSD
#define LWIP_SYSCALL_FTB_SIZE SYS_MAXSYSCALL
#endif

void lwip_obsoleted lwip_syscall_pre_signature {
	LWIP_CRITICAL("Obsoleted system call %d is made", *syscall_no_ptr);
}

void lwip_unhandled lwip_syscall_pre_signature {
	LWIP_CRITICAL("Unhandled system call %d is made", *syscall_no_ptr);
}

pt2syscall_pre_handler default_highI_syscall_pre_ftb[LWIP_SYSCALL_FTB_SIZE] = {
	LWIP_SYSCALL_HIGH_PRE_HANDLER_ENTRY,
	[LWIP_SYSCALL_FTB_SIZE-1] = NULL
};

pt2syscall_pre_handler default_lowI_syscall_pre_ftb[LWIP_SYSCALL_FTB_SIZE] = {
	LWIP_SYSCALL_LOW_PRE_HANDLER_ENTRY,
	[LWIP_SYSCALL_FTB_SIZE-1] = NULL
};

pt2syscall_post_handler default_highI_syscall_post_ftb[LWIP_SYSCALL_FTB_SIZE] = {
	LWIP_SYSCALL_HIGH_POST_HANDLER_ENTRY,
	[LWIP_SYSCALL_FTB_SIZE-1] = NULL
};

pt2syscall_post_handler default_lowI_syscall_post_ftb[LWIP_SYSCALL_FTB_SIZE] = {
	LWIP_SYSCALL_LOW_POST_HANDLER_ENTRY,
	[LWIP_SYSCALL_FTB_SIZE-1] = NULL
};

#undef lc
#define lc(syscall) [SYS_ ##syscall] = syscall ##_post


