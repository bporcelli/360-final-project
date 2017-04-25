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

/*
#include "lwip_ae_syscall_mapping.h"
#include "lwip_ae_syscall.h"


#include "lwip_tx_syscall_mapping.h"
#include "lwip_rd_syscall_mapping.h"
#include "lwip_iso_syscall_mapping.h"
#include "lwip_in_syscall_mapping.h"



#include "lwip_debug.h"
#include "lwip_common.h"
#include "lwip_tx_open.h"

#include "lwip_rd_getuid.h"
#include "lwip_rd_fork.h"
#include "lwip_rd_execve.h"
#include "lwip_rd_pgid.h"
#include "lwip_rd_open.h"
#include "lwip_rd_unlink.h"

#include "lwip_iso_getuid.h"
#include "lwip_iso_fork.h"
#include "lwip_iso_execve.h"
#include "lwip_iso_pgid.h"
#include "lwip_iso_open.h"
#include "lwip_iso_unlink.h"
#include "lwip_iso_rename.h"

#include "lwip_in_getuid.h"
#include "lwip_in_open.h"
#include "lwip_in_execve.h"
#include "lwip_in_futex.h"



*/

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

/*
void lwip_ae_obsoleted_post lwip_syscall_post_signature {
	LWIP_CRITICAL("AE Obsoleted system call %d is made", syscall_no);
}

void lwip_ae_unhandled lwip_syscall_pre_signature {
	LWIP_AE("AE Unhandled system call %d is made", *syscall_no_ptr);
}

void lwip_tx_obsoleted_post lwip_syscall_post_signature {
	LWIP_CRITICAL("TX Obsoleted system call %d is made", syscall_no);
}

void lwip_tx_unhandled lwip_syscall_pre_signature {
	LWIP_CRITICAL("TX Unhandled system call %d is made", *syscall_no_ptr);
}

void lwip_rd_obsoleted_post lwip_syscall_post_signature {
	LWIP_CRITICAL("RD Obsoleted system call %d is made", syscall_no);
}

void lwip_rd_unhandled lwip_syscall_pre_signature {
	LWIP_CRITICAL("RD Unhandled system call %d is made", *syscall_no_ptr);
}

void lwip_iso_obsoleted_post lwip_syscall_post_signature {
	LWIP_CRITICAL("ISO Obsoleted system call %d is made", syscall_no);
}

void lwip_iso_unhandled lwip_syscall_pre_signature {
	LWIP_CRITICAL("ISO Unhandled system call %d is made", *syscall_no_ptr);
}

void lwip_in_obsoleted_post lwip_syscall_post_signature {
	LWIP_CRITICAL("IN Obsoleted system call %d is made", syscall_no);
}

void lwip_in_unhandled lwip_syscall_pre_signature {
	LWIP_CRITICAL("IN Unhandled system call %d is made", *syscall_no_ptr);
}
*/

pt2syscall_pre_handler default_highI_syscall_pre_ftb[LWIP_SYSCALL_FTB_SIZE] = {
	LWIP_SYSCALL_HIGH_PRE_HANDLER_ENTRY,
	[LWIP_SYSCALL_FTB_SIZE-1] = NULL
};

pt2syscall_pre_handler default_lowI_syscall_pre_ftb[LWIP_SYSCALL_FTB_SIZE] = {
	LWIP_SYSCALL_LOW_PRE_HANDLER_ENTRY,
	[LWIP_SYSCALL_FTB_SIZE-1] = NULL
};

/*

pt2syscall_pre_handler ae_syscall_pre_ftb[LWIP_SYSCALL_FTB_SIZE] = {
	LWIP_AE_SYSCALL_PRE_HANDLER_ENTRY,
	[LWIP_SYSCALL_FTB_SIZE-1] = NULL
};

pt2syscall_pre_handler tx_syscall_pre_ftb[LWIP_SYSCALL_FTB_SIZE] = {
	LWIP_TX_SYSCALL_PRE_HANDLER_ENTRY,
	[LWIP_SYSCALL_FTB_SIZE-1] = NULL
};

pt2syscall_pre_handler rd_syscall_pre_ftb[LWIP_SYSCALL_FTB_SIZE] = {
	LWIP_RD_SYSCALL_PRE_HANDLER_ENTRY,
	[LWIP_SYSCALL_FTB_SIZE-1] = NULL
};

pt2syscall_pre_handler iso_syscall_pre_ftb[LWIP_SYSCALL_FTB_SIZE] = {
	LWIP_ISO_SYSCALL_PRE_HANDLER_ENTRY,
	[LWIP_SYSCALL_FTB_SIZE-1] = NULL
};

pt2syscall_pre_handler in_syscall_pre_ftb[LWIP_SYSCALL_FTB_SIZE] = {
	LWIP_IN_SYSCALL_PRE_HANDLER_ENTRY,
	[LWIP_SYSCALL_FTB_SIZE-1] = NULL
};

//pt2syscall_pre_handler *syscall_pre_ftb = default_syscall_pre_ftb;

*/


pt2syscall_post_handler default_highI_syscall_post_ftb[LWIP_SYSCALL_FTB_SIZE] = {
	LWIP_SYSCALL_HIGH_POST_HANDLER_ENTRY,
	[LWIP_SYSCALL_FTB_SIZE-1] = NULL
};

pt2syscall_post_handler default_lowI_syscall_post_ftb[LWIP_SYSCALL_FTB_SIZE] = {
	LWIP_SYSCALL_LOW_POST_HANDLER_ENTRY,
	[LWIP_SYSCALL_FTB_SIZE-1] = NULL
};

/*
pt2syscall_post_handler ae_syscall_post_ftb[LWIP_SYSCALL_FTB_SIZE] = {
	LWIP_AE_SYSCALL_POST_HANDLER_ENTRY,
	[LWIP_SYSCALL_FTB_SIZE-1] = NULL
};

pt2syscall_post_handler tx_syscall_post_ftb[LWIP_SYSCALL_FTB_SIZE] = {
	LWIP_TX_SYSCALL_POST_HANDLER_ENTRY,
	[LWIP_SYSCALL_FTB_SIZE-1] = NULL
};

pt2syscall_post_handler rd_syscall_post_ftb[LWIP_SYSCALL_FTB_SIZE] = {
	LWIP_RD_SYSCALL_POST_HANDLER_ENTRY,
	[LWIP_SYSCALL_FTB_SIZE-1] = NULL
};

pt2syscall_post_handler iso_syscall_post_ftb[LWIP_SYSCALL_FTB_SIZE] = {
	LWIP_ISO_SYSCALL_POST_HANDLER_ENTRY,
	[LWIP_SYSCALL_FTB_SIZE-1] = NULL
};

pt2syscall_post_handler in_syscall_post_ftb[LWIP_SYSCALL_FTB_SIZE] = {
	LWIP_IN_SYSCALL_POST_HANDLER_ENTRY,
	[LWIP_SYSCALL_FTB_SIZE-1] = NULL
};

//pt2syscall_post_handler *syscall_post_ftb = default_syscall_post_ftb;
*/

#undef lc
#define lc(syscall) [SYS_ ##syscall] = syscall ##_post


