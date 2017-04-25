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

#ifndef __LWIP_AE_UTILS_H__
#define __LWIP_AE_UTILS_H__

#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include "lwip_notifier.h"
#include <limits.h>
#include <lwip_common.h>
#include <sys/file.h>
#include "lwip_debug.h"

#define LWIP_AE_TRACE(format, args...) 

/*

#define LWIP_AE_VIOLATION_EXIT(format, args...) do { \
	LWIP_AE(format, ##args); \
	LWIP_AE("Violation occured, sending signal to terminate the process group"); \
	sleep(1); \
	kill(getpgid(0)-1, SIGUSR1); \
	kill(-getpgid(0), 9); \
	} while (0)

//sh_showUserMsgN("Abstract Execution Violation: " format " pgid: %d", ##args, getpgid(0));

char *lwip_ae_getTraceDir();
char *getTraceFile();
extern char traceFilePath[PATH_MAX];

void lwip_ae_initialization();

#define AE_MSG_FORMAT "%d, %d, %s, "
#define AE_MSG_CONTENT getpid(), getuid(), lwip_util_getProcessImagePath()

#define LWIP_AE_TRACE(format, args...) \
	do { \
		LWIP_CUSTOM_LOG(getTraceFile(), AE_MSG_FORMAT format, AE_MSG_CONTENT, ##args); \
	} while (0)



#define LWIP_AE_TRACE_MSG(format, args...) \
	do {\
		 LWIP_AE_TRACE("Message, " format, ##args); \
	} while (0)

*/
#endif /* __LWIP_AE_UTILS_H__ */ 


