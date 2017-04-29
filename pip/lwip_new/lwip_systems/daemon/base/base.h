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

#ifndef __LWIP_DELEGATOR_BASE_H__
#define __LWIP_DELEGATOR_BASE_H__

#include "delegator.h"

#include "lwip_debug.h"
#include "lwip_level.h"
#include "lwip_utils.h"
#include "lwip_common.h"
#include "lwip_redirectHelper.h"
#include "lwip_bufferManager.h"
#include "lwip_os_mapping.h"
#include <unistd.h>
#include <fcntl.h>

#include <sys/time.h>


//socket
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h> 
#include <string.h>
#include <pthread.h>
//#include <unistd.h>
#include <sys/cdefs.h>

#ifdef LWIP_OS_LINUX
#include <stddef.h>
#endif

/**
 * NOTE: Contains function prototypes for delegated syscall handlers.
 * The actual implementations can be found in the files in directory
 * lwip_systems/daemon/base.
 */

//access
lwip_del_call(faccessat);

//chmod
lwip_del_call(fchmodat);
lwip_del_call(fchmod);

//chown
lwip_del_call(fchownat);


//symlink
lwip_del_call(symlink);
lwip_del_call(readlink);
lwip_del_call(linkat);

//mkdir
lwip_del_call(mkdir);

//open
lwip_del_call(open);

//rename
lwip_del_call(rename);

//socket
#ifdef LWIP_OS_LINUX
lwip_del_call(socketcall_connect_fd);
lwip_del_call(socketcall_bind);
#endif

//stat
#if 0
#ifdef LWIP_OS_BSD
lwip_del_call(fstatat);
#elif defined LWIP_OS_LINUX
lwip_del_call(fstatat64);
#endif
#endif

lwip_del_call(lwip_fstatat);

//statfs
lwip_del_call(statfs);
#ifdef LWIP_OS_LINUX
lwip_del_call(statfs64);
#endif

//unlink
lwip_del_call(unlinkat);

//utime
lwip_del_call(utimes);
#ifdef LWIP_OS_LINUX
lwip_del_call(utime);
lwip_del_call(utimensat);
#elif defined LWIP_OS_BSD
lwip_del_call(lutimes);
#endif



#endif /* __LWIP_DELEGATOR_BASE_H__ */


