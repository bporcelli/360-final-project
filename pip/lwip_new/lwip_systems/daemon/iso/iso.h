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

#ifndef __LWIP_DELEGATOR_ISO_H__
#define __LWIP_DELEGATOR_ISO_H__

#include "delegator.h"

#include "lwip_debug.h"
#include "lwip_level.h"
#include "lwip_utils.h"
#include "lwip_common.h"
#include "lwip_redirectHelper.h"

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

lwip_del_iso_call(faccessat);
lwip_del_iso_call(open);

lwip_del_iso_call(fchmodat);
lwip_del_iso_call(fchownat);
lwip_del_iso_call(mkdir);
lwip_del_iso_call(rename);
lwip_del_iso_call(symlink);
lwip_del_iso_call(unlinkat);


#endif /* __LWIP_DELEGATOR_ISO_H__ */

