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

#ifndef __LWIP_OPEN_H__
#define __LWIP_OPEN_H__

#include "lwip_syscall_handler.h"

lwip_syscall(open, pre);

#ifdef LWIP_OS_LINUX
lwip_syscall(creat, pre);
#endif

lwip_syscall(openat, pre);
lwip_syscall(openat, post);


lwip_syscall(open_h, post);
lwip_syscall(openat_h, post);

lwip_syscall(open_l, pre);
lwip_syscall(openat_l, pre);
lwip_syscall(openat_l, post);

#endif /* __LWIP_OPEN_H__ */


