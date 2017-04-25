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

#ifndef __LWIP_SOCKET_H__
#define __LWIP_SOCKET_H__
#include "lwip_syscall_handler.h"

#ifdef LWIP_OS_BSD

lwip_syscall(connect_l, pre);
lwip_syscall(connect_l, post);

lwip_syscall(sendmsg_l, pre);
lwip_syscall(bind_l, pre);

#elif defined LWIP_OS_LINUX

//lwip_syscall(socketcall_h, pre);
lwip_syscall(socketcall_h, post);

lwip_syscall(socketcall_l, pre);
lwip_syscall(socketcall_l, post);
#endif

#endif /* __LWIP_SOCKET_H__ */

