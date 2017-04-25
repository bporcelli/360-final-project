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

#ifndef __LWIP_UTIMES_H
#define __LWIP_UTIMES_H
#include "lwip_syscall_handler.h"

lwip_syscall(utimes_l, pre);
lwip_syscall(utimes_l, post);

lwip_syscall(futimesat_l, pre);

#ifdef LWIP_OS_LINUX
lwip_syscall(utime_l, pre);
lwip_syscall(utime_l, post);
lwip_syscall(utimensat_l, pre);
lwip_syscall(utimensat_l, post);
#elif defined LWIP_OS_BSD
lwip_syscall(lutimes_l, pre);
lwip_syscall(lutimes_l, post);
#endif









#endif /* __LWIP_UTIMES_H */

