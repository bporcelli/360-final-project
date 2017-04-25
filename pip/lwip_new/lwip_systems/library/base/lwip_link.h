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

#ifndef __LWIP_LINK_H__
#define __LWIP_LINK_H__
#include "lwip_syscall_handler.h"

lwip_syscall(link, pre);
lwip_syscall(linkat, pre);
lwip_syscall(linkat, post);

lwip_syscall(symlink, pre);
lwip_syscall(readlink, pre);
lwip_syscall(symlinkat, post);
lwip_syscall(readlinkat, post);



lwip_syscall(link_l, pre);
lwip_syscall(linkat_l, pre);
lwip_syscall(linkat_l, post);

lwip_syscall(symlink_l, pre);
lwip_syscall(readlink_l, pre);
lwip_syscall(symlinkat_l, pre);
lwip_syscall(symlinkat_l, post);
lwip_syscall(readlinkat_l, pre);
lwip_syscall(readlinkat_l, post);


#endif /* __LWIP_LINK_H__ */

