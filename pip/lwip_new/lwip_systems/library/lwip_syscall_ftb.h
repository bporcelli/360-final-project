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

#ifndef __LWIP_SYSCALLFTB_H_
#define __LWIP_SYSCALLFTB_H_



#include "lwip_syscall_handler.h"

typedef void (*pt2syscall_pre_handler) lwip_syscall_pre_signature;


extern pt2syscall_pre_handler default_syscall_pre_ftb[];
extern pt2syscall_pre_handler ae_syscall_pre_ftb[];
extern pt2syscall_pre_handler tx_syscall_pre_ftb[];
extern pt2syscall_pre_handler rd_syscall_pre_ftb[];
extern pt2syscall_pre_handler iso_syscall_pre_ftb[];
extern pt2syscall_pre_handler in_syscall_pre_ftb[];
extern pt2syscall_pre_handler default_lowI_syscall_pre_ftb[];
extern pt2syscall_pre_handler default_highI_syscall_pre_ftb[];

extern pt2syscall_pre_handler *syscall_pre_ftb;


typedef void (*pt2syscall_post_handler) lwip_syscall_post_signature;

extern pt2syscall_post_handler default_syscall_post_ftb[];
extern pt2syscall_post_handler ae_syscall_post_ftb[];
extern pt2syscall_post_handler tx_syscall_post_ftb[];
extern pt2syscall_post_handler rd_syscall_post_ftb[];
extern pt2syscall_post_handler iso_syscall_post_ftb[];
extern pt2syscall_post_handler in_syscall_post_ftb[];
extern pt2syscall_post_handler default_lowI_syscall_post_ftb[];
extern pt2syscall_post_handler default_highI_syscall_post_ftb[];

extern pt2syscall_post_handler *syscall_post_ftb;



//extern void (*syscall_pre_ftb[]) lwip_syscall_pre_signature;
//extern void (*syscall_post_ftb[]) lwip_syscall_post_signature;

//extern void (*default_syscall_pre_ftb[]) lwip_syscall_pre_signature;


#endif /* __LWIP_SYSCALLFTB_H_ */
