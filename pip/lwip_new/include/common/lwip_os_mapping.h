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

#ifndef __LWIP_OS_MAPPING_H__
#define __LWIP_OS_MAPPING_H__

#ifdef LWIP_OS_LINUX

#define SYS_lwip_fstatat SYS_fstatat64
#define SYS_lwip_stat SYS_stat64
#define SYS_lwip_lstat SYS_lstat64

#define lwip_fstatat_struct_stat struct stat64


#define SYS_lwip_chown SYS_chown32
#define SYS_lwip_lchown SYS_lchown32
#define SYS_lwip_fchown SYS_fchown32


#elif defined LWIP_OS_BSD

#define SYS_lwip_fstatat SYS_fstatat
#define SYS_lwip_stat SYS_stat
#define SYS_lwip_lstat SYS_lstat

#define lwip_fstatat_struct_stat struct stat


#define SYS_lwip_chown SYS_chown
#define SYS_lwip_lchown SYS_lchown
#define SYS_lwip_fchown SYS_fchown



#endif


/*** Socket ***/
#ifdef LWIP_OS_BSD //#if defined(SCM_CREDS)          /* BSD interface */
#define CREDSTRUCT      cmsgcred
#define SCM_CREDTYPE    SCM_CREDS
#define CREDOPT         LOCAL_PEERCRED
#elif defined LWIP_OS_LINUX //(SCM_CREDENTIALS)  /* Linux interface */
#define CREDSTRUCT      ucred
#define SCM_CREDTYPE    SCM_CREDENTIALS
#define CREDOPT         SO_PASSCRED
#else
#error passing credentials is unsupported!
#endif

/* size of control buffer to send/recv one file descriptor */
#define RIGHTSLEN   CMSG_LEN(sizeof(int))
#define CREDSLEN    CMSG_LEN(sizeof(struct CREDSTRUCT))
#define CONTROLLEN  (RIGHTSLEN + CREDSLEN)



#endif /* __LWIP_OS_MAPPING_H__ */

