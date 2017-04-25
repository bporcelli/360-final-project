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
#include "lwip_syscall_handler.h"
#include "lwip_os_mapping.h"

#define LWIP_UNHANDLED lwip_unhandled
#if 0
L, access, access_l_pre, /* faccessat_l_post */
L, faccessat, faccessat_l_pre, faccessat_l_post
H, access, , access_h_post
H, faccessat, , faccessat_h_post
#endif


#ifdef LWIP_OS_LINUX
B, mq_open, LWIP_UNHANDLED
B, mount, LWIP_UNHANDLED
B, pivot_root, LWIP_UNHANDLED
B, uselib, LWIP_UNHANDLED
#elif defined LWIP_OS_BSD

B, __mac_execve, LWIP_UNHANDLED
B, __semctl, LWIP_UNHANDLED
B, __setugid, LWIP_UNHANDLED
B, __syscall, LWIP_UNHANDLED
B, accept, LWIP_UNHANDLED
B, connect, LWIP_UNHANDLED
B, fchmod, LWIP_UNHANDLED
B, fchmodat, LWIP_UNHANDLED
B, fchown, LWIP_UNHANDLED
B, fchownat, LWIP_UNHANDLED
B, fexecve, LWIP_UNHANDLED
B, fhopen, LWIP_UNHANDLED
B, fhstat, LWIP_UNHANDLED
B, freebsd7___semctl, LWIP_UNHANDLED
B, freebsd7_msgctl, LWIP_UNHANDLED
B, freebsd7_shmctl, LWIP_UNHANDLED
B, kldload, LWIP_UNHANDLED
B, kmq_open, LWIP_UNHANDLED
B, ksem_open, LWIP_UNHANDLED
B, link, LWIP_UNHANDLED
B, linkat, LWIP_UNHANDLED
B, mkfifo, LWIP_UNHANDLED
B, mkfifoat, LWIP_UNHANDLED
B, mknod, LWIP_UNHANDLED
B, mknodat, LWIP_UNHANDLED
B, mount, LWIP_UNHANDLED
B, msgctl, LWIP_UNHANDLED
B, msgget, LWIP_UNHANDLED
B, netbsd_lchown, LWIP_UNHANDLED
B, nlstat, LWIP_UNHANDLED
B, nmount, LWIP_UNHANDLED
B, recvfrom, LWIP_UNHANDLED
B, recvmsg, LWIP_UNHANDLED
B, sctp_generic_recvmsg, LWIP_UNHANDLED
B, sctp_generic_sendmsg, LWIP_UNHANDLED
B, sctp_generic_sendmsg_iov, LWIP_UNHANDLED
B, semget, LWIP_UNHANDLED
B, sendmsg, LWIP_UNHANDLED
B, seteuid, LWIP_UNHANDLED
B, setgid, LWIP_UNHANDLED
B, setegid, LWIP_UNHANDLED
B, setgroups, LWIP_UNHANDLED
B, setregid, LWIP_UNHANDLED
B, setresgid, LWIP_UNHANDLED
B, setresuid, LWIP_UNHANDLED
B, setreuid, LWIP_UNHANDLED

B, shm_open, LWIP_UNHANDLED
B, shm_unlink, LWIP_UNHANDLED
B, shmctl, LWIP_UNHANDLED
B, shmget, LWIP_UNHANDLED
B, syscall, LWIP_UNHANDLED






#endif



/* This file defines the mapping of system calls to function handlers */

//access
//B, access, access_pre, /*faccessat*/
//B, faccessat, faccessat_pre, faccessat_post
L, access, access_l_pre, /* faccessat_l_post */
L, faccessat, faccessat_l_pre, faccessat_l_post
H, access, , access_h_post
H, faccessat, , faccessat_h_post

#ifdef LWIP_OS_BSD
L, eaccess, eaccess_l_pre, /*faccessat*/
#endif

//chdir
//H, chdir, chdir_pre, 
//L, chdir, , chdir_l_post


#ifdef LWIP_INTERCEPT_DBUS_MESSAGE
//L, write, write_l_pre, write_l_post
#endif

//chmod
//B, chmod, chmod_pre,/* fchmodat_post*/
//B, fchmod, , fchmod_post

H, chmod, chmod_h_pre, 
H, fchmodat, fchmodat_h_pre, 
H, fchmod, fchmod_h_pre,

L, chmod, chmod_l_pre,
L, fchmodat, fchmodat_l_pre, fchmodat_l_post
L, fchmod, , fchmod_l_post

//fchmod ???
//B, fchmodat, fchmodat_pre, fchmodat_post
#ifdef LWIP_OS_BSD
L, lchmod, lchmod_l_pre, /*fchmodat_post*/
#endif

//chown
//B, fchownat, fchownat_pre, fchownat_post

H, fchownat, fchownat_h_pre,
L, fchownat, fchownat_l_pre, fchownat_l_post
H, lwip_chown, chown_h_pre, 
H, lwip_lchown, lchown_h_pre, 
H, lwip_fchown, fchown_h_pre,
L, lwip_fchown, , fchown_l_post
L, lwip_chown, chown_l_pre,
L, lwip_lchown, lchown_l_pre,


//execve
//B, execve, execve_pre, 
H, execve, execve_h_pre, 
L, execve, execve_l_pre, 
#ifdef LWIP_OS_BSD
//B, fexecve, fexecve_pre, 
#endif


//fork
B, vfork, vfork_pre, vfork_post
//vfork, , vfork_post

#ifdef LWIP_OS_LINUX
B, clone, clone_pre, clone_post
#endif



//getuid
#ifdef LWIP_OS_LINUX
L, getuid32, , getxuid_l_post
L, geteuid32, , getxuid_l_post
L, getgid32, , getxgid_l_post
L, getegid32, , getxgid_l_post
L, getresuid32, , getresuid_l_post
L, getresgid32, , getresgid_l_post
L, setuid32, setxuid_l_pre, 
L, setresuid32, setresuid_l_pre, 
L, setresgid32, setresuid_l_pre, 
#elif defined LWIP_OS_BSD
L, setuid, setxuid_l_pre,
L, getuid, , getxuid_l_post
L, geteuid, , getxuid_l_post
L, getgid, , getxgid_l_post
L, getegid, , getxgid_l_post
L, getresuid, , getresuid_l_post
L, getresgid, , getresgid_l_post
#endif



//ipc
#ifdef LWIP_OS_LINUX
H, ipc, ipc_h_pre, ipc_h_post
#endif

//link
L, symlink, symlink_l_pre, /*symlinkat*/
L, readlink, readlink_l_pre, /*readlinkat*/
L, symlinkat, symlinkat_l_pre, symlinkat_l_post
L, readlinkat, readlinkat_l_pre, readlinkat_l_post
L, link, link_l_pre,
L, linkat, linkat_l_pre, linkat_l_post

//mkdir
//H, mkdir, mkdir_pre, /*mkdirat*/
//H, mkdirat, , mkdirat_post

L, mkdir, mkdir_l_pre,
L, mkdirat, mkdirat_l_pre,


//open
//B, open, open_pre, /*openat*/
L, open, open_l_pre, /*openat_l_post*/
L, openat, openat_l_pre, openat_l_post
H, open, , open_h_post
H, openat, , openat_h_post

#ifdef LWIP_OS_LINUX
//B, creat, creat_pre, 
#endif
B, mknod, LWIP_UNHANDLED,  
B, mknodat, LWIP_UNHANDLED, 



//rename
//B, rename, rename_pre, /*renameat*/
//B, renameat, renameat_pre, renameat_post
H, rename, , rename_h_post
H, renameat, , renameat_h_post
L, rename, rename_l_pre,
L, renameat, renameat_l_pre, renameat_l_post

//socket
#ifdef LWIP_OS_BSD
L, connect, connect_l_pre, connect_l_post
L, sendmsg, sendmsg_l_pre,
L, bind, bind_l_pre,
#elif defined LWIP_OS_LINUX
H, socketcall, , socketcall_h_post
L, socketcall, socketcall_l_pre, socketcall_l_post
#endif


//stat

L, lwip_stat, stat_l_pre, 
L, lwip_lstat, lstat_l_pre,
L, lwip_fstatat, fstatat_l_pre, fstatat_l_post


//statfs
L, statfs, statfs_l_pre, statfs_l_post
#ifdef LWIP_OS_LINUX
L, statfs64, statfs64_l_pre, statfs64_l_post
#endif



//unlink
//H, unlink, unlink_pre, /*unlinkat*/
//H, rmdir, rmdir_pre, /*unlinkat*/
//H, unlinkat, unlinkat_pre, unlinkat_post

L, unlink, unlink_l_pre,
L, rmdir, rmdir_l_pre,
L, unlinkat, unlinkat_l_pre,


//utimes

L, utimes, utimes_l_pre, utimes_l_post
L, futimesat, futimesat_l_pre,
#ifdef LWIP_OS_BSD
L, lutimes, lutimes_l_pre, lutimes_l_post
#elif defined LWIP_OS_LINUX
L, utime, utime_l_pre, utime_l_post
L, utimensat, utimensat_l_pre, utimensat_l_post
#endif




