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

#ifndef __LWIP_DEL_CONFIG_H__
#define __LWIP_DEL_CONFIG_H__

#include <sys/types.h>
#include <sys/stat.h>

#include <sys/socket.h> 
#include <limits.h>
#include <sys/syscall.h>

#include "lwip_common.h"
#include <utime.h>
#include <sys/time.h>

#include <unistd.h>

#include "lwip_os_mapping.h"


#ifdef LWIP_OS_BSD
#include <sys/param.h>
#include <sys/mount.h>
#elif defined LWIP_OS_LINUX
#include <sys/vfs.h>
#endif



#define SEND_CORRECT(fd, buf, size) send((fd), (buf), (size), MSG_DONTWAIT) == (size)
#define RECV_CORRECT(fd, buf, size) recv((fd), (buf), (size), 0) == (size)

#define SEND_DEL_PKT_CORRECT(fd, pkt) SEND_CORRECT((fd), &(pkt), (pkt).l_size)
#define RECV_DEL_PKT_CORRECT(fd, pkt) RECV_CORRECT((fd), &(pkt), (pkt).l_size)


struct del_pkt_header {
  int pkt_size;
  int syscall_no;
};

struct del_response_pkt_header {
  int pkt_size;
  int syscall_no;
  int rv;
  int isError;
};

#ifdef LWIP_OS_BSD
#define CUSTOM_CALLNO 700
#elif defined LWIP_OS_LINUX
#define CUSTOM_CALLNO 400
#endif

#define SYS_socketcall_connect CUSTOM_CALLNO + 1
#define SYS_socketcall_bind CUSTOM_CALLNO + 2
#define SYS_socketcall_connect_proxy CUSTOM_CALLNO + 3
#define SYS_socketcall_connect_fd CUSTOM_CALLNO + 4
#define SYS_xxattr CUSTOM_CALLNO + 5 
#define SYS_generate_Xcookies CUSTOM_CALLNO + 6
//#define SYS_showUserMsg CUSTOM_CALLNO + 6

#define PACKET_HEADER struct del_pkt_header header
#define RESPONSE_PACKET_HEADER struct del_response_pkt_header header
#define l_size header.pkt_size
#define l_sysno header.syscall_no
#define l_rv header.rv
#define l_isError header.isError

struct del_pkt {
  PACKET_HEADER;  
};

#define EXPAND_ARG0(...)
#define EXPAND_ARG1(t1, a1) t1 a1;

#define EXPAND_ARG2(t1, a1, ...) t1 a1; \
	EXPAND_ARG1(__VA_ARGS__)

#define EXPAND_ARG3(t1, a1, ...) t1 a1; \
	EXPAND_ARG2(__VA_ARGS__)

#define EXPAND_ARG4(t1, a1, ...) t1 a1; \
	EXPAND_ARG3(__VA_ARGS__)

#define del_pkt_declaration(call, argcount,  ...) struct del_pkt_ ##call { \
	PACKET_HEADER; \
	EXPAND_ARG ##argcount(__VA_ARGS__)\
}

#define del_pkt_response_declaration(call, argcount,  ...) struct del_pkt_ ##call ##_response { \
	RESPONSE_PACKET_HEADER; \
	EXPAND_ARG ##argcount(__VA_ARGS__)\
}


#define del_pkt_prepare_packets(call, pkt, response) \
	struct del_pkt_ ##call pkt = lwip_del_getPkt(call); \
	struct del_pkt_ ##call ##_response response = lwip_del_getPktResponse(call)

//generic
del_pkt_response_declaration(generic, 0);

//access
del_pkt_declaration(faccessat, 3, char, pathname[PATH_MAX], int, mode, int, flag);
del_pkt_response_declaration(faccessat, 0);

//chdir
del_pkt_declaration(chdir, 1, char, path[PATH_MAX]);
del_pkt_response_declaration(chdir, 0);

//chmod
del_pkt_declaration(fchmodat, 3, char, path[PATH_MAX], mode_t, mode, int, flag);
del_pkt_response_declaration(fchmodat, 0);

//fchmod
del_pkt_declaration(fchmod, 2, int, fd, mode_t, mode);
del_pkt_response_declaration(fchmod, 0);

//chown
del_pkt_declaration(fchownat, 4, char, path[PATH_MAX], uid_t, owner, gid_t, group, int, flag);
del_pkt_response_declaration(fchownat, 0);

//symlink
del_pkt_declaration(symlink, 2, char, oldpath[PATH_MAX], char, newpath[PATH_MAX]);
del_pkt_response_declaration(symlink, 0);

del_pkt_declaration(readlink, 2, char, path[PATH_MAX], size_t, bufsiz);
del_pkt_response_declaration(readlink, 1, char, buf[PATH_MAX]);

del_pkt_declaration(linkat, 3, char, oldpath[PATH_MAX], char, newpath[PATH_MAX], int, flags);
del_pkt_response_declaration(linkat, 0);

//mkdir
del_pkt_declaration(mkdir, 2, char, path[PATH_MAX], mode_t, mode);
del_pkt_response_declaration(mkdir, 0);

//open
del_pkt_declaration(open, 3, char, pathname[PATH_MAX], int, flags, mode_t, mode);
del_pkt_response_declaration(open, 0);

//rename
del_pkt_declaration(rename, 2, char, from[PATH_MAX], char, to[PATH_MAX]);
del_pkt_response_declaration(rename, 0);

//socket
del_pkt_declaration(socketcall_connect_proxy, 3, char, addr[PATH_MAX], socklen_t, addrlen, int, sockType);
del_pkt_response_declaration(socketcall_connect_proxy, 0);

del_pkt_declaration(socketcall_connect_fd, 3, char, addr[PATH_MAX], socklen_t, addrlen, int, sockType);
del_pkt_response_declaration(socketcall_connect_fd, 0);

del_pkt_declaration(socketcall_bind, 3, char, addr[PATH_MAX], socklen_t, addrlen, int, sockType);
del_pkt_response_declaration(socketcall_bind, 0);


del_pkt_declaration(lwip_fstatat, 2, char, pathname[PATH_MAX], int, flags);
del_pkt_response_declaration(lwip_fstatat, 1, lwip_fstatat_struct_stat, buf);

/*
//stat
#ifdef LWIP_OS_LINUX
del_pkt_declaration(fstatat64, 2, char, pathname[PATH_MAX], int, flags);
del_pkt_response_declaration(fstatat64, 1, struct stat64, buf);
#elif defined LWIP_OS_BSD
del_pkt_declaration(fstatat, 2, char, path[PATH_MAX], int, flag);
del_pkt_response_declaration(fstatat, 1, struct stat, sb);
#endif
*/
//statfs
del_pkt_declaration(statfs, 2, char, path[PATH_MAX], int, size);
del_pkt_response_declaration(statfs, 1, struct statfs, buf);

#ifdef LWIP_OS_LINUX
del_pkt_declaration(statfs64, 2, char, path[PATH_MAX], int, size);
del_pkt_response_declaration(statfs64, 1, struct statfs64, buf);
#endif

//unlink
del_pkt_declaration(unlinkat, 2, char, path[PATH_MAX], int, flag);
del_pkt_response_declaration(unlinkat, 0);

//utime
del_pkt_declaration(utimes, 3, char, path[PATH_MAX], int, timeisnull, struct timeval, times[2]);
del_pkt_response_declaration(utimes, 0);

#ifdef LWIP_OS_LINUX
del_pkt_declaration(utime, 3, char, filename[PATH_MAX], int, timeisnull, struct utimbuf, times);
del_pkt_response_declaration(utime, 0);

del_pkt_declaration(utimensat, 4, char, pathname[PATH_MAX], int, timeisnull, struct timespec, times[2], int, flags);
del_pkt_response_declaration(utimensat, 0);

#elif defined LWIP_OS_BSD
del_pkt_declaration(lutimes, 3, char, path[PATH_MAX], int, timeisnull, struct timeval, times[2]);
del_pkt_response_declaration(lutimes, 0);
#endif


#define lwip_del_getPktResponse(name) {			\
    .l_size= sizeof(struct del_pkt_ ##name ##_response),	\
      .l_sysno = SYS_ ##name			\
      }


#define lwip_del_getPkt(name) {			\
    .l_size= sizeof(struct del_pkt_ ##name),	\
      .l_sysno = SYS_ ##name			\
      }



#endif /* __LWIP_DEL_CONFIG_H__ */

