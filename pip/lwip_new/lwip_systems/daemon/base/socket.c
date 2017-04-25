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

#include "base.h"

//socket
#ifdef LWIP_OS_LINUX
lwip_del_call(socketcall_connect_fd) {

	getVariables3(char *, addr, socklen_t, addrlen, int, sockType);
	int socket2dbus = socket(PF_LOCAL, sockType, 0);

	LWIP_INFO("Calling connect to path %s", ((struct sockaddr_un *)(addr))->sun_path);
	if (connect(socket2dbus, (struct sockaddr *)addr, addrlen) < 0){
		close(socket2dbus);
		LWIP_SET_RESPONSE_ERROR(errno);
		LWIP_INFO("Connect is failed, errno: %d", errno);
		return -1;
	}
	else {
		LWIP_UNSET_RESPONSE_ERROR(0);
		LWIP_INFO("Connect is successful!");
		return socket2dbus;
	}
}

lwip_del_call(socketcall_bind) {
	
	getVariables3(char *, addr, socklen_t, addrlen, int, sockType);
	int sockfd = socket(PF_LOCAL, sockType, 0);
	LWIP_INFO("Calling bind to path %s", ((struct sockaddr_un *)(addr))->sun_path);

	if (bind(sockfd, (struct sockaddr_un *)addr, addrlen) < 0) {
		LWIP_ERROR("[BIND] failed, len: %d", req->addrlen);
		LWIP_SET_RESPONSE_ERROR(errno);
		close(sockfd);
		return -1;
	}

	char *path = ((struct sockaddr_un *)addr)->sun_path;

	int rv = fchown(sockfd, -1, LWIP_CF_UNTRUSTED_USERID);

	LWIP_INFO("[BIND] bind on %s", path);

	if (rv < 0)
		LWIP_ERROR("[BIND] Failed to chown on the file path %s", path);
	
	rv = fchmod(sockfd, S_IRWXU|S_IRWXG|S_IROTH|S_IXOTH);
	if (rv < 0)
		LWIP_ERROR("[BIND] Failed to chmod on the file path %s", path);

	LWIP_UNSET_RESPONSE_ERROR(0);
	return sockfd;
}


#endif





