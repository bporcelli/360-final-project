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

#include "lwip_socket.h"

#include "lwip_debug.h"
#include "lwip_level.h"
#include "lwip_del_conf.h"
#include "lwip_delegator_connection.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/un.h>

#ifdef LWIP_OS_LINUX
#include <linux/net.h>
#endif



static struct sockaddr_un proxy_sockaddr = {
#ifdef LWIP_OS_BSD
	.sun_len = sizeof(proxy_sockaddr),
#endif
        .sun_family = AF_UNIX,
        .sun_path = LWIP_DAEMON_COMMUNICATION_PATH "/all-connect"
};

__thread struct sockaddr *original_name = NULL;
__thread socklen_t original_len = 0;
__thread char connect_address[PATH_MAX];




lwip_callback(ask_delegator_bind_l_post) {

	prepare_variables2(int VARIABLE_IS_NOT_USED, call, unsigned long *, args);



	del_pkt_prepare_packets(socketcall_bind, pkt, response);
	socklen_t len2 = sizeof(pkt.sockType);
	getsockopt(args[0], SOL_SOCKET, SO_TYPE, &pkt.sockType, &len2);
	memcpy(&pkt.addr, (void *)args[1], args[2]);
	pkt.addrlen = args[2];
	int newfd; 

#ifdef LWIP_DEBUG_ON
	char *path = ((struct sockaddr_un *)args[1])->sun_path;
#endif

	LWIP_INFO("Requesting delegator to bind");

	if (sh_SEND2DELEGATOR(&pkt) == 0) {
		sh_RECVFDFROMDELEGATOR(&response, &newfd);
		sh_COPYRESPONSE(response);
		if (!response.l_isError) {
			close(args[0]);
			dup2(newfd, args[0]);
			close(newfd);
			LWIP_INFO("Delegator returned %d on socket bind %s, new fd is %d", response.l_rv, path, newfd);
		}
		else
			LWIP_INFO("Delegator failed to bind on path %s!!! %d", path, response.l_rv);

	} else
		LWIP_UNEXPECTED_PATH_REACHED;
}



/* Similar to files, socket must be owned by the real user. So, we ask the delegator
   directly */
lwip_syscall(bind_l, pre) {
	/* XXX: Should be full path? */
	prepare_variables2(int VARIABLE_IS_NOT_USED, call, unsigned long *, args);
	char *path = ((struct sockaddr_un *)args[1])->sun_path;

	if (((struct sockaddr *)args[1])->sa_family == AF_INET) {
		LWIP_INFO("Trying to bind internet socket");
		return;
	}

	if (path[0] != '\0')
		lwip_cancelSyscall(&ask_delegator_bind_l_post);
}

/* Modify sendmsg SCM_CREDENTIALS since kernel does not allow sending fake info */
lwip_syscall(sendmsg_l, pre) {
	prepare_variables2(int VARIABLE_IS_NOT_USED, call, unsigned long *, args);

	struct msghdr *msg = (struct msghdr *) args[1];
	struct cmsghdr  *cmptr;
	if ((cmptr = CMSG_FIRSTHDR(msg)) != NULL) {
		if (cmptr->cmsg_type == SCM_CREDTYPE) {
			struct CREDSTRUCT cred;
			memcpy(&cred, CMSG_DATA(cmptr), sizeof(cred));

			uid_t process_uid = getuid();
			gid_t process_gid = getgid();

#ifdef LWIP_OS_LINUX
			if (cred.uid != process_uid || cred.gid != process_gid) {
				LWIP_INFO("Modifying the cred.uid from %d to %d", cred.uid, process_uid);
				cred.uid = process_uid;
				cred.gid = process_gid;
				memcpy(CMSG_DATA(cmptr), &cred, sizeof(cred));
			} 
#elif defined LWIP_OS_BSD
			if (cred.cmcred_uid != process_uid || cred.cmcred_gid != process_gid || cred.cmcred_euid != process_uid) {
				LWIP_INFO("Modifying the cred.uid from %d to %d", cred.cmcred_uid, process_uid);
				cred.cmcred_uid = process_uid;
				cred.cmcred_gid = process_gid;
				cred.cmcred_euid = process_uid;
				memcpy(CMSG_DATA(cmptr), &cred, sizeof(cred));
				LWIP_CRITICAL("Check if the message is sent properly or not");
			}
#endif 
		}
	}
}



lwip_syscall(connect_l, pre) {

#ifdef LWIP_OS_BSD
	prepare_variables3(int, s, struct sockaddr *, name, socklen_t, namelen);
#elif defined LWIP_OS_LINUX
	prepare_variables2(int VARIABLE_IS_NOT_USED, call, unsigned long *, args);
	int s = args[0];
	struct sockaddr *name = (struct sockaddr *)args[1];
	socklen_t namelen = (socklen_t) args[2];
#endif

	struct sockaddr *address = (struct sockaddr *)connect_address;
	socklen_t len = PATH_MAX;

#ifdef LWIP_OS_LINUX
	if (getsockname(s, address, &len)) {
#elif defined LWIP_OS_BSD
	if (syscall(SYS_getsockname, s, address, &len)) {
#endif
		LWIP_UNEXPECTED("Failed to do getsockname");
		goto out;
	}



	if (address->sa_family == PF_LOCAL || address->sa_family == PF_UNIX 
#ifdef LWIP_OS_LINUX
		|| address->sa_family == AF_FILE 
#endif
		|| address->sa_family == AF_UNIX) {


#ifdef LWIP_OS_LINUX
		/* The dus connection requires special treatment*/

		/* Untrusted processes can connect to abstract namespace without problem */
		if (name->sa_data[0] == '\0') {
#ifdef LWIP_DEBUG_ON
			char *path = (char *) &(name->sa_data[1]);
			LWIP_INFO("Connecting via abstract namespace: %s, should be able to connect!!!", path);
#endif
#ifdef LWIP_INTERCEPT_DBUS_MESSAGE
			goto out;
#endif
			if (!lwip_isIN_mode)
				goto connect_via_delegator;
			goto out;

		}
#endif
		if (access(name->sa_data, W_OK) == 0) {
			LWIP_INFO("Untrusted process can connect to the path %s, len %d. Nothing is required to do.", name->sa_data, namelen);
			goto out;
		}
		LWIP_INFO("Untrusted process will not be able to connect to path %s, errno: %d", name->sa_data, errno);
		if (errno == EPERM || errno == EACCES) {

#ifdef LWIP_OS_LINUX
connect_via_delegator:
#endif
			LWIP_INFO("Will connect to path %s via delegator...", name->sa_data);
			original_name = name;
			original_len = namelen;
#ifdef LWIP_OS_BSD			
			*p2_ptr = (unsigned int)&proxy_sockaddr;
			*p3_ptr = sizeof(proxy_sockaddr);
#elif defined LWIP_OS_LINUX
			args[1] = (unsigned long)&proxy_sockaddr;
			args[2] = (unsigned long)sizeof(proxy_sockaddr);
#endif

		}
	} else if ((address->sa_family != AF_INET) && (address->sa_family != AF_INET6))
		LWIP_CRITICAL("The address family is not known/implemented?? %d", address->sa_family);
	
out:
	return;
}



lwip_syscall(connect_l, post) {

#ifdef LWIP_OS_BSD
	prepare_variables3(int, s, struct sockaddr *, name, socklen_t, namelen);
#elif defined LWIP_OS_LINUX
	prepare_variables2(int VARIABLE_IS_NOT_USED, call, unsigned long *, args);
	int s = args[0];
#ifdef LWIP_DEBUG_ON
	struct sockaddr *name = (struct sockaddr *)args[1];
	socklen_t namelen = (socklen_t)args[2];
#endif
#endif

	LWIP_INFO("Connect is called to path %s on socket %d, len %d", name->sa_data, s, namelen);
	if (LWIP_ISERROR) {
		LWIP_INFO("Connect is failed with error %d", lwip_syscall_errno);

	}
	else if (original_len != 0) { /* Connected to proxy. Will ask proxy to connect to original target */
		del_pkt_prepare_packets(socketcall_connect_fd, pkt, response);
		memcpy(&pkt.addr, (void *)original_name, original_len);
		pkt.addrlen = original_len;

		socklen_t len2 = sizeof(pkt.sockType);
		getsockopt(s, SOL_SOCKET, SO_TYPE, &pkt.sockType, &len2);

		LWIP_INFO("getsockopt gives type: %d, errno: %d", pkt.sockType, errno);

		int newfd;

		if (LWIP_likely(sh_SEND2DELEGATOR(&pkt) == 0)) {
			if (LWIP_likely(sh_RECVFDFROMDELEGATOR(&response, &newfd) != -1)) {
				if (response.l_isError) {
					LWIP_INFO("Delegator also failed to connect the file %s: errno: %d", name->sa_data, response.l_rv);
					LWIP_SET_SYSCALL_ERROR(response.l_rv);
				} else {
					LWIP_INFO("Delegator returned %d on open, new fd is %d", response.l_rv, newfd);
					LWIP_UNSET_SYSCALL_ERROR(0);
					close(s);
					dup2(newfd, s);
					close(newfd);
				} 
			}
		} else
			LWIP_UNEXPECTED_PATH_REACHED;

		original_len = 0;
	}
}


inline lwip_syscall(accept, post) {
//	prepare_variables2(int VARIABLE_IS_NOT_USED, call, unsigned long *, args);
	LWIP_SPECIAL("Accept is called");
}




#ifdef LWIP_OS_LINUX

lwip_syscall(socketcall_l, pre) {
	prepare_variables1(int, call);

	switch (call) {
		case SYS_CONNECT: lwip_call(connect_l, pre); break;
		case SYS_SENDMSG: lwip_call(sendmsg_l, pre); break;
		case SYS_BIND: lwip_call(bind_l, pre); break;
	}
	LWIP_SPECIAL("Call is %d", call);
}

lwip_syscall(socketcall_l, post)
{
	prepare_variables1(int, call);
	switch (call) {
		case SYS_CONNECT: lwip_call(connect_l, post); break;
		case SYS_ACCEPT: lwip_call(accept, post); break;
		case SYS_ACCEPT4: lwip_call(accept, post); break;
	}
}

#endif

