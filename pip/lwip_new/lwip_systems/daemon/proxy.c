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

#include "lwip_debug.h"
#include "lwip_common.h"
#include "lwip_del_conf.h"
#include "delegator.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h> 
#include <string.h>
#include <pthread.h>
//#include <unistd.h>
#include <sys/cdefs.h>
#include "lwip_os_mapping.h"


#ifdef LWIP_OS_LINUX
#include <stddef.h>
#endif

/**
 * The functions in this file enable the helper process to
 * connect(2) to a socket on behalf of an untrusted process.
 * See lwip_new/lwip_systems/library/base/lwip_socket_l.c for
 * more information.
 */

/**
 * Forwards a message from clientSocket to dBusSocket.
 */
void *start_generic_proxy_msg(void *arg)
{
	int dbusSocket = ((int *)arg)[0];
	int clientSocket = ((int *)arg)[1];
	char buf[4096];

	int on = 1;
	setsockopt(dbusSocket, SOL_SOCKET, CREDOPT, &on, sizeof(on));

	union {
        struct cmsghdr  cm;
        char    control[CMSG_SPACE(sizeof(struct CREDSTRUCT))];
	} control_un;
	struct msghdr msg;
	struct iovec iov[1];
	struct cmsghdr *cmptr;
	socklen_t controllen;

	controllen = sizeof(control_un.control);

	int n;

	while (1) {

        iov[0].iov_base = buf;
        iov[0].iov_len = sizeof(buf);

        msg.msg_name = NULL;
        msg.msg_namelen = 0;
        msg.msg_iov = iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control_un.control;
        msg.msg_controllen = controllen;
        msg.msg_flags = 0;

        controllen = CMSG_SPACE(sizeof(struct CREDSTRUCT));

		n = recvmsg(clientSocket, &msg, 0);
		if (n <= 0) {
			LWIP_INFO("recvmsg failed with errno: %d", errno);
			return NULL;
		}

		if ((cmptr = CMSG_FIRSTHDR(&msg)) != NULL) {
			if (cmptr->cmsg_level != SOL_SOCKET || 
				cmptr->cmsg_type != SCM_CREDTYPE) {
				LWIP_INFO("sendmsg but not sending credential...");
				goto send_msg;
			}
			msg.msg_controllen = sizeof(control_un.control);
			LWIP_INFO("credential is being sent...");

#ifdef LWIP_OS_LINUX
			struct ucred cred;
			memcpy(&cred, CMSG_DATA(cmptr), sizeof(cred));

			cred.pid = getpid();
			cred.uid = getuid();
			cred.gid = getgid();

			memcpy(CMSG_DATA(cmptr), &cred, sizeof(cred));
#endif

		}
		else {
			msg.msg_controllen = sizeof(struct cmsghdr);
			cmptr = CMSG_FIRSTHDR(&msg);
			cmptr->cmsg_len = CMSG_LEN(0);
			cmptr->cmsg_level = SOL_SOCKET;
			cmptr->cmsg_type = SCM_CREDTYPE;

		}

send_msg:					
		iov[0].iov_base = buf;
		iov[0].iov_len = n;

        msg.msg_control = control_un.control;
		msg.msg_name = NULL;
		msg.msg_namelen = 0;
		msg.msg_iov = iov;
		msg.msg_iovlen = 1;
		msg.msg_flags = 0;

		n = sendmsg(dbusSocket, &msg, 0);
		if (n <= 0) {
			LWIP_INFO("sendmsg failed with errno: %d", errno);
		}


	}
	return 0;
}


/**
 * Handles "direct" connect(2) requests.
 */
void serving_connect_fd(int sock2client, struct del_pkt_socketcall_connect_fd *pkt) {

	struct sockaddr_un addr;
	bzero(&addr, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	int len;
	int tosend = -1;

	int socket2dbus = socket(PF_LOCAL, pkt->sockType, 0);
	len = pkt->addrlen;

	struct del_pkt_socketcall_connect_fd_response response = lwip_del_getPktResponse(socketcall_connect_fd);

	LWIP_INFO("Calling connect to path %s", ((struct sockaddr_un *)(pkt->addr))->sun_path);
	if (connect(socket2dbus, (struct sockaddr *)&pkt->addr, len) < 0){
		tosend = -1;
		response.l_isError = 1;
		response.l_rv = -errno;
		LWIP_INFO("Connect is failed");
	}
	else {
		tosend = socket2dbus;
		response.l_isError = 0;
		response.l_rv = 0;
		LWIP_INFO("Connect is successful!");
	}

	lwip_util_send_fd(sock2client, &response, response.l_size, tosend);
	LWIP_INFO("fd is sent: %d", tosend);
	sleep(10);
	LWIP_INFO("Closing the socket");
	close(socket2dbus);

}

/**
 * Handles proxied connect(2) requests.
 */
void serving_connect_proxy(int sock2client, struct del_pkt_socketcall_connect_proxy *pkt) {

	struct sockaddr_un addr;
	bzero(&addr, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	int len;

	int socket2dbus = socket(PF_LOCAL, pkt->sockType, 0);
	len = pkt->addrlen;

	struct del_pkt_socketcall_connect_proxy_response response = lwip_del_getPktResponse(socketcall_connect_proxy);

	LWIP_INFO("Calling connect to path %s", ((struct sockaddr_un *)(pkt->addr))->sun_path);
	/* if (connect(socket2dbus, (struct sockaddr *) &addr, len) < 0){ */
	if (connect(socket2dbus, (struct sockaddr *)&pkt->addr, len) < 0){
		LWIP_INFO("Failed to connect to the destination %s!!!", ((struct sockaddr_un *)(pkt->addr))->sun_path);

		response.l_isError = 1;
		response.l_rv = -errno;
		if (!SEND_DEL_PKT_CORRECT(sock2client, response))
			LWIP_CRITICAL("Failed to send the packet back to the process");
		else
			LWIP_INFO("Connect to the destination failed, response to the apps");

	}
	else {

		LWIP_INFO("Connect to path %s is successful", ((struct sockaddr_un *)(pkt->addr))->sun_path);
		response.l_isError = 0;
		response.l_rv = 0;
		if (!SEND_DEL_PKT_CORRECT(sock2client, response))
			LWIP_CRITICAL("Failed to send the packet back to the process");
		else
			LWIP_INFO("Telling apps that it is done!!!");

		pthread_t sendmsg_recvmsg_thread1, sendmsg_recvmsg_thread2;

		int sockets[2];
		sockets[0] = socket2dbus;
		sockets[1] = sock2client;

		if (pthread_create(&sendmsg_recvmsg_thread1,NULL,&start_generic_proxy_msg,(void*)sockets)) {
		  LWIP_CRITICAL("Failed to create thread (errno: %d)", errno);
		}

		int sockets2[2];
		sockets2[1] = socket2dbus;
		sockets2[0] = sock2client;

		if (pthread_create(&sendmsg_recvmsg_thread2,NULL,&start_generic_proxy_msg,(void*)sockets2)) {
		  LWIP_CRITICAL("Failed to create thread (errno: %d)", errno);
		}

		pthread_join(sendmsg_recvmsg_thread1, NULL);
		pthread_join(sendmsg_recvmsg_thread2, NULL);

	}

	close(socket2dbus);
	return;
}

/**
 * Executes in each worker thread.
 *
 * Calls either serving_connect_proxy or serving_connect_fd based
 * on intercepted syscall name.
 */
void *serving_connection(void *arg)
{

	int newfd = *(int *)arg;
	free(arg);

	int on = 1;
	setsockopt(newfd, SOL_SOCKET, CREDOPT, &on, sizeof(on));

	char message[PATH_MAX*2];

	int ret;
	int message_size;

	ret = recv(newfd, &message_size, sizeof(int), MSG_PEEK);
	if (ret <= 0) {
		if (ret == -1)
			LWIP_CRITICAL("generic-proxy: Connection Recv error: %d", errno);
		goto out;
	}

	if (message_size > sizeof(message)) {
		LWIP_CRITICAL("Message size is too big to be handled");
		goto out;
	}

	ret = recv(newfd, &message, message_size, 0);

	switch (*(int *)(message + 4)) { /* Switching on syscall name */
		case SYS_socketcall_connect_proxy: serving_connect_proxy(newfd, (struct del_pkt_socketcall_connect_proxy *)&message); break;
		case SYS_socketcall_connect_fd: serving_connect_fd(newfd, (struct del_pkt_socketcall_connect_fd *)&message); break;
		default: {
				 LWIP_CRITICAL("Wrong syscall number !!!: receved: %d, expected: %d", *(int *)(message + 4), SYS_socketcall_connect_proxy);
				 goto out;
		}
	}


out:
	close(newfd);
	return 0;
} 

/**
 * Starts a proxy thread.
 *
 * The proxy thread waits for requests on socket LWIP_DAEMON_COMMUNICATION_PATH/all-connect.
 * When it receives a new request, it spawns a new thread to serve the connection.
 *
 * It appears that proxy threads are specifically responsible for handling socket-related
 * system calls (see socketcall(2)).
 */
void *start_generic_proxy(void *arg)
{

	int sockfd, size;
	unsigned int len;

	struct sockaddr_un addr, client_addr;
	char *per_process_id = (char *)arg; /* NOTE: always "all" */
	char proxy_listen_path[PATH_MAX];


	sockfd = socket(PF_LOCAL, SOCK_STREAM, 0);
	fcntl(sockfd, F_SETFD, FD_CLOEXEC);

	if(sockfd < 0) {
		LWIP_CRITICAL("socket fail in generic proxy: %d", errno);
		return 0;
	}

	sprintf(proxy_listen_path, LWIP_DAEMON_COMMUNICATION_PATH "/%s-connect", per_process_id);
	unlink(proxy_listen_path);

	bzero(&addr, sizeof(addr));
	addr.sun_family = PF_LOCAL;
	strcpy(addr.sun_path, proxy_listen_path);

#ifdef LWIP_OS_BSD
	size = (__offsetof(struct sockaddr_un, sun_path) + strlen(addr.sun_path) + 1);
#elif defined LWIP_OS_LINUX
	size = (offsetof(struct sockaddr_un, sun_path) + strlen(addr.sun_path) + 1);
#endif

	if (bind(sockfd, (struct sockaddr *)&addr, size) < 0) {
		LWIP_CRITICAL("proxy bind failed!, errno: %d", errno);
		goto closefd;
	}

	LWIP_INFO("binding on the proxy path %s successfully!", proxy_listen_path);

	chmod(proxy_listen_path, S_IRWXU | S_IRWXG | S_IRWXO);

	if(listen(sockfd, 5) < 0) {
		LWIP_INFO("listen failed, errno: %d", errno);
		return 0; 
	}

	while(1) {
		LWIP_INFO("generic proxy-server new block on accept");
		int *newfd = (int *) malloc(sizeof(int));
		*newfd = accept(sockfd, (struct sockaddr*)&client_addr, &len);
		LWIP_INFO("generic proxy-server got an accept, %d", *newfd);

		pthread_t sendmsg_recvmsg_thread;
		pthread_create(&sendmsg_recvmsg_thread, NULL, &serving_connection, (void*)newfd);
	}

closefd:
	close(sockfd);

	return 0;
}
