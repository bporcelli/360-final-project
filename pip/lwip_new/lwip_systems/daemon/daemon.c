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

#include "daemon.h"
#include "delegator.h"
#include "proxy.h"

#include "base.h"
//#include "iso.h"

#include "thpool.h"

#include "lwip_del_conf.h"
#include "lwip_debug.h"
#include "lwip_common.h"
#include <sys/syscall.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <sys/param.h>
#include <sys/un.h>

#include <stdio.h>

#include <grp.h>

#define daemon_case(syscallName) \
  case SYS_ ##syscallName: { \
	  struct del_pkt_ ##syscallName ##_response response = lwip_del_getPktResponse(syscallName); \
	  process_ ##syscallName((struct del_pkt_ ##syscallName *)&message, &response);  \
    if (!SEND_DEL_PKT_CORRECT(newfd, response)) \
      LWIP_CRITICAL("Failed to send the delegator response."); \
    break; \
  }

static int exit_flag = 0;
static char per_process_daemon_path[PATH_MAX];

//void * handle_request(void *arg)
void handle_request(int newfd) {

	int syscall_num = -1;
	int ret;

	//  uid_t uid;
	//  gid_t gid;

	int breakloop = 0;
//	int tid = *((int*)arg);
//	int newfd = threads[tid].newfd;
	int message_size = 0;

	static char message[PATH_MAX*3];
	int fd_received = -1;

	while(!breakloop && !exit_flag)
	{
		ret = recv(newfd, message, sizeof(int)*2, MSG_PEEK);
		message_size = ((int *)message)[0];
		syscall_num = ((int *)message)[1];

		if (ret == 0) {
			breakloop = 1;
			break;
		}

		if (LWIP_unlikely(ret < 0)) {
			LWIP_CRITICAL("Failed to receive message size: ret: %d, errno: %d", ret, errno);
			breakloop = 1;
			break;
		}

		if (LWIP_unlikely(message_size > sizeof(message))) {
			LWIP_CRITICAL("Message size declared is greater than what is supported %d, %d", message_size, sizeof(message));
			breakloop = 1;
			break;
		} 

		if (syscall_num == SYS_fchmod) {
			ret = lwip_util_recv_fd(newfd, message, message_size, &fd_received);
		} else
			ret = recv(newfd, message, message_size, 0);

		if(LWIP_unlikely(ret != message_size)) {
			//COnnection closed.
			LWIP_CRITICAL("The message received is not the same as the size given: %d vs %d", message_size, ret);
			breakloop = 1;
			break;
		}

		syscall_num = *(int *)(message+4);
/*
		if (lwip_util_isInsideContainer()) {
			switch(syscall_num) {

				daemon_iso_case(faccessat);

				case SYS_open: {
				       int rv;
				       struct del_pkt_open_response response = lwip_del_getPktResponse(open);
				       rv = process_iso_open((struct del_pkt_open *)&message, &response);
				       lwip_util_send_fd(newfd, &response, response.l_size, rv);
				       if (rv >= 0)
					       close (rv);
				       break;
				}

				daemon_iso_case(fchmodat);
				daemon_iso_case(fchownat);
				daemon_iso_case(mkdir);
				daemon_iso_case(rename);
				daemon_iso_case(symlink);
				daemon_iso_case(unlinkat);

				default:
					goto base_handler;
			}
			continue;
		}

base_handler:
*/
		switch(syscall_num) {
			
			//access
			daemon_case(faccessat);

			//chmod
			daemon_case(fchmodat);

			//chown
			daemon_case(fchownat);

			//symlink
			daemon_case(symlink);
			daemon_case(readlink);
			daemon_case(linkat);

			//mkdir
			daemon_case(mkdir);

			//open
			case SYS_open: {
				int rv;
				struct del_pkt_open_response response = lwip_del_getPktResponse(open);
				rv = process_open((struct del_pkt_open *)&message, &response);
				lwip_util_send_fd(newfd, &response, response.l_size, rv);
				if (rv >= 0)
					close (rv);
				break;
			}

			case SYS_fchmod: {
				int rv;
				struct del_pkt_fchmod_response response = lwip_del_getPktResponse(fchmod);
				((struct del_pkt_fchmod *)&message)->fd = fd_received;
				rv = process_fchmod((struct del_pkt_fchmod *)&message, &response);
				close(fd_received);
				if (!SEND_DEL_PKT_CORRECT(newfd, response))
					LWIP_CRITICAL("Failed to send the delegator response.");
				break;
			 }


			//rename
			daemon_case(rename);

			//socket
			case SYS_socketcall_connect_fd: {
				int rv;
				struct del_pkt_socketcall_connect_fd_response response = lwip_del_getPktResponse(socketcall_connect_fd);
				rv = process_socketcall_connect_fd((struct del_pkt_socketcall_connect_fd *)&message, &response);
				lwip_util_send_fd(newfd, &response, response.l_size, rv);
				if (rv >= 0)
					close (rv);
				break;
			}
			case SYS_socketcall_bind: {
				int rv;
				struct del_pkt_socketcall_bind_response response = lwip_del_getPktResponse(socketcall_bind);
				rv = process_socketcall_bind((struct del_pkt_socketcall_bind *)&message, &response);
				lwip_util_send_fd(newfd, &response, sizeof(response), rv);
				if (rv >= 0)
					close (rv);

				break; 
			}



/*			//stat
#if 0
#ifdef LWIP_OS_BSD
			daemon_case(fstatat);
#elif defined LWIP_OS_LINUX
			daemon_case(fstatat64);
#endif
#endif*/
			daemon_case(lwip_fstatat);


			//statfs
			daemon_case(statfs);
#ifdef LWIP_OS_LINUX
			daemon_case(statfs64);
#endif

			//unlink
			daemon_case(unlinkat);

			//utime
			daemon_case(utimes);
#ifdef LWIP_OS_LINUX
			daemon_case(utime);
			daemon_case(utimensat);
#elif defined LWIP_OS_BSD
			daemon_case(lutimes);
#endif

			default: {
					 LWIP_CRITICAL("Daemon received unexpected syscall number %d", syscall_num);
					 break;
				 }
		}//switch

	}
	LWIP_INFO("Connection closed: %d", newfd);
	close(newfd);
//	threads[tid].no_clients = 0;
}



int find_free_thread() {
	int i,pos = -1;
	for(i = 0; i < DAEMON_MAX_CONNECTION; i++) {
		if(threads[i].no_clients == 0) {
			pos = i;
			threads[i].no_clients = 1;
			break;
		}
	}
	return pos;
}


int is_connection_valid(int sockfd, uid_t *uid, gid_t *gid) {

#ifdef LWIP_OS_BSD
	/* FreeBSD specific */
	getpeereid(sockfd, uid, gid);
#elif defined LWIP_OS_LINUX
	struct ucred creds;
	unsigned int len = sizeof(struct ucred);
	char readPath_exe[PATH_MAX], readPath[PATH_MAX];

	if(getsockopt(sockfd,SOL_SOCKET,SO_PEERCRED,&creds,&len)) {
		LWIP_INFO("cannot get creds");
		return -1;
	}
	*uid = creds.uid;
	*gid = creds.gid;
	LWIP_INFO("the creds pid %d",creds.pid); 

	memset(readPath_exe, 0, PATH_MAX);
	sprintf(readPath_exe, "/proc/%d/exe", creds.pid);
	memset(readPath, 0, PATH_MAX);
	readlink(readPath_exe, readPath, PATH_MAX);
	LWIP_INFO("From process: %s, %d", readPath, creds.pid);
#endif
	return 1;
}


void *start_server(void *arg) {
	int sockfd,ret, i;
	unsigned int len;
	struct sockaddr_un addr,client_addr;

	uid_t uid;
	gid_t gid;

	char *per_process_id = (char *)arg;

	LWIP_INFO("Starting the server"); 

	for(i = 0; i < DAEMON_MAX_CONNECTION; i++)
		threads[i].no_clients = 0;

#ifdef LWIP_OS_BSD
	sockfd = socket(PF_UNIX, SOCK_STREAM, 0);
#elif defined LWIP_OS_LINUX
	sockfd = socket(PF_UNIX, SOCK_SEQPACKET, 0);
#endif
	
	if(sockfd < 0) {
		LWIP_CRITICAL("socket fail, errno: %d", errno);
		return 0;
	}

	sprintf(per_process_daemon_path, LWIP_DAEMON_COMMUNICATION_PATH "/%s", per_process_id);

	LWIP_INFO("per_process_daemon_path is %s", per_process_daemon_path);

	unlink(per_process_daemon_path);

	bzero(&addr, sizeof(addr));
	addr.sun_family = AF_UNIX;
#ifdef LWIP_OS_BSD
	len = sizeof(addr.sun_family) + sprintf(addr.sun_path, "%s", per_process_daemon_path) + 1; /* FreeBSD requires + 1 */
#elif defined LWIP_OS_LINUX
	len = sizeof(addr.sun_family) + sprintf(addr.sun_path, "%s", per_process_daemon_path); /* FreeBSD requires + 1 */
#endif

	ret = bind(sockfd, (struct sockaddr*)&addr, len);
	if(ret < 0) {
		LWIP_CRITICAL("bind failed, errno: %d", errno);
		return 0;
	}

	//chmod the socket so that anyone can connect to it
	//chmod(DAEMON_PATH, S_IRWXU | S_IRWXG | S_IRWXO);
	chmod(per_process_daemon_path, S_IRWXU | S_IRWXG | S_IRWXO);

	if(listen(sockfd, DAEMON_MAX_CONNECTION) < 0) {
		LWIP_CRITICAL("listen failed: errno %d", errno);
		return 0; 
	}


	thpool_t *threadpool;
	threadpool = thpool_init(15);

	while(!exit_flag) {

		int newfd = accept(sockfd, (struct sockaddr*)&client_addr, &len);
		LWIP_INFO("server got an accept, %d", newfd);
		if(newfd < 0) {
			LWIP_INFO("accept failed");
			exit(0);
			break;
		}
		is_connection_valid(newfd,&uid,&gid);

		thpool_add_work(threadpool, (void *)handle_request, (void *)newfd);

/*

		ret = find_free_thread();
		if(ret < 0) {
			LWIP_CRITICAL("no thread is free");
			close(newfd);
			return 0;
		}	
		//start a new thread to manage this connection
		threads[ret].newfd = newfd;
		int rv = 0, retry = 0;
tryagain:
		if ((rv = pthread_create(&threads[ret].tid, NULL, &handle_request, (void *)&ret)) != 0) {
			LWIP_UNEXPECTED("pthread create for daemon is error: %d, retry: %d", rv, retry);
			if (retry++ < 5) {
				sleep(1);
				goto tryagain;
			}
		} else {
			LWIP_UNEXPECTED("pthread create succeed");
		}
*/
	}//while on socket

	thpool_destroy(threadpool);

	unlink(per_process_daemon_path);

	return 0;
}

int main(int argc, char **argv)
{
	pthread_t server_thread, proxy_thread;

	int ret;


	gid_t list[] = {LWIP_CF_REAL_USERID, LWIP_CF_UNTRUSTED_USERID};

	setgroups(2, list);
	
//	setresgid(LWIP_CF_REAL_USERID, LWIP_CF_REAL_USERID, LWIP_CF_REAL_USERID);
	setresgid(LWIP_CF_REAL_USERID, LWIP_CF_UNTRUSTED_USERID, LWIP_CF_REAL_USERID);
	umask(S_IWOTH);
	setresuid(LWIP_CF_REAL_USERID, LWIP_CF_REAL_USERID, LWIP_CF_REAL_USERID/*LWIP_CF_UNTRUSTED_USERID*/);

	LWIP_INFO("process ruid: %d, euid: %d", getuid(), geteuid());

	LWIP_INFO("daemon pid: %d", getpid());
	if (argv[1])
		LWIP_INFO("arg1 = %s", argv[1]);
	else
		LWIP_INFO("arg1 is NULL");

	ret = pthread_create(&server_thread,NULL,&start_server,(void*)argv[1]);
	ret = pthread_create(&proxy_thread,NULL,&start_generic_proxy,(void*)argv[1]);

	//not doing pthread join as not to wait for the sever to end

	while(!exit_flag) {
		sleep(30);
		LWIP_INFO("Delegator main thread is still in the sleep loop!");	
	}

	LWIP_INFO("Delegator main thread is now exit!");

	return ret;
}
