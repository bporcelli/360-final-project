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
#include "lwip_delegator_connection.h"
#include "lwip_debug.h"
#include "lwip_syscall_handler.h"

#include <sys/syscall.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>

int sh_delegatorSocket = -1;

/**
 * This function starts the trusted helper by running the "daemon" executable.
 * Note that while the daemon accepts a per-process ID as an argument, the ID
 * is being set to "all" for every process. The authors must have decided against
 * using unique IDs for each process.
 */
void sh_startDelegator()
{
	if (lwip_isIN_mode) {
		LWIP_INFO("Root delegator process should have been started outside of the chroot");
		sleep(1);
		return;
	}
	
	char *argv[] = {
		"daemon",
		"54321",
		NULL
	};
	char per_process_id[sizeof(int)*3];
	sprintf(per_process_id, "%s", "all");

	argv[1] = per_process_id;

	pid_t pID = fork();
	if (pID == 0) {
		LWIP_INFO("Starting the delegator process ...");
		execv(LWIP_DAEMON_EXE_PATH, argv);
		LWIP_CRITICAL("Starting the delegator process failed?, errno: %d", errno);
	}
	sleep(1);
}

void sh_closeDelegatorSocket()
{
	if (sh_delegatorSocket != -1) {
		close(sh_delegatorSocket);
		sh_delegatorSocket = -1;
	}
}


/**
 * This function is used to send delegated system calls to the trusted helper.
 *
 * It first checks whether a socket for communicating with the trusted helper
 * is open (line 89). If not, it creates a new socket (line 95) and attempts
 * to connect to the helper (line 122). If the helper is not yet started, it
 * calls sh_startDelegator() (line 129).
 *
 * Once the delegator socket is open, it sends the delegated syscall to the
 * helper process (line 140).
 */
int sh_sendPkt2delegator(struct del_pkt *pkt)
{
	int len;
	struct sockaddr_un addr;
	int retry = 0;

	if (sh_delegatorSocket != -1)
		goto send_data;

#ifdef LWIP_OS_BSD
	sh_delegatorSocket = socket(PF_UNIX, SOCK_STREAM, 0); 
#elif defined LWIP_OS_LINUX
	sh_delegatorSocket = socket(PF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0); 
#endif
	if (sh_delegatorSocket < 0) {
		LWIP_ERROR("Failed to create socket to delegator!");
		return -1;
	}

	if (sh_delegatorSocket < 20)
		if (dup2(sh_delegatorSocket, 99) != -1) {
			close(sh_delegatorSocket);
			sh_delegatorSocket = 99;
		}

	if (fcntl(sh_delegatorSocket, F_SETFD, FD_CLOEXEC) < 0)
		LWIP_ERROR("Failed to set the socket to be closed on exec, errno: %d", errno);

	bzero(&addr, sizeof(addr));
	addr.sun_family = AF_UNIX;

	char per_process_daemon_path[PATH_MAX];

	if (lwip_isIN_mode)
		sprintf(per_process_daemon_path, LWIP_ROOT_DAEMON_COMMUNICATION_PATH "/install");
	else
		sprintf(per_process_daemon_path, LWIP_DAEMON_COMMUNICATION_PATH "/all"); /* NOTE: per-process ID always "all" */

	len = sizeof(addr.sun_family) + sprintf(addr.sun_path, "%s", per_process_daemon_path);
	LWIP_INFO("per_process_daemon_path is %s, connect socket is %d", per_process_daemon_path, sh_delegatorSocket);

connect_to_delegator:

	if (connect(sh_delegatorSocket, (struct sockaddr *) &addr, sizeof(addr)) < 0){
		retry++;
		LWIP_INFO("Connect failed, errno: %d", errno);
		if (retry < 3 && (errno == ECONNREFUSED || errno == ENOENT)) {
			LWIP_INFO("Connect to delegator failed, calling start process()");
			sh_startDelegator();
			goto connect_to_delegator;
		}
		sh_closeDelegatorSocket();
		LWIP_CRITICAL("Failed to connect after maximum retried");
		return -1;
	}

send_data:
	if (!SEND_DEL_PKT_CORRECT(sh_delegatorSocket, *pkt)) {
		LWIP_CRITICAL("Failed to send the packet");
		return -1;
	}

	return 0;
}


//Return 0 when no problem
int sh_recvPktFromDelegator(struct del_pkt *pkt) {
	int expectedResponseSyscallNo = pkt->l_sysno;

	if (sh_delegatorSocket == -1) {
		LWIP_CRITICAL("Trying to receive on a closed socket!");
		return -1;
	}
	if (!RECV_DEL_PKT_CORRECT(sh_delegatorSocket, *pkt)) {
		LWIP_CRITICAL("Failed to receive the packet from delegator, errno %d", errno);
		return -1;
	}
	if (expectedResponseSyscallNo != pkt->l_sysno) {
		LWIP_CRITICAL("Incorrect response received from delegator: Expected: %d, Received: %d", expectedResponseSyscallNo, pkt->l_sysno);
		return -1;
	}
	return 0;
}


int sh_recvFDFromDelegator(struct del_pkt *response, int *newfd) {
	return lwip_util_recv_fd(sh_delegatorSocket, response, response->l_size, newfd);
}


