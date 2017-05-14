/* daemon. Responsible for receiving and responding to delegated syscalls. */

#define _GNU_SOURCE

#include <unistd.h>
#include <stdio.h>
#include <grp.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/un.h>

#include "common.h"   // Generated from template
#include "logger.h"   // Logging
#include "packet.h"   // Packet manipulation methods
#include "handlers.h" // Syscall handlers

#define DAEMON_MAX_CONNECTION 1000

static int exit_flag = 0;

/**
 * Handles a request from an untrusted process.
 *
 * @param void* pointer to client socket descriptor.
 */
void *handle_connection(void* arg) {
	pthread_detach(pthread_self());	/* Let OS reap thread resources */

	int clientfd = *(int*) arg;
	free(arg);

	sip_info("Spawned thread to handle connection with descriptor %d\n", clientfd);

	struct msghdr request;
	sip_packet_init(&request);
	long callnum;

	while (1) {

		/* Initially, we allocate enough space to store the sycall num only. */
		SIP_PKT_SET(&request, 0, SIP_ARG, long, &callnum);

		/* Peek into message queue to get syscall number. */
		ssize_t received = recvmsg(clientfd, &request, MSG_PEEK);

		sip_info("Received %ld bytes from client.\n", received);

		if (received == 0) {
			sip_info("Client closed connection. Exiting thread loop.\n");
			sip_packet_destroy(&request);
			break;
		}

		sip_info("Received syscall request with number %ld\n", SIP_PKT_GET(&request, 0, long));

		/* Initialize msghdr struct for response. */
		// struct msghdr response;
		// sip_packet_init(&response);

		// /* First arg in packet will be syscall num. */
		// long callnum = SIP_PKT_GET(&msg, 0, long);

		// sip_info("callnum is %ld\n", callnum);

		// switch (callnum) {
		// 	case SYS_delegatortest:
		// 		sip_info("Delegator received delegatortest call.\n");
		// 		handle_delegatortest(&msg, &response);
		// 	break;
		// 	default:
		// 		sip_error("Unhandled delegated syscall: %d\n", callnum);
		// 		continue;
		// }

		// /* Send back response */
		// ssize_t sent = sendmsg(clientfd, &response, 0);

		// if (sent == -1) {
		// 	sip_error("Failed to send response to client: %s\n", strerror(errno));
		// 	return NULL; /* TODO: appropriate? */
		// }
	}

	sip_packet_destroy(&request);

	sip_info("Exiting thread for descriptor %d.\n", clientfd);

	/* Clean up */
	close(clientfd);
}

int main(int argc, char **argv) {

	struct sockaddr_un addr, client_addr;

	int addrlen, listenfd, clientfd, *fdcopy;

	/* Set real, effective, and saved GID/UID. NOTE: the effective GID
	   is set to SIP_UNTRUSTED_USERID so new files are automatically
	   marked with a low integrity label. */
	setresgid(SIP_REAL_USERID, SIP_UNTRUSTED_USERID, SIP_REAL_USERID);
	setresuid(SIP_REAL_USERID, SIP_REAL_USERID, SIP_REAL_USERID);

	sip_info("Daemon started. RUID is %d, EUID is %d, PID is %d.\n",
		     getuid(), geteuid(), getpid());

	/* Create UNIX domain socket. */
	listenfd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	
	if (listenfd < 0) {
		sip_error("Creating socket failed: %s\n", strerror(errno));
		return 1;
	}

	/* Bind to SIP_DAEMON_COMMUNICATION_PATH/all */
	bzero(&addr, sizeof(addr));
	
	addr.sun_family = AF_UNIX; // socket for local communication
	addrlen = sizeof(addr.sun_family) + sprintf(addr.sun_path, "%s/all", SIP_DAEMON_COMMUNICATION_PATH);

	unlink(SIP_DAEMON_COMMUNICATION_PATH "/all"); // allow re-binding when server exits

	if(bind(listenfd, (struct sockaddr*)&addr, addrlen) < 0) {
		sip_error("Failed to bind socket %d to %s: %s.\n", listenfd, SIP_DAEMON_COMMUNICATION_PATH "/all", strerror(errno));
		return 1;
	}

	/* Allow all to connect to socket. */
	chmod(SIP_DAEMON_COMMUNICATION_PATH "/all", S_IRWXU | S_IRWXG | S_IRWXO);

	/* Listen for connections -- allow up to DAEMON_MAX_CONNECTION pending
	   connection requests at any given time. */
	if(listen(listenfd, DAEMON_MAX_CONNECTION) < 0) {
		sip_error("Listen error: %s.\n", strerror(errno));
		return 1;
	}

	/* Wait for new connections in an infinite loop. When a connection arrives,
	   spawn a thread to handle it. */
	pthread_t tid;

	while (!exit_flag) {
		clientfd = accept(listenfd, (struct sockaddr*)&client_addr, &addrlen);
		sip_info("Daemon received a connection request!\n");

		if (clientfd < 0) {
			sip_error("Accept failed: %s. Aborting.\n", strerror(errno));
			exit(1);
		}

		// TODO: NEED TO DO THIS? I THINK WE CAN HANDLE THIS PERMS ON COM PATH.
		// Right now, this function just does logging... but it could:
			// Get link to executable path
			// Check ownership and group ownership of executable using sip_path_to_level and if the value returned is HIGH or -1, then abort (don't add to pool).
			// This would confirm that the peer process is running with the untrusted userid
		// 			is_connection_valid(newfd,&uid,&gid); 

		if ((fdcopy = malloc(sizeof(int))) == NULL) {
			sip_error("Couldn't accept connection: out of memory.\n");
			continue; /* Maybe some memory will free up? */
		}
		*fdcopy = clientfd;
		
		pthread_create(&tid, NULL, &handle_connection, fdcopy);
	}

	/* Clean up */
	close(listenfd);

	return 0;
}
