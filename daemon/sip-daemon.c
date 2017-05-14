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
#include "handlers.h" // Syscall handlers
#include "packets.h"  // Packet structs
#include "util.h"     // sip_send_fd

#define DAEMON_MAX_CONNECTION 1000

static int exit_flag = 0;

/**
 * Handles a request from an untrusted process.
 *
 * @param void* pointer to client socket descriptor.
 */
void *handle_connection(void* arg) {
	
	pthread_detach(pthread_self()); /* Let OS reap thread resources */

	struct sip_response response;
	ssize_t sent = 0, received = 0;
	void* packet = NULL;
	int clientfd = *(int*) arg, pkt_head[2], respfd;
	free(arg);

	while (1) {

		respfd = -1; /* fd to include in response (-1 for none) */

		/* Read packet header to determine call number & packet size. */
	 	received = recv(clientfd, &pkt_head, 2 * sizeof(int), MSG_PEEK);

		if (received == 0) {
			sip_info("Client closed connection. Exiting thread loop.\n");
			break;
		}

		/* Allocate space for packet. */
		packet = realloc(packet, pkt_head[1]);	
		
		if (packet == NULL) {
			sip_error("Can't serve request: out of memory.\n");
			break;
		}

		/* Read entire packet. */
		received = recv(clientfd, packet, pkt_head[1], 0);

		if (received < 0 || received != pkt_head[1]) {
			sip_error("Failed to read packet: %s\n", strerror(errno));
			break;
		}

		sip_info("Received delegated syscall request. Call number is %d.\n", pkt_head[0]);

		/* Based on call number, execute an appropriate handler. Note that
		   calls that send back file descriptors need special handling, as
		   we must sendmsg instead of send to send back the response. */ 
		switch (pkt_head[0]) {
			case SYS_delegatortest:
				handle_delegatortest(packet, &response);
			break;
			case SYS_faccessat:
				handle_faccessat(packet, &response);
			break;
			case SYS_fchmodat:
				handle_fchmodat(packet, &response);
			break;
			case SYS_fchownat:
				handle_fchownat(packet, &response);
			break;
			case SYS_fstatat:
				handle_fstatat(packet, &response);
			break;
			case SYS_statvfs:
				handle_statvfs(packet, &response);
			break;
			case SYS_linkat:
				handle_linkat(packet, &response);
			break;
			case SYS_mkdirat:
				handle_mkdirat(packet, &response);
			break;
			case SYS_mknodat:
				handle_mknodat(packet, &response);
			break;
			case SYS_openat:
				handle_openat(packet, &response);
				respfd = response.rv;
			break;
			case SYS_renameat2:
				handle_renameat2(packet, &response);
			break;
			case SYS_symlinkat:
				handle_symlinkat(packet, &response);
			break;
			case SYS_unlinkat:
				handle_unlinkat(packet, &response);
			break;
			case SYS_utime:
				handle_utime(packet, &response);
			break;
			case SYS_utimes:
				handle_utimes(packet, &response);
			break;
			case SYS_utimensat:
				handle_utimensat(packet, &response);
			break;
			case SYS_bind:
				handle_bind(packet, &response);
				respfd = response.rv;
			break;
			case SYS_connect:
				handle_connect(packet, &response);
				respfd = response.rv;
			break;
			default:
				sip_error("Unhandled delegated syscall: %d\n", pkt_head[0]);
				continue;
		}

		/* Send back response */
		sent = send(clientfd, &response, sizeof(struct sip_response), 0);

		if (sent != sizeof(struct sip_response)) {
			sip_error("Failed to send response to client: %s\n", strerror(errno));
			break;
		}

		/* Send back descriptor if necessary */
		if (respfd >= 0) {
			if (sip_send_fd(clientfd, respfd) == 0) {
				close(respfd);
			}
		}
	}

	/* Clean up */
	if (packet != NULL)
		free(packet);

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

	while (1) {
		clientfd = accept(listenfd, (struct sockaddr*)&client_addr, &addrlen);

		if (clientfd < 0) {
			sip_error("Accept failed: %s. Aborting.\n", strerror(errno));
			exit(1);
		}

		sip_info("Daemon received a connection request!\n");

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
