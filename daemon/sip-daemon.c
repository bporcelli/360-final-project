/* daemon. Responsible for receiving and responding to delegated syscalls. */

#define _GNU_SOURCE

#include <unistd.h>
#include <stdio.h>
#include <grp.h>
#include <errno.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/un.h>

// From delegator.h
#include <pthread.h>


#include "common.h" // Generated from template
#include "thpool.h"	// Thread pool
#include "logger.h" // Logging

#define DAEMON_MAX_CONNECTION 1000
struct Thread {
	pthread_t tid;
	int no_clients;
	int newfd;
}threads[DAEMON_MAX_CONNECTION];

static int exit_flag = 0;

/*
 * Handles a request from an untrusted process
 */
void handle_request(int newfd) {

}


int main(int argc, char **argv) {

	// TODO: SET PERMS ON SIP_DAEMON_COMMUNICATION_PATH SUCH THAT
	// ONLY BENIGN USER AND UNTRUSTED USER CAN RWX
	struct sockaddr_un addr;
	int addrlen, listenfd, clientfd;

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

	/* Bind to SIP_DAEMON_COMMUNICATION_PATH */
	bzero(&addr, sizeof(addr));
	
	addr.sun_family = AF_UNIX // socket for local communication
	addrlen = sizeof(addr.sun_family) + sprintf(addr.sun_path, "%s", SIP_DAEMON_COMMUNICATION_PATH);

	if(bind(listenfd, (struct sockaddr*)&addr, addrlen) < 0) {
		sip_error("Failed to bind socket %d to %s: %s.\n", listenfd, SIP_DAEMON_COMMUNICATION_PATH, strerror(errno));
		return 1;
	}

	/* Listen for connections -- allow up to DAEMON_MAX_CONNECTION pending
	   connection requests at any given time. */
	if(listen(listenfd, DAEMON_MAX_CONNECTION) < 0) {
		sip_error("Listen error: %s.\n", strerror(errno));
		return 1;
	}

	/* Wait for new connections in an infinite loop. When a connection arrives,
	   spawn a thread to handle it. */
	while (true) {
		clientfd = accept(listenfd, NULL, NULL);
		
		if (clientfd < 0) {
			sip_error("Accept failed: %s. Aborting.\n", strerror(errno));
			exit(1);
		}

		sip_info("Server accepted FD: %d", clientfd);

		// TODO: NEED TO DO THIS? I THINK WE CAN HANDLE THIS PERMS ON COM PATH.
		// Right now, this function just does logging... but it could:
			// Get link to executable path
			// Check ownership and group ownership of executable using sip_path_to_level and if the value returned is HIGH or -1, then abort (don't add to pool).
			// This would confirm that the peer process is running with the untrusted userid
		// 			is_connection_valid(newfd,&uid,&gid); 

		// TODO: CREATE THREAD TO HANDLE CONNECTION; DETACH
		// pthread_create(&server_thread, NULL, &start_server, (void*)argv[1]);
	}

	return 0;
}