#include <stdio.h>
#include <grp.h>
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

/* The daemon will be responsible for receiving and responding to delegated syscalls. */
static int exit_flag = 0;
static char per_process_daemon_path[PATH_MAX];

/**
 * Starts the server thread.
 *
 * The main server thread accepts connections from untrusted processes and * spawns worker threads to handle requests from each.
 */
void *start_server(void *arg) {
	/* Behaves like a typical server -- 
		it will accept connections on the UNIX domain socket, 
		spawns a thread to handle the request, 
		and repeat this process ad infinitum. */

	/* Path bound to: "/home/" SIP_REAL_USERNAME "/sip_daemon" */

	// Set number of clients for all threads to 0
	int i;
	for(i = 0; i < DAEMON_MAX_CONNECTION; i++)
		threads[i].no_clients = 0;
	
	// Create UNIX domain socket (linux)
	int sockfd = socket(PF_UNIX, SOCK_SEQPACKET, 0);
	if (sockfd < 0) {
		sip_error("Creating socket failed! Errno: %d", errno);
		return 0;
	}

	/* Create a UNIX domain socket and bind it to a known pathname -- in our case, something like /sip/communication. */
	struct sockaddr_un addr, client_addr;
	char *per_process_id = (char *)arg; /* NOTE: Will always be "all" */
	sprintf(per_process_daemon_path, SIP_DAEMON_COMMUNICATION_PATH "/%s", per_process_id);
	sip_info("per_process_daemon_path is %s", per_process_daemon_path);
	unlink(per_process_daemon_path); //makes sure it gets deleted when there are no remaining links
	bzero(&addr, sizeof(addr)); // zero out address
	addr.sun_family = AF_UNIX; // socket for local communications
	unsigned int len = sizeof(addr.sun_family) + sprintf(addr.sun_path, "%s", per_process_daemon_path);

	/* Binds socket to per_process_daemon_path. Any process can connect to this path to send a delegated request to the server. */
	int ret = bind(sockfd, (struct sockaddr*)&addr, len);
	if(ret < 0) {
		sip_error("Bind failed! Errno: %d", errno);
		return 0;
	}
	// chmod the socket so that anyone can connect to it
	chmod(per_process_daemon_path, S_IRWXU | S_IRWXG | S_IRWXO);
	// Begin listening for socket connections
	if(listen(sockfd, DAEMON_MAX_CONNECTION) < 0) {
		sip_error("Listen failed! Errno %d", errno);
		return 0; 
	}

	/* The threads will run a routine that decodes the syscall arguments and then calls an appropriate handler. There should be handlers for all of the syscalls that have files in lwip_new/lwip_systems/daemon/base. */
	thpool_t *threadpool;
	threadpool = thpool_init(15);	// Create a thread pool of 15

	/* NOTE: these vars are "unused". */
	uid_t uid;
	gid_t gid;
	//while on socket
	while(!exit_flag) {
		// Accept connections on the socket as they come
		int newfd = accept(sockfd, (struct sockaddr*)&client_addr, &len);
		if(newfd < 0) {
			LWIP_INFO("accept failed");
			exit(0);	// Is the break needed after this process exits?
			break;
		}
		sip_info("Server accepted FD: %d", newfd);

		// Right now, this function just does logging... but it could:
			// Get link to executable path
			// Check ownership and group ownership of executable using sip_path_to_level and if the value returned is HIGH or -1, then abort (don't add to pool).
			// This would confirm that the peer process is running with the untrusted userid
		// 			is_connection_valid(newfd,&uid,&gid); 

		// Add to the thread pool
		thpool_add_work(threadpool, (void *)handle_request, (void *)newfd);
	}

	// Not sure where exit_flag will become 1, but if it did:
	thpool_destroy(threadpool);
	unlink(per_process_daemon_path);

	return 0;
}

/*
 * Handles a request from an untrusted process
 */
void handle_request(int newfd) {

}


int main(int argc, char **argv) {
	// Sets the supplementary group IDs for the calling process
	gid_t list[] = {SIP_REAL_USERID, SIP_UNTRUSTED_USERID};
	setgroups(2, list);
	// Q: Why are they providing userids as arguments to setresgid? Group IDs are expected. 
	setresgid(SIP_REAL_USERID, SIP_UNTRUSTED_USERID, SIP_REAL_USERID);
	umask(S_IWOTH);
	setresuid(SIP_REAL_USERID, SIP_REAL_USERID, SIP_REAL_USERID/*SIP_UNTRUSTED_USERID*/);

	sip_info("process ruid: %d, euid: %d", getuid(), geteuid());
	sip_info("daemon pid: %d", getpid());

	// Create thread for the server
	pthread_t server_thread;
	int result = pthread_create(&server_thread, NULL, &start_server, (void*)argv[1]);

	// Delegator main thread is still in the sleep loop
	while (!exit_flag) {
		sleep(30);
	}

	return result;
}