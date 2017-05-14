#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include "logger.h"
#include "common.h"

static int sockfd = -1;

/**
 * Start the helper process.
 */
static void sip_delegate_start() {
	pid_t pid;

	char *args[2] = {SIP_DAEMON_PATH, NULL};

	if ((pid = fork()) == 0) {
		execv(SIP_DAEMON_PATH, args);
		sip_error("Failed to start daemon: %s\n", strerror(errno));
		return;
	}

	/* Allow time for helper to bind socket. */
	sleep(1);
}

/**
 * Establish a connection with the helper. If the helper hasn't been started
 * yet, start it.
 *
 * @return 1 on success, 0 on failure.
 */
static int sip_delegate_connect() {
	struct sockaddr_un addr;
	
	int addrlen = 0;
	int attempts = 0;
	int conn = 0;

	if (sockfd > 0) {
		return 1;
	}

	/* Create socket. Set SOCK_CLOEXEC flag so socket is not inherited
	 * by child processes. */
	sockfd = socket(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0);

	if (sockfd == -1) {
		sip_error("Failed to create socket for delegator: %s.\n", strerror(errno));
		return 0;
	}

	/* Get address to connect to. */
	bzero(&addr, sizeof(addr));
	addr.sun_family = AF_UNIX;
	sprintf(addr.sun_path, SIP_DAEMON_COMMUNICATION_PATH "/all");

	/* Attempt connection up to 3 times. */
	do {
		sip_info("Attempting connection client-side.\n");
		conn = connect(sockfd, (struct sockaddr*) &addr, sizeof(addr));
		if (conn < 0) {
			sip_delegate_start();
		}
		attempts++;
	} while (conn < 0 && attempts < 3);

	/* Still not connected? Bail. */
	if (conn < 0) {
		sip_error("Failed to start delegator: %s\n", strerror(errno));
		return 0;
	}

	sip_info("Connection on client side successful!\n");

	return 1;
}

/**
 * Sends a syscall request to the trusted helper and gets the response.
 *
 * @param struct msghdr* request
 * @param struct msghdr* response
 * @return int 0 on success, -1 on error.
 */
static int sip_delegate_get_response(struct msghdr *request, struct msghdr *response) {
	ssize_t sent, received;

	if (!sip_delegate_connect()) {
		return -1;
	}

	sip_info("About to call sendmsg. socket is %d, request is %p.\n", sockfd, request);
	sip_info("iov_len for request is: %zu\n", request->msg_iovlen);
	errno = 0;

	sent = sendmsg(sockfd, request, 0);

	if (sent == -1) {
		sip_error("Failed to send syscall request: %s\n", strerror(errno));
		return -1;
	} else if (sent == 0) {
		sip_error("No data was sent. Error was: %s\n", strerror(errno));
	}

	sip_info("Sent %lu bytes to the helper.\n", sent);
	received = recvmsg(sockfd, response, 0); // TODO: RETURNING BEFORE ACCEPT()
	sip_info("Received %ld bytes from the helper.\n", received);

	if (received <= 0) {
		sip_error("Failed to read syscall response: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

/**
 * This function can be used to delegate a syscall to the trusted helper. It
 * accepts a syscall number and two pointers to msghdr structs. The first is
 * the request, and the second is used to store the response.
 *
 * On success, the function returns the return value obtained from the helper,
 * sets errno, and copies the response into response.
 *
 * @param struct msghdr* request
 * @param struct msghdr* response
 * @return int
 */
int sip_delegate_call(struct msghdr *request, struct msghdr *response) {
	/* Attempt delegated call */
	int ret = sip_delegate_get_response(request, response);

	sip_info("return from sip_delegate_get_response is: %d\n", ret);

	if (ret == -1) {
		sip_error("Failed to send delegated call: %s\n", strerror(errno));
		return -1;
	}

	/* Set response value and errno -- leave it to the caller to extract
	   any other needed values in the response. */
	return 0;
}
