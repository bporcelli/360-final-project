#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include "logger.h"
#include "common.h"
#include "packets.h"

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

	return 1;
}

/**
 * This function can be used to delegate a syscall to the trusted helper. It
 * accepts a pointer to the data to send (one of the structs in packets.h), a
 * the number of bytes to send, and a pointer to a sip_response struct. On
 * error, it returns -1. On success, it returns 0 and copies the response to
 * the response buffer.
 *
 * @param  void* request
 * @param  struct sip_response* response
 * @return int -1 on error, 0 on success.
 */
int sip_delegate_call(void *request, struct sip_response *response) {
	
	struct sip_header *head = (struct sip_header*) request;
	ssize_t sent, received;

	if (!sip_delegate_connect()) {
		return -1;
	}

	sent = send(sockfd, request, head->size, 0);

	if (sent == -1) {
		sip_error("Failed to send syscall request: %s\n", strerror(errno));
		return -1;
	}

	received = recv(sockfd, response, sizeof(struct sip_response), 0);

	if (received <= 0) {
		sip_error("Failed to read syscall response: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

/**
 * Special version of sip_delegate_call that expects a file descriptor in the
 * response. Must be used for calls like openat(2) that return a descriptor.
 */
int sip_delegate_call_fd(void *request, struct sip_response *response) {

	int rv = sip_delegate_call(request, response);

	if (rv == 0 && response->err == 0) {	/* success! expect a descriptor. */

		struct msghdr msg = {0};
		struct cmsghdr *cmsg;
		int myfd[1], *fdptr;
		char data[5];
		struct iovec iov[1];

		/* need to transfer at least one byte of non-ancillary data */
		iov[0].iov_base = &data;
		iov[0].iov_len = 5;

		union {
		   /* ancillary data buffer, wrapped in a union in order to ensure
		      it is suitably aligned */
		   char buf[CMSG_SPACE(sizeof myfd)];
		   struct cmsghdr align;
		} u;

		msg.msg_iov = iov;
		msg.msg_iovlen = 1;
		msg.msg_control = u.buf;
		msg.msg_controllen = sizeof u.buf;

		if (recvmsg(sockfd, &msg, 0) <= 0) {
			sip_error("Failed to receive descriptor from helper: %s\n", strerror(errno));
			return -1;
		}

		cmsg = CMSG_FIRSTHDR(&msg);

		if (cmsg == NULL) {
			sip_error("Failed to receive descriptor from helper: msg_control is empty.\n");
			return -1;
		}

		fdptr = (int *) CMSG_DATA(cmsg);
		memcpy(&myfd, fdptr, sizeof(int));

		sip_info("Success! Received descriptor %d from helper.\n", myfd[0]);
		return 0;
	}

	return -1;
}
