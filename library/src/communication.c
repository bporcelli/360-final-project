#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "communication.h"

static int sockfd = -1;

/**
 * Start the helper process.
 */
static void sip_delegate_start() {
	pid_t pid;

	char args[2] = {SIP_DAEMON_COMMUNICATION_PATH, NULL};

	if ((pid = fork()) == 0) {
		sip_info("Starting delegator with process id %lu\n", pid);
		execv(SIP_DAEMON_PATH, args);
		sip_error("Failed to start daemon: %s\n", strerror(errno));
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
	sprintf(addr.sun_path, SIP_DAEMON_COMMUNICATION_PATH);

	/* Attempt connection up to 3 times. */
	do {
		conn = connect(sockfd, (struct sockaddr*) addr, sizeof(addr));
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
 * Sends a syscall request to the trusted helper and gets the response.
 *
 * @param struct msghdr* request
 * @param struct msghdr* response
 * @return int Response value on success, -1 on error.
 */
static int sip_delegate_get_response(struct msghdr *request, struct msghdr *response) {

	ssize_t sent, received;

	if (!sip_delegate_connect()) {
		return -1;
	}

	sent = sendmsg(sockfd, request, MSG_DONTWAIT);

	if (sent == -1) {
		sip_error("Failed to send syscall request: %s\n", strerror(errno));
		return -1;
	}

	sip_info("Sent %lu bytes to the helper.\n", sent);
	received = recvmsg(sockfd, response, 0);
	sip_info("Received %lu bytes from the helper.\n", received);

	if (received <= 0) {
		sip_error("Failed to read syscall response: %s\n", strerror(errno));
		return -1;
	}

	// TODO: RETURN REAL RETURN VALUE/ERRNO EXTRACTED FROM RESPONSE
	return 0;
}

/**
 * This function can be used to delegate a syscall to the trusted helper. It
 * constructs a syscall request packet that can be transmitted with sendmsg,
 * then invokes sip_delegate_get_response to send the syscall request and get
 * a response. 
 *
 * In the syscall packet, the first member of msg_iov encodes the syscall
 * number. Each subsequent member corresponds to a single argument of type 
 * SIP_ARG. File descriptor arguments are passed through the first control
 * message (max of two allowed).
 *
 * @param long number Syscall number.
 * @param int argc Number of args.
 * @param struct sip_arg args[] Arguments.
 * @return int -2 on connection failure. Refer to syscall manpage otherwise.
 */
int sip_delegate_call(long number, int argc, struct sip_arg args[]) {

	// TODO: EXTRACT "BUILD PACKET" LOGIC SO WE CAN USE IT ON SERVER SIDE AS WELL
	struct msghdr request = {0}, response = {0};
	struct cmsghdr *cmsg;
	struct iovec *vec;
	struct sip_arg arg;
	
	int fds[SIP_NUM_FD], i, fdi, rv;

	/* Allocate space to hold a struct iovec for each argument AND the syscall
	   number. */
	request.msg_iov = malloc((argc + 1) * sizeof(struct iovec));
	if (request.msg_iov == NULL) {
		sip_error("Failed to delegate call: out of memory.\n");
		return -1;	
	}
	request.msg_iovlen = argc + 1;

	/* Add iovec for syscall number. */	
	request.msg_iov[0]->iov_base = &number;
	request.msg_iov[0]->iov_len = sizeof(long);

	/* Add one struct iovec for each argument. Gather list of descriptors
	   to pass. */
	for (i = 0, fdi = 0; i < argc; i++) {
		arg = args[i];

		if (arg.type == SIP_ARG) {
			request.msg_iov[i + 1]->iov_base = arg.data;
			request.msg_iov[i + 1]->iov_len = arg.len;
		} else {
			request.msg_iov[i + 1]->iov_base = SIP_FD_DATA;
			request.msg_iov[i + 1]->iov_len = sizeof(void*);

			if (fdi == SIP_NUM_FD) {
				sip_error("Failed to delegate call: too many file descriptor arguments.\n");
				rv = -1;
				goto exit;
			} else {
				fds[fdi++] = *(int *) arg.data;
			}
		}
	}

	/* Pass all file descriptor arguments in a control message. Code below
	   follows example on manpage cmsg(3). */
	union {
		/* wrap in union to ensure proper alignment. */
		char buf[CMSG_SPACE(sizeof fds)];
		struct cmsghdr align;
	} u;
	int *fdptr;

	request.msg_control = u.buf;
	request.msg_controllen = sizeof u.buf;
	
	cmsg = CMSG_FIRSTHDR(&request);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int) * SIP_NUM_FD);

	fdptr = (int *) CMSG_DATA(cmsg);
	memcpy(fdptr, fds, SIP_NUM_FD * sizeof(int));

	/* Attempt delegated call */
	rv = sip_delegate_get_response(&request, &response);

exit:
	/* Clean up */
	free(request.msg_iov);

	return rv;
}
