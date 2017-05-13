#include <sys/uio.h>
#include <stdlib.h>
#include <string.h>
#include "packet.h"
#include "logger.h"

/**
 * Initialize the given packet.
 *
 * @param struct msghdr *pkt
 */
void sip_packet_init(struct msghdr* pkt) {
	struct iovec *iov;

	if ((iov = malloc(SIP_MAX_ARGS * sizeof(struct iovec))) == NULL) {
		sip_error("Failed to initialize packet: out of memory.\n");
		return;
	}

	pkt->msg_name = NULL;
	pkt->msg_namelen = 0;
	pkt->msg_iov = iov;
	pkt->msg_iovlen = 0;
	pkt->msg_controllen = 0;
	pkt->msg_control = NULL; 
	pkt->msg_flags = 0;
}

/**
 * Destroy the given packet.
 *
 * @param struct msghdr *pkt
 */
void sip_packet_destroy(struct msghdr *pkt) {
	if (pkt->msg_iov != NULL) {
		free(pkt->msg_iov);
	}
}

/**
 * Add an argument to the given packet. Note that only one arg of type
 * SIP_FD_ARG can be added to any given packet.
 *
 * @param struct msghdr* pkt Packet.
 * @param int index Positional index of argument.
 * @param struct sip_arg arg Argument.
 */
void sip_packet_set(struct msghdr *pkt, int index, struct sip_arg arg) {
	if (index >= SIP_MAX_ARGS) {
		sip_error("Failed to add argument to packet: max args exceeded.\n");
		return;
	}

	struct iovec *vec = &pkt->msg_iov[index];
	
	vec->iov_base = arg.data;
	vec->iov_len = arg.len;

	/* If type is SIP_FD_ARG, add control message. */
	if (arg.type == SIP_FD_ARG) {
		if (pkt->msg_controllen > 0) {
			sip_error("Failed to add argument to packet: more than one fd arg added.\n");
			return;
		}

		struct cmsghdr *cmsg;

		union {
			/* wrap in union to ensure proper alignment. */
			char buf[CMSG_SPACE(sizeof(int))];
			struct cmsghdr align;
		} u;

		pkt->msg_control = u.buf;
		pkt->msg_controllen = sizeof u.buf;
		
		cmsg = CMSG_FIRSTHDR(pkt);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));

		memcpy((int *) CMSG_DATA(cmsg), arg.data, sizeof(int));
	}
}

/**
 * Extract an argument from the given package given its index.
 *
 * @param struct msghdr *pkt Packet.
 * @param int index Positional index of argument to extract.
 * @return Pointer to argument value, or NULL on error.
 */
void *sip_packet_get(struct msghdr *pkt, int index) {
	if (index < 0 || index >= SIP_MAX_ARGS) {
		sip_error("Failed to extract argument from packet: %d is an invalid index.\n", index);
		return NULL;
	}
	return pkt->msg_iov[index].iov_base;
}
