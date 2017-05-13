#ifndef _SIP_PACKET_H
#define _SIP_PACKET_H

#include <sys/types.h>
#include <sys/socket.h>

#define SIP_ARG 0
#define SIP_FD_ARG 1
#define SIP_NUM_FD 1
#define SIP_MAX_ARGS 4
#define SYS_delegatortest 400

struct sip_arg {
	int type;		/* SIP_FD_ARG for file descriptors, otherwise SIP_ARG */
	void *data;		/* Starting address */
	size_t len;		/* Number of bytes */
};

#define SIP_PKT_SET(pkt, idx, atype, dtype, val) 			\
	do {													\
		struct sip_arg a = {								\
			.type = atype,									\
			.data = val,									\
			.len = sizeof(dtype)							\
		}; 													\
		sip_packet_set(pkt, idx, a);						\
	} while (0)

#define SIP_PKT_GET(pkt, idx, type) *(type *)(sip_packet_get(pkt, idx))

void sip_packet_init(struct msghdr* pkt);
void sip_packet_destroy(struct msghdr *pkt);
void sip_packet_set(struct msghdr *pkt, int index, struct sip_arg arg);
void *sip_packet_get(struct msghdr *pkt, int index);

#endif
