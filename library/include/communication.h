#ifndef _SIP_COMM_H
#define _SIP_COMM_H

#include <sys/types.h>

#define SIP_ARG 0
#define SIP_FD_ARG 1
#define SIP_NUM_FD 2
#define SIP_FD_DATA (void*) -11;

struct sip_arg {
	int type;		/* SIP_FD_ARG for file descriptors, otherwise SIP_ARG */
	void *data;		/* Starting address */
	size_t len;		/* Number of bytes */
}

int sip_delegate_call(long number, int argc, struct sip_arg[]);

#endif
