/**
 * Basic test of packet manipulation functions.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include "packet.h"

int main(int argc, char** argv) {
	struct msghdr request;
	
	sip_packet_init(&request);
	
	long arg1 = SYS_delegatortest;
	long arg2 = 42;

	SIP_PKT_SET(&request, 0, SIP_ARG, long, &arg1);
	SIP_PKT_SET(&request, 1, SIP_ARG, long, &arg2); // should be returned in errno

	if (arg1 != SIP_PKT_GET(&request, 0, long)) {
		printf("arg1 value changed :(\n");
	} else {
		printf("arg1 value correct :)\n");
	}

	if (arg2 != SIP_PKT_GET(&request, 1, long)) {
		printf("arg2 value changed :(\n");
	} else {
		printf("arg2 value correct :)\n");
	}

	sip_packet_destroy(&request);
	return 0;
}
