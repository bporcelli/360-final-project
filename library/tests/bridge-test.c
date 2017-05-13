/**
 * Test for helper bridge methods. Sends a SYS_delegatortest call to daemon, then
 * prints the return value and errno.
 *
 * If the test succeeds, the return value should be 0 and errno should be 42.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <errno.h>
#include "packet.h"
#include "bridge.h"

int main(int argc, char** argv) {
	struct msghdr request;
	struct msghdr response;

	sip_packet_init(&request);
	
	long arg1 = SYS_delegatortest;
	long arg2 = 42;

	SIP_PKT_SET(&request, 0, SIP_ARG, long, &arg1);
	SIP_PKT_SET(&request, 1, SIP_ARG, long, &arg2); // should be returned in errno

	int rv = sip_delegate_call(&request, &response);

	printf("return value is %ld and errno is %d\n", arg1, errno);
	
	sip_packet_destroy(&request);
	return 0;
}
