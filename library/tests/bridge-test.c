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
#include "packets.h"
#include "bridge.h"

int main(int argc, char** argv) {

	struct sip_response response;
	struct sip_request_test request;

	request.head.callno = SYS_delegatortest;
	request.head.size = sizeof(struct sip_request_test);
	request.err = 42;

	int rv = sip_delegate_call(&request, &response);

	if (rv == -1) {
		printf("failed to send request :(\n");
	} else {
		printf("rv is %d, errno is %d.\n", response.rv, response.err);
	}

	return 0;
}
