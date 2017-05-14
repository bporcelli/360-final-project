#include "handlers.h"
#include "packet.h"
#include "logger.h"

/**
 * Handler for SYS_delegatortest.
 *
 * Returns response where return value is 0 and errno is the second argument in
 * the request.
 */
void handle_delegatortest(struct msghdr *request, struct msghdr *response) {
	sip_info("In handler handle_delegatortest.\n");

	int err = SIP_PKT_GET(request, 1, int);

	/* In responses, first "argument" is return value... */
	SIP_PKT_SET(response, 0, SIP_ARG, int, 0);

	/* ... and second is errno. */
	SIP_PKT_SET(response, 1, SIP_ARG, long, &err);
}
