#include "handlers.h"
#include "logger.h"

/**
 * Handler for SYS_delegatortest. Simply sets the return value to 0
 * and sets errno to the given value.
 */
void handle_delegatortest(struct sip_request_test *request, struct sip_response *response) {
	response->rv = 0;
	response->err = request->err;
}

/**
 * Handler for SYS_openat.
 */
void handle_openat(struct sip_request_test *request, struct sip_response *response) {
	sip_info("received delegated openat request.\n");
}
