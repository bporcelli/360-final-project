#ifndef _SIP_HANDLER_H
#define _SIP_HANDLER_H

#include "packets.h"

void handle_delegatortest(struct sip_request_test *request, struct sip_response *response);
void handle_openat(struct sip_request_test *request, struct sip_response *response);

#endif
