#ifndef _SIP_COMM_H
#define _SIP_COMM_H

#include <sys/types.h>
#include "packets.h"

int sip_delegate_call(void *request, struct sip_response *response);
int sip_delegate_call_fd(void *request, struct sip_response *response);

#endif
