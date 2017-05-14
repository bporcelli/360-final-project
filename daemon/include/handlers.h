#ifndef _SIP_HANDLER_H
#define _SIP_HANDLER_H

#include "packets.h"

void handle_delegatortest(struct sip_request_test *request, struct sip_response *response);
void handle_faccessat(struct sip_request_test *request, struct sip_response *response);
void handle_fchmodat(struct sip_request_test *request, struct sip_response *response);
void handle_fchownat(struct sip_request_test *request, struct sip_response *response);
void handle_fstatat(struct sip_request_test *request, struct sip_response *response);
void handle_statvfs(struct sip_request_test *request, struct sip_response *response);
void handle_linkat(struct sip_request_test *request, struct sip_response *response);
void handle_mkdirat(struct sip_request_test *request, struct sip_response *response);
void handle_mknodat(struct sip_request_test *request, struct sip_response *response);
void handle_openat(struct sip_request_test *request, struct sip_response *response);
void handle_renameat2(struct sip_request_test *request, struct sip_response *response);
void handle_symlinkat(struct sip_request_test *request, struct sip_response *response);
void handle_unlinkat(struct sip_request_test *request, struct sip_response *response);
void handle_utime(struct sip_request_test *request, struct sip_response *response);
void handle_utimes(struct sip_request_test *request, struct sip_response *response);
void handle_utimensat(struct sip_request_test *request, struct sip_response *response);
void handle_bind(struct sip_request_test *request, struct sip_response *response);
void handle_connect(struct sip_request_test *request, struct sip_response *response);

#endif
