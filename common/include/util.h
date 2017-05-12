#ifndef _SIP_UTIL_H
#define _SIP_UTIL_H

#include <unistd.h>

char* sip_fd_to_path(int fd);

int sip_uid_to_level(uid_t uid);
int sip_gid_to_level(uid_t uid);

#endif
