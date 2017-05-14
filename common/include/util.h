#ifndef _SIP_UTIL_H
#define _SIP_UTIL_H

#include <sys/socket.h>

char* sip_fd_to_path(int fd);

int sip_is_named_sock(const struct sockaddr* addr, socklen_t addrlen);
int sip_is_daemon();

#endif
