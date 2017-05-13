#ifndef _REDIRECT_H
#define _REDIRECT_H

#include <sys/types.h>

int sip_should_redirect(const char *pathname, mode_t mode);
int sip_is_redirected(const char *pathname);
char *sip_build_redirect_path(const char *pathname);
char *sip_revert_path(char *pathname);
char *sip_convert_to_redirected_path(char *pathname);

#endif