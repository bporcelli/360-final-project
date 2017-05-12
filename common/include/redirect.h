#ifndef _REDIRECT_H
#define _REDIRECT_H


int sip_should_redirect(const char *pathname, int mode);
int sip_is_redirect(const char *pathname);
const char *sip_build_redirect_path(const char *pathname);
const char *sip_revert_path(const char *pathname);
const char *sip_convert_if(const char *pathname);

#endif