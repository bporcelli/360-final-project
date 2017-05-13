#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include "redirect.h"
#include "common.h"
#include "level.h"
#include "util.h"

int sip_should_redirect(const char *pathname, mode_t mode) {
	if (sip_path_to_level(pathname) == SIP_LV_LOW)
		return 0;
	return ((mode & O_WRONLY) || (mode & O_RDWR));
}

int sip_is_redirected(const char *pathname) {
	return (strstr(SIP_REDIRECTION_PATH, pathname) == pathname);
}

char *sip_build_redirect_path(const char *pathname) {
	char* str_path = malloc(strlen(pathname) + strlen(SIP_REDIRECTION_PATH) + 2);
	
	strcpy(str_path, SIP_REDIRECTION_PATH);
	strcat(str_path, pathname);

	return str_path;
}

char *sip_revert_path(char *pathname) {
	return pathname + strlen(SIP_REDIRECTION_PATH);
}

char *sip_convert_to_redirected_path(char *pathname) {
	char *test = sip_build_redirect_path(pathname);

	if(access(test, F_OK) != -1) {
		return test;
	}
	else {
		return pathname;
	}
}

