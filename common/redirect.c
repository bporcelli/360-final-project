#include <utime.h>
#include <sys/statfs.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdlib.h>

#include "wrappers.h"
#include "dlhelper.h"
#include "common.h"
#include "logger.h"
#include "level.h"
#include "util.h"

int sip_should_redirect(const char *pathname, int mode) {

	return ((sip_path_to_level(pathname) == SIP_LV_HIGH) && ((mode & O_WRONLY) || (mode & O_RDWR)));
}

int sip_is_redirect(const char *pathname) {

	return (strstr(SIP_REDIRECTION_PATH, pathname) == pathname)
}

const char *sip_build_redirect_path(const char *pathname) {

	char* str_path = malloc(strlen(pathname) + strlen(SIP_REDIRECTION_PATH) + 2);
	strcpy(str_path, SIP_REDIRECTION_PATH);
	strcat(str_path, pathname);

	return str_path;
}

const char *sip_revert_path(const char *pathname) {

	return char* temp_rmvd = pathname + strlen(SIP_REDIRECTION_PATH);
}

