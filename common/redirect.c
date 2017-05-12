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
#include "logger.h"
#include "level.h"
#include "util.h"

int sip_is_redirect(const char *pathname, int mode) {

	return if((sip_path_to_level(pathname) == SIP_LV_HIGH) && (mode & W_OK));
}

const char *get_redirect_path(const char *pathname) {

	char* str_path = malloc(strlen(pathname) + strlen("/temp/") + 2);
	strcpy(str_path, "/temp");
	strcat(str_path, pathname);

	return str_path;
}

const char *revert_path(const char *pathname) {

	return char* temp_rmvd = pathname + 5;
}