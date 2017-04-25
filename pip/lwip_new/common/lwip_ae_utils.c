/* * Portable Integrity Protection (PIP) System -
 * Copyright (C) 2012 Secure Systems Laboratory, Stony Brook University
 *
 * This file is part of Portable Integrity Protection (PIP) System.
 *
 * Portable Integrity Protection (PIP) System is free software: you can redistribute it
 * and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Portable Integrity Protection (PIP) System is distributed in the hope that it will
 * be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Portable Integrity Protection (PIP) System.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include "lwip_ae_utils.h"
#include <unistd.h>
#include <stdio.h>
#include <limits.h>

#include <dirent.h>
#include <string.h>
#include <stdlib.h>

#include "lwip_utils.h"
#include "lwip_level.h"
#include "lwip_common.h"
#include "lwip_bufferManager.h"
/*
char traceFilePath[PATH_MAX];
char *lwip_ae_traceDir = NULL;
int pathInitialized = 0;

char *getTraceFile() {
	if (!pathInitialized) {
		snprintf(traceFilePath, PATH_MAX, LWIP_AE_TRACE_DIR "/%d/" LWIP_AE_TRACE_FILE, getpgid(0));
		pathInitialized = 1;
	}
	return traceFilePath;
}


char *lwip_ae_getTraceDir() {
	if (lwip_ae_traceDir == NULL) {
		lwip_ae_traceDir = lwip_bm_malloc(PATH_MAX);
		sprintf(lwip_ae_traceDir, LWIP_AE_TRACE_DIR "/%d", getpgid(0));
	}
	return lwip_ae_traceDir;
}


int pgidlen() {
	int pgid = getpgid(0);
	int len = 0;
	while (pgid > 0) {
		pgid /= 10;
		len++;
	}
	return len;
}


void lwip_ae_initialization() {

	//Print files that are opened in read and write modes.
	DIR *dirp;
	struct dirent *dp;
	char filePath[PATH_MAX];
	int fd, access_mode;

	dirp = opendir("/proc/self/fd");
	while (dirp){
		if ((dp = readdir(dirp)) != NULL) {

			if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
				continue;
			fd = atoi(dp->d_name);

			if (lwip_util_fd2fullPath(fd, filePath))
				continue;

			access_mode = fcntl(fd, F_GETFL) & O_ACCMODE;
			if ((access_mode == O_RDWR) || (access_mode == O_RDONLY)) {
				if (lwip_level_isLow(lwip_fd2Lv_read(fd)) || strstr(filePath, "pipe:[") == filePath)  { 
					LWIP_AE_TRACE("Open_Read, %s, which is of low integrity/pipe", filePath);
				}
			}
			if ((access_mode == O_RDWR) || (access_mode == O_WRONLY)) {
				if (lwip_level_isHigh(lwip_fd2Lv_read(fd)) || strstr(filePath, "pipe:[") == filePath)  {
					char *ptr = filePath;
					if (strstr(filePath, LWIP_AE_REDIRECTION_PATH) == filePath)
						ptr += sizeof(LWIP_AE_REDIRECTION_PATH) + pgidlen();
					LWIP_AE_TRACE("Open_Write, %s, which is of high integrity/pipe", ptr);
				}
			}
	
		}
		else {
			closedir(dirp);
			break;
		}
	}

}
*/
