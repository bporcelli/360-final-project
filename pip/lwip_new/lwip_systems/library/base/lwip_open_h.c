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

#include "lwip_open.h"
#include "lwip_notifier.h"

#include "lwip_debug.h"
#include "lwip_utils.h"
#include "lwip_level.h"
#include "lwip_trusted.h"

#include "lwip_syscall_handler.h"
#include "lwip_del_conf.h"
#include "lwip_delegator_connection.h"

#include "lwip_in_utils.h"

#include <string.h>
#include <fcntl.h>
#include <libgen.h>


#include "lwip_trackOpen.h"

#include <sys/types.h>
#include <dirent.h>

extern char **environ;

char *(*lwip_extra_explicit_argument)(char *) = NULL;

lwip_syscall(open_h, post) {
	lwip_call_syscall_post_handler4(openat_h, AT_FDCWD, *p1_ptr, *p2_ptr, *p3_ptr);
}

lwip_syscall(openat_h, post) {
	int ret = (int)*return_value_ptr;
	char *bufferPath = NULL;

	if (!LWIP_ISERROR) {

		struct stat buf;
		prepare_variables3(int VARIABLE_IS_NOT_USED, dirfd, char *, op_pathname, int, flags);
		//prepare_variables4(int VARIABLE_IS_NOT_USED, dirfd, char *, op_pathname, int, flags, mode_t, mode);
		int openedMode = flags & 3;

		#define actualOpenedPath bufferPath

#ifdef LWIP_TRACK_IMPLICIT_EXPLICIT


		actualOpenedPath = lwip_bm_malloc(PATH_MAX);
		if (lwip_extra_explicit_argument != NULL) {
			LWIP_CRITICAL("PPPPPPPPPPPPPPP folder path is %s", lwip_extra_explicit_argument(actualOpenedPath));			
		}


		if (lwip_util_fd2fullPath(ret, actualOpenedPath)) {
			LWIP_UNEXPECTED("Failed to get fd2fullPath of opened file: %s, errno: %d", op_pathname, errno);
		} else
			lwip_trackOpen_testIsExplict(actualOpenedPath, flags);
#endif


		if (openedMode == O_WRONLY)
			goto out;

		if (lwip_util_fstat(ret, &buf)) {
			LWIP_UNEXPECTED("Failed to do fstat on opened file: errno: %d", errno);
			goto out;
		}

		if (lwip_level_statLv(buf) == LV_HIGH)
			goto out;

/*		if ((flags & O_CREAT) && (mode & S_IWOTH)) {
			if ((buf.st_mode & S_IRWXO) && (buf.st_mode & S_IRWXG) && (buf.st_mode & S_IRWXO)) {
				if ((fchown(ret, LWIP_CF_TRUSTED_GROUP_GID, 0) == 0)
					&& (fchmod(ret, buf.st_mode & ~(S_IWOTH)) == 0)) {
					LWIP_HIGHI_VIOLATION("Making file %s as group writable instead of worldwritable", op_pathname);
				} else
					LWIP_HIGHI_VIOLATION("Failed to change world-writable file into group-writable file %s", op_pathname);
			}
		}
*/
		/* Potentially low integrity file is opened in read mode. Need slow path to check */
		if (actualOpenedPath == NULL) {
			actualOpenedPath = lwip_bm_malloc(PATH_MAX);
			if (lwip_util_fd2fullPath(ret, actualOpenedPath)) {
				LWIP_UNEXPECTED("Failed to get fd2fullPath of opened file: %s, errno: %d", op_pathname, errno);
				goto out;
			}
		}
		if (!lwip_isTrusted2Open(actualOpenedPath)) {
			LWIP_HIGHI_VIOLATION("Opening of low integrity file %s for reading", actualOpenedPath);
			//close the file
			close(ret);
			LWIP_SET_SYSCALL_ERROR(EACCES);
			sh_showUserMsgN("File open DENIED for %s", actualOpenedPath);
			goto out;
		}


	} else { /* if (LWIP_ISERROR) */

		prepare_variables2(int VARIABLE_IS_NOT_USED, dirfd, char *, op_pathname);
		if (LWIP_ISERRORNO(ENOENT) && (op_pathname != NULL) && (strncmp(op_pathname, "/LWIP sour", strlen("/LWIP sour")) == 0)) {
			LWIP_INFO("FIREFOX LOG: %s", op_pathname);
			char *buffer_path = lwip_bm_malloc(PATH_MAX);

			strcpy(buffer_path, op_pathname);
			char *tempPtr = strstr(buffer_path, "file-path-start:");

			LWIP_ASSERT(tempPtr != NULL, "Firefox log should contain \"file-path-start:\", but %s", op_pathname);

			char *filePtr = tempPtr + strlen("file-path-start:");
			tempPtr = strstr(filePtr, ":file-path-end");

			LWIP_ASSERT(tempPtr != NULL, "Firefox log should contain \"file-path-end:\", but %s", op_pathname);
			*tempPtr = 0;

			tempPtr = strstr(buffer_path, "source-host-start:");
			LWIP_ASSERT(tempPtr != NULL, "Firefox log should contain \"source-host-start:\", but %s", op_pathname);

			char *hostPtr = tempPtr + strlen("source-host-start:");
			tempPtr = strstr(hostPtr, ":source-host-end");
			LWIP_ASSERT(tempPtr != NULL, "Firefox log should contain \"source-host-end:\", but %s", op_pathname);
			*tempPtr = 0;

			LWIP_INFO("Host: %s, file: %s", hostPtr, filePtr);

			if (filePtr != NULL) {
				LWIP_INFO("Downgrading File is --%s--", filePtr);
				lwip_util_downgradeFile(filePtr);
				lwip_trackOpen_addUntrusted(filePtr);
			}
			goto out;
		}
	}

out:
	if (bufferPath != NULL)
		lwip_bm_free(bufferPath);
}

