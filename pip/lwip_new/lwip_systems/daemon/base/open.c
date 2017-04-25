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

#include "base.h"

//open


lwip_del_call(open) {
	int fd;
	getVariables3(char *, pathname, int, flags, mode_t, mode);
	int open_flags = flags & 3;
	struct stat buf;
	int labelAsUntrusted = 0;
	char redirectedPath[PATH_MAX];

	LWIP_INFO("[OPEN] %s, flags: %d", pathname, open_flags);
//	snprintf(redirectedPath, PATH_MAX, LWIP_REDIRECTION_PATH "%s", pathname);

	/* If the file is redirected, and a redirected copy exists, simply return the redirected copy */
/*	if (lwip_isRedirectableFile(pathname) && lwip_util_fileExist(redirectedPath)) {
		LWIP_CRITICAL("Low integrity process should not ask the delegator to open the redirected file %s", pathname);
		pathname = redirectedPath;
		goto do_permission_checking;
	}
*/
	/* If the file is in read only mode, and no redirected copy exists, return the original copy */
//	if (open_flags == O_RDONLY)
		goto do_permission_checking;
	
	/* If the file is redirectable and is opened in write mode, we must redirect it */
	if (lwip_isRedirectableFile(pathname)) {
		lwip_createDirsIgnLast_with_permissions(redirectedPath, LWIP_CF_UNTRUSTED_USERID, S_IRWXU|S_IRWXG);
		if (lwip_util_fileExist(pathname)) {
			lwip_copyFile(pathname, redirectedPath, LWIP_CF_UNTRUSTED_USERID, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);
		}
		pathname = redirectedPath;
		goto do_permission_checking;
	}
	/* File is not redirectable */
	goto do_permission_checking;

do_permission_checking:
	if (lwip_util_stat(pathname, &buf)) {
		if (errno == ENOENT && (flags & O_CREAT)) {
			labelAsUntrusted = 1;
			goto do_file_opening;
		}
		LWIP_SET_RESPONSE_ERROR(errno);
		return -1;
	}

	if (open_flags == O_RDWR || open_flags == O_WRONLY) {
		if (lwip_level_isLow(lwip_file2Lv_write(pathname))) {
			LWIP_INFO("\t[OPEN] file is of low integrity, opening will proceed");
			goto do_file_opening;		
		} else {
			LWIP_VIOLATION("\t[OPEN] opening of file %s in write mode is not allowed", pathname);
			LWIP_SET_RESPONSE_ERROR(EACCES); 
			return -1;
		}
	}

do_file_opening:
	fd = open(pathname, flags, mode|S_IWGRP);
	if (fd > 0) {
		LWIP_UNSET_RESPONSE_ERROR(fd);
		if (labelAsUntrusted) {
/*			if (fchown(fd, -1, LWIP_CF_UNTRUSTED_USERID))
				LWIP_CRITICAL("\tFailed to change the file group owner of %s to be untrusted %d, %d!!", pathname, LWIP_CF_UNTRUSTED_USERID, errno);
			if (fchmod(fd, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|mode))
				LWIP_CRITICAL("\tFailed to change the file %s to be group writable %d", pathname, errno);
*/		}
		LWIP_INFO("\t[OPEN] opening of file %s gives %d", pathname, fd);
		return fd;
	} else {
		LWIP_INFO("\t[OPEN] opening of file %s failed with errno %d", pathname, errno);
		LWIP_SET_RESPONSE_ERROR(errno); 
		return -1;
	}
}



