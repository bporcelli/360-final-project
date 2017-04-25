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

//access
lwip_del_call(faccessat) { 
	getVariables3(char *, pathname, int, mode, int, flag);
	struct stat buf;

	WARN_IF_NOT_ABS(pathname);
	if (lwip_util_stat(pathname, &buf)) {
		LWIP_INFO("\tFailed to do stat, errno: %d", errno);
		LWIP_SET_RESPONSE_ERROR(errno);
		return 0;
	}

	/* No need to worry about race condition since it will not result in security failure.*/
	/* If the file is of lowI, should return allowed if user can perform the operation*/
	if (lwip_isRedirectableFile(pathname) || ((mode & W_OK) == 0) || S_ISDIR(buf.st_mode) || lwip_level_isLow(lwip_file2Lv_write(pathname)))
		lwip_del_performOperationAndSetResponse(faccessat(-1, pathname, mode, flag));
	else {
		//Default error
		LWIP_SET_RESPONSE_ERROR(EACCES);
		LWIP_LOWI_VIOLATION("[ACCESS] File %s, mode %s, is not redirectable or is opened in write access mode", pathname, lwip_util_mode2perms(mode));
	}

	return 0;
}

