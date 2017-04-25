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

#include "iso.h"

//mkdir TODO
lwip_del_iso_call(mkdir) {
	getVariables2(char *, path, mode_t, mode);
	int rv;

	WARN_IF_NOT_ABS(path);

	if ((rv = mkdir(path, mode)) < 0) {
		LWIP_SET_RESPONSE_ERROR(errno);
		LWIP_INFO("[MKDIR] on path %s is failed: errno %d", path, errno);
	} else {
		LWIP_UNSET_RESPONSE_ERROR(rv);
		lwip_util_downgradeFile(path);
/*		if (chown(path, -1, LWIP_CF_UNTRUSTED_USERID))
			LWIP_CRITICAL("\tFailed to change the folder to be untrusted!, %s, errno: %d", path, errno);
*/		
		//Execute permission is required!!!
		if (chmod(path, S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IWGRP|S_IXGRP))
			LWIP_CRITICAL("\tFailed to change the folder to be untrusted!, %s, errno: %d", path, errno);
		LWIP_INFO("[MKDIR] on path %s is successful", path);
	}

	return 0;
}


