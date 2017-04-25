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

//mkdir TODO
lwip_del_call(mkdir) {
	getVariables2(char *, path, mode_t, mode);

	WARN_IF_NOT_ABS(path);
	char redirectedPath[PATH_MAX];

	if (lwip_isRedirectableFile(path)) {
		snprintf(redirectedPath, PATH_MAX, LWIP_REDIRECTION_PATH "%s", path);
		lwip_createDirsIgnLast_nochown_nochmod(redirectedPath, S_IRWXU|S_IRWXG);
		path = redirectedPath;
	} else if (strstr(path, LWIP_REDIRECTION_PATH) == path) {
		lwip_createDirsIgnLast_nochown_nochmod(path, S_IRWXU|S_IRWXG);
	} 

	/* Combined with egid and umask, directory created will be untrusted automatically */
	lwip_del_performOperationAndSetResponse(mkdir(path, mode|S_IWGRP|S_IXGRP|S_IRGRP));

	return 0;
}


