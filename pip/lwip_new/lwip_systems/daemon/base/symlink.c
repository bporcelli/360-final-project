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

//symlink
lwip_del_call(symlink) {
	getVariables2(char *, oldpath, char *, newpath);
	int rv;

	WARN_IF_NOT_ABS(newpath);
	//Firefox creates a dangling symlink
	if (strstr(oldpath, "127.0.1.1:+") != oldpath)
		WARN_IF_NOT_ABS(oldpath);
	char redirectedPath[PATH_MAX];


	if (lwip_isRedirectableFile(newpath)) {
		snprintf(redirectedPath, PATH_MAX, LWIP_REDIRECTION_PATH "%s", newpath);
		lwip_createDirsIgnLast_with_permissions(redirectedPath, LWIP_CF_UNTRUSTED_USERID, S_IRWXU|S_IRWXG);
		newpath = redirectedPath;
	}


	if ((rv = symlink(oldpath, newpath)) < 0) {
		LWIP_SET_RESPONSE_ERROR(errno);
		goto out;
	} else
		LWIP_UNSET_RESPONSE_ERROR(rv);

	if (lchown(newpath, -1, LWIP_CF_UNTRUSTED_USERID))
		LWIP_CRITICAL("Failed to set the group owner of the symlink %s to be untrusted!!!, errno: %d", newpath, errno);
out:
	LWIP_INFO("[SYMLINK] on path %s -> %s gives %d", oldpath, newpath, response->l_rv);
	return 0;
}

lwip_del_call(readlink) {
	getVariables2(char *, path, size_t, bufsiz);

	WARN_IF_NOT_ABS(path);

	lwip_del_performOperationAndSetResponse(readlink(path, response->buf, bufsiz));

	LWIP_INFO("[READLINK] on link at %s gives %d", path, response->l_rv);
	return 0;
}

lwip_del_call(linkat) {
	getVariables3(char *, oldpath, char *, newpath, int, flags);

	WARN_IF_NOT_ABS(oldpath);
	WARN_IF_NOT_ABS(newpath);

	LWIP_SET_RESPONSE_ERROR(EACCES);
	LWIP_LOWI_VIOLATION("[LINK] not supported: Low integrity processes tries to link: %s to %s, flags: %d", oldpath, newpath, flags);

//	lwip_del_performOperationAndSetResponse(linkat(-1, oldpath, -1, newpath, flags));

	LWIP_INFO("[LINKAT] on link at %s to %s, flags: %d gives %d", oldpath, newpath, flags, response->l_rv);
	return 0;
}




