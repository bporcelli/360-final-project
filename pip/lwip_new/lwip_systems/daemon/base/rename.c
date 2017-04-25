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

//rename
lwip_del_call(rename) {
	getVariables2(char *, from, char *, to);
	
	LWIP_INFO("[RENAME] From %s to %s", from, to);

	WARN_IF_NOT_ABS(from);
	WARN_IF_NOT_ABS(to);

	struct stat buf;
	char redirectedPath[PATH_MAX];


	if (lwip_util_stat(from, &buf)) {
		LWIP_INFO("\tCannot stat the from path, errno %d", errno);
		LWIP_SET_RESPONSE_ERROR(errno);
		return 0;
	}
	if (!lwip_isUntrustedBuf(buf)) {
		LWIP_INFO("\tTried to rename a file %s which is not lowI", from);
		LWIP_SET_RESPONSE_ERROR(EPERM);
		return 0;
	}

	if (strstr(to, LWIP_REDIRECTION_PATH ) == to)
		goto do_rename;

	if (lwip_util_stat(to, &buf)) {
		if (errno == ENOENT) {
			if (lwip_isRedirectableFile(to))
				goto do_redirect_first;
			goto do_rename;
		}
		LWIP_INFO("\tStat on to file %s failed, errno: %d", to, errno);
		LWIP_SET_RESPONSE_ERROR(errno);
		return 0;
	}

	if (!lwip_isUntrustedBuf(buf)) {
		if (lwip_isRedirectableFile(to)) {
do_redirect_first:
			snprintf(redirectedPath, PATH_MAX, LWIP_REDIRECTION_PATH "%s", to);
			lwip_createDirsIgnLast_with_permissions(redirectedPath, LWIP_CF_UNTRUSTED_USERID, S_IRWXU|S_IRWXG);
			to = redirectedPath;
			LWIP_INFO("The target path is redirectable, modified that to %s", to);
			goto do_rename;
		}

                LWIP_VIOLATION("\tTried to overwrite by rename a file which is not lowI, may be a conf file");
		LWIP_SET_RESPONSE_ERROR(EPERM);
                return 0;
        }

do_rename:

	lwip_del_performOperationAndSetResponse(rename(from, to));

	LWIP_INFO("\tRename on file from %s to %s gives isError: %d, errno: %d", from, to, response->l_isError, errno);
	return 0;
}





