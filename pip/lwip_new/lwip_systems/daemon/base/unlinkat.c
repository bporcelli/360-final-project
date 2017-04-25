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

//unlink
lwip_del_call(unlinkat) {
	getVariables2(char *, path, int, flag);
	struct stat buf;

	LWIP_INFO("[UNLINK] Request on %s", path);

	WARN_IF_NOT_ABS(path);
	if (lwip_util_stat(path, &buf) && lstat(path, &buf)) {
		LWIP_INFO("\t[UNLINKAT] Failed to stat file %s, errno: %d", path, errno);
		LWIP_SET_RESPONSE_ERROR(errno);
		return -1;
	}

	if (!lwip_isUntrustedBuf(buf)) {
		LWIP_INFO("\t[UNLINKAT] Trying to unlink file which is not lowI: %s, uid: %d, gid: %d", path, buf.st_uid, buf.st_gid);
		LWIP_SET_RESPONSE_ERROR(EACCES);
		return 0;
	}

	lwip_del_performOperationAndSetResponse(unlinkat(-1, path, flag));

	LWIP_INFO("\t[UNLINK] unlink on %s gives %d", path, response->l_rv);
	return 0;
}




