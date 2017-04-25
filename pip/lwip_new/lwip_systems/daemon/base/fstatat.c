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


//stat
#ifdef LWIP_OS_BSD
lwip_del_call(fstatat) {
	getVariables2(char *, path, int, flag);
/*
	WARN_IF_NOT_ABS(path);
	if (fstatat(-1, path, &response->sb, flag)) {
		response->l_isError = 1;
		response->l_rv = errno;
		LWIP_INFO("[FStatat] on path %s is failed: errno %d", path, errno);
	} else {
		response->l_isError = 0;
		response->l_rv = 0;
		LWIP_INFO("[FStatat] on path %s is successful", path);
	}
*/
	lwip_del_performOperationAndSetResponse(fstatat(-1, path, &response->sb, flag));

	return 0;
}
#elif defined LWIP_OS_LINUX
lwip_del_call(lwip_fstatat) {
	getVariables2(char *, pathname, int, flags);
	WARN_IF_NOT_ABS(pathname);

	lwip_del_performOperationAndSetResponse(syscall(SYS_fstatat64, -1, pathname, &response->buf, flags));

	return 0;
}
#endif





