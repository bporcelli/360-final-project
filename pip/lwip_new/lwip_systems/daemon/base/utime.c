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

//utime
lwip_del_call(utimes) {
	getVariables3(char *, path, int, timeisnull, struct timeval *, times);

	LWIP_INFO("[UTIMES] Request on %s", path);

	WARN_IF_NOT_ABS(path);

	if (timeisnull)
		times = NULL;

	lwip_del_performOperationAndSetResponse(utimes(path, times));

	LWIP_INFO("\t[UTIMES] utimes on %s gives %d", path, response->l_rv);

	return 0;
}

#ifdef LWIP_OS_LINUX

lwip_del_call(utime) {
	getVariables3(char *, filename, int, timeisnull, struct utimbuf, times);
	int rv;

	LWIP_INFO("[UTIME] Request on %s", filename);
	WARN_IF_NOT_ABS(filename);

	if (timeisnull)
		rv = utime(filename, NULL);
	else
		 rv = utime(filename, &times);

	if (rv < 0)
		LWIP_SET_RESPONSE_ERROR(errno);
	else
		LWIP_UNSET_RESPONSE_ERROR(rv);

	LWIP_INFO("\t[UTIME] utime on %s gives %d", filename, response->l_rv);

	return 0;
}

lwip_del_call(utimensat) {
	getVariables4(char *, pathname, int, timeisnull, struct timespec *, times, int, flags);

	LWIP_INFO("[UTIMENSAT] Request on %s", pathname);
	WARN_IF_NOT_ABS(pathname);

	if (timeisnull)
		times = NULL;

	lwip_del_performOperationAndSetResponse(utimensat(-1, pathname, times, flags));

	LWIP_INFO("\t[UTIMENSAT] utimensat on %s gives %d", pathname, response->l_rv);

	return 0;
}

#elif defined LWIP_OS_BSD

lwip_del_call(lutimes) {
	getVariables3(char *, path, int, timeisnull, struct timeval *, times);
	int rv;

	LWIP_INFO("[LUTIMES] Request on %s", path);
	WARN_IF_NOT_ABS(path);

	if (timeisnull)
		times = NULL;

	lwip_del_performOperationAndSetResponse(lutimes(path, times));

	LWIP_INFO("\t[LUTIMES] lutimes on %s gives %d", path, response->l_rv);

	return 0;
}

#endif

