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

//statfs
lwip_del_call(statfs) {
	getVariables1(char *, path);

	LWIP_INFO("[STATFS] Request for statfs on file: %s", path);
	int rv = syscall(SYS_statfs, path, &response->buf);
	if (rv >= 0)
		LWIP_UNSET_RESPONSE_ERROR(rv);
	else
		LWIP_SET_RESPONSE_ERROR(rv);
	LWIP_INFO("\t[STATFS] statfs gives %d", rv);

	return 1;
}

#ifdef LWIP_OS_LINUX
lwip_del_call(statfs64) {
	getVariables2(char *, path, size_t, size);

	LWIP_INFO("[STATFS64] Request for statfs64 on file: %s, size: %d", path, size);
	int rv = syscall(SYS_statfs64, path, size, &response->buf);
	if (rv >= 0)
		LWIP_UNSET_RESPONSE_ERROR(rv);
	else
		LWIP_SET_RESPONSE_ERROR(rv);

	LWIP_INFO("\t[STATFS64] statfs64 gives %d", rv);

	return 1;
}
#endif



