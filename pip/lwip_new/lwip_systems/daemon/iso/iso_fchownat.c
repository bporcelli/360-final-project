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

//chown
lwip_del_iso_call(fchownat) {
	getVariables4(char *, path, uid_t, owner, gid_t, group, int, flag);
	int rv;

	WARN_IF_NOT_ABS(path);
	if (owner == -1 || group == -1)
		LWIP_CRITICAL("owner and group should not be -1!! uid %d, gid %d", owner, group);

	LWIP_CRITICAL("Should add checking code");

	if ((rv = fchownat(-1, path, owner, group, flag)) < 0)
		LWIP_SET_RESPONSE_ERROR(errno);
	else
		LWIP_UNSET_RESPONSE_ERROR(rv);

	LWIP_INFO("[FCHOWNAT] on path %s gives %d", path, response->l_rv);
	return 0;
}

