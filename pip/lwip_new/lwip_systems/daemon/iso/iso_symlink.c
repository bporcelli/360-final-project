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

//symlink
lwip_del_iso_call(symlink) {
	getVariables2(char *, oldpath, char *, newpath);
	int rv;

	WARN_IF_NOT_ABS(newpath);

	if ((rv = symlink(oldpath, newpath)) < 0) {
		LWIP_SET_RESPONSE_ERROR(errno);
		goto out;
	}

	LWIP_UNSET_RESPONSE_ERROR(rv);
	if (lchown(newpath, -1, LWIP_CF_UNTRUSTED_USERID))
		LWIP_CRITICAL("Failed to set the group owner of the symlink %s to be untrusted!!!, errno: %d", newpath, errno);
out:
	LWIP_INFO("[SYMLINK] on path %s -> %s gives %d", oldpath, newpath, response->l_rv);
	return 0;
}


