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



//rename
lwip_del_iso_call(rename) {
	getVariables2(char *, from, char *, to);
	int rv;
	
	LWIP_INFO("[RENAME] From %s to %s", from, to);

	WARN_IF_NOT_ABS(from);
	WARN_IF_NOT_ABS(to);

	if ((rv = rename(from, to)) < 0)
		LWIP_SET_RESPONSE_ERROR(errno);
	else {
		LWIP_UNSET_RESPONSE_ERROR(rv);
		lwip_util_downgradeFile(to);
	}

	LWIP_INFO("\tRename on file from %s to %s gives isError: %d, errno: %d", from, to, response->l_isError, errno);
	return 0;
}





