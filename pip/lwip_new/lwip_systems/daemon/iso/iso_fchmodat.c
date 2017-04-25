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

//chmod
lwip_del_iso_call(fchmodat) {
	getVariables3(char *, path, mode_t, mode, int, flag);
	struct stat buf;
	int rv;

	WARN_IF_NOT_ABS(path);

	if (((flag & AT_SYMLINK_NOFOLLOW) == 0) && lwip_util_stat(path, &buf)) {
		LWIP_SET_RESPONSE_ERROR(errno);
		return 0;
	}

	if (flag & AT_SYMLINK_NOFOLLOW) {
		LWIP_CRITICAL("Unhandled case: no follow flag is set!!!");
	}

	if (!lwip_isUntrustedBuf(buf)) {
		LWIP_CRITICAL("To be handled: what 2 do when chmod is called is ISO?");
		LWIP_VIOLATION("\t[CHMOD] Try to chmod a file which is not lowI %s", path);
		LWIP_SET_RESPONSE_ERROR(EPERM);
		return 0;
	}

	//The lowI file should be writable and readable by the lowI process
	//If stat is used, it is better to set the owner also read and write-able to the file //, openoffice
	mode |= S_IWGRP|S_IRGRP|S_IWUSR|S_IRUSR;

	if ((rv = fchmodat(-1, path, mode, flag)) < 0)
		LWIP_SET_RESPONSE_ERROR(errno);
	else {
		LWIP_UNSET_RESPONSE_ERROR(rv);
		lwip_util_downgradeFile(path);
	}
	return 0;
}

