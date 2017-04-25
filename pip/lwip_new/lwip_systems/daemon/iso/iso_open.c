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

lwip_del_iso_call(open) {

	int fd;
	getVariables3(char *, pathname, int, flags, mode_t, mode);
	int open_flags = flags & 3;
	
	fd = open(pathname, flags, mode);
	if (fd > 0) {
		LWIP_UNSET_RESPONSE_ERROR(fd);
		if (open_flags == O_RDWR || open_flags == O_WRONLY) {
			if (fchown(fd, -1, LWIP_CF_UNTRUSTED_USERID))
				LWIP_CRITICAL("Cannot downgrade file, errno: %d", errno);
			if (fchmod(fd, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP))
				LWIP_CRITICAL("Failed to set the file writable by untrusted user, errno: %d", errno);

		}
		return fd;

	} else {
		LWIP_SET_RESPONSE_ERROR(errno);
		return -1;
	}
}

