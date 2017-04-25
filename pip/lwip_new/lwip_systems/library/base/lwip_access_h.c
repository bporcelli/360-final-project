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

#include "lwip_access.h"
#include "lwip_syscall_handler.h"

#include "lwip_debug.h"
#include "lwip_utils.h"
#include "lwip_level.h"

#include "lwip_delegator_connection.h"
#include <string.h>
#include <unistd.h>

#include "lwip_redirect.h"

lwip_syscall(access_h, post) {
        lwip_call_syscall_post_handler4(faccessat_h, AT_FDCWD, *p1_ptr, *p2_ptr, 0);
}

lwip_syscall(faccessat_h, post) {
	if (!LWIP_ISERROR) {
                prepare_variables4(int, dirfd, char *, path, int, mode, int, flag);
		/* Report file not readable if file is of low integrity */
		if ((mode & R_OK) == R_OK) {
			if (!lwip_file2readLvIsHighat3(dirfd, path, flag)) {
				LWIP_HIGHI_VIOLATION("Read access on low integrity file %s", path);
				LWIP_SET_SYSCALL_ERROR(EACCES);
			}
		}
	}
}

