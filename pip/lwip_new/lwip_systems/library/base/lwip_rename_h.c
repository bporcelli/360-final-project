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

#include "lwip_rename.h"
#include "lwip_syscall_handler.h"

#include "lwip_debug.h"
#include "lwip_utils.h"
#include "lwip_level.h"

#include <string.h>
#include "lwip_in_utils.h"

#include "lwip_trackOpen.h"


lwip_syscall(rename_h, post) {
        lwip_call_syscall_post_handler4(renameat_h, AT_FDCWD, *p1_ptr, AT_FDCWD, *p2_ptr);
}

lwip_syscall(renameat_h, post) {
	/* We are not using dirfd. The pathname should contain the information we need */
#ifdef LWIP_TRACK_IMPLICIT_EXPLICIT
	prepare_variables4(int VARIABLE_IS_NOT_USED, olddirfd, char * VARIABLE_IS_NOT_USED, from, int, newdirfd, char *, to);
	if (!LWIP_ISERROR) {
		if (strstr(to, "lwip-untrusted") != NULL) {
			if (strcmp(lwip_util_getProcessImagePath(), "/usr/lib/thunderbird/thunderbird") == 0) {
				LWIP_INFO("Downgrading file %s based on file name", to);
				lwip_util_downgradeFileAt(newdirfd, to, 0);
			}
		}
		if (strcmp(lwip_util_getProcessImagePath(), "/usr/lib/firefox/firefox") == 0 && lwip_trackOpen_isUntrusted(to)) {
			LWIP_INFO("Downgrading file %s based on record", to);
			lwip_util_downgradeFileAt(newdirfd, to, 0);
		}
	}

	char *buf = lwip_bm_malloc(PATH_MAX);
	lwip_util_getFullPathAt(newdirfd, to, buf);
	lwip_trackOpen_testIsExplict(buf, O_WRONLY);
	lwip_bm_free(buf);

#endif
	


}

