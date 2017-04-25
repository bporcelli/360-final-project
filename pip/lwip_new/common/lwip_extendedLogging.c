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

#include "lwip_extendedLogging.h"
#include "lwip_bufferManager.h"
//#include "lwip_utils.h"
#include "lwip_redirectHelper.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

static char *lwip_el_perGroupLoggingPath = NULL;

char *lwip_el_getPerGroupLoggingPath() {
	if (lwip_el_perGroupLoggingPath == NULL) {
		lwip_el_perGroupLoggingPath = lwip_bm_malloc(PATH_MAX);
		sprintf(lwip_el_perGroupLoggingPath, LWIP_EXTENDEDLOGGING_DIR "/%d.perGroupLogging", getpgid(0));
		lwip_createDirsIgnLast_with_permissions(lwip_el_perGroupLoggingPath, -1, S_IRWXU|S_IRWXG|S_IROTH|S_IXOTH);
		int fd = open(lwip_el_perGroupLoggingPath, S_IRWXU|S_IRWXG|S_IRWXO|O_CREAT|O_EXCL);
		if (fd != -1) {
			fchmod(fd, S_IRWXU|S_IRWXG|S_IRWXO);
			close(fd);
		}
	}
	return lwip_el_perGroupLoggingPath;
}
