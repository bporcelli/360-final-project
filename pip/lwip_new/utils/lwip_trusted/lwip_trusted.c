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

#include <dirent.h>
#include "lwip_common.h"
#include <unistd.h>
#include <stdio.h>
#include "lwip_debug.h"
#include "lwip_level.h"
#include <fcntl.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <sys/user.h>
#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/sysctl.h>

#include <stdlib.h>

#ifdef LWIP_OS_BSD
#include <libutil.h>
#endif

#include <sys/wait.h>
#include <sys/types.h>
#include <signal.h>


#include <sys/select.h>
#include "lwip_utils.h"
#include "lwip_redirectHelper.h"

#include "lwip_iso_conf.h"

#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	char *command = malloc(sysconf(_SC_ARG_MAX));
	int i;
	long count = 0;

	setenv("LWIP_TRUSTED", "1", 1);

//	printf("** This tool introduced for bypassing the library policy enforcement\n");
//	printf("** It is for convenient purpose only.\n\n");

	for (i = 1; i < argc; i++) {
		if (count > sysconf(_SC_ARG_MAX))
			printf("too long arguments");
		if (strchr(argv[i], '"') != NULL)
			count += snprintf(command + count, sysconf(_SC_ARG_MAX) - count, "\"%s\" ", argv[i]);
		else
			count += snprintf(command + count, sysconf(_SC_ARG_MAX) - count, "%s ", argv[i]);

	}

	char *args[] = {"/bin/sh", "-c", command, NULL};
	execv("/bin/sh", args);

	free(command);
	printf("exec failed: errno: %d", errno);
	
	return 0;
}

