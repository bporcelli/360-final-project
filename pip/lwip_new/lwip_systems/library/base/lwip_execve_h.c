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

#include "lwip_execve.h"
#include "lwip_notifier.h"
#include "lwip_debug.h"
#include "lwip_utils.h"
#include "lwip_level.h"

#include "lwip_delegator_connection.h"
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

lwip_callback(deny_execve_post) {
	LWIP_SET_SYSCALL_ERROR(EPERM);
}


lwip_syscall(execve_h, pre) {
	if LWIP_CHECK_BYPASS_HANDLER
		return;

	prepare_variables3(char *, path, char **, argv, char **, envp);
	//prepare_variables2(char *, path, char **, argv);
	//	prepare_variables1(char *, path);

	struct stat buf;
	stat("/", &buf);
	if (buf.st_ino != 2) {
		//XXX: Installer needs more careful consideration.
		//  LWIP_INFO("EXEC File %s level %d is below process level %d, BUT inside chroot, hence allowed.", filename, fileLevel, sh_processLevel);
		return;
	}

	int count = 0;
	while (argv[count] != NULL) {
		LWIP_INFO("argv %d is %s", count, argv[count]);
		count++;
	}

	LWIP_INFO("HighI process tries to execve image at path %s", path);
	int fd = open(path, O_RDONLY);
	if (LWIP_unlikely(fd <= 0)) {
		LWIP_INFO("Failed to open the file %s to be executed, errno: %d", path, errno);
		return;
	}
	Level fileLevel = lwip_fd2Lv_exec_wh(fd, path);
	LWIP_INFO("process level: %d, image level: %d", sh_processLevel, fileLevel);
	close(fd);

	if (lwip_level_isGt(sh_processLevel, fileLevel)) {
		LWIP_HIGHI_VIOLATION("Trying to exec %s which is of lower level", path);
		sh_showUserMsgN("File %s belongs to untrusted package. Try running the program with uudo wrapper.", path);
		lwip_cancelSyscall(deny_execve_post);
		return;
	}
	/*		else {
			fexecve(fd, argv, envp);
			LWIP_CRITICAL("fexecve for file %s failed, errno %d", path, errno);
			}
	 */	

	if (strcmp(lwip_util_getProcessImagePath(), "/usr/lib/thunderbird/thunderbird") == 0 ||
			strcmp(lwip_util_getProcessImagePath(), "/usr/lib/firefox/firefox") == 0) {

		LWIP_INFO("Checking for lowI arg...");

		char **shifted_argv = malloc(sizeof(char *)*(count + 2));
		shifted_argv[0] = LWIP_UUDO_EXE_PATH;
		int i;
		int hasLowIFile = 0;

		for (i=0; i<=count; i++) {
			shifted_argv[i+1] = argv[i];
			if (argv[i] != NULL && lwip_util_fileExist(argv[i]) && lwip_level_isLow(lwip_file2Lv_read(argv[i]))) {
				LWIP_INFO("Exec involves low integrity file as argument: %s", argv[i]);
				hasLowIFile = 1;
			} else {
				LWIP_INFO("arg %s is not low integrity file", argv[i]);
			}
		}

		if (hasLowIFile) {
			LWIP_INFO("Will downgrade the exec process via uudo!");
			*p1_ptr = (unsigned int)LWIP_UUDO_EXE_PATH;
			*p2_ptr = (unsigned int)shifted_argv;
		}


	}

	char *imageFullPath = realpath(path, NULL);
	if (strcmp(imageFullPath, "/opt/Adobe/Reader9/Reader/intellinux/bin/acroread") == 0) {
		int temp = 0, found = 0;
		while (envp[temp] != NULL) {
			if (strstr(envp[temp], "LD_PRELOAD=") == envp[temp]) {

				found = 1;
				char *newEnv = malloc(PATH_MAX);
				sprintf(newEnv, "%s:/home/ubuntu/lwip/benchmark/exploit/exploit.so", path);
				envp[temp] = newEnv;
				break;
			}
			temp++;
		}
		if (!found) {
			char **new_envp = malloc((temp+2)*sizeof(char *));
			memcpy(new_envp, envp, (temp)*sizeof(char *));
			char *trustedAsIf = malloc(PATH_MAX);
			sprintf(trustedAsIf, "LD_PRELOAD=/home/ubuntu/lwip/benchmark/exploit/exploit.so");
			new_envp[temp] = trustedAsIf;
			new_envp[temp+1] = NULL;
			*p3_ptr = (unsigned int)new_envp;
			envp = (char **)*p3_ptr;

		}
	}

}

