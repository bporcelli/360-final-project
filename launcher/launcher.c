/**
 * This command-line utility accepts a program name and zero or more arguments
 * as input. It closes open descriptors for benign files, then executes the
 * input program as the untrusted user. The launcher must be able to change
 * its real, effective, and saved UID, so it should be setuid-root.
 */

#define _GNU_SOURCE /* setresuid/setresgid */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "logger.h"
#include "level.h"
#include "common.h"
#include "util.h"


void close_benign_files() {
	DIR* dp;
	struct dirent* entry;

	/* /proc/self/fd contains "one entry for each file which the process has
	 * open, named by its file descriptor and which is a symbolic link to the
	 * actual file." */
	if ((dp = opendir("/proc/self/fd")) == NULL) {
		printf("Failed to open /self/proc/fd. The program will not be executed.\n");
		exit(1);
	}

	while ((entry = readdir(dp)) != NULL) {

		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			continue;
		}

		/* Entry name is a file descriptor. */
		int fd = atoi(entry->d_name);

		/* Resolve descriptor to path. */
		char* path = sip_fd_to_path(fd);

		if (path == NULL) {
			printf("Path resolution for descriptor %d failed. Aborting.\n", fd);
			exit(1);
		}
		
		/* Files in /dev/pts are pseudo-terminals -- software-based terminals
		 * used by applications like shells to receive input and display out-
		 * put. We don't want to block untrusted applications from receiving
		 * input or printing output, so we leave these files open. */
		if (strstr(path, "/dev/pts") == path) {
			free(path);
			continue;
		}

		/* If file is benign and open for writing, downgrade it by setting the
		 * group ownership to the untrusted group. If that fails, attempt to 
		 * close it. */
		int mode = fcntl(fd, F_GETFL) & O_ACCMODE;

		if (mode & O_RDWR || mode & O_WRONLY) {

			/* Note: can't use S_ISFIFO to detect pipes reliably -- only FIFOs
			 * (named pipes) will be detected. Therefore, we have add a special
			 * check based on the resolved path name here. Pipes are always
			 * considered high integrity. */
			if (SIP_LV_HIGH == sip_fd_to_level(fd) || strstr(path, "pipe:[") != NULL) {
				if (sip_downgrade_fd(fd) == 0) {
					sip_info("Downgraded file %s to level SIP_LV_LOW.\n", path);
				} else if (close(fd) == -1) {
					sip_error("Failed to downgrade or close high integrity file %s\n", path);
					printf("High integrity file %s (%d) open for writing. Aborting.\n", path, fd);
					free(path);
					exit(1);
				}
			}
		}

		free(path);
	}

	closedir(dp);
}


int main(int argc, char* argv[]) {

	if (argc < 2) {
		printf("Usage: runt PROGRAM [ARGS]\n");
		return 1;
	}

	sip_info("Running program %s as untrusted.", argv[1]);

	/* Close all open benign files/pipes */
	close_benign_files();

	/* Set real, effective, and saved group ID & user ID (order important) */
	if (setresgid(SIP_UNTRUSTED_USERID, SIP_UNTRUSTED_USERID, SIP_UNTRUSTED_USERID) < 0) {
		perror("call to setresgid failed");
		return 1;
	}
	if (setresuid(SIP_UNTRUSTED_USERID, SIP_UNTRUSTED_USERID, SIP_UNTRUSTED_USERID) < 0) {
		perror("call to setresuid failed");
		return 1;
	}

	/* Execute program */
	execvp(argv[1], &argv[1]);
	perror("execvp failed");
	return 1;
}
