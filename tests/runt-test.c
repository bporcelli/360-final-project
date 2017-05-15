/**
 * Test program for runt. Prints a list of open descriptors and their resolved
 * path names.
 */

#include <sys/types.h>
#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include "util.h"

int main(int argc, char** argv) {
	DIR* dp;
	struct dirent* entry;

	if ((dp = opendir("/proc/self/fd")) == NULL) {
		printf("Failed to open /self/proc/fd :(\n");
		return 1;
	}

	printf("AFTER - Open files are:\n");

	while ((entry = readdir(dp)) != NULL) {
		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			continue;
		}

		/* Entry name is a file descriptor. */
		int fd = atoi(entry->d_name);

		printf("\t%d --> %s\n", fd, sip_fd_to_path(fd));
	}

	closedir(dp);

	return 0;
}
