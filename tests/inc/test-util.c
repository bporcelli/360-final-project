#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include "common.h"
#include "util.h"
#include "level.h"

char *level_to_string(int level) {
	return SIP_LV_HIGH == level ? "BENIGN" : "UNTRUSTED";
}

void print_open_files() {
	DIR* dp;
	struct dirent* entry;
	char* path;
	int fd, level;

	if ((dp = opendir("/proc/self/fd")) == NULL) {
		printf("Failed to open /self/proc/fd :(\n");
		return;
	}

	printf("\nFD, PATH, LEVEL\n");
	printf("------------------------------------------------\n");

	while ((entry = readdir(dp)) != NULL) {
		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			continue;
		}

		fd = atoi(entry->d_name);
		path = sip_fd_to_path(fd);

		if (path == NULL) {
			printf("Couldn't resolve path for fd %d.\n", fd);
			continue;
		}

		level = sip_path_to_level(path);

		printf("%d, %s, %s\n", fd, path, level_to_string(level));

		free(path);
	}

	printf("\n");

	closedir(dp);
}
