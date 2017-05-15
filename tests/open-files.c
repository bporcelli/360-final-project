#include <sys/types.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "level.h"
#include "test-util.h"

/**
 * Open a benign file for reading, then open the same file for writing.
 *
 * Expected Result: First open succeeds, second open fails.
 */
int main(int argc, char **argv) {
	int fd;
	uid_t uid = geteuid();
	int ulevel = sip_uid_to_level(uid);

	printf("Running with UID %d (%s)\n", uid, level_to_string(ulevel));

	printf("Attempting to open ./files/benign-file.txt for reading.\n");

	if ((fd = open("./files/benign-file.txt", O_RDONLY)) < 0) {
		perror("Error opening file");
	} else {
		printf("File opened for reading successfully!\n");
		close(fd);
	}

	printf("Attempting to open ./files/benign-file.txt for reading and writing.\n");

	if ((fd = open("./files/benign-file.txt", O_RDWR)) < 0) {
		perror("Error opening file");
	} else {
		printf("File opened for writing successfully!\n");
		close(fd);
	}
	return 0;
}