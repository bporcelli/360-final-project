#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include "level.h"
#include "test-util.h"

int main(int argc, char** argv) {
	uid_t uid = geteuid();
	int ulevel = sip_uid_to_level(uid);

	printf("Running with UID %d (%s)\n", uid, level_to_string(ulevel));

	printf("Attempting to unlink ./files/benign-file.txt\n");

	if (unlink("./files/benign-file.txt") < 0) {
		perror("unlink failed");
	} else {
		printf("unlink successful!\n");
	}

	printf("Attempting to unlink ./files/untrusted-file.txt\n");

	if (unlink("./files/untrusted-file.txt") < 0) {
		perror("unlink failed");
	} else {
		printf("unlink successful!\n");
	}
}
