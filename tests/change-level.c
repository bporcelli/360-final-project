#include <unistd.h>
#include <stdio.h>
#include "level.h"
#include "test-util.h"
#include "common.h"

/**
 * Attempts to change the integrity level of benign-file.txt
 *
 * Expected Result: chown fails.
 */
int main(int argc, char** argv) {
	uid_t uid = geteuid();
	int ulevel = sip_uid_to_level(uid);

	printf("Running with UID %d (%s)\n", uid, level_to_string(ulevel));

	printf("Attempting to downgrade file ./files/benign-file.txt to low integrity.\n");

	if (chown("./files/benign-file.txt", SIP_UNTRUSTED_USERID, -1) < 0) {
		perror("chown failed");
	} else {
		printf("Downgrade successful!");
	}
}
