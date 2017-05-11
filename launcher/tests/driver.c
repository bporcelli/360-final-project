/**
 * Test driver.
 *
 * Opens two benign files for writing, one which can be downgraded and one which
 * can't. It also opens an untrusted file for writing. Finally, it executes the 
 * test program with runt.
 *
 * If runt is working properly, the list of files printed SHOULD include
 * BENIGN_FILE and UNTRUSTED_FILE, but should not include BENIGN_FILE_ND.
 *
 * NOTE: you should run this from the 'launcher' directory
 */

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "common.h"

#define UNTRUSTED_FILE "untrusted.txt"
#define BENIGN_FILE "benign.txt"
#define BENIGN_FILE_ND "benign-nd.txt"

int main(int argc, char** argv) {
	FILE* benign = fopen(BENIGN_FILE, "w");
	FILE* benign_nd = fopen(BENIGN_FILE_ND, "w");
	FILE* untrusted = fopen(UNTRUSTED_FILE, "w");

	if (benign == NULL || benign_nd == NULL || untrusted == NULL) {
		perror("fopen failed");
		return 1;
	}

	/* untrusted should be owned by the untrusted group. */
	chown(UNTRUSTED_FILE, -1, SIP_UNTRUSTED_USERID);

	/* benign should be owned and group owned by the real user. */
	chown(BENIGN_FILE, SIP_REAL_USERID, SIP_REAL_USERID);

	/* benign_nd should be owned by the real user and group owned
	 * by the trusted group. This combination will block a downgrade
	 * attempt. */
	chown(BENIGN_FILE_ND, SIP_REAL_USERID, SIP_TRUSTED_GROUP_GID);
	chmod(BENIGN_FILE_ND, S_IRWXU|S_IRGRP);

	/* run test */
	char* args[] = {"runt", "tests/test", NULL};
	execvp("runt", args);
	
	/* execvp shouldn't return -- something went wrong. */
	perror("execvp error");
	return 1;
}
