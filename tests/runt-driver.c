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
 * NOTE: you should run this from the 'tests' directory
 */

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include "test-util.h"

#define FILEDIR "files" 

int main(int argc, char** argv) {

	FILE* benign = fopen(FILEDIR "/benign-file.txt", "w");
	FILE* benign_nd = fopen(FILEDIR "/benign-file-no-downgrade.txt", "w");
	FILE* untrusted = fopen(FILEDIR "/untrusted-file.txt", "w");

	if (benign == NULL || benign_nd == NULL || untrusted == NULL) {
		perror("fopen failed");
		return 1;
	}

	printf("Before running ./runt_test, open files are:\n");
	print_open_files();

	char* args[] = {"runt", "bin/runt_test", NULL};
	execvp("runt", args);
	
	/* execvp shouldn't return -- something went wrong. */
	perror("execvp error");
	return 1;
}
