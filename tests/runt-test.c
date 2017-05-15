/**
 * Test program for runt. Prints a list of open descriptors and their resolved
 * path names.
 */

#include <stdio.h>
#include "test-util.h"

int main(int argc, char** argv) {
	printf("In ./runt_test, open files are:\n");
	print_open_files();
	return 0;
}
