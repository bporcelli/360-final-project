#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

/*
 *  Display result of getuid and getgid
 *
 *  Expected Result: Action Denied
 */
int main(int argc, char **argv) {
	printf("Result of getuid(): " + getuid());
	printf("Result of getgid(): " + getgid());
}