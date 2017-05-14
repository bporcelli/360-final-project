/**
 * Test for helper bridge methods. Sends a SYS_delegatortest call to daemon, then
 * prints the return value and errno.
 *
 * If the test succeeds, the return value should be 0 and errno should be 42.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <errno.h>
#include "bridge.h"

int main(int argc, char** argv) {
	// TODO
	return 0;
}
