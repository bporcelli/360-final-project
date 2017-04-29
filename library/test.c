/**
 * Basic program to demonstrate that syscall interception is
 * working.
 *
 * When this program executes, new log entires should be added
 * to the file "log.txt."
 */

#include <unistd.h>
#include <fcntl.h>

int main(int argc, char** argv) {
	int fd = open("test.txt", O_CREAT | O_WRONLY, S_IRWXU);
	write(fd, "test", 4);
	return 0;
}