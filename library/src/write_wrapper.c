#define _GNU_SOURCE /* Must include to use RTLD_NEXT pseudo-handle with dlsym(3) */

#include "write_wrapper.h"

/**
 * Basic wrapper for write(2). It logs the write request, then invokes
 * glibc write(2) with the given arguments.
 *
 * Note that the function prototype for write(2) is defined in <unistd.h>.
 */

ssize_t write_wrapper(int fd, const void *buf, size_t count) {

	logmsg("Intercepted write call with fd: %d, count: %lu\n", fd, count);

    _write = dlsym(RTLD_NEXT, "write");
    return _write(fd, buf, count);
}

