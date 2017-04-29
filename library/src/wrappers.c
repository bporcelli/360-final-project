#define _GNU_SOURCE /* Must include to use RTLD_NEXT pseudo-handle with dlsym(3) */

#include "wrappers.h"

/**
 * Basic wrapper for open(2). It logs the open request, then invokes
 * glibc open(2) with the given arguments.
 *
 * Note that the function prototype for open(2) is defined in <fcntl.h>.
 */
wrapper(int, open, const char *__file, int __oflag, ...) {
	va_list args;

	mode_t mode = 0;

	/* Initialize variable argument list */
	va_start(args, __oflag);

	/* Mode only considered when flags includes O_CREAT or O_TMPFILE */
	if (__oflag & O_CREAT || __oflag & O_TMPFILE)
		mode = va_arg(args, mode_t);

	logmsg("intercepted open call with file=%s, flags=%d, mode=%d\n", __file, __oflag, mode);

	/* Destory va list */
	va_end(args);

	_open = dlsym(RTLD_NEXT, "open");
	return _open(__file, __oflag, mode);
}