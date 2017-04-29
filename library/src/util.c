#include "util.h"

/**
 * Write a log message to stderr.
 */
void logmsg(const char *format, ...) {
	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
}
