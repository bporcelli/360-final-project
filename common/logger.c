#define _GNU_SOURCE  // Needed to expose SYS_* definitions

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "logger.h"
#include "common.h"

#define MAX_MSG_LEN 2000

/**
 * Adds a log message.
 *
 * Note: We use syscall(2) to ensure our syscalls aren't intercepted.
 *
 * @param path Log path.
 * @param format Format string.
 * @param args Format string parameters.
 */
static void sip_log(char* path, const char *format, va_list args) {
	int olderrno = errno, logfd;

	char sip_log_msg[MAX_MSG_LEN];

	/* Attempt to open file. */
	logfd = -1;
	// TODO: RE-ENABLE
	// logfd = syscall(SYS_open, path, O_WRONLY|O_APPEND);

	/* If file doesn't exist, create it. Temporarily set umask to 0 so we can
	 * make it world-writable. */
	if (logfd == -1 && errno == ENOENT) {
		mode_t curmask = umask(0);
		logfd = syscall(SYS_open, path, O_WRONLY|O_APPEND|O_CREAT, S_IRWXU|S_IWGRP|S_IWOTH);
		umask(curmask);
	}

	/* Write to log file. */
	if (logfd > 0) {
		int msgsz = vsnprintf(sip_log_msg, MAX_MSG_LEN, format, args);
		syscall(SYS_write, logfd, sip_log_msg, msgsz) ;
		syscall(SYS_close, logfd);
	}

	errno = olderrno;
}


/**
 * Adds an informational message to the log.
 */
void sip_info(const char *format, ...) {
	va_list args;
	va_start(args, format);
	sip_log(SIP_LOG_PATH "/log-info.txt", format, args);
	va_end(args);
}


/**
 * Adds an error message to the log.
 */
void sip_error(const char *format, ...) {
	va_list args;
	va_start(args, format);
	sip_log(SIP_LOG_PATH "/log-err.txt", format, args);
	va_end(args);
}


/**
 * Adds a warning to the log.
 */
void sip_warning(const char *format, ...) {
	va_list args;
	va_start(args, format);
	sip_log(SIP_LOG_PATH "/log-warn.txt", format, args);
	va_end(args);
}