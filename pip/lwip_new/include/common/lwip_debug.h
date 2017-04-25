/* * Portable Integrity Protection (PIP) System -
 * Copyright (C) 2012 Secure Systems Laboratory, Stony Brook University
 *
 * This file is part of Portable Integrity Protection (PIP) System.
 *
 * Portable Integrity Protection (PIP) System is free software: you can redistribute it
 * and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Portable Integrity Protection (PIP) System is distributed in the hope that it will
 * be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Portable Integrity Protection (PIP) System.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef __LWIP_DEBUG_H_
#define __LWIP_DEBUG_H_

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "sys/syscall.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include "lwip_utils.h"
#include "lwip_common.h"

#define MAX_LOG_MSG_LEN 2000


#define TEST_PGID


#define LWIP_DEBUG_ON


#define LWIP_LOG_VIOLATION_ON


#ifdef LWIP_OS_BSD
#define LOGGING_PATH "/usr/home/" LWIP_CF_REAL_USERNAME "/Desktop"
#elif defined LWIP_OS_LINUX
#define LOGGING_PATH "/home/" LWIP_CF_REAL_USERNAME "/Desktop"
#endif

#define ALL_LOGGING_PATH LOGGING_PATH "/all2"
#define INFO_LOGGING_PATH LOGGING_PATH "/info2"
#define ERROR_LOGGING_PATH LOGGING_PATH "/error2"
#define CRITICAL_LOGGING_PATH LOGGING_PATH "/critical2"
#define ASSERT_LOGGING_PATH LOGGING_PATH "/assert2"
#define VIOLATION_LOGGING_PATH LOGGING_PATH "/violation2"
#define ABSTRACT_EXECUTION_LOGGING_PATH LOGGING_PATH "/ae2"
#define WARNING_LOGGING_PATH LOGGING_PATH "/warn2"
#define DPKG_VIOLATION_PATH LOGGING_PATH "/dpkg_violation2"
#define INSTALL_MODE_PATH "/tmp/in2"
#define SYSTEM_INVARIANT_VIOLATION_PATH LOGGING_PATH "/invariant_violation2"
#define UNEXPECTED_PATH LOGGING_PATH "/unexpected2"
#define HIGHI_VIOLATION_PATH LOGGING_PATH "/highI_violation2"
#define LOWI_VIOLATION_PATH LOGGING_PATH "/lowI_violation2"

#define LWIP_LOG_FILES ALL_LOGGING_PATH, \
	INFO_LOGGING_PATH, \
	ERROR_LOGGING_PATH, \
	CRITICAL_LOGGING_PATH, \
	VIOLATION_LOGGING_PATH, \
	ASSERT_LOGGING_PATH, \
	WARNING_LOGGING_PATH, \
	ABSTRACT_EXECUTION_LOGGING_PATH, \
	DPKG_VIOLATION_PATH, \
	INSTALL_MODE_PATH, \
	HIGHI_VIOLATION_PATH, \
	LOWI_VIOLATION_PATH, \
	UNEXPECTED_PATH



extern __thread char lwip_debug_msg_buf[MAX_LOG_MSG_LEN];

#ifdef LWIP_OS_BSD

#define MSG_FORMAT "[%d-%ld] (%s) %s %d "
#define MSG_CONTENT getpid(), __lwip_tid , lwip_util_getProcessImagePath(), __func__, __LINE__
#define LWIP_CUSTOM_LOG(PATH, format, args...) \
  do { \
    int saved_errno = errno; \
    int byteCount = 0; \
    long int __lwip_tid; \
    syscall(SYS_thr_self, &__lwip_tid); \
    int fd = syscall(SYS_open, PATH, O_APPEND|O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH); \
    if (fd >= 0) { \
      byteCount = snprintf(lwip_debug_msg_buf, MAX_LOG_MSG_LEN, format "\n", ##args); \
      syscall(SYS_write, fd, lwip_debug_msg_buf, byteCount); \
      syscall(SYS_close, fd); \
      fd = syscall(SYS_open, ALL_LOGGING_PATH, O_APPEND|O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH); \
      if (fd >= 0) { \
        syscall(SYS_write, fd, lwip_debug_msg_buf, byteCount); \
        syscall(SYS_close, fd); \
      } \
    } \
    errno = saved_errno; \
  } while (0)

#elif defined LWIP_OS_LINUX

#define MSG_FORMAT "[%d-%d] (%s) %s %s %d "
#define MSG_CONTENT (pid_t)syscall(SYS_getpid), (pid_t)syscall(SYS_gettid) , lwip_util_getProcessImagePath(), __FILE__, __func__, __LINE__



#define LWIP_CUSTOM_LOG(PATH, format, args...)				\
  do {									\
    int saved_errno = errno;						\
    int byteCount = 0;							\
    int pFile = syscall(SYS_open, PATH, O_WRONLY|O_APPEND, S_IRWXU|S_IWGRP|S_IWOTH); \
    if (pFile == -1 && errno == ENOENT) \
      pFile = syscall(SYS_open, PATH, O_WRONLY|O_APPEND|O_CREAT, S_IRWXU|S_IWGRP|S_IWOTH); \
    if (pFile > 0) {							\
      byteCount = snprintf(lwip_debug_msg_buf, MAX_LOG_MSG_LEN, format "\n", ##args); \
      syscall(SYS_write, pFile, lwip_debug_msg_buf, byteCount);		\
      syscall(SYS_close, pFile);					\
      pFile = syscall(SYS_open, ALL_LOGGING_PATH, O_WRONLY|O_APPEND|O_CREAT, S_IRWXU|S_IWGRP|S_IWOTH); \
      if (pFile > 0) {							\
	syscall(SYS_write, pFile, lwip_debug_msg_buf, byteCount);	\
	syscall(SYS_close, pFile);					\
      }									\
    }									\
    errno = saved_errno;						\
  } while (0)


#endif

#define LWIP_LOG(PATH, format, args...) LWIP_CUSTOM_LOG(PATH, MSG_FORMAT format, MSG_CONTENT, ##args)


#ifdef LWIP_DEBUG_ON
#define LWIP_INFO(format, args...) LWIP_LOG(INFO_LOGGING_PATH, format, ##args)
#else
#define LWIP_INFO(format, args...)
#endif

#define LWIP_SPECIAL(format, args...) LWIP_LOG(INFO_LOGGING_PATH, " *************** " format, ##args)
#define LWIP_VIOLATION(format, args...) LWIP_LOG(VIOLATION_LOGGING_PATH, format, ##args)
#define LWIP_ERROR(format, args...) LWIP_LOG(ERROR_LOGGING_PATH, format, ##args)
#define LWIP_CRITICAL(format, args...) LWIP_LOG(CRITICAL_LOGGING_PATH, format, ##args)
#define LWIP_AE(format, args...) LWIP_LOG(ABSTRACT_EXECUTION_LOGGING_PATH, "%d " format, getpgid(0), ##args)
#define LWIP_IN(format, args...) LWIP_LOG(INSTALL_MODE_PATH, format, ##args)
#define LWIP_UNEXPECTED(format, args...) LWIP_LOG(UNEXPECTED_PATH, format, ##args)
#define LWIP_HIGHI_VIOLATION(format, args...) LWIP_LOG(HIGHI_VIOLATION_PATH, format, ##args)
#define LWIP_LOWI_VIOLATION(format, args...) LWIP_LOG(LOWI_VIOLATION_PATH, format, ##args)

#define LWIP_UNEXPECTED_PATH_REACHED LWIP_UNEXPECTED("Unexpected Path Reached")

#define LWIP_INVARIANT_VIOLATION(format, args...) LWIP_LOG(SYSTEM_INVARIANT_VIOLATION_PATH, format, ##args)

#define LWIP_ASSERT1(expression) \
	do { \
		if (!(expression))	\
			LWIP_LOG(ASSERT_LOGGING_PATH, "ASSERT FAILED: " #expression); \
	} while(0)

#define LWIP_ASSERT(expression, format, args...) \
	do { \
		if (!(expression))	\
			LWIP_LOG(ASSERT_LOGGING_PATH, "ASSERT FAILED: %s, " format, #expression, ##args); \
	} while (0)

#define LWIP_WARNIF(expression, format, args...) \
	do { \
		if (expression)	\
			LWIP_LOG(WARNING_LOGGING_PATH, format, ##args); \
	} while (0)




#endif /* __LWIP_DEBUG_H_ */

