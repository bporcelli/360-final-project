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

#ifndef __LWIP_IN_UTILS_H__
#define __LWIP_IN_UTILS_H__

#include "lwip_common.h"
#include "lwip_debug.h"

//int lwip_in_canExecuteAsTrusted(char *imagePath, char **argv, char **envp);
//int lwip_in_ExecuteAsTrusted(char *imagePath, char **argv, char **envp);

char *lwip_in_deb2packageName(char *debName, char *buffer);

#define LWIP_IN_VALIDATION_SCRIPTS_DIR LWIP_USER_HOME_LWIP_DIR "/executables/dpkg/validations"
#define LWIP_IN_VS_DIFF_BLSR LWIP_IN_VALIDATION_SCRIPTS_DIR "/diff_BLSR.sh"
#define LWIP_IN_VS_DIFF_LSR LWIP_IN_VALIDATION_SCRIPTS_DIR "/diff_LSR.sh"
#define LWIP_IN_VS_APPEND_ONLY LWIP_IN_VALIDATION_SCRIPTS_DIR "/diff_appendOnly.sh"
#define LWIP_IN_VS_DIFF_LSR_WN LWIP_IN_VALIDATION_SCRIPTS_DIR "/diff_LSR_wn.sh"
#define LWIP_IN_VS_DIFF_BLSR_INSTALLED LWIP_IN_VALIDATION_SCRIPTS_DIR "/diff_BLSR_wm.sh"
#define LWIP_IN_VS_DIFF_BLSR_DPKG_AVAILABLE LWIP_IN_VALIDATION_SCRIPTS_DIR "/diff_BLSR_dpkg_available.sh"

#define LWIP_IN_LOG_MANAGEMENT_DIR LWIP_USER_HOME_LWIP_DIR "/installer/records"
#define LWIP_IN_LOG_CREATE_RECORD LWIP_IN_LOG_MANAGEMENT_DIR "/insert_record.sh"
#define LWIP_IN_LOG_REMOVE_RECORD LWIP_IN_LOG_MANAGEMENT_DIR "/remove_record.sh"
#define LWIP_IN_LOG_GET_RECORD LWIP_IN_LOG_MANAGEMENT_DIR "/get_record.sh"
#define LWIP_IN_LOG_GET_KEY LWIP_IN_LOG_MANAGEMENT_DIR "/get_key.sh"



#define LWIP_IN_REPORT_PATH "/tmp/installation_report"

#define LWIP_IN_REPORT(format, args...) LWIP_LOG(LWIP_IN_REPORT_PATH, format, ##args)

#ifndef IN_MSG_FORMAT

#define IN_MSG_FORMAT "%d, %d, %s, "
#define IN_MSG_CONTENT getpid(), getuid(), lwip_util_getProcessImagePath()

#define LWIP_IN_TRACE(format, args...) \
	do { \
		LWIP_CUSTOM_LOG(LWIP_IN_TRACE_FILE, IN_MSG_FORMAT format, IN_MSG_CONTENT, ##args); \
	} while (0)

#endif

#define LWIP_IN_TRACE_MSG(format, args...) \
	do {\
		 LWIP_IN_TRACE("Message, " format, ##args); \
	} while (0)


		//if (lwip_isIN_mode) 

#endif /* __LWIP_IN_UTILS_H__ */


