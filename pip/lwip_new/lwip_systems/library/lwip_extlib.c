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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "sys/syscall.h"
#include <sys/stat.h>

#include <fcntl.h>

#include <errno.h>
#include <limits.h>

#include "lwip_common.h"


//#define LWIP_NOINTERCEPTION_BUT_LOG_ERROR

// #define LWIP_LOG_PER_PROCESSGRP_ERROR

#ifdef LWIP_OS_LINUX
#include <linux/net.h>

#define SYS_connect SYS_CONNECT 
#define SYS_sendmsg SYS_SENDMSG   

#endif

#include "lwip_debug.h"
#include "lwip_syscall_handler.h"

#include "lwip_utils.h"
#include "lwip_level.h"
#include "lwip_trusted.h"

#include "lwip_syscall_ftb.h"
#include "lwip_ae_utils.h"

#include "lwip_delegator_connection.h"

#include "lwip_trackOpen.h"
#include "lwip_extendedLogging.h"

__thread int entered = 0;
__thread int saved_syscall_no = 0;
__thread int syscall_no = 0;
static int initialized = 0;

__thread int lwip_bypass_handler = 0;

extern char **environ;
static int environ_inspected = 0;

static int do_not_intercept = 0;

/* Syscalls made by these executables are not intercepted */
const char * const sh_ignored_process_path[] = {
  LWIP_REDIRECTHELPER_EXE_PATH,
  LWIP_DAEMON_EXE_PATH,
  LWIP_ROOT_DAEMON_EXE_PATH,
  LWIP_RUDO_EXE_PATH,
  "/home/ubuntu/lwip/lwip_new/lwip_systems/lwip_ae/lwip_ae",
  LWIP_2UID_EXE_PATH,
  "/lwip/executables/lwip_iso",
  "/home/ubuntu/lwip/lwip_new/secure_installer/lwip_in_apt-get2/lwip_in_apt-get",
  "/home/ubuntu/lwip/lwip_new/secure_installer/lwip_in_apt-get3/lwip_in_apt-get",
  "/lwip/executables/dpkg/lwip_in_isodpkg",
  "/lwip/executables/dpkg/lwip_in_genericInstaller",
  NULL
};

__thread int lwip_parameter_store[LWIP_MAX_PARAMETER_TOSAVE];
__thread int lwip_restore_parameter_cnt = 0;
__thread int saved_errno = 0;

Level sh_processLevel = -1;

__thread int sh_restore_p1;
__thread unsigned int sh_original_p1;

__thread void (*sh_custom_callback) lwip_syscall_post_signature = NULL;

__thread char *syscall_rename_buffer1 = NULL, *syscall_rename_buffer2 = NULL;

int lwip_isAE_mode = 0;
int lwip_isTX_mode = 0;
int lwip_isRD_mode = 0;
int lwip_isISO_mode = 0;
int lwip_isIN_mode = 0;

/* THE BELOW FUNCTIONS DO NOT APPEAR TO BE USED -- COMMENTING OUT FOR NOW */

// void initialization() {

//   //  do_not_intercept = 1;
//   char *process_img_path = lwip_util_getProcessImagePath();


//   /* FreeBSD doesn't have SYS_getuid32 */
//   uid_t process_ruid = syscall(SYS_getuid);
//   uid_t process_euid = syscall(SYS_geteuid);

//   LWIP_INFO("Process started: %s ruid: %d, euid: %d", process_img_path, process_ruid, process_euid);
 
//   if (lwip_util_stringInArray(process_img_path, sh_ignored_process_path)) {
//     LWIP_INFO("Process is ignored process.");
//     do_not_intercept = 1;
//     return;
//   }

//   sh_processLevel = lwip_level_min(lwip_uid2Lv(process_ruid), lwip_uid2Lv(process_euid));
//   if (sh_processLevel == LV_HIGH)
//     LWIP_INFO("Process level is high");
//   else
//     LWIP_INFO("Process level is low");


//   if (process_ruid == LWIP_CF_UNTRUSTEDROOT_USERID && process_euid == LWIP_CF_UNTRUSTEDROOT_USERID) {
// 	  lwip_isIN_mode = 1;
// 	  LWIP_INFO("LWIP_INSTALLATION flag is set!");
// 	  LWIP_IN("LWIP_INSTALLATION flag is set!");
// 	  //To make sure that the socket used is the root daemon
// 	  sh_closeDelegatorSocket();
//   }

// #ifdef LWIP_TRACK_IMPLICIT_EXPLICIT


//   if (LWIP_PROCESS_LV_HIGH) {

// 	  //cannot call malloc in initialization???? skype will result in segfault.
// 	  FILE *cmdline = fopen("/proc/self/cmdline", "rb");
// 	  char *arg = lwip_bm_malloc(PATH_MAX);
// 	  size_t size = 0;//PATH_MAX;



// 	  if (cmdline != NULL) {
// 		  while (getdelim(&arg, &size, 0, cmdline) != -1)
// 			  lwip_trackOpen_addExplict(arg);


// 		  LWIP_INFO("end of initialization");
// 		  fclose(cmdline);

// 	  }
// 	  lwip_bm_free(arg);
//   }

// #endif

// }

// void pre_handler(int *eax, unsigned int *p1_ptr, unsigned int *p2_ptr, unsigned int *p3_ptr, unsigned int *p4_ptr, unsigned int *p5_ptr, unsigned int *p6_ptr) {

// #ifdef LWIP_NOINTERCEPTION_BUT_LOG_ERROR
// 	return;
// #endif


// 	if (do_not_intercept == 1)
// 		goto out;

// 	if (initialized == 0) {
// 		initialization();
// 		initialized = 1;
// 		if (do_not_intercept == 1)
// 			goto out;
	
// 	}


// 	if (environ_inspected == 0) {
// 		if (environ != NULL) {
// 			environ_inspected = 1;

// 			if (getenv("LWIP_TRUSTED") != NULL) {
// 				LWIP_INFO("LWIP_TRUSTED flag is set. Will ignore the process");
// 				do_not_intercept = 1;
// 				goto out;
// 			}
// 		}
// 	}
	

// 	int *syscall_no_ptr = eax;

// 	saved_syscall_no = *eax;

// 	LWIP_UNSET_BYPASS_HANDLER;

// 	if (LWIP_PROCESS_LV_HIGH) {
// 		if (default_highI_syscall_pre_ftb[*syscall_no_ptr] != NULL)
// 			(*default_highI_syscall_pre_ftb[*syscall_no_ptr])lwip_syscall_pre_invocation;
// 	} else {
// 		if (default_lowI_syscall_pre_ftb[*syscall_no_ptr] != NULL)
// 			(*default_lowI_syscall_pre_ftb[*syscall_no_ptr])lwip_syscall_pre_invocation;
// 	}

// goto out;

// out:
// 	return;
// }


// void post_handler(int syscall_no, unsigned int *eax, unsigned int *flags_ptr, unsigned int *p1_ptr, unsigned int *p2_ptr, unsigned int *p3_ptr, unsigned int *p4_ptr, unsigned int *p5_ptr, unsigned int *p6_ptr) {
	
// 	unsigned int *return_value_ptr = eax;

// #ifdef LWIP_NOINTERCEPTION_BUT_LOG_ERROR
// 	goto logError;
// #endif

// 	if (do_not_intercept)
// 		goto out;


// 	if (sh_custom_callback != NULL) {
// 		sh_custom_callback lwip_syscall_post_invocation;
// 		sh_custom_callback = NULL;
// 		syscall_no = saved_syscall_no;
// 		goto out;
// 		goto nextHandler;
// 	}

// 	if (LWIP_PROCESS_LV_HIGH) {
// 		if (default_highI_syscall_post_ftb[syscall_no] != NULL)
// 			(*default_highI_syscall_post_ftb[syscall_no])lwip_syscall_post_invocation;
// 	} else {
// 		if (default_lowI_syscall_post_ftb[syscall_no] != NULL)
// 			(*default_lowI_syscall_post_ftb[syscall_no])lwip_syscall_post_invocation;
// 	}

// nextHandler:

// 	goto out;

// out:

// #ifdef LWIP_NOINTERCEPTION_BUT_LOG_ERROR
// logError:
// #endif

// #ifdef LWIP_LOG_PER_PROCESSGRP_ERROR

// 	if (LWIP_ISERROR) {
// 		LWIP_EL_PERGROUP("%d: %d", syscall_no, lwip_syscall_errno);
// 	}

// #endif

// 	LWIP_RESTORE_PARAMETERS;
// 	lwip_syscall_freeConvert2FullAndRedirectedPathat_re;
// 	return;
// }



// #ifdef LWIP_OS_LINUX
// void func_enter(unsigned int edi, unsigned int esi, unsigned int ebp, unsigned int sp, unsigned int ebx, unsigned int edx, unsigned int ecx, unsigned int eax) {
// #elif defined LWIP_OS_BSD
// void func_enter(unsigned int *esp){
// #endif
// 	if (entered == 0) {
// 		entered = 1;
// 		saved_errno = errno;
// #ifdef LWIP_OS_LINUX
// 		pre_handler((int *)&eax, &ebx, &ecx, &edx, &esi, &edi, &ebp);
// 		syscall_no = eax;
// #elif defined LWIP_OS_BSD 
// 		int *eax_ptr = (int *)esp + 7;
// 		unsigned int *p1 = (unsigned int *)eax_ptr + 2;
// 		pre_handler(eax_ptr, p1, p1+1, p1+2, p1+3, p1+4, p1+5);
// 		syscall_no = *eax_ptr;
// #endif

// 		entered = 0;
// 	}
// }


// #ifdef LWIP_OS_LINUX
// void func_exit(unsigned int edi, unsigned int esi, unsigned int ebp, unsigned int sp, unsigned int ebx, unsigned int edx, unsigned int ecx, unsigned int eax) {
// #elif defined LWIP_OS_BSD
// void func_exit(unsigned int *esp){
// #endif
// 	if (entered == 0) {
// 		entered = 1;

// #ifdef LWIP_OS_LINUX
// 		post_handler(syscall_no, &eax, 0, &ebx, &ecx, &edx, &esi, &edi, &ebp);
// #elif defined LWIP_OS_BSD
// 		unsigned int *eax = esp + 8; //eax
// 		unsigned int *p1 = eax + 2;
// 		unsigned int *flags_ptr = esp;
// 		post_handler(syscall_no, eax, flags_ptr, p1, p1+1, p1+2, p1+3, p1+4, p1+5); 
// #endif

// 		errno = saved_errno;
// 		entered = 0;
// 	}

// }

