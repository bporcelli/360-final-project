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

#ifndef __LWIP_SYSHANDLER_H_
#define __LWIP_SYSHANDLER_H_

#include "lwip_level.h"
#include "lwip_redirect.h"
#include "lwip_bufferManager.h"
#include "lwip_os_mapping.h"

#define prepare_variables1(t1, a1) \
  t1 a1 = (t1) *p1_ptr;

#define prepare_variables2(t1, a1, t2, a2) \
  t2 a2 = (t2) *p2_ptr; \
  prepare_variables1(t1, a1);

#define prepare_variables3(t1, a1, t2, a2, t3, a3) \
  t3 a3 = (t3) *p3_ptr; \
  prepare_variables2(t1, a1, t2, a2);

#define prepare_variables4(t1, a1, t2, a2, t3, a3, t4, a4) \
  t4 a4 = (t4) *p4_ptr;				   \
  prepare_variables3(t1, a1, t2, a2, t3, a3);

#define prepare_variables5(t1, a1, t2, a2, t3, a3, t4, a4, t5, a5) \
  t5 a5 = (t5) *p5_ptr; \
  prepare_variables4(t1, a1, t2, a2, t3, a3, t4, a4);

#define prepare_variables6(t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6) \
  t6 a6 = (t6) *p6_ptr; \
  prepare_variables5(t1, a1, t2, a2, t3, a3, t4, a4, t5, a5);


#define modify_syscall_paramter(n, v1) \
	do { \
		LWIP_SAVE_PARAMETERS; \
		*p ##n_ptr = (unsigned int) v1; \
	} while (0)
	

/**
 * The below macros are used to define pre/post functions for syscalls.
 * Pre functions have names of the form SYSCALLNAME_pre, and post functions
 * have names of the form SYSCALLNAME_post.
 */
	
#define lwip_syscall(syscallName, prepost) _lwip_syscall_ ##prepost(syscallName)


#define lwip_syscall_pre_invocation (syscall_no_ptr, p1_ptr, p2_ptr, p3_ptr, p4_ptr, p5_ptr, p6_ptr)

#define lwip_syscall_pre_signature (int *syscall_no_ptr, unsigned int *p1_ptr, unsigned int *p2_ptr, unsigned int *p3_ptr, unsigned int *p4_ptr, unsigned int *p5_ptr, unsigned int *p6_ptr)
#define lwip_syscall_post_signature (int syscall_no, unsigned int *return_value_ptr, unsigned int *flags_ptr, unsigned int *p1_ptr, unsigned int *p2_ptr, unsigned int *p3_ptr, unsigned int *p4_ptr, unsigned int *p5_ptr, unsigned int *p6_ptr)
#define lwip_syscall_post_invocation (syscall_no, return_value_ptr, flags_ptr, p1_ptr, p2_ptr, p3_ptr, p4_ptr, p5_ptr, p6_ptr)

#define _lwip_syscall_pre(syscallName) void syscallName ##_pre lwip_syscall_pre_signature
#define _lwip_syscall_post(syscallName) void syscallName ##_post lwip_syscall_post_signature

#define lwip_call(syscallName, prepost) _lwip_call_ ##prepost(syscallName)

#define _lwip_call_pre(syscallName) syscallName ##_pre lwip_syscall_pre_invocation
#define _lwip_call_post(syscallName) syscallName ##_post lwip_syscall_post_invocation




#define lwip_case(syscallName, prepost) _lwip_case(syscallName, prepost)
#define _lwip_case(syscallName, prepost) case SYS_ ##syscallName: lwip_call(syscallName, prepost); break;




#ifdef LWIP_OS_BSD

#define LWIP_SET_SYSCALL_ERROR(error) do { \
        *flags_ptr = *flags_ptr | 1; \
        *return_value_ptr = error; \
  } while (0) 
#define LWIP_ISERROR (*flags_ptr & 1)
#define LWIP_UNSET_SYSCALL_ERROR(rv) do { \
        *flags_ptr = *flags_ptr & (~1); \
        *return_value_ptr = rv; \
  } while (0)
#define lwip_syscall_errno ((int)*return_value_ptr)



#define lwip_bsd_case(syscallName, prepost) lwip_case(syscallName, prepost)
#define lwip_linux_case(syscallName, prepost)

#elif defined LWIP_OS_LINUX

#define LWIP_SET_SYSCALL_ERROR(error_no) (*return_value_ptr = -error_no)
#define LWIP_ISERROR (((int)*return_value_ptr) < 0)
#define LWIP_UNSET_SYSCALL_ERROR(rv) (*return_value_ptr = rv)
#define lwip_syscall_errno (-((int)*return_value_ptr))

#define lwip_linux_case(syscallName, prepost) lwip_case(syscallName, prepost)
#define lwip_bsd_case(syscallName, prepost)

#endif

#define LWIP_ISERRORNO(errNum) (LWIP_ISERROR && (lwip_syscall_errno == (errNum)))


extern Level sh_processLevel;

extern __thread int sh_restore_p1;
extern __thread unsigned int sh_original_p1;

extern __thread int lwip_bypass_handler;


#define LWIP_SET_BYPASS_HANDLER lwip_bypass_handler = 1
#define LWIP_UNSET_BYPASS_HANDLER lwip_bypass_handler = 0
#define LWIP_CHECK_BYPASS_HANDLER (lwip_bypass_handler == 1)


extern int lwip_isISO_mode;
extern int lwip_isIN_mode;
extern int lwip_isAE_mode;

//Used for rename
extern __thread char *syscall_rename_buffer1, *syscall_rename_buffer2;

#define lwip_syscall_covert2FullAndRedirectedPathat_re(param1_ptr, param2_ptr) \
	do { \
		if (syscall_rename_buffer1 != NULL) \
			LWIP_CRITICAL("Something is seriously wrong!!"); \
		syscall_rename_buffer1 = (char *)lwip_bm_malloc(PATH_MAX); \
        	syscall_rename_buffer2 = (char *)lwip_bm_malloc(PATH_MAX); \
	        convert2FullAndRedirectPathat_re(param1_ptr, param2_ptr, syscall_rename_buffer1, syscall_rename_buffer2); \
	} while (0)

#define lwip_syscall_covert2FullAndRedirectedPath_re(param1_ptr) \
	do { \
		if (syscall_rename_buffer1 != NULL) \
			LWIP_CRITICAL("Something is seriously wrong!!"); \
		syscall_rename_buffer1 = (char *)lwip_bm_malloc(PATH_MAX); \
	        convert2FullAndRedirectPath_re(param1_ptr, syscall_rename_buffer1); \
	} while (0)

#define lwip_syscall_freeConvert2FullAndRedirectedPathat_re \
	do { \
		if (syscall_rename_buffer1 != NULL) { \
			lwip_bm_free(syscall_rename_buffer1); \
			syscall_rename_buffer1 = NULL; \
		} \
		if (syscall_rename_buffer2 != NULL) { \
			lwip_bm_free(syscall_rename_buffer2); \
			syscall_rename_buffer2 = NULL; \
		} \
	} while (0)



#ifdef __GNUC__
#define VARIABLE_IS_NOT_USED __attribute__ ((unused))
#else
#define VARIABLE_IS_NOT_USED
#endif


#define preprocessPath_p1 \
	do { \
		if (sh_restore_p1 == 0) \
			sh_original_p1 = *p1_ptr; \
		convert2FullAndRedirectPath(p1_ptr); \
	} while (0)


#define lwip_callback(name) void name lwip_syscall_post_signature
#define lwip_invokeCallback(name) name lwip_syscall_post_invocation


extern __thread void (*sh_custom_callback) lwip_syscall_post_signature;


#define lwip_cancelSyscall(callback) \
	do { \
		sh_custom_callback = callback; \
		*syscall_no_ptr = SYS_getpid; \
	} while (0)

extern __thread int lwip_restore_parameter_cnt;
#define LWIP_MAX_PARAMETER_TOSAVE 6
extern __thread int lwip_parameter_store[LWIP_MAX_PARAMETER_TOSAVE];


#ifdef LWIP_OS_BSD

#define LWIP_SAVE_PARAMETERS_N(count) do { \
 	if (lwip_restore_parameter_cnt == 0) { \
		lwip_restore_parameter_cnt = count; \
		memcpy((char *)lwip_parameter_store, (char *)p1_ptr, sizeof(int)*lwip_restore_parameter_cnt); \
	} \
	} while(0)

#define LWIP_SAVE_PARAMETERS do { \
 	if (lwip_restore_parameter_cnt == 0) { \
		lwip_restore_parameter_cnt = LWIP_MAX_PARAMETER_TOSAVE; \
		memcpy((char *)lwip_parameter_store, (char *)p1_ptr, sizeof(int)*lwip_restore_parameter_cnt); \
	} \
	} while(0)

#define LWIP_RESTORE_PARAMETERS do { \
 	if (lwip_restore_parameter_cnt > 0) { \
		memcpy((char *)p1_ptr, (char *)lwip_parameter_store, sizeof(int)*lwip_restore_parameter_cnt); \
		lwip_restore_parameter_cnt = 0; \
	} \
	} while(0)

#elif defined LWIP_OS_LINUX

#define LWIP_SAVE_PARAMETERS_N(count) do { \
	if (lwip_restore_parameter_cnt == 0) { \
		lwip_restore_parameter_cnt = count; \
		LWIP_SAVE_PARAMETERS_ ##count; \
	}\
	} while(0)

#define LWIP_SAVE_PARAMETERS LWIP_SAVE_PARAMETERS_N(6)
 
#define LWIP_SAVE_PARAMETERS_1 lwip_parameter_store[0] = *p1_ptr
#define LWIP_SAVE_PARAMETERS_2 lwip_parameter_store[1] = *p2_ptr; \
	LWIP_SAVE_PARAMETERS_1
#define LWIP_SAVE_PARAMETERS_3 lwip_parameter_store[2] = *p3_ptr; \
	LWIP_SAVE_PARAMETERS_2
#define LWIP_SAVE_PARAMETERS_4 lwip_parameter_store[3] = *p4_ptr; \
	LWIP_SAVE_PARAMETERS_3
#define LWIP_SAVE_PARAMETERS_5 lwip_parameter_store[4] = *p5_ptr; \
	LWIP_SAVE_PARAMETERS_4
#define LWIP_SAVE_PARAMETERS_6 lwip_parameter_store[5] = *p6_ptr; \
	LWIP_SAVE_PARAMETERS_5

#define LWIP_RESTORE_PARAMETERS do { \
	switch (lwip_restore_parameter_cnt) { \
		case 6: *p6_ptr = lwip_parameter_store[5]; \
		case 5: *p5_ptr = lwip_parameter_store[4]; \
		case 4: *p4_ptr = lwip_parameter_store[3]; \
		case 3: *p3_ptr = lwip_parameter_store[2]; \
		case 2: *p2_ptr = lwip_parameter_store[1]; \
		case 1: *p1_ptr = lwip_parameter_store[0]; \
	} \
	lwip_restore_parameter_cnt = 0; \
	} while(0)

#endif

#define lwip_change_syscall(syscall_no) do { \
        *syscall_no_ptr = syscall_no; \
        } while (0)

#define lwip_change_syscall1(syscall_no, new_p1_ptr) do { \
	LWIP_SAVE_PARAMETERS_N(1); \
        *p1_ptr = (unsigned int)new_p1_ptr; \
        lwip_change_syscall(syscall_no); \
        } while (0)

#define lwip_change_syscall2(syscall_no, new_p1_ptr, new_p2_ptr) do { \
	LWIP_SAVE_PARAMETERS_N(2); \
        *p2_ptr = (unsigned int)new_p2_ptr; \
        lwip_change_syscall1(syscall_no, new_p1_ptr); \
        } while (0)

#define lwip_change_syscall3(syscall_no, new_p1_ptr, new_p2_ptr, new_p3_ptr) do { \
	LWIP_SAVE_PARAMETERS_N(3); \
        *p3_ptr = (unsigned int)new_p3_ptr; \
        lwip_change_syscall2(syscall_no, new_p1_ptr, new_p2_ptr); \
        } while (0)

#define lwip_change_syscall4(syscall_no, new_p1_ptr, new_p2_ptr, new_p3_ptr, new_p4_ptr) do { \
	LWIP_SAVE_PARAMETERS_N(4); \
        *p4_ptr = (unsigned int)new_p4_ptr; \
        lwip_change_syscall3(syscall_no, new_p1_ptr, new_p2_ptr, new_p3_ptr); \
        } while (0)

#define lwip_change_syscall5(syscall_no, new_p1_ptr, new_p2_ptr, new_p3_ptr, new_p4_ptr, new_p5_ptr) do { \
	LWIP_SAVE_PARAMETERS_N(5); \
        *p5_ptr = (unsigned int)new_p5_ptr; \
        lwip_change_syscall4(syscall_no, new_p1_ptr, new_p2_ptr, new_p3_ptr, new_p4_ptr); \
        } while (0)

#define lwip_change_syscall6(syscall_no, new_p1_ptr, new_p2_ptr, new_p3_ptr, new_p4_ptr, new_p5_ptr, new_p6_ptr) do { \
	LWIP_SAVE_PARAMETERS_N(6); \
        *p6_ptr = (unsigned int)new_p6_ptr; \
        lwip_change_syscall5(syscall_no, new_p1_ptr, new_p2_ptr, new_p3_ptr, new_p4_ptr, new_p5_ptr); \
        } while (0)

#define lwip_call_syscall_post_handler(syscallName) do { \
		lwip_call(syscallName, post); \
        } while (0)

#define lwip_call_syscall_post_handler1(syscallName, new_p1_ptr) do { \
	LWIP_SAVE_PARAMETERS_N(1); \
        *p1_ptr = (unsigned int)new_p1_ptr; \
        lwip_call_syscall_post_handler(syscallName); \
        } while (0)

#define lwip_call_syscall_post_handler2(syscallName, new_p1_ptr, new_p2_ptr) do { \
	LWIP_SAVE_PARAMETERS_N(2); \
        *p2_ptr = (unsigned int)new_p2_ptr; \
        lwip_call_syscall_post_handler1(syscallName, new_p1_ptr); \
        } while (0)

#define lwip_call_syscall_post_handler3(syscallName, new_p1_ptr, new_p2_ptr, new_p3_ptr) do { \
	LWIP_SAVE_PARAMETERS_N(3); \
        *p3_ptr = (unsigned int)new_p3_ptr; \
        lwip_call_syscall_post_handler2(syscallName, new_p1_ptr, new_p2_ptr); \
        } while (0)

#define lwip_call_syscall_post_handler4(syscallName, new_p1_ptr, new_p2_ptr, new_p3_ptr, new_p4_ptr) do { \
	LWIP_SAVE_PARAMETERS_N(4); \
        *p4_ptr = (unsigned int)new_p4_ptr; \
        lwip_call_syscall_post_handler3(syscallName, new_p1_ptr, new_p2_ptr, new_p3_ptr); \
        } while (0)

#define lwip_call_syscall_post_handler5(syscallName, new_p1_ptr, new_p2_ptr, new_p3_ptr, new_p4_ptr, new_p5_ptr) do { \
	LWIP_SAVE_PARAMETERS_N(5); \
        *p5_ptr = (unsigned int)new_p5_ptr; \
        lwip_call_syscall_post_handler4(syscallName, new_p1_ptr, new_p2_ptr, new_p3_ptr, new_p4_ptr); \
        } while (0)

#define lwip_call_syscall_post_handler6(syscallName, new_p1_ptr, new_p2_ptr, new_p3_ptr, new_p4_ptr, new_p5_ptr, new_p6_ptr) do { \
	LWIP_SAVE_PARAMETERS_N(6); \
        *p6_ptr = (unsigned int)new_p6_ptr; \
        lwip_call_syscall_post_handler5(syscallName, new_p1_ptr, new_p2_ptr, new_p3_ptr, new_p4_ptr, new_p5_ptr); \
        } while (0)







#define NOT_NULL(parameter) LWIP_ASSERT1(parameter != NULL)


#define LWIP_PROCESS_LV_HIGH (lwip_level_isHigh(sh_processLevel))
#define LWIP_PROCESS_LV_LOW (lwip_level_isLow(sh_processLevel))


#define LWIP_INTERCEPT_DBUS_MESSAGE


#endif /* __LWIP_SYSHANDLER_H_ */
